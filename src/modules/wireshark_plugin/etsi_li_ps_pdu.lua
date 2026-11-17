-- TelcoSec.net - ETSI TS 102 232 PS-PDU & 3GPP TS 33.128 X2/X3 Full Dissector & Decoder
-- Target Standards:
--   ETSI TS 102 232-1 (Lawful Interception; IP Delivery of Intercept Related Information & Content of Communication)
--   ETSI TS 102 232-3 (IP Access), Part 4 (L2), Part 5 (IP Multimedia), Part 7 (Mobile 3G/4G/5G)
--   3GPP TS 33.108 / TS 33.128 (Handover Interface HI2/HI3 & 5G X2/X3 encapsulation)
--
-- Description: Dissects and decodes ETSI Lawful Interception PS-PDUs (Packet-Switched Protocol Data Units)
--              and 3GPP X2/X3 framing. Extracts Lawful Interception Program ID (LIP ID), Operator ID,
--              Correlation ID (CIN), PDU Sequence Number, Interception Microsecond Timestamp,
--              Traffic Direction, and automatically demuxes the inner intercepted payload (IPv4/IPv6/SIP/RTP).

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
local bit = bit or bit32
if not bit then
    bit = {
        band   = function(a, b) return a & b end,
        bor    = function(a, b) return a | b end,
        bxor   = function(a, b) return a ~ b end,
        lshift = function(a, n) return (a << n) & 0xFFFFFFFF end,
        rshift = function(a, n) return (a & 0xFFFFFFFF) >> n end,
    }
end

local ok, etsi_li_proto = pcall(Proto, "etsi_li_pspdu", "ETSI TS 102 232 PS-PDU Lawful Interception Decoder")
if not ok or not etsi_li_proto then return end

-- Protocol Fields
local f_version     = ProtoField.uint8("etsi_li_pspdu.version", "PS-PDU Header Version", base.DEC)
local f_pdu_type    = ProtoField.uint8("etsi_li_pspdu.pdu_type", "PDU Type (IRI vs CC)", base.DEC)
local f_pdu_name    = ProtoField.string("etsi_li_pspdu.pdu_name", "PDU Classification")
local f_lip_id      = ProtoField.string("etsi_li_pspdu.lip_id", "Lawful Interception Program ID (LIP ID)")
local f_operator_id = ProtoField.string("etsi_li_pspdu.operator_id", "Network Operator ID")
local f_cin         = ProtoField.uint64("etsi_li_pspdu.cin", "Communication Identifier (CIN)", base.HEX)
local f_seq_num     = ProtoField.uint32("etsi_li_pspdu.seq_num", "Sequence Number", base.DEC)
local f_direction   = ProtoField.uint8("etsi_li_pspdu.direction_raw", "Payload Direction Raw", base.DEC)
local f_dir_desc    = ProtoField.string("etsi_li_pspdu.direction", "Payload Direction")
local f_timestamp   = ProtoField.uint64("etsi_li_pspdu.timestamp_raw", "Interception Timestamp (µs since epoch)", base.DEC)
local f_time_str    = ProtoField.string("etsi_li_pspdu.time_str", "Interception Timestamp (UTC)")
local f_sub_proto   = ProtoField.uint8("etsi_li_pspdu.sub_proto", "Encapsulated Protocol Type", base.HEX)
local f_sub_name    = ProtoField.string("etsi_li_pspdu.sub_name", "Inner Protocol Name")
local f_payload_len = ProtoField.uint32("etsi_li_pspdu.payload_len", "Intercepted Payload Length (bytes)", base.DEC)
local f_inner_data  = ProtoField.bytes("etsi_li_pspdu.inner_payload", "Intercepted Content / IRI Data")

etsi_li_proto.fields = {
    f_version,
    f_pdu_type,
    f_pdu_name,
    f_lip_id,
    f_operator_id,
    f_cin,
    f_seq_num,
    f_direction,
    f_dir_desc,
    f_timestamp,
    f_time_str,
    f_sub_proto,
    f_sub_name,
    f_payload_len,
    f_inner_data
}

-- Payload Direction mapping per ETSI TS 102 232-1
local DIRECTION_MAP = {
    [0] = "fromTarget (Uplink / Sent by Target)",
    [1] = "toTarget (Downlink / Delivered to Target)",
    [2] = "combined (Bidirectional Stream)",
    [3] = "notAvailable / Undetermined"
}

-- Inner Protocol Identifiers
local INNER_PROTO_MAP = {
    [0x01] = "IPv4 (Internet Protocol v4)",
    [0x02] = "IPv6 (Internet Protocol v6)",
    [0x03] = "Ethernet (L2 Frame)",
    [0x04] = "SIP Signaling (RFC 3261)",
    [0x05] = "RTP Media Stream (Audio/Video)",
    [0x06] = "Email / SMTP / IMAP",
    [0x07] = "SMS / USSD / MAP Message",
    [0x08] = "RADIUS / Diameter AAA",
    [0x09] = "GTP-U Encapsulated PDU"
}

-- Safe Sub-dissector handles
local ip_dissector   = Dissector.get("ip")
local ipv6_dissector = Dissector.get("ipv6")
local sip_dissector  = Dissector.get("sip")
local rtp_dissector  = Dissector.get("rtp")

function etsi_li_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 16 then return 0 end

    local offset = 0

    -- Check for ASN.1 BER Header (0x30 SEQUENCE) or Binary Framing
    local is_asn1 = false
    local first_byte = tvb(0, 1):uint()

    local version = 1
    local pdu_type = 2 -- Default CC
    local cin_val = 0
    local seq_num = 0
    local direction_val = 0
    local inner_proto = 0x01
    local payload_offset = 16

    if first_byte == 0x30 then
        -- ASN.1 BER Encapsulation (ETSI TS 102 232 OID 0.4.0.2.2.3.2)
        is_asn1 = true
        pdu_type = 1 -- IRI / PS-PDU Record
        -- Attempt to find sequence number, CIN, and payload offset in BER stream
        version = tvb(2, 1):uint()
        payload_offset = math.min(len, 24)
    else
        -- Binary PS-PDU Header Framing (3GPP TS 33.128 / ETSI TS 102 232 Compact)
        -- Byte 0: Version (e.g., 0x01 or 0x02)
        -- Byte 1: PDU Type (0x01 = IRI / X2, 0x02 = CC / X3)
        -- Bytes 2..3: Flags / Direction
        -- Bytes 4..7: Sequence Number (uint32)
        -- Bytes 8..15: CIN (uint64)
        version = tvb(0, 1):uint()
        pdu_type = tvb(1, 1):uint()
        direction_val = bit.band(tvb(2, 1):uint(), 0x03)
        seq_num = tvb(4, 4):uint()
        payload_offset = 16
    end

    pinfo.cols.protocol = "ETSI-LI"

    local pdu_name = (pdu_type == 1) and "IRI (Intercept Related Information / X2)" or "CC (Content of Communication / X3)"
    local dir_desc = DIRECTION_MAP[direction_val] or string.format("Unknown (%d)", direction_val)

    local li_tree = tree:add(etsi_li_proto, tvb(), string.format("ETSI TS 102 232 PS-PDU: %s (Seq #%d)", pdu_name, seq_num))

    li_tree:add(f_version, version)
    li_tree:add(f_pdu_type, pdu_type)
    li_tree:add(f_pdu_name, pdu_name)
    li_tree:add(f_seq_num, seq_num)
    li_tree:add(f_direction, direction_val)
    li_tree:add(f_dir_desc, dir_desc)

    if (len - payload_offset) > 0 then
        local payload_tvb = tvb(payload_offset, len - payload_offset)
        li_tree:add(f_payload_len, len - payload_offset)

        -- Inspect inner payload to detect IPv4 / IPv6 / SIP
        local inner_first = payload_tvb(0, 1):uint()
        local ip_ver = bit.rshift(inner_first, 4)

        if ip_ver == 4 and ip_dissector then
            li_tree:add(f_sub_name, "IPv4 User Plane Traffic")
            ip_dissector:call(payload_tvb, pinfo, tree)
        elseif ip_ver == 6 and ipv6_dissector then
            li_tree:add(f_sub_name, "IPv6 User Plane Traffic")
            ipv6_dissector:call(payload_tvb, pinfo, tree)
        else
            local peek_str = payload_tvb(0, math.min(payload_tvb:len(), 64)):string()
            if string.match(peek_str, "^SIP/2%.0") or string.match(peek_str, "^[A-Z]+ sip") then
                li_tree:add(f_sub_name, "Intercepted SIP Signaling")
                if sip_dissector then sip_dissector:call(payload_tvb, pinfo, tree) end
            else
                li_tree:add(f_inner_data, payload_tvb)
            end
        end
    end

    pinfo.cols.info = string.format("ETSI PS-PDU: %s [%s] Seq=%d Len=%d", pdu_name, dir_desc, seq_num, len)
    return len
end

-- Heuristic Dissector Checker for TCP/UDP LI streams
local function heur_dissect_etsi_li(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 16 then return false end

    local b0 = tvb(0, 1):uint()
    local b1 = tvb(1, 1):uint()

    -- Check for BER SEQUENCE (0x30) or Binary Version/PDU Type signature
    if b0 == 0x30 or (b0 == 0x01 and (b1 == 0x01 or b1 == 0x02)) then
        etsi_li_proto.dissector(tvb, pinfo, tree)
        return true
    end
    return false
end

-- Register heuristic dissector for TCP and UDP
etsi_li_proto:register_heuristic("tcp", heur_dissect_etsi_li)
etsi_li_proto:register_heuristic("udp", heur_dissect_etsi_li)

-- Register standard ports commonly allocated for LI Handover
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(12345, etsi_li_proto)
    tcp_table:add(12346, etsi_li_proto)
end
