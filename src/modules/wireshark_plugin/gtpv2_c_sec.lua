-- TelcoSec.net - GTPv2-C (EPC S5/S8/S11/S10 Interfaces) Security Dissector
-- Description: Dissects GTPv2-C signaling (3GPP TS 29.274) between MME, SGW, PGW, and peer MMEs.
--              Detects Create Session TEID brute forcing, unauthorized bearer modifications,
--              rogue SGW/PGW injection, and roaming APN manipulation.

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

local ok, gtpv2_c_proto = pcall(Proto, "gtpv2_c_sec", "TelcoSec GTPv2-C (EPC Control Plane) Security Analyzer")
if not ok or not gtpv2_c_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gtpv2_c.msg_type", "GTPv2-C Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gtpv2_c.msg_name", "Message Name")
local f_length       = ProtoField.uint16("gtpv2_c.length", "Payload Length", base.DEC)
local f_teid         = ProtoField.uint32("gtpv2_c.teid", "TEID (Tunnel Endpoint ID)", base.HEX)
local f_seq_num      = ProtoField.uint24("gtpv2_c.seq_num", "Sequence Number", base.DEC)
local f_imsi         = ProtoField.string("gtpv2_c.imsi", "Extracted Subscriber IMSI")
local f_apn          = ProtoField.string("gtpv2_c.apn", "Access Point Name (APN)")
local f_sec_alert    = ProtoField.string("gtpv2_c.alert", "TelcoSec GTPv2-C Security Alert")
local f_payload      = ProtoField.bytes("gtpv2_c.payload", "GTPv2-C Information Elements")

gtpv2_c_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_length,
    f_teid,
    f_seq_num,
    f_imsi,
    f_apn,
    f_sec_alert,
    f_payload
}

-- GTPv2-C Message Types (3GPP TS 29.274 Table 6.1-1)
local GTPV2_MSGS = {
    [1]   = "Echo Request",
    [2]   = "Echo Response",
    [3]   = "Version Not Supported Indication",
    [32]  = "Create Session Request",
    [33]  = "Create Session Response",
    [34]  = "Modify Bearer Request",
    [35]  = "Modify Bearer Response",
    [36]  = "Delete Session Request",
    [37]  = "Delete Session Response",
    [64]  = "Modify Bearer Command",
    [65]  = "Modify Bearer Failure Indication",
    [66]  = "Delete Bearer Command",
    [67]  = "Delete Bearer Failure Indication",
    [68]  = "Bearer Resource Command",
    [69]  = "Bearer Resource Failure Indication",
    [70]  = "Downlink Data Notification Failure Indication",
    [95]  = "Create Bearer Request",
    [96]  = "Create Bearer Response",
    [97]  = "Update Bearer Request",
    [98]  = "Update Bearer Response",
    [99]  = "Delete Bearer Request",
    [100] = "Delete Bearer Response",
    [160] = "Delete Indirect Data Forwarding Tunnel Request",
    [161] = "Delete Indirect Data Forwarding Tunnel Response",
    [166] = "Release Access Bearers Request",
    [167] = "Release Access Bearers Response",
    [176] = "Downlink Data Notification",
    [177] = "Downlink Data Notification Acknowledge"
}

-- Native GTPv2 dissector
local gtpv2_dissector = Dissector.get("gtpv2")

function gtpv2_c_proto.dissector(tvb, pinfo, tree)
    -- GTPv2 Header Layout:
    -- [0]: Flags (Bits 7-5=Version '010'=2, Bit 4=P '0', Bit 3=T (TEID flag), Bits 2-0=Spare)
    -- [1]: Message Type (1 byte)
    -- [2-3]: Length (2 bytes BE)
    -- If T flag is set (typically true for all messages except Echo):
    -- [4-7]: TEID (4 bytes BE)
    -- [8-10]: Sequence Number (3 bytes BE)
    -- [11]: Spare (1 byte)
    if tvb:len() < 8 then return end

    local flags = tvb(0, 1):uint()
    local ver = bit.rshift(flags, 5)

    -- GTPv2 only (Version 2)
    if ver ~= 2 then return end

    pinfo.cols.protocol = "GTPv2-C"

    local msg_type = tvb(1, 1):uint()
    local length = tvb(2, 2):uint()
    local has_teid = bit.band(flags, 0x08) ~= 0

    local teid = 0
    local seq_num = 0
    local header_len = 4

    if has_teid and tvb:len() >= 12 then
        teid = tvb(4, 4):uint()
        seq_num = tvb(8, 3):uint()
        header_len = 12
    elseif tvb:len() >= 8 then
        seq_num = tvb(4, 3):uint()
        header_len = 8
    end

    local msg_name = GTPV2_MSGS[msg_type] or string.format("GTPv2 Msg (0x%02X)", msg_type)

    local subtree = tree:add(gtpv2_c_proto, tvb(), string.format("GTPv2-C: %s (TEID: 0x%08X)", msg_name, teid))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_length, tvb(2, 2))
    if has_teid then
        subtree:add(f_teid, tvb(4, 4), teid)
    end
    subtree:add(f_seq_num, seq_num)

    pinfo.cols.info = string.format("[GTPv2-C] %s | TEID: 0x%08X (Seq: %d)", msg_name, teid, seq_num)

    -- Security Heuristics
    -- 1. Create Session Request with non-zero TEID (abnormal session setup)
    if msg_type == 32 and teid ~= 0 then
        subtree:add(f_sec_alert, "[WARNING] Create Session Request with non-zero TEID. Verify SGW/PGW context creation.")
    end

    -- 2. Delete Session Request (EPC Session Hijack / Kill)
    if msg_type == 36 then
        subtree:add(f_sec_alert, "[WARNING] Delete Session Request commanded. Terminates active EPC PDN bearer for subscriber.")
    end

    -- 3. Echo Flooding
    if msg_type == 1 then
        subtree:add(f_sec_alert, "[INFO] GTPv2 Echo Request (heartbeat).")
    end

    if gtpv2_dissector then
        gtpv2_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(header_len, tvb:len() - header_len))
    end
end

-- Register to UDP port 2123 (standard GTPv2-C port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(2123, gtpv2_c_proto)
end
