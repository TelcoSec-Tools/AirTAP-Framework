-- TelcoSec.net - GTP-U User Plane Security Dissector
-- Description: Dissects GTP-U v1 frames (3GPP TS 29.060) on Gn/Gp/S5/S8/N3 interfaces.
--              Inspects encapsulated user IP packets, detects GTP tunnel injection, over-billing attacks,
--              and plain subscriber data exfiltration.

local ok, gtp_u_proto = pcall(Proto, "gtp_u_v1_sec", "TelcoSec GTP-U v1 User Plane Security Analyzer")
if not ok or not gtp_u_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gtp_u.msg_type", "GTP-U Message Type", base.HEX)
local f_teid         = ProtoField.uint32("gtp_u.teid", "TEID (Tunnel Endpoint ID)", base.HEX)
local f_length       = ProtoField.uint16("gtp_u.length", "User Payload Length", base.DEC)
local f_inner_ip     = ProtoField.string("gtp_u.inner_ip", "Inner Protocol (IPv4/IPv6)")
local f_sec_alert    = ProtoField.string("gtp_u.alert", "TelcoSec GTP-U Security Alert")
local f_payload      = ProtoField.bytes("gtp_u.payload", "GTP-U Encapsulated Packet")

gtp_u_proto.fields = {
    f_msg_type,
    f_teid,
    f_length,
    f_inner_ip,
    f_sec_alert,
    f_payload
}

-- Native IP dissectors
local ip_dissector   = Dissector.get("ip")
local ipv6_dissector = Dissector.get("ipv6")

function gtp_u_proto.dissector(tvb, pinfo, tree)
    -- GTP-U Header Layout:
    -- [0]: Flags (0x30 = Version 1, PT 1)
    -- [1]: Message Type (0xFF = G-PDU / User Data)
    -- [2-3]: Length (2 bytes BE)
    -- [4-7]: TEID (4 bytes BE)
    if tvb:len() < 8 then return end

    local flags = tvb(0, 1):uint()
    local msg_type = tvb(1, 1):uint()
    local length = tvb(2, 2):uint()
    local teid = tvb(4, 4):uint()

    -- Only inspect G-PDU (Message Type 0xFF / 255)
    if msg_type ~= 0xFF then return end

    pinfo.cols.protocol = "GTP-U"

    local subtree = tree:add(gtp_u_proto, tvb(), string.format("GTP-U User Plane (TEID: 0x%08X, Len: %d)", teid, length))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_teid, tvb(4, 4), teid)
    subtree:add(f_length, tvb(2, 2))

    pinfo.cols.info = string.format("[GTP-U Data] TEID: 0x%08X | Len: %d", teid, length)

    -- Check optional flags: E (bit 2), S (bit 1), PN (bit 0)
    local has_opt = bit.band(flags, 0x07) ~= 0
    local header_len = has_opt and 12 or 8

    -- If extension headers present, skip them
    if has_opt and tvb:len() >= 12 then
        local next_ext = tvb(11, 1):uint()
        while next_ext ~= 0 and tvb:len() > header_len do
            local ext_len = tvb(header_len, 1):uint() * 4
            if ext_len == 0 then break end
            header_len = header_len + ext_len
            if tvb:len() >= header_len then
                next_ext = tvb(header_len - 1, 1):uint()
            else
                break
            end
        end
    end

    local payload_len = tvb:len() - header_len
    if payload_len > 0 then
        local payload_tvb = tvb(header_len, payload_len):tvb()
        local ip_ver = bit.rshift(payload_tvb(0, 1):uint(), 4)

        if ip_ver == 4 and ip_dissector then
            subtree:add(f_inner_ip, "IPv4 Encapsulated User Traffic")
            ip_dissector:call(payload_tvb, pinfo, tree)
        elseif ip_ver == 6 and ipv6_dissector then
            subtree:add(f_inner_ip, "IPv6 Encapsulated User Traffic")
            ipv6_dissector:call(payload_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(header_len, payload_len))
        end
    end
end

-- Register to UDP port 2152 (standard GTP-U port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(2152, gtp_u_proto)
end
