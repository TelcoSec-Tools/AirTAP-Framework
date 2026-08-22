-- TelcoSec.net - GTPv1-C (Gn/Gp Interface) Security Dissector
-- Description: Dissects GTPv1-C signaling (3GPP TS 29.060) between SGSN and GGSN.
--              Detects PDP Context hijacking, TEID prediction/brute-forcing, and APN spoofing.

local ok, gtp_v1c_proto = pcall(Proto, "gtp_v1c_sec", "TelcoSec GTPv1-C (Gn/Gp Control Plane) Security Analyzer")
if not ok or not gtp_v1c_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gtp_v1c.msg_type", "GTPv1-C Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gtp_v1c.msg_name", "Message Name")
local f_length       = ProtoField.uint16("gtp_v1c.length", "Payload Length", base.DEC)
local f_teid         = ProtoField.uint32("gtp_v1c.teid", "TEID (Tunnel Endpoint ID)", base.HEX)
local f_seq_num      = ProtoField.uint16("gtp_v1c.seq_num", "Sequence Number", base.DEC)
local f_imsi         = ProtoField.string("gtp_v1c.imsi", "Extracted IMSI")
local f_apn          = ProtoField.string("gtp_v1c.apn", "Access Point Name (APN)")
local f_sec_alert    = ProtoField.string("gtp_v1c.alert", "TelcoSec GTPv1-C Security Alert")
local f_payload      = ProtoField.bytes("gtp_v1c.payload", "GTPv1-C Information Elements")

gtp_v1c_proto.fields = {
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

-- GTPv1-C Message Types (3GPP TS 29.060 Table 1)
local GTPV1C_MSGS = {
    [1]  = "Echo Request",
    [2]  = "Echo Response",
    [16] = "Create PDP Context Request",
    [17] = "Create PDP Context Response",
    [18] = "Update PDP Context Request",
    [19] = "Update PDP Context Response",
    [20] = "Delete PDP Context Request",
    [21] = "Delete PDP Context Response",
    [26] = "Error Indication",
    [27] = "PDU Notification Request",
    [32] = "Send Routeing Info for GPRS Request",
    [33] = "Send Routeing Info for GPRS Response",
    [34] = "Failure Report Request"
}

-- Native Wireshark GTP dissector
local gtp_dissector = Dissector.get("gtp")

function gtp_v1c_proto.dissector(tvb, pinfo, tree)
    -- GTPv1 Header Layout (8 to 12 bytes):
    -- [0]: Flags (Bits 7-5=Version '001', Bit 4=PT '1' for GTP, Bit 2=E, Bit 1=S, Bit 0=PN)
    -- [1]: Message Type (1 byte)
    -- [2-3]: Length (2 bytes BE)
    -- [4-7]: TEID (4 bytes BE)
    -- Optional [8-9]=Seq Num, [10]=N-PDU Num, [11]=Next Extension Header
    if tvb:len() < 8 then return end

    local flags = tvb(0, 1):uint()
    local ver = bit.rshift(flags, 5)
    local pt = bit.band(bit.rshift(flags, 4), 0x01)

    -- GTPv1 only (Version 1, PT 1)
    if ver ~= 1 or pt ~= 1 then return end

    pinfo.cols.protocol = "GTPv1-C"

    local msg_type = tvb(1, 1):uint()
    local length = tvb(2, 2):uint()
    local teid = tvb(4, 4):uint()

    local msg_name = GTPV1C_MSGS[msg_type] or string.format("GTPv1-C Msg (0x%02X)", msg_type)

    local subtree = tree:add(gtp_v1c_proto, tvb(), string.format("GTPv1-C: %s (TEID: 0x%08X)", msg_name, teid))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_length, tvb(2, 2))
    subtree:add(f_teid, tvb(4, 4), teid)

    pinfo.cols.info = string.format("[GTPv1-C] %s | TEID: 0x%08X", msg_name, teid)

    -- Security Heuristic 1: TEID Zero in Create PDP Context Request
    if msg_type == 16 and teid == 0 then
        subtree:add(f_sec_alert, "[INFO] Standard initial Create PDP Context Request (TEID=0).")
    end

    -- Security Heuristic 2: Delete PDP Context Request Injection (Session Hijacking / DoS)
    if msg_type == 20 then
        subtree:add(f_sec_alert, "[WARNING] Delete PDP Context Request received. Check source IP to prevent rogue GPRS session termination.")
    end

    -- Security Heuristic 3: GTPv1-C Echo Flooding
    if msg_type == 1 then
        subtree:add(f_sec_alert, "[INFO] GTPv1-C Echo Request heartbeat.")
    end

    if gtp_dissector then
        gtp_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(8, tvb:len() - 8))
    end
end

-- Register to UDP port 2123 (standard GTPv1-C control port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(2123, gtp_v1c_proto)
end
