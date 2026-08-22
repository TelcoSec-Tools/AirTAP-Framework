-- TelcoSec.net - Apple Radio Interface (ARI / CommCenter IPC) Security Dissector
-- Description: Dissects Apple Radio Interface (ARI) framing between iOS CommCenter and cellular basebands (Qualcomm / Intel).
--              Monitors baseband-to-AP IPC, STK proactive triggers, baseband crash reports, and PDP context provisioning.

-- Safe protocol registration guard against dual-folder loading
local ok, ari_proto = pcall(Proto, "apple_ari_commcenter", "Apple Radio Interface (ARI / CommCenter) Analyzer")
if not ok or not ari_proto then return end

-- Protocol fields
local f_ari_magic    = ProtoField.uint32("ari_sec.magic", "ARI Magic (0x41524930)", base.HEX)
local f_group_id     = ProtoField.uint8("ari_sec.group_id", "ARI Group ID", base.HEX)
local f_msg_id       = ProtoField.uint16("ari_sec.msg_id", "ARI Msg ID", base.HEX)
local f_group_name   = ProtoField.string("ari_sec.group_name", "Subsystem Name")
local f_seq_num      = ProtoField.uint16("ari_sec.seq_num", "Sequence Number", base.DEC)
local f_sec_alert    = ProtoField.string("ari_sec.alert", "TelcoSec Apple ARI Alert")
local f_payload      = ProtoField.bytes("ari_sec.payload", "ARI SDU Data")

ari_proto.fields = {
    f_ari_magic,
    f_group_id,
    f_msg_id,
    f_group_name,
    f_seq_num,
    f_sec_alert,
    f_payload
}

-- ARI Subsystem Groups
local ARI_GROUPS = {
    [0x01] = "ARI_GROUP_SIM (USIM / STK / eSIM)",
    [0x02] = "ARI_GROUP_NET (Registration & RAT State)",
    [0x03] = "ARI_GROUP_CALL (VoLTE / IMS / Call Control)",
    [0x04] = "ARI_GROUP_SMS (Short Message Service)",
    [0x05] = "ARI_GROUP_DATA (PDP / EPS / 5GS Bearers)",
    [0x06] = "ARI_GROUP_PWR (Power & Baseband Sleep)",
    [0x0A] = "ARI_GROUP_SYS (Baseband Panic & Crash Notification)"
}

function ari_proto.dissector(tvb, pinfo, tree)
    -- ARI Header (8 bytes):
    -- [0-3]: Magic ("ARI0" / 0x41524930)
    -- [4]: Group ID
    -- [5-6]: Msg ID (2 bytes LE)
    -- [7]: Flags / Seq
    if tvb:len() < 8 then return end

    local magic = tvb(0, 4):uint()
    if magic ~= 0x41524930 and magic ~= 0x30495241 then return end

    pinfo.cols.protocol = "Apple ARI"

    local group_id = tvb(4, 1):uint()
    local msg_id = tvb(5, 2):le_uint()
    local group_name = ARI_GROUPS[group_id] or string.format("Group 0x%02X", group_id)

    local subtree = tree:add(ari_proto, tvb(), string.format("Apple ARI (CommCenter): %s", group_name))
    subtree:add(f_ari_magic, tvb(0, 4))
    subtree:add(f_group_id, tvb(4, 1), group_id)
    subtree:add(f_msg_id, tvb(5, 2), msg_id)
    subtree:add(f_group_name, group_name)

    pinfo.cols.info = string.format("[Apple ARI] %s (Msg: 0x%04X)", group_name, msg_id)

    -- Security Heuristic 1: Baseband Crash Notification to CommCenter
    if group_id == 0x0A then
        subtree:add(f_sec_alert, "[CRITICAL] Baseband Panic / Crash Notification reported to iOS CommCenter! Possible OTA vulnerability trigger.")
        pinfo.cols.info:append(" [TELCOSEC: IOS BASEBAND PANIC!]")
    end

    -- Security Heuristic 2: STK Proactive Command Trigger in iOS
    if group_id == 0x01 and msg_id == 0x0012 then
        subtree:add(f_sec_alert, "[WARNING] STK Proactive Command forwarded to CommCenter (Potential SIMjacker trigger).")
    end

    if tvb:len() > 8 then
        subtree:add(f_payload, tvb(8, tvb:len() - 8))
    end
end

-- Register to UDP port 5002 (Apple ARI logging socket)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(5002, ari_proto)
end
