-- TelcoSec.net - MediaTek (MTK) Baseband Diagnostic & MobileLog Dissector
-- Description: Dissects MediaTek Catcher / MobileLog / ELT diagnostic packets (Dimensity / Helio modems).
--              Parses HDLC/0x7E framed modem traces across 2G/3G/4G/5G radio stacks,
--              detecting baseband panic assertions, OTA fuzzing crashes, and AT debug backdoor probes.

local ok, mtk_diag_proto = pcall(Proto, "mtk_mobilelog_framing", "MediaTek (MTK) MobileLog Diagnostic Protocol Analyzer")
if not ok or not mtk_diag_proto then return end

-- Protocol fields
local f_sync_byte    = ProtoField.uint8("mtk_diag.sync", "Sync Byte (0x7E)", base.HEX)
local f_msg_id       = ProtoField.uint16("mtk_diag.msg_id", "MTK SAP / Msg ID", base.HEX)
local f_sap_name     = ProtoField.string("mtk_diag.sap_name", "Service Access Point (SAP)")
local f_length       = ProtoField.uint16("mtk_diag.length", "Frame Length", base.DEC)
local f_sec_alert    = ProtoField.string("mtk_diag.alert", "TelcoSec MTK Baseband Alert")
local f_payload      = ProtoField.bytes("mtk_diag.payload", "MTK Modem Trace Data")

mtk_diag_proto.fields = {
    f_sync_byte,
    f_msg_id,
    f_sap_name,
    f_length,
    f_sec_alert,
    f_payload
}

-- MediaTek Common Service Access Points (SAPs)
local MTK_SAPS = {
    [0x0001] = "SAP_L1_LOG (Physical Layer)",
    [0x0002] = "SAP_L2_LOG (MAC / RLC)",
    [0x0003] = "SAP_RRC_LOG (Radio Resource Control)",
    [0x0004] = "SAP_NAS_LOG (Mobility & Session Management)",
    [0x0005] = "SAP_SYS_ASSERT (Baseband Panic / Crash Dump)",
    [0x0006] = "SAP_AT_DEBUG (AT Command Engine)",
    [0x0007] = "SAP_SIM_LOG (SIM / USIM Driver)",
    [0x0010] = "SAP_5G_NR_L3 (5G NR RRC / 5GS NAS)"
}

function mtk_diag_proto.dissector(tvb, pinfo, tree)
    -- MediaTek Frame Header:
    -- [0]: Sync Byte (0x7E)
    -- [1-2]: Length (2 bytes LE)
    -- [3-4]: Msg ID / SAP (2 bytes LE)
    if tvb:len() < 5 then return end

    local sync = tvb(0, 1):uint()
    if sync ~= 0x7E then return end

    pinfo.cols.protocol = "MTK MobileLog"

    local length = tvb(1, 2):le_uint()
    local msg_id = tvb(3, 2):le_uint()
    local sap_name = MTK_SAPS[msg_id] or string.format("SAP 0x%04X", msg_id)

    local subtree = tree:add(mtk_diag_proto, tvb(), string.format("MediaTek Modem Diagnostic: %s", sap_name))
    subtree:add(f_sync_byte, tvb(0, 1))
    subtree:add(f_length, tvb(1, 2), length)
    subtree:add(f_msg_id, tvb(3, 2), msg_id)
    subtree:add(f_sap_name, sap_name)

    pinfo.cols.info = string.format("[MTK Modem] %s (Len: %d)", sap_name, length)

    -- Security Heuristic 1: Baseband Panic / Memory Fault (SYS_ASSERT)
    if msg_id == 0x0005 then
        subtree:add(f_sec_alert, "[CRITICAL] MediaTek Baseband Assertion / Panic Dump! Modem crashed due to OTA memory corruption or fatal state exception.")
        pinfo.cols.info:append(" [TELCOSEC: MTK BASEBAND CRASH!]")
    end

    -- Security Heuristic 2: AT Debug Engine Probing
    if msg_id == 0x0006 then
        subtree:add(f_sec_alert, "[WARNING] MediaTek AT Debug engine message. Verify unauthorized engineering mode access.")
    end

    if tvb:len() > 5 then
        subtree:add(f_payload, tvb(5, tvb:len() - 5))
    end
end

-- Register to UDP port 5000 (common MTK Catcher / MobileLog stream port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(5000, mtk_diag_proto)
end
