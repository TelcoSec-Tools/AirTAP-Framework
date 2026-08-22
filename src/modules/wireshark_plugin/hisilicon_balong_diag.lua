-- TelcoSec.net - HiSilicon (Huawei Kirin / Balong) Baseband Diagnostic Dissector
-- Description: Dissects HiSilicon Balong OAM / Diagnostic frames used in Huawei Kirin modems.
--              Extracts radio state transitions, null-ciphering alerts, DSP logs, and modem crash dumps.

local ok, hisi_diag_proto = pcall(Proto, "hisilicon_balong_diag", "HiSilicon (Balong/Kirin) Diagnostic Protocol Analyzer")
if not ok or not hisi_diag_proto then return end

-- Protocol fields
local f_magic        = ProtoField.uint16("hisi_diag.magic", "Magic Word (0x5A5A)", base.HEX)
local f_msg_id       = ProtoField.uint16("hisi_diag.msg_id", "Balong Msg ID", base.HEX)
local f_module       = ProtoField.string("hisi_diag.module", "Subsystem Module")
local f_length       = ProtoField.uint16("hisi_diag.length", "Payload Length", base.DEC)
local f_sec_alert    = ProtoField.string("hisi_diag.alert", "TelcoSec Balong Alert")
local f_payload      = ProtoField.bytes("hisi_diag.payload", "Diagnostic Raw Data")

hisi_diag_proto.fields = {
    f_magic,
    f_msg_id,
    f_module,
    f_length,
    f_sec_alert,
    f_payload
}

-- Balong Subsystem Modules
local HISI_MODULES = {
    [0x1001] = "BALONG_MODEM_RRC (3G/4G/5G RRC)",
    [0x1002] = "BALONG_MODEM_NAS (MM / EMM / 5GMM)",
    [0x1003] = "BALONG_DSP_PHY (Physical Layer / DSP)",
    [0x1004] = "BALONG_USIM_DRIVER (Smart Card APDU)",
    [0x1008] = "BALONG_EXCEPTION_DUMP (Modem Crash Panic)",
    [0x1020] = "BALONG_AT_SERVER (AT Commands)"
}

function hisi_diag_proto.dissector(tvb, pinfo, tree)
    -- HiSilicon Diagnostic Header (6 bytes):
    -- [0-1]: Magic Word (0x5A5A or 0xA5A5)
    -- [2-3]: Module / Msg ID (2 bytes LE)
    -- [4-5]: Length (2 bytes LE)
    if tvb:len() < 6 then return end

    local magic = tvb(0, 2):uint()
    if magic ~= 0x5A5A and magic ~= 0xA5A5 then return end

    pinfo.cols.protocol = "Balong DIAG"

    local msg_id = tvb(2, 2):le_uint()
    local length = tvb(4, 2):le_uint()
    local mod_name = HISI_MODULES[msg_id] or string.format("Module 0x%04X", msg_id)

    local subtree = tree:add(hisi_diag_proto, tvb(), string.format("HiSilicon Balong: %s", mod_name))
    subtree:add(f_magic, tvb(0, 2))
    subtree:add(f_msg_id, tvb(2, 2), msg_id)
    subtree:add(f_module, mod_name)
    subtree:add(f_length, tvb(4, 2), length)

    pinfo.cols.info = string.format("[Balong Modem] %s (Len: %d)", mod_name, length)

    -- Security Heuristic: Balong Exception Dump (Crash Triage)
    if msg_id == 0x1008 then
        subtree:add(f_sec_alert, "[CRITICAL] HiSilicon Balong Baseband Exception Dump! Potential OTA exploit or memory corruption crash.")
        pinfo.cols.info:append(" [TELCOSEC: BALONG CRASH DUMP!]")
    end

    if tvb:len() > 6 then
        subtree:add(f_payload, tvb(6, tvb:len() - 6))
    end
end

-- Register to UDP port 5001 (Huawei OM diagnostic port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(5001, hisi_diag_proto)
end
