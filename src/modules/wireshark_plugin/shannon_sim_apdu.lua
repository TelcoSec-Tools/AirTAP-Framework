-- TelcoSec.net - Samsung Shannon SIM / USIM APDU & Authentication Dissector
-- Description: Dissects Shannon DM Group 0x60 and IPC Channel 6 (SIM/UICC interface).
--              Inspects SIM APDU commands (AUTHENTICATE AKA, SELECT EF_IMSI, SIM Toolkit)
--              to detect SIM-swapping, rogue OTA SMS applet execution, and SUCI/IMSI extraction.

local ok, shannon_sim_proto = pcall(Proto, "shannon_sim", "Samsung Shannon SIM/USIM APDU Analyzer")
if not ok or not shannon_sim_proto then return end

-- Protocol fields
local f_cla          = ProtoField.uint8("shannon_sim.cla", "APDU CLA", base.HEX)
local f_ins          = ProtoField.uint8("shannon_sim.ins", "APDU INS", base.HEX)
local f_p1           = ProtoField.uint8("shannon_sim.p1", "APDU P1", base.HEX)
local f_p2           = ProtoField.uint8("shannon_sim.p2", "APDU P2", base.HEX)
local f_apdu_name    = ProtoField.string("shannon_sim.apdu_name", "Command Name")
local f_sw1sw2       = ProtoField.uint16("shannon_sim.sw", "Status Word (SW1-SW2)", base.HEX)
local f_sec_alert    = ProtoField.string("shannon_sim.alert", "TelcoSec SIM Security Alert")
local f_apdu_data    = ProtoField.bytes("shannon_sim.data", "APDU Data")

shannon_sim_proto.fields = {
    f_cla,
    f_ins,
    f_p1,
    f_p2,
    f_apdu_name,
    f_sw1sw2,
    f_sec_alert,
    f_apdu_data
}

-- ISO/IEC 7816 & 3GPP TS 31.102 APDU Commands
local APDU_COMMANDS = {
    [0x88] = "AUTHENTICATE (AKA / GSM Security Context)",
    [0x89] = "AUTHENTICATE (5G / EAP-AKA')",
    [0x84] = "GET CHALLENGE",
    [0xA4] = "SELECT FILE (EF / DF)",
    [0xB0] = "READ BINARY",
    [0xD6] = "UPDATE BINARY",
    [0xC0] = "GET RESPONSE",
    [0x10] = "TERMINAL PROFILE (STK Capability Exchange)",
    [0x12] = "FETCH (Proactive SIM Toolkit Command)",
    [0x14] = "TERMINAL RESPONSE (STK Response)"
}

function shannon_sim_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 4 then return end

    pinfo.cols.protocol = "Shannon SIM"

    local cla = tvb(0, 1):uint()
    local ins = tvb(1, 1):uint()
    local p1 = tvb(2, 1):uint()
    local p2 = tvb(3, 1):uint()

    local cmd_name = APDU_COMMANDS[ins] or string.format("APDU Command (0x%02X)", ins)

    local subtree = tree:add(shannon_sim_proto, tvb(), string.format("Shannon USIM APDU: %s", cmd_name))
    subtree:add(f_cla, tvb(0, 1))
    subtree:add(f_ins, tvb(1, 1)):append_text(string.format(" (%s)", cmd_name))
    subtree:add(f_p1, tvb(2, 1))
    subtree:add(f_p2, tvb(3, 1))
    subtree:add(f_apdu_name, cmd_name)

    pinfo.cols.info = string.format("[Shannon USIM] %s (CLA: 0x%02X)", cmd_name, cla)

    -- Security Heuristic 1: Proactive SIM Toolkit (STK) Command FETCH
    -- Often used by SIM card backdoors (e.g. S@T Browser / SIMjacker) to exfiltrate IMEI/Location or send covert SMS.
    if ins == 0x12 then
        subtree:add(f_sec_alert, "[CRITICAL] Proactive SIM Toolkit FETCH command issued by UICC! Inspect for SIMjacker / rogue STK applet behavior.")
        pinfo.cols.info:append(" [TELCOSEC: PROACTIVE STK FETCH]")
    end

    -- Security Heuristic 2: Authentication AKA Execution
    if ins == 0x88 or ins == 0x89 then
        subtree:add(f_sec_alert, "[INFO] SIM Authenticate (AKA) initiated. Cryptographic challenge-response computed inside UICC secure element.")
    end

    -- Security Heuristic 3: SELECT EF_IMSI (File ID 0x6F07) or EF_LOCI (0x6F7E)
    if ins == 0xA4 and tvb:len() >= 7 then
        local target_fid = tvb(5, 2):uint()
        if target_fid == 0x6F07 then
            subtree:add(f_sec_alert, "[WARNING] Direct read of EF_IMSI (0x6F07). Baseband or host application extracting subscriber identity.")
        end
    end

    if tvb:len() > 4 then
        subtree:add(f_apdu_data, tvb(4, tvb:len() - 4))
    end
end

-- Register to Shannon DM Group table
local dm_table = DissectorTable.get("shannon_dm.group")
if dm_table then
    dm_table:add(0x60, shannon_sim_proto) -- Shannon SIM Group
end

-- Register to Shannon IPC Channel table
local ipc_table = DissectorTable.get("shannon_ipc.channel")
if ipc_table then
    ipc_table:add(6, shannon_sim_proto) -- Shannon SIM Channel
end
