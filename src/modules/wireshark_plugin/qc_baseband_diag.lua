-- TelcoSec.net - Qualcomm Baseband Diagnostics, FTM & Crash Triage Dissector
-- Description: Dissects Qualcomm Diagnostic Subsystem Commands (0x75), Factory Test Mode (FTM),
--              and Modem Subsystem Restart (SSR) / Error Log Items (0x1000-0x1FFF).
--              Essential for Over-The-Air Baseband Fuzzing, exploit triage, and RF override monitoring.

local ok, qc_bb_diag_proto = pcall(Proto, "qc_bb_diag", "Qualcomm Baseband Diagnostics & Crash Triage")
if not ok or not qc_bb_diag_proto then return end

-- Protocol fields
local f_diag_type    = ProtoField.string("qc_bb_diag.type", "Diagnostic Event Type")
local f_subsystem    = ProtoField.string("qc_bb_diag.subsystem", "Baseband Subsystem")
local f_fault_addr   = ProtoField.uint32("qc_bb_diag.fault_addr", "Fault PC / Memory Address", base.HEX)
local f_crash_msg    = ProtoField.string("qc_bb_diag.crash_msg", "Crash / Assertion Message")
local f_ftm_cmd_id   = ProtoField.uint16("qc_bb_diag.ftm_cmd", "FTM Command ID", base.HEX)
local f_sec_alert    = ProtoField.string("qc_bb_diag.alert", "TelcoSec Fuzzing & Exploit Alert")
local f_raw_dump     = ProtoField.bytes("qc_bb_diag.raw_dump", "Raw Diagnostic Dump")

qc_bb_diag_proto.fields = {
    f_diag_type,
    f_subsystem,
    f_fault_addr,
    f_crash_msg,
    f_ftm_cmd_id,
    f_sec_alert,
    f_raw_dump
}

-- FTM (Factory Test Mode) Command Types
local FTM_COMMANDS = {
    [0x0000] = "FTM_RF_COMMAND",
    [0x0001] = "FTM_GSM_BER",
    [0x0002] = "FTM_WCDMA_BER",
    [0x0004] = "FTM_LTE_BER",
    [0x0006] = "FTM_1X_CALIBRATION",
    [0x0007] = "FTM_RAW_RF_TX_ENABLE",
    [0x0008] = "FTM_FREQUENCY_SYNTHESIZER_OVERRIDE"
}

function qc_bb_diag_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "QC Baseband"

    local subtree = tree:add(qc_bb_diag_proto, tvb(), "Qualcomm Baseband Diagnostic Event")
    local first_byte = tvb(0, 1):uint()

    -- Check if it's an FTM command payload
    if tvb:len() >= 4 and first_byte == 0x08 then -- Subsystem 8 = FTM
        local ftm_cmd = tvb(2, 2):le_uint()
        local ftm_name = FTM_COMMANDS[ftm_cmd] or string.format("FTM Cmd 0x%04X", ftm_cmd)

        subtree:add(f_diag_type, "Factory Test Mode (FTM) Dispatch")
        subtree:add(f_subsystem, "RF / Transceiver Engine")
        subtree:add(f_ftm_cmd_id, tvb(2, 2))

        pinfo.cols.info = string.format("[QC FTM] %s", ftm_name)

        if ftm_cmd == 0x0007 or ftm_cmd == 0x0008 then
            subtree:add(f_sec_alert, "[CRITICAL] Direct RF Transmission Override commanded. Verify modem is within shielded RF enclosure!")
        end
    else
        -- Baseband Crash / SSR / Assertion Log Item (0x1000 - 0x1FFF series)
        subtree:add(f_diag_type, "Modem Core Assertion / Crash Log")
        subtree:add(f_subsystem, "Hexagon DSP (QDSP6 / Modem Core)")

        if tvb:len() >= 8 then
            local fault_pc = tvb(0, 4):le_uint()
            subtree:add(f_fault_addr, tvb(0, 4), fault_pc)

            -- Extract ASCII assertion string if present
            local msg_len = math.min(tvb:len() - 4, 128)
            if msg_len > 0 then
                local raw_str = tvb(4, msg_len):string()
                -- Clean printable characters
                local clean_str = string.gsub(raw_str, "[^%w%s%p]", ".")
                subtree:add(f_crash_msg, clean_str)
                pinfo.cols.info = string.format("[QC BASEBAND CRASH] Fault PC: 0x%08X | %s", fault_pc, clean_str)
            else
                pinfo.cols.info = string.format("[QC BASEBAND CRASH] Fault PC: 0x%08X", fault_pc)
            end

            subtree:add(f_sec_alert, "[CRITICAL] Baseband Crash / Exception Detected! Possible air-interface RCE or memory corruption during fuzzing.")
            pinfo.cols.info:append(" [TELCOSEC: MODEM CRASH DETECTED]")
        else
            pinfo.cols.info = "[QC DIAG] Baseband Diagnostic Event"
            subtree:add(f_raw_dump, tvb())
        end
    end
end

-- Register to Qualcomm DIAG Log Code table for crash/error/event codes
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x1000, qc_bb_diag_proto) -- Error Logs
    qc_log_table:add(0x1004, qc_bb_diag_proto) -- Core Assertion
    qc_log_table:add(0x11EB, qc_bb_diag_proto) -- SSR Event
    qc_log_table:add(0x199A, qc_bb_diag_proto) -- Hexagon DSP Crash Dump
end
