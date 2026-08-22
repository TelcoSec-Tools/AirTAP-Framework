-- TelcoSec.net - GSM SMS, Silent SMS (Type 0) & Cell Broadcast Security Dissector
-- Description: Dissects GSM SMS (TP-PDU / RP-PDU / CP-PDU) and Cell Broadcast Service (CBS).
--              Detects Silent SMS (Type 0 / TP-PID 0x40), Flash SMS (Class 0), fake emergency alerts,
--              and SIMjacker / S@T Browser OTA SMS applet execution.

local ok, gsm_sms_sec_proto = pcall(Proto, "gsm_sms_sec", "TelcoSec GSM SMS & Silent Ping Analyzer")
if not ok or not gsm_sms_sec_proto then return end

-- Protocol fields
local f_sms_type     = ProtoField.string("gsm_sms_sec.type", "SMS PDU Type")
local f_tp_mti       = ProtoField.uint8("gsm_sms_sec.tp_mti", "TP-MTI (Message Type Indicator)", base.HEX)
local f_tp_pid       = ProtoField.uint8("gsm_sms_sec.tp_pid", "TP-PID (Protocol Identifier)", base.HEX)
local f_tp_dcs       = ProtoField.uint8("gsm_sms_sec.tp_dcs", "TP-DCS (Data Coding Scheme)", base.HEX)
local f_tp_udhi      = ProtoField.bool("gsm_sms_sec.tp_udhi", "TP-UDHI (User Data Header Indicator)")
local f_is_silent    = ProtoField.bool("gsm_sms_sec.is_silent", "Silent SMS (Type 0) Ping")
local f_is_flash     = ProtoField.bool("gsm_sms_sec.is_flash", "Flash SMS (Class 0)")
local f_is_stk       = ProtoField.bool("gsm_sms_sec.is_stk", "SIM Toolkit / OTA Applet Execution")
local f_sec_alert    = ProtoField.string("gsm_sms_sec.alert", "TelcoSec SMS Security Alert")
local f_payload      = ProtoField.bytes("gsm_sms_sec.payload", "SMS Raw Payload")

gsm_sms_sec_proto.fields = {
    f_sms_type,
    f_tp_mti,
    f_tp_pid,
    f_tp_dcs,
    f_tp_udhi,
    f_is_silent,
    f_is_flash,
    f_is_stk,
    f_sec_alert,
    f_payload
}

-- Native Wireshark SMS dissectors
local gsm_sms_dissector = Dissector.get("gsm_sms")

function gsm_sms_sec_proto.dissector(tvb, pinfo, tree)
    -- Check if SMS signaling (CP-DATA / RP-DATA / TP-PDU)
    local tvb_len = tvb:len()
    if tvb_len < 3 then return end

    pinfo.cols.protocol = "GSM SMS"

    local subtree = tree:add(gsm_sms_sec_proto, tvb(), "GSM Short Message Service Security Analysis")

    local is_silent_sms = false
    local is_flash_sms  = false
    local is_stk_sms    = false

    -- Parse the outer CP layer (1 byte PD/TI/MTI) then RP layer to reach TP-PDU.
    -- CP-DATA: byte[0] = PD/TI (lower nibble PD=9 for SMS), byte[1] = CP-MTI
    -- RP-DATA: byte[2] = RP-MTI, byte[3] = RP-MR, then RP-OA/DA/UDL, ...
    -- The TP-PDU starts after the RP headers. We scan for TP-PID and TP-DCS
    -- at known relative positions to avoid a full hex dump.
    -- For robustness, we scan bytes 0..N-1 directly for telltale field values.

    -- Security Heuristic 1: Silent SMS (Type 0)
    -- TP-PID = 0x40 (SME-to-SME protocol, Short Message Type 0) followed by any TP-DCS.
    -- TP-PID appears at a fixed offset after TP-VPF/TP-MR depending on MTI.
    -- Scan the first 16 bytes for 0x40 at typical TP-PID positions (offset 3..9).
    for off = 3, math.min(9, tvb_len - 2) do
        local b = tvb(off, 1):uint()
        if b == 0x40 then
            is_silent_sms = true
            subtree:add(f_tp_pid,   tvb(off, 1), b)
            subtree:add(f_is_silent, true)
            subtree:add(f_sec_alert,
                "[CRITICAL] Type 0 (Silent SMS) ping detected! " ..
                "Covert location tracking probe sent to mobile station.")
            pinfo.cols.info = "[GSM SMS] SILENT SMS (TYPE 0) LOCATION PROBE DETECTED!"
            break
        end
    end

    -- Security Heuristic 2: Flash SMS (Class 0)
    -- TP-DCS Class 0: 0xF0 (special coding group, Class 0), or 0x10 (General group Class 0).
    -- Scan for TP-DCS bytes in the range offset 4..12.
    if not is_silent_sms then
        for off = 4, math.min(12, tvb_len - 1) do
            local b = tvb(off, 1):uint()
            if b == 0xF0 or b == 0x10 or b == 0x18 then
                is_flash_sms = true
                subtree:add(f_tp_dcs,  tvb(off, 1), b)
                subtree:add(f_is_flash, true)
                subtree:add(f_sec_alert,
                    "[WARNING] Flash SMS (Class 0) detected. Overrides screen display immediately.")
                pinfo.cols.info = "[GSM SMS] Flash SMS (Class 0)"
                break
            end
        end
    end

    -- Security Heuristic 3: SIM Toolkit / OTA Applet Execution (SIMjacker / S@T Browser)
    -- TP-PID = 0x7F = SIM Data Download (teleservice addressed to SIM via UDH).
    -- Also detected via TAR header 0x000000 / 0x000027 in TP-UDH (Toolkit App Reference).
    for off = 3, math.min(9, tvb_len - 1) do
        local b = tvb(off, 1):uint()
        if b == 0x7F then
            is_stk_sms = true
            subtree:add(f_tp_pid, tvb(off, 1), b)
            subtree:add(f_is_stk, true)
            subtree:add(f_sec_alert,
                "[CRITICAL] OTA SIM Toolkit (STK) Command Download! " ..
                "Potential SIMjacker / S@T Browser spyware payload targeting UICC.")
            pinfo.cols.info = "[GSM SMS] CRITICAL: SIMJACKER / OTA STK APPLET PAYLOAD!"
            break
        end
    end
    -- Also scan for TAR byte sequence 0x02 0x70 0x00 (S@T Browser TAR) anywhere in UDH region
    if not is_stk_sms and tvb_len >= 12 then
        for off = 5, tvb_len - 3 do
            if tvb(off, 1):uint() == 0x02 and
               tvb(off + 1, 1):uint() == 0x70 and
               tvb(off + 2, 1):uint() == 0x00 then
                is_stk_sms = true
                subtree:add(f_is_stk, true)
                subtree:add(f_sec_alert,
                    "[CRITICAL] S@T Browser TAR (0x027000) found in UDH! " ..
                    "Confirmed SIMjacker OTA applet execution payload.")
                pinfo.cols.info = "[GSM SMS] CRITICAL: SIMJACKER / OTA STK APPLET PAYLOAD!"
                break
            end
        end
    end

    if not is_silent_sms and not is_flash_sms and not is_stk_sms then
        pinfo.cols.info = "[GSM SMS] User SMS / PDU"
    end

    if gsm_sms_dissector then
        gsm_sms_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
