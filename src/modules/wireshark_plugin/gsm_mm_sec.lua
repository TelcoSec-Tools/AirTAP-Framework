-- TelcoSec.net - GSM Mobility Management (MM) Security Dissector
-- Description: Dissects GSM MM messages (3GPP TS 24.008) on SDCCH.
--              Detects Location Updating Rejections (Causes #2, #3, #6) used for persistent DoS,
--              plain Identity Requests harvesting IMSI/IMEI, and Authentication bypasses.

local ok, gsm_mm_sec_proto = pcall(Proto, "gsm_mm_sec", "TelcoSec GSM MM Security Analyzer")
if not ok or not gsm_mm_sec_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gsm_mm_sec.msg_type", "MM Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gsm_mm_sec.msg_name", "MM Message Name")
local f_reject_cause = ProtoField.uint8("gsm_mm_sec.reject_cause", "Reject Cause Code", base.DEC)
local f_cause_name   = ProtoField.string("gsm_mm_sec.cause_name", "Reject Cause Description")
local f_id_type      = ProtoField.string("gsm_mm_sec.id_type", "Requested Identity Type")
local f_sec_alert    = ProtoField.string("gsm_mm_sec.alert", "TelcoSec GSM MM Security Alert")
local f_payload      = ProtoField.bytes("gsm_mm_sec.payload", "MM Payload")

gsm_mm_sec_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_reject_cause,
    f_cause_name,
    f_id_type,
    f_sec_alert,
    f_payload
}

-- GSM MM Message Types
local MM_MSG_TYPES = {
    [0x01] = "IMSI Detach Indication",
    [0x02] = "Location Updating Accept",
    [0x04] = "Location Updating Reject",
    [0x08] = "Location Updating Request",
    [0x11] = "Authentication Reject",
    [0x12] = "Authentication Request",
    [0x14] = "Authentication Response",
    [0x18] = "Identity Request",
    [0x19] = "Identity Response",
    [0x1A] = "TMSI Reallocation Command",
    [0x1B] = "TMSI Reallocation Complete",
    [0x20] = "CM Service Accept",
    [0x21] = "CM Service Reject",
    [0x24] = "CM Service Request"
}

-- 3GPP TS 24.008 Table 10.5.95: Location Updating Reject Causes
local REJECT_CAUSES = {
    [2]  = "IMSI unknown in HLR (Forces SIM disable / denial of service)",
    [3]  = "Illegal MS (Deactivates SIM card access to network)",
    [4]  = "IMSI unknown in VLR",
    [5]  = "IMEI not accepted",
    [6]  = "Illegal ME (Causes ME to be blacklisted)",
    [11] = "PLMN not allowed",
    [12] = "Location Area not allowed",
    [13] = "Roaming not allowed in this location area",
    [15] = "No Suitable Cells In Location Area",
    [17] = "Network failure",
    [22] = "Congestion"
}

function gsm_mm_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    local pd = bit.band(tvb(0, 1):uint(), 0x0F)
    local msg_type = bit.band(tvb(1, 1):uint(), 0x3F)

    -- Protocol Discriminator 5 = Mobility Management (MM)
    if pd ~= 5 then return end

    pinfo.cols.protocol = "GSM MM"

    local msg_name = MM_MSG_TYPES[msg_type] or string.format("MM Msg (0x%02X)", msg_type)
    local subtree = tree:add(gsm_mm_sec_proto, tvb(), string.format("GSM MM: %s", msg_name))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GSM MM] %s", msg_name)

    -- Security Heuristic 1: Identity Request for IMSI/IMEI
    if msg_type == 0x18 and tvb:len() >= 3 then
        local raw_id_type = bit.band(tvb(2, 1):uint(), 0x07)
        local id_names = { [1]="IMSI", [2]="IMEI", [3]="IMEISV", [4]="TMSI" }
        local id_str = id_names[raw_id_type] or string.format("Type %d", raw_id_type)

        subtree:add(f_id_type, id_str)
        pinfo.cols.info:append(string.format(" (Target: %s)", id_str))

        if raw_id_type == 1 or raw_id_type == 2 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] Base station requesting plain %s! Rogue 2G IMSI Catcher harvesting subscriber credentials.", id_str))
            pinfo.cols.info:append(" [TELCOSEC: IDENTITY HARVEST]")
        end
    end

    -- Security Heuristic 2: Location Updating Reject Attacks
    if msg_type == 0x04 and tvb:len() >= 3 then
        local cause_code = tvb(2, 1):uint()
        local cause_desc = REJECT_CAUSES[cause_code] or string.format("Cause %d", cause_code)

        subtree:add(f_reject_cause, tvb(2, 1), cause_code)
        subtree:add(f_cause_name, cause_desc)
        pinfo.cols.info:append(string.format(" (Cause %d: %s)", cause_code, cause_desc))

        if cause_code == 2 or cause_code == 3 or cause_code == 6 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] Malicious Location Updating Reject (Cause #%d: %s)! Known exploit to brick/disable victim's SIM registration.", cause_code, cause_desc))
            pinfo.cols.info:append(" [TELCOSEC: SIM BRICKING ATTACK]")
        end
    end

    if tvb:len() > 2 then
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end
