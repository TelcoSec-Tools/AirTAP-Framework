-- TelcoSec.net - 5GS NAS (5G Mobility & Session Management) Security Dissector
-- Description: Dissects 5GS NAS signaling (3GPP TS 24.501) between 5G UE and AMF/SMF.
--              Detects plain SUPI / IMSI Identity Requests, SUCI de-anonymization bypasses,
--              malicious De-registration attacks, and forced 5G-to-4G downgrade rejections.

local ok, nas_5g_proto = pcall(Proto, "nas_5g_sec", "TelcoSec 5GS NAS (5GMM/5GSM) Security Analyzer")
if not ok or not nas_5g_proto then return end

-- Protocol fields
local f_sec_hdr_type = ProtoField.uint8("nas_5g_sec.sec_hdr_type", "Security Header Type", base.HEX)
local f_proto_disc   = ProtoField.uint8("nas_5g_sec.proto_disc", "Protocol Discriminator", base.HEX)
local f_msg_type     = ProtoField.uint8("nas_5g_sec.msg_type", "5GS NAS Message Type", base.HEX)
local f_msg_name     = ProtoField.string("nas_5g_sec.msg_name", "Message Name")
local f_5gmm_cause   = ProtoField.uint8("nas_5g_sec.5gmm_cause", "5GMM Cause Code", base.DEC)
local f_cause_desc   = ProtoField.string("nas_5g_sec.cause_desc", "Cause Description")
local f_id_type      = ProtoField.string("nas_5g_sec.id_type", "5GS Identity Type (SUPI/SUCI/5G-GUTI)")
local f_sec_alert    = ProtoField.string("nas_5g_sec.alert", "TelcoSec 5GS NAS Security Alert")
local f_payload      = ProtoField.bytes("nas_5g_sec.payload", "NAS Payload")

nas_5g_proto.fields = {
    f_sec_hdr_type,
    f_proto_disc,
    f_msg_type,
    f_msg_name,
    f_5gmm_cause,
    f_cause_desc,
    f_id_type,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 24.501 Table 9.7.1: 5GMM Message Types
local FGMM_MESSAGES = {
    [0x41] = "Registration Request",
    [0x42] = "Registration Accept",
    [0x43] = "Registration Complete",
    [0x44] = "Registration Reject",
    [0x45] = "Deregistration Request (UE-originating)",
    [0x46] = "Deregistration Accept (UE-originating)",
    [0x47] = "Deregistration Request (UE-terminated)",
    [0x48] = "Deregistration Accept (UE-terminated)",
    [0x4C] = "Service Request",
    [0x4D] = "Service Reject",
    [0x4E] = "Service Accept",
    [0x54] = "Control Plane Service Request",
    [0x56] = "Authentication Request",
    [0x57] = "Authentication Response",
    [0x58] = "Authentication Reject",
    [0x5B] = "Identity Request",
    [0x5C] = "Identity Response",
    [0x5D] = "Security Mode Command",
    [0x5E] = "Security Mode Complete",
    [0x5F] = "Security Mode Reject",
    [0x64] = "5GMM Status",
    [0x65] = "Notification",
    [0x66] = "Notification Response",
    [0x67] = "UL NAS Transport",
    [0x68] = "DL NAS Transport"
}

-- 3GPP TS 24.501 Table 9.11.3.2: 5GMM Cause Values
local FGMM_CAUSES = {
    [2]  = "Illegal UE (Forces SIM de-registration)",
    [3]  = "Illegal ME (IMEI blacklisted)",
    [5]  = "PEI not accepted",
    [7]  = "5GS services not allowed (Forces downgrade to 4G/3G/2G)",
    [8]  = "5GS services and non-5GS services not allowed (Total cellular disconnection)",
    [9]  = "UE identity cannot be derived by the network",
    [10] = "Implicitly deregistered",
    [11] = "PLMN not allowed",
    [12] = "Tracking Area not allowed",
    [13] = "Roaming not allowed in this tracking area",
    [14] = "5GS services not allowed in this PLMN (Forces 4G/2G downgrade)",
    [15] = "No Suitable Cells In tracking area",
    [22] = "Congestion",
    [27] = "N1 mode not allowed (Forces 4G fallback)"
}

-- Native 5GS NAS dissector
local nas_5gs_dissector = Dissector.get("nas-5gs")

function nas_5g_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "5GS NAS"

    local byte0 = tvb(0, 1):uint()
    local sec_hdr = bit.rshift(byte0, 4)
    local proto_disc = bit.band(byte0, 0x0F)

    local sec_hdr_names = {
        [0] = "Plain 5GS NAS message (Not security protected)",
        [1] = "Integrity protected",
        [2] = "Integrity protected and ciphered",
        [3] = "Integrity protected with new 5GS security context",
        [4] = "Integrity protected and ciphered with new 5GS security context"
    }
    local sec_hdr_str = sec_hdr_names[sec_hdr] or string.format("Sec Type %d", sec_hdr)

    local subtree = tree:add(nas_5g_proto, tvb(), string.format("5GS NAS Security: %s", sec_hdr_str))
    subtree:add(f_sec_hdr_type, tvb(0, 1), sec_hdr):append_text(string.format(" (%s)", sec_hdr_str))
    subtree:add(f_proto_disc, tvb(0, 1), proto_disc)

    local msg_offset = (sec_hdr == 0) and 1 or 7
    if tvb:len() > msg_offset then
        local msg_type = tvb(msg_offset, 1):uint()
        local msg_name = FGMM_MESSAGES[msg_type] or string.format("5GS Msg (0x%02X)", msg_type)

        subtree:add(f_msg_type, tvb(msg_offset, 1), msg_type)
        subtree:add(f_msg_name, msg_name)
        pinfo.cols.info = string.format("[5GS NAS] %s (%s)", msg_name, sec_hdr_str)

        -- Security Heuristic 1: Plain Identity Request probing for SUPI (5G IMSI Catcher / Fake gNB)
        if msg_type == 0x5B and tvb:len() > (msg_offset + 1) then
            local raw_id = bit.band(tvb(msg_offset + 1, 1):uint(), 0x07)
            local id_names = { [1]="SUPI (IMSI)", [2]="5G-GUTI", [3]="IMEI", [4]="5G-S-TMSI", [5]="IMEISV", [6]="SUCI" }
            local id_str = id_names[raw_id] or string.format("Type %d", raw_id)
            subtree:add(f_id_type, id_str)

            if raw_id == 1 or raw_id == 3 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] Unprotected 5GS Identity Request querying plain %s! 5G IMSI Catcher probing attack bypassing SUCI encryption.", id_str))
                pinfo.cols.info:append(" [TELCOSEC: SUPI HARVEST PROBE!]")
            end
        end

        -- Security Heuristic 2: Registration Reject / 5GMM Reject with Cause #7 / #14 / #27 (Forced 4G/2G Downgrade)
        if (msg_type == 0x44 or msg_type == 0x4D) and tvb:len() > (msg_offset + 1) then
            local cause = tvb(msg_offset + 1, 1):uint()
            local cause_desc = FGMM_CAUSES[cause] or string.format("Cause %d", cause)

            subtree:add(f_5gmm_cause, tvb(msg_offset + 1, 1), cause)
            subtree:add(f_cause_desc, cause_desc)

            if cause == 7 or cause == 14 or cause == 27 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] Malicious 5GMM Reject (Cause #%d: %s)! Exploited by 5G Stingrays to disable 5G SA and force victim down to legacy 4G/2G.", cause, cause_desc))
                pinfo.cols.info:append(" [TELCOSEC: 5G DOWNGRADE INJECTION!]")
            elseif cause == 2 or cause == 3 or cause == 8 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] SIM Bricking 5GMM Reject (Cause #%d: %s)!", cause, cause_desc))
            end
        end

        -- Security Heuristic 3: Network-Initiated Deregistration Request (DoS injection)
        if msg_type == 0x47 and sec_hdr == 0 then
            subtree:add(f_sec_alert, "[CRITICAL] Unprotected Network-Initiated Deregistration Request! Forcibly disconnects 5G subscriber from the network.")
            pinfo.cols.info:append(" [TELCOSEC: DEREGISTRATION INJECTION!]")
        end
    end

    if nas_5gs_dissector then
        nas_5gs_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register as postdissector to audit all 5GS NAS signaling
register_postdissector(nas_5g_proto)
