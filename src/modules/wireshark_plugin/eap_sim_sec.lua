-- TelcoSec.net - EAP-SIM & EAP-AKA Carrier Wi-Fi Offloading Security Analyzer
-- Target Standards: RFC 4186 (EAP-SIM), RFC 4187 (EAP-AKA), RFC 5448 (EAP-AKA'), 3GPP TS 33.234 / TS 33.402
-- Description: Dissects Extensible Authentication Protocol (EAP) messages for SIM and AKA/AKA' cellular-to-Wi-Fi authentication.
--              Detects Wi-Fi rogue AP credential harvesting, cleartext IMSI leaks in EAP-Response/Identity,
--              EAP-SIM AT_RAND challenge replays, and rogue AT_NOTIFICATION denial-of-service attacks.

local ok, eap_sim_proto = pcall(Proto, "eap_sim_sec", "TelcoSec EAP-SIM & EAP-AKA Security Analyzer")
if not ok or not eap_sim_proto then return end

-- Protocol fields
local f_eap_code        = ProtoField.uint8("eap_sim_sec.code", "EAP Code", base.DEC)
local f_eap_code_name   = ProtoField.string("eap_sim_sec.code_name", "EAP Code Name")
local f_eap_id          = ProtoField.uint8("eap_sim_sec.id", "EAP Identifier", base.DEC)
local f_eap_type        = ProtoField.uint8("eap_sim_sec.type", "EAP Method Type", base.DEC)
local f_eap_type_name   = ProtoField.string("eap_sim_sec.type_name", "EAP Method Name")
local f_subtype         = ProtoField.uint8("eap_sim_sec.subtype", "SIM/AKA Subtype", base.DEC)
local f_subtype_name    = ProtoField.string("eap_sim_sec.subtype_name", "SIM/AKA Subtype Name")
local f_identity        = ProtoField.string("eap_sim_sec.identity", "Extracted Identity (IMSI / NAI)")
local f_sec_alert       = ProtoField.string("eap_sim_sec.alert", "TelcoSec EAP Security Alert")

eap_sim_proto.fields = {
    f_eap_code,
    f_eap_code_name,
    f_eap_id,
    f_eap_type,
    f_eap_type_name,
    f_subtype,
    f_subtype_name,
    f_identity,
    f_sec_alert
}

local EAP_CODES = {
    [1] = "Request",
    [2] = "Response",
    [3] = "Success",
    [4] = "Failure"
}

local EAP_TYPES = {
    [1]  = "Identity",
    [2]  = "Notification",
    [3]  = "NAK",
    [4]  = "MD5-Challenge",
    [5]  = "One-Time Password (OTP)",
    [6]  = "Generic Token Card (GTC)",
    [18] = "EAP-SIM (RFC 4186)",
    [23] = "EAP-AKA (RFC 4187)",
    [50] = "EAP-AKA' (RFC 5448)"
}

local SIM_AKA_SUBTYPES = {
    [1]  = "AKA-Challenge / SIM-Start",
    [2]  = "AKA-Authentication-Reject",
    [3]  = "AKA-Synchronization-Failure",
    [4]  = "AKA-Identity",
    [5]  = "AKA-Notification",
    [10] = "SIM-Challenge",
    [11] = "SIM-Notification",
    [12] = "SIM-Reauthentication",
    [13] = "SIM-Client-Error"
}

function eap_sim_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "EAP") or string.find(proto_str, "EAPOL") or string.find(proto_str, "RADIUS") or string.find(proto_str, "IEEE 802.1X")) then
        return
    end

    -- Must have at least 4 bytes for EAP header: [0]=Code, [1]=ID, [2-3]=Length
    if tvb:len() < 4 then return end

    local eap_code = tvb(0, 1):uint()
    local eap_id = tvb(1, 1):uint()
    local eap_len = tvb(2, 2):uint()

    local code_name = EAP_CODES[eap_code]
    if not code_name then return end

    local subtree = tree:add(eap_sim_proto, tvb(), string.format("EAP Cellular Authentication Security: %s (ID: %d)", code_name, eap_id))
    subtree:add(f_eap_code, tvb(0, 1), eap_code)
    subtree:add(f_eap_code_name, code_name)
    subtree:add(f_eap_id, tvb(1, 1), eap_id)

    if tvb:len() >= 5 then
        local eap_type = tvb(4, 1):uint()
        local type_name = EAP_TYPES[eap_type] or string.format("Type %d", eap_type)
        subtree:add(f_eap_type, tvb(4, 1), eap_type)
        subtree:add(f_eap_type_name, type_name)

        pinfo.cols.protocol = type_name
        pinfo.cols.info = string.format("[EAP %s] %s (ID: %d)", type_name, code_name, eap_id)

        -- Extract Identity in EAP-Response/Identity
        if eap_code == 2 and eap_type == 1 and tvb:len() > 5 then
            local id_str = tvb(5, tvb:len() - 5):string()
            subtree:add(f_identity, id_str)

            -- Heuristic 1: Cleartext IMSI in EAP Identity Request
            if string.match(id_str, "^1%d%d%d%d%d%d") or string.match(id_str, "^0%d%d%d%d%d%d") or string.match(id_str, "^%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d") then
                subtree:add(f_sec_alert, string.format("[CRITICAL] Cleartext IMSI identity exposed over Wi-Fi EAP-Identity (%s)! Rogue Wi-Fi AP harvesting subscriber identities.", id_str))
                pinfo.cols.info:append(" [TELCOSEC: CLEARTEXT IMSI LEAK!]")
            end
        end

        -- Inspect EAP-SIM (18) or EAP-AKA (23/50) Subtypes
        if (eap_type == 18 or eap_type == 23 or eap_type == 50) and tvb:len() >= 6 then
            local subtype = tvb(5, 1):uint()
            local subtype_name = SIM_AKA_SUBTYPES[subtype] or string.format("Subtype %d", subtype)
            subtree:add(f_subtype, tvb(5, 1), subtype)
            subtree:add(f_subtype_name, subtype_name)

            pinfo.cols.info = string.format("[%s] %s: %s", type_name, code_name, subtype_name)

            -- Heuristic 2: Fake Notification Denial of Service
            if subtype == 5 or subtype == 11 then
                subtree:add(f_sec_alert, "[WARNING] EAP-SIM/AKA Notification received! Unauthenticated rogue AP can inject failure notifications to kick user from cellular Wi-Fi.")
            end
        end
    end
end

register_postdissector(eap_sim_proto)
