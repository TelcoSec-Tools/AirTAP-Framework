-- TelcoSec.net - Access Point Name (APN) & 5G Data Network Name (DNN) Security Analyzer
-- Target Standards: 3GPP TS 23.003 (Numbering/Addressing), TS 23.060 (GPRS), TS 23.401 (LTE EPS), TS 23.501 (5GS), TS 29.274 (GTPv2-C)
-- Description: Cross-protocol security dissector inspecting APN and DNN parameters across 2G/3G/4G/5G NAS, GTP, Diameter, and RADIUS.
--              Deconstructs Network/Operator IDs, audits carrier administrative APNs (IMS/SOS/XCAP), enforces APN Restriction Levels,
--              flags rogue proxy/MitM APNs, and verifies 5G Network Slice (S-NSSAI SST/SD) isolation.

local ok, apn_dnn_proto = pcall(Proto, "apn_dnn_sec", "TelcoSec APN & 5G DNN Telecom Security Analyzer")
if not ok or not apn_dnn_proto then return end

-- Protocol fields
local f_raw_apn        = ProtoField.string("apn_dnn_sec.raw_apn", "Raw APN / DNN String")
local f_net_id         = ProtoField.string("apn_dnn_sec.net_id", "APN Network Identifier (NI)")
local f_op_id          = ProtoField.string("apn_dnn_sec.op_id", "APN Operator Identifier (OI)")
local f_mcc            = ProtoField.string("apn_dnn_sec.mcc", "Extracted Mobile Country Code (MCC)")
local f_mnc            = ProtoField.string("apn_dnn_sec.mnc", "Extracted Mobile Network Code (MNC)")
local f_apn_category   = ProtoField.string("apn_dnn_sec.category", "APN Category / Profile")
local f_restr_level    = ProtoField.string("apn_dnn_sec.restr_level", "3GPP APN Restriction Level")
local f_pdn_type       = ProtoField.string("apn_dnn_sec.pdn_type", "PDN / PDU Session Type")
local f_s_nssai_sst    = ProtoField.uint8("apn_dnn_sec.sst", "5G Slice Service Type (SST)", base.DEC)
local f_s_nssai_sd     = ProtoField.uint32("apn_dnn_sec.sd", "5G Slice Differentiator (SD)", base.HEX)
local f_slice_desc     = ProtoField.string("apn_dnn_sec.slice_desc", "5G Network Slice Profile")
local f_sec_alert      = ProtoField.string("apn_dnn_sec.alert", "TelcoSec APN/DNN Security Alert")

apn_dnn_proto.fields = {
    f_raw_apn,
    f_net_id,
    f_op_id,
    f_mcc,
    f_mnc,
    f_apn_category,
    f_restr_level,
    f_pdn_type,
    f_s_nssai_sst,
    f_s_nssai_sd,
    f_slice_desc,
    f_sec_alert
}

-- Safe field getter helper
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

-- Protocol field extractors across network layers
local f_gsm_apn_f      = safe_field("gsm_a.sm.apn") or safe_field("gsm_a.dtap.apn")
local f_lte_apn_f      = safe_field("nas_eps.esm.access_point_name") or safe_field("nas-eps.esm.access_point_name") or safe_field("nas_eps.esm.apn")
local f_lte_pdn_f      = safe_field("nas_eps.esm.pdn_type") or safe_field("nas-eps.esm.pdn_type")
local f_nr_dnn_f       = safe_field("nas_5gs.sm.dnn") or safe_field("nas-5gs.sm.dnn") or safe_field("nas_5gs.dnn")
local f_nr_pdu_type_f  = safe_field("nas_5gs.sm.pdu_session_type") or safe_field("nas-5gs.sm.pdu_session_type")
local f_nr_sst_f       = safe_field("nas_5gs.sm.s_nssai_sst") or safe_field("nas-5gs.sm.s_nssai_sst")
local f_nr_sd_f        = safe_field("nas_5gs.sm.s_nssai_sd") or safe_field("nas-5gs.sm.s_nssai_sd")
local f_gtp_apn_f      = safe_field("gtp.apn") or safe_field("gtpv2.apn")
local f_gtp_restr_f    = safe_field("gtpv2.apn_restriction")
local f_diam_apn_f     = safe_field("diameter.Service-Selection") or safe_field("diameter.Called-Station-Id")
local f_rad_apn_f      = safe_field("radius.Called_Station_Id")

-- 3GPP APN Restriction Levels (TS 29.274 Section 8.57)
local APN_RESTRICTION_NAMES = {
    [0] = "No Restriction (Level 0)",
    [1] = "Public-1 / General Internet (Level 1)",
    [2] = "Public-2 / Operator Multimedia/MMS (Level 2)",
    [3] = "Private-1 / Corporate Intranet VPN (Level 3)",
    [4] = "Private-2 / Core Network Infrastructure (Level 4)"
}

-- 5G Standardized Slice/Service Types (SST - 3GPP TS 23.501 Table 5.15.2.2-1)
local SST_NAMES = {
    [1] = "eMBB (Enhanced Mobile Broadband)",
    [2] = "URLLC (Ultra-Reliable Low-Latency)",
    [3] = "MIoT (Massive IoT)",
    [4] = "V2X (Vehicle-to-Everything)",
    [5] = "HMTC (High-Performance Machine-Type)"
}

-- Known Carrier Infrastructure & Administrative APNs
local CARRIER_ADMIN_APNS = {
    ["ims"]             = "VoLTE / VoNR Core Signaling & Media Bearer",
    ["sos"]             = "Emergency Call PDN (E911 / E112 Bearer)",
    ["emergency"]       = "Emergency Call PDN (3GPP TS 23.167)",
    ["xcap"]            = "XCAP Supplementary Services Configuration (Ut Interface)",
    ["bsf"]             = "Bootstrapping Server Function (GBA Authentication)",
    ["mms"]             = "Multimedia Messaging Service Bearer",
    ["rcs"]             = "Rich Communication Services Cloud Gateway",
    ["internal.admin"]  = "Carrier Private Maintenance & Baseband Management",
    ["ota"]             = "Over-The-Air Device Management (DM / TR-069)",
    ["provisioning"]    = "Carrier SIM/eSIM Remote Provisioning Gateway"
}

-- Known Malicious / Rogue / Proxy APNs
local ROGUE_APN_KEYWORDS = {
    "proxy", "hack", "free", "admob", "ctmail", "adblock", "tunnel", "traffic", "rogue", "phish", "redirect"
}

function apn_dnn_proto.dissector(tvb, pinfo, tree)
    -- Step 1: Extract APN / DNN from various protocol layers
    local apn_str = nil
    local src_layer = "Unknown"

    if f_lte_apn_f and f_lte_apn_f() then
        apn_str = tostring(f_lte_apn_f().value)
        src_layer = "4G LTE NAS (ESM)"
    elseif f_nr_dnn_f and f_nr_dnn_f() then
        apn_str = tostring(f_nr_dnn_f().value)
        src_layer = "5G NR NAS (5GSM)"
    elseif f_gsm_apn_f and f_gsm_apn_f() then
        apn_str = tostring(f_gsm_apn_f().value)
        src_layer = "2G/3G GPRS (SM)"
    elseif f_gtp_apn_f and f_gtp_apn_f() then
        apn_str = tostring(f_gtp_apn_f().value)
        src_layer = "GTP Control Plane"
    elseif f_diam_apn_f and f_diam_apn_f() then
        apn_str = tostring(f_diam_apn_f().value)
        src_layer = "Diameter Core Interface"
    elseif f_rad_apn_f and f_rad_apn_f() then
        apn_str = tostring(f_rad_apn_f().value)
        src_layer = "RADIUS Authentication"
    end

    if not apn_str or apn_str == "" then
        return
    end

    -- Step 2: APN Parsing & Decomposition (TS 23.003)
    local net_id = apn_str
    local op_id = nil
    local mcc = nil
    local mnc = nil

    -- Match 3GPP FQDN format: <NI>.mnc<MNC>.mcc<MCC>.gprs
    local mnc_match, mcc_match = string.match(string.lower(apn_str), "%.mnc(%d+)%.mcc(%d+)%.gprs")
    if mnc_match and mcc_match then
        mnc = mnc_match
        mcc = mcc_match
        op_id = string.format("MNC %s, MCC %s", mnc, mcc)
        local idx = string.find(string.lower(apn_str), "%.mnc%d+%.mcc%d+%.gprs")
        if idx and idx > 1 then
            net_id = string.sub(apn_str, 1, idx - 1)
        end
    end

    local lower_net_id = string.lower(net_id)
    local alerts = {}

    -- Step 3: Build Dissection Tree
    local subtree = tree:add(apn_dnn_proto, tvb(), string.format("TelcoSec APN/DNN Security: '%s' (%s)", apn_str, src_layer))
    subtree:add(f_raw_apn, apn_str)
    subtree:add(f_net_id, net_id)

    if op_id then
        subtree:add(f_op_id, op_id)
        subtree:add(f_mcc, mcc)
        subtree:add(f_mnc, mnc)
    end

    -- Step 4: Carrier Infrastructure / Admin APN Check
    local admin_desc = CARRIER_ADMIN_APNS[lower_net_id]
    if admin_desc then
        subtree:add(f_apn_category, string.format("Carrier Infrastructure: %s", admin_desc))
        if lower_net_id == "ims" or lower_net_id == "sos" or lower_net_id == "emergency" then
            subtree:add(f_sec_alert, string.format("[NOTICE] Critical Telecom Signaling APN: '%s' (%s)", net_id, admin_desc))
        else
            table.insert(alerts, string.format("[WARNING] Access requested to Private Carrier Administrative APN '%s' (%s)! Verify authentication scope.", net_id, admin_desc))
        end
    else
        subtree:add(f_apn_category, "Commercial / Public Data Network")
    end

    -- Step 5: Wildcard & Blank APN Check
    if lower_net_id == "" or lower_net_id == "*" or lower_net_id == "." then
        table.insert(alerts, "[HIGH] Wildcard / Blank APN bearer established! Bypasses explicit network security gateway mapping.")
    end

    -- Step 6: Rogue / MitM Proxy APN Keyword Inspection
    for _, kw in ipairs(ROGUE_APN_KEYWORDS) do
        if string.find(lower_net_id, kw) then
            table.insert(alerts, string.format("[CRITICAL] Suspicious / Rogue APN keyword ('%s') detected in APN '%s'! Potential MitM traffic redirection or ad-fraud.", kw, apn_str))
            break
        end
    end

    -- Step 7: 3GPP APN Restriction Level (GTPv2-C)
    if f_gtp_restr_f and f_gtp_restr_f() then
        local restr_val = f_gtp_restr_f().value
        local restr_name = APN_RESTRICTION_NAMES[restr_val] or string.format("Restriction Level %d", restr_val)
        subtree:add(f_restr_level, restr_name)

        if restr_val >= 3 then
            subtree:add(f_sec_alert, string.format("[INFO] Private / Intranet APN Restriction Enforced (%s).", restr_name))
        end
    end

    -- Step 8: 5G Network Slicing (S-NSSAI) to DNN Cross-Check
    if f_nr_sst_f and f_nr_sst_f() then
        local sst = f_nr_sst_f().value
        local sst_name = SST_NAMES[sst] or string.format("Custom SST %d", sst)
        subtree:add(f_s_nssai_sst, sst)
        subtree:add(f_slice_desc, sst_name)

        if f_nr_sd_f and f_nr_sd_f() then
            local sd = f_nr_sd_f().value
            subtree:add(f_s_nssai_sd, sd)
        end

        -- Security Cross-Check: Mission-critical DNN on standard eMBB slice
        if (lower_net_id == "v2x" or string.find(lower_net_id, "safety") or string.find(lower_net_id, "teleop")) and sst == 1 then
            table.insert(alerts, string.format("[HIGH] Mission-critical automotive DNN ('%s') requested on standard eMBB slice (SST 1) instead of URLLC (SST 2) / V2X (SST 4)!", net_id))
        end
    end

    -- Step 9: Render Alerts & Info Column
    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(string.format(" [TELCOSEC APN: %d ALERT(S)!]", #alerts))
    end
end

register_postdissector(apn_dnn_proto)
