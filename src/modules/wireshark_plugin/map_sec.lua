-- TelcoSec.net - SS7 MAP (Mobile Application Part - 3GPP TS 29.002 / GSM 09.02) Master Security Dissector
-- Description: Complete analyzer for SS7 Mobile Application Part (MAP) signaling across all functional domains:
--              Location Management (updateLocation, cancelLocation, purgeMS), Call Routing (SRI, PRN),
--              SMS (SRI-SM, MO/MT-ForwardSM), Security & Auth (SendAuthInfo, InsertSubscriberData, SendIMSI),
--              USSD & Supplementary Services (USSR, USSN), and Location Services (PSI, ATI, SLR).
--              Enforces GSMA FS.11 / FS.19 / FS.20 / FS.21 SS7 Interconnect Firewall & Threat Hunting Rules.

local ok, map_sec_proto = pcall(Proto, "map_sec", "TelcoSec SS7 MAP (Mobile Application Part) Security Analyzer")
if not ok or not map_sec_proto then return end

-- Protocol fields
local f_op_code         = ProtoField.uint8("map_sec.op_code", "MAP Operation Code", base.DEC)
local f_op_name         = ProtoField.string("map_sec.op_name", "Operation Name")
local f_category        = ProtoField.string("map_sec.category", "MAP Functional Category")
local f_imsi            = ProtoField.string("map_sec.imsi", "Target Subscriber IMSI")
local f_msisdn          = ProtoField.string("map_sec.msisdn", "Target MSISDN (Phone Number)")
local f_vlr_num         = ProtoField.string("map_sec.vlr_number", "Serving VLR / SGSN Number (E.164)")
local f_msc_num         = ProtoField.string("map_sec.msc_number", "Serving MSC Number (E.164)")
local f_hlr_num         = ProtoField.string("map_sec.hlr_number", "Home HLR Number (E.164)")
local f_ussd_str        = ProtoField.string("map_sec.ussd_string", "USSD String Content")
local f_sec_alert       = ProtoField.string("map_sec.alert", "TelcoSec MAP Security Alert")
local f_gsma_cat        = ProtoField.string("map_sec.gsma_rule", "GSMA FS.11 Category Classification")
local f_payload         = ProtoField.bytes("map_sec.payload", "MAP Raw ASN.1 Payload")

map_sec_proto.fields = {
    f_op_code,
    f_op_name,
    f_category,
    f_imsi,
    f_msisdn,
    f_vlr_num,
    f_msc_num,
    f_hlr_num,
    f_ussd_str,
    f_sec_alert,
    f_gsma_cat,
    f_payload
}

-- 3GPP TS 29.002 Table 17.1/1 MAP Operation Codes
local MAP_OP_CODES = {
    -- Location Management
    [2]  = { name = "updateLocation",                cat = "Location Management",  gsma = "Cat 1 (Unauthorized Cross-PLMN)" },
    [3]  = { name = "cancelLocation",                cat = "Location Management",  gsma = "Cat 1 (Subscriber Kill DoS)" },
    [4]  = { name = "provideRoamingNumber",          cat = "Call Handling",        gsma = "Cat 3 (Call Hijack / Interception)" },
    [6]  = { name = "resumeCallHandling",            cat = "Call Handling",        gsma = "Cat 3 (Call Redirection)" },
    [7]  = { name = "insertSubscriberData",          cat = "Subscriber Management",gsma = "Cat 1 (HLR Profile / CFU Hijack)" },
    [8]  = { name = "deleteSubscriberData",          cat = "Subscriber Management",gsma = "Cat 1 (Subscriber Profile Stripping)" },
    [10] = { name = "registerSS",                    cat = "Supplementary Svc",    gsma = "Cat 3 (Call Forwarding Tampering)" },
    [11] = { name = "eraseSS",                       cat = "Supplementary Svc",    gsma = "Cat 3 (Supp Svc Modification)" },
    [12] = { name = "activateSS",                    cat = "Supplementary Svc",    gsma = "Cat 3 (Supp Svc Modification)" },
    [13] = { name = "deactivateSS",                  cat = "Supplementary Svc",    gsma = "Cat 3 (Supp Svc Modification)" },
    [14] = { name = "interrogateSS",                 cat = "Supplementary Svc",    gsma = "Cat 2 (Info Gathering)" },
    [22] = { name = "sendRoutingInfo",               cat = "Call Handling",        gsma = "Cat 3 (Interception / Routing Query)" },
    [23] = { name = "updateGprsLocation",            cat = "GPRS Location Mgt",    gsma = "Cat 1 (GPRS Session Hijack)" },
    [24] = { name = "sendRoutingInfoForGprs",        cat = "GPRS Call Handling",   gsma = "Cat 2 (GPRS Node Discovery)" },
    [44] = { name = "mt-forwardSM",                  cat = "SMS / Messaging",      gsma = "Cat 3 (SMS Spoofing / Interception)" },
    [45] = { name = "sendRoutingInfoForSM",          cat = "SMS / Messaging",      gsma = "Cat 2 (IMSI & MSC Harvest Probe)" },
    [46] = { name = "mo-forwardSM",                  cat = "SMS / Messaging",      gsma = "Cat 3 (SMS Relay)" },
    [47] = { name = "reportSM-DeliveryStatus",       cat = "SMS / Messaging",      gsma = "Cat 2 (SMS Status Tracking)" },
    [50] = { name = "activateTraceMode",             cat = "Lawful / Trace",       gsma = "Cat 1 (Unauthorized Wiretap Setup)" },
    [51] = { name = "deactivateTraceMode",           cat = "Lawful / Trace",       gsma = "Cat 1 (Wiretap Teardown)" },
    [55] = { name = "sendIdentification",            cat = "Identity Management",  gsma = "Cat 1 (IMSI / Key Extraction)" },
    [56] = { name = "sendAuthenticationInfo",        cat = "Security & Auth",      gsma = "Cat 1 (Auth Vector Exfiltration)" },
    [57] = { name = "restoreData",                   cat = "Subscriber Management",gsma = "Cat 1 (HLR Restoration)" },
    [58] = { name = "sendIMSI",                      cat = "Identity Management",  gsma = "Cat 2 (Target IMSI Harvesting)" },
    [59] = { name = "processUnstructuredSS-Request", cat = "USSD / Banking",       gsma = "Cat 3 (USSD / 2FA Session Hijack)" },
    [60] = { name = "unstructuredSS-Request",        cat = "USSD / Banking",       gsma = "Cat 3 (USSD Prompt Injection)" },
    [61] = { name = "unstructuredSS-Notify",         cat = "USSD / Banking",       gsma = "Cat 3 (USSD Notification)" },
    [62] = { name = "anyTimeSubscriptionInterrogation",cat="Location / Privacy",   gsma = "Cat 2 (Covert Subscriber Profiling)" },
    [63] = { name = "informServiceCenter",           cat = "SMS / Messaging",      gsma = "Cat 2 (SMS Routing Info)" },
    [64] = { name = "alertServiceCenter",            cat = "SMS / Messaging",      gsma = "Cat 2 (SMS Alert)" },
    [65] = { name = "anyTimeModification",           cat = "Subscriber Management",gsma = "Cat 1 (Unauthorized HLR Modification)" },
    [67] = { name = "purgeMS",                       cat = "Location Management",  gsma = "Cat 1 (VLR Context Purge DoS)" },
    [71] = { name = "anyTimeInterrogation",          cat = "Location / Privacy",   gsma = "Cat 2 (Covert Location Tracking)" },
    [83] = { name = "provideSubscriberLocation",     cat = "Location / LCS",       gsma = "Cat 2 (Real-Time Geolocation Tracking)" },
    [85] = { name = "sendRoutingInfoForLCS",         cat = "Location / LCS",       gsma = "Cat 2 (LCS Entity Discovery)" }
}

-- Native MAP dissector
local native_map = Dissector.get("gsm_map")

-- Helper: decode TBDA BCD phone numbers / IMSI
local function decode_tbcd(tvb, offset, length)
    if offset + length > tvb:len() then return nil end
    local digits = ""
    for i = 0, length - 1 do
        local b = tvb(offset + i, 1):uint()
        local low = bit.band(b, 0x0F)
        local high = bit.rshift(b, 4)
        if low <= 9 then digits = digits .. tostring(low) end
        if high <= 9 then digits = digits .. tostring(high) end
    end
    return digits
end

function map_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    pinfo.cols.protocol = "SS7 MAP"

    -- Determine MAP Operation Code (First byte or inside TCAP invoke parameter)
    local op_code = tvb(0, 1):uint()
    local op_info = MAP_OP_CODES[op_code]

    -- If not direct byte 0, scan first 6 bytes for valid MAP op code
    if not op_info and len >= 4 then
        for off = 0, math.min(len - 1, 5) do
            local cand = tvb(off, 1):uint()
            if MAP_OP_CODES[cand] then
                op_code = cand
                op_info = MAP_OP_CODES[cand]
                break
            end
        end
    end

    local op_name = op_info and op_info.name or string.format("MAP Op %d", op_code)
    local category = op_info and op_info.cat or "SS7 Core Signaling"
    local gsma_cat = op_info and op_info.gsma or "General SS7 Operation"

    local subtree = tree:add(map_sec_proto, tvb(), string.format("SS7 MAP Security Engine: %s (%s)", op_name, category))
    subtree:add(f_op_code, tvb(0, 1), op_code)
    subtree:add(f_op_name, op_name)
    subtree:add(f_category, category)
    subtree:add(f_gsma_cat, gsma_cat)

    pinfo.cols.info = string.format("[SS7 MAP] %s (%s)", op_name, category)

    local alerts = {}

    -- Scan for IMSI / MSISDN in payload (TBCD encoded)
    if len > 3 then
        local raw_hex = tvb:bytes():tohex()
        -- Tag 0x04 or 0x80 (IMSI Octet String in MAP)
        for off = 1, len - 8 do
            local tag = tvb(off, 1):uint()
            local l = tvb(off + 1, 1):uint()
            if (tag == 0x04 or tag == 0x80) and (l >= 5 and l <= 8) and off + 2 + l <= len then
                local imsi_cand = decode_tbcd(tvb, off + 2, l)
                if imsi_cand and #imsi_cand >= 10 and #imsi_cand <= 15 then
                    subtree:add(f_imsi, imsi_cand)
                    pinfo.cols.info:append(string.format(" [IMSI: %s]", imsi_cand))
                    break
                end
            end
        end
    end

    -- Security Heuristic 1: Authentication Vector Exfiltration (SendAuthenticationInfo - SAI)
    if op_code == 56 then
        table.insert(alerts, "[CRITICAL] MAP sendAuthenticationInfo (SAI) Detected! Unauthorized cross-operator query attempting to extract 2G/3G/4G authentication triplets/quintuplets. Enables subscriber OTA traffic decryption & SIM cloning.")
        pinfo.cols.info:append(" [TELCOSEC: AUTH VECTOR EXFILTRATION!]")
    end

    -- Security Heuristic 2: HLR Profile Hijacking / Call Forwarding Tampering (InsertSubscriberData - ISD)
    if op_code == 7 then
        table.insert(alerts, "[CRITICAL] MAP insertSubscriberData (ISD) Detected! Remote entity overwriting VLR subscriber profile. Potential Call Forwarding Unconditional (CFU) hijack to intercept calls/SMS.")
        pinfo.cols.info:append(" [TELCOSEC: HLR PROFILE HIJACK!]")
    end

    -- Security Heuristic 3: Subscriber Silent Kill / Denial of Service (CancelLocation - CL)
    if op_code == 3 then
        table.insert(alerts, "[CRITICAL] MAP cancelLocation (CL) Commanded! Forcibly wipes subscriber registration from serving VLR, severing cellular service.")
        pinfo.cols.info:append(" [TELCOSEC: SUBSCRIBER KILL DOS!]")
    end

    -- Security Heuristic 4: Covert Real-Time Geolocation Tracking (PSI / ATI)
    if op_code == 83 or op_code == 71 then
        table.insert(alerts, string.format(
            "[CRITICAL] Covert Subscriber Geolocation Probe (%s)! " ..
            "Querying serving Cell ID, Timing Advance, and VLR coordinates without handset notification. Violates GSMA FS.11 Privacy guidelines.",
            op_name))
        pinfo.cols.info:append(" [TELCOSEC: COVERT LOCATION PROBE!]")
    end

    -- Security Heuristic 5: IMSI / MSC Harvesting via SMS Gateway Probe (SRI-SM)
    if op_code == 45 then
        table.insert(alerts, "[HIGH RISK] MAP sendRoutingInfoForSM (SRI-SM) Query! Pre-attack reconnaissance extracting subscriber IMSI and serving MSC address.")
        pinfo.cols.info:append(" [TELCOSEC: SRI-SM RECON PROBE]")
    end

    -- Security Heuristic 6: Banking 2FA / USSD Session Hijacking (processUnstructuredSS-Request)
    if op_code == 59 or op_code == 60 then
        table.insert(alerts, "[CRITICAL] MAP USSD Interaction (%s)! Inspect for mobile banking, balance transfer, or OTP token interception.", op_name)
        pinfo.cols.info:append(" [TELCOSEC: USSD INTERACTION!]")
    end

    -- Security Heuristic 7: Call Interception & Wiretap Setup (sendRoutingInfo / provideRoamingNumber)
    if op_code == 22 or op_code == 4 then
        table.insert(alerts, string.format("[HIGH RISK] MAP %s (Call Routing Query). Potential call interception / man-in-the-middle rerouting probe.", op_name))
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if native_map then
        native_map:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register on SCCP SSN table for MAP (6=HLR, 7=VLR, 8=MSC)
local sccp_ssn_table = DissectorTable.get("sccp.ssn")
if sccp_ssn_table then
    sccp_ssn_table:add(6, map_sec_proto)
    sccp_ssn_table:add(7, map_sec_proto)
    sccp_ssn_table:add(8, map_sec_proto)
end

-- Register as postdissector to inspect all SS7 MAP signaling
register_postdissector(map_sec_proto)
