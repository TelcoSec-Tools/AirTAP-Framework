-- TelcoSec.net - Emergency Services (SOS) & eCall Security Post-Dissector & Analyzer
-- Target Standards:
--   3GPP TS 23.167 (IP Multimedia Subsystem (IMS) emergency sessions)
--   3GPP TS 24.229 (IP multimedia call control protocol based on SIP and SDP)
--   RFC 5031 (A Uniform Resource Name (URN) for Emergency and Other Well-Known Services)
--   RFC 4412 / RFC 8147 (SIP Resource-Priority Header for Emergency / Priority Services)
--   RFC 4119 / RFC 5139 (Presence Information Data Format Location Object - PIDF-LO)
--   ETSI EN 15722 / 3GPP TS 26.267 (eCall Minimum Set of Data - MSD)
--
-- Description: Inspects SIP/IMS signaling for Emergency Call flows, eCall in-vehicle systems,
--              Resource-Priority QoS fraud, PIDF-LO/AML location telemetry presence,
--              unauthenticated emergency registration, and malicious 380 Alternative Service redirections.

local ok, telcosec_sos_proto = pcall(Proto, "telcosec_sos", "TelcoSec SOS Emergency & eCall Security Analyzer")
if not ok or not telcosec_sos_proto then return end

-- Protocol fields
local f_alert         = ProtoField.string("telcosec_sos.alert", "TelcoSec SOS Alert")
local f_service_urn   = ProtoField.string("telcosec_sos.service_urn", "Emergency Service URN")
local f_service_type  = ProtoField.string("telcosec_sos.service_type", "Emergency Category")
local f_caller_id     = ProtoField.string("telcosec_sos.caller_id", "Emergency Caller Identity (PAI/From)")
local f_req_uri       = ProtoField.string("telcosec_sos.req_uri", "SIP Request-URI")
local f_priority      = ProtoField.string("telcosec_sos.priority", "Resource-Priority Header")
local f_priority_ns   = ProtoField.string("telcosec_sos.priority_ns", "Priority Namespace")
local f_ecall_msd     = ProtoField.string("telcosec_sos.ecall_msd", "eCall Minimum Set of Data (MSD)")
local f_location_info = ProtoField.string("telcosec_sos.location_info", "Extracted Location (PIDF-LO / AML)")
local f_resp_code     = ProtoField.uint32("telcosec_sos.resp_code", "Emergency SIP Response Code", base.DEC)

telcosec_sos_proto.fields = {
    f_alert,
    f_service_urn,
    f_service_type,
    f_caller_id,
    f_req_uri,
    f_priority,
    f_priority_ns,
    f_ecall_msd,
    f_location_info,
    f_resp_code
}

-- Safe field getters
local function safe_field(name)
    local ok_f, f = pcall(Field.new, name)
    return ok_f and f or nil
end

local f_sip_req_uri    = safe_field("sip.Request-URI")
local f_sip_to         = safe_field("sip.To")
local f_sip_from       = safe_field("sip.From")
local f_sip_pai        = safe_field("sip.P-Asserted-Identity")
local f_sip_method     = safe_field("sip.Method")
local f_sip_status     = safe_field("sip.Status-Code")
local f_sip_res_pri    = safe_field("sip.Resource-Priority")
local f_sip_content_type = safe_field("sip.Content-Type")
local f_sip_geoloc     = safe_field("sip.Geolocation")

-- RFC 5031 Emergency URN dictionary
local SOS_URN_TYPES = {
    ["urn:service:sos.police"]          = "Police Emergency (110 / 999 / 911)",
    ["urn:service:sos.fire"]            = "Fire Rescue (112 / 911)",
    ["urn:service:sos.ambulance"]       = "Medical Ambulance (112 / 911)",
    ["urn:service:sos.marine"]          = "Maritime Coast Guard Rescue",
    ["urn:service:sos.mountain"]        = "Mountain / Alpine Search & Rescue",
    ["urn:service:sos.ecall.manual"]    = "eCall: Manual In-Vehicle Trigger (112)",
    ["urn:service:sos.ecall.automatic"] = "eCall: Automatic Crash Sensor Trigger (112)",
    ["urn:service:sos.counseling"]      = "Emergency Counseling / Mental Health",
    ["urn:service:sos.poison"]          = "Toxicology / Poison Control Center",
    ["urn:service:sos"]                 = "General Emergency Service"
}

-- Recognized national emergency numbers in SIP URIs (e.g. sip:911@..., tel:112, etc.)
local EMERGENCY_NUMBERS = {
    ["911"] = "North American Emergency (911)",
    ["112"] = "European / Global Universal Emergency (112)",
    ["999"] = "UK / Commonwealth Emergency (999)",
    ["000"] = "Australian Emergency (000)",
    ["110"] = "Police Emergency (110)",
    ["119"] = "Fire / Ambulance Emergency (119)",
    ["122"] = "Austria / Europe Fire (122)",
    ["120"] = "China Emergency Medical (120)",
    ["128"] = "International Maritime Emergency"
}

-- Resource-Priority Emergency Namespaces (RFC 4412 / RFC 8147)
local PRIORITY_NAMESPACES = {
    ["esnet"] = "Emergency Services IP Network (ESInet / NENA)",
    ["psap"]  = "Public Safety Answering Point (PSAP-level priority)",
    ["wps"]   = "Wireless Priority Service (Federal / Gov National Security)",
    ["ets"]   = "Emergency Telecommunications Service",
    ["dsv"]   = "Defense Switched Voice Network Priority",
    ["drsm"]  = "Disaster Recovery Services Management"
}

function telcosec_sos_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 10 then return end

    -- Verify SIP payload signature
    local raw_str = tvb(0, math.min(len, 3000)):string()
    local is_sip = string.match(raw_str, "^SIP/2%.0") or string.match(raw_str, "^[A-Z]+ sip") or string.match(raw_str, "^[A-Z]+ tel") or string.match(raw_str, "\r\nSIP/2%.0")
    if not is_sip then return end

    local method = string.match(raw_str, "^([A-Z]+) ")
    local status_code = tonumber(string.match(raw_str, "^SIP/2%.0 (%d%d%d)")) or (f_sip_status and f_sip_status() and tonumber(f_sip_status().value))

    local req_uri_val = string.match(raw_str, "^[A-Z]+%s+([^%s\r\n]+)") or (f_sip_req_uri and f_sip_req_uri() and tostring(f_sip_req_uri().value)) or ""
    local to_val = string.match(raw_str, "[Tt][Oo]:%s*([^;\r\n]+)") or (f_sip_to and f_sip_to() and tostring(f_sip_to().value)) or ""
    local from_val = string.match(raw_str, "[Ff][Rr][Oo][Mm]:%s*([^;\r\n]+)") or (f_sip_from and f_sip_from() and tostring(f_sip_from().value)) or ""
    local pai_val = string.match(raw_str, "[Pp]%-[Aa][Ss][Ss][Ee][Rr][Tt][Ee][Dd]%-[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:%s*([^;\r\n]+)") or (f_sip_pai and f_sip_pai() and tostring(f_sip_pai().value)) or ""
    local rp_val = string.match(raw_str, "[Rr][Ee][Ss][Oo][Uu][Rr][Cc][Ee]%-[Pp][Rr][Ii][Oo][Rr][Ii][Tt][Yy]:%s*([^\r\n]+)") or (f_sip_res_pri and f_sip_res_pri() and tostring(f_sip_res_pri().value)) or ""
    local content_type = string.match(raw_str, "[Cc][Oo][Nn][Tt][Aa][Ee][Nn][Tt]%-[Tt][Yy][Pp][Ee]:%s*([^\r\n]+)") or (f_sip_content_type and f_sip_content_type() and tostring(f_sip_content_type().value)) or ""

    local is_emergency = false
    local matched_urn = nil
    local emergency_desc = nil

    -- 1. Evaluate RFC 5031 URNs in Request-URI or To header
    local search_targets = { req_uri_val, to_val, raw_str }
    for _, target_str in ipairs(search_targets) do
        for urn, desc in pairs(SOS_URN_TYPES) do
            local escaped_urn = urn:gsub("%-", "%%-"):gsub("%.", "%%.")
            if string.find(target_str, escaped_urn) then
                is_emergency = true
                matched_urn = urn
                emergency_desc = desc
                break
            end
        end
        if is_emergency then break end
    end

    -- 2. Evaluate Exact National Emergency Numbers in Request-URI or To header
    if not is_emergency then
        local user_num = string.match(req_uri_val, "sip:([^@;:]+)") or string.match(req_uri_val, "tel:([^;]+)") or string.match(to_val, "sip:([^@;:]+)") or string.match(to_val, "tel:([^;]+)")
        if user_num then
            -- Strip leading '+' or prefixes
            user_num = user_num:gsub("^%+", "")
            if EMERGENCY_NUMBERS[user_num] then
                is_emergency = true
                matched_urn = "urn:service:sos (" .. user_num .. ")"
                emergency_desc = EMERGENCY_NUMBERS[user_num]
            end
        end
    end

    -- 3. Evaluate Resource-Priority Header for Priority / Emergency Namespaces
    local has_priority = false
    local priority_namespace = nil
    if rp_val ~= "" then
        for ns, ns_desc in pairs(PRIORITY_NAMESPACES) do
            if string.find(rp_val:lower(), ns) then
                has_priority = true
                priority_namespace = ns_desc
                break
            end
        end
    end

    -- 4. Check for 380 Alternative Service (Emergency Redirection)
    local is_380_emergency_alt = false
    if status_code == 380 and (string.find(raw_str, "<type>emergency</type>") or string.find(raw_str, "urn:service:sos") or string.find(raw_str, "emergency%-registration")) then
        is_emergency = true
        is_380_emergency_alt = true
        emergency_desc = "380 Alternative Service: Forced Emergency Network Redirection"
    end

    -- If no emergency indicators and no priority headers, skip
    if not is_emergency and not has_priority then return end

    -- Build TelcoSec Analysis Subtree
    local title = is_emergency and ("TelcoSec Emergency Services (SOS) Analysis: " .. (emergency_desc or "Emergency Call")) or ("TelcoSec Priority QoS Analysis: " .. (rp_val))
    local subtree = tree:add(telcosec_sos_proto, tvb(), title)

    if matched_urn then subtree:add(f_service_urn, matched_urn) end
    if emergency_desc then subtree:add(f_service_type, emergency_desc) end
    if req_uri_val ~= "" then subtree:add(f_req_uri, req_uri_val) end
    
    local caller = pai_val ~= "" and pai_val or from_val
    if caller ~= "" then subtree:add(f_caller_id, caller) end

    if rp_val ~= "" then
        subtree:add(f_priority, rp_val)
        if priority_namespace then subtree:add(f_priority_ns, priority_namespace) end
    end

    if status_code then
        subtree:add(f_resp_code, status_code)
    end

    -- Location extraction: PIDF-LO XML / Geolocation Header
    local location_extracted = nil
    if string.find(raw_str, "application/pidf%+xml") or string.find(raw_str, "<presence") or string.find(raw_str, "<geopriv") then
        local lat = string.match(raw_str, "<gml:pos>%s*([%d%.%-]+)%s+([%d%.%-]+)") or string.match(raw_str, "<latitude>%s*([%d%.%-]+)")
        local lon = string.match(raw_str, "<gml:pos>[%d%.%-]+%s+([%d%.%-]+)") or string.match(raw_str, "<longitude>%s*([%d%.%-]+)")
        local civic_street = string.match(raw_str, "<RD>([^<]+)</RD>") or string.match(raw_str, "<street>([^<]+)</street>")
        local civic_city = string.match(raw_str, "<A3>([^<]+)</A3>") or string.match(raw_str, "<city>([^<]+)</city>")

        if lat and lon then
            location_extracted = string.format("GPS/WGS84 Lat: %s, Lon: %s (PIDF-LO GML)", lat, lon)
        elseif civic_street or civic_city then
            location_extracted = string.format("Civic Address: %s, %s (PIDF-LO)", civic_street or "N/A", civic_city or "N/A")
        else
            location_extracted = "PIDF-LO XML Container Present (Geopriv Location Object)"
        end
        subtree:add(f_location_info, location_extracted)
    end

    -- Location extraction: Advanced Mobile Location (AML / ELS SMS/HTTPS data)
    if string.find(raw_str, "LT=") and string.find(raw_str, "LG=") then
        local aml_lat = string.match(raw_str, "LT=([%d%.%-]+)")
        local aml_lon = string.match(raw_str, "LG=([%d%.%-]+)")
        local aml_rd  = string.match(raw_str, "RD=(%d+)")
        local aml_str = string.format("AML/ELS Fast Location: Lat: %s, Lon: %s (Radius: %sm)", aml_lat or "?", aml_lon or "?", aml_rd or "?")
        subtree:add(f_location_info, aml_str)
        location_extracted = aml_str
    end

    -- eCall MSD (Minimum Set of Data) Container Extraction
    if string.find(raw_str, "application/emergencyCallData.eCall.MSD") or string.find(raw_str, "urn:service:sos.ecall") then
        local vin_match = string.match(raw_str, "([A-HJ-NPR-Z0-9]{17})")
        local msd_info = "eCall MSD Container Present"
        if vin_match then
            msd_info = msd_info .. " [VIN: " .. vin_match .. "]"
        end
        subtree:add(f_ecall_msd, msd_info)
    end

    -- Security Heuristic 1: Resource-Priority QoS Fraud / Privilege Escalation
    if has_priority and not is_emergency then
        subtree:add(f_alert, string.format("[CRITICAL RISK] Priority Header Abuse / QoS Escalation! Non-emergency session injecting Resource-Priority (%s) without emergency URN destination.", rp_val))
    end

    -- Security Heuristic 2: Emergency Call Rejection / Malicious Redirection
    if is_emergency and status_code then
        if status_code >= 400 and status_code <= 699 then
            subtree:add(f_alert, string.format("[CRITICAL] Emergency Call Blocked / Rejected! SIP Status Code %d returned for emergency destination. Violates mandatory PSAP availability guidelines.", status_code))
        elseif status_code == 380 then
            subtree:add(f_alert, "[HIGH RISK] SIP 380 Alternative Service received for emergency call! Ensure redirection leads to a legitimate E-CSCF / PSAP and not a rogue trap.")
        end
    end

    -- Security Heuristic 3: Missing Location Telemetry on Emergency INVITE
    if is_emergency and method == "INVITE" and not location_extracted and not string.find(raw_str, "[Gg][Ee][Oo][Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:") then
        subtree:add(f_alert, "[WARNING] Emergency INVITE dispatched without Geolocation header or PIDF-LO location container! PSAP dispatch accuracy degraded.")
    end

    -- Security Heuristic 4: Unauthenticated Emergency Registration Audit
    if method == "REGISTER" and (matched_urn or string.find(raw_str, "sos")) then
        subtree:add(f_alert, "[AUDIT] Emergency SIP Registration (3GPP TS 24.229 unauthenticated emergency attach flow). Monitor for unauthorized access abuse.")
    end

    -- Update Wireshark Info Column
    if is_emergency then
        local col_tag = " [TelcoSec: EMERGENCY " .. (matched_urn or "CALL")
        if location_extracted then col_tag = col_tag .. " +LOC" end
        col_tag = col_tag .. "]"
        pinfo.cols.info:append(col_tag)
    elseif has_priority then
        pinfo.cols.info:append(" [TelcoSec: PRIORITY " .. (rp_val) .. "]")
    end
end

-- Register as postdissector so it executes across SIP UDP, TCP, and TLS
register_postdissector(telcosec_sos_proto)
