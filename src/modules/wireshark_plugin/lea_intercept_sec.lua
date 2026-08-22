-- TelcoSec.net - Lawful Interception (LEA) Security Post-Dissector & Analyzer
-- Target Standards:
--   ETSI TS 102 232 (IP Delivery of Intercept Related Information and Content of Communication)
--   ETSI TS 101 671 / 3GPP TS 33.108 (Handover Interface HI1, HI2, HI3 for 3G/4G)
--   3GPP TS 33.127 / TS 33.128 (5G Lawful Interception Architecture, X1/X2/X3 & HI1/HI2/HI3)
--
-- Description: Analyzes Lawful Interception signaling and payload handovers across 3GPP and ETSI networks.
--              Extracts Intercept Target IDs (SUPI, IMSI, MSISDN, IMEI, PEI, SIP URI, IPv4/IPv6),
--              inspects X1 Administration (ADMF -> POI/MDF), X2/HI2 (IRI) and X3/HI3 (CC),
--              detects unencrypted handover exposures, sequence number tampering, and unauthorized interception taps.

local ok, telcosec_lea_proto = pcall(Proto, "telcosec_lea", "TelcoSec Lawful Interception (LEA) Security Analyzer")
if not ok or not telcosec_lea_proto then return end

-- Protocol Fields
local f_alert       = ProtoField.string("telcosec_lea.alert", "TelcoSec LEA Alert")
local f_interface   = ProtoField.string("telcosec_lea.interface", "LI Interface (X1/X2/X3/HI1/HI2/HI3)")
local f_standard    = ProtoField.string("telcosec_lea.standard", "Target LI Standard")
local f_msg_type    = ProtoField.string("telcosec_lea.msg_type", "LI Message / PDU Type")
local f_target_id   = ProtoField.string("telcosec_lea.target_id", "Intercept Target ID")
local f_target_type = ProtoField.string("telcosec_lea.target_type", "Target Identifier Type")
local f_cin         = ProtoField.string("telcosec_lea.cin", "Correlation Identifier (CIN / CID)")
local f_operator_id = ProtoField.string("telcosec_lea.operator_id", "Operator / Delivery Identifier")
local f_seq_num     = ProtoField.uint32("telcosec_lea.seq_num", "PDU Sequence Number", base.DEC)
local f_direction   = ProtoField.string("telcosec_lea.direction", "Traffic Direction (fromTarget / toTarget)")
local f_encryption  = ProtoField.string("telcosec_lea.encryption", "Transport Security State")

telcosec_lea_proto.fields = {
    f_alert,
    f_interface,
    f_standard,
    f_msg_type,
    f_target_id,
    f_target_type,
    f_cin,
    f_operator_id,
    f_seq_num,
    f_direction,
    f_encryption
}

-- Safe field extractors
local function safe_field(name)
    local ok_f, f = pcall(Field.new, name)
    return ok_f and f or nil
end

local f_http2_path    = safe_field("http2.header.path")
local f_http2_data    = safe_field("http2.data.data")
local f_http_uri      = safe_field("http.request.uri")
local f_http_data     = safe_field("http.file_data")
local f_tls_record    = safe_field("tls.record")
local f_ssl_record    = safe_field("ssl.record")
local f_etsi_li_pdu   = safe_field("etsi_li.pdu") or safe_field("etsi_li")
local f_ber_oid       = safe_field("ber.oid")

-- Sequence tracker for anomaly/gap detection per CIN/stream
local seq_tracker = {}

-- Known 3GPP/ETSI LI OIDs (ASN.1 prefixes)
local LI_OIDS = {
    ["0.4.0.2.2.3.2"] = "ETSI TS 102 232 (IP Delivery)",
    ["0.4.0.2.2.3.2.1"] = "ETSI TS 102 232-1 (General IP PDU)",
    ["0.4.0.2.2.3.2.2"] = "ETSI TS 102 232-2 (Email Messaging)",
    ["0.4.0.2.2.3.2.3"] = "ETSI TS 102 232-3 (IP Access)",
    ["0.4.0.2.2.3.2.4"] = "ETSI TS 102 232-4 (L2 Services)",
    ["0.4.0.2.2.3.2.5"] = "ETSI TS 102 232-5 (IP Multimedia)",
    ["0.4.0.2.2.3.2.7"] = "ETSI TS 102 232-7 (Mobile Services)",
    ["0.4.0.1.6.7.1"]   = "ETSI TS 101 671 (HI2/HI3 Handover)",
    ["1.3.12.2.1010.5.2"] = "3GPP TS 33.108 (3G/4G Handover Interface)"
}

-- Check if transport is encrypted (TLS / IPsec)
local function is_encrypted_transport(pinfo)
    if f_tls_record and f_tls_record() then return true end
    if f_ssl_record and f_ssl_record() then return true end
    local proto_str = tostring(pinfo.cols.protocol):lower()
    if string.find(proto_str, "tls") or string.find(proto_str, "ssl") or string.find(proto_str, "esp") or string.find(proto_str, "ah") then
        return true
    end
    return false
end

function telcosec_lea_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 4 then return end

    -- Fast early-exit: check if packet is candidate for Lawful Interception signaling
    local p_col = tostring(pinfo.cols.protocol):upper()
    local is_candidate = string.find(p_col, "HTTP") or string.find(p_col, "BER") or 
                         string.find(p_col, "ETSI") or string.find(p_col, "3GPP") or
                         string.find(p_col, "JSON") or string.find(p_col, "XML") or
                         string.find(p_col, "X1") or string.find(p_col, "X2") or string.find(p_col, "X3") or
                         (pinfo.src_port and (pinfo.src_port == 12345 or pinfo.src_port == 12346 or pinfo.src_port == 8080 or pinfo.src_port == 8443)) or
                         (pinfo.dst_port and (pinfo.dst_port == 12345 or pinfo.dst_port == 12346 or pinfo.dst_port == 8080 or pinfo.dst_port == 8443))
    
    if not is_candidate and tvb(0, 1):uint() ~= 0x30 then
        return
    end

    local is_li = false
    local li_standard = nil
    local li_interface = nil
    local li_msg_type = nil
    local target_id = nil
    local target_type = nil
    local cin_val = nil
    local op_id = nil
    local seq_num = nil
    local direction = nil

    -- 1. Inspect HTTP / HTTP/2 (3GPP TS 33.127 X1 / X2 / X3 REST APIs)
    local raw_str = tvb(0, math.min(len, 2048)):string()
    
    -- Check 3GPP TS 33.127 5G LI REST Endpoints (e.g. /3gpp-x1/v1/..., /3gpp-x2/v1/..., /3gpp-x3/v1/...)
    if string.find(raw_str, "/3gpp%-x1") or string.find(raw_str, "3gpp:x1") or string.find(raw_str, "activateTask") or string.find(raw_str, "deactivateTask") or string.find(raw_str, "modifyTask") then
        is_li = true
        li_standard = "3GPP TS 33.127 (5G LI Architecture)"
        li_interface = "X1 (LI Administration ADMF <-> POI/MDF)"
        if string.find(raw_str, "activateTask") then li_msg_type = "activateTaskRequest"
        elseif string.find(raw_str, "deactivateTask") then li_msg_type = "deactivateTaskRequest"
        elseif string.find(raw_str, "modifyTask") then li_msg_type = "modifyTaskRequest"
        elseif string.find(raw_str, "getTaskDetails") then li_msg_type = "getTaskDetailsRequest"
        else li_msg_type = "X1-Administrative-Message" end
    elseif string.find(raw_str, "/3gpp%-x2") or string.find(raw_str, "3gpp:x2") or string.find(raw_str, "x2Report") then
        is_li = true
        li_standard = "3GPP TS 33.127 (5G LI)"
        li_interface = "X2 (IRI POI -> MDF2)"
        li_msg_type = "x2Report"
    elseif string.find(raw_str, "/3gpp%-x3") or string.find(raw_str, "3gpp:x3") or string.find(raw_str, "x3Delivery") then
        is_li = true
        li_standard = "3GPP TS 33.127 (5G LI)"
        li_interface = "X3 (CC POI -> MDF3)"
        li_msg_type = "x3Delivery"
    end

    -- Check 3GPP Target ID Patterns in JSON / XML payloads
    if is_li or string.find(raw_str, "targetIdentifier") or string.find(raw_str, "supi") or string.find(raw_str, "gpsi") or string.find(raw_str, "pei") then
        local supi_m = string.match(raw_str, '"supi"%s*:%s*"([^"]+)"') or string.match(raw_str, "<supi>([^<]+)</supi>")
        local gpsi_m = string.match(raw_str, '"gpsi"%s*:%s*"([^"]+)"') or string.match(raw_str, "<gpsi>([^<]+)</gpsi>")
        local pei_m  = string.match(raw_str, '"pei"%s*:%s*"([^"]+)"') or string.match(raw_str, "<pei>([^<]+)</pei>")
        local imsi_m = string.match(raw_str, '"imsi"%s*:%s*"([^"]+)"') or string.match(raw_str, "<imsi>([^<]+)</imsi>")
        local msisdn_m = string.match(raw_str, '"msisdn"%s*:%s*"([^"]+)"') or string.match(raw_str, "<msisdn>([^<]+)</msisdn>")
        local uri_m  = string.match(raw_str, '"sipUri"%s*:%s*"([^"]+)"') or string.match(raw_str, '<sipUri>([^<]+)</sipUri>')
        local cin_m  = string.match(raw_str, '"correlationId"%s*:%s*"([^"]+)"') or string.match(raw_str, '"cin"%s*:%s*(%d+)')
        local op_m   = string.match(raw_str, '"operatorIdentifier"%s*:%s*"([^"]+)"') or string.match(raw_str, '"admfId"%s*:%s*"([^"]+)"')

        if supi_m then target_id = supi_m; target_type = "SUPI (5G Subscription Permanent Identifier)"; is_li = true
        elseif gpsi_m then target_id = gpsi_m; target_type = "GPSI / MSISDN"; is_li = true
        elseif pei_m then target_id = pei_m; target_type = "PEI / IMEI"; is_li = true
        elseif imsi_m then target_id = imsi_m; target_type = "IMSI"; is_li = true
        elseif msisdn_m then target_id = msisdn_m; target_type = "MSISDN"; is_li = true
        elseif uri_m then target_id = uri_m; target_type = "SIP URI"; is_li = true end

        if cin_m then cin_val = tostring(cin_m) end
        if op_m then op_id = tostring(op_m) end
    end

    -- 2. Inspect ETSI TS 102 232 / TS 101 671 BER/ASN.1 Handover Headers
    -- ETSI TS 102 232 uses BER encapsulation starting with SEQUENCE (0x30), OID or PS-PDU tags
    if not is_li and len >= 12 then
        local first_byte = tvb(0, 1):uint()
        if first_byte == 0x30 then -- ASN.1 SEQUENCE
            -- Check for ETSI TS 102 232 PS-PDU header structures
            -- Common tags: [APPLICATION 0..3] or direct OID sub-identifiers
            for oid_prefix, oid_name in pairs(LI_OIDS) do
                if f_ber_oid then
                    local oids = { f_ber_oid() }
                    for _, o in ipairs(oids) do
                        if string.find(tostring(o.value), oid_prefix) then
                            is_li = true
                            li_standard = oid_name
                            li_interface = "HI2 / HI3 (ETSI Handover Interface)"
                            break
                        end
                    end
                end
            end
        end
    end

    -- 3. Check for specific LI delivery ports / metadata if not detected yet
    if not is_li then
        local li_ports = { [12345]=true, [12346]=true }
        if (pinfo.src_port and li_ports[pinfo.src_port]) or (pinfo.dst_port and li_ports[pinfo.dst_port]) then
            -- Only consider if payload is non-HTTP or matches telecom structure
            if len >= 16 and (tvb(0,1):uint() == 0x30 or string.find(raw_str, "HI2") or string.find(raw_str, "HI3") or string.find(raw_str, "ETSI")) then
                is_li = true
                li_standard = "ETSI TS 102 232 / 3GPP TS 33.108"
                li_interface = "HI2 (IRI) / HI3 (CC) Handover Interface"
            end
        end
    end

    if not is_li then return end

    -- Build TelcoSec Dissection Tree
    local encrypted = is_encrypted_transport(pinfo)
    local subtree_title = string.format("TelcoSec Lawful Interception Analysis: %s [%s]", 
        li_interface or "LEA Handover", 
        encrypted and "ENCRYPTED TLS/IPsec" or "CLEARTEXT / UNENCRYPTED")
    
    local subtree = tree:add(telcosec_lea_proto, tvb(), subtree_title)

    if li_interface then subtree:add(f_interface, li_interface) end
    if li_standard then subtree:add(f_standard, li_standard) end
    if li_msg_type then subtree:add(f_msg_type, li_msg_type) end
    if target_id then
        subtree:add(f_target_id, target_id)
        if target_type then subtree:add(f_target_type, target_type) end
    end
    if cin_val then subtree:add(f_cin, cin_val) end
    if op_id then subtree:add(f_operator_id, op_id) end
    if seq_num then subtree:add(f_seq_num, seq_num) end
    if direction then subtree:add(f_direction, direction) end

    subtree:add(f_encryption, encrypted and "Encrypted (TLS / IPsec Protected)" or "Cleartext (VULNERABLE)")

    -- Security Heuristic 1: Unencrypted Handover Exposure (Critical Compliance Violation)
    if not encrypted then
        subtree:add(f_alert, "[CRITICAL] Unencrypted Lawful Interception Handover detected! Target warrants, IRI, and CC payload exposed in cleartext. Violates ETSI TS 102 232 and 3GPP TS 33.127 confidentiality mandates.")
    end

    -- Security Heuristic 2: Plaintext Target Identity Leakage
    if target_id and not encrypted then
        subtree:add(f_alert, string.format("[HIGH RISK] Cleartext Target Identification leak: %s (%s). Warrant privacy compromised.", target_id, target_type or "Identifier"))
    end

    -- Security Heuristic 3: Administrative Warrant Activation (X1 Task Provisioning)
    if li_msg_type == "activateTaskRequest" or li_msg_type == "modifyTaskRequest" then
        subtree:add(f_alert, string.format("[AUDIT] Real-time Interception Task Provisioning (%s). Verify Warrant Authorization & ADMF authenticity.", li_msg_type))
    elseif li_msg_type == "deactivateTaskRequest" then
        subtree:add(f_alert, "[AUDIT] Interception Task Deactivation command detected.")
    end

    -- Security Heuristic 4: Sequence Number Gap & Evidence Tampering Audit
    if cin_val and seq_num then
        local prev_seq = seq_tracker[cin_val]
        if prev_seq and seq_num > (prev_seq + 1) then
            local missing = seq_num - prev_seq - 1
            subtree:add(f_alert, string.format("[CRITICAL] Interception Stream Sequence Gap detected! %d PDU(s) missing between Seq #%d and #%d for CIN %s. Possible evidence suppression or network packet drop.", missing, prev_seq, seq_num, cin_val))
        end
        seq_tracker[cin_val] = seq_num
    end

    -- Update Info Column
    local info_tag = " [TelcoSec: LEA"
    if li_interface then info_tag = info_tag .. " " .. (string.match(li_interface, "^(%w+)") or "TRAFFIC") end
    if target_id then info_tag = info_tag .. " Target:" .. target_id end
    if not encrypted then info_tag = info_tag .. " (CLEARTEXT!)" end
    info_tag = info_tag .. "]"
    
    pinfo.cols.info:append(info_tag)
end

-- Register as postdissector to run across TCP, UDP, HTTP, HTTP/2, and ASN.1 payloads
register_postdissector(telcosec_lea_proto)
