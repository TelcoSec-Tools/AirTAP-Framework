-- TelcoSec.net - IMS XCAP / Ut Interface & GBA Security Dissector
-- Target Standards: RFC 4825 (XCAP), 3GPP TS 24.623 (Extensible Markup Language Configuration Access Protocol), TS 33.220 (GBA)
-- Description: Dissects XCAP operations over HTTP/TLS (Ut interface) between UE and Telephony Application Server (TAS) / BSF.
--              Decodes 'simservs' XML documents for Call Forwarding (CFU/CFB/CFNR), Call Barring (ICB/OCB), OIP/OIR,
--              detects unauthorized call diversion attacks, and audits GBA bootstrapping requests.

local ok, ims_xcap_proto = pcall(Proto, "ims_xcap_ut_sec", "TelcoSec IMS XCAP / Ut Interface Security Analyzer")
if not ok or not ims_xcap_proto then return end

-- Protocol fields
local f_http_method    = ProtoField.string("ims_xcap_ut_sec.method", "HTTP Method")
local f_http_uri       = ProtoField.string("ims_xcap_ut_sec.uri", "XCAP Request URI")
local f_xcap_doc_type  = ProtoField.string("ims_xcap_ut_sec.doc_type", "XCAP Document / AUID Type")
local f_cf_target      = ProtoField.string("ims_xcap_ut_sec.cf_target", "Call Forwarding Target Number / URI")
local f_cf_type        = ProtoField.string("ims_xcap_ut_sec.cf_type", "Call Forwarding Service Type")
local f_cb_type        = ProtoField.string("ims_xcap_ut_sec.cb_type", "Call Barring Rule / Condition")
local f_gba_bsf        = ProtoField.string("ims_xcap_ut_sec.gba_bsf", "GBA Bootstrapping Server Function (BSF)")
local f_sec_alert      = ProtoField.string("ims_xcap_ut_sec.alert", "TelcoSec XCAP/Ut Security Alert")

ims_xcap_proto.fields = {
    f_http_method,
    f_http_uri,
    f_xcap_doc_type,
    f_cf_target,
    f_cf_type,
    f_cb_type,
    f_gba_bsf,
    f_sec_alert
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_http_req_meth  = safe_field("http.request.method")
local f_http_req_uri   = safe_field("http.request.uri")
local f_http_content   = safe_field("http.file_data")
local f_http_auth      = safe_field("http.authorization")

function ims_xcap_proto.dissector(tvb, pinfo, tree)
    -- Guard: Check if packet is HTTP and touches XCAP or GBA paths
    local is_http = f_http_req_uri and f_http_req_uri()
    if not is_http then return end

    local uri_str = tostring(f_http_req_uri().value)
    local is_xcap = string.find(uri_str, "xcap") or string.find(uri_str, "simservs") or string.find(uri_str, "org.3gpp.ngn")
    local is_gba  = string.find(uri_str, "bootstrapping") or string.find(uri_str, "bsf")

    if not (is_xcap or is_gba) then return end

    local subtree = tree:add(ims_xcap_proto, tvb(), string.format("TelcoSec IMS Ut / XCAP Security Engine (%s)", is_xcap and "XCAP Supplementary Services" or "GBA Bootstrap"))
    subtree:add(f_http_uri, uri_str)

    if f_http_req_meth and f_http_req_meth() then
        subtree:add(f_http_method, tostring(f_http_req_meth().value))
    end

    local alerts = {}

    -- XCAP Supplementary Services Parsing (simservs)
    if is_xcap then
        subtree:add(f_xcap_doc_type, "3GPP simservs (TS 24.623)")

        if f_http_content and f_http_content() then
            local payload_str = tostring(f_http_content().value)

            -- Check Call Forwarding XML (<communication-diversion>)
            if string.find(payload_str, "communication%-diversion") or string.find(payload_str, "call%-diversion") then
                local target_uri = string.match(payload_str, "target%s*=%s*[\"']([^\"']+)[\"']") or string.match(payload_str, "<target>([^<]+)</target>")
                if target_uri then
                    subtree:add(f_cf_target, target_uri)
                    table.insert(alerts, string.format("[CRITICAL] Call Forwarding Diversion Modified -> Target: %s! Verify subscriber authorization against toll fraud / call interception.", target_uri))
                end

                if string.find(payload_str, "communication%-diversion%-unconditional") or string.find(payload_str, "cfu") then
                    subtree:add(f_cf_type, "Call Forwarding Unconditional (CFU)")
                elseif string.find(payload_str, "communication%-diversion%-busy") or string.find(payload_str, "cfb") then
                    subtree:add(f_cf_type, "Call Forwarding Busy (CFB)")
                elseif string.find(payload_str, "communication%-diversion%-no%-reply") or string.find(payload_str, "cfnr") then
                    subtree:add(f_cf_type, "Call Forwarding No Reply (CFNR)")
                end
            end

            -- Check Call Barring XML (<communication-barring>)
            if string.find(payload_str, "communication%-barring") or string.find(payload_str, "incoming%-communication%-barring") then
                subtree:add(f_cb_type, "Incoming / Outgoing Call Barring Rule Modification")
                table.insert(alerts, "[WARNING] IMS Call Barring rules modified via Ut interface.")
            end
        end
    end

    -- GBA Authentication Bootstrapping Check
    if is_gba then
        subtree:add(f_gba_bsf, "Generic Bootstrapping Architecture (TS 33.220)")
        if f_http_auth and f_http_auth() then
            local auth_hdr = tostring(f_http_auth().value)
            if string.find(auth_hdr, "Digest") and string.find(auth_hdr, "aka") then
                subtree:add(f_sec_alert, "[INFO] GBA HTTP Digest AKA Authentication Vector Transmitted to BSF.")
            end
        else
            table.insert(alerts, "[HIGH] Unauthenticated GBA Bootstrap request to BSF! Missing Digest AKA authorization.")
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: XCAP/UT ALERT!]")
    end
end

register_postdissector(ims_xcap_proto)
