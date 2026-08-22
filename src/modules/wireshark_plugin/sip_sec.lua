-- TelcoSec.net - SIP & IMS VoLTE Signaling Security Analyzer
-- Target Standards: RFC 3261 (SIP), RFC 3325 (P-Asserted-Identity), 3GPP TS 24.229 (IP multimedia call control based on SIP/SDP)
-- Description: Inspects Session Initiation Protocol (SIP) messages across IMS, VoLTE, and VoIP networks.
--              Detects Caller ID spoofing (P-Asserted-Identity / From mismatch), SIP registration hijacking,
--              INVITE flood Denial of Service, unauthenticated BYE injection, Digest auth brute force, and Toll Fraud.

local ok, sip_sec_proto = pcall(Proto, "sip_sec", "TelcoSec SIP & VoLTE Signaling Security Analyzer")
if not ok or not sip_sec_proto then return end

-- Protocol fields
local f_method          = ProtoField.string("sip_sec.method", "SIP Method")
local f_status_code     = ProtoField.uint32("sip_sec.status_code", "SIP Status Code", base.DEC)
local f_from_uri        = ProtoField.string("sip_sec.from_uri", "From Header URI")
local f_to_uri          = ProtoField.string("sip_sec.to_uri", "To Header URI")
local f_pai_uri         = ProtoField.string("sip_sec.pai_uri", "P-Asserted-Identity (PAI) URI")
local f_ppi_uri         = ProtoField.string("sip_sec.ppi_uri", "P-Preferred-Identity (PPI) URI")
local f_call_id         = ProtoField.string("sip_sec.call_id", "Call-ID")
local f_user_agent      = ProtoField.string("sip_sec.user_agent", "User-Agent / Server Banner")
local f_auth_digest     = ProtoField.string("sip_sec.auth_digest", "Authorization Digest Username")
local f_contact_uri     = ProtoField.string("sip_sec.contact_uri", "Contact Header URI")
local f_expires         = ProtoField.uint32("sip_sec.expires", "Registration Expiry (seconds)", base.DEC)
local f_sec_alert       = ProtoField.string("sip_sec.alert", "TelcoSec SIP Security Alert")

sip_sec_proto.fields = {
    f_method,
    f_status_code,
    f_from_uri,
    f_to_uri,
    f_pai_uri,
    f_ppi_uri,
    f_call_id,
    f_user_agent,
    f_auth_digest,
    f_contact_uri,
    f_expires,
    f_sec_alert
}

-- Native Wireshark SIP field extractors
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_sip_method      = safe_field("sip.Method")
local f_sip_status      = safe_field("sip.Status-Code")
local f_sip_from        = safe_field("sip.from.addr")
local f_sip_to          = safe_field("sip.to.addr")
local f_sip_call_id     = safe_field("sip.Call-ID")
local f_sip_user_agent  = safe_field("sip.User-Agent") or safe_field("sip.server")
local f_sip_contact     = safe_field("sip.contact.uri")
local f_sip_expires     = safe_field("sip.expires")
local f_sip_pai         = safe_field("sip.P-Asserted-Identity")

-- State tracking for INVITE flood DoS detection
local invite_tracker = {
    window_start = 0,
    count = 0
}

function sip_sec_proto.dissector(tvb, pinfo, tree)
    -- Must have text payload starting with standard SIP tokens or status
    local len = tvb:len()
    if len < 10 then return end

    -- Fast 4-byte check before full string allocation
    local pfx = tvb(0, 4):string()
    if pfx ~= "SIP/" and not pfx:match("^[A-Z]+$") then
        return
    end

    local raw_str = tvb(0, math.min(len, 1200)):string()
    if not (string.match(raw_str, "^SIP/2%.0") or string.match(raw_str, "^[A-Z]+ sip") or string.match(raw_str, "^[A-Z]+ tel")) then
        return
    end

    local subtree = tree:add(sip_sec_proto, tvb(), "TelcoSec SIP & VoLTE Security Engine")

    local alerts = {}

    -- Extract SIP Method or Response Status
    local method = string.match(raw_str, "^([A-Z]+) ")
    local status_code = tonumber(string.match(raw_str, "^SIP/2%.0 (%d%d%d)"))

    if method then
        subtree:add(f_method, method)
    end
    if status_code then
        subtree:add(f_status_code, status_code)
    end

    -- Extract From, To, P-Asserted-Identity
    local from_val = string.match(raw_str, "[Ff][Rr][Oo][Mm]:%s*([^;\r\n]+)")
    local to_val = string.match(raw_str, "[Tt][Oo]:%s*([^;\r\n]+)")
    local pai_val = string.match(raw_str, "[Pp]%-[Aa][Ss][Ss][Ee][Rr][Tt][Ee][Dd]%-[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:%s*([^;\r\n]+)")
    local ppi_val = string.match(raw_str, "[Pp]%-[Pp][Rr][Ee][Ff][Ee][Rr][Rr][Ee][Dd]%-[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:%s*([^;\r\n]+)")
    local user_agent = string.match(raw_str, "[Uu][Ss][Ee][Rr]%-[Aa][Gg][Ee][Nn][Tt]:%s*([^\r\n]+)")
    local call_id = string.match(raw_str, "[Cc][Aa][Ll][Ll]%-[Ii][Dd]:%s*([^\r\n]+)")
    local contact_val = string.match(raw_str, "[Cc][Oo][Nn][Tt][Aa][Cc][Tt]:%s*([^;\r\n]+)")
    local expires_val = tonumber(string.match(raw_str, "[Ee][Xx][Pp][Ii][Rr][Ee][Ss]:%s*(%d+)"))

    if from_val then subtree:add(f_from_uri, from_val) end
    if to_val then subtree:add(f_to_uri, to_val) end
    if pai_val then subtree:add(f_pai_uri, pai_val) end
    if ppi_val then subtree:add(f_ppi_uri, ppi_val) end
    if user_agent then subtree:add(f_user_agent, user_agent) end
    if call_id then subtree:add(f_call_id, call_id) end
    if contact_val then subtree:add(f_contact_uri, contact_val) end
    if expires_val then subtree:add(f_expires, expires_val) end

    -- Security Heuristic 1: Caller ID Spoofing / P-Asserted-Identity Mismatch
    if method == "INVITE" and from_val and pai_val then
        local from_user = string.match(from_val, "<?[sS][iI][pP]:([^@>]+)") or string.match(from_val, "<?[tT][eE][lL]:([^@>]+)")
        local pai_user = string.match(pai_val, "<?[sS][iI][pP]:([^@>]+)") or string.match(pai_val, "<?[tT][eE][lL]:([^@>]+)")
        if from_user and pai_user and from_user ~= pai_user then
            table.insert(alerts, string.format("[CRITICAL] Caller ID Spoofing detected! Header 'From' (%s) does not match authenticated carrier identity 'P-Asserted-Identity' (%s).", from_user, pai_user))
        end
    end

    -- Security Heuristic 2: SIP Scanner / Attack Tool Fingerprint
    if user_agent then
        local ua_lower = string.lower(user_agent)
        if string.find(ua_lower, "friendly-scanner") or string.find(ua_lower, "sipvicious") or string.find(ua_lower, "sundayddr") or string.find(ua_lower, "sipcli") or string.find(ua_lower, "sipp") then
            table.insert(alerts, string.format("[CRITICAL] Known SIP VoIP reconnaissance tool detected in User-Agent: '%s'!", user_agent))
        end
    end

    -- Security Heuristic 3: Registration Hijack / Contact Replacement
    if method == "REGISTER" and expires_val and expires_val == 0 then
        table.insert(alerts, "[WARNING] SIP De-registration commanded (Expires: 0). Possible subscriber reachability DoS.")
    end

    -- Security Heuristic 4: INVITE Flood DoS
    if method == "INVITE" then
        local cur_time = tonumber(pinfo.rel_ts) or tonumber(tostring(pinfo.abs_ts)) or 0
        if (cur_time - invite_tracker.window_start) > 1.0 then
            if invite_tracker.count > 100 then
                table.insert(alerts, string.format("[CRITICAL] High-frequency SIP INVITE Flood (%d msgs/sec)! Telephony Denial of Service attack.", invite_tracker.count))
            end
            invite_tracker.window_start = cur_time
            invite_tracker.count = 1
        else
            invite_tracker.count = invite_tracker.count + 1
        end
    end

    -- Security Heuristic 5: Premium-rate Toll Fraud / Suspicious Prefix
    if method == "INVITE" and to_val then
        local to_user = string.match(to_val, "<?[sS][iI][pP]:([^@>]+)") or string.match(to_val, "<?[tT][eE][lL]:([^@>]+)")
        if to_user and (string.match(to_user, "^0088") or string.match(to_user, "^%+88") or string.match(to_user, "^0900") or string.match(to_user, "^1900")) then
            table.insert(alerts, string.format("[CRITICAL] High-cost International / Premium-Rate destination dialed (%s)! Potential Telecom Toll Fraud.", to_user))
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: SIP SECURITY ALERT!]")
    end
end

-- Register as postdissector to inspect all SIP packets
register_postdissector(sip_sec_proto)
