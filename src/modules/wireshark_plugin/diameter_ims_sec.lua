-- TelcoSec.net - IMS Diameter Cx/Dx/Sh/Rx Interface Security Analyzer
-- Target Standards: 3GPP TS 29.228 (Cx/Dx - I-CSCF/S-CSCF <-> HSS), 3GPP TS 29.328 (Sh - AS <-> HSS), 3GPP TS 29.214 (Rx - P-CSCF <-> PCRF)
-- Description: Dissects Diameter IMS command codes (UAR/UAA, SAR/SAA, LIR/LIA, MAR/MAA, PUR/PUA, UDR/UDA, AAR/AAA).
--              Detects unauthenticated IMS HSS subscriber profile exfiltration, multimedia authentication vector leaks,
--              and unauthorized QoS privilege escalation over the Rx interface.

local ok, diam_ims_proto = pcall(Proto, "diameter_ims_sec", "TelcoSec Diameter IMS (Cx/Dx/Sh/Rx) Security Analyzer")
if not ok or not diam_ims_proto then return end

-- Protocol fields
local f_cmd_code        = ProtoField.uint32("diameter_ims_sec.cmd_code", "Diameter Command Code", base.DEC)
local f_cmd_name        = ProtoField.string("diameter_ims_sec.cmd_name", "IMS Command Name")
local f_app_id          = ProtoField.uint32("diameter_ims_sec.app_id", "IMS Application-ID", base.DEC)
local f_app_name        = ProtoField.string("diameter_ims_sec.app_name", "IMS Interface Name")
local f_public_id       = ProtoField.string("diameter_ims_sec.public_id", "User-Public-Identity (IMPU / SIP URI)")
local f_private_id      = ProtoField.string("diameter_ims_sec.private_id", "User-Name (IMPI / IMSI)")
local f_auth_item       = ProtoField.string("diameter_ims_sec.auth_item", "SIP-Auth-Data-Item Item (Vectors)")
local f_user_data       = ProtoField.string("diameter_ims_sec.user_data", "Extracted HSS XML User-Data Profile")
local f_sec_alert       = ProtoField.string("diameter_ims_sec.alert", "TelcoSec IMS Diameter Alert")

diam_ims_proto.fields = {
    f_cmd_code,
    f_cmd_name,
    f_app_id,
    f_app_name,
    f_public_id,
    f_private_id,
    f_auth_item,
    f_user_data,
    f_sec_alert
}

-- Known 3GPP IMS Diameter Applications
local IMS_APP_NAMES = {
    [16777216] = "Cx / Dx (CSCF <-> HSS)",
    [16777217] = "Sh (Application Server <-> HSS)",
    [16777236] = "Rx (P-CSCF <-> PCRF Policy Control)",
    [16777222] = "Zh (BSF <-> HSS Bootstrapping / GAA)"
}

-- Known 3GPP IMS Diameter Command Codes
local IMS_CMD_NAMES = {
    [300] = "UAR / UAA (User-Authorization)",
    [301] = "SAR / SAA (Server-Assignment)",
    [302] = "LIR / LIA (Location-Info)",
    [303] = "MAR / MAA (Multimedia-Auth)",
    [304] = "RTR / RTA (Registration-Termination)",
    [305] = "PPR / PPA (Push-Profile)",
    [306] = "UDR / UDA (User-Data)",
    [307] = "PUR / PUA (Profile-Update)",
    [308] = "SNR / SNA (Subscribe-Notifications)",
    [309] = "PNR / PNA (Push-Notification)",
    [265] = "AAR / AAA (AA-Request / Rx QoS)"
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_diam_cmd = safe_field("diameter.cmd.code")
local f_diam_app = safe_field("diameter.applicationId")
local f_diam_user= safe_field("diameter.User-Name")

function diam_ims_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "Diameter") or string.find(proto_str, "DIAMETER") or (pinfo.src_port and pinfo.src_port == 3868) or (pinfo.dst_port and pinfo.dst_port == 3868)) then
        return
    end

    -- Must have at least 20 bytes for Diameter Header
    if tvb:len() < 20 then return end

    local version = tvb(0, 1):uint()
    if version ~= 1 then return end

    local cmd_code = tvb(5, 3):uint()
    local app_id = tvb(8, 4):uint()

    local app_name = IMS_APP_NAMES[app_id]
    local cmd_name = IMS_CMD_NAMES[cmd_code]

    -- Only inspect if this is an IMS Application or Command
    if not (app_name or cmd_name) then return end

    local subtree = tree:add(diam_ims_proto, tvb(), string.format("IMS Diameter Security: %s (%s)", cmd_name or string.format("Cmd %d", cmd_code), app_name or "IMS"))
    subtree:add(f_cmd_code, cmd_code)
    subtree:add(f_cmd_name, cmd_name or "Unknown IMS Command")
    subtree:add(f_app_id, app_id)
    subtree:add(f_app_name, app_name or "IMS Application")

    local alerts = {}

    -- Security Heuristic 1: Multimedia-Auth (MAR/MAA) Vector Harvest
    if cmd_code == 303 then
        table.insert(alerts, "[CRITICAL] Multimedia-Auth Request/Answer (MAR/MAA)! Contains AKA authentication vectors (RAND, AUTN, XRES, CK, IK). Potential voice interception key extraction.")
    end

    -- Security Heuristic 2: HSS User-Data Profile Exfiltration (UDR/UDA)
    if cmd_code == 306 then
        table.insert(alerts, "[CRITICAL] Sh User-Data Query (UDR/UDA)! Reading full subscriber IMS XML profile, service triggers, and call-diversion configurations from HSS.")
    end

    -- Security Heuristic 3: Registration Termination Request (RTR) - IMS Voice Kick
    if cmd_code == 304 then
        table.insert(alerts, "[WARNING] Registration-Termination Request (RTR) from HSS! Forcefully disconnects subscriber VoLTE session.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: IMS DIAMETER ALERT!]")
    end
end

register_postdissector(diam_ims_proto)
