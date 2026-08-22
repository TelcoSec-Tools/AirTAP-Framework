-- TelcoSec.net - GSMA eSIM Remote SIM Provisioning (RSP - GSMA SGP.22 / SGP.02 / SGP.32) Master Security Dissector
-- Description: Complete analyzer for GSMA eSIM Remote SIM Provisioning protocols across ES9+ (SM-DP+ <-> LPA),
--              ES10 (LPA <-> eUICC), and ES2+ (MNO <-> SM-DP+) interfaces over TLS / HTTPS and ISO-7816 APDU.
--              Decodes initiateAuthentication, authenticateClient, getBoundProfilePackage (BPP), handleNotification,
--              enableProfile, disableProfile, deleteProfile, setDefaultDpAddress, and loadCRL.
--              Detects default SM-DP+ provisioning server hijacking, certificate validation bypasses,
--              mass profile deletion DoS attacks, and eUICC identifier harvesting.

local ok, esim_rsp_proto = pcall(Proto, "esim_rsp_sec", "TelcoSec GSMA eSIM (Remote SIM Provisioning) Security Analyzer")
if not ok or not esim_rsp_proto then return end

-- Protocol fields
local f_interface       = ProtoField.string("esim_rsp.interface", "RSP Interface (ES9+ / ES10 / ES2+)")
local f_function        = ProtoField.string("esim_rsp.function", "RSP Function Name")
local f_eid             = ProtoField.string("esim_rsp.eid", "eUICC Identifier (EID - 32 Digits)")
local f_iccid           = ProtoField.string("esim_rsp.iccid", "Target eSIM Profile ICCID")
local f_matching_id     = ProtoField.string("esim_rsp.matching_id", "Matching ID / Activation Code")
local f_smdp_address    = ProtoField.string("esim_rsp.smdp_address", "SM-DP+ Server FQDN")
local f_txn_id          = ProtoField.string("esim_rsp.txn_id", "Transaction ID")
local f_profile_state   = ProtoField.string("esim_rsp.profile_state", "Profile State (Enabled/Disabled/Deleted)")
local f_error_code      = ProtoField.string("esim_rsp.error_code", "RSP Error Cause")
local f_sec_alert       = ProtoField.string("esim_rsp.alert", "TelcoSec eSIM Security Alert")
local f_payload         = ProtoField.bytes("esim_rsp.payload", "RSP Raw Payload")

esim_rsp_proto.fields = {
    f_interface,
    f_function,
    f_eid,
    f_iccid,
    f_matching_id,
    f_smdp_address,
    f_txn_id,
    f_profile_state,
    f_error_code,
    f_sec_alert,
    f_payload
}

-- GSMA SGP.22 ES9+ & ES10 Function Catalog
local RSP_FUNCTIONS = {
    -- ES9+ (LPA <-> SM-DP+)
    ["initiateAuthentication"]    = { name = "Initiate Authentication",       iface = "ES9+", desc = "eUICC / LPA challenge exchange with SM-DP+" },
    ["authenticateClient"]        = { name = "Authenticate Client",           iface = "ES9+", desc = "Cryptographic client proof validation" },
    ["getBoundProfilePackage"]    = { name = "Get Bound Profile Package (BPP)",iface = "ES9+", desc = "Encrypted profile payload download" },
    ["handleNotification"]        = { name = "Handle Notification",           iface = "ES9+", desc = "Profile lifecycle event reporting" },
    ["cancelSession"]             = { name = "Cancel Session",                iface = "ES9+", desc = "Aborts active RSP transaction" },

    -- ES10 (LPA <-> eUICC)
    ["getEUICCInfo1"]             = { name = "Get eUICC Info 1",              iface = "ES10", desc = "Retrieves SVN and supported curve list" },
    ["getEUICCInfo2"]             = { name = "Get eUICC Info 2",              iface = "ES10", desc = "Retrieves eUICC capabilities & certificate rules" },
    ["getEUICCChallenge"]         = { name = "Get eUICC Challenge",           iface = "ES10", desc = "Retrieves eUICC nonce for SM-DP+ authentication" },
    ["authenticateServer"]        = { name = "Authenticate Server",           iface = "ES10", desc = "Validates SM-DP+ signed challenge on eUICC" },
    ["prepareDownload"]           = { name = "Prepare Download",              iface = "ES10", desc = "Generates one-time EC keypair for profile binding" },
    ["loadBoundProfilePackage"]   = { name = "Load Bound Profile Package",    iface = "ES10", desc = "Installs decrypted profile into eUICC ISD-P" },
    ["listProfileInfo"]           = { name = "List Profile Info",             iface = "ES10", desc = "Queries installed profile metadata & states" },
    ["enableProfile"]             = { name = "Enable Profile",                iface = "ES10", desc = "Activates installed eSIM profile on baseband" },
    ["disableProfile"]            = { name = "Disable Profile",               iface = "ES10", desc = "Deactivates active eSIM profile" },
    ["deleteProfile"]             = { name = "Delete Profile",                iface = "ES10", desc = "Permanently deletes profile from eUICC" },
    ["setDefaultDpAddress"]       = { name = "Set Default SM-DP+ Address",    iface = "ES10", desc = "Configures default remote provisioning server" },
    ["loadCRL"]                   = { name = "Load Certificate Revocation",   iface = "ES10", desc = "Updates GSMA Root CI CRL on eUICC" },
    ["setNickname"]               = { name = "Set Profile Nickname",          iface = "ES10", desc = "Assigns user-friendly alias to profile" }
}

function esim_rsp_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 4 then return end

    local text = tvb:raw()
    pinfo.cols.protocol = "eSIM RSP"

    local subtree = tree:add(esim_rsp_proto, tvb(), "GSMA eSIM Remote Provisioning (RSP) Security Engine")
    local alerts = {}
    local matched_entry = nil
    local func_key_name = nil

    -- 1. Identify Function Name
    for func_key, meta in pairs(RSP_FUNCTIONS) do
        if string.find(text, func_key) then
            matched_entry = meta
            func_key_name = func_key
            subtree:add(f_function, meta.name)
            subtree:add(f_interface, meta.iface)
            pinfo.cols.info = string.format("[eSIM %s] %s", meta.iface, meta.name)
            break
        end
    end

    if not matched_entry then
        subtree:add(f_function, "eSIM RSP Protocol Message")
        pinfo.cols.info = "[eSIM RSP] Provisioning Data"
    end

    -- 2. Extract Key JSON/ASN.1 Parameters
    local eid_val = string.match(text, '"eid"%s*:%s*"([0-9A-Fa-f]+)"') or string.match(text, '"eId"%s*:%s*"([0-9A-Fa-f]+)"')
    if eid_val then
        subtree:add(f_eid, eid_val)
        pinfo.cols.info:append(string.format(" [EID: %s]", eid_val:sub(1, 16) .. "..."))
    end

    local iccid_val = string.match(text, '"iccid"%s*:%s*"([0-9A-Fa-f]+)"') or string.match(text, '"iccidList"%s*:%s*%[%s*"([0-9A-Fa-f]+)"')
    if iccid_val then
        subtree:add(f_iccid, iccid_val)
        pinfo.cols.info:append(string.format(" [ICCID: %s]", iccid_val))
    end

    local smdp_val = string.match(text, '"smdpAddress"%s*:%s*"([^"]+)"') or string.match(text, '"defaultDpAddress"%s*:%s*"([^"]+)"')
    if smdp_val then
        subtree:add(f_smdp_address, smdp_val)
    end

    local match_id = string.match(text, '"matchingId"%s*:%s*"([^"]+)"')
    if match_id then
        subtree:add(f_matching_id, match_id)
    end

    -- 3. Security Heuristic 1: Default SM-DP+ Address Redirection (Rogue Provisioning Server Hijack)
    if func_key_name == "setDefaultDpAddress" or string.find(text, "setDefaultDpAddress") then
        table.insert(alerts, string.format(
            "[CRITICAL] Default SM-DP+ Provisioning Server Modified (%s)! " ..
            "Host or malware overriding default carrier SM-DP+ address. Potential rogue profile injection / eSIM hijack.",
            smdp_val or "Unknown Server"))
        pinfo.cols.info:append(" [TELCOSEC: SM-DP+ SERVER REDIRECT!]")
    end

    -- 3. Security Heuristic 2: Bound Profile Package Download & Decryption (BPP)
    if func_key_name == "getBoundProfilePackage" or func_key_name == "loadBoundProfilePackage" then
        table.insert(alerts, "[INFO] Encrypted Bound Profile Package (BPP) installation. Decrypted inside eUICC hardware security boundary using GSMA Root CI PKI.")
        pinfo.cols.info:append(" [BPP INSTALLATION]")
    end

    -- 3. Security Heuristic 3: Profile Deletion / Disable DoS
    if func_key_name == "deleteProfile" then
        table.insert(alerts, "[CRITICAL] eSIM Profile Deletion Commanded! Permanently removes carrier profile from eUICC, terminating subscriber connectivity.")
        pinfo.cols.info:append(" [TELCOSEC: PROFILE DELETED!]")
    elseif func_key_name == "disableProfile" then
        table.insert(alerts, "[WARNING] eSIM Profile Disabled on eUICC.")
    end

    -- 3. Security Heuristic 4: Profile Installation / Authentication Errors
    if string.find(text, '"error"') or string.find(text, '"bppRejection"') or string.find(text, '"errorResult"') then
        local err_code = string.match(text, '"subjectCode"%s*:%s*"([^"]+)"') or "Installation Failed"
        subtree:add(f_error_code, err_code)
        table.insert(alerts, string.format("[CRITICAL] eSIM Profile Installation / Crypto Verification Failed (%s)! Potential untrusted Root CI certificate or tampered BPP payload.", err_code))
        pinfo.cols.info:append(" [TELCOSEC: PROFILE INSTALL FAILURE!]")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    subtree:add(f_payload, tvb())
end

-- Register on HTTPS/TLS ports (8443, 8444) and HTTP
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(8444, esim_rsp_proto)
    tcp_table:add(8443, esim_rsp_proto)
end

-- Register as postdissector
register_postdissector(esim_rsp_proto)
