-- TelcoSec.net - H.248 / MEGACO & MGCP Media Gateway Security Analyzer
-- Target Standards: ITU-T H.248.1 / RFC 3525 (MEGACO), RFC 3435 (MGCP)
-- Description: Dissects H.248/MEGACO and MGCP commands controlling Media Gateways (MGW) and Media Gateway Controllers (MGC / Softswitches).
--              Detects unauthorized bearer termination modification (Subtract / Modify), circuit cross-connect hijacking,
--              and audit-leakage of active trunk terminations.

local ok, megaco_mgcp_proto = pcall(Proto, "megaco_mgcp_sec", "TelcoSec H.248 / MEGACO & MGCP Gateway Security Analyzer")
if not ok or not megaco_mgcp_proto then return end

-- Protocol fields
local f_proto_name      = ProtoField.string("megaco_mgcp_sec.proto", "Protocol Standard (H.248 MEGACO / MGCP)")
local f_command         = ProtoField.string("megaco_mgcp_sec.cmd", "Gateway Command")
local f_trans_id        = ProtoField.string("megaco_mgcp_sec.trans_id", "Transaction / Request ID")
local f_endpoint        = ProtoField.string("megaco_mgcp_sec.endpoint", "Endpoint / Termination ID (Circuit/TDM/RTP)")
local f_context_id      = ProtoField.string("megaco_mgcp_sec.context", "MEGACO Context ID")
local f_sec_alert       = ProtoField.string("megaco_mgcp_sec.alert", "TelcoSec Gateway Alert")

megaco_mgcp_proto.fields = {
    f_proto_name,
    f_command,
    f_trans_id,
    f_endpoint,
    f_context_id,
    f_sec_alert
}

-- Known MGCP Commands
local MGCP_CMDS = {
    ["EPCF"] = "EndpointConfiguration",
    ["CRCX"] = "CreateConnection",
    ["MDCX"] = "ModifyConnection",
    ["DLCX"] = "DeleteConnection",
    ["RQNT"] = "RequestEvent (Notification)",
    ["NTFY"] = "Notify (Event Report)",
    ["AUEP"] = "AuditEndpoint",
    ["AUCX"] = "AuditConnection",
    ["RSIP"] = "RestartInProgress"
}

-- Known MEGACO / H.248 Command Keywords
local MEGACO_CMDS = {
    ["ADD"]      = "Add Termination to Context",
    ["MODIFY"]   = "Modify Termination Parameters",
    ["SUBTRACT"] = "Subtract Termination (Teardown)",
    ["MOVE"]     = "Move Termination to New Context",
    ["AUDITVALUE"] = "AuditValue (Query Gateway State)",
    ["AUDITCAP"] = "AuditCapabilities",
    ["NOTIFY"]   = "Notify Event",
    ["SERVICECHANGE"] = "ServiceChange (Admin State)"
}

function megaco_mgcp_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 8 then return end

    local raw_str = tvb(0, math.min(len, 600)):string()

    -- 1. Identify MGCP Text Mode
    local mgcp_cmd, mgcp_trans, mgcp_ep = string.match(raw_str, "^([A-Z]{4})%s+(%d+)%s+([^%s\r\n]+)")
    if mgcp_cmd and MGCP_CMDS[mgcp_cmd] then
        pinfo.cols.protocol = "MGCP"
        local subtree = tree:add(megaco_mgcp_proto, tvb(), string.format("MGCP Security: %s (%s)", mgcp_cmd, MGCP_CMDS[mgcp_cmd]))
        subtree:add(f_proto_name, "MGCP (RFC 3435)")
        subtree:add(f_command, string.format("%s (%s)", mgcp_cmd, MGCP_CMDS[mgcp_cmd]))
        subtree:add(f_trans_id, mgcp_trans)
        subtree:add(f_endpoint, mgcp_ep)

        -- Security Heuristic: Mass Endpoint Audit or Call Teardown
        if mgcp_cmd == "DLCX" then
            subtree:add(f_sec_alert, "[WARNING] DeleteConnection (DLCX) commanded! Forcefully tears down active media gateway RTP bearer.")
            pinfo.cols.info:append(" [TELCOSEC: MGW BEARER TEARDOWN!]")
        elseif mgcp_cmd == "AUEP" and (mgcp_ep == "*" or string.find(mgcp_ep, "all")) then
            subtree:add(f_sec_alert, "[INFO] Wildcard AuditEndpoint (AUEP *) detected. Full trunk inventory query.")
        end
        return
    end

    -- 2. Identify MEGACO / H.248 Text Mode
    local megaco_match = string.match(raw_str, "MEGACO/%d") or string.match(raw_str, "H%.248/%d") or string.match(raw_str, "^!%s*/%d")
    if megaco_match then
        pinfo.cols.protocol = "H.248 MEGACO"
        local subtree = tree:add(megaco_mgcp_proto, tvb(), "H.248 / MEGACO Security Engine")
        subtree:add(f_proto_name, "H.248 / MEGACO (RFC 3525)")

        local alerts = {}
        for cmd_key, cmd_desc in pairs(MEGACO_CMDS) do
            if string.find(raw_str, cmd_key) then
                subtree:add(f_command, string.format("%s (%s)", cmd_key, cmd_desc))
                if cmd_key == "SUBTRACT" then
                    table.insert(alerts, "[WARNING] H.248 SUBTRACT: Tearing down media gateway context termination.")
                elseif cmd_key == "SERVICECHANGE" and string.find(raw_str, "Graceful") == nil and string.find(raw_str, "Forced") ~= nil then
                    table.insert(alerts, "[CRITICAL] H.248 SERVICECHANGE Forced! Abrupt administrative shutdown of gateway trunk.")
                end
            end
        end

        if #alerts > 0 then
            for _, alert_msg in ipairs(alerts) do
                subtree:add(f_sec_alert, alert_msg)
            end
            pinfo.cols.info:append(" [TELCOSEC: H.248 GATEWAY ALERT!]")
        end
    end
end

register_postdissector(megaco_mgcp_proto)
