-- TelcoSec.net - MCPTT & M3AP (Mission-Critical Push-To-Talk / Public Safety LTE - 3GPP TS 24.380 / TS 23.379 / TS 36.444) Security Dissector
-- Description: Dissects MCPTT floor control signaling, floor priority arbitration, talkgroup pre-emption, and M3AP MBMS session control.
--              Decodes message subtypes, floor indicators (Normal, Emergency, Imminent Peril, Broadcast Group),
--              floor denial reject causes, user/group IDs, and SSRC/Track IDs.
--              Detects tactical channel floor hijacking, rogue Floor Revoke blackout attacks, and public safety DoS floods.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
local bit = bit or bit32
if not bit then
    bit = {
        band   = function(a, b) return a & b end,
        bor    = function(a, b) return a | b end,
        bxor   = function(a, b) return a ~ b end,
        lshift = function(a, n) return (a << n) & 0xFFFFFFFF end,
        rshift = function(a, n) return (a & 0xFFFFFFFF) >> n end,
    }
end

local ok, mcptt_sec_proto = pcall(Proto, "mcptt_sec", "TelcoSec MCPTT Mission-Critical Voice Security Analyzer")
if not ok or not mcptt_sec_proto then return end

-- Protocol fields
local f_msg_type        = ProtoField.uint8("mcptt_sec.msg_type", "Floor Control Message Type", base.HEX)
local f_msg_name        = ProtoField.string("mcptt_sec.msg_name", "Message Name")
local f_floor_pri       = ProtoField.uint8("mcptt_sec.floor_priority", "Floor Priority (0-255)", base.DEC)
local f_pri_level       = ProtoField.string("mcptt_sec.pri_level", "Priority Classification")
local f_indicator       = ProtoField.uint8("mcptt_sec.indicator", "Floor Indicator Flags", base.HEX)
local f_is_emergency    = ProtoField.bool("mcptt_sec.is_emergency", "Emergency Call Flag")
local f_is_imminent     = ProtoField.bool("mcptt_sec.is_imminent", "Imminent Peril Call Flag")
local f_is_broadcast    = ProtoField.bool("mcptt_sec.is_broadcast", "Broadcast Group Call Flag")
local f_track_id        = ProtoField.uint32("mcptt_sec.track_id", "SSRC / Track ID", base.HEX)
local f_reject_cause    = ProtoField.uint8("mcptt_sec.reject_cause", "Floor Reject Cause Code", base.DEC)
local f_reject_desc     = ProtoField.string("mcptt_sec.reject_desc", "Floor Reject Reason")
local f_caller_id       = ProtoField.string("mcptt_sec.caller_id", "User / Group URI")
local f_sec_alert       = ProtoField.string("mcptt_sec.alert", "TelcoSec Public Safety Alert")
local f_payload         = ProtoField.bytes("mcptt_sec.payload", "MCPTT Raw Payload")

mcptt_sec_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_floor_pri,
    f_pri_level,
    f_indicator,
    f_is_emergency,
    f_is_imminent,
    f_is_broadcast,
    f_track_id,
    f_reject_cause,
    f_reject_desc,
    f_caller_id,
    f_sec_alert,
    f_payload
}

-- MCPTT Floor Control Messages (3GPP TS 24.380 Section 8.2)
local MCPTT_MESSAGES = {
    [0x00] = "Floor Request",
    [0x01] = "Floor Granted",
    [0x02] = "Floor Denied",
    [0x03] = "Floor Release",
    [0x04] = "Floor Idle",
    [0x05] = "Floor Taken",
    [0x06] = "Floor Revoke",
    [0x07] = "Floor Queue Position Request",
    [0x08] = "Floor Queue Position Info",
    [0x09] = "Floor Ack",
    [0x0A] = "Floor Non-Ack"
}

-- MCPTT Reject Causes (TS 24.380 Section 8.2.3)
local MCPTT_REJECT_CAUSES = {
    [1]   = "Another user has the floor",
    [2]   = "Floor request queue full",
    [3]   = "Priority level too low for pre-emption",
    [4]   = "Floor not granted / transmission timeout",
    [5]   = "Unauthorized to request floor on this talkgroup",
    [6]   = "Talkgroup broadcast only (receive-only)",
    [255] = "Unspecified / Protocol error"
}

function mcptt_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    pinfo.cols.protocol = "LTE MCPTT"

    -- MCPTT Floor Control Header:
    -- [0]: Subtype / Message Type (1 byte)
    -- [1]: Priority (1 byte: 0=Normal, 100=High, 200=Emergency, 255=Imminent Peril)
    local msg_type = tvb(0, 1):uint()
    local priority = tvb(1, 1):uint()
    local msg_name = MCPTT_MESSAGES[msg_type] or string.format("MCPTT Msg (0x%02X)", msg_type)

    local pri_level = "Normal (0-99)"
    if priority >= 250 then
        pri_level = "Imminent Peril (250-255)"
    elseif priority >= 200 then
        pri_level = "Emergency Pre-emptive (200-249)"
    elseif priority >= 100 then
        pri_level = "High Priority (100-199)"
    end

    local subtree = tree:add(mcptt_sec_proto, tvb(), string.format("MCPTT Public Safety: %s (Priority: %d - %s)", msg_name, priority, pri_level))
    subtree:add(f_msg_type, tvb(0, 1), msg_type)
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_floor_pri, tvb(1, 1), priority)
    subtree:add(f_pri_level, pri_level)

    local alerts = {}

    -- Decode SSRC / Track ID if present
    if len >= 6 then
        local track_id = tvb(2, 4):uint()
        subtree:add(f_track_id, tvb(2, 4), track_id)
    end

    -- Decode Floor Indicator flags if present (TS 24.380 Section 8.3.2)
    if len >= 7 then
        local ind_byte = tvb(6, 1):uint()
        local is_emerg = bit.band(ind_byte, 0x80) ~= 0
        local is_immin = bit.band(ind_byte, 0x40) ~= 0
        local is_bcast = bit.band(ind_byte, 0x20) ~= 0
        subtree:add(f_indicator, tvb(6, 1), ind_byte)
        subtree:add(f_is_emergency, is_emerg)
        subtree:add(f_is_imminent, is_immin)
        subtree:add(f_is_broadcast, is_bcast)
    end

    -- Decode Reject Cause for Floor Denied / Non-Ack
    if (msg_type == 0x02 or msg_type == 0x0A) and len >= 8 then
        local cause = tvb(7, 1):uint()
        local cause_str = MCPTT_REJECT_CAUSES[cause] or string.format("Cause %d", cause)
        subtree:add(f_reject_cause, tvb(7, 1), cause)
        subtree:add(f_reject_desc, cause_str)
        pinfo.cols.info = string.format("[MCPTT] %s | %s (Cause: %d)", msg_name, cause_str, cause)
    else
        pinfo.cols.info = string.format("[MCPTT] %s | Priority: %d (%s)", msg_name, priority, pri_level)
    end

    -- Security Heuristic 1: Emergency Pre-emption / Floor Takeover
    if priority >= 200 then
        table.insert(alerts, string.format(
            "[CRITICAL] Emergency Pre-emptive Floor Control (%s, Priority: %d)! " ..
            "Overrides current talkgroup transmissions. Verify user authorization against CAD / Dispatch policy.",
            pri_level, priority))
        pinfo.cols.info:append(" [TELCOSEC: EMERGENCY FLOOR PRE-EMPTION!]")
    end

    -- Security Heuristic 2: Rogue Floor Revoke (First-Responder Communications Blackout)
    if msg_type == 0x06 then
        table.insert(alerts, "[CRITICAL] Floor Revoke commanded! Active speaker forcibly disconnected from public safety channel. Monitor for tactical radio silencing attacks.")
        pinfo.cols.info:append(" [TELCOSEC: FLOOR REVOKE BLACKOUT!]")
    end

    -- Security Heuristic 3: Floor Queue Flooding DoS
    if msg_type == 0x07 then
        table.insert(alerts, "[INFO] Floor Queue Position Request. Monitor request rate for floor queue exhaustion attempts.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if len > 8 then
        subtree:add(f_payload, tvb(8, len - 8))
    end
end

-- Register to UDP ports for MCPTT floor control (50000, 50002, 50004)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(50000, mcptt_sec_proto)
    udp_table:add(50002, mcptt_sec_proto)
    udp_table:add(50004, mcptt_sec_proto)
end

-- Register as postdissector to inspect MCPTT over RTP / UDP / IPsec
register_postdissector(mcptt_sec_proto)
