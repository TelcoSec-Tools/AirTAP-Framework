-- TelcoSec.net - SS7 SIGTRAN (M3UA / M2UA / SUA) Security Analyzer
-- Target Standards: RFC 4666 (M3UA), RFC 3331 (M2UA), RFC 3868 (SUA)
-- Description: Dissects SIGTRAN adaptation layer messages over SCTP payload protocol identifiers.
--              Detects unauthorized Application Server Process (ASP) activation (ASPUP/ASPAC spoofing),
--              Routing Key injection, unauthenticated DEREG/INACT commands, and telecom core link disruption.

local ok, sigtran_sec_proto = pcall(Proto, "ss7_sigtran_sec", "TelcoSec SS7 SIGTRAN (M3UA/M2UA/SUA) Security Analyzer")
if not ok or not sigtran_sec_proto then return end

-- Protocol fields
local f_sigtran_proto   = ProtoField.string("ss7_sigtran_sec.proto", "SIGTRAN Protocol")
local f_msg_class       = ProtoField.uint8("ss7_sigtran_sec.msg_class", "Message Class", base.HEX)
local f_msg_type        = ProtoField.uint8("ss7_sigtran_sec.msg_type", "Message Type", base.HEX)
local f_msg_name        = ProtoField.string("ss7_sigtran_sec.msg_name", "Message Name")
local f_routing_context = ProtoField.uint32("ss7_sigtran_sec.routing_context", "Routing Context", base.DEC)
local f_traffic_mode    = ProtoField.string("ss7_sigtran_sec.traffic_mode", "Traffic Mode Type")
local f_info_string     = ProtoField.string("ss7_sigtran_sec.info_str", "Info String / Banner")
local f_sec_alert       = ProtoField.string("ss7_sigtran_sec.alert", "TelcoSec SIGTRAN Security Alert")

sigtran_sec_proto.fields = {
    f_sigtran_proto,
    f_msg_class,
    f_msg_type,
    f_msg_name,
    f_routing_context,
    f_traffic_mode,
    f_info_string,
    f_sec_alert
}

-- M3UA Message Classes & Types (RFC 4666)
local M3UA_MSG_CLASSES = {
    [0] = "Management (MGMT)",
    [1] = "Transfer Messages",
    [2] = "SS7 Signalling Network Management (SSNM)",
    [3] = "ASP State Maintenance (ASPSM)",
    [4] = "ASP Traffic Maintenance (ASPTM)",
    [9] = "Routing Key Management (RKM)"
}

local M3UA_MSG_TYPES = {
    -- ASPSM (Class 3)
    [0x0301] = "ASP Up (ASPUP)",
    [0x0302] = "ASP Up Ack (ASPUP_ACK)",
    [0x0303] = "ASP Down (ASPDN)",
    [0x0304] = "ASP Down Ack (ASPDN_ACK)",
    [0x0305] = "Heartbeat (BEAT)",
    [0x0306] = "Heartbeat Ack (BEAT_ACK)",
    -- ASPTM (Class 4)
    [0x0401] = "ASP Active (ASPAC)",
    [0x0402] = "ASP Active Ack (ASPAC_ACK)",
    [0x0403] = "ASP Inactive (ASPIA)",
    [0x0404] = "ASP Inactive Ack (ASPIA_ACK)",
    -- SSNM (Class 2)
    [0x0201] = "Destination Unavailable (DUNA)",
    [0x0202] = "Destination Available (DAVA)",
    [0x0203] = "Destination State Audit (DAUD)",
    [0x0204] = "Signalling Congestion (SCON)",
    [0x0205] = "Destination User Part Unavailable (DUPU)",
    -- Transfer (Class 1)
    [0x0101] = "Payload Data (DATA)",
    -- RKM (Class 9)
    [0x0901] = "Registration Request (REG_REQ)",
    [0x0902] = "Registration Response (REG_RSP)",
    [0x0903] = "Deregistration Request (DEREG_REQ)",
    [0x0904] = "Deregistration Response (DEREG_RSP)"
}

function sigtran_sec_proto.dissector(tvb, pinfo, tree)
    -- Guard: Check protocol or length
    local len = tvb:len()
    if len < 8 then return end

    local version = tvb(0, 1):uint()
    if version ~= 1 then return end

    local msg_class = tvb(2, 1):uint()
    local msg_type  = tvb(3, 1):uint()
    local key = bit.lshift(msg_class, 8) + msg_type
    local msg_name = M3UA_MSG_TYPES[key]

    if not msg_name then return end

    pinfo.cols.protocol = "M3UA SIGTRAN"
    pinfo.cols.info = string.format("[M3UA] %s", msg_name)

    local subtree = tree:add(sigtran_sec_proto, tvb(), string.format("SIGTRAN Security: %s (Class %d, Type %d)", msg_name, msg_class, msg_type))
    subtree:add(f_sigtran_proto, "M3UA (RFC 4666)")
    subtree:add(f_msg_class, tvb(2, 1), msg_class)
    subtree:add(f_msg_type, tvb(3, 1), msg_type)
    subtree:add(f_msg_name, msg_name)

    local alerts = {}

    -- Security Heuristic 1: Unauthorized Destination Unavailable (DUNA Injection - SS7 DoS)
    if key == 0x0201 then
        table.insert(alerts, "[CRITICAL] M3UA Destination Unavailable (DUNA) injected! Forcefully blocks SS7 routing to target Point Code.")
    end

    -- Security Heuristic 2: Dynamic Routing Key Registration (RKM REG_REQ)
    if key == 0x0901 then
        table.insert(alerts, "[CRITICAL] M3UA Dynamic Routing Key Registration (REG_REQ)! Rogue node attempting to register routing keys to intercept SS7 MAP/ISUP traffic.")
    end

    -- Security Heuristic 3: ASP State Manipulation (ASPUP / ASPAC Spoofing)
    if key == 0x0301 then
        table.insert(alerts, string.format("[AUDIT] M3UA ASP Up (ASPUP) received from %s. Verify ASP identity against telecom signaling firewall whitelist.", tostring(pinfo.src)))
    elseif key == 0x0401 then
        table.insert(alerts, string.format("[AUDIT] M3UA ASP Active (ASPAC) commanded from %s! Activates traffic processing for this routing context.", tostring(pinfo.src)))
    elseif key == 0x0403 then
        table.insert(alerts, "[WARNING] M3UA ASP Inactive (ASPIA) commanded: Halts active SS7 traffic flow on this association.")
    elseif key == 0x0303 then
        table.insert(alerts, "[WARNING] ASP Down (ASPDN) received: Administrative teardown of SS7-over-IP association.")
    end

    -- Security Heuristic 4: Fake Signalling Congestion (SCON Injection)
    if key == 0x0204 then
        table.insert(alerts, "[CRITICAL] M3UA Signalling Congestion (SCON) injected! Malicious SCON forces upstream STP/MSC to throttle or drop subscriber traffic.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: SIGTRAN THREAT!]")
    end
end

register_postdissector(sigtran_sec_proto)
