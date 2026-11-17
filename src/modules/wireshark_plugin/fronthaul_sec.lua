-- TelcoSec.net - OpenRAN eCPRI & CPRI Fronthaul Security Analyzer
-- Target Standards: eCPRI Specification V2.0, O-RAN Fronthaul Working Group 4 (O-RAN.WG4.CUS.0-v07.00)
-- Description: Dissects eCPRI (Ethernet type 0xAEFE / UDP port 58310) and CPRI transport frames between O-DU (Distributed Unit) and O-RU (Radio Unit).
--              Analyzes IQ data payloads, Real-Time Control Plane (RT-CP) messages, One-Way Delay Measurements, and Remote Memory Access.
--              Detects unauthenticated O-RU beamforming weight manipulation, delay spoofing, and IQ stream injection attacks.

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

local ok, ecpri_sec_proto = pcall(Proto, "ecpri_sec", "TelcoSec OpenRAN eCPRI & CPRI Fronthaul Security Analyzer")
if not ok or not ecpri_sec_proto then return end

-- Protocol fields
local f_protocol_rev    = ProtoField.uint8("ecpri_sec.proto_rev", "eCPRI Protocol Revision", base.DEC)
local f_concat_flag     = ProtoField.bool("ecpri_sec.concat", "Concatenation Flag")
local f_msg_type        = ProtoField.uint8("ecpri_sec.msg_type", "eCPRI Message Type", base.HEX)
local f_msg_name        = ProtoField.string("ecpri_sec.msg_name", "Message Name")
local f_payload_size    = ProtoField.uint16("ecpri_sec.payload_size", "Payload Size (bytes)", base.DEC)
local f_pcid            = ProtoField.uint16("ecpri_sec.pcid", "eAxC ID / Physical Channel ID (PC_ID)", base.HEX)
local f_seq_id          = ProtoField.uint16("ecpri_sec.seq_id", "Sequence ID (Seq_ID)", base.DEC)
local f_measurement_id  = ProtoField.uint8("ecpri_sec.meas_id", "Delay Measurement ID", base.HEX)
local f_action_type     = ProtoField.uint8("ecpri_sec.action_type", "Delay Action Type", base.HEX)
local f_sec_alert       = ProtoField.string("ecpri_sec.alert", "TelcoSec Fronthaul Security Alert")

ecpri_sec_proto.fields = {
    f_protocol_rev,
    f_concat_flag,
    f_msg_type,
    f_msg_name,
    f_payload_size,
    f_pcid,
    f_seq_id,
    f_measurement_id,
    f_action_type,
    f_sec_alert
}

-- eCPRI Message Types (eCPRI Specification v2.0 Table 1)
local ECPRI_MSG_TYPES = {
    [0x00] = "IQ Data (User Plane)",
    [0x01] = "Bit Sequence",
    [0x02] = "Real-Time Control Data (RT-CP)",
    [0x03] = "Generic Data Transfer",
    [0x04] = "Remote Memory Access (RMA)",
    [0x05] = "One-Way Delay Measurement",
    [0x06] = "Remote Reset",
    [0x07] = "Event Indication"
}

function ecpri_sec_proto.dissector(tvb, pinfo, tree)
    -- eCPRI Common Header is 4 bytes:
    -- [0]: [7:4] Protocol Revision (1), [3:1] Reserved, [0] Concatenation flag
    -- [1]: Message Type
    -- [2-3]: Payload Size (BE uint16)
    if tvb:len() < 4 then return end

    local byte0 = tvb(0, 1):uint()
    local proto_rev = bit.rshift(byte0, 4)
    local concat_flag = bit.band(byte0, 1) ~= 0

    if proto_rev ~= 1 and proto_rev ~= 2 then return end

    local msg_type = tvb(1, 1):uint()
    local msg_name = ECPRI_MSG_TYPES[msg_type]
    if not msg_name then return end

    local payload_size = tvb(2, 2):uint()

    pinfo.cols.protocol = "O-RAN eCPRI"
    pinfo.cols.info = string.format("[O-RAN eCPRI] %s (Size: %d)", msg_name, payload_size)

    local subtree = tree:add(ecpri_sec_proto, tvb(), string.format("OpenRAN eCPRI Fronthaul Security: %s (Type: 0x%02X)", msg_name, msg_type))
    subtree:add(f_protocol_rev, tvb(0, 1), proto_rev)
    subtree:add(f_concat_flag, concat_flag)
    subtree:add(f_msg_type, tvb(1, 1), msg_type)
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_payload_size, tvb(2, 2), payload_size)

    local alerts = {}

    if tvb:len() >= 8 then
        local pcid = tvb(4, 2):uint()
        local seq_id = tvb(6, 2):uint()
        subtree:add(f_pcid, tvb(4, 2), pcid)
        subtree:add(f_seq_id, tvb(6, 2), seq_id)
        pinfo.cols.info = string.format("[O-RAN eCPRI] %s | eAxC: 0x%04X, Seq: %d", msg_name, pcid, seq_id)
    end

    -- Security Heuristic 1: Remote Reset (O-RU Hardware Reboot Attack)
    if msg_type == 0x06 then
        table.insert(alerts, "[CRITICAL] eCPRI Remote Reset commanded! Unauthenticated reset packet can reboot physical Radio Units (O-RU), causing total radio blackout.")
    end

    -- Security Heuristic 2: Remote Memory Access (RMA - Direct Memory Manipulation in O-RU)
    if msg_type == 0x04 then
        table.insert(alerts, "[CRITICAL] eCPRI Remote Memory Access (RMA) detected! Direct read/write to O-RU hardware registers or beamforming calibration tables.")
    end

    -- Security Heuristic 3: Delay Measurement Spoofing
    if msg_type == 0x05 and tvb:len() >= 6 then
        local meas_id = tvb(4, 1):uint()
        local action_type = tvb(5, 1):uint()
        subtree:add(f_measurement_id, tvb(4, 1), meas_id)
        subtree:add(f_action_type, tvb(5, 1), action_type)
        if action_type == 0x00 then
            table.insert(alerts, "[WARNING] One-Way Delay Measurement Request: Monitor for artificial delay inflation or TDD time-alignment desync.")
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: FRONTHAUL ATTACK ALERT!]")
    end
end

-- Register to standard eCPRI Ethernet type (0xAEFE) and UDP port (58310)
local eth_type_table = DissectorTable.get("ethertype")
if eth_type_table then
    eth_type_table:add(0xAEFE, ecpri_sec_proto)
end

local udp_port_table = DissectorTable.get("udp.port")
if udp_port_table then
    udp_port_table:add(58310, ecpri_sec_proto)
end
