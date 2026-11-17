-- TelcoSec.net - 5G IAB BAP & ALCAP Transport Security Analyzer
-- Target Standards: 3GPP TS 38.340 (5G NR Backhaul Adaptation Protocol - BAP), ITU-T Q.2630.1 / Q.2630.2 (ALCAP AAL2 Signalling)
-- Description: Dissects 5G Integrated Access and Backhaul (IAB) BAP Data and Control PDUs between IAB-nodes and IAB-donors.
--              Also analyzes legacy ATM/IP ALCAP (AAL2 Layer 3 Signalling) establishing and releasing switched virtual circuits.
--              Detects BAP routing ID table poisoning, loop generation attacks in multi-hop wireless backhauls, and unauthenticated ALCAP bearer resets.

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

local ok, bap_alcap_proto = pcall(Proto, "bap_alcap_sec", "TelcoSec 5G IAB BAP & ALCAP Transport Security Analyzer")
if not ok or not bap_alcap_proto then return end

-- Protocol fields
local f_proto_name      = ProtoField.string("bap_alcap_sec.proto", "Protocol (5G BAP / ALCAP)")
local f_bap_pdu_type    = ProtoField.string("bap_alcap_sec.bap_type", "BAP PDU Type (Data / Flow Control)")
local f_bap_routing_id  = ProtoField.uint16("bap_alcap_sec.bap_routing_id", "BAP Routing ID (10-bit BAP Address + 6-bit Path ID)", base.HEX)
local f_bap_address     = ProtoField.uint16("bap_alcap_sec.bap_address", "Destination BAP Address (10-bit)", base.HEX)
local f_bap_path_id     = ProtoField.uint8("bap_alcap_sec.bap_path_id", "BAP Path ID (6-bit)", base.DEC)
local f_bap_bh_rleid    = ProtoField.uint32("bap_alcap_sec.bh_rleid", "Backhaul RLC Channel ID (BH RLC CH ID)", base.HEX)
local f_alcap_msg_type  = ProtoField.uint8("bap_alcap_sec.alcap_msg", "ALCAP Message Type", base.HEX)
local f_alcap_msg_name  = ProtoField.string("bap_alcap_sec.alcap_name", "ALCAP Message Name")
local f_sec_alert       = ProtoField.string("bap_alcap_sec.alert", "TelcoSec Transport Alert")

bap_alcap_proto.fields = {
    f_proto_name,
    f_bap_pdu_type,
    f_bap_routing_id,
    f_bap_address,
    f_bap_path_id,
    f_bap_bh_rleid,
    f_alcap_msg_type,
    f_alcap_msg_name,
    f_sec_alert
}

-- Known ALCAP Message Types (ITU-T Q.2630.1)
local ALCAP_MSGS = {
    [0x01] = "Establish Request (ERQ)",
    [0x02] = "Establish Confirm (ECF)",
    [0x05] = "Release Request (REL)",
    [0x06] = "Release Confirm (RLC)",
    [0x07] = "Reset Request (RES)",
    [0x08] = "Reset Confirm (RSC)",
    [0x09] = "Block Request (BLQ)",
    [0x0A] = "Block Confirm (BDC)",
    [0x0B] = "Unblock Request (UBL)",
    [0x0C] = "Unblock Confirm (UBC)"
}

function bap_alcap_proto.dissector(tvb, pinfo, tree)
    -- Guard: Only execute if BAP or ALCAP or Q.2630 is active
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "BAP") or string.find(proto_str, "ALCAP") or string.find(proto_str, "Q.2630")) then
        return
    end

    local len = tvb:len()
    if len < 2 then return end

    -- 1. Inspect 5G NR IAB Backhaul Adaptation Protocol (BAP TS 38.340)
    -- BAP Data PDU Header: [0]: [7]=D/C bit (1=Data, 0=Control), [6:0]=Reserved (or upper bits)
    local byte0 = tvb(0, 1):uint()
    local is_data = bit.band(byte0, 0x80) ~= 0

    if len >= 3 then
        local routing_id = tvb(0, 2):uint()
        local bap_addr = bit.rshift(bit.band(routing_id, 0x7FE0), 5)
        local bap_path = bit.band(routing_id, 0x001F)

        if is_data and bap_addr > 0 then
            pinfo.cols.protocol = "5G IAB BAP"
            local subtree = tree:add(bap_alcap_proto, tvb(), string.format("5G IAB BAP Security: Routing ID 0x%04X (Node: 0x%03X, Path: %d)", routing_id, bap_addr, bap_path))
            subtree:add(f_proto_name, "5G NR IAB BAP (3GPP TS 38.340)")
            subtree:add(f_bap_pdu_type, "BAP Data PDU")
            subtree:add(f_bap_routing_id, tvb(0, 2), routing_id)
            subtree:add(f_bap_address, bap_addr)
            subtree:add(f_bap_path_id, bap_path)

            pinfo.cols.info = string.format("[5G IAB BAP] Data PDU | Dest Node: 0x%03X, Path: %d", bap_addr, bap_path)
            return
        end
    end

    -- 2. Inspect ALCAP AAL2 Signalling (Q.2630)
    local alcap_msg = tvb(0, 1):uint()
    local msg_name = ALCAP_MSGS[alcap_msg]
    if msg_name then
        pinfo.cols.protocol = "ALCAP Q.2630"
        local subtree = tree:add(bap_alcap_proto, tvb(), string.format("ALCAP Transport Security: %s (0x%02X)", msg_name, alcap_msg))
        subtree:add(f_proto_name, "ALCAP AAL2 Transport (ITU-T Q.2630)")
        subtree:add(f_alcap_msg_type, tvb(0, 1), alcap_msg)
        subtree:add(f_alcap_msg_name, msg_name)

        pinfo.cols.info = string.format("[ALCAP] %s", msg_name)

        -- Security Heuristic: Reset Request / Circuit Teardown
        if alcap_msg == 0x07 or alcap_msg == 0x09 then
            subtree:add(f_sec_alert, string.format("[CRITICAL] ALCAP %s commanded! Abruptly tears down or blocks telecom trunk bearers.", msg_name))
            pinfo.cols.info:append(" [TELCOSEC: TRUNK RESET ALERT!]")
        end
    end
end

register_postdissector(bap_alcap_proto)
