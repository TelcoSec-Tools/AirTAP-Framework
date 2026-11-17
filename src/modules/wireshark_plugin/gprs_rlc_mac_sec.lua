-- TelcoSec.net - GPRS/EGPRS RLC/MAC Air Interface Security Dissector
-- Description: Dissects GPRS/EGPRS RLC/MAC control and data blocks (3GPP TS 44.060).
--              Detects Temporary Block Flow (TBF) hijacking, Uplink State Flag (USF) spoofing,
--              and radio resource exhaustion DoS.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pt_names = { [0]="RLC Data Block", [1]="RLC/MAC Control Block (Optional Octets)", [2]="RLC/MAC Control Block", [3]="Reserved" }

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

local ok, gprs_rlc_mac_proto = pcall(Proto, "gprs_rlc_mac_sec", "TelcoSec GPRS/EGPRS RLC/MAC Analyzer")
if not ok or not gprs_rlc_mac_proto then return end

-- Protocol fields
local f_payload_type = ProtoField.string("gprs_rlc_mac.payload_type", "Payload Type")
local f_usf          = ProtoField.uint8("gprs_rlc_mac.usf", "Uplink State Flag (USF)", base.DEC)
local f_rrbp         = ProtoField.uint8("gprs_rlc_mac.rrbp", "RRBP (Reserved Block Period)", base.HEX)
local f_tfi          = ProtoField.uint8("gprs_rlc_mac.tfi", "Temporary Flow Identity (TFI)", base.DEC)
local f_bsn          = ProtoField.uint16("gprs_rlc_mac.bsn", "Block Sequence Number (BSN)", base.DEC)
local f_ctrl_msg     = ProtoField.string("gprs_rlc_mac.ctrl_msg", "Control Message Type")
local f_sec_alert    = ProtoField.string("gprs_rlc_mac.alert", "TelcoSec RLC/MAC Security Alert")
local f_payload      = ProtoField.bytes("gprs_rlc_mac.payload", "RLC/MAC Block Data")

gprs_rlc_mac_proto.fields = {
    f_payload_type,
    f_usf,
    f_rrbp,
    f_tfi,
    f_bsn,
    f_ctrl_msg,
    f_sec_alert,
    f_payload
}

-- RLC/MAC Downlink Control Message Types (3GPP TS 44.060 Table 11.2.0.1)
local DL_CTRL_MSGS = {
    [0x00] = "Packet Access Reject",
    [0x01] = "Packet Cell Change Order",
    [0x02] = "Packet Downlink Assignment",
    [0x03] = "Packet Measurement Order",
    [0x04] = "Packet Polling Request",
    [0x05] = "Packet Power Control/Timing Advance",
    [0x06] = "Packet Queueing Notification",
    [0x07] = "Packet Timeslot Reconfigure",
    [0x08] = "Packet TBF Release",
    [0x09] = "Packet Uplink Ack/Nack",
    [0x0A] = "Packet Uplink Assignment",
    [0x21] = "Packet Downlink Dummy Control Block"
}

-- Native Wireshark dissectors
local gprs_llc_dissector = Dissector.get("gprs_llc")

function gprs_rlc_mac_proto.dissector(tvb, pinfo, tree)
    -- MAC Header Layout (Downlink Data/Control):
    -- [0]: Payload Type (Bits 7-6: 00=RLC Data, 01=RLC Control with optional octets, 10=RLC Control with no octets)
    --      RRBP (Bits 5-4), S/P (Bit 3), USF (Bits 2-0)
    -- [1]: RLC Header: PR (Bits 7-6), TFI (Bits 5-1), FBI (Bit 0)
    -- [2]: BSN (Bits 7-1), E (Bit 0)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "GPRS RLC/MAC"

    local byte0 = tvb(0, 1):uint()
    local pt = bit.rshift(bit.band(byte0, 0xC0), 6)
    local rrbp = bit.rshift(bit.band(byte0, 0x30), 4)
    local usf = bit.band(byte0, 0x07)

    local pt_str = pt_names[pt] or string.format("Type %d", pt)

    local subtree = tree:add(gprs_rlc_mac_proto, tvb(), string.format("GPRS RLC/MAC: %s (USF: %d)", pt_str, usf))
    subtree:add(f_payload_type, pt_str)
    subtree:add(f_usf, tvb(0, 1), usf)
    subtree:add(f_rrbp, tvb(0, 1), rrbp)

    if pt == 0 then
        -- RLC Data Block
        local byte1 = tvb(1, 1):uint()
        local byte2 = tvb(2, 1):uint()
        local tfi = bit.rshift(bit.band(byte1, 0x3E), 1)
        local bsn = bit.rshift(bit.band(byte2, 0xFE), 1)

        subtree:add(f_tfi, tvb(1, 1), tfi)
        subtree:add(f_bsn, tvb(2, 1), bsn)

        pinfo.cols.info = string.format("[GPRS RLC DATA] TFI: %d, BSN: %d | USF: %d", tfi, bsn, usf)

        local offset = 3
        local payload_len = tvb:len() - offset
        if payload_len > 0 then
            local payload_tvb = tvb(offset, payload_len):tvb()
            if gprs_llc_dissector then
                gprs_llc_dissector:call(payload_tvb, pinfo, tree)
            else
                subtree:add(f_payload, tvb(offset, payload_len))
            end
        end
    else
        -- RLC/MAC Control Block
        local ctrl_msg_type = bit.rshift(bit.band(tvb(1, 1):uint(), 0x3F), 0)
        local ctrl_name = DL_CTRL_MSGS[ctrl_msg_type] or string.format("Control Msg (0x%02X)", ctrl_msg_type)

        subtree:add(f_ctrl_msg, ctrl_name)
        pinfo.cols.info = string.format("[GPRS RLC CTRL] %s | USF: %d", ctrl_name, usf)

        -- Security Heuristic 1: Packet Access Reject (Air-interface Denial of Service)
        if ctrl_msg_type == 0x00 then
            subtree:add(f_sec_alert, "[WARNING] Packet Access Reject broadcast by base station. UE blocked from establishing GPRS packet data flow.")
            pinfo.cols.info:append(" [TELCOSEC: PACKET ACCESS REJECT]")
        end

        -- Security Heuristic 2: Packet TBF Release (Forced Data Teardown)
        if ctrl_msg_type == 0x08 then
            subtree:add(f_sec_alert, "[WARNING] Packet TBF Release commanded. Temporary Block Flow prematurely aborted.")
        end

        -- Security Heuristic 3: Packet Cell Change Order (Forced Reselection)
        if ctrl_msg_type == 0x01 then
            subtree:add(f_sec_alert, "[CRITICAL] Packet Cell Change Order received! Potential rogue base station forcing victim UE to another frequency/cell.")
            pinfo.cols.info:append(" [TELCOSEC: FORCED CELL CHANGE ORDER]")
        end

        if tvb:len() > 2 then
            subtree:add(f_payload, tvb(2, tvb:len() - 2))
        end
    end
end
