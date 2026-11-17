-- TelcoSec.net - GSM Call Control (CC) & USSD / SS Security Dissector
-- Description: Dissects GSM CC (Call Setup, Connect) and Supplementary Services / USSD (3GPP TS 24.080).
--              Detects unauthorized call-forwarding manipulation (*21*...#), premium-rate fraud,
--              and unsolicited USSD prompts.

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

local ok, gsm_cc_sec_proto = pcall(Proto, "gsm_cc_sec", "TelcoSec GSM Call Control & USSD Analyzer")
if not ok or not gsm_cc_sec_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gsm_cc_sec.msg_type", "CC Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gsm_cc_sec.msg_name", "CC Message Name")
local f_called_num   = ProtoField.string("gsm_cc_sec.called_num", "Called Party Number")
local f_ussd_str     = ProtoField.string("gsm_cc_sec.ussd_string", "USSD Command String")
local f_sec_alert    = ProtoField.string("gsm_cc_sec.alert", "TelcoSec Call Control Alert")
local f_payload      = ProtoField.bytes("gsm_cc_sec.payload", "CC Raw Payload")

gsm_cc_sec_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_called_num,
    f_ussd_str,
    f_sec_alert,
    f_payload
}

-- GSM CC Message Types
local CC_MSG_TYPES = {
    [0x01] = "Alerting",
    [0x02] = "Call Confirmed",
    [0x03] = "Call Proceeding",
    [0x05] = "Setup (Initiate Call)",
    [0x07] = "Connect",
    [0x08] = "Connect Acknowledge",
    [0x0F] = "Connect (Supplementary Services)",
    [0x25] = "Disconnect",
    [0x2A] = "Release",
    [0x2D] = "Release Complete",
    [0x3B] = "Facility (USSD / Supplementary Services)"
}

function gsm_cc_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    local pd = bit.band(tvb(0, 1):uint(), 0x0F)
    local msg_type = bit.band(tvb(1, 1):uint(), 0x3F)

    -- PD 3 = Call Control (CC), PD 11 = Non-call related SS (USSD)
    if pd ~= 3 and pd ~= 11 then return end

    pinfo.cols.protocol = "GSM CC/USSD"

    local msg_name = CC_MSG_TYPES[msg_type] or string.format("Msg (0x%02X)", msg_type)
    local subtree = tree:add(gsm_cc_sec_proto, tvb(), string.format("GSM Call Control: %s", msg_name))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GSM CC] %s", msg_name)

    -- Security Heuristics
    -- 1. Facility / USSD Hijacking / Call Forwarding Injection
    if msg_type == 0x3B or pd == 11 then
        subtree:add(f_sec_alert, "[WARNING] Supplementary Services / USSD transaction. Verify if call forwarding (*21*, *67*) or SIM balance query was user-initiated.")
        pinfo.cols.info:append(" [USSD / FACILITY TRANSACTION]")
    end

    -- 2. Emergency Setup.
    --
    -- 3GPP TS 24.008 10.5.4.33: the Emergency Category IE is a TLV with IEI
    -- 0x2E inside EMERGENCY SETUP / SETUP. Walked to rather than matched as
    -- the substring "0401" anywhere in the message, which collided with
    -- ordinary CC information elements.
    if msg_type == 0x05 and tvb:len() >= 4 then
        local offset = 2        -- octets 0..1 are PD/TI and message type
        local limit = tvb:len()
        local guard = 0

        while offset + 1 < limit and guard < 32 do
            guard = guard + 1
            local iei = tvb(offset, 1):uint()
            local ie_len = tvb(offset + 1, 1):uint()
            if offset + 2 + ie_len > limit then break end

            if iei == 0x2E then
                subtree:add(f_sec_alert, "[INFO] Emergency Call Setup (112 / 911).")
                break
            end

            offset = offset + 2 + ie_len
        end
    end

    if tvb:len() > 2 then
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end
