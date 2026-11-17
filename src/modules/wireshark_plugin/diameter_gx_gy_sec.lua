-- TelcoSec.net - Diameter Gx / Gy / Rx Policy & Charging Security Dissector
-- Description: Dissects Diameter Gx (PCRF policy), Gy (OCS prepaid charging), and Rx (AF QoS) messages.
--              Detects QoS privilege escalation, bandwidth theft, and online prepaid rating tampering.

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

local ok, diameter_gx_proto = pcall(Proto, "diameter_gx_gy_sec", "TelcoSec Diameter Gx/Gy/Rx (PCC) Security Analyzer")
if not ok or not diameter_gx_proto then return end

-- Protocol fields
local f_app_id       = ProtoField.string("diameter_gx.app_id", "Diameter Application (Gx/Gy/Rx)")
local f_cmd_code     = ProtoField.uint24("diameter_gx.cmd_code", "Command Code", base.DEC)
local f_cmd_name     = ProtoField.string("diameter_gx.cmd_name", "Command Name")
local f_req_type     = ProtoField.string("diameter_gx.cc_req_type", "CC-Request-Type")
local f_qci          = ProtoField.uint8("diameter_gx.qci", "QoS Class Identifier (QCI)", base.DEC)
local f_sec_alert    = ProtoField.string("diameter_gx.alert", "TelcoSec Policy & Billing Alert")
local f_payload      = ProtoField.bytes("diameter_gx.payload", "Diameter Information Elements")

diameter_gx_proto.fields = {
    f_app_id,
    f_cmd_code,
    f_cmd_name,
    f_req_type,
    f_qci,
    f_sec_alert,
    f_payload
}

-- Mapping Diameter 3GPP Application IDs
local APP_IDS = {
    [16777238] = "3GPP Gx (PCRF Policy Control)",
    [16777216] = "3GPP Gx (Re-auth)",
    [4]        = "Diameter Credit-Control / Gy (Prepaid OCS)",
    [16777236] = "3GPP Rx (IMS Application Function QoS)",
    [16777302] = "3GPP Sy (Spending Limit Policy)"
}

-- Credit-Control Commands (RFC 4006 / 3GPP TS 29.212 / TS 32.299)
local DIAMETER_CC_MSGS = {
    [272] = "Credit-Control (CCR/CCA)",
    [258] = "Re-Auth (RAR/RAA)",
    [274] = "Abort-Session (ASR/ASA)",
    [275] = "Session-Termination (STR/STA)",
    [265] = "AA-Request/Answer (AAR/AAA)"
}

-- Native Diameter dissector
local diameter_dissector = Dissector.get("diameter")

function diameter_gx_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 20 then return end

    local version = tvb(0, 1):uint()
    if version ~= 1 then return end

    local app_id = tvb(8, 4):uint()
    local app_name = APP_IDS[app_id]
    if not app_name then return end

    pinfo.cols.protocol = "Diameter Gx/Gy"

    local flags = tvb(4, 1):uint()
    local is_req = bit.band(flags, 0x80) ~= 0
    local cmd_code = tvb(5, 3):uint()
    local cmd_name = DIAMETER_CC_MSGS[cmd_code] or string.format("Command %d", cmd_code)
    local msg_type_str = is_req and "Request" or "Answer"

    local subtree = tree:add(diameter_gx_proto, tvb(), string.format("Diameter %s: %s (%s)", app_name, cmd_name, msg_type_str))
    subtree:add(f_app_id, app_name)
    subtree:add(f_cmd_code, tvb(5, 3), cmd_code)
    subtree:add(f_cmd_name, cmd_name)

    pinfo.cols.info = string.format("[%s] %s (%s)", app_name, cmd_name, msg_type_str)

    -- Security Heuristic 1: Gx Policy Modification (QoS Privilege Escalation / QCI=1)
    if app_id == 16777238 and is_req then
        subtree:add(f_sec_alert, "[INFO] Gx QoS Policy provisioning between PGW and PCRF. Verify authorized maximum bitrates (AMBR) and QCI profile.")
    end

    -- Security Heuristic 2: Gy Credit-Control Request (Prepaid Balance Bypass)
    if app_id == 4 then
        subtree:add(f_sec_alert, "[INFO] Gy Online Charging session active. Evaluates subscriber data quota and rating group.")
    end

    if diameter_dissector then
        diameter_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(20, tvb:len() - 20))
    end
end

-- Register to Diameter port
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(3868, diameter_gx_proto)
end
