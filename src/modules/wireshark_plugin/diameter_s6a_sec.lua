-- TelcoSec.net - Diameter S6a / S6d Security Dissector & Post-Dissector
-- Description: Dissects Diameter S6a/S6d messages (3GPP TS 29.272) between MME/SGSN and HSS.
--              Detects 4G EPS Authentication Vector extraction (RAND, AUTN, KASME),
--              rogue MME Update-Location requests, and malicious Cancel-Location DoS attacks.

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

local ok, diameter_s6a_proto = pcall(Proto, "diameter_s6a_sec", "TelcoSec Diameter S6a/S6d (HSS-MME) Security Analyzer")
if not ok or not diameter_s6a_proto then return end

-- Protocol fields
local f_cmd_code     = ProtoField.uint24("diameter_s6a.cmd_code", "Command Code", base.DEC)
local f_cmd_name     = ProtoField.string("diameter_s6a.cmd_name", "Command Name")
local f_is_request   = ProtoField.bool("diameter_s6a.is_request", "Request Flag (R)")
local f_imsi         = ProtoField.string("diameter_s6a.user_name", "User-Name (IMSI)")
local f_origin_host  = ProtoField.string("diameter_s6a.origin_host", "Origin-Host (MME / HSS)")
local f_origin_realm = ProtoField.string("diameter_s6a.origin_realm", "Origin-Realm")
local f_sec_alert    = ProtoField.string("diameter_s6a.alert", "TelcoSec Diameter S6a Alert")
local f_payload      = ProtoField.bytes("diameter_s6a.payload", "Diameter AVPs")

diameter_s6a_proto.fields = {
    f_cmd_code,
    f_cmd_name,
    f_is_request,
    f_imsi,
    f_origin_host,
    f_origin_realm,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 29.272 S6a / S6d Command Codes
local S6A_COMMANDS = {
    [316] = "Update-Location (ULR/ULA)",
    [317] = "Cancel-Location (CLR/CLA)",
    [318] = "Authentication-Information (AIR/AIA)",
    [319] = "Insert-Subscriber-Data (IDR/IDA)",
    [320] = "Delete-Subscriber-Data (DSR/DSA)",
    [321] = "Purge-UE (PUR/PUA)",
    [322] = "Reset (RSR/RSA)",
    [323] = "Notify (NOR/NOA)"
}

-- Native Diameter dissector
local diameter_dissector = Dissector.get("diameter")

function diameter_s6a_proto.dissector(tvb, pinfo, tree)
    -- Diameter Header (20 bytes):
    -- [0]: Version (0x01)
    -- [1-3]: Message Length (3 bytes BE)
    -- [4]: Command Flags (Bit 7=Request, Bit 6=Proxiable, Bit 5=Error, Bit 4=T)
    -- [5-7]: Command Code (3 bytes BE)
    -- [8-11]: Application-ID (4 bytes BE: 16777251 = 3GPP S6a/S6d)
    -- [12-15]: Hop-by-Hop ID
    -- [16-19]: End-to-End ID
    if tvb:len() < 20 then return end

    local version = tvb(0, 1):uint()
    if version ~= 1 then return end

    local app_id = tvb(8, 4):uint()
    -- Application ID 16777251 = 3GPP S6a/S6d
    if app_id ~= 16777251 and app_id ~= 0 then return end

    pinfo.cols.protocol = "Diameter S6a"

    local flags = tvb(4, 1):uint()
    local is_req = bit.band(flags, 0x80) ~= 0
    local cmd_code = tvb(5, 3):uint()
    local cmd_name = S6A_COMMANDS[cmd_code] or string.format("Command %d", cmd_code)
    local msg_type_str = is_req and "Request" or "Answer"

    local subtree = tree:add(diameter_s6a_proto, tvb(), string.format("Diameter S6a: %s (%s)", cmd_name, msg_type_str))
    subtree:add(f_cmd_code, tvb(5, 3), cmd_code)
    subtree:add(f_cmd_name, cmd_name)
    subtree:add(f_is_request, is_req)

    pinfo.cols.info = string.format("[Diameter S6a] %s (%s)", cmd_name, msg_type_str)

    -- Security Heuristic 1: Authentication-Information-Request / Answer (AIR/AIA - KASME Extraction)
    if cmd_code == 318 then
        if is_req then
            subtree:add(f_sec_alert, "[CRITICAL] Authentication-Information-Request (AIR) querying 4G EPS security vectors (RAND/AUTN/KASME).")
            pinfo.cols.info:append(" [TELCOSEC: EPS AUTH VECTOR REQUEST]")
        else
            subtree:add(f_sec_alert, "[CRITICAL] Authentication-Information-Answer (AIA) containing cryptographic KASME master keys!")
            pinfo.cols.info:append(" [TELCOSEC: KASME KEYS TRANSMITTED]")
        end
    end

    -- Security Heuristic 2: Update-Location-Request (ULR - Rogue MME Registration)
    if cmd_code == 316 and is_req then
        subtree:add(f_sec_alert, "[CRITICAL] Update-Location-Request (ULR) from MME. Rogue MME injection allows intercepting all subscriber calls/SMS/data.")
        pinfo.cols.info:append(" [TELCOSEC: MME LOCATION REGISTRATION]")
    end

    -- Security Heuristic 3: Cancel-Location-Request (CLR - Forced Subscriber Disconnect DoS)
    if cmd_code == 317 and is_req then
        subtree:add(f_sec_alert, "[WARNING] Cancel-Location-Request (CLR) commanded. Forces MME to purge subscriber context.")
    end

    if diameter_dissector then
        diameter_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(20, tvb:len() - 20))
    end
end

-- Register to Diameter standard port 3868
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(3868, diameter_s6a_proto)
end

local tcp_port_table = DissectorTable.get("tcp.port")
if tcp_port_table then
    tcp_port_table:add(3868, diameter_s6a_proto)
end
