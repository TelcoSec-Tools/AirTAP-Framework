-- TelcoSec.net - GPRS Subnetwork Dependent Convergence Protocol (SNDCP) Dissector
-- Description: Dissects GPRS SNDCP frames (3GPP TS 44.065) transporting User Plane IP traffic.
--              Inspects unencrypted IPv4/IPv6 packet data, DNS queries, and compression headers over 2G GPRS/EDGE.

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

local ok, gprs_sndcp_proto = pcall(Proto, "gprs_sndcp_sec", "TelcoSec GPRS SNDCP User Plane Analyzer")
if not ok or not gprs_sndcp_proto then return end

-- Protocol fields
local f_nsapi        = ProtoField.uint8("gprs_sndcp_sec.nsapi", "NSAPI (Network SAPI)", base.DEC)
local f_first_seg    = ProtoField.bool("gprs_sndcp_sec.first_seg", "First Segment (F)")
local f_more_seg     = ProtoField.bool("gprs_sndcp_sec.more_seg", "More Segments (M)")
local f_pcomp        = ProtoField.uint8("gprs_sndcp_sec.pcomp", "Packet Compression (PCOMP)", base.DEC)
local f_dcomp        = ProtoField.uint8("gprs_sndcp_sec.dcomp", "Data Compression (DCOMP)", base.DEC)
local f_sec_alert    = ProtoField.string("gprs_sndcp_sec.alert", "TelcoSec SNDCP Alert")
local f_payload      = ProtoField.bytes("gprs_sndcp_sec.payload", "SNDCP User Plane IP Packet")

gprs_sndcp_proto.fields = {
    f_nsapi,
    f_first_seg,
    f_more_seg,
    f_pcomp,
    f_dcomp,
    f_sec_alert,
    f_payload
}

-- Native IP dissectors
local ip_dissector   = Dissector.get("ip")
local ipv6_dissector = Dissector.get("ipv6")

function gprs_sndcp_proto.dissector(tvb, pinfo, tree)
    -- SNDCP Header Layout:
    -- [0]: First byte: Bit 7=Spare, Bit 6=First Segment (F), Bit 5=More (M), Bits 3-0=NSAPI
    -- [1]: Compression header (PCOMP, DCOMP)
    -- [2..N]: Upper Layer Protocol (IPv4, IPv6, PPP)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "GPRS SNDCP"

    local byte0 = tvb(0, 1):uint()
    local first_seg = bit.band(byte0, 0x40) ~= 0
    local more_seg = bit.band(byte0, 0x20) ~= 0
    local nsapi = bit.band(byte0, 0x0F)

    local subtree = tree:add(gprs_sndcp_proto, tvb(), string.format("GPRS SNDCP (NSAPI: %d)", nsapi))
    subtree:add(f_nsapi, tvb(0, 1), nsapi)
    subtree:add(f_first_seg, tvb(0, 1), first_seg)
    subtree:add(f_more_seg, tvb(0, 1), more_seg)

    pinfo.cols.info = string.format("[GPRS SNDCP] NSAPI: %d (First: %s, More: %s)", nsapi, tostring(first_seg), tostring(more_seg))

    local offset = 1
    if first_seg then
        local byte1 = tvb(1, 1):uint()
        local pcomp = bit.rshift(bit.band(byte1, 0xF0), 4)
        local dcomp = bit.band(byte1, 0x0F)
        subtree:add(f_pcomp, tvb(1, 1), pcomp)
        subtree:add(f_dcomp, tvb(1, 1), dcomp)
        offset = 2
    end

    local payload_len = tvb:len() - offset
    if payload_len > 0 then
        local payload_tvb = tvb(offset, payload_len):tvb()
        local ip_ver = bit.rshift(payload_tvb(0, 1):uint(), 4)

        if ip_ver == 4 and ip_dissector then
            subtree:add(f_sec_alert, "[INFO] Plain IPv4 user plane packet extracted from GPRS bearer.")
            ip_dissector:call(payload_tvb, pinfo, tree)
        elseif ip_ver == 6 and ipv6_dissector then
            subtree:add(f_sec_alert, "[INFO] Plain IPv6 user plane packet extracted from GPRS bearer.")
            ipv6_dissector:call(payload_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, payload_len))
        end
    end
end
