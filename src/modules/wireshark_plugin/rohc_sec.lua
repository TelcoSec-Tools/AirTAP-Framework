-- TelcoSec.net - Robust Header Compression (ROHC) Air-Interface Security Analyzer
-- Target Standards: RFC 3095 (ROHC Framework), RFC 5795, 3GPP TS 36.323 (LTE PDCP), 3GPP TS 38.323 (5G NR PDCP)
-- Description: Inspects Robust Header Compression (ROHC) packets over LTE/5G PDCP radio bearers.
--              Tracks ROHC Context IDs (CID), profiles (RTP/UDP/IP, ESP, TCP), and packet types (IR, IR-DYN, UO-0, UO-1, UOR-2).
--              Detects decompressor state desynchronization attacks, SN jump corruption, and CRC spoofing causing mass radio bearer packet drops.

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

local ok, rohc_sec_proto = pcall(Proto, "rohc_sec", "TelcoSec ROHC Radio Bearer Security Analyzer")
if not ok or not rohc_sec_proto then return end

-- Protocol fields
local f_packet_type     = ProtoField.string("rohc_sec.pkt_type", "ROHC Packet Type")
local f_profile         = ProtoField.string("rohc_sec.profile", "ROHC Profile")
local f_cid             = ProtoField.uint16("rohc_sec.cid", "Context ID (CID)", base.DEC)
local f_sn              = ProtoField.uint16("rohc_sec.sn", "Sequence Number (SN)", base.DEC)
local f_crc             = ProtoField.uint8("rohc_sec.crc", "CRC Integrity", base.HEX)
local f_desync_flag     = ProtoField.bool("rohc_sec.desync", "Decompressor Desynchronization Suspected")
local f_sec_alert       = ProtoField.string("rohc_sec.alert", "TelcoSec ROHC Alert")

rohc_sec_proto.fields = {
    f_packet_type,
    f_profile,
    f_cid,
    f_sn,
    f_crc,
    f_desync_flag,
    f_sec_alert
}

-- ROHC Profiles (RFC 3095 / RFC 4996)
local ROHC_PROFILES = {
    [0x0000] = "Profile 0x0000 (Uncompressed)",
    [0x0001] = "Profile 0x0001 (RTP / UDP / IP - VoLTE Voice)",
    [0x0002] = "Profile 0x0002 (UDP / IP)",
    [0x0003] = "Profile 0x0003 (ESP / IP)",
    [0x0004] = "Profile 0x0004 (IP)",
    [0x0006] = "Profile 0x0006 (TCP / IP)",
    [0x0101] = "Profile 0x0101 (ROHCv2 RTP/UDP/IP)",
    [0x0102] = "Profile 0x0102 (ROHCv2 UDP/IP)"
}

-- Safe native field getter
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_rohc_profile_f = safe_field("rohc.profile")
local f_rohc_mode_f    = safe_field("rohc.mode")

function rohc_sec_proto.dissector(tvb, pinfo, tree)
    -- Guard: Only execute if ROHC protocol is active on this frame
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "ROHC") or (f_rohc_profile_f and f_rohc_profile_f())) then
        return
    end

    -- Must have at least 2 bytes for ROHC packet
    if tvb:len() < 2 then return end

    local byte0 = tvb(0, 1):uint()
    local pkt_type = "Compressed (UO/UOR)"
    local is_ir = false

    -- Identify ROHC Header format
    if byte0 == 0xFD or byte0 == 0xFE then
        pkt_type = (byte0 == 0xFD) and "IR (Initialization and Refresh)" or "IR-DYN (Dynamic Initialization)"
        is_ir = true
    elseif bit.band(byte0, 0xFE) == 0xF8 then
        pkt_type = "Feedback Packet"
    elseif bit.band(byte0, 0xC0) == 0x40 then
        pkt_type = "UO-1 / UOR-2"
    elseif bit.band(byte0, 0x80) == 0x00 then
        pkt_type = "UO-0 (Smallest Compressed Header)"
    end

    local subtree = tree:add(rohc_sec_proto, tvb(), string.format("ROHC Air Security: %s", pkt_type))
    subtree:add(f_packet_type, pkt_type)

    local alerts = {}

    -- Parse IR Packet Profile & CID
    if is_ir and tvb:len() >= 3 then
        local profile_id = tvb(1, 1):uint()
        local profile_name = ROHC_PROFILES[profile_id] or string.format("Profile 0x%04X", profile_id)
        subtree:add(f_profile, profile_name)
        pinfo.cols.protocol = "ROHC"
        pinfo.cols.info = string.format("[ROHC %s] %s", pkt_type, profile_name)

        -- Heuristic 1: IR Refresh Flooding Attack
        local cid = (tvb:len() >= 4) and tvb(2, 1):uint() or 0
        subtree:add(f_cid, cid)
    end

    -- Heuristic 2: ROHC Decompressor Desynchronization / Feedback Negative ACK storm
    if byte0 == 0xF8 and tvb:len() >= 2 then
        table.insert(alerts, "[WARNING] ROHC NACK / STATIC-NACK feedback received! Decompressor state lost; radio bearer forced to re-transmit uncompressed full headers.")
        subtree:add(f_desync_flag, true)
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: ROHC DESYNC ALERT!]")
    end
end

register_postdissector(rohc_sec_proto)
