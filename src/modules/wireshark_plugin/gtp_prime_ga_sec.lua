-- TelcoSec.net - GTP' (GTP-Prime Ga Interface) Charging & CDR Security Dissector
-- Description: Dissects GTP' protocol (3GPP TS 32.295) on the Ga interface between SGSN/GGSN and Charging Gateway (CG).
--              Detects CDR (Call Detail Record) suppression, free-riding billing bypass fraud, and zero-rating tampering.

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

local ok, gtp_prime_proto = pcall(Proto, "gtp_prime_ga_sec", "TelcoSec GTP' (Ga Charging Interface) Analyzer")
if not ok or not gtp_prime_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gtp_prime.msg_type", "GTP' Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gtp_prime.msg_name", "Message Name")
local f_length       = ProtoField.uint16("gtp_prime.length", "Payload Length", base.DEC)
local f_seq_num      = ProtoField.uint16("gtp_prime.seq_num", "Sequence Number", base.DEC)
local f_cdr_type     = ProtoField.string("gtp_prime.cdr_type", "CDR Type (S-CDR/G-CDR)")
local f_data_vol     = ProtoField.uint64("gtp_prime.data_vol", "Volume Data (Bytes)", base.DEC)
local f_sec_alert    = ProtoField.string("gtp_prime.alert", "TelcoSec Billing Security Alert")
local f_payload      = ProtoField.bytes("gtp_prime.payload", "CDR Information Elements")

gtp_prime_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_length,
    f_seq_num,
    f_cdr_type,
    f_data_vol,
    f_sec_alert,
    f_payload
}

-- GTP' Message Types (3GPP TS 32.295 Table 7.1)
local GTP_PRIME_MSGS = {
    [1]   = "Echo Request",
    [2]   = "Echo Response",
    [3]   = "Version Not Supported",
    [4]   = "Node Alive Request",
    [5]   = "Node Alive Response",
    [6]   = "Redirection Request",
    [7]   = "Redirection Response",
    [240] = "Data Record Transfer Request",
    [241] = "Data Record Transfer Response"
}

function gtp_prime_proto.dissector(tvb, pinfo, tree)
    -- GTP' Header Layout (6 bytes):
    -- [0]: Flags (Bits 7-5=Version '010' or '001', Bit 4=PT '0' for GTP', Bits 2-0=Reserved)
    -- [1]: Message Type (1 byte)
    -- [2-3]: Length (2 bytes BE)
    -- [4-5]: Sequence Number (2 bytes BE)
    if tvb:len() < 6 then return end

    local flags = tvb(0, 1):uint()
    local pt = bit.band(bit.rshift(flags, 4), 0x01)

    -- PT must be 0 for GTP' (distinguishes GTP' from standard GTP)
    if pt ~= 0 then return end

    pinfo.cols.protocol = "GTP' Ga"

    local msg_type = tvb(1, 1):uint()
    local length = tvb(2, 2):uint()
    local seq_num = tvb(4, 5):uint()
    local msg_name = GTP_PRIME_MSGS[msg_type] or string.format("GTP' Msg (0x%02X)", msg_type)

    local subtree = tree:add(gtp_prime_proto, tvb(), string.format("GTP' Ga Charging: %s (Seq: %d)", msg_name, seq_num))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_length, tvb(2, 2))
    subtree:add(f_seq_num, tvb(4, 2))

    pinfo.cols.info = string.format("[GTP' Ga] %s | Seq: %d (Len: %d)", msg_name, seq_num, length)

    -- Security Heuristic 1: Data Record Transfer Request (CDR Transfer Inspection)
    if msg_type == 240 then
        subtree:add(f_sec_alert, "[INFO] Live CDR (Call Detail Record) batch transfer to Charging Gateway. Inspect for rating manipulation or zero-rated data suppression.")
    end

    -- Security Heuristic 2: Redirection Request (Charging Gateway Hijack)
    if msg_type == 6 then
        subtree:add(f_sec_alert, "[CRITICAL] Charging Gateway Redirection Request received! Verify authorized charging cluster topology to prevent billing diversion.")
        pinfo.cols.info:append(" [TELCOSEC: CHARGING REDIRECTION]")
    end

    if tvb:len() > 6 then
        subtree:add(f_payload, tvb(6, tvb:len() - 6))
    end
end

-- Register GTP' to UDP port 3386 (standard Ga port) and TCP port 3386
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(3386, gtp_prime_proto)
end

local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(3386, gtp_prime_proto)
end
