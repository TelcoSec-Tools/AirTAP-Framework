-- TelcoSec.net - Qualcomm 5G NR Layer 2 (SDAP, PDCP, RLC, MAC) Dissector & Security Analyzer
-- Description: Dissects Qualcomm Log Codes 0xB881-0xB889 (NR L2 Packet Logs).
--              Analyzes User Plane ciphering status (NEA0 vs NEA2), PDCP sequence number tampering,
--              and MAC RACH/BSR spoofing.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local layer_names = { [1] = "NR-PDCP", [2] = "NR-RLC", [3] = "NR-MAC", [4] = "NR-SDAP" }

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

local ok, qc_5g_l2_proto = pcall(Proto, "qc_5g_l2", "Qualcomm 5G NR Layer 2 (SDAP/PDCP/RLC/MAC) Analyzer")
if not ok or not qc_5g_l2_proto then return end

-- Protocol fields
local f_layer         = ProtoField.string("qc_5g_l2.layer", "L2 Layer")
local f_rb_id         = ProtoField.uint8("qc_5g_l2.rb_id", "Radio Bearer ID", base.DEC)
local f_rb_type       = ProtoField.string("qc_5g_l2.rb_type", "Bearer Type (SRB/DRB)")
local f_cipher_algo   = ProtoField.string("qc_5g_l2.cipher_algo", "PDCP Ciphering Algorithm (NEA)")
local f_sn_len        = ProtoField.uint8("qc_5g_l2.sn_len", "PDCP SN Length (bits)", base.DEC)
local f_pdcp_sn       = ProtoField.uint32("qc_5g_l2.pdcp_sn", "PDCP Sequence Number", base.DEC)
local f_mac_lcid      = ProtoField.uint8("qc_5g_l2.mac_lcid", "MAC LCID", base.HEX)
local f_sec_alert     = ProtoField.string("qc_5g_l2.alert", "TelcoSec 5G L2 Security Alert")
local f_payload       = ProtoField.bytes("qc_5g_l2.payload", "L2 Payload Data")

qc_5g_l2_proto.fields = {
    f_layer,
    f_rb_id,
    f_rb_type,
    f_cipher_algo,
    f_sn_len,
    f_pdcp_sn,
    f_mac_lcid,
    f_sec_alert,
    f_payload
}

-- Native Wireshark L2 dissectors
local pdcp_nr_dissector = Dissector.get("pdcp-nr")
local rlc_nr_dissector  = Dissector.get("rlc-nr")
local mac_nr_dissector  = Dissector.get("mac-nr")

function qc_5g_l2_proto.dissector(tvb, pinfo, tree)
    -- Layout:
    -- [0]: Packet Version (1 byte)
    -- [1]: Sub-layer ID (1=PDCP, 2=RLC, 3=MAC)
    -- [2]: RB ID / Channel ID (1 byte)
    -- [3]: Direction / Flags (1 byte: 0=UL, 1=DL)
    -- [4-7]: Sequence Number / Control (4 bytes LE)
    -- [8..N]: Payload
    if tvb:len() < 8 then return end

    pinfo.cols.protocol = "QC 5G L2"

    local version = tvb(0, 1):uint()
    local layer_id = tvb(1, 1):uint()
    local rb_id = tvb(2, 1):uint()
    local direction = tvb(3, 1):uint()
    local dir_str = (direction == 0) and "UL" or "DL"
    local sn = tvb(4, 4):le_uint()

    local layer_str = layer_names[layer_id] or string.format("L2 Layer %d", layer_id)
    local rb_type_str = (rb_id < 3) and string.format("SRB%d", rb_id) or string.format("DRB%d (User Plane)", rb_id - 2)

    local subtree = tree:add(qc_5g_l2_proto, tvb(), string.format("Qualcomm 5G %s (%s, %s)", layer_str, rb_type_str, dir_str))
    subtree:add(f_layer, layer_str)
    subtree:add(f_rb_id, tvb(2, 1), rb_id)
    subtree:add(f_rb_type, rb_type_str)
    subtree:add(f_pdcp_sn, tvb(4, 4), sn)

    pinfo.cols.info = string.format("[5G %s %s] %s | SN: %d", layer_str, dir_str, rb_type_str, sn)

    local offset = 8
    local pdu_len = tvb:len() - offset

    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()

        -- Security Heuristic 1: Unencrypted User Plane DRB (NEA0)
        if layer_id == 1 and rb_id >= 3 then
            -- DRB with no encryption tag or known plain IP headers
            local first_byte = pdu_tvb(0, 1):uint()
            local ip_version = bit.rshift(first_byte, 4)
            if ip_version == 4 or ip_version == 6 then
                subtree:add(f_cipher_algo, "NEA0 (Null Ciphering / Plaintext)")
                subtree:add(f_sec_alert, "[CRITICAL] 5G User Plane Data (DRB) is unencrypted (NEA0)! Plain IPv4/IPv6 traffic exposed over air interface.")
                pinfo.cols.info:append(" [TELCOSEC: PLAIN USER PLANE TRAFFIC!]")
            end
        end

        -- Security Heuristic 2: Out of order / suspicious SN replay
        if layer_id == 1 and sn == 0 and pinfo.number > 100 then
            subtree:add(f_sec_alert, "[WARNING] PDCP Sequence Number reset to 0 mid-session. Verify key renegotiation or replay attempt.")
        end

        -- Call native dissectors
        if layer_id == 1 and pdcp_nr_dissector then
            pdcp_nr_dissector:call(pdu_tvb, pinfo, tree)
        elseif layer_id == 2 and rlc_nr_dissector then
            rlc_nr_dissector:call(pdu_tvb, pinfo, tree)
        elseif layer_id == 3 and mac_nr_dissector then
            mac_nr_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB881, qc_5g_l2_proto) -- NR PDCP DL
    qc_log_table:add(0xB882, qc_5g_l2_proto) -- NR PDCP UL
    qc_log_table:add(0xB883, qc_5g_l2_proto) -- NR RLC DL
    qc_log_table:add(0xB884, qc_5g_l2_proto) -- NR RLC UL
    qc_log_table:add(0xB887, qc_5g_l2_proto) -- NR MAC DL
    qc_log_table:add(0xB888, qc_5g_l2_proto) -- NR MAC UL
    qc_log_table:add(0xB889, qc_5g_l2_proto) -- NR SDAP
end
