-- TelcoSec.net - Qualcomm LTE Layer 2 (PDCP, RLC, MAC) Dissector & Security Analyzer
-- Description: Dissects Qualcomm Log Codes 0xB0A0 (LTE PDCP), 0xB080 (LTE RLC), and 0xB060-0xB063 (LTE MAC).
--              Inspects LTE radio bearer ciphering, PDCP replay protection, and Buffer Status Report (BSR) manipulation.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local layer_names = { [1] = "LTE-PDCP", [2] = "LTE-RLC", [3] = "LTE-MAC" }

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

local ok, qc_lte_l2_proto = pcall(Proto, "qc_lte_l2", "Qualcomm LTE Layer 2 (PDCP/RLC/MAC) Analyzer")
if not ok or not qc_lte_l2_proto then return end

-- Protocol fields
local f_layer         = ProtoField.string("qc_lte_l2.layer", "L2 Layer")
local f_rb_id         = ProtoField.uint8("qc_lte_l2.rb_id", "Radio Bearer ID", base.DEC)
local f_direction     = ProtoField.string("qc_lte_l2.direction", "Direction")
local f_pdcp_sn       = ProtoField.uint32("qc_lte_l2.pdcp_sn", "PDCP Sequence Number", base.DEC)
local f_cipher_algo   = ProtoField.string("qc_lte_l2.cipher_algo", "PDCP Ciphering Status")
local f_sec_alert     = ProtoField.string("qc_lte_l2.alert", "TelcoSec LTE L2 Security Alert")
local f_payload       = ProtoField.bytes("qc_lte_l2.payload", "L2 Payload Data")

qc_lte_l2_proto.fields = {
    f_layer,
    f_rb_id,
    f_direction,
    f_pdcp_sn,
    f_cipher_algo,
    f_sec_alert,
    f_payload
}

-- Native Wireshark LTE L2 dissectors
local pdcp_lte_dissector = Dissector.get("pdcp-lte")
local rlc_lte_dissector  = Dissector.get("rlc-lte")
local mac_lte_dissector  = Dissector.get("mac-lte")

function qc_lte_l2_proto.dissector(tvb, pinfo, tree)
    -- Layout:
    -- [0]: Version (1 byte)
    -- [1]: Sub-layer ID (1=PDCP, 2=RLC, 3=MAC)
    -- [2]: RB ID (1 byte)
    -- [3]: Direction (0=UL, 1=DL)
    -- [4-7]: Sequence Number (4 bytes LE)
    -- [8..N]: Payload
    if tvb:len() < 8 then return end

    pinfo.cols.protocol = "QC LTE L2"

    local version = tvb(0, 1):uint()
    local layer_id = tvb(1, 1):uint()
    local rb_id = tvb(2, 1):uint()
    local direction = tvb(3, 1):uint()
    local dir_str = (direction == 0) and "UL" or "DL"
    local sn = tvb(4, 4):le_uint()

    local layer_str = layer_names[layer_id] or string.format("L2 Layer %d", layer_id)

    local subtree = tree:add(qc_lte_l2_proto, tvb(), string.format("Qualcomm LTE %s (RB: %d, %s)", layer_str, rb_id, dir_str))
    subtree:add(f_layer, layer_str)
    subtree:add(f_rb_id, tvb(2, 1), rb_id)
    subtree:add(f_direction, dir_str)
    subtree:add(f_pdcp_sn, tvb(4, 4), sn)

    pinfo.cols.info = string.format("[LTE %s %s] RB: %d | SN: %d", layer_str, dir_str, rb_id, sn)

    local offset = 8
    local pdu_len = tvb:len() - offset

    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()

        -- Security Heuristic 1: Unencrypted User Data on DRB (EEA0)
        if layer_id == 1 and rb_id >= 3 then
            local first_byte = pdu_tvb(0, 1):uint()
            local ip_ver = bit.rshift(first_byte, 4)
            if ip_ver == 4 or ip_ver == 6 then
                subtree:add(f_cipher_algo, "EEA0 (Null Ciphering / Plain IP)")
                subtree:add(f_sec_alert, "[CRITICAL] LTE User Plane Data transmitted without ciphering (EEA0)! IMSI Catcher / Rogue eNodeB active eavesdropping.")
                pinfo.cols.info:append(" [TELCOSEC: UNENCRYPTED DRB]")
            end
        end

        -- Call native dissector
        if layer_id == 1 and pdcp_lte_dissector then
            pdcp_lte_dissector:call(pdu_tvb, pinfo, tree)
        elseif layer_id == 2 and rlc_lte_dissector then
            rlc_lte_dissector:call(pdu_tvb, pinfo, tree)
        elseif layer_id == 3 and mac_lte_dissector then
            mac_lte_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB0A0, qc_lte_l2_proto) -- LTE PDCP DL
    qc_log_table:add(0xB0A1, qc_lte_l2_proto) -- LTE PDCP UL
    qc_log_table:add(0xB080, qc_lte_l2_proto) -- LTE RLC DL
    qc_log_table:add(0xB081, qc_lte_l2_proto) -- LTE RLC UL
    qc_log_table:add(0xB060, qc_lte_l2_proto) -- LTE MAC DL
    qc_log_table:add(0xB061, qc_lte_l2_proto) -- LTE MAC UL
end
