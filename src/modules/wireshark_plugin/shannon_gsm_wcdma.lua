-- TelcoSec.net - Samsung Shannon 2G GSM & 3G WCDMA Dissector & Security Analyzer
-- Description: Dissects Shannon DM Group 0x20 (GSM 2G) and Group 0x30 (UMTS 3G).
--              Detects 2G IMSI Catcher attacks forcing A5/0 (no ciphering) or A5/1 (weak cipher)
--              and 3G UEA0 null-cipher configurations.

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

local ok, shannon_legacy_proto = pcall(Proto, "shannon_legacy", "Samsung Shannon 2G/3G Legacy Cellular Analyzer")
if not ok or not shannon_legacy_proto then return end

-- Protocol fields
local f_rat          = ProtoField.string("shannon_legacy.rat", "Radio Access Tech")
local f_arfcn        = ProtoField.uint16("shannon_legacy.arfcn", "ARFCN / UARFCN", base.DEC)
local f_cipher_algo  = ProtoField.string("shannon_legacy.cipher_algo", "Ciphering Status")
local f_sec_alert    = ProtoField.string("shannon_legacy.alert", "TelcoSec Shannon 2G/3G Alert")
local f_payload      = ProtoField.bytes("shannon_legacy.payload", "Signaling Payload")

shannon_legacy_proto.fields = {
    f_rat,
    f_arfcn,
    f_cipher_algo,
    f_sec_alert,
    f_payload
}

-- Native dissectors
local gsm_a_dtap_dissector = Dissector.get("gsm_a_dtap")
local rrc_dissector        = Dissector.get("rrc")

function shannon_legacy_proto.dissector(tvb, pinfo, tree)
    -- Shannon 2G/3G DM layout:
    -- [0]: RAT Type (0=GSM, 1=UMTS)
    -- [1-2]: ARFCN/UARFCN (2 bytes LE)
    -- [3..N]: 3GPP PDU
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "Shannon 2G/3G"

    local rat_id = tvb(0, 1):uint()
    local arfcn = tvb(1, 2):le_uint()
    local rat_str = (rat_id == 0) and "2G GSM" or "3G UMTS"

    local subtree = tree:add(shannon_legacy_proto, tvb(), string.format("Samsung Shannon %s (Channel: %d)", rat_str, arfcn))
    subtree:add(f_rat, rat_str)
    subtree:add(f_arfcn, tvb(1, 2), arfcn)

    pinfo.cols.info = string.format("[Shannon %s] ARFCN: %d", rat_str, arfcn)

    local offset = 3
    local pdu_len = tvb:len() - offset

    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()

        -- Security Heuristic 1: GSM Ciphering Mode Command with A5/0.
        --
        -- 3GPP TS 44.018 9.1.9 / 10.5.2.9: the message is PD 0x06 (Radio
        -- Resources) with message type 0x35, and the Cipher Mode Setting IE
        -- sits in octet 3. Bit 0 is SC (0 = no ciphering) and bits 3..1 are
        -- the algorithm. Read at that offset rather than matched as the
        -- substring "063500"/"063501" anywhere in the frame.
        if rat_id == 0 and pdu_len >= 3 then
            local pd = bit.band(pdu_tvb(0, 1):uint(), 0x0F)
            local msg_type = pdu_tvb(1, 1):uint()
            if pd == 0x06 and msg_type == 0x35 then
                local setting = pdu_tvb(2, 1):uint()
                local start_ciph = bit.band(setting, 0x01)
                local algo = bit.rshift(bit.band(setting, 0x0E), 1)

                if start_ciph == 0 or algo == 0 then
                    subtree:add(f_cipher_algo, "A5/0 (No Encryption)")
                    subtree:add(f_sec_alert, "[CRITICAL] Network commanded A5/0 (Plaintext) on Exynos modem! 2G IMSI Catcher active.")
                    pinfo.cols.info:append(" [TELCOSEC: A5/0 NULL CIPHER]")
                elseif algo == 1 then
                    subtree:add(f_cipher_algo, "A5/1 (Weak / Broken Cipher)")
                    subtree:add(f_sec_alert, "[WARNING] A5/1 negotiated. Vulnerable to real-time cracking.")
                else
                    subtree:add(f_cipher_algo, string.format("A5/%d", algo))
                end
            end
        end

        -- Security Heuristic 2: UMTS Security Mode Command with UEA0.
        --
        -- Handled by qc_wcdma_rrc.lua, which reads the UPER-decoded
        -- rrc.cipheringAlgorithm field from the native RRC dissector invoked
        -- below. The previous check here searched this PDU for the substring
        -- "0000" at any nibble offset in a bit-packed ASN.1 payload, so an
        -- ordinary Security Mode Command raised a [CRITICAL] null-cipher
        -- alert. Do not reintroduce a substring scan here.

        if rat_id == 0 and gsm_a_dtap_dissector then
            gsm_a_dtap_dissector:call(pdu_tvb, pinfo, tree)
        elseif rat_id == 1 and rrc_dissector then
            rrc_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Shannon DM Group table
local dm_table = DissectorTable.get("shannon_dm.group")
if dm_table then
    dm_table:add(0x20, shannon_legacy_proto) -- Shannon 2G GSM
    dm_table:add(0x30, shannon_legacy_proto) -- Shannon 3G UMTS
end
