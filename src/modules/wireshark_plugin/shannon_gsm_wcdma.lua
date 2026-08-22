-- TelcoSec.net - Samsung Shannon 2G GSM & 3G WCDMA Dissector & Security Analyzer
-- Description: Dissects Shannon DM Group 0x20 (GSM 2G) and Group 0x30 (UMTS 3G).
--              Detects 2G IMSI Catcher attacks forcing A5/0 (no ciphering) or A5/1 (weak cipher)
--              and 3G UEA0 null-cipher configurations.

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
        local hex_str = tostring(pdu_tvb:bytes():tohex())

        -- Security Heuristic 1: GSM Ciphering Mode Command A5/0 (No Encryption)
        if rat_id == 0 and string.find(hex_str, "0635") then
            if string.find(hex_str, "063500") or string.find(hex_str, "063501") then
                subtree:add(f_cipher_algo, "A5/0 (No Encryption)")
                subtree:add(f_sec_alert, "[CRITICAL] Network forced A5/0 (Plaintext) on Exynos modem! 2G IMSI Catcher active.")
                pinfo.cols.info:append(" [TELCOSEC: A5/0 NULL CIPHER]")
            end
        end

        -- Security Heuristic 2: UMTS Security Mode Command with UEA0
        if rat_id == 1 and string.find(hex_str, "0000") and pdu_len < 25 then
            subtree:add(f_cipher_algo, "UEA0 (Null Encryption)")
            subtree:add(f_sec_alert, "[CRITICAL] UMTS Bearer negotiated UEA0 (No Ciphering)!")
        end

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
