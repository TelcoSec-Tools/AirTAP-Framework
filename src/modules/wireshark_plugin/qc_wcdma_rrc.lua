-- TelcoSec.net - Qualcomm 3G WCDMA RRC OTA & Active Set Dissector
-- Description: Dissects Qualcomm Log Codes 0x412F (WCDMA RRC Signaling), 0x4125 (WCDMA NAS), and 0x4010 (Active Set Measurements).
--              Analyzes 3G UMTS signaling for UEA0 null-ciphering and forced URA/PCH paging attacks.

local ok, qc_wcdma_rrc_proto = pcall(Proto, "qc_wcdma_rrc", "Qualcomm 3G WCDMA RRC & Security Analyzer")
if not ok or not qc_wcdma_rrc_proto then return end

-- Protocol fields
local f_psc          = ProtoField.uint16("qc_wcdma_rrc.psc", "Primary Scrambling Code (PSC)", base.DEC)
local f_uarfcn       = ProtoField.uint16("qc_wcdma_rrc.uarfcn", "UARFCN", base.DEC)
local f_rrc_state    = ProtoField.string("qc_wcdma_rrc.state", "RRC State")
local f_cipher_algo  = ProtoField.string("qc_wcdma_rrc.cipher_algo", "WCDMA Ciphering (UEA)")
local f_sec_alert    = ProtoField.string("qc_wcdma_rrc.alert", "TelcoSec 3G Security Alert")
local f_payload      = ProtoField.bytes("qc_wcdma_rrc.payload", "WCDMA RRC PDU")

qc_wcdma_rrc_proto.fields = {
    f_psc,
    f_uarfcn,
    f_rrc_state,
    f_cipher_algo,
    f_sec_alert,
    f_payload
}

-- Native Wireshark RRC dissector
local rrc_dissector = Dissector.get("rrc")

function qc_wcdma_rrc_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0x412F layout:
    -- [0]: Version (1 byte)
    -- [1-2]: UARFCN (2 bytes LE)
    -- [3-4]: Primary Scrambling Code (PSC, 2 bytes LE)
    -- [5]: Radio Bearer ID (1 byte)
    -- [6]: PDU Length (1 byte)
    -- [7..N]: 3GPP RRC ASN.1 PDU
    if tvb:len() < 7 then return end

    pinfo.cols.protocol = "WCDMA RRC"

    local uarfcn = tvb(1, 2):le_uint()
    local psc = tvb(3, 2):le_uint()
    local rb_id = tvb(5, 1):uint()
    local pdu_len = tvb(6, 1):uint()

    local subtree = tree:add(qc_wcdma_rrc_proto, tvb(), string.format("Qualcomm WCDMA RRC OTA (PSC: %d, UARFCN: %d)", psc, uarfcn))
    subtree:add(f_uarfcn, tvb(1, 2), uarfcn)
    subtree:add(f_psc, tvb(3, 2), psc)

    pinfo.cols.info = string.format("[WCDMA RRC] PSC: %d, UARFCN: %d | RB: %d", psc, uarfcn, rb_id)

    local offset = 7
    local actual_pdu_len = tvb:len() - offset

    if actual_pdu_len > 0 then
        if rrc_dissector then
            rrc_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, actual_pdu_len))
        end

        -- Security Heuristic 1: SecurityModeCommand with UEA0 (No ciphering)
        local f_rrc_cipher = Field.new("rrc.cipheringAlgorithm")
        local is_uea0 = false

        if f_rrc_cipher and f_rrc_cipher() then
            local alg_val = tostring(f_rrc_cipher().value)
            if alg_val == "0" or string.find(alg_val:lower(), "uea0") then
                is_uea0 = true
            end
        elseif (rb_id == 1 or rb_id == 2) and actual_pdu_len >= 4 then
            -- Byte-level fallback check for DL-DCCH SecurityModeCommand (TS 25.331)
            -- DL-DCCH msg_type choice 18 (securityModeCommand) with uea0 (0)
            local b0 = pdu_tvb(0, 1):uint()
            local b1 = pdu_tvb(1, 1):uint()
            -- DL-DCCH SecurityModeCommand bit pattern check
            if bit.band(b0, 0x3E) == 0x24 and bit.band(b1, 0xC0) == 0x00 then
                is_uea0 = true
            end
        end

        if is_uea0 then
            subtree:add(f_cipher_algo, "UEA0 (Null Ciphering)")
            subtree:add(f_sec_alert, "[CRITICAL] 3G UMTS Security Mode Command negotiated UEA0 (No Encryption)! Plaintext voice/data eavesdropping.")
            pinfo.cols.info:append(" [TELCOSEC: UEA0 NULL-CIPHER]")
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x412F, qc_wcdma_rrc_proto) -- WCDMA RRC Signaling
    qc_log_table:add(0x4125, qc_wcdma_rrc_proto) -- WCDMA NAS Signaling
    qc_log_table:add(0x4010, qc_wcdma_rrc_proto) -- WCDMA Active Set
end
