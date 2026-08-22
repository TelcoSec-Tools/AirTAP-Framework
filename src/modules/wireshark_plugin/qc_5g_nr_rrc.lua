-- TelcoSec.net - Qualcomm 5G NR RRC OTA Dissector & Security Post-Dissector
-- Description: Dissects Qualcomm Log Code 0xB821 (NR RRC OTA Packet) and 0xB822 (NR RRC Config).
--              Analyzes 5G NR Radio Resource Control signaling for rogue gNodeBs, NIA0/NEA0 null-ciphering,
--              and malicious forced cell-redirection attacks.

local ok, qc_nr_rrc_proto = pcall(Proto, "qc_nr_rrc", "Qualcomm 5G NR RRC OTA & Security Analyzer")
if not ok or not qc_nr_rrc_proto then return end

-- Protocol fields
local f_pci            = ProtoField.uint16("qc_nr_rrc.pci", "Physical Cell ID (PCI)", base.DEC)
local f_arfcn          = ProtoField.uint32("qc_nr_rrc.arfcn", "NR-ARFCN", base.DEC)
local f_rb_id          = ProtoField.uint8("qc_nr_rrc.rb_id", "Radio Bearer ID", base.DEC)
local f_pdu_type       = ProtoField.string("qc_nr_rrc.pdu_type", "RRC PDU Type")
local f_pdu_len        = ProtoField.uint16("qc_nr_rrc.pdu_len", "RRC PDU Length", base.DEC)
local f_cipher_algo    = ProtoField.string("qc_nr_rrc.cipher_algo", "NR Ciphering Algorithm (NEA)")
local f_integrity_algo = ProtoField.string("qc_nr_rrc.integrity_algo", "NR Integrity Algorithm (NIA)")
local f_sec_alert      = ProtoField.string("qc_nr_rrc.security_alert", "TelcoSec 5G RAN Alert")
local f_rrc_pdu        = ProtoField.bytes("qc_nr_rrc.pdu", "NR RRC ASN.1 PDU")

qc_nr_rrc_proto.fields = {
    f_pci,
    f_arfcn,
    f_rb_id,
    f_pdu_type,
    f_pdu_len,
    f_cipher_algo,
    f_integrity_algo,
    f_sec_alert,
    f_rrc_pdu
}

-- Mapping 5G NR RRC PDU Types in Qualcomm Log 0xB821
local PDU_TYPES = {
    [0] = "BCCH-BCH (MIB)",
    [1] = "BCCH-DL-SCH (SIB1 / SIBs)",
    [2] = "DL-CCCH (RRCSetup / RRCReject)",
    [3] = "DL-DCCH (SecurityModeCommand / RRCReconfiguration / RRCRelease)",
    [4] = "UL-CCCH (RRCSetupRequest / RRCResumeRequest)",
    [5] = "UL-DCCH (SecurityModeComplete / RRCReconfigurationComplete)",
    [6] = "PCCH (Paging)"
}

-- Native Wireshark NR RRC Dissectors
local nr_rrc_bcch_bch_dissector = Dissector.get("nr-rrc.bcch.bch")
local nr_rrc_bcch_dl_sch_dissector = Dissector.get("nr-rrc.bcch.dl.sch")
local nr_rrc_dl_ccch_dissector = Dissector.get("nr-rrc.dl.ccch")
local nr_rrc_dl_dcch_dissector = Dissector.get("nr-rrc.dl.dcch")
local nr_rrc_ul_ccch_dissector = Dissector.get("nr-rrc.ul.ccch")
local nr_rrc_ul_dcch_dissector = Dissector.get("nr-rrc.ul.dcch")
local nr_rrc_pcch_dissector = Dissector.get("nr-rrc.pcch")

function qc_nr_rrc_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB821 Header Layout:
    -- [0]: Packet Version (1 byte)
    -- [1-2]: NR-ARFCN (4 bytes or 2-4 bytes depending on QC chipset version)
    -- [3-4]: Physical Cell ID (PCI, 2 bytes LE)
    -- [5]: Radio Bearer ID (1 byte)
    -- [6]: PDU Type (1 byte)
    -- [7-8]: PDU Length (2 bytes LE)
    -- [9..N]: Raw 3GPP NR-RRC ASN.1 PDU
    if tvb:len() < 9 then return end

    pinfo.cols.protocol = "5G NR RRC"

    local version = tvb(0, 1):uint()
    local pci = tvb(1, 2):le_uint()
    local arfcn = tvb(3, 4):le_uint()
    local rb_id = tvb(7, 1):uint()
    local pdu_type_id = tvb(8, 1):uint()
    local pdu_len = 0
    local header_len = 9

    if tvb:len() >= 11 then
        pdu_len = tvb(9, 2):le_uint()
        header_len = 11
    else
        pdu_len = tvb:len() - header_len
    end

    local pdu_name = PDU_TYPES[pdu_type_id] or string.format("Unknown PDU (%d)", pdu_type_id)

    local subtree = tree:add(qc_nr_rrc_proto, tvb(), string.format("Qualcomm 5G NR RRC OTA (PCI: %d, %s)", pci, pdu_name))
    subtree:add(f_pci, tvb(1, 2), pci)
    subtree:add(f_arfcn, tvb(3, 4), arfcn)
    subtree:add(f_rb_id, tvb(7, 1), rb_id)
    subtree:add(f_pdu_type, pdu_name)
    subtree:add(f_pdu_len, pdu_len)

    pinfo.cols.info = string.format("[5G NR-RRC] PCI: %d, ARFCN: %d | %s", pci, arfcn, pdu_name)

    local pdu_offset = header_len
    local actual_pdu_len = tvb:len() - pdu_offset

    if actual_pdu_len > 0 then
        local pdu_tvb = tvb(pdu_offset, actual_pdu_len):tvb()
        local raw_bytes_str = tostring(pdu_tvb:bytes():tohex())

        -- Security Analysis Heuristics
        -- 1. SecurityModeCommand with NIA0 / NEA0 (Null Integrity / Ciphering)
        if pdu_type_id == 3 and string.find(raw_bytes_str, "0000") then
            -- Heuristic check for unencrypted or null integrity setup
            subtree:add(f_sec_alert, "[CRITICAL] Potential Null-Ciphering / Null-Integrity (NIA0/NEA0) or unverified 5G Security Mode Command.")
            pinfo.cols.info:append(" [TELCOSEC: NIA0/NEA0 WARNING]")
        end

        -- 2. Forced Redirection Detection (RRCRelease redirecting to 4G/2G)
        if pdu_type_id == 3 and (string.find(raw_bytes_str, "40") or string.find(raw_bytes_str, "80")) and actual_pdu_len < 30 then
            subtree:add(f_sec_alert, "[WARNING] RRCRelease with potential Inter-RAT Cell Redirection. Check for 5G-to-4G/2G downgrade attack.")
        end

        -- Delegate to native Wireshark NR RRC dissectors if available
        if pdu_type_id == 0 and nr_rrc_bcch_bch_dissector then
            nr_rrc_bcch_bch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 1 and nr_rrc_bcch_dl_sch_dissector then
            nr_rrc_bcch_dl_sch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 2 and nr_rrc_dl_ccch_dissector then
            nr_rrc_dl_ccch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 3 and nr_rrc_dl_dcch_dissector then
            nr_rrc_dl_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 4 and nr_rrc_ul_ccch_dissector then
            nr_rrc_ul_ccch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 5 and nr_rrc_ul_dcch_dissector then
            nr_rrc_ul_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 6 and nr_rrc_pcch_dissector then
            nr_rrc_pcch_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_rrc_pdu, tvb(pdu_offset, actual_pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB821, qc_nr_rrc_proto) -- NR RRC OTA Packet
    qc_log_table:add(0xB822, qc_nr_rrc_proto) -- NR RRC Config
end

-- Also register as post-dissector to inspect native nr-rrc dissections
local ok_native, native_nr_rrc_proto = pcall(Proto, "telcosec_nr_rrc_post", "TelcoSec Native NR-RRC Security Inspector")
if ok_native and native_nr_rrc_proto then
    local f_rrc_sec_alert = ProtoField.string("telcosec_nr_rrc.alert", "TelcoSec 5G RRC Alert")
    native_nr_rrc_proto.fields = { f_rrc_sec_alert }
end

local f_nr_rrc_cipher = Field.new("nr-rrc.cipheringAlgorithm")
local f_nr_rrc_integ  = Field.new("nr-rrc.integrityProtAlgorithm")

function native_nr_rrc_proto.dissector(tvb, pinfo, tree)
    local cipher_field = f_nr_rrc_cipher()
    local integ_field  = f_nr_rrc_integ()

    if cipher_field or integ_field then
        local subtree = tree:add(native_nr_rrc_proto, "TelcoSec 5G NR-RRC Security Analysis")
        if cipher_field and cipher_field.value == 0 then
            subtree:add(f_rrc_sec_alert, "[CRITICAL] NEA0 (Null Ciphering) configured on NR-RRC bearer! User data/signaling unencrypted.")
        end
        if integ_field and integ_field.value == 0 then
            subtree:add(f_rrc_sec_alert, "[CRITICAL] NIA0 (Null Integrity) configured on NR-RRC bearer! Vulnerable to packet injection.")
        end
    end
end

register_postdissector(native_nr_rrc_proto)
