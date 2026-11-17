-- TelcoSec.net - Qualcomm LTE RRC OTA Dissector & Security Post-Dissector
-- Description: Dissects Qualcomm Log Code 0xB0C0 (LTE RRC OTA Packet), 0xB0C1 (MIB), and 0xB0C2 (ServCell Info).
--              Inspects 4G LTE RRC signaling for False Base Stations (FBS / IMSI Catchers),
--              malicious 2G downgrade redirections, and SIB cell-reselection tampering.

local ok, qc_lte_rrc_proto = pcall(Proto, "qc_lte_rrc", "Qualcomm LTE RRC OTA & Security Analyzer")
if not ok or not qc_lte_rrc_proto then return end

-- Protocol fields
local f_earfcn       = ProtoField.uint32("qc_lte_rrc.earfcn", "EARFCN", base.DEC)
local f_pci          = ProtoField.uint16("qc_lte_rrc.pci", "Physical Cell ID (PCI)", base.DEC)
local f_pdu_type     = ProtoField.string("qc_lte_rrc.pdu_type", "RRC PDU Type")
local f_pdu_len      = ProtoField.uint16("qc_lte_rrc.pdu_len", "PDU Length", base.DEC)
-- Retained and registered although this dissector no longer populates it:
-- its security findings now come from the lte_radio_sec.lua post-dissector.
-- Keeping the field registered preserves saved Wireshark display filters and
-- custom columns that reference qc_lte_rrc.alert.
local f_sec_alert    = ProtoField.string("qc_lte_rrc.alert", "TelcoSec LTE RAN Alert")
local f_payload      = ProtoField.bytes("qc_lte_rrc.pdu", "LTE RRC ASN.1 PDU")

qc_lte_rrc_proto.fields = {
    f_earfcn,
    f_pci,
    f_pdu_type,
    f_pdu_len,
    f_sec_alert,
    f_payload
}

-- LTE RRC PDU Types in Qualcomm Log 0xB0C0
local LTE_PDU_TYPES = {
    [0]  = "BCCH-BCH (MIB)",
    [1]  = "BCCH-DL-SCH (SIB1 / SIBs)",
    [2]  = "MCCH",
    [3]  = "PCCH (Paging)",
    [4]  = "DL-CCCH (RRCConnectionSetup / Reject)",
    [5]  = "DL-DCCH (SecurityModeCommand / RRCConnectionReconfiguration / RRCConnectionRelease)",
    [6]  = "UL-CCCH (RRCConnectionRequest / ResumeRequest)",
    [7]  = "UL-DCCH (SecurityModeComplete / RRCConnectionReconfigurationComplete)"
}

-- Native Wireshark LTE RRC Dissectors
local lte_rrc_bcch_bch_dissector = Dissector.get("lte-rrc.bcch.bch")
local lte_rrc_bcch_dl_sch_dissector = Dissector.get("lte-rrc.bcch.dl.sch")
local lte_rrc_dl_ccch_dissector = Dissector.get("lte-rrc.dl.ccch")
local lte_rrc_dl_dcch_dissector = Dissector.get("lte-rrc.dl.dcch")
local lte_rrc_ul_ccch_dissector = Dissector.get("lte-rrc.ul.ccch")
local lte_rrc_ul_dcch_dissector = Dissector.get("lte-rrc.ul.dcch")
local lte_rrc_pcch_dissector = Dissector.get("lte-rrc.pcch")

function qc_lte_rrc_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB0C0 layout:
    -- [0]: Packet Version (1 byte)
    -- [1-2]: EARFCN (2 or 4 bytes depending on chipset)
    -- [3-4]: Physical Cell ID (PCI, 2 bytes LE)
    -- [5]: Radio Bearer ID (1 byte)
    -- [6]: PDU Type (1 byte)
    -- [7-8]: PDU Length (2 bytes LE)
    -- [9..N]: 3GPP LTE-RRC ASN.1 PDU
    if tvb:len() < 8 then return end

    pinfo.cols.protocol = "LTE RRC"

    local earfcn = tvb(1, 2):le_uint()
    local pci = tvb(3, 2):le_uint()
    local pdu_type_id = tvb(5, 1):uint()
    local pdu_name = LTE_PDU_TYPES[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)

    local subtree = tree:add(qc_lte_rrc_proto, tvb(), string.format("Qualcomm LTE RRC OTA (PCI: %d, %s)", pci, pdu_name))
    subtree:add(f_earfcn, tvb(1, 2), earfcn)
    subtree:add(f_pci, tvb(3, 2), pci)
    subtree:add(f_pdu_type, pdu_name)

    pinfo.cols.info = string.format("[LTE RRC] PCI: %d, EARFCN: %d | %s", pci, earfcn, pdu_name)

    local offset = 7
    if tvb:len() >= 9 then
        local pdu_len = tvb(6, 2):le_uint()
        subtree:add(f_pdu_len, pdu_len)
        offset = 8
    end

    local pdu_len = tvb:len() - offset
    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()

        -- Security heuristics for inter-RAT redirection and EEA0/EIA0 null
        -- security deliberately live in lte_radio_sec.lua, which runs as a
        -- post-dissector over the UPER-decoded lte-rrc.* fields populated by
        -- the native dissector called below (redirectedCarrierInfo,
        -- cipheringAlgorithm_r8, integrityProtAlgorithm_r8).
        --
        -- Earlier revisions scanned a hex string of this PDU for "28"/"50"
        -- (redirection) and "0000" (null cipher). That is unsound: the search
        -- is unanchored, so it matched across byte boundaries at any offset in
        -- a bit-packed ASN.1 UPER payload with no regard for field position.
        -- A single-byte pattern hits ~8-17% of RRCConnectionRelease-sized PDUs
        -- by chance, so benign releases raised [CRITICAL] downgrade alerts.
        -- Field-based detection is exact; do not reintroduce substring scans.

        -- Delegate to native Wireshark dissectors
        if pdu_type_id == 0 and lte_rrc_bcch_bch_dissector then
            lte_rrc_bcch_bch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 1 and lte_rrc_bcch_dl_sch_dissector then
            lte_rrc_bcch_dl_sch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 4 and lte_rrc_dl_ccch_dissector then
            lte_rrc_dl_ccch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 5 and lte_rrc_dl_dcch_dissector then
            lte_rrc_dl_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 6 and lte_rrc_ul_ccch_dissector then
            lte_rrc_ul_ccch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 7 and lte_rrc_ul_dcch_dissector then
            lte_rrc_ul_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif pdu_type_id == 3 and lte_rrc_pcch_dissector then
            lte_rrc_pcch_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB0C0, qc_lte_rrc_proto) -- LTE RRC OTA Packet
    qc_log_table:add(0xB0C1, qc_lte_rrc_proto) -- LTE RRC MIB Packet
    qc_log_table:add(0xB0C2, qc_lte_rrc_proto) -- LTE RRC ServCell Info
end
