-- TelcoSec.net - Samsung Shannon 5G NR (RRC & NAS) Dissector & Security Analyzer
-- Description: Dissects Shannon DM Group 0x50 (5G NR RRC) and Group 0x51 (5G 5GS NAS).
--              Analyzes 5G signaling on Samsung Exynos basebands for rogue gNBs,
--              NIA0/NEA0 null-ciphering, and plain SUPI exposure.

local ok, shannon_5g_proto = pcall(Proto, "shannon_5g", "Samsung Shannon 5G NR (RRC & NAS) Analyzer")
if not ok or not shannon_5g_proto then return end

-- Protocol fields
local f_type         = ProtoField.string("shannon_5g.type", "5G Signaling Type")
local f_pci          = ProtoField.uint16("shannon_5g.pci", "Physical Cell ID (PCI)", base.DEC)
local f_arfcn        = ProtoField.uint32("shannon_5g.arfcn", "NR-ARFCN", base.DEC)
local f_pdu_type     = ProtoField.string("shannon_5g.pdu_type", "PDU Type")
local f_sec_alert    = ProtoField.string("shannon_5g.alert", "TelcoSec Shannon 5G Alert")
local f_payload      = ProtoField.bytes("shannon_5g.payload", "5G Payload Data")

shannon_5g_proto.fields = {
    f_type,
    f_pci,
    f_arfcn,
    f_pdu_type,
    f_sec_alert,
    f_payload
}

-- Native Wireshark 5G dissectors
local nr_rrc_bcch_bch_dissector = Dissector.get("nr-rrc.bcch.bch")
local nr_rrc_bcch_dl_sch_dissector = Dissector.get("nr-rrc.bcch.dl.sch")
local nr_rrc_dl_dcch_dissector = Dissector.get("nr-rrc.dl.dcch")
local nr_rrc_ul_dcch_dissector = Dissector.get("nr-rrc.ul.dcch")
local nas_5gs_dissector = Dissector.get("nas-5gs")

function shannon_5g_proto.dissector(tvb, pinfo, tree)
    -- Shannon 5G DM payload layout:
    -- [0]: Signaling Type (0=NR-RRC, 1=5G-NAS)
    -- [1-2]: PCI (2 bytes LE)
    -- [3-6]: ARFCN (4 bytes LE)
    -- [7]: PDU Type ID (1 byte)
    -- [8-9]: PDU Length (2 bytes LE)
    -- [10..N]: 3GPP PDU
    if tvb:len() < 8 then return end

    pinfo.cols.protocol = "Shannon 5G NR"

    local sig_type = tvb(0, 1):uint()
    local pci = tvb(1, 2):le_uint()
    local arfcn = tvb(3, 4):le_uint()
    local pdu_type_id = tvb(7, 1):uint()

    local type_str = (sig_type == 0) and "5G NR RRC" or "5GS NAS"
    local subtree = tree:add(shannon_5g_proto, tvb(), string.format("Samsung Shannon %s (PCI: %d, ARFCN: %d)", type_str, pci, arfcn))
    subtree:add(f_type, type_str)
    subtree:add(f_pci, tvb(1, 2), pci)
    subtree:add(f_arfcn, tvb(3, 4), arfcn)

    pinfo.cols.info = string.format("[Shannon %s] PCI: %d, ARFCN: %d", type_str, pci, arfcn)

    local offset = 8
    if tvb:len() >= 10 then
        offset = 10
    end

    local pdu_len = tvb:len() - offset
    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()
        local hex_str = tostring(pdu_tvb:bytes():tohex())

        -- Security Heuristics
        -- 1. Plaintext SUPI / IMSI Harvesting in 5G NAS
        if sig_type == 1 and string.find(hex_str, "7e005b") then
            subtree:add(f_sec_alert, "[CRITICAL] Plaintext 5GS Identity Request received by Shannon baseband! Potential 5G IMSI Catcher.")
            pinfo.cols.info:append(" [TELCOSEC: SUPI HARVEST PROBE]")
        end

        -- 2. Null Ciphering (NEA0 / NIA0): detected by nr_radio_sec.lua from the
        -- UPER-decoded nr-rrc.cipheringAlgorithm / integrityProtAlgorithm
        -- fields populated by the native nr-rrc dissector invoked below.
        -- A "0000" substring scan over a bit-packed ASN.1 PDU matched at any
        -- nibble offset regardless of field position, so benign
        -- SecurityModeCommand frames raised [CRITICAL] null-security alerts.

        -- Call subdissector
        if sig_type == 0 and nr_rrc_dl_dcch_dissector then
            nr_rrc_dl_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif sig_type == 1 and nas_5gs_dissector then
            nas_5gs_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Shannon DM Group table
local dm_table = DissectorTable.get("shannon_dm.group")
if dm_table then
    dm_table:add(0x50, shannon_5g_proto) -- Shannon 5G NR RRC
    dm_table:add(0x51, shannon_5g_proto) -- Shannon 5G NAS
end
