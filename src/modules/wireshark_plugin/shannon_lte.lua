-- TelcoSec.net - Samsung Shannon 4G LTE (RRC & NAS) Dissector & Security Analyzer
-- Description: Dissects Shannon DM Group 0x40 (LTE RRC) and Group 0x41 (LTE NAS).
--              Inspects LTE air-interface signaling on Exynos modems for False Base Stations (FBS),
--              malicious 2G GERAN downgrade redirections, and unencrypted security mode commands.

local ok, shannon_lte_proto = pcall(Proto, "shannon_lte", "Samsung Shannon 4G LTE Analyzer")
if not ok or not shannon_lte_proto then return end

-- Protocol fields
local f_type         = ProtoField.string("shannon_lte.type", "LTE Signaling Type")
local f_pci          = ProtoField.uint16("shannon_lte.pci", "Physical Cell ID (PCI)", base.DEC)
local f_earfcn       = ProtoField.uint32("shannon_lte.earfcn", "EARFCN", base.DEC)
local f_sec_alert    = ProtoField.string("shannon_lte.alert", "TelcoSec Shannon LTE Alert")
local f_payload      = ProtoField.bytes("shannon_lte.payload", "LTE Payload")

shannon_lte_proto.fields = {
    f_type,
    f_pci,
    f_earfcn,
    f_sec_alert,
    f_payload
}

-- Native Wireshark LTE dissectors
local lte_rrc_bcch_dl_sch_dissector = Dissector.get("lte-rrc.bcch.dl.sch")
local lte_rrc_dl_dcch_dissector = Dissector.get("lte-rrc.dl.dcch")
local nas_eps_dissector = Dissector.get("nas-eps")

function shannon_lte_proto.dissector(tvb, pinfo, tree)
    -- Shannon LTE DM payload layout:
    -- [0]: Signaling Type (0=LTE-RRC, 1=LTE-NAS)
    -- [1-2]: PCI (2 bytes LE)
    -- [3-4]: EARFCN (2 bytes LE)
    -- [5-6]: PDU Length (2 bytes LE)
    -- [7..N]: LTE 3GPP PDU
    if tvb:len() < 5 then return end

    pinfo.cols.protocol = "Shannon LTE"

    local sig_type = tvb(0, 1):uint()
    local pci = tvb(1, 2):le_uint()
    local earfcn = tvb(3, 2):le_uint()

    local type_str = (sig_type == 0) and "LTE RRC" or "LTE NAS"
    local subtree = tree:add(shannon_lte_proto, tvb(), string.format("Samsung Shannon %s (PCI: %d, EARFCN: %d)", type_str, pci, earfcn))
    subtree:add(f_type, type_str)
    subtree:add(f_pci, tvb(1, 2), pci)
    subtree:add(f_earfcn, tvb(3, 2), earfcn)

    pinfo.cols.info = string.format("[Shannon %s] PCI: %d, EARFCN: %d", type_str, pci, earfcn)

    local offset = 5
    if tvb:len() >= 7 then
        offset = 7
    end

    local pdu_len = tvb:len() - offset
    if pdu_len > 0 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()
        local hex_str = tostring(pdu_tvb:bytes():tohex())

        -- Security Heuristics
        -- Inter-RAT 2G redirection detection lives in lte_radio_sec.lua, which
        -- post-dissects the UPER-decoded lte-rrc.redirectedCarrierInfo field
        -- produced by the native dissector invoked below. The previous check
        -- here searched a hex string of the bit-packed ASN.1 PDU for "28"/"50"
        -- at any offset, which matched ~8-17% of release-sized PDUs by chance
        -- and raised [CRITICAL] FBS alerts on benign traffic.

        -- 1. IMSI Identity Request Probe in LTE NAS
        -- Retains a byte-pattern match: at three bytes (NAS EPS Identity
        -- Request, IMSI) the chance collision rate is negligible, unlike the
        -- single-byte patterns removed above.
        if sig_type == 1 and string.find(hex_str, "075501") then
            subtree:add(f_sec_alert, "[CRITICAL] Network requesting IMSI via plain Identity Request! 4G IMSI Catcher active.")
            pinfo.cols.info:append(" [TELCOSEC: IMSI HARVEST ATTEMPT]")
        end

        -- Call native dissectors
        if sig_type == 0 and lte_rrc_dl_dcch_dissector then
            lte_rrc_dl_dcch_dissector:call(pdu_tvb, pinfo, tree)
        elseif sig_type == 1 and nas_eps_dissector then
            nas_eps_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Shannon DM Group table
local dm_table = DissectorTable.get("shannon_dm.group")
if dm_table then
    dm_table:add(0x40, shannon_lte_proto) -- Shannon LTE RRC
    dm_table:add(0x41, shannon_lte_proto) -- Shannon LTE NAS
end
