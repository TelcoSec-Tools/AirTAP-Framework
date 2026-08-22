-- TelcoSec.net - Qualcomm 5G NR ML1 (Physical Layer, Beamforming & RF) Dissector
-- Description: Dissects Qualcomm Log Codes 0xB97F (NR ML1 Beam Management), 0xB8D8 (PDSCH Status), 0xB8D9 (PUSCH Status).
--              Inspects SSB / CSI-RS beam search and power metrics. Detects 5G IMSI Catchers manipulating RF parameters
--              and performing beam hijacking.

local ok, qc_nr_ml1_proto = pcall(Proto, "qc_nr_ml1", "Qualcomm 5G NR ML1 & Beamforming Analyzer")
if not ok or not qc_nr_ml1_proto then return end

-- Protocol fields
local f_pci          = ProtoField.uint16("qc_nr_ml1.pci", "Physical Cell ID (PCI)", base.DEC)
local f_ssb_index    = ProtoField.uint8("qc_nr_ml1.ssb_index", "SSB Beam Index (0-63)", base.DEC)
local f_ssb_rsrp     = ProtoField.float("qc_nr_ml1.ssb_rsrp", "SSB RSRP (dBm)")
local f_ssb_rsrq     = ProtoField.float("qc_nr_ml1.ssb_rsrq", "SSB RSRQ (dB)")
local f_ssb_sinr     = ProtoField.float("qc_nr_ml1.ssb_sinr", "SSB SINR (dB)")
local f_beam_count   = ProtoField.uint8("qc_nr_ml1.beam_count", "Detected Beams Count", base.DEC)
local f_sec_alert    = ProtoField.string("qc_nr_ml1.alert", "TelcoSec 5G RF Security Alert")
local f_payload      = ProtoField.bytes("qc_nr_ml1.payload", "ML1 Raw Data")

qc_nr_ml1_proto.fields = {
    f_pci,
    f_ssb_index,
    f_ssb_rsrp,
    f_ssb_rsrq,
    f_ssb_sinr,
    f_beam_count,
    f_sec_alert,
    f_payload
}

function qc_nr_ml1_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB97F layout:
    -- [0]: Version (1 byte)
    -- [1-2]: Serving PCI (2 bytes LE)
    -- [3]: Num Beams (1 byte)
    -- [4..N]: Beam Records [SSB Index (1B), RSRP (2B signed), RSRQ (2B signed), SINR (2B signed)]
    if tvb:len() < 4 then return end

    pinfo.cols.protocol = "QC 5G ML1"

    local version = tvb(0, 1):uint()
    local pci = tvb(1, 2):le_uint()
    local beam_count = tvb(3, 1):uint()

    local subtree = tree:add(qc_nr_ml1_proto, tvb(), string.format("Qualcomm 5G NR ML1 Beamforming & RF (PCI: %d, Beams: %d)", pci, beam_count))
    subtree:add(f_pci, tvb(1, 2), pci)
    subtree:add(f_beam_count, tvb(3, 1), beam_count)

    local offset = 4
    local best_rsrp = -140.0
    local best_beam = 0

    for i = 1, beam_count do
        if offset + 7 > tvb:len() then break end

        local ssb_idx = tvb(offset, 1):uint()
        local raw_rsrp = tvb(offset + 1, 2):le_int()
        local raw_rsrq = tvb(offset + 3, 2):le_int()
        local raw_sinr = tvb(offset + 5, 2):le_int()

        local rsrp_val = raw_rsrp / 100.0 -- Typically in 0.01 dBm units
        local rsrq_val = raw_rsrq / 100.0
        local sinr_val = raw_sinr / 100.0

        if rsrp_val > best_rsrp then
            best_rsrp = rsrp_val
            best_beam = ssb_idx
        end

        local beam_tree = subtree:add(qc_nr_ml1_proto, tvb(offset, 7), string.format("Beam #%d (SSB Index: %d, RSRP: %.2f dBm)", i, ssb_idx, rsrp_val))
        beam_tree:add(f_ssb_index, tvb(offset, 1), ssb_idx)
        beam_tree:add(f_ssb_rsrp, tvb(offset + 1, 2), rsrp_val)
        beam_tree:add(f_ssb_rsrq, tvb(offset + 3, 2), rsrq_val)
        beam_tree:add(f_ssb_sinr, tvb(offset + 5, 2), sinr_val)

        offset = offset + 7
    end

    pinfo.cols.info = string.format("[5G NR ML1] PCI: %d | Best SSB: %d (RSRP: %.2f dBm)", pci, best_beam, best_rsrp)

    -- Security Heuristics:
    -- 1. Extreme unnatural RF power (RSRP > -45 dBm indicates tactical nearby IMSI Catcher / jammer transmitter)
    if best_rsrp > -45.0 then
        subtree:add(f_sec_alert, string.format("[CRITICAL] Abnormally high 5G RSRP (%.2f dBm)! Tactical rogue 5G gNodeB transmitter in immediate proximity (<5m).", best_rsrp))
        pinfo.cols.info:append(" [TELCOSEC: EXTREME RF POWER ALERT]")
    end

    -- 2. Beam hijacking anomaly: Single isolated high-power beam with invalid neighbor measurements
    if beam_count == 1 and best_rsrp > -60.0 then
        subtree:add(f_sec_alert, "[WARNING] Isolated single-beam high-gain signal detected without normal multi-beam SSB grid. Suspected rogue directional transmitter.")
    end

    if tvb:len() > offset then
        subtree:add(f_payload, tvb(offset, tvb:len() - offset))
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB97F, qc_nr_ml1_proto) -- NR ML1 Beam Management
    qc_log_table:add(0xB8D8, qc_nr_ml1_proto) -- NR ML1 PDSCH Status
    qc_log_table:add(0xB8D9, qc_nr_ml1_proto) -- NR ML1 PUSCH Status
end
