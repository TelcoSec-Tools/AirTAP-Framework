-- TelcoSec.net - Qualcomm LTE ML1 (Physical Layer, Serving & Neighbor Measurements) Dissector
-- Description: Dissects Qualcomm Log Codes 0xB193 (LTE ML1 Serving Cell Measurements) and 0xB195 (Neighbor Cell Measurements).
--              Identifies unnatural RF power surges (RSRP > -50 dBm) and anomalous cell-reselection thresholds
--              characteristic of 4G IMSI Catchers.

local ok, qc_lte_ml1_proto = pcall(Proto, "qc_lte_ml1", "Qualcomm LTE ML1 & RF Measurement Analyzer")
if not ok or not qc_lte_ml1_proto then return end

-- Protocol fields
local f_earfcn       = ProtoField.uint32("qc_lte_ml1.earfcn", "EARFCN", base.DEC)
local f_pci          = ProtoField.uint16("qc_lte_ml1.pci", "Physical Cell ID (PCI)", base.DEC)
local f_rsrp         = ProtoField.float("qc_lte_ml1.rsrp", "Serving RSRP (dBm)")
local f_rsrq         = ProtoField.float("qc_lte_ml1.rsrq", "Serving RSRQ (dB)")
local f_rssi         = ProtoField.float("qc_lte_ml1.rssi", "Serving RSSI (dBm)")
local f_sinr         = ProtoField.float("qc_lte_ml1.sinr", "Serving SINR (dB)")
local f_num_neigh    = ProtoField.uint8("qc_lte_ml1.num_neigh", "Neighbor Cells Count", base.DEC)
local f_sec_alert    = ProtoField.string("qc_lte_ml1.alert", "TelcoSec LTE RF Alert")
local f_payload      = ProtoField.bytes("qc_lte_ml1.payload", "ML1 Raw Data")

qc_lte_ml1_proto.fields = {
    f_earfcn,
    f_pci,
    f_rsrp,
    f_rsrq,
    f_rssi,
    f_sinr,
    f_num_neigh,
    f_sec_alert,
    f_payload
}

function qc_lte_ml1_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB193 / 0xB195 layout:
    -- [0]: Version (1 byte)
    -- [1-2]: EARFCN (2 bytes LE)
    -- [3-4]: Serving PCI (2 bytes LE)
    -- [5-6]: RSRP (2 bytes signed LE, 0.01 dBm)
    -- [7-8]: RSRQ (2 bytes signed LE, 0.01 dB)
    -- [9-10]: RSSI (2 bytes signed LE, 0.01 dBm)
    -- [11-12]: SINR (2 bytes signed LE, 0.01 dB)
    -- [13]: Num Neighbors (1 byte)
    if tvb:len() < 13 then return end

    pinfo.cols.protocol = "QC LTE ML1"

    local version = tvb(0, 1):uint()
    local earfcn = tvb(1, 2):le_uint()
    local pci = tvb(3, 2):le_uint()
    local raw_rsrp = tvb(5, 2):le_int()
    local raw_rsrq = tvb(7, 2):le_int()
    local raw_rssi = tvb(9, 2):le_int()
    local raw_sinr = tvb(11, 2):le_int()

    local rsrp_val = raw_rsrp / 100.0
    local rsrq_val = raw_rsrq / 100.0
    local rssi_val = raw_rssi / 100.0
    local sinr_val = raw_sinr / 100.0

    local subtree = tree:add(qc_lte_ml1_proto, tvb(), string.format("Qualcomm LTE ML1 Serving Cell (PCI: %d, RSRP: %.2f dBm)", pci, rsrp_val))
    subtree:add(f_earfcn, tvb(1, 2), earfcn)
    subtree:add(f_pci, tvb(3, 2), pci)
    subtree:add(f_rsrp, tvb(5, 2), rsrp_val)
    subtree:add(f_rsrq, tvb(7, 2), rsrq_val)
    subtree:add(f_rssi, tvb(9, 2), rssi_val)
    subtree:add(f_sinr, tvb(11, 2), sinr_val)

    pinfo.cols.info = string.format("[LTE ML1] PCI: %d, EARFCN: %d | RSRP: %.2f dBm, SINR: %.2f dB", pci, earfcn, rsrp_val, sinr_val)

    -- Security Heuristics:
    -- 1. Unnatural Extreme RSRP (> -50 dBm) indicative of portable IMSI Catcher in close vicinity
    if rsrp_val > -50.0 then
        subtree:add(f_sec_alert, string.format("[CRITICAL] Unusually high LTE RSRP (%.2f dBm)! False Base Station (FBS) / IMSI Catcher transmitter nearby.", rsrp_val))
        pinfo.cols.info:append(" [TELCOSEC: ROGUE BASE STATION RF SURGE!]")
    end

    -- 2. Suspicious RF Isolation: High RSRP but 0 neighboring cells reported in dense urban EARFCN
    if tvb:len() >= 14 then
        local num_neigh = tvb(13, 1):uint()
        subtree:add(f_num_neigh, tvb(13, 1), num_neigh)
        if num_neigh == 0 and rsrp_val > -65.0 then
            subtree:add(f_sec_alert, "[WARNING] Zero neighbor cells reported despite strong serving signal. Possible RF jamming of commercial carriers.")
        end
    end

    if tvb:len() > 14 then
        subtree:add(f_payload, tvb(14, tvb:len() - 14))
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB193, qc_lte_ml1_proto) -- LTE ML1 Serving Cell Measurements
    qc_log_table:add(0xB195, qc_lte_ml1_proto) -- LTE ML1 Neighbor Cell Measurements
    qc_log_table:add(0xB192, qc_lte_ml1_proto) -- LTE ML1 PUSCH/PDSCH Stats
end
