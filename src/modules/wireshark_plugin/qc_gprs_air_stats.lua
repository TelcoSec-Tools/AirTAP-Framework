-- TelcoSec.net - Qualcomm GPRS Air Quality & RF Jamming Statistics Dissector
-- Description: Dissects Qualcomm Log Code 0x5201 (GPRS Air Interface & BLER Statistics).
--              Tracks Block Error Rates (BLER), C/I ratio, and detects 2G packet data RF jamming.

local ok, qc_gprs_stats_proto = pcall(Proto, "qc_gprs_air_stats", "Qualcomm GPRS Air Quality & BLER Analyzer")
if not ok or not qc_gprs_stats_proto then return end

-- Protocol fields
local f_bler         = ProtoField.float("qc_gprs_stats.bler", "Block Error Rate (BLER %)")
local f_ci_ratio     = ProtoField.float("qc_gprs_stats.ci_ratio", "Carrier-to-Interference (C/I dB)")
local f_rx_level     = ProtoField.int8("qc_gprs_stats.rx_level", "Rx Level (dBm)", base.DEC)
local f_rx_qual      = ProtoField.uint8("qc_gprs_stats.rx_qual", "Rx Quality (0-7)", base.DEC)
local f_sec_alert    = ProtoField.string("qc_gprs_stats.alert", "TelcoSec GPRS RF Alert")
local f_payload      = ProtoField.bytes("qc_gprs_stats.payload", "Statistics Raw Data")

qc_gprs_stats_proto.fields = {
    f_bler,
    f_ci_ratio,
    f_rx_level,
    f_rx_qual,
    f_sec_alert,
    f_payload
}

function qc_gprs_stats_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0x5201 layout:
    -- [0]: Version (1 byte)
    -- [1-2]: BLER (2 bytes LE, 0.01%)
    -- [3-4]: C/I Ratio (2 bytes signed LE, 0.01 dB)
    -- [5]: Rx Level (1 byte signed dBm)
    -- [6]: Rx Quality (1 byte)
    if tvb:len() < 7 then return end

    pinfo.cols.protocol = "QC GPRS Stats"

    local raw_bler = tvb(1, 2):le_uint()
    local raw_ci = tvb(3, 2):le_int()
    local rx_level = tvb(5, 1):int()
    local rx_qual = tvb(6, 1):uint()

    local bler_pct = raw_bler / 100.0
    local ci_db = raw_ci / 100.0

    local subtree = tree:add(qc_gprs_stats_proto, tvb(), string.format("Qualcomm GPRS Air Quality (BLER: %.1f%%, C/I: %.1f dB)", bler_pct, ci_db))
    subtree:add(f_bler, tvb(1, 2), bler_pct)
    subtree:add(f_ci_ratio, tvb(3, 2), ci_db)
    subtree:add(f_rx_level, tvb(5, 1), rx_level)
    subtree:add(f_rx_qual, tvb(6, 1), rx_qual)

    pinfo.cols.info = string.format("[QC GPRS Stats] BLER: %.1f%%, C/I: %.1f dB, RxLev: %d dBm", bler_pct, ci_db, rx_level)

    -- Security Heuristic 1: High BLER (>50%) with good RxLevel indicates active selective GPRS data jamming
    if bler_pct > 50.0 and rx_level > -85 then
        subtree:add(f_sec_alert, string.format("[CRITICAL] Severe GPRS Block Error Rate (%.1f%%) despite strong RF signal (%d dBm)! Potential targeted 2G data jamming.", bler_pct, rx_level))
        pinfo.cols.info:append(" [TELCOSEC: 2G DATA JAMMING ALERT]")
    end

    if tvb:len() > 7 then
        subtree:add(f_payload, tvb(7, tvb:len() - 7))
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x5201, qc_gprs_stats_proto) -- GPRS Air Quality & BLER Stats
end
