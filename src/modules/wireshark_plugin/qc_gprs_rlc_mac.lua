-- TelcoSec.net - Qualcomm GPRS/EGPRS RLC/MAC OTA Dissector
-- Description: Dissects Qualcomm Log Code 0x5226 (EGPRS RLC/MAC DL PDU) and 0x5230 (EGPRS RLC/MAC UL PDU).
--              Analyzes raw GPRS/EDGE data blocks directly from modem baseband buffers for OTA fuzzing and TBF inspection.

local ok, qc_gprs_proto = pcall(Proto, "qc_gprs_rlc_mac", "Qualcomm GPRS/EGPRS RLC/MAC OTA Analyzer")
if not ok or not qc_gprs_proto then return end

-- Protocol fields
local f_direction    = ProtoField.string("qc_gprs.direction", "Direction")
local f_mcs          = ProtoField.string("qc_gprs.mcs", "Modulation & Coding Scheme (MCS)")
local f_tfi          = ProtoField.uint8("qc_gprs.tfi", "TFI", base.DEC)
local f_bsn          = ProtoField.uint16("qc_gprs.bsn", "BSN", base.DEC)
local f_sec_alert    = ProtoField.string("qc_gprs.alert", "TelcoSec GPRS Baseband Alert")
local f_payload      = ProtoField.bytes("qc_gprs.payload", "GPRS Block Data")

qc_gprs_proto.fields = {
    f_direction,
    f_mcs,
    f_tfi,
    f_bsn,
    f_sec_alert,
    f_payload
}

-- Mapping EGPRS MCS Schemes
local MCS_SCHEMES = {
    [1] = "MCS-1 (GMSK)", [2] = "MCS-2 (GMSK)", [3] = "MCS-3 (GMSK)", [4] = "MCS-4 (GMSK)",
    [5] = "MCS-5 (8-PSK)", [6] = "MCS-6 (8-PSK)", [7] = "MCS-7 (8-PSK)", [8] = "MCS-8 (8-PSK)", [9] = "MCS-9 (8-PSK)"
}

function qc_gprs_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0x5226 / 0x5230 Header:
    -- [0]: Version (1 byte)
    -- [1]: Direction (0=UL, 1=DL)
    -- [2]: MCS Scheme (1 byte)
    -- [3]: TFI (1 byte)
    -- [4-5]: BSN (2 bytes LE)
    -- [6..N]: Raw Air Block
    if tvb:len() < 6 then return end

    pinfo.cols.protocol = "QC GPRS RLC"

    local direction = tvb(1, 1):uint()
    local dir_str = (direction == 0) and "UL (UE -> BTS)" or "DL (BTS -> UE)"
    local mcs_id = tvb(2, 1):uint()
    local mcs_str = MCS_SCHEMES[mcs_id] or string.format("MCS/CS %d", mcs_id)
    local tfi = tvb(3, 1):uint()
    local bsn = tvb(4, 2):le_uint()

    local subtree = tree:add(qc_gprs_proto, tvb(), string.format("Qualcomm GPRS/EDGE OTA (%s, %s)", dir_str, mcs_str))
    subtree:add(f_direction, dir_str)
    subtree:add(f_mcs, mcs_str)
    subtree:add(f_tfi, tvb(3, 1), tfi)
    subtree:add(f_bsn, tvb(4, 2), bsn)

    pinfo.cols.info = string.format("[QC GPRS %s] %s | TFI: %d, BSN: %d", dir_str, mcs_str, tfi, bsn)

    local offset = 6
    local payload_len = tvb:len() - offset
    if payload_len > 0 then
        subtree:add(f_payload, tvb(offset, payload_len))
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x5226, qc_gprs_proto) -- EGPRS RLC/MAC DL
    qc_log_table:add(0x5230, qc_gprs_proto) -- EGPRS RLC/MAC UL
end
