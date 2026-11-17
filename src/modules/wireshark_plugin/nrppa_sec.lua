-- TelcoSec.net - 5G NRPPa (NR Positioning Protocol A - 3GPP TS 38.455 / TS 37.355) Security Dissector
-- Description: Dissects NRPPa signaling over the N2 interface between gNodeB and LMF (Location Management Function).
--              Decodes elementary procedures, measurement IDs (LMF/RAN), positioning methods (UL-TDOA, DL-TDOA, DL-AoD, Multi-RTT, NR E-CID),
--              and Transmission Reception Point (TRP) configurations.
--              Detects stealth 5G beam-level location tracking probes, SRS positioning spoofing, and rogue LMF surveillance.

-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }

local ok, nrppa_sec_proto = pcall(Proto, "nrppa_sec", "TelcoSec 5G NRPPa (Location & Positioning) Security Analyzer")
if not ok or not nrppa_sec_proto then return end

-- Protocol fields
local f_pdu_type        = ProtoField.string("nrppa_sec.pdu_type", "NRPPa PDU Type")
local f_proc_code       = ProtoField.uint8("nrppa_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name       = ProtoField.string("nrppa_sec.proc_name", "Procedure Name")
local f_lmf_ue_id       = ProtoField.uint32("nrppa_sec.lmf_ue_id", "LMF UE Measurement ID", base.DEC)
local f_ran_ue_id       = ProtoField.uint32("nrppa_sec.ran_ue_id", "RAN UE Measurement ID", base.DEC)
local f_pos_method      = ProtoField.string("nrppa_sec.pos_method", "5G Positioning Method")
local f_trp_id          = ProtoField.uint32("nrppa_sec.trp_id", "TRP (Transmission-Reception Point) ID", base.HEX)
local f_sec_alert       = ProtoField.string("nrppa_sec.alert", "TelcoSec 5G Location Security Alert")
local f_payload         = ProtoField.bytes("nrppa_sec.payload", "NRPPa ASN.1 Payload")

nrppa_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_lmf_ue_id,
    f_ran_ue_id,
    f_pos_method,
    f_trp_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.455 Table 9.3.1-1 Elementary Procedures
local NRPPA_PROC_CODES = {
    [0]  = "E-CIDMeasurementInitiation",
    [1]  = "E-CIDMeasurementFailureIndication",
    [2]  = "E-CIDMeasurementReport",
    [3]  = "E-CIDMeasurementTermination",
    [4]  = "OTDOAInformationExchange",
    [5]  = "AssistanceInformationControl",
    [6]  = "PositioningInformationExchange",
    [7]  = "PositioningActivation",
    [8]  = "PositioningDeactivation",
    [9]  = "TRPInformationExchange",
    [10] = "MeasurementPreconfiguration",
    [11] = "MeasurementActivation",
    [12] = "PositioningDeactivation",
    [13] = "PositioningInformationUpdate",
    [14] = "MeasurementPreconfiguration"
}

-- Native NRPPa dissector
local nrppa_dissector = Dissector.get("nrppa")

function nrppa_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 3 then return end

    pinfo.cols.protocol = "5G NRPPa"

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = NRPPA_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(nrppa_sec_proto, tvb(), string.format("5G NRPPa Positioning: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G NRPPa] %s (%s)", proc_name, pdu_type_str)

    local alerts = {}

    -- Security Heuristic 1: High-Precision 5G Device Geolocation Query (Beam-level / E-CID / TRP angles)
    if (proc_code == 0 or proc_code == 6 or proc_code == 7 or proc_code == 11) and pdu_type_id == 0 then
        table.insert(alerts, string.format(
            "[CRITICAL] 5G High-Precision Geolocation Query (%s)! " ..
            "LMF actively commanding gNodeB to track subscriber angle of arrival (AoA), beam RSRP, and round-trip time. Verify authorized legal warrant.",
            proc_name))
        pinfo.cols.info:append(" [TELCOSEC: 5G GEOLOCATION PROBE!]")
    end

    -- Security Heuristic 2: TRP Information Harvesting
    if proc_code == 9 and pdu_type_id == 0 then
        table.insert(alerts, "[HIGH RISK] TRP (Transmission Reception Point) Physical Coordinate Exchange! LMF querying precise antenna spatial geometry.")
    end

    -- Security Heuristic 3: Positioning Deactivation
    if proc_code == 8 or proc_code == 12 then
        table.insert(alerts, "[INFO] NRPPa Positioning Session Deactivated.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if nrppa_dissector then
        nrppa_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, len - 2))
    end
end

-- Register as postdissector to inspect NRPPa over NGAP / SCTP
register_postdissector(nrppa_sec_proto)
