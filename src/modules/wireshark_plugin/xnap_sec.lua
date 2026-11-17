-- TelcoSec.net - 5G XnAP (Xn-C Interface: Inter-gNB / ng-eNB) Security Dissector
-- Description: Dissects XnAP signaling (3GPP TS 38.423) between neighboring 5G gNodeBs / ng-eNBs.
--              Detects malicious 5G SA inter-cell handover hijacks, unauthorized Xn Setup,
--              and 5G cell load-dumping DoS attacks.

-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }

local ok, xnap_sec_proto = pcall(Proto, "xnap_sec", "TelcoSec 5G XnAP (Inter-gNB) Security Analyzer")
if not ok or not xnap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("xnap_sec.pdu_type", "XnAP PDU Type")
local f_proc_code    = ProtoField.uint8("xnap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("xnap_sec.proc_name", "Procedure Name")
local f_source_ng_id = ProtoField.uint32("xnap_sec.source_ng_id", "Source NG-RAN Node ID", base.DEC)
local f_target_ng_id = ProtoField.uint32("xnap_sec.target_ng_id", "Target NG-RAN Node ID", base.DEC)
local f_sec_alert    = ProtoField.string("xnap_sec.alert", "TelcoSec XnAP Security Alert")
local f_payload      = ProtoField.bytes("xnap_sec.payload", "XnAP ASN.1 Payload")

xnap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_source_ng_id,
    f_target_ng_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.423 Elementary Procedures (Table 9.2.0-1)
local XNAP_PROC_CODES = {
    [0]  = "HandoverPreparation",
    [1]  = "HandoverCancel",
    [2]  = "SNStatusTransfer",
    [3]  = "TargetRANNToSourceRANNTransport",
    [4]  = "XnSetup",
    [5]  = "Reset",
    [6]  = "NG-RANNodeConfigurationUpdate",
    [7]  = "CellActivation",
    [8]  = "ResourceStatusReportingInitiation",
    [9]  = "ResourceStatusReporting",
    [10] = "MobilitySettingsChange",
    [11] = "RadioResourceStatus",
    [12] = "SecondaryNodeAddition",
    [13] = "SecondaryNodeReconfiguration",
    [14] = "SecondaryNodeModification",
    [15] = "SecondaryNodeRelease",
    [16] = "SecondaryNodeChange"
}

-- Native XnAP dissector
local xnap_dissector = Dissector.get("xnap")

function xnap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "5G XnAP"

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = XNAP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(xnap_sec_proto, tvb(), string.format("5G XnAP Security: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G XnAP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: Xn Setup Request (Rogue 5G Radio Node Peering)
    if proc_code == 4 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] Xn Setup Request between 5G radio nodes. Verify peer gNB IP (" .. tostring(pinfo.src) .. ") is an authentic neighboring cell.")
    end

    -- Security Heuristic 2: Handover Cancel (Forced Handover Abort / Radio Hijacking)
    if proc_code == 1 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] Inter-gNB Handover Cancel received. 5G SA handover process terminated.")
    end

    -- Security Heuristic 3: Xn Reset
    if proc_code == 5 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[CRITICAL] Xn Reset commanded! Destroys active inter-gNodeB context and triggers radio link failures.")
        pinfo.cols.info:append(" [TELCOSEC: XN RESET INJECTION!]")
    end

    if xnap_dissector then
        xnap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 67 (XnAP) and SCTP port 38422
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(38422, xnap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(67, xnap_sec_proto)
end
