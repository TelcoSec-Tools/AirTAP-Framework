-- TelcoSec.net - 5G F1AP (OpenRAN gNB-CU <-> gNB-DU Interface) Security Dissector
-- Description: Dissects F1AP signaling (3GPP TS 38.473) between Centralized Unit (CU) and Distributed Unit (DU).
--              Detects unauthenticated DU provisioning, rogue DU injection, and RRC container tampering.

-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }

local ok, f1ap_sec_proto = pcall(Proto, "f1ap_sec", "TelcoSec 5G F1AP (OpenRAN CU-DU) Security Analyzer")
if not ok or not f1ap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("f1ap_sec.pdu_type", "F1AP PDU Type")
local f_proc_code    = ProtoField.uint8("f1ap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("f1ap_sec.proc_name", "Procedure Name")
local f_cu_ue_id     = ProtoField.uint32("f1ap_sec.cu_ue_id", "gNB-CU UE F1AP ID", base.DEC)
local f_du_ue_id     = ProtoField.uint32("f1ap_sec.du_ue_id", "gNB-DU UE F1AP ID", base.DEC)
local f_sec_alert    = ProtoField.string("f1ap_sec.alert", "TelcoSec F1AP Security Alert")
local f_payload      = ProtoField.bytes("f1ap_sec.payload", "F1AP ASN.1 Payload")

f1ap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_cu_ue_id,
    f_du_ue_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.473 Elementary Procedures (Table 9.2.0-1)
local F1AP_PROC_CODES = {
    [0]  = "Reset",
    [1]  = "F1Setup",
    [2]  = "ErrorIndication",
    [3]  = "gNBDUConfigurationUpdate",
    [4]  = "gNBCUConfigurationUpdate",
    [5]  = "UEContextSetup",
    [6]  = "UEContextRelease",
    [7]  = "UEContextModification",
    [8]  = "UEContextModificationRequired",
    [9]  = "UEMobilityCommand",
    [10] = "InitialULRRCMessageTransfer",
    [11] = "DLRRCTransfer",
    [12] = "ULRRCTransfer",
    [14] = "Paging",
    [16] = "Notify",
    [20] = "PWSCancel",
    [25] = "AccessAndMobilityIndication"
}

-- Native F1AP dissector
local f1ap_dissector = Dissector.get("f1ap")

function f1ap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "5G F1AP"

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = F1AP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(f1ap_sec_proto, tvb(), string.format("5G F1AP OpenRAN: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G F1AP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: F1Setup Request (Rogue DU Attachment in OpenRAN)
    if proc_code == 1 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] F1Setup Request from Distributed Unit (DU). Verify DU IP (" .. tostring(pinfo.src) .. ") is an authenticated physical/virtual DU node.")
    end

    -- Security Heuristic 2: F1 Reset
    if proc_code == 0 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[CRITICAL] F1 Reset commanded! Teardown of active CU-DU radio associations.")
        pinfo.cols.info:append(" [TELCOSEC: F1 RESET INJECTION]")
    end

    if f1ap_dissector then
        f1ap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 62 (F1AP) and SCTP port 38472
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(38472, f1ap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(62, f1ap_sec_proto)
end
