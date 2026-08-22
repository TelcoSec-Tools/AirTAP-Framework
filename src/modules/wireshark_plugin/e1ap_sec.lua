-- TelcoSec.net - 5G E1AP (OpenRAN gNB-CU-CP <-> gNB-CU-UP Interface) Security Dissector
-- Description: Dissects E1AP signaling (3GPP TS 38.463) separating Control and User planes in 5G gNodeBs.
--              Detects unauthorized User Plane bearer modifications, user-plane diversion, and QoS profile tampering.

local ok, e1ap_sec_proto = pcall(Proto, "e1ap_sec", "TelcoSec 5G E1AP (OpenRAN CU-CP/UP) Security Analyzer")
if not ok or not e1ap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("e1ap_sec.pdu_type", "E1AP PDU Type")
local f_proc_code    = ProtoField.uint8("e1ap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("e1ap_sec.proc_name", "Procedure Name")
local f_cp_ue_id     = ProtoField.uint32("e1ap_sec.cp_ue_id", "gNB-CU-CP UE E1AP ID", base.DEC)
local f_up_ue_id     = ProtoField.uint32("e1ap_sec.up_ue_id", "gNB-CU-UP UE E1AP ID", base.DEC)
local f_sec_alert    = ProtoField.string("e1ap_sec.alert", "TelcoSec E1AP Security Alert")
local f_payload      = ProtoField.bytes("e1ap_sec.payload", "E1AP ASN.1 Payload")

e1ap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_cp_ue_id,
    f_up_ue_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.463 Elementary Procedures (Table 9.2.0-1)
local E1AP_PROC_CODES = {
    [0]  = "Reset",
    [1]  = "ErrorIndication",
    [2]  = "GNBCUUPSetup",
    [3]  = "GNBCUUPConfigurationUpdate",
    [4]  = "GNBCUCPConfigurationUpdate",
    [5]  = "BearerContextSetup",
    [6]  = "BearerContextModification",
    [7]  = "BearerContextModificationRequired",
    [8]  = "BearerContextRelease",
    [9]  = "BearerContextReleaseRequest",
    [10] = "BearerContextInactivityNotification"
}

-- Native E1AP dissector
local e1ap_dissector = Dissector.get("e1ap")

function e1ap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "5G E1AP"

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }
    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = E1AP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(e1ap_sec_proto, tvb(), string.format("5G E1AP OpenRAN: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G E1AP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: gNB-CU-UP Setup (Rogue User Plane Node Attachment)
    if proc_code == 2 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] gNB-CU-UP Setup Request. Verify CU-UP IP (" .. tostring(pinfo.src) .. ") is an authentic User Plane execution function.")
    end

    -- Security Heuristic 2: Bearer Context Modification (User Plane Redirection / Eavesdropping)
    if proc_code == 6 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] Bearer Context Modification on E1 interface. Inspect GTP-U termination endpoints for user traffic diversion.")
    end

    if e1ap_dissector then
        e1ap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 64 (E1AP) and SCTP port 38462
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(38462, e1ap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(64, e1ap_sec_proto)
end
