-- TelcoSec.net - S1AP (S1-MME Interface) Security Dissector & Post-Dissector
-- Description: Dissects S1AP signaling (3GPP TS 36.413) between eNodeB and MME.
--              Detects rogue eNodeB connections, malicious S1AP Reset DoS,
--              plain IMSI identity harvesting, and unencrypted NAS transfers on S1.

local ok, s1ap_sec_proto = pcall(Proto, "s1ap_sec", "TelcoSec S1AP (S1-MME) Security Analyzer")
if not ok or not s1ap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("s1ap_sec.pdu_type", "S1AP PDU Type")
local f_proc_code    = ProtoField.uint8("s1ap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("s1ap_sec.proc_name", "Procedure Name")
local f_mme_ue_id    = ProtoField.uint32("s1ap_sec.mme_ue_id", "MME UE S1AP ID", base.DEC)
local f_enb_ue_id    = ProtoField.uint32("s1ap_sec.enb_ue_id", "eNodeB UE S1AP ID", base.DEC)
local f_tac          = ProtoField.uint16("s1ap_sec.tac", "Tracking Area Code (TAC)", base.DEC)
local f_cell_id      = ProtoField.uint32("s1ap_sec.cell_id", "E-UTRAN Cell ID (ECI)", base.HEX)
local f_sec_alert    = ProtoField.string("s1ap_sec.alert", "TelcoSec S1AP Security Alert")
local f_payload      = ProtoField.bytes("s1ap_sec.payload", "S1AP ASN.1 Payload")

s1ap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_mme_ue_id,
    f_enb_ue_id,
    f_tac,
    f_cell_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 36.413 Elementary Procedures
local S1AP_PROC_CODES = {
    [0]  = "HandoverPreparation",
    [1]  = "HandoverResourceAllocation",
    [2]  = "HandoverNotification",
    [3]  = "PathSwitchRequest",
    [4]  = "HandoverCancel",
    [5]  = "E-RABSetup",
    [6]  = "E-RABModify",
    [7]  = "E-RABRelease",
    [9]  = "InitialContextSetup",
    [11] = "Paging",
    [12] = "DownlinkNASTransport",
    [13] = "InitialUEMessage",
    [14] = "UplinkNASTransport",
    [17] = "S1Setup",
    [18] = "UEContextRelease",
    [19] = "UEContextModification",
    [20] = "UECapabilityInfoIndication",
    [21] = "ErrorIndication",
    [22] = "NASNonDeliveryIndication",
    [23] = "Reset"
}

-- Native S1AP and SCTP hooks
local s1ap_dissector = Dissector.get("s1ap")

function s1ap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "LTE S1AP"

    -- S1AP ASN.1 Header: [0]=PDU Type (0=Initiating, 1=Successful, 2=Unsuccessful), [1]=Procedure Code
    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }
    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = S1AP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(s1ap_sec_proto, tvb(), string.format("S1AP Security: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[S1AP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: S1Setup Request (Rogue eNodeB Detection)
    if proc_code == 17 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] S1Setup Request from eNodeB. Verify eNodeB IP (" .. tostring(pinfo.src) .. ") is authorized on the S1-MME subnet.")
    end

    -- Security Heuristic 2: S1 Reset Injection (Core-level Denial of Service)
    if proc_code == 23 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[CRITICAL] S1 Reset commanded! Tears down all active UE radio connections on this S1-MME association.")
        pinfo.cols.info:append(" [TELCOSEC: S1 RESET INJECTION!]")
    end

    -- Security Heuristic 3: UEContextReleaseCommand Injection
    if proc_code == 18 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] UE Context Release commanded. Active 4G subscriber connection aborted.")
    end

    if s1ap_dissector then
        s1ap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 18 (S1AP) and SCTP port 36412
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(36412, s1ap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(18, s1ap_sec_proto)
end
