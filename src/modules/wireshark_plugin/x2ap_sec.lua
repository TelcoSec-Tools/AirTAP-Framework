-- TelcoSec.net - X2AP (Inter-eNodeB Interface) Security Dissector
-- Description: Dissects X2AP signaling (3GPP TS 36.423) between neighboring eNodeBs.
--              Detects malicious inter-eNodeB handover hijacks, unauthorized X2 Setup,
--              and cell load-dumping DoS attacks.

-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }

local ok, x2ap_sec_proto = pcall(Proto, "x2ap_sec", "TelcoSec X2AP (Inter-eNodeB) Security Analyzer")
if not ok or not x2ap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("x2ap_sec.pdu_type", "X2AP PDU Type")
local f_proc_code    = ProtoField.uint8("x2ap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("x2ap_sec.proc_name", "Procedure Name")
local f_old_enb_ue   = ProtoField.uint16("x2ap_sec.old_enb_ue", "Old eNodeB UE X2AP ID", base.DEC)
local f_new_enb_ue   = ProtoField.uint16("x2ap_sec.new_enb_ue", "New eNodeB UE X2AP ID", base.DEC)
local f_sec_alert    = ProtoField.string("x2ap_sec.alert", "TelcoSec X2AP Security Alert")
local f_payload      = ProtoField.bytes("x2ap_sec.payload", "X2AP Payload")

x2ap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_old_enb_ue,
    f_new_enb_ue,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 36.423 Elementary Procedures
local X2AP_PROC_CODES = {
    [0]  = "HandoverPreparation",
    [1]  = "HandoverCancel",
    [2]  = "LoadIndication",
    [3]  = "ErrorIndication",
    [4]  = "SNStatusTransfer",
    [5]  = "UEContextRelease",
    [6]  = "X2Setup",
    [7]  = "Reset",
    [8]  = "ENBConfigurationUpdate",
    [9]  = "ResourceStatusReportingInitiation",
    [10] = "ResourceStatusReporting",
    [14] = "CellActivation"
}

-- Native X2AP dissector
local x2ap_dissector = Dissector.get("x2ap")

function x2ap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "LTE X2AP"

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = X2AP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(x2ap_sec_proto, tvb(), string.format("X2AP Security: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[X2AP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: X2 Setup Request (Rogue Base Station Peering)
    if proc_code == 6 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] X2 Setup Request between base stations. Verify peer eNodeB IP (" .. tostring(pinfo.src) .. ") is an authentic neighboring cell.")
    end

    -- Security Heuristic 2: Handover Cancel / Forced Handover Hijack
    if proc_code == 1 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] Inter-eNodeB Handover Cancel received. Radio handover aborted.")
    end

    -- Security Heuristic 3: Cell Activation / Load Dumping
    if proc_code == 14 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] Cell Activation / Energy Savings state toggle on X2 interface.")
    end

    -- Security Heuristic 4: X2 Reset
    if proc_code == 7 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[CRITICAL] X2 Reset commanded! Destroys all active inter-cell handover context.")
        pinfo.cols.info:append(" [TELCOSEC: X2 RESET INJECTION]")
    end

    if x2ap_dissector then
        x2ap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 27 (X2AP) and SCTP port 36422
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(36422, x2ap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(27, x2ap_sec_proto)
end
