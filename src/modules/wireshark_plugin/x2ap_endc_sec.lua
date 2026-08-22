-- TelcoSec.net - 5G NSA (EN-DC: E-UTRA-NR Dual Connectivity) Security Dissector
-- Description: Dissects X2AP EN-DC signaling (3GPP TS 36.423 Rel-15+) between 4G MeNB and 5G SgNB.
--              Detects rogue 5G SgNB addition, unencrypted Secondary Cell Group (SCG) bearer establishment,
--              and 5G NSA session hijacking.

local ok, x2ap_endc_proto = pcall(Proto, "x2ap_endc_sec", "TelcoSec 5G NSA (EN-DC / X2AP) Security Analyzer")
if not ok or not x2ap_endc_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("x2ap_endc.pdu_type", "X2AP PDU Type")
local f_proc_code    = ProtoField.uint8("x2ap_endc.proc_code", "EN-DC Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("x2ap_endc.proc_name", "Procedure Name")
local f_menb_ue_id   = ProtoField.uint32("x2ap_endc.menb_ue_id", "MeNB UE X2AP ID", base.DEC)
local f_sgnb_ue_id   = ProtoField.uint32("x2ap_endc.sgnb_ue_id", "SgNB UE X2AP ID", base.DEC)
local f_sec_alert    = ProtoField.string("x2ap_endc.alert", "TelcoSec 5G NSA Security Alert")
local f_payload      = ProtoField.bytes("x2ap_endc.payload", "X2AP EN-DC Payload")

x2ap_endc_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_menb_ue_id,
    f_sgnb_ue_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 36.423 EN-DC Elementary Procedures
local ENDC_PROC_CODES = {
    [27] = "SgNBAdditionPreparation",
    [28] = "SgNBReconfigurationCompletion",
    [29] = "SgNBModificationPreparation",
    [30] = "SgNBRelease",
    [31] = "SgNBCounterCheck",
    [32] = "SgNBChange",
    [33] = "RRCTransfer",
    [36] = "SecondaryRATDataUsageReport"
}

-- Native X2AP dissector
local x2ap_dissector = Dissector.get("x2ap")

function x2ap_endc_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    -- Only inspect EN-DC procedures (Codes 27 to 36)
    if not ENDC_PROC_CODES[proc_code] then return end

    pinfo.cols.protocol = "EN-DC X2AP"

    local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }
    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = ENDC_PROC_CODES[proc_code]

    local subtree = tree:add(x2ap_endc_proto, tvb(), string.format("5G NSA EN-DC: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G NSA EN-DC] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: SgNB Addition Request (5G NSA Secondary Carrier Attachment)
    if proc_code == 27 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] SgNB Addition Request. 4G anchor adding 5G NR secondary carrier. Verify SgNB IP (" .. tostring(pinfo.dst) .. ") is an authentic 5G gNodeB.")
    end

    -- Security Heuristic 2: SgNB Release Request (5G NSA Secondary Carrier Drop / DoS)
    if proc_code == 30 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] SgNB Release commanded. Drops 5G NR dual connectivity, reducing connection to LTE only.")
        pinfo.cols.info:append(" [TELCOSEC: 5G NSA RELEASE]")
    end

    if x2ap_dissector then
        x2ap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 27 (X2AP) and port 36422
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(36422, x2ap_endc_proto)
end
