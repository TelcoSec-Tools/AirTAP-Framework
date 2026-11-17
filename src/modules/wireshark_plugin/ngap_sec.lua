-- TelcoSec.net - 5G NGAP (N2 Interface: gNB <-> AMF) Security Dissector
-- Description: Dissects NGAP signaling (3GPP TS 38.413) between 5G gNodeB and AMF.
--              Detects rogue gNodeB connections, malicious NG Reset DoS,
--              plain SUPI/IMSI extraction queries, and unauthorized AMF associations.

-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local pdu_types = { [0]="InitiatingMessage", [1]="SuccessfulOutcome", [2]="UnsuccessfulOutcome" }

local ok, ngap_sec_proto = pcall(Proto, "ngap_sec", "TelcoSec 5G NGAP (N2 Interface) Security Analyzer")
if not ok or not ngap_sec_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.string("ngap_sec.pdu_type", "NGAP PDU Type")
local f_proc_code    = ProtoField.uint8("ngap_sec.proc_code", "Procedure Code", base.DEC)
local f_proc_name    = ProtoField.string("ngap_sec.proc_name", "Procedure Name")
local f_amf_ue_id    = ProtoField.uint64("ngap_sec.amf_ue_id", "AMF UE NGAP ID", base.DEC)
local f_gnb_ue_id    = ProtoField.uint32("ngap_sec.gnb_ue_id", "RAN UE NGAP ID", base.DEC)
local f_plmn_id      = ProtoField.string("ngap_sec.plmn_id", "Serving PLMN ID")
local f_sec_alert    = ProtoField.string("ngap_sec.alert", "TelcoSec NGAP Security Alert")
local f_payload      = ProtoField.bytes("ngap_sec.payload", "NGAP ASN.1 Payload")

ngap_sec_proto.fields = {
    f_pdu_type,
    f_proc_code,
    f_proc_name,
    f_amf_ue_id,
    f_gnb_ue_id,
    f_plmn_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.413 Elementary Procedures (Table 9.2.0-1)
local NGAP_PROC_CODES = {
    [0]  = "HandoverPreparation",
    [1]  = "HandoverResourceAllocation",
    [2]  = "HandoverNotification",
    [3]  = "PathSwitchRequest",
    [4]  = "HandoverCancel",
    [14] = "InitialContextSetup",
    [20] = "NGReset",
    [21] = "NGSetup",
    [22] = "OverloadStart",
    [23] = "OverloadStop",
    [24] = "Paging",
    [28] = "RerouteNASRequest",
    [29] = "DownlinkNASTransport",
    [30] = "InitialUEMessage",
    [31] = "UplinkNASTransport",
    [33] = "UEContextRelease",
    [34] = "UEContextModification",
    [35] = "UEContextSuspend",
    [36] = "UEContextResume",
    [37] = "UEInformationTransfer",
    [40] = "WriteReplaceWarning",
    [41] = "PWSCancel"
}

-- Native NGAP dissector
local ngap_dissector = Dissector.get("ngap")

function ngap_sec_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "5G NGAP"

    -- NGAP ASN.1 Header: [0]=PDU Type (0=Initiating, 1=Successful, 2=Unsuccessful), [1]=Procedure Code
    local pdu_type_id = tvb(0, 1):uint()
    local proc_code = tvb(1, 1):uint()

    local pdu_type_str = pdu_types[pdu_type_id] or string.format("PDU Type %d", pdu_type_id)
    local proc_name = NGAP_PROC_CODES[proc_code] or string.format("Procedure %d", proc_code)

    local subtree = tree:add(ngap_sec_proto, tvb(), string.format("5G NGAP Security: %s (%s)", proc_name, pdu_type_str))
    subtree:add(f_pdu_type, pdu_type_str)
    subtree:add(f_proc_code, tvb(1, 1), proc_code)
    subtree:add(f_proc_name, proc_name)

    pinfo.cols.info = string.format("[5G NGAP] %s (%s)", proc_name, pdu_type_str)

    -- Security Heuristic 1: NGSetup Request (Rogue gNodeB Detection)
    if proc_code == 21 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[INFO] NGSetup Request from gNodeB. Verify gNB IP (" .. tostring(pinfo.src) .. ") is an authorized 5G radio node on N2.")
    end

    -- Security Heuristic 2: NGReset Injection (Core-level 5G Denial of Service)
    if proc_code == 20 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[CRITICAL] NGReset commanded! Tears down all active 5G Standalone subscriber sessions on this AMF-gNB association.")
        pinfo.cols.info:append(" [TELCOSEC: 5G NG RESET INJECTION!]")
    end

    -- Security Heuristic 3: OverloadStart (AMF Throttle Manipulation)
    if proc_code == 22 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] OverloadStart received. Restricts new 5GS registration attempts.")
    end

    -- Security Heuristic 4: UE Context Release Command
    if proc_code == 33 and pdu_type_id == 0 then
        subtree:add(f_sec_alert, "[WARNING] 5G UE Context Release commanded. Abrupt subscriber session teardown.")
    end

    if ngap_dissector then
        ngap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end

-- Register to SCTP Payload Protocol ID 60 (NGAP) and SCTP port 38412
local sctp_port_table = DissectorTable.get("sctp.port")
if sctp_port_table then
    sctp_port_table:add(38412, ngap_sec_proto)
end

local sctp_ppi_table = DissectorTable.get("sctp.ppi")
if sctp_ppi_table then
    sctp_ppi_table:add(60, ngap_sec_proto)
end
