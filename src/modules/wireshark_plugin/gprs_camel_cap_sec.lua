-- TelcoSec.net - GPRS Ge Interface (CAMEL / CAP for GPRS) Security Dissector
-- Description: Dissects CAMEL Application Part (CAP) messages (3GPP TS 23.078) on Ge interface (SGSN to gsmSCF).
--              Inspects real-time prepaid GPRS billing, session charging, and quota manipulation.

local ok, gprs_cap_proto = pcall(Proto, "gprs_camel_cap_sec", "TelcoSec GPRS Ge (CAMEL/CAP) Security Analyzer")
if not ok or not gprs_cap_proto then return end

-- Protocol fields
local f_op_code      = ProtoField.uint8("gprs_cap.op_code", "CAP Operation Code", base.DEC)
local f_op_name      = ProtoField.string("gprs_cap.op_name", "CAP Operation Name")
local f_pdp_type     = ProtoField.string("gprs_cap.pdp_type", "PDP Type")
local f_sec_alert    = ProtoField.string("gprs_cap.alert", "TelcoSec CAMEL Security Alert")
local f_payload      = ProtoField.bytes("gprs_cap.payload", "CAP Payload")

gprs_cap_proto.fields = {
    f_op_code,
    f_op_name,
    f_pdp_type,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 23.078 CAP v3/v4 Operations for GPRS
local CAP_GPRS_OPS = {
    [70] = "initialDPGPRS",
    [71] = "applyChargingGPRS",
    [72] = "applyChargingReportGPRS",
    [73] = "cancelGPRS",
    [74] = "connectGPRS",
    [75] = "continueGPRS",
    [76] = "releaseGPRS",
    [77] = "requestReportGPRSEvent",
    [78] = "eventReportGPRS",
    [79] = "furnishChargingInformationGPRS",
    [80] = "activityTestGPRS",
    [81] = "sendChargingInformationGPRS"
}

-- Native CAMEL dissector
local camel_dissector = Dissector.get("camel")

function gprs_cap_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "SS7 CAP (Ge)"

    local op_code = tvb(0, 1):uint()
    local op_name = CAP_GPRS_OPS[op_code] or string.format("CAP Op %d", op_code)

    local subtree = tree:add(gprs_cap_proto, tvb(), string.format("GPRS Ge (CAMEL CAP): %s", op_name))
    subtree:add(f_op_code, tvb(0, 1))
    subtree:add(f_op_name, op_name)

    pinfo.cols.info = string.format("[GPRS Ge CAP] %s", op_name)

    -- Security Heuristic 1: initialDPGPRS (Prepaid Session Establishment)
    if op_code == 70 then
        subtree:add(f_sec_alert, "[INFO] GPRS Prepaid Session Initialization. Evaluates subscriber account balance and allowed APN services.")
    end

    -- Security Heuristic 2: applyChargingGPRS (Quota Allocation Inspection)
    if op_code == 71 then
        subtree:add(f_sec_alert, "[INFO] Real-time data volume/duration quota granted by SCP.")
    end

    -- Security Heuristic 3: releaseGPRS (Forced Session Disconnection)
    if op_code == 76 then
        subtree:add(f_sec_alert, "[WARNING] Immediate GPRS Session Teardown commanded by gsmSCF (Prepaid quota depleted or policy kill).")
        pinfo.cols.info:append(" [TELCOSEC: PREPAID SESSION TERMINATION]")
    end

    if camel_dissector then
        camel_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
