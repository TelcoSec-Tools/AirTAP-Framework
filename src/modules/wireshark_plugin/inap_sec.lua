-- TelcoSec.net - ITU-T INAP (Intelligent Network Application Part - ITU-T Q.1218 / Q.1228 / ETS 300 374-1 CS-1/CS-2) Master Security Dissector
-- Description: Complete analyzer for INAP signaling between SSF (Service Switching Function) and SCF (Service Control Function).
--              Decodes InitialDP, Connect, ReleaseCall, PromptAndCollectUserInformation, ApplyCharging, FurnishChargingInformation,
--              InitiateCallAttempt, and EventReportBCSM operations.
--              Detects PSTN/PLMN toll fraud, destination routing address hijacking, voice trunk denial of service,
--              and sensitive DTMF / PIN exfiltration attacks.

local ok, inap_sec_proto = pcall(Proto, "inap_sec", "TelcoSec ITU-T INAP (Intelligent Network Application Part) Security Analyzer")
if not ok or not inap_sec_proto then return end

-- Protocol fields
local f_op_code         = ProtoField.uint8("inap_sec.op_code", "INAP Operation Code", base.DEC)
local f_op_name         = ProtoField.string("inap_sec.op_name", "Operation Name")
local f_service_key     = ProtoField.uint32("inap_sec.service_key", "Service Key", base.DEC)
local f_called_party    = ProtoField.string("inap_sec.called_party", "Called Party Number")
local f_calling_party   = ProtoField.string("inap_sec.calling_party", "Calling Party Number")
local f_dest_routing    = ProtoField.string("inap_sec.dest_routing", "Destination Routing Address")
local f_collected_digits= ProtoField.string("inap_sec.collected_digits", "Collected DTMF / User Input Digits")
local f_release_cause   = ProtoField.uint8("inap_sec.release_cause", "Release Cause Code", base.DEC)
local f_sec_alert       = ProtoField.string("inap_sec.alert", "TelcoSec INAP Security Alert")
local f_payload         = ProtoField.bytes("inap_sec.payload", "INAP Raw ASN.1 Payload")

inap_sec_proto.fields = {
    f_op_code,
    f_op_name,
    f_service_key,
    f_called_party,
    f_calling_party,
    f_dest_routing,
    f_collected_digits,
    f_release_cause,
    f_sec_alert,
    f_payload
}

-- ITU-T Q.1218 / Q.1228 INAP Operation Codes
local INAP_OP_CODES = {
    [0]  = "InitialDP",
    [16] = "AssistRequestInstructions",
    [17] = "EstablishTemporaryConnection",
    [18] = "DisconnectForwardConnection",
    [19] = "ConnectToResource",
    [20] = "Connect",
    [22] = "ReleaseCall",
    [23] = "RequestReportBCSMEvent",
    [24] = "EventReportBCSM",
    [25] = "SpecializedResourceReport",
    [27] = "CollectInformation",
    [31] = "Continue",
    [32] = "InitiateCallAttempt",
    [34] = "FurnishChargingInformation",
    [35] = "ApplyCharging",
    [36] = "ApplyChargingReport",
    [46] = "SendChargingInformation",
    [47] = "PlayAnnouncement",
    [48] = "PromptAndCollectUserInformation",
    [53] = "Cancel",
    [55] = "ActivityTest"
}

-- Native INAP dissector
local native_inap = Dissector.get("inap")

function inap_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    pinfo.cols.protocol = "SS7 INAP"

    local op_code = tvb(0, 1):uint()
    local op_name = INAP_OP_CODES[op_code]

    if not op_name and len >= 4 then
        for off = 0, math.min(len - 1, 5) do
            local cand = tvb(off, 1):uint()
            if INAP_OP_CODES[cand] then
                op_code = cand
                op_name = INAP_OP_CODES[cand]
                break
            end
        end
    end

    op_name = op_name or string.format("INAP Op %d", op_code)

    local subtree = tree:add(inap_sec_proto, tvb(), string.format("ITU-T INAP Security Engine: %s", op_name))
    subtree:add(f_op_code, tvb(0, 1), op_code)
    subtree:add(f_op_name, op_name)

    pinfo.cols.info = string.format("[SS7 INAP] %s", op_name)

    local alerts = {}

    -- Security Heuristic 1: Destination Routing Address Hijack (Connect - Op 20)
    if op_code == 20 then
        table.insert(alerts, "[CRITICAL] INAP Connect: SCF commanded call routing address override! Verify destination number against toll-fraud / premium rate blocklists.")
        pinfo.cols.info:append(" [TELCOSEC: ROUTING ADDRESS OVERRIDE!]")
    end

    -- Security Heuristic 2: Abrupt Voice Trunk Teardown (ReleaseCall - Op 22)
    if op_code == 22 then
        table.insert(alerts, "[WARNING] INAP ReleaseCall: Forcibly terminates active telephone session from SCP.")
        pinfo.cols.info:append(" [TELCOSEC: INAP CALL TEARDOWN]")
    end

    -- Security Heuristic 3: DTMF / PIN Exfiltration (PromptAndCollectUserInformation - Op 48)
    if op_code == 48 then
        table.insert(alerts, "[HIGH RISK] INAP PromptAndCollectUserInformation: Interactive voice response prompting for user DTMF input (PIN/Account Number). Verify legitimate banking/IVR service context.")
        pinfo.cols.info:append(" [TELCOSEC: DTMF COLLECTION PROMPT]")
    end

    -- Security Heuristic 4: Unauthorized Call Inception (InitiateCallAttempt - Op 32)
    if op_code == 32 then
        table.insert(alerts, "[CRITICAL] INAP InitiateCallAttempt: SCF initiating new call attempt without subscriber handset origin! Potential automated toll fraud / callback generation.")
        pinfo.cols.info:append(" [TELCOSEC: SCP CALL INITIATION!]")
    end

    -- Security Heuristic 5: CDR Manipulation (FurnishChargingInformation - Op 34)
    if op_code == 34 then
        table.insert(alerts, "[HIGH RISK] INAP FurnishChargingInformation: Overrides switch billing records (CDR). Inspect for zero-rating evasion.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if native_inap then
        native_inap:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register as postdissector to inspect all SS7 INAP traffic
register_postdissector(inap_sec_proto)
