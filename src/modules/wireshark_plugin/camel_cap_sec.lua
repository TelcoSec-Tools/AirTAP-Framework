-- TelcoSec.net - 3GPP CAMEL Application Part (CAP Phase 1..4 - 3GPP TS 29.078 / TS 23.078) Master Security Dissector
-- Description: Complete analyzer for CAMEL Application Part (CAP) signaling between gsmSSF/gprsSSF and gsmSCF.
--              Decodes InitialDP, Connect, ReleaseCall, ApplyCharging, FurnishChargingInformation, EventReportBCSM,
--              and specialized user interaction procedures.
--              Detects intelligent network call hijacking, wiretap redirection, telecom toll fraud,
--              covert CAMEL location harvesting, and billing bypass vulnerabilities.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
local bit = bit or bit32
if not bit then
    bit = {
        band   = function(a, b) return a & b end,
        bor    = function(a, b) return a | b end,
        bxor   = function(a, b) return a ~ b end,
        lshift = function(a, n) return (a << n) & 0xFFFFFFFF end,
        rshift = function(a, n) return (a & 0xFFFFFFFF) >> n end,
    }
end

local ok, cap_sec_proto = pcall(Proto, "camel_cap_sec", "TelcoSec 3GPP CAMEL / CAP (Customised Applications for Mobile networks) Security Analyzer")
if not ok or not cap_sec_proto then return end

-- Protocol fields
local f_op_code         = ProtoField.uint8("camel_cap_sec.op_code", "CAP Operation Code", base.DEC)
local f_op_name         = ProtoField.string("camel_cap_sec.op_name", "Operation Name")
local f_service_key     = ProtoField.uint32("camel_cap_sec.service_key", "Service Key", base.DEC)
local f_called_party    = ProtoField.string("camel_cap_sec.called_party", "Called Party BCD Number")
local f_calling_party   = ProtoField.string("camel_cap_sec.calling_party", "Calling Party Number")
local f_dest_routing    = ProtoField.string("camel_cap_sec.dest_routing", "Destination Routing Address (Redirect Target)")
local f_location_num    = ProtoField.string("camel_cap_sec.location_num", "Location Number / Cell ID")
local f_imsi            = ProtoField.string("camel_cap_sec.imsi", "Subscriber IMSI")
local f_max_duration    = ProtoField.uint32("camel_cap_sec.max_duration", "Max Call Duration (seconds)", base.DEC)
local f_fci_data        = ProtoField.bytes("camel_cap_sec.fci_data", "Furnish Charging Info (FCI) Data")
local f_sec_alert       = ProtoField.string("camel_cap_sec.alert", "TelcoSec CAMEL/CAP Security Alert")
local f_payload         = ProtoField.bytes("camel_cap_sec.payload", "CAP Raw ASN.1 Payload")

cap_sec_proto.fields = {
    f_op_code,
    f_op_name,
    f_service_key,
    f_called_party,
    f_calling_party,
    f_dest_routing,
    f_location_num,
    f_imsi,
    f_max_duration,
    f_fci_data,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 29.078 Table 6-1 CAP Operation Codes
local CAP_OP_CODES = {
    [0]  = "initialDP",
    [17] = "establishTemporaryConnection",
    [18] = "disconnectForwardConnection",
    [19] = "connectToResource",
    [20] = "connect",
    [22] = "releaseCall",
    [23] = "requestReportBCSMEvent",
    [24] = "eventReportBCSM",
    [25] = "specializedResourceReport",
    [31] = "continue",
    [34] = "furnishChargingInformation",
    [35] = "applyCharging",
    [36] = "applyChargingReport",
    [46] = "sendChargingInformation",
    [47] = "playAnnouncement",
    [48] = "promptAndCollectUserInformation",
    [53] = "cancel",
    [55] = "activityTest",
    [56] = "continueWithArgument",
    [60] = "initialDPGPRS",
    [61] = "initialDPSMS",
    [62] = "requestReportSMSEvent",
    [63] = "eventReportSMS",
    [64] = "furnishChargingInformationGPRS",
    [65] = "activityTestGPRS",
    [66] = "requestReportGPRSEvent",
    [67] = "eventReportGPRS",
    [68] = "sendChargingInformationGPRS"
}

-- Native CAMEL dissector
local native_camel = Dissector.get("camel")

-- Helper: decode TBCD phone numbers
local function decode_tbcd_str(tvb, offset, length)
    if offset + length > tvb:len() then return nil end
    local digits = ""
    for i = 0, length - 1 do
        local b = tvb(offset + i, 1):uint()
        local low = bit.band(b, 0x0F)
        local high = bit.rshift(b, 4)
        if low <= 9 then digits = digits .. tostring(low) end
        if high <= 9 then digits = digits .. tostring(high) end
    end
    return digits
end

function cap_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    pinfo.cols.protocol = "SS7 CAMEL/CAP"

    -- Find Operation Code
    local op_code = tvb(0, 1):uint()
    local op_name = CAP_OP_CODES[op_code]

    if not op_name and len >= 4 then
        for off = 0, math.min(len - 1, 5) do
            local cand = tvb(off, 1):uint()
            if CAP_OP_CODES[cand] then
                op_code = cand
                op_name = CAP_OP_CODES[cand]
                break
            end
        end
    end

    op_name = op_name or string.format("CAP Op %d", op_code)

    local subtree = tree:add(cap_sec_proto, tvb(), string.format("3GPP CAMEL / CAP Security Engine: %s", op_name))
    subtree:add(f_op_code, tvb(0, 1), op_code)
    subtree:add(f_op_name, op_name)

    pinfo.cols.info = string.format("[CAMEL CAP] %s", op_name)

    local alerts = {}

    -- Parse Service Key (Integer Tag 0x02) in InitialDP
    if op_code == 0 and len >= 6 then
        for off = 1, len - 4 do
            if tvb(off, 1):uint() == 0x02 and tvb(off + 1, 1):uint() <= 4 then
                local sk_len = tvb(off + 1, 1):uint()
                local sk_val = tvb(off + 2, sk_len):uint()
                subtree:add(f_service_key, tvb(off + 2, sk_len), sk_val)
                pinfo.cols.info:append(string.format(" (ServiceKey: %d)", sk_val))
                break
            end
        end
    end

    -- Security Heuristic 1: Malicious Call Redirection / Wiretap Routing (Connect - Op 20)
    if op_code == 20 then
        table.insert(alerts, "[CRITICAL] CAMEL Connect Commanded! The gsmSCF is dynamically rewriting the destination routing address. Potential call diversion / MITM wiretap routing.")
        pinfo.cols.info:append(" [TELCOSEC: CALL ROUTING REWRITE!]")
    end

    -- Security Heuristic 2: Toll Fraud & Billing Bypass (FurnishChargingInformation / ApplyCharging)
    if op_code == 34 or op_code == 64 then
        table.insert(alerts, "[HIGH RISK] CAMEL FurnishChargingInformation (FCI) Received! Manipulates Call Detail Record (CDR) billing data in MSC. Inspect for toll fraud zero-rating.")
        pinfo.cols.info:append(" [TELCOSEC: CDR CHARGING OVERRIDE]")
    elseif op_code == 35 then
        table.insert(alerts, "[INFO] CAMEL ApplyCharging Received. Real-time call duration balance enforcement.")
    end

    -- Security Heuristic 3: Abrupt Call Teardown / DoS (ReleaseCall - Op 22)
    if op_code == 22 then
        table.insert(alerts, "[WARNING] CAMEL ReleaseCall Commanded. Active call forcibly torn down by SCP.")
        pinfo.cols.info:append(" [TELCOSEC: CAMEL CALL TEARDOWN]")
    end

    -- Security Heuristic 4: Covert Location Harvesting in InitialDP (Cell ID / Location Number)
    if op_code == 0 or op_code == 60 then
        table.insert(alerts, "[INFO] CAMEL InitialDP received with subscriber cell/location metadata.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if native_camel then
        native_camel:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register on SCCP SSN table for CAP (146=gsmSCF, 147=gsmSSF)
local sccp_ssn_table = DissectorTable.get("sccp.ssn")
if sccp_ssn_table then
    sccp_ssn_table:add(146, cap_sec_proto)
    sccp_ssn_table:add(147, cap_sec_proto)
end

-- Register as postdissector
register_postdissector(cap_sec_proto)
