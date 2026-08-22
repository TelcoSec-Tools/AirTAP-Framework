-- TelcoSec.net - GPRS Gr Interface (MAP over SS7/SIGTRAN) Security Dissector
-- Description: Dissects MAP messages on the Gr interface (3GPP TS 29.002) between SGSN and HLR.
--              Detects GPRS authentication triplet (sendAuthenticationInfo) interception,
--              rogue SGSN location updates (updateGprsLocation), and APN profile injection.

local ok, gprs_map_proto = pcall(Proto, "gprs_map_gr_sec", "TelcoSec GPRS Gr (MAP) Security Analyzer")
if not ok or not gprs_map_proto then return end

-- Protocol fields
local f_op_code      = ProtoField.uint8("gprs_map.op_code", "MAP Operation Code", base.DEC)
local f_op_name      = ProtoField.string("gprs_map.op_name", "MAP Operation Name")
local f_imsi         = ProtoField.string("gprs_map.imsi", "Target IMSI")
local f_sgsn_addr    = ProtoField.string("gprs_map.sgsn_addr", "SGSN Number / Address")
local f_sec_alert    = ProtoField.string("gprs_map.alert", "TelcoSec Gr Security Alert")
local f_payload      = ProtoField.bytes("gprs_map.payload", "MAP Payload")

gprs_map_proto.fields = {
    f_op_code,
    f_op_name,
    f_imsi,
    f_sgsn_addr,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 29.002 MAP Operations for GPRS
local MAP_GPRS_OPS = {
    [23] = "updateGprsLocation",
    [24] = "cancelLocation (GPRS)",
    [25] = "sendRoutingInfoForGprs",
    [56] = "sendAuthenticationInfo (GPRS Triplets)",
    [57] = "restoreData (GPRS)",
    [7]  = "insertSubscriberData (GPRS PDP Context Profile)",
    [8]  = "deleteSubscriberData (GPRS)",
    [2]  = "purgeMS (GPRS)"
}

-- Native GSM MAP dissector
local gsm_map_dissector = Dissector.get("gsm_map")

function gprs_map_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "SS7 MAP (Gr)"

    local op_code = tvb(0, 1):uint()
    local op_name = MAP_GPRS_OPS[op_code] or string.format("MAP Op %d", op_code)

    local subtree = tree:add(gprs_map_proto, tvb(), string.format("GPRS Gr (MAP): %s", op_name))
    subtree:add(f_op_code, tvb(0, 1))
    subtree:add(f_op_name, op_name)

    pinfo.cols.info = string.format("[GPRS Gr MAP] %s", op_name)

    -- Security Heuristic 1: sendAuthenticationInfo (GPRS Triplet Interception)
    if op_code == 56 then
        subtree:add(f_sec_alert, "[CRITICAL] GPRS Authentication Triplets (RAND, SRES, Kc) requested! Verify SGSN source Global Title (GT) to prevent remote subscriber impersonation.")
        pinfo.cols.info:append(" [TELCOSEC: GPRS AUTH TRIPLET REQUEST]")
    end

    -- Security Heuristic 2: updateGprsLocation (Rogue SGSN Location Tracking / DoS)
    if op_code == 23 then
        subtree:add(f_sec_alert, "[CRITICAL] GPRS Location Update commanded. Rogue SGSN GT injection can hijack incoming GPRS data sessions or track subscriber.")
        pinfo.cols.info:append(" [TELCOSEC: GPRS LOCATION UPDATE]")
    end

    -- Security Heuristic 3: insertSubscriberData (Malicious APN / QoS Injection)
    if op_code == 7 then
        subtree:add(f_sec_alert, "[WARNING] Subscriber GPRS profile / APN context injected by HLR.")
    end

    if gsm_map_dissector then
        gsm_map_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
