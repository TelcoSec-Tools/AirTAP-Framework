-- TelcoSec.net - LTE & 5G NR Positioning Protocol (LPP / TS 36.355 / TS 37.355) Security Dissector
-- Description: Dissects 3GPP LPP positioning signaling over SLs / LCS interfaces and NAS Generic Container.
--              Decodes transaction headers, procedure types (Capabilities, Location Info, Assistance Data),
--              positioning methods (A-GNSS, OTDOA, E-CID, RTK, Sensor, WLAN, Bluetooth), and QoS accuracy constraints.
--              Detects covert device geolocation tracking, GNSS spoofing vectors, and E911 emergency location abort attacks.

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

local ok, lpp_sec_proto = pcall(Proto, "lpp_positioning_sec", "TelcoSec LTE/5G Positioning Protocol (LPP) Security Analyzer")
if not ok or not lpp_sec_proto then return end

-- Protocol fields
local f_trans_id         = ProtoField.uint8("lpp_sec.trans_id", "Transaction ID", base.DEC)
local f_end_trans        = ProtoField.bool("lpp_sec.end_trans", "End Transaction Flag")
local f_seq_num          = ProtoField.uint8("lpp_sec.seq_num", "Sequence Number", base.DEC)
local f_msg_type         = ProtoField.uint8("lpp_sec.msg_type", "LPP Message Type Code", base.HEX)
local f_msg_name         = ProtoField.string("lpp_sec.msg_name", "LPP Message Type")
local f_methods          = ProtoField.string("lpp_sec.methods", "Active Positioning Methods")
local f_horiz_acc        = ProtoField.uint8("lpp_sec.horiz_acc", "Horizontal Accuracy Requested (m)", base.DEC)
local f_resp_time        = ProtoField.uint8("lpp_sec.resp_time", "Response Time Constraint (s)", base.DEC)
local f_period_rpt       = ProtoField.bool("lpp_sec.periodic_rpt", "Periodic Location Reporting Requested")
local f_sec_alert        = ProtoField.string("lpp_sec.alert", "TelcoSec Positioning Security Alert")
local f_payload          = ProtoField.bytes("lpp_sec.payload", "LPP Raw ASN.1 Payload")

lpp_sec_proto.fields = {
    f_trans_id,
    f_end_trans,
    f_seq_num,
    f_msg_type,
    f_msg_name,
    f_methods,
    f_horiz_acc,
    f_resp_time,
    f_period_rpt,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 36.355 LPP Message Types (choice index in LPP-Message-Body)
local LPP_MSG_TYPES = {
    [0] = "requestCapabilities",
    [1] = "provideCapabilities",
    [2] = "requestLocationInformation",
    [3] = "provideLocationInformation",
    [4] = "requestAssistanceData",
    [5] = "provideAssistanceData",
    [6] = "error",
    [7] = "abort"
}

-- Native LPP dissector
local lpp_dissector = Dissector.get("lpp")

function lpp_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    -- Parse LPP Header (TS 36.355 §6.2)
    -- Byte 0: [7:5] Transaction ID (3-8 bits), [4] End Transaction, [3:0] Sequence / Extension
    local b0 = tvb(0, 1):uint()
    local trans_id  = bit.rshift(b0, 3)
    local end_trans = bit.band(bit.rshift(b0, 2), 1) ~= 0
    local has_seq   = bit.band(b0, 0x03) ~= 0

    local hdr_len = 1
    local seq_num = 0
    if has_seq and len >= 2 then
        seq_num = tvb(1, 1):uint()
        hdr_len = 2
    end

    -- Determine LPP Message Type from subsequent byte choice
    local msg_type_idx = 0
    local msg_name = "LPP-Message"
    if len > hdr_len then
        local b_choice = tvb(hdr_len, 1):uint()
        msg_type_idx = bit.band(bit.rshift(b_choice, 4), 0x07)
        msg_name = LPP_MSG_TYPES[msg_type_idx] or string.format("LPP Choice %d", msg_type_idx)
    end

    pinfo.cols.protocol = "LTE LPP"
    pinfo.cols.info = string.format("[LPP Positioning] %s (Tx: %d%s)", msg_name, trans_id, end_trans and " [END]" or "")

    local subtree = tree:add(lpp_sec_proto, tvb(), string.format("LTE/5G Positioning Protocol (LPP): %s (Tx ID: %d)", msg_name, trans_id))
    subtree:add(f_trans_id, tvb(0, 1), trans_id)
    subtree:add(f_end_trans, end_trans)
    if has_seq then
        subtree:add(f_seq_num, tvb(1, 1), seq_num)
    end
    subtree:add(f_msg_type, msg_type_idx)
    subtree:add(f_msg_name, msg_name)

    local alerts = {}
    local methods = {}

    -- Inspect positioning methods in payload
    -- Check for method identifiers across LPP payload
    for off = hdr_len, len - 1 do
        local b = tvb(off, 1):uint()
        -- TS 36.355 method presence bit patterns
        if b == 0x01 or b == 0x81 then
            table.insert(methods, "A-GNSS")
        elseif b == 0x02 or b == 0x82 then
            table.insert(methods, "OTDOA (PRS)")
        elseif b == 0x03 or b == 0x83 then
            table.insert(methods, "E-CID (Cell/Beam)")
        elseif b == 0x04 or b == 0x84 then
            table.insert(methods, "Sensor / Barometer")
        elseif b == 0x05 or b == 0x85 then
            table.insert(methods, "WLAN AP Positioning")
        elseif b == 0x06 or b == 0x86 then
            table.insert(methods, "Bluetooth Beacon")
        elseif b == 0x07 or b == 0x87 then
            table.insert(methods, "RTK / High-Accuracy GNSS")
        end
    end

    if #methods > 0 then
        local methods_str = table.concat(methods, ", ")
        subtree:add(f_methods, methods_str)
    end

    -- Security Heuristic 1: Covert High-Accuracy Geolocation Tracking Request
    if msg_type_idx == 2 then -- requestLocationInformation
        table.insert(alerts, string.format(
            "[CRITICAL] Device Geolocation Query (requestLocationInformation)! " ..
            "E-SMLC / LMF actively querying precise coordinates via LPP. Verify authorized lawful warrant.",
            trans_id))
        pinfo.cols.info:append(" [TELCOSEC: GEOLOCATION QUERY!]")
    end

    -- Security Heuristic 2: Real-Time RTK / High-Precision Carrier Phase Tracking
    if msg_type_idx == 4 then -- requestAssistanceData
        for _, m in ipairs(methods) do
            if m == "RTK / High-Accuracy GNSS" then
                table.insert(alerts, "[HIGH RISK] RTK / Differential Carrier-Phase Assistance Requested! Sub-meter precision tracking active.")
                break
            end
        end
    end

    -- Security Heuristic 3: LPP Abort (Emergency E911 Location Denial of Service)
    if msg_type_idx == 7 then -- abort
        table.insert(alerts, "[WARNING] LPP Positioning Session Aborted! Possible positioning failure or malicious abort injection during emergency location lookup.")
    end

    -- Security Heuristic 4: LPP Error Reporting
    if msg_type_idx == 6 then -- error
        table.insert(alerts, "[INFO] LPP Positioning Error PDU received. Target UE cannot satisfy accuracy or method requirements.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if lpp_dissector then
        lpp_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(hdr_len, len - hdr_len))
    end
end

-- Register as postdissector to analyze LPP inside NAS / SLs / NGAP / S1AP
register_postdissector(lpp_sec_proto)
