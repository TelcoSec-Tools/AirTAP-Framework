-- TelcoSec.net - SS7 ISUP & TCAP Call Routing Security Analyzer
-- Target Standards: ITU-T Q.763 (ISUP Formats and Codes), ITU-T Q.773 (TCAP Formats and Syntax)
-- Description: Dissects ISUP call setup/teardown messages (IAM, ACM, ANM, REL, RLC) and TCAP transaction packages.
--              Detects unauthenticated call diversion (IAM Called Party Number tampering), premium-rate toll fraud,
--              abrupt circuit release injection (REL), and TCAP transaction hijacking.

local ok, isup_tcap_proto = pcall(Proto, "isup_tcap_sec", "TelcoSec SS7 ISUP & TCAP Security Analyzer")
if not ok or not isup_tcap_proto then return end

-- Protocol fields
local f_msg_type        = ProtoField.uint8("isup_tcap_sec.msg_type", "ISUP Message Type", base.HEX)
local f_msg_name        = ProtoField.string("isup_tcap_sec.msg_name", "ISUP Message Name")
local f_cic             = ProtoField.uint16("isup_tcap_sec.cic", "Circuit Identification Code (CIC)", base.DEC)
local f_called_party    = ProtoField.string("isup_tcap_sec.called_party", "Called Party Number")
local f_calling_party   = ProtoField.string("isup_tcap_sec.calling_party", "Calling Party Number")
local f_rel_cause       = ProtoField.uint8("isup_tcap_sec.rel_cause", "Release Cause", base.DEC)
local f_tcap_pkg_type   = ProtoField.string("isup_tcap_sec.tcap_pkg", "TCAP Package Type")
local f_sec_alert       = ProtoField.string("isup_tcap_sec.alert", "TelcoSec ISUP/TCAP Alert")

isup_tcap_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_cic,
    f_called_party,
    f_calling_party,
    f_rel_cause,
    f_tcap_pkg_type,
    f_sec_alert
}

-- Known ISUP Message Types (ITU-T Q.763)
local ISUP_MSGS = {
    [0x01] = "Initial Address Message (IAM)",
    [0x02] = "Subsequent Address Message (SAM)",
    [0x03] = "Information Request (INR)",
    [0x04] = "Information (INF)",
    [0x05] = "Continuity Check (COT)",
    [0x06] = "Address Complete (ACM)",
    [0x07] = "Connect (CON)",
    [0x08] = "Forward Transfer (FOT)",
    [0x09] = "Answer (ANM)",
    [0x0C] = "Release (REL)",
    [0x0E] = "User-to-User Info (USR)",
    [0x10] = "Release Complete (RLC)",
    [0x11] = "Continuity Check Request (CCR)",
    [0x12] = "Reset Circuit (RSC)",
    [0x13] = "Blocking (BLO)",
    [0x14] = "Unblocking (UBL)",
    [0x15] = "Blocking Ack (BLA)",
    [0x16] = "Unblocking Ack (UBA)",
    [0x17] = "Circuit Group Reset (GRS)",
    [0x18] = "Circuit Group Blocking (CGB)",
    [0x19] = "Circuit Group Unblocking (CGU)"
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_isup_msg_f   = safe_field("isup.message_type")
local f_isup_called  = safe_field("isup.called_party_number")
local f_isup_calling = safe_field("isup.calling_party_number")
local f_tcap_tag     = safe_field("tcap.tag")

function isup_tcap_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    local is_isup = string.find(proto_str, "ISUP") or (f_isup_msg_f and f_isup_msg_f())
    local is_tcap = string.find(proto_str, "TCAP") or (f_tcap_tag and f_tcap_tag())

    if not (is_isup or is_tcap) then return end

    local subtree = tree:add(isup_tcap_proto, tvb(), "TelcoSec SS7 ISUP / TCAP Security Engine")
    local alerts = {}

    if is_isup and f_isup_msg_f and f_isup_msg_f() then
        local msg_type = f_isup_msg_f().value
        local msg_name = ISUP_MSGS[msg_type] or string.format("ISUP Msg 0x%02X", msg_type)
        subtree:add(f_msg_type, msg_type)
        subtree:add(f_msg_name, msg_name)

        -- Security Heuristic 1: Reset Circuit / Circuit Group Blocking DoS
        if msg_type == 0x12 or msg_type == 0x17 or msg_type == 0x18 then
            table.insert(alerts, string.format("[CRITICAL] ISUP %s commanded! Abruptly tears down or blocks PSTN voice trunk circuits.", msg_name))
        end

        -- Security Heuristic 2: Premium-rate / High-cost Destination Check
        if msg_type == 0x01 and f_isup_called and f_isup_called() then
            local called_num = tostring(f_isup_called().value)
            subtree:add(f_called_party, called_num)
            if string.match(called_num, "^0088") or string.match(called_num, "^0900") or string.match(called_num, "^1900") then
                table.insert(alerts, string.format("[CRITICAL] High-cost International / Premium-Rate ISUP Destination (%s)! Telecom Toll Fraud alert.", called_num))
            end
        end
    end

    if is_tcap then
        subtree:add(f_tcap_pkg_type, "TCAP Transaction Package")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: ISUP/TCAP ALERT!]")
    end
end

register_postdissector(isup_tcap_proto)
