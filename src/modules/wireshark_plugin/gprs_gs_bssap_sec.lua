-- TelcoSec.net - GPRS Gs Interface (BSSAP+) Security Dissector
-- Description: Dissects BSSAP+ messages (3GPP TS 29.018) between SGSN and MSC/VLR.
--              Analyzes combined GPRS/IMSI mobility management and paging cancellation.

local ok, gprs_gs_proto = pcall(Proto, "gprs_gs_bssap_sec", "TelcoSec GPRS Gs (BSSAP+) Security Analyzer")
if not ok or not gprs_gs_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gprs_gs.msg_type", "BSSAP+ Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gprs_gs.msg_name", "Message Name")
local f_imsi         = ProtoField.string("gprs_gs.imsi", "Target IMSI")
local f_sec_alert    = ProtoField.string("gprs_gs.alert", "TelcoSec Gs Security Alert")
local f_payload      = ProtoField.bytes("gprs_gs.payload", "BSSAP+ Payload")

gprs_gs_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_imsi,
    f_sec_alert,
    f_payload
}

-- BSSAP+ Message Types (3GPP TS 29.018 Table 9.1)
local GS_MSG_TYPES = {
    [0x01] = "BSSAP+-PAGING-REQUEST",
    [0x02] = "BSSAP+-PAGING-REJECT",
    [0x06] = "BSSAP+-LOCATION-UPDATE-ACCEPT",
    [0x07] = "BSSAP+-LOCATION-UPDATE-REJECT",
    [0x08] = "BSSAP+-LOCATION-UPDATE-REQUEST",
    [0x09] = "BSSAP+-TMSI-REALLOCATION-COMPLETE",
    [0x0B] = "BSSAP+-ALERT-REQUEST",
    [0x0C] = "BSSAP+-ALERT-ACK",
    [0x0D] = "BSSAP+-ALERT-REJECT",
    [0x0E] = "BSSAP+-MS-ACTIVITY-INDICATION",
    [0x0F] = "BSSAP+-GPRS-DETACH-INDICATION",
    [0x10] = "BSSAP+-GPRS-DETACH-ACK",
    [0x11] = "BSSAP+-IMSI-DETACH-INDICATION",
    [0x12] = "BSSAP+-IMSI-DETACH-ACK",
    [0x13] = "BSSAP+-RESET-INDICATION",
    [0x14] = "BSSAP+-RESET-ACK",
    [0x19] = "BSSAP+-PAGING-CANCEL"
}

function gprs_gs_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 1 then return end

    pinfo.cols.protocol = "GPRS Gs (BSSAP+)"

    local msg_type = tvb(0, 1):uint()
    local msg_name = GS_MSG_TYPES[msg_type] or string.format("BSSAP+ Msg (0x%02X)", msg_type)

    local subtree = tree:add(gprs_gs_proto, tvb(), string.format("GPRS Gs (BSSAP+): %s", msg_name))
    subtree:add(f_msg_type, tvb(0, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[Gs BSSAP+] %s", msg_name)

    -- Security Heuristic 1: Paging Cancel Injection
    if msg_type == 0x19 then
        subtree:add(f_sec_alert, "[WARNING] BSSAP+ Paging Cancel received. Aborts circuit-switched incoming call paging over GPRS.")
        pinfo.cols.info:append(" [TELCOSEC: PAGING CANCEL]")
    end

    -- Security Heuristic 2: RESET Indication (SGSN-VLR association wipe)
    if msg_type == 0x13 then
        subtree:add(f_sec_alert, "[CRITICAL] BSSAP+ Reset Indication. Flushes all combined MM associations between SGSN and VLR.")
    end

    if tvb:len() > 1 then
        subtree:add(f_payload, tvb(1, tvb:len() - 1))
    end
end

-- Register as postdissector to inspect BSSAP+ over SS7 / M3UA / SCCP
register_postdissector(gprs_gs_proto)
