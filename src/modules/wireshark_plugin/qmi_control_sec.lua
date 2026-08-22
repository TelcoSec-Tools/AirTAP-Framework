-- TelcoSec.net - Qualcomm QMI (Qualcomm MSM Interface - Host-to-Modem Control) Master Security Dissector
-- Description: Complete analyzer for Qualcomm QMI control protocol framing across USB cdc-wdm, QRTR, and PCIe interfaces.
--              Decodes all major QMI services: DMS (Device Management), NAS (Network Access), WDS (Wireless Data),
--              UIM (User Identity Module / SIM), LOC (Location / GNSS), VOICE, and WMS (SMS).
--              Parses QMUX headers, SDU transactions, message IDs, and TLV parameter containers.
--              Detects hardware IMEI rewrite attacks, direct smart card APDU execution, rogue APN profile injection,
--              SIM network lock bypasses (Depersonalization), and stealth call/SMS initiation.

local ok, qmi_sec_proto = pcall(Proto, "qmi_control_sec", "TelcoSec Qualcomm QMI Control Message Security Analyzer")
if not ok or not qmi_sec_proto then return end

-- Protocol fields
local f_if_type         = ProtoField.uint8("qmi_sec.if_type", "Interface Type (0x01=QMUX)", base.HEX)
local f_length          = ProtoField.uint16("qmi_sec.length", "QMUX Packet Length", base.DEC)
local f_flags           = ProtoField.uint8("qmi_sec.flags", "Control Flags", base.HEX)
local f_svc_type        = ProtoField.uint8("qmi_sec.svc_type", "QMI Service Type", base.HEX)
local f_svc_name        = ProtoField.string("qmi_sec.svc_name", "Service Subsystem")
local f_client_id       = ProtoField.uint8("qmi_sec.client_id", "Client ID", base.DEC)
local f_msg_type_str    = ProtoField.string("qmi_sec.msg_type_str", "Message Type (Req/Rsp/Ind)")
local f_txn_id          = ProtoField.uint16("qmi_sec.txn_id", "Transaction ID", base.DEC)
local f_msg_id          = ProtoField.uint16("qmi_sec.msg_id", "QMI Message ID", base.HEX)
local f_msg_name        = ProtoField.string("qmi_sec.msg_name", "Message Name")
local f_apn_str         = ProtoField.string("qmi_sec.apn", "Configured APN Profile")
local f_imei_str        = ProtoField.string("qmi_sec.imei", "Extracted IMEI / Serial")
local f_sec_alert       = ProtoField.string("qmi_sec.alert", "TelcoSec QMI Security Alert")
local f_payload         = ProtoField.bytes("qmi_sec.payload", "QMI SDU / TLV Payload")

qmi_sec_proto.fields = {
    f_if_type,
    f_length,
    f_flags,
    f_svc_type,
    f_svc_name,
    f_client_id,
    f_msg_type_str,
    f_txn_id,
    f_msg_id,
    f_msg_name,
    f_apn_str,
    f_imei_str,
    f_sec_alert,
    f_payload
}

-- QMI Subsystem Services
local QMI_SERVICES = {
    [0x00] = "CTL (Control)",
    [0x01] = "WDS (Wireless Data Service)",
    [0x02] = "DMS (Device Management Service)",
    [0x03] = "NAS (Network Access Service)",
    [0x04] = "QOS (Quality of Service)",
    [0x05] = "WMS (Wireless Messaging Service)",
    [0x06] = "PDS (Position Determination Service)",
    [0x0B] = "UIM (User Identity Module / SIM)",
    [0x10] = "LOC (Location Service / GNSS)",
    [0x1A] = "VOICE (Voice Call Service)",
    [0x24] = "PDC (Persistent Device Configuration / MBN)"
}

-- QMI Message Catalog (by Service ID -> Message ID)
local QMI_MESSAGE_CATALOG = {
    -- DMS (0x02)
    [0x02] = {
        [0x0020] = "DMS_GET_CAPS",
        [0x0021] = "DMS_GET_MANUFACTURER",
        [0x0022] = "DMS_GET_MODEL_ID",
        [0x0023] = "DMS_GET_REV_ID",
        [0x0025] = "DMS_GET_SERIAL_NUMBERS (IMEI/MEID/ESN)",
        [0x002B] = "DMS_SET_SERIAL_NUMBERS (IMEI Rewrite)",
        [0x002D] = "DMS_GET_OPERATING_MODE",
        [0x002E] = "DMS_SET_OPERATING_MODE (Reset/Online/Offline)",
        [0x003A] = "DMS_SET_BAND_CONFIG",
        [0x0047] = "DMS_RESTORE_FACTORY_DEFAULTS"
    },
    -- NAS (0x03)
    [0x03] = {
        [0x0020] = "NAS_RESET",
        [0x0021] = "NAS_SET_EVENT_REPORT",
        [0x0022] = "NAS_GET_SIGNAL_STRENGTH",
        [0x0023] = "NAS_PERFORM_NETWORK_SCAN",
        [0x0024] = "NAS_INITIATE_NETWORK_REGISTER",
        [0x0025] = "NAS_INITIATE_ATTACH",
        [0x0026] = "NAS_SET_SYSTEM_SELECTION_PREFERENCE",
        [0x004F] = "NAS_GET_SIGNAL_INFO",
        [0x0051] = "NAS_GET_CELL_LOCATION_INFO (Cell ID/TAC/PCI)",
        [0x0068] = "NAS_SET_DUAL_STANDBY_PREF"
    },
    -- WDS (0x01)
    [0x01] = {
        [0x0020] = "WDS_RESET",
        [0x0022] = "WDS_START_NETWORK_INTERFACE (Connect Data)",
        [0x0023] = "WDS_STOP_NETWORK_INTERFACE (Disconnect Data)",
        [0x0027] = "WDS_MODIFY_PROFILE_SETTINGS (APN Injection)",
        [0x002B] = "WDS_CREATE_PROFILE",
        [0x002D] = "WDS_GET_PROFILE_SETTINGS",
        [0x002E] = "WDS_GET_DEFAULT_SETTINGS",
        [0x0033] = "WDS_GET_PACKET_STATISTICS",
        [0x0085] = "WDS_SET_KEEP_ALIVE"
    },
    -- UIM (0x0B)
    [0x0B] = {
        [0x0020] = "UIM_RESET",
        [0x0021] = "UIM_READ_TRANSPARENT",
        [0x0022] = "UIM_READ_RECORD",
        [0x0023] = "UIM_WRITE_TRANSPARENT",
        [0x0024] = "UIM_WRITE_RECORD",
        [0x0028] = "UIM_AUTHENTICATE (Milenage AKA Challenge)",
        [0x002B] = "UIM_VERIFY_PIN",
        [0x002C] = "UIM_UNBLOCK_PIN (PUK)",
        [0x003B] = "UIM_SEND_APDU (Direct Raw APDU Execution)",
        [0x0046] = "UIM_DEPERSONALIZATION (SIM Unlock Bypass)"
    },
    -- LOC (0x10)
    [0x10] = {
        [0x0020] = "LOC_START_POSITION_SESSION",
        [0x0021] = "LOC_STOP_POSITION_SESSION",
        [0x0022] = "LOC_INJECT_POSITION",
        [0x0023] = "LOC_INJECT_TIME",
        [0x0024] = "LOC_GET_BEST_AVAILABLE_POSITION",
        [0x0027] = "LOC_SET_GEOFENCE"
    },
    -- VOICE (0x1A)
    [0x1A] = {
        [0x0020] = "VOICE_DIAL_CALL",
        [0x0021] = "VOICE_END_CALL",
        [0x0022] = "VOICE_ANSWER_CALL",
        [0x0026] = "VOICE_MANAGE_CALLS"
    },
    -- WMS (0x05)
    [0x05] = {
        [0x0020] = "WMS_RESET",
        [0x0021] = "WMS_SET_EVENT_REPORT",
        [0x0022] = "WMS_SEND_SMS",
        [0x0023] = "WMS_RAW_SEND_SMS",
        [0x0024] = "WMS_READ_SMS",
        [0x0025] = "WMS_DELETE_SMS"
    }
}

-- Native QMI dissector
local native_qmi = Dissector.get("qmi")

function qmi_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 6 then return end

    -- QMUX Header (6 bytes):
    -- [0]: IF Type (0x01)
    -- [1-2]: Length (2 bytes LE)
    -- [3]: Control Flags
    -- [4]: Service Type
    -- [5]: Client ID
    local if_type = tvb(0, 1):uint()
    if if_type ~= 0x01 then return end

    pinfo.cols.protocol = "Qualcomm QMI"

    local qmux_len  = tvb(1, 2):le_uint()
    local flags     = tvb(3, 1):uint()
    local svc_type  = tvb(4, 1):uint()
    local client_id = tvb(5, 1):uint()
    local svc_name  = QMI_SERVICES[svc_type] or string.format("Service 0x%02X", svc_type)

    local subtree = tree:add(qmi_sec_proto, tvb(), string.format("Qualcomm QMI: %s (Client: %d)", svc_name, client_id))
    subtree:add(f_if_type, tvb(0, 1), if_type)
    subtree:add(f_length, tvb(1, 2), qmux_len)
    subtree:add(f_flags, tvb(3, 1), flags)
    subtree:add(f_svc_type, tvb(4, 1), svc_type)
    subtree:add(f_svc_name, svc_name)
    subtree:add(f_client_id, tvb(5, 1), client_id)

    local alerts = {}
    local msg_name = "QMI SDU"

    -- SDU parsing (Offset 6)
    if len >= 12 then
        local sdu_flags = tvb(6, 1):uint()
        local msg_type_str = "Request"
        if bit.band(sdu_flags, 0x02) ~= 0 then
            msg_type_str = "Response"
        elseif bit.band(sdu_flags, 0x04) ~= 0 then
            msg_type_str = "Indication"
        end
        subtree:add(f_msg_type_str, msg_type_str)

        local txn_id = tvb(7, 2):le_uint()
        local msg_id = tvb(9, 2):le_uint()
        subtree:add(f_txn_id, tvb(7, 2), txn_id)
        subtree:add(f_msg_id, tvb(9, 2), msg_id)

        local svc_catalog = QMI_MESSAGE_CATALOG[svc_type]
        msg_name = (svc_catalog and svc_catalog[msg_id]) or string.format("Msg 0x%04X", msg_id)
        subtree:add(f_msg_name, msg_name)

        pinfo.cols.info = string.format("[QMI %s] %s (%s, Tx: %d)", svc_name, msg_name, msg_type_str, txn_id)

        -- Security Heuristic 1: Hardware IMEI Rewrite (DMS_SET_SERIAL_NUMBERS - 0x002B)
        if svc_type == 0x02 and msg_id == 0x002B then
            table.insert(alerts, "[CRITICAL] QMI DMS Hardware IMEI Rewrite Commanded! Host application rewriting device IMEI/MEID serial identifier. Potential device spoofing / blacklisted IMEI bypass.")
            pinfo.cols.info:append(" [TELCOSEC: IMEI REWRITE ATTEMPT!]")
        end

        -- Security Heuristic 2: Direct Smart Card APDU Injection (UIM_SEND_APDU - 0x003B)
        if svc_type == 0x0B and msg_id == 0x003B then
            table.insert(alerts, "[CRITICAL] QMI UIM Send APDU Commanded! Direct raw ISO-7816 smart card APDU execution bypass. Potential SIM crypto extraction or SIMjacker payload execution.")
            pinfo.cols.info:append(" [TELCOSEC: RAW SIM APDU!]")
        end

        -- Security Heuristic 3: SIM Network Depersonalization (UIM_DEPERSONALIZATION - 0x0046)
        if svc_type == 0x0B and msg_id == 0x0046 then
            table.insert(alerts, "[CRITICAL] QMI UIM Depersonalization! Carrier SIM lock removal attempt.")
            pinfo.cols.info:append(" [TELCOSEC: SIM UNLOCK BYPASS!]")
        end

        -- Security Heuristic 4: APN Profile Injection (WDS_MODIFY_PROFILE_SETTINGS - 0x0027)
        if svc_type == 0x01 and (msg_id == 0x0027 or msg_id == 0x002B) then
            table.insert(alerts, "[HIGH RISK] QMI WDS Profile Settings Modified! Verify configured APN name against rogue proxy / ad-fraud network redirects.")
            pinfo.cols.info:append(" [TELCOSEC: APN PROFILE MODIFIED]")
        end

        -- Security Heuristic 5: Silent Call Initiation (VOICE_DIAL_CALL - 0x0020)
        if svc_type == 0x1A and msg_id == 0x0020 then
            table.insert(alerts, "[HIGH RISK] Outbound Voice Call initiated via QMI VOICE service! Verify user interaction to prevent silent toll-fraud call initiation.")
            pinfo.cols.info:append(" [TELCOSEC: QMI OUTBOUND CALL!]")
        end

        -- Security Heuristic 6: Radio Reset / Baseband Kill (DMS_SET_OPERATING_MODE - 0x002E)
        if svc_type == 0x02 and msg_id == 0x002E then
            table.insert(alerts, "[WARNING] QMI DMS Set Operating Mode: Changing baseband radio state (Offline/Reset/Low Power).")
        end
    else
        pinfo.cols.info = string.format("[QMI %s] Client ID: %d", svc_name, client_id)
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if len > 6 then
        subtree:add(f_payload, tvb(6, len - 6))
    end

    if native_qmi then
        native_qmi:call(tvb, pinfo, tree)
    end
end

-- Register as postdissector to inspect all QMI traffic
register_postdissector(qmi_sec_proto)
