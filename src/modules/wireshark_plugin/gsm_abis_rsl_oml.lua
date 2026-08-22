-- TelcoSec.net - GSM Abis Interface (RSL & OML) Base Station Backhaul Dissector
-- Description: Dissects GSM Abis interface between BTS and BSC (3GPP TS 48.058 RSL & TS 52.021 OML).
--              Analyzes base station backhaul commands, transmitter power override,
--              and unauthenticated BTS management injection.

local ok, gsm_abis_proto = pcall(Proto, "gsm_abis_rsl_oml", "TelcoSec GSM Abis (RSL/OML) Backhaul Analyzer")
if not ok or not gsm_abis_proto then return end

-- Protocol fields
local f_abis_type    = ProtoField.string("gsm_abis.type", "Abis Protocol Type")
local f_msg_disc     = ProtoField.uint8("gsm_abis.msg_disc", "Message Discriminator", base.HEX)
local f_msg_type     = ProtoField.uint8("gsm_abis.msg_type", "Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gsm_abis.msg_name", "Message Name")
local f_channel_nr   = ProtoField.uint8("gsm_abis.channel_nr", "Channel Number", base.HEX)
local f_tx_power     = ProtoField.uint8("gsm_abis.tx_power", "BTS Power Level (dBm)", base.DEC)
local f_sec_alert    = ProtoField.string("gsm_abis.alert", "TelcoSec Abis Security Alert")
local f_payload      = ProtoField.bytes("gsm_abis.payload", "Abis Payload")

gsm_abis_proto.fields = {
    f_abis_type,
    f_msg_disc,
    f_msg_type,
    f_msg_name,
    f_channel_nr,
    f_tx_power,
    f_sec_alert,
    f_payload
}

-- RSL Message Discriminators
local RSL_DISC_RADIO_LINK = 0x00
local RSL_DISC_DED_CHAN   = 0x08
local RSL_DISC_COM_CHAN   = 0x10
local RSL_DISC_TRX_MGMT   = 0x18
local RSL_DISC_LOC_MGMT   = 0x20

-- RSL Message Types
local RSL_MSG_TYPES = {
    [0x01] = "DATA REQ",
    [0x02] = "DATA IND",
    [0x04] = "ESTABLISH REQ",
    [0x05] = "ESTABLISH CONF",
    [0x06] = "ESTABLISH IND",
    [0x07] = "RELEASE REQ",
    [0x08] = "RELEASE CONF",
    [0x09] = "RELEASE IND",
    [0x0E] = "UNIT DATA REQ",
    [0x0F] = "UNIT DATA IND",
    [0x11] = "BCCH INFO",
    [0x12] = "CCCH LOAD IND",
    [0x13] = "CHAN RQD",
    [0x14] = "DELETE IND",
    [0x15] = "PAGING CMD",
    [0x16] = "IMMEDIATE ASSIGN CMD",
    [0x17] = "SMS BC REQ",
    [0x21] = "RF RESource IND",
    [0x22] = "SACCH FILLING",
    [0x23] = "OVERLOAD",
    [0x24] = "ERROR REPORT",
    [0x31] = "ENCRyption CMD",
    [0x32] = "HANDOVER DETection",
    [0x33] = "MEASurement RESult",
    [0x34] = "MODE RECORD",
    [0x35] = "RF CHANnel RELease",
    [0x36] = "MS POWER CONTROL",
    [0x37] = "BS POWER CONTROL"
}

-- Native Wireshark Abis dissectors
local rsl_dissector = Dissector.get("gsm_abis_rsl")
local oml_dissector = Dissector.get("gsm_abis_oml")

function gsm_abis_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "GSM Abis"

    local msg_disc = tvb(0, 1):uint()
    local msg_type = tvb(1, 1):uint()

    local is_oml = (msg_disc == 0x80 or msg_disc == 0x81)
    local abis_str = is_oml and "OML (BTS Management)" or "RSL (Radio Signalling)"
    local msg_name = (not is_oml and RSL_MSG_TYPES[msg_type]) or string.format("Msg 0x%02X", msg_type)

    local subtree = tree:add(gsm_abis_proto, tvb(), string.format("GSM Abis: %s | %s", abis_str, msg_name))
    subtree:add(f_abis_type, abis_str)
    subtree:add(f_msg_disc, tvb(0, 1))
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GSM Abis %s] %s", abis_str, msg_name)

    -- Security Heuristic 1: ENCRYPTION COMMAND over Abis (Extraction of A5 ciphering keys / Kc)
    if not is_oml and msg_type == 0x31 then
        subtree:add(f_sec_alert, "[CRITICAL] Encryption Command transmitted on Abis link. Verify Kc / encryption key confidentiality on backhaul.")
        pinfo.cols.info:append(" [TELCOSEC: ENCRYPTION COMMAND ON ABIS]")
    end

    -- Security Heuristic 2: BS POWER CONTROL (BTS Power Injection)
    if not is_oml and msg_type == 0x37 then
        subtree:add(f_sec_alert, "[WARNING] Base Station (BS) Power Control commanded. Potential transmission power manipulation.")
    end

    if is_oml and oml_dissector then
        oml_dissector:call(tvb, pinfo, tree)
    elseif not is_oml and rsl_dissector then
        rsl_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register Abis dissector to TCP port 3002 / 3003 (standard Osmocom/OpenBSC Abis over IP)
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(3002, gsm_abis_proto)
    tcp_table:add(3003, gsm_abis_proto)
end
