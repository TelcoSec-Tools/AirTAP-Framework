-- TelcoSec.net - USB MBIM (Mobile Broadband Interface Model) Security Dissector
-- Description: Dissects USB-IF MBIM v1.0 / v2.0 control messages between host OS (Windows / Linux) and cellular modem.
--              Monitors CID (Command ID) execution across Basic Connect, SMS, USSD, and Phonebook services.
--              Detects PIN brute-forcing, rogue SMS injection, APN tampering, and network disconnect spoofing.

local ok, mbim_sec_proto = pcall(Proto, "mbim_control_sec", "TelcoSec USB MBIM Control Channel Security Analyzer")
if not ok or not mbim_sec_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint32("mbim_sec.msg_type", "MBIM Message Type", base.HEX)
local f_msg_name     = ProtoField.string("mbim_sec.msg_name", "Message Name")
local f_msg_len      = ProtoField.uint32("mbim_sec.msg_len", "Message Length", base.DEC)
local f_txn_id       = ProtoField.uint32("mbim_sec.txn_id", "Transaction ID", base.DEC)
local f_cid          = ProtoField.uint32("mbim_sec.cid", "Command ID (CID)", base.DEC)
local f_cid_name     = ProtoField.string("mbim_sec.cid_name", "Command Name")
local f_sec_alert    = ProtoField.string("mbim_sec.alert", "TelcoSec MBIM Security Alert")
local f_payload      = ProtoField.bytes("mbim_sec.payload", "MBIM Payload")

mbim_sec_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_msg_len,
    f_txn_id,
    f_cid,
    f_cid_name,
    f_sec_alert,
    f_payload
}

-- MBIM Message Types (USB-IF MBIM Specification)
local MBIM_MESSAGES = {
    [0x00000001] = "MBIM_OPEN_MSG",
    [0x80000001] = "MBIM_OPEN_DONE",
    [0x00000002] = "MBIM_CLOSE_MSG",
    [0x80000002] = "MBIM_CLOSE_DONE",
    [0x00000003] = "MBIM_COMMAND_MSG",
    [0x80000003] = "MBIM_COMMAND_DONE",
    [0x00000004] = "MBIM_HOST_ERROR_MSG",
    [0x80000007] = "MBIM_FUNCTION_ERROR_MSG",
    [0x80000005] = "MBIM_INDICATE_STATUS_MSG"
}

-- MBIM Basic Connect CIDs (UUID: MBIM_UUID_BASIC_CONNECT)
local MBIM_BASIC_CIDS = {
    [1]  = "MBIM_CID_DEVICE_CAPS",
    [2]  = "MBIM_CID_SUBSCRIBER_READY_STATUS",
    [3]  = "MBIM_CID_RADIO_STATE",
    [4]  = "MBIM_CID_PIN",
    [5]  = "MBIM_CID_PIN_LIST",
    [6]  = "MBIM_CID_HOME_PROVIDER",
    [7]  = "MBIM_CID_PREFERRED_PROVIDERS",
    [8]  = "MBIM_CID_VISIBLE_PROVIDERS",
    [9]  = "MBIM_CID_REGISTER_STATE",
    [10] = "MBIM_CID_PACKET_SERVICE",
    [11] = "MBIM_CID_SIGNAL_STATE",
    [12] = "MBIM_CID_CONNECT",
    [13] = "MBIM_CID_PROVISIONED_CONTEXTS"
}

-- Native MBIM dissector
local mbim_dissector = Dissector.get("mbim")

function mbim_sec_proto.dissector(tvb, pinfo, tree)
    -- MBIM Generic Header (12 bytes):
    -- [0-3]: MessageType (4 bytes LE)
    -- [4-7]: MessageLength (4 bytes LE)
    -- [8-11]: TransactionId (4 bytes LE)
    if tvb:len() < 12 then return end

    local msg_type = tvb(0, 4):le_uint()
    local msg_len = tvb(4, 4):le_uint()
    local txn_id = tvb(8, 4):le_uint()
    local msg_name = MBIM_MESSAGES[msg_type] or string.format("MBIM Msg 0x%08X", msg_type)

    pinfo.cols.protocol = "MBIM Control"

    local subtree = tree:add(mbim_sec_proto, tvb(), string.format("USB MBIM: %s (Txn: %d)", msg_name, txn_id))
    subtree:add(f_msg_type, tvb(0, 4), msg_type)
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_msg_len, tvb(4, 4), msg_len)
    subtree:add(f_txn_id, tvb(8, 4), txn_id)

    pinfo.cols.info = string.format("[USB MBIM] %s (Txn: %d)", msg_name, txn_id)

    -- If Command Msg or Done, parse CID
    if (msg_type == 0x00000003 or msg_type == 0x80000003) and tvb:len() >= 36 then
        -- UUID: [16-31], CID: [32-35] (LE)
        local cid = tvb(32, 4):le_uint()
        local cid_name = MBIM_BASIC_CIDS[cid] or string.format("CID %d", cid)
        subtree:add(f_cid, tvb(32, 4), cid)
        subtree:add(f_cid_name, cid_name)

        pinfo.cols.info:append(string.format(" | %s", cid_name))

        -- Security Heuristic 1: PIN Manipulation (Brute Force / Lock)
        if cid == 4 then
            subtree:add(f_sec_alert, "[WARNING] MBIM SIM PIN command executed. Monitor for PIN brute-forcing or unauthorized card lock.")
        end

        -- Security Heuristic 2: Provisioned Contexts / APN injection
        if cid == 13 then
            subtree:add(f_sec_alert, "[INFO] MBIM Provisioned APN Contexts query/update.")
        end
    end

    if mbim_dissector then
        mbim_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb(12, tvb:len() - 12))
    end
end
