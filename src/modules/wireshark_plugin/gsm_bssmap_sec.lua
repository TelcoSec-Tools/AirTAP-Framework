-- TelcoSec.net - GSM A-Interface BSSMAP / BSSAP Security Dissector
-- Description: Dissects GSM A-Interface BSSMAP (3GPP TS 48.008) signaling between BSC and MSC.
--              Analyzes Cipher Mode Commands, Handover Requests, and cleartext IMSI transfers across the core network.

local ok, gsm_bssmap_proto = pcall(Proto, "gsm_bssmap_sec", "TelcoSec GSM A-Interface BSSMAP Analyzer")
if not ok or not gsm_bssmap_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gsm_bssmap.msg_type", "BSSMAP Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gsm_bssmap.msg_name", "BSSMAP Message Name")
local f_cipher_info  = ProtoField.string("gsm_bssmap.cipher_info", "Permitted Encryption Algorithms")
local f_imsi         = ProtoField.string("gsm_bssmap.imsi", "Transferred IMSI")
local f_sec_alert    = ProtoField.string("gsm_bssmap.alert", "TelcoSec BSSMAP Security Alert")
local f_payload      = ProtoField.bytes("gsm_bssmap.payload", "BSSMAP Raw Payload")

gsm_bssmap_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_cipher_info,
    f_imsi,
    f_sec_alert,
    f_payload
}

-- BSSMAP Message Types (3GPP TS 48.008)
local BSSMAP_MSG_TYPES = {
    [0x01] = "Assignment Request",
    [0x02] = "Assignment Complete",
    [0x03] = "Assignment Failure",
    [0x10] = "Handover Request",
    [0x11] = "Handover Required",
    [0x12] = "Handover Request Acknowledge",
    [0x13] = "Handover Command",
    [0x14] = "Handover Complete",
    [0x15] = "Handover Failure",
    [0x20] = "Clear Command",
    [0x21] = "Clear Complete",
    [0x22] = "Clear Request",
    [0x52] = "Cipher Mode Command",
    [0x53] = "Cipher Mode Complete",
    [0x54] = "Cipher Mode Reject",
    [0x58] = "Paging",
    [0x60] = "Reset",
    [0x61] = "Reset Acknowledge"
}

-- Native Wireshark BSSMAP dissector
local gsm_bssmap_dissector = Dissector.get("gsm_a_bssmap")

function gsm_bssmap_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "GSM BSSMAP"

    local msg_type = tvb(0, 1):uint()
    local msg_name = BSSMAP_MSG_TYPES[msg_type] or string.format("BSSMAP Msg (0x%02X)", msg_type)

    local subtree = tree:add(gsm_bssmap_proto, tvb(), string.format("GSM BSSMAP: %s", msg_name))
    subtree:add(f_msg_type, tvb(0, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GSM BSSMAP] %s", msg_name)

    -- Security Heuristic 1: Cipher Mode Command with A5/0 (No Encryption)
    if msg_type == 0x52 and tvb:len() >= 3 then
        local hex_str = tostring(tvb:bytes():tohex())
        if string.find(hex_str, "0101") or string.find(hex_str, "0000") then
            subtree:add(f_cipher_info, "A5/0 Allowed / Plaintext")
            subtree:add(f_sec_alert, "[CRITICAL] MSC commanded A5/0 (No Encryption) on BSSMAP interface! Core network forcing plaintext over radio link.")
            pinfo.cols.info:append(" [TELCOSEC: A5/0 COMMAND ON A-INTERFACE]")
        end
    end

    -- Security Heuristic 2: Plaintext IMSI in Paging or Handover Request
    if (msg_type == 0x58 or msg_type == 0x10) and tvb:len() >= 10 then
        subtree:add(f_sec_alert, "[INFO] Subscriber Paging / Handover transaction between BSC and MSC.")
    end

    if gsm_bssmap_dissector then
        gsm_bssmap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
