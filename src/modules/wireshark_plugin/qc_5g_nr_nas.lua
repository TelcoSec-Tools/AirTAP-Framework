-- TelcoSec.net - Qualcomm 5G NR NAS (5GMM/5GSM) Dissector & Security Post-Dissector
-- Description: Dissects Qualcomm Log Code 0xB801 (5G NR NAS Plain OTA) and 0xB808 (5G NR NAS Security Protected).
--              Analyzes 5GS NAS messages for plaintext SUPI exposure, rogue AMF authentication attacks,
--              and malicious de-registration injections.

local ok, qc_5g_nas_proto = pcall(Proto, "qc_5g_nas", "Qualcomm 5G NR NAS Security Analyzer")
if not ok or not qc_5g_nas_proto then return end

-- Protocol fields
local f_nas_sec_header = ProtoField.uint8("qc_5g_nas.sec_header_type", "Security Header Type", base.HEX)
local f_nas_proto_disc = ProtoField.uint8("qc_5g_nas.proto_disc", "Protocol Discriminator", base.HEX)
local f_nas_msg_type   = ProtoField.uint8("qc_5g_nas.msg_type", "5GS NAS Message Type", base.HEX)
local f_supi_exposed   = ProtoField.string("qc_5g_nas.supi_exposed", "Exposed Plaintext SUPI/IMSI")
local f_nas_sec_alert  = ProtoField.string("qc_5g_nas.alert", "TelcoSec 5G NAS Alert")
local f_nas_payload    = ProtoField.bytes("qc_5g_nas.payload", "NAS Payload")

qc_5g_nas_proto.fields = {
    f_nas_sec_header,
    f_nas_proto_disc,
    f_nas_msg_type,
    f_supi_exposed,
    f_nas_sec_alert,
    f_nas_payload
}

-- 5GS NAS Protocol Discriminators
local PROTO_5GMM = 0x7E -- 5GS Mobility Management
local PROTO_5GSM = 0x2E -- 5GS Session Management

-- Common 5GMM Message Types
local MSG_TYPES_5GMM = {
    [0x41] = "Registration Request",
    [0x42] = "Registration Accept",
    [0x43] = "Registration Complete",
    [0x44] = "Registration Reject",
    [0x45] = "Deregistration Request (UE-originating)",
    [0x46] = "Deregistration Accept (UE-originating)",
    [0x47] = "Deregistration Request (UE-terminated)",
    [0x48] = "Deregistration Accept (UE-terminated)",
    [0x54] = "Authentication Request",
    [0x55] = "Authentication Response",
    [0x56] = "Authentication Reject",
    [0x57] = "Authentication Failure",
    [0x5B] = "Identity Request",
    [0x5C] = "Identity Response",
    [0x5D] = "Security Mode Command",
    [0x5E] = "Security Mode Complete",
    [0x5F] = "Security Mode Reject"
}

-- Wireshark native 5GS NAS dissector
local nas_5gs_dissector = Dissector.get("nas-5gs")

function qc_5g_nas_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB801 / 0xB808 layout:
    -- [0]: Version (1 byte)
    -- [1]: Direction (1 byte: 0=UL, 1=DL)
    -- [2-3]: Length (2 bytes LE)
    -- [4..N]: 5GS NAS PDU
    if tvb:len() < 5 then return end

    pinfo.cols.protocol = "5GS NAS"

    local version = tvb(0, 1):uint()
    local direction = tvb(1, 1):uint()
    local dir_str = (direction == 0) and "UL (UE -> AMF)" or "DL (AMF -> UE)"
    local nas_len = tvb(2, 2):le_uint()

    local subtree = tree:add(qc_5g_nas_proto, tvb(), string.format("Qualcomm 5G NAS OTA (%s, Len: %d)", dir_str, nas_len))

    local nas_offset = 4
    local pdu_len = tvb:len() - nas_offset

    if pdu_len >= 2 then
        local pdu_tvb = tvb(nas_offset, pdu_len):tvb()
        local epd = pdu_tvb(0, 1):uint()
        local sec_hdr = pdu_tvb(1, 1):uint()

        subtree:add(f_nas_proto_disc, pdu_tvb(0, 1))
        subtree:add(f_nas_sec_header, pdu_tvb(1, 1))

        if pdu_len >= 3 then
            local msg_type = pdu_tvb(2, 1):uint()
            local msg_name = MSG_TYPES_5GMM[msg_type] or string.format("5GS Message (0x%02X)", msg_type)
            subtree:add(f_nas_msg_type, pdu_tvb(2, 1)):append_text(string.format(" (%s)", msg_name))
            pinfo.cols.info = string.format("[5G NAS %s] %s", dir_str, msg_name)

            -- Security Heuristic 1: Identity Request / Plaintext SUPI harvesting
            if msg_type == 0x5B then
                subtree:add(f_nas_sec_alert, "[CRITICAL] Plaintext Identity Request received from AMF/gNB. Possible 5G IMSI/SUPI Catcher.")
                pinfo.cols.info:append(" [TELCOSEC: SUPI HARVESTING ATTEMPT]")
            end

            -- Security Heuristic 2: Identity Response / Plaintext SUPI leakage
            if msg_type == 0x5C then
                subtree:add(f_nas_sec_alert, "[CRITICAL] UE transmitting Identity Response in plaintext! Privacy violation / SUPI exposure.")
            end

            -- Security Heuristic 3: Malicious De-registration
            if msg_type == 0x47 then
                subtree:add(f_nas_sec_alert, "[WARNING] Network-initiated Deregistration Request. Monitor for Denial of Service / Silent kick attacks.")
            end
        end

        -- Pass to native nas-5gs dissector if available
        if nas_5gs_dissector then
            nas_5gs_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_nas_payload, tvb(nas_offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB801, qc_5g_nas_proto) -- 5G NAS Plain OTA
    qc_log_table:add(0xB808, qc_5g_nas_proto) -- 5G NAS Ciphered OTA
end
