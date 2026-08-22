-- TelcoSec.net - Qualcomm DIAG Root Framing & Log Demuxer Dissector
-- Description: Dissects raw Qualcomm Diagnostic (DIAG/DM) protocol frames, validates HDLC framing,
--              extracts Log Items (0x10 / 0x80), decodes 64-bit CDMA/GPS timestamps, and demultiplexes
--              to sub-dissectors registered in the "qc_diag.log_code" dissector table.

local ok, qc_diag_proto = pcall(Proto, "qc_diag", "Qualcomm Diagnostic (DIAG) Protocol")
if not ok or not qc_diag_proto then return end

-- Protocol fields
local f_cmd_code     = ProtoField.uint8("qc_diag.cmd_code", "Command Code", base.HEX)
local f_subsys_id    = ProtoField.uint8("qc_diag.subsys_id", "Subsystem ID", base.HEX)
local f_subsys_cmd   = ProtoField.uint16("qc_diag.subsys_cmd", "Subsystem Command Code", base.HEX)
local f_log_code     = ProtoField.uint16("qc_diag.log_code", "Log Item Code", base.HEX)
local f_log_len      = ProtoField.uint16("qc_diag.log_len", "Log Packet Length", base.DEC)
local f_timestamp    = ProtoField.string("qc_diag.timestamp", "Qualcomm Timestamp (CDMA/GPS 64-bit)")
local f_log_version  = ProtoField.uint8("qc_diag.log_version", "Log Header Version", base.DEC)
local f_crc          = ProtoField.uint16("qc_diag.crc", "CRC-16", base.HEX)
local f_payload      = ProtoField.bytes("qc_diag.payload", "Log Payload Data")

qc_diag_proto.fields = {
    f_cmd_code,
    f_subsys_id,
    f_subsys_cmd,
    f_log_code,
    f_log_len,
    f_timestamp,
    f_log_version,
    f_crc,
    f_payload
}

-- Sub-dissector table for Log Codes (e.g., 0xB821 for 5G NR RRC, 0xB0C0 for LTE RRC, 0x512F for GSM RR)
local log_code_table = DissectorTable.new("qc_diag.log_code", "Qualcomm DIAG Log Code", ftypes.UINT16, base.HEX)

-- Qualcomm Command Code Constants
local CMD_LOG_ITEM          = 0x10
local CMD_SUBSYS_DISPATCH   = 0x75
local CMD_EXT_LOG_ITEM      = 0x80

-- Mapping known Subsystem IDs
local SUBSYS_NAMES = {
    [0]  = "OEM",
    [1]  = "ZRF",
    [2]  = "SD",
    [3]  = "BT",
    [4]  = "WCDMA",
    [5]  = "NAS",
    [6]  = "DCM",
    [7]  = "DATA",
    [8]  = "FTM (Factory Test Mode)",
    [9]  = "GSM",
    [10] = "GPS / GNSS",
    [11] = "1X (CDMA2000)",
    [12] = "HDR (EVDO)",
    [13] = "LTE",
    [14] = "QDSP",
    [15] = "QCHAT",
    [68] = "NR5G (5G New Radio)"
}

-- Helper function to decode Qualcomm 64-bit CDMA/GPS timestamp
local function decode_qc_timestamp(tvb_ts)
    if tvb_ts:len() < 8 then return "Invalid TS" end
    -- Timestamp: lower 48-bits count 1.25ms / 3 (32.5520833 us) units since 1980-01-06 00:00:00 UTC
    local raw_low  = tvb_ts(0, 4):le_uint()
    local raw_high = tvb_ts(4, 4):le_uint()
    
    -- Fast approximate epoch conversion: GPS Epoch = 315964800 (1980-01-06)
    local total_seconds = math.floor((raw_high * 4294967296 + raw_low) * 0.0000325520833) + 315964800
    if total_seconds > 315964800 and total_seconds < 2500000000 then
        local formatted = os.date("!%Y-%m-%d %H:%M:%S UTC", total_seconds)
        return string.format("%s (0x%08X%08X)", formatted, raw_high, raw_low)
    else
        return string.format("0x%08X%08X (QC 64-bit TS)", raw_high, raw_low)
    end
end

local QC_LOG_PROTO_NAMES = {
    [0xB821] = "QC 5G RRC",
    [0xB801] = "QC 5G L2",
    [0xB887] = "QC 5G ML1",
    [0xB0C0] = "QC LTE RRC",
    [0xB0E0] = "QC LTE NAS",
    [0xB063] = "QC LTE MAC",
    [0xB064] = "QC LTE RLC",
    [0xB193] = "QC LTE ML1",
    [0x512F] = "QC GSM L3",
    [0x5134] = "QC GSM RR",
    [0x5115] = "QC GSM CellInfo",
    [0x4125] = "QC WCDMA RRC",
    [0x5201] = "QC GPRS RLC",
    [0x1801] = "QC GNSS/GPS",
    [0x1000] = "QC Baseband"
}

function qc_diag_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 4 then return end

    pinfo.cols.protocol = "QC DIAG"

    local cmd_code = tvb(0, 1):uint()
    local subtree = tree:add(qc_diag_proto, tvb(), "Qualcomm DIAG Protocol")
    subtree:add(f_cmd_code, tvb(0, 1))

    if cmd_code == CMD_LOG_ITEM then
        -- Standard Log Item Format:
        if tvb:len() < 14 then return end

        local log_len = tvb(2, 2):le_uint()
        local log_code = tvb(4, 2):le_uint()
        local ts_str = decode_qc_timestamp(tvb(6, 8))

        pinfo.cols.protocol = QC_LOG_PROTO_NAMES[log_code] or string.format("QC Log 0x%04X", log_code)

        subtree:add_le(f_log_len, tvb(2, 2))
        local item_code = subtree:add_le(f_log_code, tvb(4, 2))
        subtree:add(f_timestamp, tvb(6, 8), ts_str)

        pinfo.cols.info = string.format("QC Log Item: 0x%04X (Len: %d)", log_code, log_len)

        local payload_offset = 14
        local payload_len = tvb:len() - payload_offset

        -- Strip CRC if present at end
        if payload_len >= 2 and tvb:len() >= (log_len + 4) then
            subtree:add_le(f_crc, tvb(tvb:len() - 2, 2))
            payload_len = payload_len - 2
        end

        if payload_len > 0 then
            local payload_tvb = tvb(payload_offset, payload_len):tvb()
            local subdissector = log_code_table:get_dissector(log_code)
            local ok = false
            if subdissector then
                ok = pcall(function()
                    subdissector:call(payload_tvb, pinfo, tree)
                end)
            end
            if not ok then
                subtree:add(f_payload, tvb(payload_offset, payload_len))
            end
        end

    elseif cmd_code == CMD_EXT_LOG_ITEM then
        -- Extended Log Item Format:
        if tvb:len() < 14 then return end

        local version = tvb(1, 1):uint()
        local log_len = tvb(2, 2):le_uint()
        local log_code = tvb(4, 2):le_uint()
        local ts_str = decode_qc_timestamp(tvb(6, 8))

        pinfo.cols.protocol = QC_LOG_PROTO_NAMES[log_code] or string.format("QC Log 0x%04X", log_code)

        subtree:add(f_log_version, tvb(1, 1))
        subtree:add_le(f_log_len, tvb(2, 2))
        subtree:add_le(f_log_code, tvb(4, 2))
        subtree:add(f_timestamp, tvb(6, 8), ts_str)

        pinfo.cols.info = string.format("QC Ext Log: 0x%04X (Ver: %d, Len: %d)", log_code, version, log_len)

        local payload_offset = 14
        local payload_len = tvb:len() - payload_offset
        if payload_len > 0 then
            local payload_tvb = tvb(payload_offset, payload_len):tvb()
            local subdissector = log_code_table:get_dissector(log_code)
            local ok = false
            if subdissector then
                ok = pcall(function()
                    subdissector:call(payload_tvb, pinfo, tree)
                end)
            end
            if not ok then
                subtree:add(f_payload, tvb(payload_offset, payload_len))
            end
        end

    elseif cmd_code == CMD_SUBSYS_DISPATCH then
        -- Subsystem Dispatch Format:
        -- [0]: Cmd Code (0x75)
        -- [1]: Subsystem ID (1 byte)
        -- [2-3]: Subsystem Command Code (2 bytes, LE)
        if tvb:len() < 4 then return end

        local subsys_id = tvb(1, 1):uint()
        local subsys_cmd = tvb(2, 2):le_uint()
        local subsys_name = SUBSYS_NAMES[subsys_id] or "Unknown Subsystem"

        subtree:add(f_subsys_id, tvb(1, 1)):append_text(string.format(" (%s)", subsys_name))
        subtree:add_le(f_subsys_cmd, tvb(2, 2))

        pinfo.cols.info = string.format("QC Subsys Dispatch: %s (Cmd: 0x%04X)", subsys_name, subsys_cmd)

        if tvb:len() > 4 then
            subtree:add(f_payload, tvb(4, tvb:len() - 4))
        end
    else
        pinfo.cols.info = string.format("QC DIAG Cmd: 0x%02X", cmd_code)
        if tvb:len() > 1 then
            subtree:add(f_payload, tvb(1, tvb:len() - 1))
        end
    end
end

-- Register dissector to UDP port 2500 (standard DIAG over UDP) and GSMTAP port 4729
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(2500, qc_diag_proto)
end

-- Register to DLT User table (DLT 147-162 / USER0-USER15)
local wtap_encap_table = DissectorTable.get("wtap_encap")
if wtap_encap_table and wtap_encaps then
    if wtap_encaps["USER0"] then pcall(function() wtap_encap_table:add(wtap_encaps["USER0"], qc_diag_proto) end) end
    if wtap_encaps["USER15"] then pcall(function() wtap_encap_table:add(wtap_encaps["USER15"], qc_diag_proto) end) end
end
