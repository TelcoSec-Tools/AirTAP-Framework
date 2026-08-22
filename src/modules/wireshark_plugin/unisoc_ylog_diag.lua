-- TelcoSec.net - Unisoc (Spreadtrum) YLog / ArmLog Baseband Diagnostic Dissector
-- Description: Dissects Unisoc / Spreadtrum CP ArmLog and YLog diagnostic packets.
--              Triahes 2G/3G/4G/5G baseband modem crashes, memory faults, and unauthenticated OTA frames.

local ok, unisoc_diag_proto = pcall(Proto, "unisoc_ylog_diag", "Unisoc (Spreadtrum) YLog Diagnostic Protocol Analyzer")
if not ok or not unisoc_diag_proto then return end

-- Protocol fields
local f_sync         = ProtoField.uint8("unisoc_diag.sync", "Sync Byte (0x7E)", base.HEX)
local f_channel      = ProtoField.uint8("unisoc_diag.channel", "Log Channel", base.HEX)
local f_chan_name    = ProtoField.string("unisoc_diag.chan_name", "Channel Name")
local f_type         = ProtoField.uint16("unisoc_diag.type", "Msg Type", base.HEX)
local f_length       = ProtoField.uint16("unisoc_diag.length", "Length", base.DEC)
local f_sec_alert    = ProtoField.string("unisoc_diag.alert", "TelcoSec Unisoc Alert")
local f_payload      = ProtoField.bytes("unisoc_diag.payload", "Raw Trace Bytes")

unisoc_diag_proto.fields = {
    f_sync,
    f_channel,
    f_chan_name,
    f_type,
    f_length,
    f_sec_alert,
    f_payload
}

-- Unisoc Diagnostic Channels
local UNISOC_CHANNELS = {
    [0x00] = "CHAN_CONTROL",
    [0x01] = "CHAN_PS_LOG (Protocol Stack / RRC / NAS)",
    [0x02] = "CHAN_DSP_LOG (Phy Layer / DSP)",
    [0x03] = "CHAN_ARM_LOG (Baseband OS & Task Dump)",
    [0x04] = "CHAN_ASSERT (Baseband Panic Dump)",
    [0x05] = "CHAN_AT_LOG (AT Command Log)"
}

function unisoc_diag_proto.dissector(tvb, pinfo, tree)
    -- Unisoc YLog Header (6 bytes):
    -- [0]: Sync Byte (0x7E)
    -- [1]: Channel ID
    -- [2-3]: Msg Type (2 bytes LE)
    -- [4-5]: Length (2 bytes LE)
    if tvb:len() < 6 then return end

    local sync = tvb(0, 1):uint()
    if sync ~= 0x7E then return end

    pinfo.cols.protocol = "UNISOC YLog"

    local chan_id = tvb(1, 1):uint()
    local msg_type = tvb(2, 2):le_uint()
    local length = tvb(4, 2):le_uint()
    local chan_name = UNISOC_CHANNELS[chan_id] or string.format("Channel 0x%02X", chan_id)

    local subtree = tree:add(unisoc_diag_proto, tvb(), string.format("Unisoc Modem: %s", chan_name))
    subtree:add(f_sync, tvb(0, 1))
    subtree:add(f_channel, tvb(1, 1), chan_id)
    subtree:add(f_chan_name, chan_name)
    subtree:add(f_type, tvb(2, 2), msg_type)
    subtree:add(f_length, tvb(4, 2), length)

    pinfo.cols.info = string.format("[Unisoc CP] %s (Type: 0x%04X, Len: %d)", chan_name, msg_type, length)

    -- Security Heuristic: Baseband Panic Dump (CHAN_ASSERT)
    if chan_id == 0x04 then
        subtree:add(f_sec_alert, "[CRITICAL] Unisoc Baseband Panic / Assertion! Modem crashed due to OTA memory fault or invalid state transition.")
        pinfo.cols.info:append(" [TELCOSEC: UNISOC BASEBAND PANIC!]")
    end

    if tvb:len() > 6 then
        subtree:add(f_payload, tvb(6, tvb:len() - 6))
    end
end

-- Register to UDP port 5003 (Unisoc YLog stream port)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(5003, unisoc_diag_proto)
end
