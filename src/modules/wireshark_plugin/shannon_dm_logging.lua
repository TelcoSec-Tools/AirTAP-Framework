-- TelcoSec.net - Samsung Shannon Diagnostic Monitor (DM) Root Dissector
-- Description: Dissects Shannon DM log containers, decodes Group IDs, Sub-Group IDs,
--              hardware timestamps, and dispatches to cellular protocol analyzers.

local ok, shannon_dm_proto = pcall(Proto, "shannon_dm", "Samsung Shannon Diagnostic Monitor (DM)")
if not ok or not shannon_dm_proto then return end

-- Protocol fields
local f_group_id     = ProtoField.uint8("shannon_dm.group_id", "DM Group ID", base.HEX)
local f_subgroup_id  = ProtoField.uint8("shannon_dm.subgroup_id", "DM Sub-Group ID", base.HEX)
local f_msg_id       = ProtoField.uint16("shannon_dm.msg_id", "Message ID", base.HEX)
local f_timestamp    = ProtoField.uint32("shannon_dm.timestamp", "Shannon HW Timestamp (ticks)", base.DEC)
local f_length       = ProtoField.uint16("shannon_dm.length", "Log Payload Length", base.DEC)
local f_payload      = ProtoField.bytes("shannon_dm.payload", "Log Payload")

shannon_dm_proto.fields = {
    f_group_id,
    f_subgroup_id,
    f_msg_id,
    f_timestamp,
    f_length,
    f_payload
}

-- Subdissector table for Shannon DM Group IDs
local dm_group_table = DissectorTable.get("shannon_dm.group") or DissectorTable.new("shannon_dm.group", "Samsung Shannon DM Group ID", ftypes.UINT8, base.HEX)

-- Shannon DM Group ID Mapping
local SHANNON_DM_GROUPS = {
    [0x10] = "SYS_CORE (Baseband OS & Crash Triage)",
    [0x20] = "GSM_2G (GSM RR / Layer 3 OTA)",
    [0x30] = "UMTS_3G (WCDMA RRC & NAS OTA)",
    [0x40] = "LTE_4G_RRC (LTE RRC Signaling)",
    [0x41] = "LTE_4G_NAS (LTE EMM / ESM Signaling)",
    [0x50] = "NR_5G_RRC (5G New Radio RRC Signaling)",
    [0x51] = "NR_5G_NAS (5G 5GMM / 5GSM Signaling)",
    [0x60] = "SIM_UICC (USIM APDU & Auth Interface)",
    [0x70] = "IMS_AUDIO (VoLTE / VoNR Codec & Session)"
}

function shannon_dm_proto.dissector(tvb, pinfo, tree)
    -- Shannon DM Header Layout:
    -- [0]: Group ID (1 byte)
    -- [1]: Sub-Group ID (1 byte)
    -- [2-3]: Message ID (2 bytes LE)
    -- [4-7]: Timestamp (4 bytes LE)
    -- [8-9]: Length (2 bytes LE)
    -- [10..N]: Payload
    if tvb:len() < 10 then return end

    pinfo.cols.protocol = "Shannon DM"

    local group_id = tvb(0, 1):uint()
    local subgroup_id = tvb(1, 1):uint()
    local msg_id = tvb(2, 2):le_uint()
    local timestamp = tvb(4, 4):le_uint()
    local length = tvb(8, 2):le_uint()

    local group_name = SHANNON_DM_GROUPS[group_id] or string.format("Group 0x%02X", group_id)

    local subtree = tree:add(shannon_dm_proto, tvb(), string.format("Shannon DM Log: %s (Msg: 0x%04X)", group_name, msg_id))
    subtree:add(f_group_id, tvb(0, 1)):append_text(string.format(" (%s)", group_name))
    subtree:add(f_subgroup_id, tvb(1, 1))
    subtree:add_le(f_msg_id, tvb(2, 2))
    subtree:add_le(f_timestamp, tvb(4, 4))
    subtree:add_le(f_length, tvb(8, 2))

    pinfo.cols.info = string.format("[Shannon DM] %s | Msg: 0x%04X (Len: %d)", group_name, msg_id, length)

    local offset = 10
    local payload_len = tvb:len() - offset

    if payload_len > 0 then
        local payload_tvb = tvb(offset, payload_len):tvb()
        local subdissector = dm_group_table:get_dissector(group_id)
        if subdissector then
            subdissector:call(payload_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, payload_len))
        end
    end
end

-- Register Shannon DM to Shannon IPC Channel 5 (CH_LOG)
local ipc_table = DissectorTable.get("shannon_ipc.channel")
if ipc_table then
    ipc_table:add(5, shannon_dm_proto)
end
