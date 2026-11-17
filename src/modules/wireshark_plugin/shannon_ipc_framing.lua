-- TelcoSec.net - Samsung Shannon IPC / FMT Root Framing Dissector
-- Description: Dissects Samsung Exynos Shannon Inter-Processor Communication (IPC/FMT) frames
--              transmitted between the Application Processor (AP) and Cellular Baseband (CP).
--              Demultiplexes control, AT commands, network data, and diagnostic log streams.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
local bit = bit or bit32
if not bit then
    bit = {
        band   = function(a, b) return a & b end,
        bor    = function(a, b) return a | b end,
        bxor   = function(a, b) return a ~ b end,
        lshift = function(a, n) return (a << n) & 0xFFFFFFFF end,
        rshift = function(a, n) return (a & 0xFFFFFFFF) >> n end,
    }
end

local ok, shannon_ipc_proto = pcall(Proto, "shannon_ipc", "Samsung Shannon IPC Protocol")
if not ok or not shannon_ipc_proto then return end

-- Protocol fields
local f_magic        = ProtoField.uint8("shannon_ipc.magic", "Magic Byte", base.HEX)
local f_channel      = ProtoField.uint8("shannon_ipc.channel", "Channel ID", base.DEC)
local f_direction    = ProtoField.string("shannon_ipc.direction", "Direction (AP <-> CP)")
local f_length       = ProtoField.uint16("shannon_ipc.length", "Frame Length", base.DEC)
local f_seq_num      = ProtoField.uint8("shannon_ipc.seq_num", "Sequence Number", base.DEC)
local f_flags        = ProtoField.uint8("shannon_ipc.flags", "Control Flags", base.HEX)
local f_payload      = ProtoField.bytes("shannon_ipc.payload", "Channel Payload")

shannon_ipc_proto.fields = {
    f_magic,
    f_channel,
    f_direction,
    f_length,
    f_seq_num,
    f_flags,
    f_payload
}

-- Subdissector table for Shannon IPC channels
local ipc_channel_table = DissectorTable.new("shannon_ipc.channel", "Samsung Shannon IPC Channel", ftypes.UINT8, base.DEC)

-- Shannon IPC Channel Definitions
local SHANNON_CHANNELS = {
    [0] = "CH_CTRL (IPC Control & Handshake)",
    [1] = "CH_RFS (Remote File System / NVRAM)",
    [2] = "CH_AT (Cellular AT Commands)",
    [3] = "CH_NET (User Plane Network / RMNET)",
    [4] = "CH_AUDIO (Voice / VoLTE Audio)",
    [5] = "CH_LOG (Shannon Diagnostic Monitor / DM)",
    [6] = "CH_SIM (USIM / UICC APDU Interface)",
    [7] = "CH_GPS (Baseband GNSS Interface)"
}

-- Native dissectors for encapsulation
local ip_dissector = Dissector.get("ip")
local ipv6_dissector = Dissector.get("ipv6")

function shannon_ipc_proto.dissector(tvb, pinfo, tree)
    -- Shannon FMT Header format:
    -- [0]: Magic Byte (0x7F)
    -- [1]: Channel ID (1 byte)
    -- [2-3]: Length (2 bytes LE)
    -- [4]: Sequence Number (1 byte)
    -- [5]: Flags / Direction (1 byte: 0x00=AP->CP, 0x01=CP->AP)
    -- [6..N]: Payload
    if tvb:len() < 6 then return end

    local magic = tvb(0, 1):uint()
    if magic ~= 0x7F and magic ~= 0x7E then return end

    pinfo.cols.protocol = "Shannon IPC"

    local channel_id = tvb(1, 1):uint()
    local length = tvb(2, 2):le_uint()
    local seq_num = tvb(4, 1):uint()
    local flags = tvb(5, 1):uint()

    local dir_str = (bit.band(flags, 0x01) == 1) and "CP -> AP (Modem to Host)" or "AP -> CP (Host to Modem)"
    local channel_name = SHANNON_CHANNELS[channel_id] or string.format("Channel %d", channel_id)

    local subtree = tree:add(shannon_ipc_proto, tvb(), string.format("Samsung Shannon IPC: %s (%s)", channel_name, dir_str))
    subtree:add(f_magic, tvb(0, 1))
    subtree:add(f_channel, tvb(1, 1)):append_text(string.format(" (%s)", channel_name))
    subtree:add(f_direction, dir_str)
    subtree:add_le(f_length, tvb(2, 2))
    subtree:add(f_seq_num, tvb(4, 1))
    subtree:add(f_flags, tvb(5, 1))

    pinfo.cols.info = string.format("[Shannon IPC] %s | %s (Len: %d, Seq: %d)", channel_name, dir_str, length, seq_num)

    local offset = 6
    local payload_len = tvb:len() - offset

    if payload_len > 0 then
        local payload_tvb = tvb(offset, payload_len):tvb()

        -- Check if a subdissector is registered for this channel
        local subdissector = ipc_channel_table:get_dissector(channel_id)
        if subdissector then
            subdissector:call(payload_tvb, pinfo, tree)
        elseif channel_id == 3 then
            -- Network channel: check for IPv4 / IPv6
            local first_nibble = bit.rshift(payload_tvb(0, 1):uint(), 4)
            if first_nibble == 4 and ip_dissector then
                ip_dissector:call(payload_tvb, pinfo, tree)
            elseif first_nibble == 6 and ipv6_dissector then
                ipv6_dissector:call(payload_tvb, pinfo, tree)
            else
                subtree:add(f_payload, tvb(offset, payload_len))
            end
        else
            subtree:add(f_payload, tvb(offset, payload_len))
        end
    end
end

-- Register to UDP port 3000 (standard Shannon IPC over UDP/test)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(3000, shannon_ipc_proto)
end

-- Register to DLT User table (USER1 / DLT 148)
local wtap_encap_table = DissectorTable.get("wtap_encap")
if wtap_encap_table and wtap_encaps and wtap_encaps["USER1"] then
    pcall(function() wtap_encap_table:add(wtap_encaps["USER1"], shannon_ipc_proto) end)
end
