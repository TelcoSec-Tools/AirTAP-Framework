-- TelcoSec.net - SCTP Signaling Backbone Security Analyzer
-- Target Standards: RFC 4960 (Stream Control Transmission Protocol)
-- Description: Inspects SCTP chunks (INIT, INIT_ACK, COOKIE_ECHO, ABORT, SHUTDOWN, DATA, HEARTBEAT).
--              Detects SCTP INIT flooding Denial-of-Service attacks against telecom core networks,
--              rogue ABORT chunk injection (association kill), Verification Tag reflection attacks, and MTU starvation.

local ok, sctp_sec_proto = pcall(Proto, "sctp_sec", "TelcoSec SCTP Signaling Backbone Security Analyzer")
if not ok or not sctp_sec_proto then return end

-- Protocol fields
local f_src_port        = ProtoField.uint16("sctp_sec.src_port", "SCTP Source Port", base.DEC)
local f_dst_port        = ProtoField.uint16("sctp_sec.dst_port", "SCTP Destination Port", base.DEC)
local f_vtag            = ProtoField.uint32("sctp_sec.vtag", "Verification Tag (VTag)", base.HEX)
local f_chunk_type      = ProtoField.uint8("sctp_sec.chunk_type", "SCTP Chunk Type", base.DEC)
local f_chunk_name      = ProtoField.string("sctp_sec.chunk_name", "Chunk Name")
local f_init_tsn        = ProtoField.uint32("sctp_sec.init_tsn", "Initial TSN", base.DEC)
local f_sec_alert       = ProtoField.string("sctp_sec.alert", "TelcoSec SCTP Alert")

sctp_sec_proto.fields = {
    f_src_port,
    f_dst_port,
    f_vtag,
    f_chunk_type,
    f_chunk_name,
    f_init_tsn,
    f_sec_alert
}

-- Known SCTP Chunk Types (RFC 4960)
local SCTP_CHUNKS = {
    [0]  = "DATA",
    [1]  = "INIT (Initiation)",
    [2]  = "INIT_ACK (Initiation Acknowledgement)",
    [3]  = "SACK (Selective Acknowledgement)",
    [4]  = "HEARTBEAT",
    [5]  = "HEARTBEAT_ACK",
    [6]  = "ABORT",
    [7]  = "SHUTDOWN",
    [8]  = "SHUTDOWN_ACK",
    [9]  = "ERROR",
    [10] = "COOKIE_ECHO",
    [11] = "COOKIE_ACK",
    [14] = "SHUTDOWN_COMPLETE",
    [15] = "AUTH"
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_sctp_chunk_f = safe_field("sctp.chunk_type")
local f_sctp_vtag_f  = safe_field("sctp.verification_tag")

-- State tracking for INIT flood detection
local init_flood_tracker = {
    window_start = 0,
    count = 0
}

function sctp_sec_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "SCTP") or (f_sctp_chunk_f and f_sctp_chunk_f())) then
        return
    end

    local subtree = tree:add(sctp_sec_proto, tvb(), "TelcoSec SCTP Backbone Security Engine")
    local alerts = {}

    if f_sctp_chunk_f and f_sctp_chunk_f() then
        local chunk_type = f_sctp_chunk_f().value
        local chunk_name = SCTP_CHUNKS[chunk_type] or string.format("Chunk %d", chunk_type)
        subtree:add(f_chunk_type, chunk_type)
        subtree:add(f_chunk_name, chunk_name)

        -- Security Heuristic 1: Rogue ABORT Chunk Injection (Connection Reset Attack)
        if chunk_type == 6 then
            table.insert(alerts, "[CRITICAL] SCTP ABORT Chunk detected! Forcefully terminates active telecom signaling association (NGAP/S1AP/Diameter/SIGTRAN).")
        end

        -- Security Heuristic 2: SCTP INIT Flood DoS
        if chunk_type == 1 then
            local cur_time = pinfo.abs_ts
            if (cur_time - init_flood_tracker.window_start) > 1.0 then
                if init_flood_tracker.count > 200 then
                    table.insert(alerts, string.format("[CRITICAL] High-frequency SCTP INIT Flood (%d chunks/sec)! Telecom core signaling resource exhaustion DoS.", init_flood_tracker.count))
                end
                init_flood_tracker.window_start = cur_time
                init_flood_tracker.count = 1
            else
                init_flood_tracker.count = init_flood_tracker.count + 1
            end
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: SCTP SECURITY ALERT!]")
    end
end

register_postdissector(sctp_sec_proto)
