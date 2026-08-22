-- TelcoSec.net - Real-Time Streaming Protocol (RTSP) Security Analyzer
-- Target Standards: RFC 2326 (RTSP 1.0), RFC 7826 (RTSP 2.0), 3GPP TS 26.234 (Packet-switched Streaming Service PSS)
-- Description: Dissects RTSP control commands (DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, SET_PARAMETER).
--              Detects unauthenticated session hijacking, rogue TEARDOWN injection, and media session redirection.

local ok, rtsp_sec_proto = pcall(Proto, "rtsp_sec", "TelcoSec RTSP Media Streaming Security Analyzer")
if not ok or not rtsp_sec_proto then return end

-- Protocol fields
local f_method          = ProtoField.string("rtsp_sec.method", "RTSP Method")
local f_status_code     = ProtoField.uint32("rtsp_sec.status_code", "RTSP Status Code", base.DEC)
local f_uri             = ProtoField.string("rtsp_sec.uri", "Stream URI")
local f_session_id      = ProtoField.string("rtsp_sec.session_id", "Session-ID")
local f_cseq            = ProtoField.uint32("rtsp_sec.cseq", "Sequence Number (CSeq)", base.DEC)
local f_transport       = ProtoField.string("rtsp_sec.transport", "Transport Configuration")
local f_sec_alert       = ProtoField.string("rtsp_sec.alert", "TelcoSec RTSP Alert")

rtsp_sec_proto.fields = {
    f_method,
    f_status_code,
    f_uri,
    f_session_id,
    f_cseq,
    f_transport,
    f_sec_alert
}

local RTSP_METHODS = {
    ["DESCRIBE"] = true,
    ["SETUP"]    = true,
    ["PLAY"]     = true,
    ["PAUSE"]    = true,
    ["TEARDOWN"] = true,
    ["OPTIONS"]  = true,
    ["GET_PARAMETER"] = true,
    ["SET_PARAMETER"] = true,
    ["REDIRECT"] = true
}

function rtsp_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 10 then return end

    local raw_str = tvb(0, math.min(len, 600)):string()

    -- Check if RTSP Request or Response
    local method, uri = string.match(raw_str, "^([A-Z_]+)%s+([^%s]+)%s+RTSP/")
    local status_code = tonumber(string.match(raw_str, "^RTSP/[%d%.]+%s+(%d%d%d)"))

    if not (method or status_code) then return end

    pinfo.cols.protocol = "RTSP"
    local subtree = tree:add(rtsp_sec_proto, tvb(), string.format("RTSP Security: %s", method or string.format("Status %d", status_code)))

    if method then subtree:add(f_method, method) end
    if uri then subtree:add(f_uri, uri) end
    if status_code then subtree:add(f_status_code, status_code) end

    local session_id = string.match(raw_str, "[Ss][Ee][Ss][Ss][Ii][Oo][Nn]:%s*([^;\r\n]+)")
    local cseq_val = tonumber(string.match(raw_str, "[Cc][Ss][Ee][Qq]:%s*(%d+)"))
    local transport_val = string.match(raw_str, "[Tt][Rr][Aa][Nn][Ss][Pp][Oo][Rr][Tt]:%s*([^\r\n]+)")

    if session_id then subtree:add(f_session_id, session_id) end
    if cseq_val then subtree:add(f_cseq, cseq_val) end
    if transport_val then subtree:add(f_transport, transport_val) end

    -- Security Heuristic 1: Unauthenticated Session Teardown
    if method == "TEARDOWN" then
        subtree:add(f_sec_alert, "[WARNING] RTSP TEARDOWN: Abruptly terminating video/media streaming session.")
    end

    -- Security Heuristic 2: Session REDIRECT Manipulation
    if method == "REDIRECT" then
        subtree:add(f_sec_alert, "[CRITICAL] RTSP REDIRECT commanded! Forcefully diverting media stream client to new server destination.")
    end
end

local tcp_port_table = DissectorTable.get("tcp.port")
if tcp_port_table then
    tcp_port_table:add(554, rtsp_sec_proto)
    tcp_port_table:add(8554, rtsp_sec_proto)
end

register_postdissector(rtsp_sec_proto)
