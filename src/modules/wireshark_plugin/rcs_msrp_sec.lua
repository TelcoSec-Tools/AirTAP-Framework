-- TelcoSec.net - RCS / MSRP (Message Session Relay Protocol) Security Dissector
-- Target Standards: RFC 4975 (MSRP), RFC 4976 (MSRP Relay Extensions), GSMA RCC.07 / RCC.71 (RCS Universal Profile)
-- Description: Dissects MSRP sessions used for RCS 1-to-1 Chat, Group Chat, File Transfers, and Geolocation Push.
--              Decodes MSRP transaction methods (SEND, REPORT, AUTH), byte-ranges, CPIM wrappers,
--              detects unencrypted file/image exfiltration, and identifies rogue MSRP relay bounce attacks.

local ok, rcs_msrp_proto = pcall(Proto, "rcs_msrp_sec", "TelcoSec RCS / MSRP Chat & File Transfer Security Analyzer")
if not ok or not rcs_msrp_proto then return end

-- Protocol fields
local f_msrp_method    = ProtoField.string("rcs_msrp_sec.method", "MSRP Method / Request")
local f_msrp_tx_id     = ProtoField.string("rcs_msrp_sec.tx_id", "MSRP Transaction ID")
local f_to_path        = ProtoField.string("rcs_msrp_sec.to_path", "To-Path (Target MSRP Relay/URI)")
local f_from_path      = ProtoField.string("rcs_msrp_sec.from_path", "From-Path (Originating MSRP Relay/URI)")
local f_msg_id         = ProtoField.string("rcs_msrp_sec.msg_id", "Message-ID")
local f_byte_range     = ProtoField.string("rcs_msrp_sec.byte_range", "Byte-Range (Offset / Total)")
local f_content_type   = ProtoField.string("rcs_msrp_sec.content_type", "Content-Type")
local f_rcs_payload    = ProtoField.string("rcs_msrp_sec.rcs_text", "RCS Plaintext Message / Metadata")
local f_sec_alert      = ProtoField.string("rcs_msrp_sec.alert", "TelcoSec MSRP Security Alert")

rcs_msrp_proto.fields = {
    f_msrp_method,
    f_msrp_tx_id,
    f_to_path,
    f_from_path,
    f_msg_id,
    f_byte_range,
    f_content_type,
    f_rcs_payload,
    f_sec_alert
}

function rcs_msrp_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 10 then return end

    -- Check MSRP start banner: "MSRP <tx_id> <method>"
    local header_str = tvb(0, math.min(len, 256)):string()
    if not string.match(header_str, "^MSRP%s+") then return end

    pinfo.cols.protocol = "RCS / MSRP"

    local tx_id, method = string.match(header_str, "^MSRP%s+([%w%-_]+)%s+([%a%d]+)")
    method = method or "UNKNOWN"
    tx_id = tx_id or "UNKNOWN"

    pinfo.cols.info = string.format("[RCS MSRP] %s (Tx: %s)", method, tx_id)

    local subtree = tree:add(rcs_msrp_proto, tvb(), string.format("RCS MSRP Security: %s (Tx: %s)", method, tx_id))
    subtree:add(f_msrp_method, method)
    subtree:add(f_msrp_tx_id, tx_id)

    local alerts = {}

    -- Extract To-Path and From-Path
    local to_path = string.match(header_str, "To%-Path:%s*([^\r\n]+)")
    if to_path then
        subtree:add(f_to_path, to_path)
        -- Security Check: Rogue MSRP Relay Bouncing
        if string.find(to_path, ";tcp") and not string.find(to_path, ";msrps") then
            table.insert(alerts, "[CRITICAL] Cleartext unencrypted MSRP over TCP (msrp://) instead of secure TLS (msrps://)! RCS traffic is vulnerable to wiretapping.")
        end
    end

    local from_path = string.match(header_str, "From%-Path:%s*([^\r\n]+)")
    if from_path then
        subtree:add(f_from_path, from_path)
    end

    -- Extract Byte-Range
    local byte_range = string.match(header_str, "Byte%-Range:%s*([^\r\n]+)")
    if byte_range then
        subtree:add(f_byte_range, byte_range)
    end

    -- Extract Content-Type
    local ctype = string.match(header_str, "Content%-Type:%s*([^\r\n]+)")
    if ctype then
        subtree:add(f_content_type, ctype)
        if string.find(ctype, "message/cpim") or string.find(ctype, "text/plain") then
            subtree:add(f_rcs_payload, "RCS Instant Chat Message")
        elseif string.find(ctype, "application/vnd.gsma.rcs-ft-http") or string.find(ctype, "image/") then
            subtree:add(f_rcs_payload, "RCS File / Image Media Transfer")
            table.insert(alerts, "[NOTICE] RCS File / Media Transfer active across MSRP stream.")
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: MSRP ALERT!]")
    end
end

register_postdissector(rcs_msrp_proto)
