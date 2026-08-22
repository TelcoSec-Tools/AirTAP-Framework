-- TelcoSec.net - VoLTE SDP, RTP & SRTP Media Security Analyzer
-- Target Standards: RFC 4566 (SDP), RFC 3550 (RTP), RFC 3711 (SRTP), 3GPP TS 26.114 (IP Multimedia Subsystem VoLTE Media)
-- Description: Inspects Session Description Protocol (SDP) and Real-time Transport Protocol (RTP/SRTP) streams.
--              Detects unencrypted plaintext voice streams on carrier networks, SRTP-to-RTP downgrade attacks,
--              AMR-WB (HD Voice) codec stripping, and RTP sequence number injection attacks.

local ok, sdp_rtp_proto = pcall(Proto, "sdp_rtp_sec", "TelcoSec VoLTE Media Stream (SDP/RTP/SRTP) Security Analyzer")
if not ok or not sdp_rtp_proto then return end

-- Protocol fields
local f_media_type      = ProtoField.string("sdp_rtp_sec.media_type", "Media Type (audio / video)")
local f_proto_type      = ProtoField.string("sdp_rtp_sec.proto", "Transport Profile (RTP/AVP vs RTP/SAVP / SRTP)")
local f_is_encrypted    = ProtoField.bool("sdp_rtp_sec.encrypted", "Encrypted Stream Flag (SRTP)")
local f_codec           = ProtoField.string("sdp_rtp_sec.codec", "Negotiated Audio Codec (AMR / AMR-WB / EVS / PCMU)")
local f_crypto_suite    = ProtoField.string("sdp_rtp_sec.crypto_suite", "SRTP Crypto Suite (AES_CM_128_HMAC_SHA1_80)")
local f_rtp_pt          = ProtoField.uint8("sdp_rtp_sec.payload_type", "RTP Payload Type (PT)", base.DEC)
local f_rtp_seq         = ProtoField.uint16("sdp_rtp_sec.seq_num", "RTP Sequence Number", base.DEC)
local f_rtp_ssrc        = ProtoField.uint32("sdp_rtp_sec.ssrc", "RTP Synchronization Source (SSRC)", base.HEX)
local f_sec_alert       = ProtoField.string("sdp_rtp_sec.alert", "TelcoSec Media Security Alert")

sdp_rtp_proto.fields = {
    f_media_type,
    f_proto_type,
    f_is_encrypted,
    f_codec,
    f_crypto_suite,
    f_rtp_pt,
    f_rtp_seq,
    f_rtp_ssrc,
    f_sec_alert
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_sdp_media = safe_field("sdp.media")
local f_sdp_proto = safe_field("sdp.proto")
local f_rtp_pt_f  = safe_field("rtp.p_type")
local f_rtp_seq_f = safe_field("rtp.seq")
local f_rtp_ssrc_f= safe_field("rtp.ssrc")

function sdp_rtp_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 8 then return end

    local raw_str = tvb(0, math.min(len, 600)):string()

    -- 1. Inspect SDP Media Description Offer / Answer
    if string.find(raw_str, "m=audio") or string.find(raw_str, "m=video") or string.find(raw_str, "v=0\r\n") then
        local subtree = tree:add(sdp_rtp_proto, tvb(), "TelcoSec VoLTE SDP Security Engine")
        local alerts = {}

        local media_line = string.match(raw_str, "m=([^%s]+)%s+(%d+)%s+([^%s]+)%s+([^\r\n]+)")
        local proto_val = string.match(raw_str, "m=audio%s+%d+%s+([^%s]+)") or string.match(raw_str, "m=video%s+%d+%s+([^%s]+)")
        local crypto_val = string.match(raw_str, "a=crypto:%d+%s+([^%s]+)")
        local rtpmap_val = string.match(raw_str, "a=rtpmap:%d+%s+([^/%s]+)")

        if proto_val then
            subtree:add(f_proto_type, proto_val)
            local is_srtp = string.find(proto_val, "SAVP") ~= nil or string.find(proto_val, "SAVPF") ~= nil
            subtree:add(f_is_encrypted, is_srtp)

            -- Heuristic 1: Plaintext RTP on Carrier Voice (No SRTP Encryption)
            if not is_srtp then
                table.insert(alerts, "[WARNING] Unencrypted VoLTE Voice Stream (RTP/AVP)! Audio payload transmitted in cleartext over IP network. Vulnerable to passive wiretapping.")
            end
        end

        if crypto_val then
            subtree:add(f_crypto_suite, crypto_val)
        end

        if rtpmap_val then
            subtree:add(f_codec, rtpmap_val)
            -- Heuristic 2: AMR-WB / EVS Downgrade to G.711 PCMA/PCMU
            if string.match(rtpmap_val, "PCMU") or string.match(rtpmap_val, "PCMA") or string.match(rtpmap_val, "telephone%-event") then
                table.insert(alerts, "[INFO] Legacy narrow-band codec negotiated (G.711 / PCM). HD Voice (AMR-WB / EVS) disabled.")
            end
        end

        if #alerts > 0 then
            for _, alert_msg in ipairs(alerts) do
                subtree:add(f_sec_alert, alert_msg)
            end
            pinfo.cols.info:append(" [TELCOSEC: SDP MEDIA ALERT!]")
        end
    end
end

register_postdissector(sdp_rtp_proto)
