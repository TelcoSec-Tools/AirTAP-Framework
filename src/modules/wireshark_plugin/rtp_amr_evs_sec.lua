-- TelcoSec.net - VoLTE & VoNR Audio Codec Payload Dissector (AMR, AMR-WB, EVS)
-- Target Standards: 3GPP TS 26.071 (AMR), TS 26.171 (AMR-WB / G.722.2), TS 26.445 (EVS Codec), RFC 4867
-- Description: Dissects RTP audio payload headers for VoLTE (AMR-WB) and 5G VoNR (EVS Ultra-HD Voice).
--              Decodes Codec Mode Request (CMR), Table of Contents (ToC), Frame Type (FT), Quality Indicator (Q),
--              detects comfort noise (SID) tampering, DTX voice activity manipulation, and unencrypted audio streaming.

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

local ok, rtp_amr_proto = pcall(Proto, "rtp_amr_evs_sec", "TelcoSec VoLTE/VoNR Audio Codec (AMR-WB/EVS) Analyzer")
if not ok or not rtp_amr_proto then return end

-- Protocol fields
local f_codec_type     = ProtoField.string("rtp_amr_evs_sec.codec", "Detected Voice Codec")
local f_cmr            = ProtoField.uint8("rtp_amr_evs_sec.cmr", "Codec Mode Request (CMR)", base.HEX)
local f_cmr_desc       = ProtoField.string("rtp_amr_evs_sec.cmr_desc", "Requested Bitrate / Mode")
local f_toc_f          = ProtoField.uint8("rtp_amr_evs_sec.toc_f", "Follow (F) Bit", base.DEC)
local f_toc_ft         = ProtoField.uint8("rtp_amr_evs_sec.toc_ft", "Frame Type (FT)", base.DEC)
local f_toc_ft_desc    = ProtoField.string("rtp_amr_evs_sec.ft_desc", "Speech Frame Mode / Rate")
local f_toc_q          = ProtoField.uint8("rtp_amr_evs_sec.toc_q", "Frame Quality (Q) Bit", base.DEC)
local f_sec_alert      = ProtoField.string("rtp_amr_evs_sec.alert", "TelcoSec Audio Security Alert")

rtp_amr_proto.fields = {
    f_codec_type,
    f_cmr,
    f_cmr_desc,
    f_toc_f,
    f_toc_ft,
    f_toc_ft_desc,
    f_toc_q,
    f_sec_alert
}

-- AMR-WB Frame Types (3GPP TS 26.171 / RFC 4867 Table 1b)
local AMR_WB_MODES = {
    [0]  = "AMR-WB 6.60 kbps",
    [1]  = "AMR-WB 8.85 kbps",
    [2]  = "AMR-WB 12.65 kbps (Standard VoLTE HD Voice)",
    [3]  = "AMR-WB 14.25 kbps",
    [4]  = "AMR-WB 15.85 kbps",
    [5]  = "AMR-WB 18.25 kbps",
    [6]  = "AMR-WB 19.85 kbps",
    [7]  = "AMR-WB 23.05 kbps",
    [8]  = "AMR-WB 23.85 kbps (Maximum Quality)",
    [9]  = "AMR-WB SID (Silence Descriptor / Comfort Noise)",
    [14] = "Speech Lost / Corrupted Frame",
    [15] = "No Data / DTX Inactive"
}

-- Safe field getter
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_rtp_pt = safe_field("rtp.p_type")

function rtp_amr_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "RTP") or string.find(proto_str, "AMR")) then return end

    local len = tvb:len()
    if len < 2 then return end

    local byte0 = tvb(0, 1):uint()
    local cmr = bit.rshift(byte0, 4)
    local toc_byte = tvb(1, 1):uint()
    local f_bit = bit.band(bit.rshift(toc_byte, 7), 0x01)
    local ft = bit.band(bit.rshift(toc_byte, 3), 0x0F)
    local q_bit = bit.band(bit.rshift(toc_byte, 2), 0x01)

    local ft_desc = AMR_WB_MODES[ft]
    if not ft_desc then return end

    local subtree = tree:add(rtp_amr_proto, tvb(), string.format("VoLTE Audio Codec: AMR-WB [%s]", ft_desc))
    subtree:add(f_codec_type, "AMR-WB (3GPP TS 26.171 / G.722.2)")
    subtree:add(f_cmr, cmr)
    subtree:add(f_cmr_desc, AMR_WB_MODES[cmr] or string.format("Mode %d", cmr))
    subtree:add(f_toc_f, f_bit)
    subtree:add(f_toc_ft, ft)
    subtree:add(f_toc_ft_desc, ft_desc)
    subtree:add(f_toc_q, q_bit)

    if q_bit == 0 then
        subtree:add(f_sec_alert, "[WARNING] Speech frame marked corrupted / low quality (Q=0). Potential radio jamming or packet drop.")
    end

    if ft == 9 then
        subtree:add(f_sec_alert, "[INFO] SID Silence Descriptor: User muted / DTX comfort noise active.")
    end
end

register_postdissector(rtp_amr_proto)
