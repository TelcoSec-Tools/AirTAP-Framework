-- TelcoSec.net - GPRS Logical Link Control (LLC) & GEA Cipher Downgrade Dissector
-- Description: Dissects GPRS LLC frames (3GPP TS 44.064).
--              Analyzes GPRS encryption negotiation and flags forced GEA0 (Null-cipher / plaintext)
--              and GEA1 (cryptographically broken cipher) downgrades.

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

local ok, gprs_llc_proto = pcall(Proto, "gprs_llc_sec", "TelcoSec GPRS LLC & GEA Cipher Analyzer")
if not ok or not gprs_llc_proto then return end

-- Protocol fields
local f_sapi         = ProtoField.uint8("gprs_llc_sec.sapi", "LLC SAPI", base.DEC)
local f_frame_type   = ProtoField.string("gprs_llc_sec.frame_type", "Frame Type")
local f_nu           = ProtoField.uint16("gprs_llc_sec.nu", "N(U) Unconfirmed Sequence", base.DEC)
-- Retained and registered although this dissector no longer sets it: GEA
-- selection is a GMM field, decoded by gprs_gmm_sm_sec.lua. Keeping the field
-- registered preserves saved Wireshark filters referencing gprs_llc_sec.cipher_algo.
local f_cipher_algo  = ProtoField.string("gprs_llc_sec.cipher_algo", "Negotiated GEA Cipher")
local f_xid_param    = ProtoField.string("gprs_llc_sec.xid_param", "LLC XID Parameter")
local f_fcs          = ProtoField.uint24("gprs_llc_sec.fcs", "Frame Check Sequence (FCS)", base.HEX)
local f_sec_alert    = ProtoField.string("gprs_llc_sec.alert", "TelcoSec GPRS Security Alert")
local f_payload      = ProtoField.bytes("gprs_llc_sec.payload", "LLC Information Payload")

gprs_llc_proto.fields = {
    f_sapi,
    f_frame_type,
    f_nu,
    f_cipher_algo,
    f_xid_param,
    f_fcs,
    f_sec_alert,
    f_payload
}

-- Mapping GPRS LLC SAPI
local LLC_SAPIS = {
    [1]  = "GMM (GPRS Mobility Management)",
    [3]  = "SNDCP (User Plane IP / Data)",
    [5]  = "SNDCP (User Plane IP / Data)",
    [7]  = "SMS (Short Message Service over GPRS)",
    [8]  = "TOM (Tunneling of Messages)",
    [9]  = "SNDCP (User Plane IP / Data)",
    [11] = "SNDCP (User Plane IP / Data)"
}

-- 3GPP TS 44.064 6.4.1: XID parameter types, carried in bits 6..2 of the
-- first octet of each parameter. None of these is a ciphering algorithm.
local XID_PARAM_TYPES = {
    [0x00] = "Version",
    [0x01] = "IOV-UI",
    [0x02] = "IOV-I",
    [0x03] = "T200",
    [0x04] = "N200",
    [0x05] = "N201-U",
    [0x06] = "N201-I",
    [0x07] = "mD",
    [0x08] = "mU",
    [0x09] = "kD",
    [0x0A] = "kU",
    [0x0B] = "Layer-3 Parameters",
    [0x0C] = "Reset"
}

-- Native GPRS dissectors
local gprs_sndcp_dissector = Dissector.get("sndcp")

function gprs_llc_proto.dissector(tvb, pinfo, tree)
    -- GPRS LLC Header Layout:
    -- [0]: Address Field (Bit 6=PD, Bits 3-0=SAPI)
    -- [1-2]: Control Field (UI, I, S, or U frame)
    -- [3..N-3]: Information Field
    -- [N-3..N]: FCS (3 bytes)
    if tvb:len() < 4 then return end

    pinfo.cols.protocol = "GPRS LLC"

    local addr_byte = tvb(0, 1):uint()
    local sapi = bit.band(addr_byte, 0x0F)
    local sapi_name = LLC_SAPIS[sapi] or string.format("SAPI %d", sapi)

    local ctrl_byte = tvb(1, 1):uint()
    local frame_type = "UI (Unconfirmed Information)"
    if bit.band(ctrl_byte, 0x01) == 0 then
        frame_type = "I (Information)"
    elseif bit.band(ctrl_byte, 0x03) == 1 then
        frame_type = "S (Supervisory)"
    elseif bit.band(ctrl_byte, 0x03) == 3 then
        frame_type = "U (Unnumbered / XID)"
    end

    local subtree = tree:add(gprs_llc_proto, tvb(), string.format("GPRS LLC: %s (%s)", frame_type, sapi_name))
    subtree:add(f_sapi, tvb(0, 1), sapi):append_text(string.format(" (%s)", sapi_name))
    subtree:add(f_frame_type, frame_type)

    pinfo.cols.info = string.format("[GPRS LLC] %s | %s", frame_type, sapi_name)

    -- Security Heuristic 1: XID parameter negotiation.
    --
    -- GEA cipher selection is NOT negotiated here. 3GPP TS 44.064 defines the
    -- XID parameter types as version, IOV-UI, IOV-I, T200, N200, N201-U,
    -- N201-I, mD, mU, kD, kU, Layer-3 parameters and Reset; none of them
    -- carries a ciphering algorithm. GPRS ciphering is selected by the GMM
    -- Authentication & Ciphering Request (TS 24.008 9.4.9), and that check now
    -- lives in gprs_gmm_sm_sec.lua, reading the IE at its defined offset.
    --
    -- The previous revision searched a hex dump of the whole frame for "0000"
    -- and reported a [CRITICAL] forced-GEA0 alert on any match. The search was
    -- unanchored, so it matched across byte boundaries at any nibble offset,
    -- and it looked in a protocol layer that does not carry the field, so the
    -- alert could never have been correct. Decoded below for visibility only.
    if frame_type == "U (Unnumbered / XID)" and tvb:len() >= 4 then
        local xid_tree = subtree:add(gprs_llc_proto, tvb(), "LLC XID Parameters")
        local offset = 3
        local limit = tvb:len() - 3 -- exclude the 3-byte FCS
        local guard = 0

        while offset < limit and guard < 32 do
            guard = guard + 1
            local byte1 = tvb(offset, 1):uint()
            local xl = bit.band(byte1, 0x80) ~= 0
            local xtype = bit.rshift(bit.band(byte1, 0x7C), 2)
            local plen, header

            if xl then
                -- Extended length: 2 high bits here, 6 low bits in the next
                -- octet (its bottom 2 bits are spare).
                if offset + 1 >= limit then break end
                local byte2 = tvb(offset + 1, 1):uint()
                plen = bit.bor(bit.lshift(bit.band(byte1, 0x03), 6),
                               bit.rshift(bit.band(byte2, 0xFC), 2))
                header = 2
            else
                plen = bit.band(byte1, 0x03)
                header = 1
            end

            if offset + header + plen > limit then break end
            xid_tree:add(f_xid_param, string.format("%s (type %d, %d byte%s)",
                XID_PARAM_TYPES[xtype] or string.format("Unknown type %d", xtype),
                xtype, plen, plen == 1 and "" or "s"))

            -- A Reset parameter tears down the LLC ciphering state, which is a
            -- precondition for re-negotiating a weaker cipher at GMM level.
            if xtype == 0x0C then
                xid_tree:add(f_sec_alert, "[INFO] LLC XID Reset parameter: ciphering and sequence state cleared. Correlate with any following Authentication & Ciphering Request.")
            end

            offset = offset + header + plen
        end
    end

    local offset = 3
    local payload_len = tvb:len() - offset - 3 -- Minus 3 bytes FCS
    if payload_len > 0 then
        local payload_tvb = tvb(offset, payload_len):tvb()

        -- SAPI 3, 5, 9, 11 are SNDCP user plane data
        if (sapi == 3 or sapi == 5 or sapi == 9 or sapi == 11) and gprs_sndcp_dissector then
            gprs_sndcp_dissector:call(payload_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, payload_len))
        end
    end
end
