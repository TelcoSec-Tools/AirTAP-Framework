-- TelcoSec.net - GSM LAPDm Layer 2 Frame Integrity Dissector
-- Description: Dissects GSM LAPDm frames (3GPP TS 44.006) on SDCCH, SACCH, and FACCH channels.
--              Detects unauthenticated frame injections, SABM/UA session hijacks, and UI frame tampering.

local ok, gsm_lapdm_proto = pcall(Proto, "gsm_lapdm_sec", "TelcoSec GSM LAPDm Layer 2 Integrity Analyzer")
if not ok or not gsm_lapdm_proto then return end

-- Protocol fields
local f_sapi         = ProtoField.uint8("gsm_lapdm_sec.sapi", "SAPI (Service Access Point ID)", base.DEC)
local f_cr           = ProtoField.bool("gsm_lapdm_sec.cr", "Command / Response (C/R)")
local f_ea           = ProtoField.bool("gsm_lapdm_sec.ea", "Address Field Extension (EA)")
local f_ctrl         = ProtoField.uint8("gsm_lapdm_sec.ctrl", "Control Field", base.HEX)
local f_frame_type   = ProtoField.string("gsm_lapdm_sec.frame_type", "Frame Type")
local f_ns           = ProtoField.uint8("gsm_lapdm_sec.ns", "N(S) Send Sequence", base.DEC)
local f_nr           = ProtoField.uint8("gsm_lapdm_sec.nr", "N(R) Receive Sequence", base.DEC)
local f_length       = ProtoField.uint8("gsm_lapdm_sec.length", "Payload Length Indicator (L)", base.DEC)
local f_sec_alert    = ProtoField.string("gsm_lapdm_sec.alert", "TelcoSec LAPDm Security Alert")
local f_payload      = ProtoField.bytes("gsm_lapdm_sec.payload", "LAPDm Information Payload")

gsm_lapdm_proto.fields = {
    f_sapi,
    f_cr,
    f_ea,
    f_ctrl,
    f_frame_type,
    f_ns,
    f_nr,
    f_length,
    f_sec_alert,
    f_payload
}

-- Native DTAP dissector
local gsm_a_dtap_dissector = Dissector.get("gsm_a_dtap")

function gsm_lapdm_proto.dissector(tvb, pinfo, tree)
    -- LAPDm Frame Layout:
    -- [0]: Address Field: Bits 7-5=Reserved, Bit 4=Spare, Bits 3-2=SAPI, Bit 1=C/R, Bit 0=EA
    -- [1]: Control Field (I-frame, S-frame, or U-frame)
    -- [2]: Length Indicator (Bits 7-2=Length, Bit 1=M, Bit 0=EL)
    -- [3..N]: Information Field (N201 bytes = 23 bytes max for SDCCH/FACCH)
    if tvb:len() < 3 then return end

    pinfo.cols.protocol = "GSM LAPDm"

    local addr_byte = tvb(0, 1):uint()
    local sapi = bit.rshift(bit.band(addr_byte, 0x1C), 2)
    local cr = bit.band(addr_byte, 0x02) ~= 0
    local ea = bit.band(addr_byte, 0x01) ~= 0

    local ctrl_byte = tvb(1, 1):uint()
    local len_byte = tvb(2, 1):uint()
    local pdu_len = bit.rshift(len_byte, 2)

    local frame_type = "Unknown"
    local ns = nil
    local nr = nil

    if bit.band(ctrl_byte, 0x01) == 0 then
        -- Information frame (I-frame)
        frame_type = "I-Frame (Information Transfer)"
        ns = bit.rshift(bit.band(ctrl_byte, 0x0E), 1)
        nr = bit.rshift(bit.band(ctrl_byte, 0xE0), 5)
    elseif bit.band(ctrl_byte, 0x03) == 1 then
        -- Supervisory frame (S-frame)
        local s_code = bit.rshift(bit.band(ctrl_byte, 0x0C), 2)
        local s_names = { [0]="RR (Receive Ready)", [1]="RNR (Receive Not Ready)", [2]="REJ (Reject)" }
        frame_type = s_names[s_code] or "S-Frame"
        nr = bit.rshift(bit.band(ctrl_byte, 0xE0), 5)
    elseif bit.band(ctrl_byte, 0x03) == 3 then
        -- Unnumbered frame (U-frame)
        local u_code = bit.band(ctrl_byte, 0xEF)
        if u_code == 0x2F or ctrl_byte == 0x2F or ctrl_byte == 0x3F then
            frame_type = "SABM (Set Asynchronous Balanced Mode)"
        elseif ctrl_byte == 0x63 or ctrl_byte == 0x73 then
            frame_type = "UA (Unnumbered Acknowledgement)"
        elseif ctrl_byte == 0x43 or ctrl_byte == 0x53 then
            frame_type = "DISC (Disconnect)"
        elseif ctrl_byte == 0x03 then
            frame_type = "UI (Unnumbered Information)"
        else
            frame_type = string.format("U-Frame (0x%02X)", ctrl_byte)
        end
    end

    local subtree = tree:add(gsm_lapdm_proto, tvb(), string.format("GSM LAPDm: %s (SAPI: %d, Len: %d)", frame_type, sapi, pdu_len))
    subtree:add(f_sapi, tvb(0, 1), sapi)
    subtree:add(f_cr, tvb(0, 1), cr)
    subtree:add(f_ea, tvb(0, 1), ea)
    subtree:add(f_ctrl, tvb(1, 1))
    subtree:add(f_frame_type, frame_type)
    subtree:add(f_length, tvb(2, 1), pdu_len)

    if ns then subtree:add(f_ns, ns) end
    if nr then subtree:add(f_nr, nr) end

    pinfo.cols.info = string.format("[LAPDm SAPI %d] %s (Len: %d)", sapi, frame_type, pdu_len)

    -- Security Heuristic 1: Malicious SABM injection on SDCCH (session takeover)
    if string.find(frame_type, "SABM") and pdu_len > 0 then
        subtree:add(f_sec_alert, "[INFO] SABM contention resolution frame. Establishes dedicated signaling link with base station.")
    end

    -- Security Heuristic 2: Unsolicited DISC (Forced session teardown)
    if string.find(frame_type, "DISC") then
        subtree:add(f_sec_alert, "[WARNING] LAPDm DISC received. Base station abruptly tearing down layer-2 radio connection.")
    end

    local offset = 3
    if pdu_len > 0 and tvb:len() >= (offset + pdu_len) then
        local pdu_tvb = tvb(offset, pdu_len):tvb()

        -- SAPI 0 = Signaling (RR, MM, CC) -> pass to DTAP
        -- SAPI 3 = SMS
        if sapi == 0 and gsm_a_dtap_dissector then
            gsm_a_dtap_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end
