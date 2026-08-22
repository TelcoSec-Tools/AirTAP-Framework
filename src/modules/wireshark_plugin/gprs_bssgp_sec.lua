-- TelcoSec.net - GPRS BSSGP (BSS GPRS Protocol) Security Dissector
-- Description: Dissects BSSGP frames (3GPP TS 48.018) on Gb interface (BSS/PCU to SGSN).
--              Analyzes BVCI flow control, PAGING-PS, and detects BVC buffer starvation DoS attacks.

local ok, gprs_bssgp_proto = pcall(Proto, "gprs_bssgp_sec", "TelcoSec GPRS BSSGP (Gb Interface) Security Analyzer")
if not ok or not gprs_bssgp_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.uint8("gprs_bssgp.pdu_type", "BSSGP PDU Type", base.HEX)
local f_pdu_name     = ProtoField.string("gprs_bssgp.pdu_name", "PDU Name")
local f_bvci         = ProtoField.uint16("gprs_bssgp.bvci", "BVCI (BSSGP Virtual Connection ID)", base.DEC)
local f_nsei         = ProtoField.uint16("gprs_bssgp.nsei", "NSEI (Network Service Entity ID)", base.DEC)
local f_bucket_leak  = ProtoField.uint16("gprs_bssgp.bucket_leak", "BVC Bucket Leak Rate", base.DEC)
local f_imsi         = ProtoField.string("gprs_bssgp.imsi", "Target IMSI")
local f_sec_alert    = ProtoField.string("gprs_bssgp.alert", "TelcoSec BSSGP Security Alert")
local f_payload      = ProtoField.bytes("gprs_bssgp.payload", "BSSGP Information Elements")

gprs_bssgp_proto.fields = {
    f_pdu_type,
    f_pdu_name,
    f_bvci,
    f_nsei,
    f_bucket_leak,
    f_imsi,
    f_sec_alert,
    f_payload
}

-- BSSGP PDU Types (3GPP TS 48.018 Table 10.2)
local BSSGP_PDUS = {
    [0x00] = "DL-UNITDATA (SGSN -> BSS)",
    [0x01] = "UL-UNITDATA (BSS -> SGSN)",
    [0x02] = "RA-CAPABILITY",
    [0x03] = "PTM-UNITDATA",
    [0x06] = "PAGING PS",
    [0x07] = "PAGING CS",
    [0x08] = "RA-CAPABILITY-UPDATE",
    [0x09] = "RA-CAPABILITY-UPDATE-ACK",
    [0x0A] = "RADIO-STATUS",
    [0x0B] = "SUSPEND",
    [0x0C] = "SUSPEND-ACK",
    [0x0D] = "SUSPEND-NACK",
    [0x0E] = "RESUME",
    [0x0F] = "RESUME-ACK",
    [0x10] = "RESUME-NACK",
    [0x20] = "BVC-BLOCK",
    [0x21] = "BVC-BLOCK-ACK",
    [0x22] = "BVC-RESET",
    [0x23] = "BVC-RESET-ACK",
    [0x24] = "BVC-UNBLOCK",
    [0x25] = "BVC-UNBLOCK-ACK",
    [0x26] = "FLOW-CONTROL-BVC",
    [0x27] = "FLOW-CONTROL-BVC-ACK",
    [0x28] = "FLOW-CONTROL-MS",
    [0x29] = "FLOW-CONTROL-MS-ACK",
    [0x40] = "STATUS"
}

-- Native LLC dissector
local gprs_llc_dissector = Dissector.get("gprs_llc")

function gprs_bssgp_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "GPRS BSSGP"

    local pdu_type = tvb(0, 1):uint()
    local pdu_name = BSSGP_PDUS[pdu_type] or string.format("BSSGP PDU (0x%02X)", pdu_type)

    local subtree = tree:add(gprs_bssgp_proto, tvb(), string.format("GPRS BSSGP: %s", pdu_name))
    subtree:add(f_pdu_type, tvb(0, 1))
    subtree:add(f_pdu_name, pdu_name)

    pinfo.cols.info = string.format("[BSSGP] %s", pdu_name)

    -- Security Heuristics
    -- 1. BVC-RESET / BVC-BLOCK (Gb interface cell outage / DoS)
    if pdu_type == 0x20 or pdu_type == 0x22 then
        subtree:add(f_sec_alert, "[WARNING] BVC-RESET / BVC-BLOCK commanded on Gb link. Drops all active GPRS sessions for this cell/BVCI.")
        pinfo.cols.info:append(" [TELCOSEC: BVC CELL RESET]")
    end

    -- 2. FLOW-CONTROL-BVC Starvation Attack
    if pdu_type == 0x26 and tvb:len() >= 8 then
        subtree:add(f_sec_alert, "[INFO] BVC Flow Control parameters exchanged. Check for synthetic rate limiting / buffer starvation.")
    end

    -- 3. SUSPEND / RESUME (Circuit-Switched Handover Coordination)
    if pdu_type == 0x0B then
        subtree:add(f_sec_alert, "[INFO] GPRS Suspend Indication (Mobile switching to dedicated CS call).")
    end

    -- If DL/UL-UNITDATA, inner payload contains LLC frame after Information Elements
    if (pdu_type == 0x00 or pdu_type == 0x01) and tvb:len() > 10 then
        -- Skip TLLI and IE headers (typically ~10-14 bytes)
        local llc_offset = 10
        local llc_len = tvb:len() - llc_offset
        if llc_len > 0 then
            local llc_tvb = tvb(llc_offset, llc_len):tvb()
            if gprs_llc_dissector then
                gprs_llc_dissector:call(llc_tvb, pinfo, tree)
            else
                subtree:add(f_payload, tvb(llc_offset, llc_len))
            end
        end
    else
        subtree:add(f_payload, tvb(1, tvb:len() - 1))
    end
end
