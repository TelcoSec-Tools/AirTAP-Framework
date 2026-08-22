-- TelcoSec.net - GPRS Network Service (NS) over IP/FR Dissector
-- Description: Dissects GPRS NS frames (3GPP TS 48.016) between PCU/BSS and SGSN.
--              Detects malicious NS-RESET / NS-BLOCK connection resets and Gb link DoS attacks.

local ok, gprs_ns_proto = pcall(Proto, "gprs_ns_sec", "TelcoSec GPRS Network Service (NS) Analyzer")
if not ok or not gprs_ns_proto then return end

-- Protocol fields
local f_pdu_type     = ProtoField.uint8("gprs_ns.pdu_type", "NS PDU Type", base.HEX)
local f_pdu_name     = ProtoField.string("gprs_ns.pdu_name", "NS PDU Name")
local f_nsvci        = ProtoField.uint16("gprs_ns.nsvci", "NS-VCI (Virtual Connection ID)", base.DEC)
local f_nsei         = ProtoField.uint16("gprs_ns.nsei", "NSEI (Network Service Entity ID)", base.DEC)
local f_cause        = ProtoField.uint8("gprs_ns.cause", "Cause Code", base.HEX)
local f_sec_alert    = ProtoField.string("gprs_ns.alert", "TelcoSec NS Security Alert")
local f_payload      = ProtoField.bytes("gprs_ns.payload", "NS Payload Data")

gprs_ns_proto.fields = {
    f_pdu_type,
    f_pdu_name,
    f_nsvci,
    f_nsei,
    f_cause,
    f_sec_alert,
    f_payload
}

-- NS PDU Types (3GPP TS 48.016 Table 10.2)
local NS_PDUS = {
    [0x00] = "NS-UNITDATA",
    [0x02] = "NS-RESET",
    [0x03] = "NS-RESET-ACK",
    [0x04] = "NS-BLOCK",
    [0x05] = "NS-BLOCK-ACK",
    [0x06] = "NS-UNBLOCK",
    [0x07] = "NS-UNBLOCK-ACK",
    [0x08] = "NS-STATUS",
    [0x0A] = "NS-ALIVE",
    [0x0B] = "NS-ALIVE-ACK"
}

-- Native BSSGP dissector
local bssgp_dissector = Dissector.get("bssgp")

function gprs_ns_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 1 then return end

    pinfo.cols.protocol = "GPRS NS"

    local pdu_type = tvb(0, 1):uint()
    local pdu_name = NS_PDUS[pdu_type] or string.format("NS PDU (0x%02X)", pdu_type)

    local subtree = tree:add(gprs_ns_proto, tvb(), string.format("GPRS Network Service: %s", pdu_name))
    subtree:add(f_pdu_type, tvb(0, 1))
    subtree:add(f_pdu_name, pdu_name)

    pinfo.cols.info = string.format("[GPRS NS] %s", pdu_name)

    -- Security Heuristic 1: NS-RESET / NS-BLOCK Injection (Gb link tear-down)
    if pdu_type == 0x02 or pdu_type == 0x04 then
        subtree:add(f_sec_alert, "[CRITICAL] NS-RESET / NS-BLOCK commanded on GPRS backhaul! Tears down entire virtual connection between PCU and SGSN.")
        pinfo.cols.info:append(" [TELCOSEC: GB LINK RESET INJECTION]")
    end

    -- Security Heuristic 2: NS-STATUS with abnormal cause
    if pdu_type == 0x08 and tvb:len() >= 2 then
        local cause = tvb(1, 1):uint()
        subtree:add(f_cause, tvb(1, 1), cause)
        subtree:add(f_sec_alert, string.format("[WARNING] NS-STATUS error reported (Cause 0x%02X).", cause))
    end

    if pdu_type == 0x00 and tvb:len() >= 4 then
        -- NS-UNITDATA: [0]=PDU Type, [1]=NS SDU Control, [2-3]=BVCI
        local bvci = tvb(2, 2):uint()
        subtree:add(f_nsvci, tvb(2, 2), bvci)

        local sdu_offset = 4
        local sdu_len = tvb:len() - sdu_offset
        if sdu_len > 0 then
            local sdu_tvb = tvb(sdu_offset, sdu_len):tvb()
            if bssgp_dissector then
                bssgp_dissector:call(sdu_tvb, pinfo, tree)
            else
                subtree:add(f_payload, tvb(sdu_offset, sdu_len))
            end
        end
    else
        if tvb:len() > 1 then
            subtree:add(f_payload, tvb(1, tvb:len() - 1))
        end
    end
end

-- Register NS to standard UDP port 7777 / 23000 (standard GPRS NS-over-IP)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(7777, gprs_ns_proto)
    udp_table:add(23000, gprs_ns_proto)
end
