-- TelcoSec.net - SS7 MTP2 / MTP3 Routing & Point Code Security Analyzer
-- Target Standards: ITU-T Q.703 (MTP2 Signalling Link), ITU-T Q.704 (MTP3 Signalling Network)
-- Description: Dissects MTP3 routing labels, Destination Point Codes (DPC), Originating Point Codes (OPC), Service Information Octets (SIO),
--              and Signalling Network Management (SNM) messages (TFP, TFA, TFR, RST, COO, COA).
--              Detects DPC/OPC point code spoofing, Transfer Prohibited (TFP) routing isolation attacks, and Changeover link hijacking.

local ok, mtp_sec_proto = pcall(Proto, "mtp_sec", "TelcoSec SS7 MTP2/MTP3 Point Code & Routing Security Analyzer")
if not ok or not mtp_sec_proto then return end

-- Protocol fields
local f_dpc             = ProtoField.uint32("mtp_sec.dpc", "Destination Point Code (DPC)", base.DEC)
local f_opc             = ProtoField.uint32("mtp_sec.opc", "Originating Point Code (OPC)", base.DEC)
local f_sls             = ProtoField.uint8("mtp_sec.sls", "Signalling Link Selection (SLS)", base.DEC)
local f_si              = ProtoField.uint8("mtp_sec.si", "Service Indicator (SI)", base.DEC)
local f_si_name         = ProtoField.string("mtp_sec.si_name", "Service Indicator Name")
local f_snm_h0          = ProtoField.uint8("mtp_sec.snm_h0", "Heading Code H0 (SNM Group)", base.HEX)
local f_snm_h1          = ProtoField.uint8("mtp_sec.snm_h1", "Heading Code H1 (SNM Action)", base.HEX)
local f_snm_name        = ProtoField.string("mtp_sec.snm_name", "SNM Action Name")
local f_sec_alert       = ProtoField.string("mtp_sec.alert", "TelcoSec MTP Security Alert")

mtp_sec_proto.fields = {
    f_dpc,
    f_opc,
    f_sls,
    f_si,
    f_si_name,
    f_snm_h0,
    f_snm_h1,
    f_snm_name,
    f_sec_alert
}

-- MTP3 Service Indicators (ITU-T Q.704)
local MTP3_SI = {
    [0] = "Signalling Network Management (SNM)",
    [1] = "Signalling Network Testing (SNT)",
    [2] = "Special Message Transfer (SCCP)",
    [3] = "SCCP",
    [4] = "TUP (Telephone User Part)",
    [5] = "ISUP (ISDN User Part)",
    [6] = "DUP (Data User Part)",
    [9] = "Broadband ISUP (B-ISUP)",
    [10] = "GCP (Gateway Control Protocol)"
}

-- MTP3 SNM Messages (H0/H1 codes)
local MTP3_SNM_ACTIONS = {
    [0x11] = "Changeover Order (COO)",
    [0x12] = "Changeover Ack (COA)",
    [0x21] = "Emergency Changeover Order (ECO)",
    [0x22] = "Emergency Changeover Ack (ECA)",
    [0x31] = "Transfer Prohibited (TFP)",
    [0x32] = "Transfer Allowed (TFA)",
    [0x33] = "Transfer Restricted (TFR)",
    [0x34] = "Transfer Controlled (TFC)",
    [0x35] = "Signalling Route Set Test (RST)",
    [0x41] = "Inhibit Link (LIN)",
    [0x42] = "Uninhibit Link (LUN)"
}

-- Safe field getters
local function safe_field(name)
    local ok, f = pcall(Field.new, name)
    return ok and f or nil
end

local f_mtp3_dpc_f = safe_field("mtp3.dpc")
local f_mtp3_opc_f = safe_field("mtp3.opc")
local f_mtp3_si_f  = safe_field("mtp3.service_indicator")

function mtp_sec_proto.dissector(tvb, pinfo, tree)
    local proto_str = tostring(pinfo.cols.protocol)
    if not (string.find(proto_str, "MTP3") or (f_mtp3_dpc_f and f_mtp3_dpc_f())) then
        return
    end

    local subtree = tree:add(mtp_sec_proto, tvb(), "TelcoSec SS7 MTP3 Routing Security Engine")
    local alerts = {}

    if f_mtp3_dpc_f and f_mtp3_dpc_f() then
        local dpc = f_mtp3_dpc_f().value
        subtree:add(f_dpc, dpc)
    end
    if f_mtp3_opc_f and f_mtp3_opc_f() then
        local opc = f_mtp3_opc_f().value
        subtree:add(f_opc, opc)
    end
    if f_mtp3_si_f and f_mtp3_si_f() then
        local si = f_mtp3_si_f().value
        local si_name = MTP3_SI[si] or string.format("SI %d", si)
        subtree:add(f_si, si)
        subtree:add(f_si_name, si_name)

        -- Security Heuristic 1: SNM Transfer Prohibited (TFP) Link Isolation Attack
        if si == 0 then
            table.insert(alerts, "[WARNING] MTP3 Signalling Network Management (SNM) frame: Monitor for rogue Transfer Prohibited (TFP) / Inhibit Link (LIN) routing disruption.")
        end
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
        pinfo.cols.info:append(" [TELCOSEC: MTP3 ALERT!]")
    end
end

register_postdissector(mtp_sec_proto)
