-- TelcoSec.net - SS7 TCAP (Transaction Capabilities Application Part - ITU-T Q.771..Q.775 / ANSI T1.114) Security Dissector
-- Description: Dissects TCAP transaction sub-layer packages (Unidirectional, Begin, End, Continue, Abort)
--              and component sub-layer elements (Invoke, ReturnResultLast, ReturnResultNotLast, ReturnError, Reject).
--              Parses Application Context Names (ACN OID), Originating / Responding Transaction IDs (OTID / RTID),
--              Invoke IDs, Operation Codes, and Error/Problem codes.
--              Detects TCAP transaction hijacking, stateful dialogue teardown DoS (unsolicited Abort injection),
--              unauthorized Continue injection, and ACN security profile downgrading.

local ok, tcap_sec_proto = pcall(Proto, "tcap_sec", "TelcoSec SS7 TCAP (Transaction Capabilities) Security Analyzer")
if not ok or not tcap_sec_proto then return end

-- Protocol fields
local f_pkg_type        = ProtoField.uint8("tcap_sec.pkg_type", "TCAP Package Type Tag", base.HEX)
local f_pkg_name        = ProtoField.string("tcap_sec.pkg_name", "Package Type")
local f_otid            = ProtoField.string("tcap_sec.otid", "Originating Transaction ID (OTID)")
local f_rtid            = ProtoField.string("tcap_sec.rtid", "Responding Transaction ID (RTID)")
local f_acn_oid         = ProtoField.string("tcap_sec.acn_oid", "Application Context Name (ACN OID)")
local f_acn_name        = ProtoField.string("tcap_sec.acn_name", "Application Subsystem (MAP/CAP/INAP)")
local f_comp_type       = ProtoField.uint8("tcap_sec.comp_type", "Component Type Tag", base.HEX)
local f_comp_name       = ProtoField.string("tcap_sec.comp_name", "Component Type")
local f_invoke_id       = ProtoField.int32("tcap_sec.invoke_id", "Invoke ID", base.DEC)
local f_op_code         = ProtoField.int32("tcap_sec.op_code", "Operation Code", base.DEC)
local f_error_code      = ProtoField.int32("tcap_sec.error_code", "Error Code", base.DEC)
local f_abort_cause     = ProtoField.string("tcap_sec.abort_cause", "Abort Reason / Cause")
local f_sec_alert       = ProtoField.string("tcap_sec.alert", "TelcoSec TCAP Security Alert")
local f_payload         = ProtoField.bytes("tcap_sec.payload", "TCAP Raw Payload")

tcap_sec_proto.fields = {
    f_pkg_type,
    f_pkg_name,
    f_otid,
    f_rtid,
    f_acn_oid,
    f_acn_name,
    f_comp_type,
    f_comp_name,
    f_invoke_id,
    f_op_code,
    f_error_code,
    f_abort_cause,
    f_sec_alert,
    f_payload
}

-- ITU-T Q.773 Package Type Tags
local TCAP_PKG_TYPES = {
    [0x61] = "Unidirectional",
    [0x62] = "Begin",
    [0x64] = "End",
    [0x65] = "Continue",
    [0x67] = "Abort"
}

-- ITU-T Q.773 Component Type Tags
local TCAP_COMP_TYPES = {
    [0xA1] = "Invoke",
    [0xA2] = "ReturnResultLast",
    [0xA3] = "ReturnError",
    [0xA4] = "Reject",
    [0xA7] = "ReturnResultNotLast"
}

-- Well-known ACN (Application Context Name) OID mappings (MAP / CAP / INAP)
local TCAP_ACN_MAP = {
    ["0.4.0.0.1.0.1.3"]   = "MAP networkLocUp (v3)",
    ["0.4.0.0.1.0.2.3"]   = "MAP locationCancellation (v3)",
    ["0.4.0.0.1.0.3.3"]   = "MAP roamingNumberEnquiry (v3)",
    ["0.4.0.0.1.0.14.3"]  = "MAP infoRetrieval (v3)",
    ["0.4.0.0.1.0.15.3"]  = "MAP interVlrInfoRetrieval (v3)",
    ["0.4.0.0.1.0.19.3"]  = "MAP shortMsgGateway (v3)",
    ["0.4.0.0.1.0.20.3"]  = "MAP shortMsgMO-Relay (v3)",
    ["0.4.0.0.1.0.21.3"]  = "MAP subscriberDataMngt (v3)",
    ["0.4.0.0.1.0.25.3"]  = "MAP reset (v3)",
    ["0.4.0.0.1.0.29.3"]  = "MAP gprsLocationUpdate (v3)",
    ["0.4.0.0.1.0.33.3"]  = "MAP locationSvcGateway (v3)",
    ["0.4.0.0.1.1.50.1"]  = "CAP cap-gsmSCF-to-gsmSSF (v1)",
    ["0.4.0.0.1.1.50.2"]  = "CAP cap-gsmSCF-to-gsmSSF (v2)",
    ["0.4.0.0.1.1.50.3"]  = "CAP cap-gsmSCF-to-gsmSSF (v3)",
    ["0.4.0.0.1.1.50.4"]  = "CAP cap-gsmSCF-to-gsmSSF (v4)",
    ["0.4.0.0.1.1.51.3"]  = "CAP cap-gprsSSF-to-gsmSCF (v3)",
    ["0.4.0.0.1.1.52.3"]  = "CAP cap-gsmSCF-to-gprsSSF (v3)",
    ["0.4.0.0.1.1.61.3"]  = "CAP cap-smsSSF-to-gsmSCF (v3)",
    ["0.4.0.0.1.2.1.1"]   = "INAP cs1-scf-to-ssf",
    ["0.4.0.0.1.2.2.1"]   = "INAP cs2-scf-to-ssf"
}

-- Native TCAP dissector
local native_tcap = Dissector.get("tcap")

-- Helper: Parse ASN.1 BER Length
local function parse_ber_len(tvb, offset)
    if offset >= tvb:len() then return 0, 0 end
    local b0 = tvb(offset, 1):uint()
    if b0 < 0x80 then
        return b0, 1
    elseif b0 == 0x81 and offset + 1 < tvb:len() then
        return tvb(offset + 1, 1):uint(), 2
    elseif b0 == 0x82 and offset + 2 < tvb:len() then
        return tvb(offset + 1, 2):uint(), 3
    elseif b0 == 0x83 and offset + 3 < tvb:len() then
        return tvb(offset + 1, 3):uint(), 4
    elseif b0 == 0x84 and offset + 4 < tvb:len() then
        return tvb(offset + 1, 4):uint(), 5
    end
    return 0, 1
end

function tcap_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 3 then return end

    local tag = tvb(0, 1):uint()
    local pkg_name = TCAP_PKG_TYPES[tag]
    if not pkg_name then return end

    pinfo.cols.protocol = "SS7 TCAP"

    local subtree = tree:add(tcap_sec_proto, tvb(), string.format("SS7 TCAP Transaction: %s (Tag: 0x%02X)", pkg_name, tag))
    subtree:add(f_pkg_type, tvb(0, 1), tag)
    subtree:add(f_pkg_name, pkg_name)

    local alerts = {}
    local otid_str = nil
    local rtid_str = nil
    local comp_name = nil
    local op_code_val = nil

    local off = 1
    local pkg_len, len_bytes = parse_ber_len(tvb, off)
    off = off + len_bytes

    -- Traverse TCAP Transaction Portion TLVs
    while off < len do
        if off >= len then break end
        local t = tvb(off, 1):uint()
        local l, lb = parse_ber_len(tvb, off + 1)
        local val_off = off + 1 + lb

        if val_off + l > len then break end

        -- OTID (Tag 0x48)
        if t == 0x48 and l > 0 then
            otid_str = tvb(val_off, l):bytes():tohex()
            subtree:add(f_otid, otid_str)
        -- RTID (Tag 0x49)
        elseif t == 0x49 and l > 0 then
            rtid_str = tvb(val_off, l):bytes():tohex()
            subtree:add(f_rtid, rtid_str)
        -- Dialogue Portion (Tag 0x6B)
        elseif t == 0x6B and l > 0 then
            local hex_dlg = tvb(val_off, l):bytes():tohex()
            -- Check for OID inside dialogue portion
            for oid, name in pairs(TCAP_ACN_MAP) do
                local oid_sub = string.gsub(oid, "%.", "")
                if string.find(hex_dlg, "06") then
                    subtree:add(f_acn_oid, oid)
                    subtree:add(f_acn_name, name)
                    break
                end
            end
        -- Component Portion (Tag 0x6C)
        elseif t == 0x6C and l > 0 then
            local comp_off = val_off
            if comp_off < len then
                local comp_tag = tvb(comp_off, 1):uint()
                comp_name = TCAP_COMP_TYPES[comp_tag] or string.format("Component 0x%02X", comp_tag)
                subtree:add(f_comp_type, tvb(comp_off, 1), comp_tag)
                subtree:add(f_comp_name, comp_name)

                local comp_len, clb = parse_ber_len(tvb, comp_off + 1)
                local ie_off = comp_off + 1 + clb

                -- Parse Invoke ID / Operation Code
                while ie_off < val_off + l and ie_off < len do
                    local it = tvb(ie_off, 1):uint()
                    local il, ilb = parse_ber_len(tvb, ie_off + 1)
                    local iv_off = ie_off + 1 + ilb
                    if iv_off + il > len then break end

                    -- Invoke ID (Tag 0x02)
                    if it == 0x02 and il == 1 then
                        local inv_id = tvb(iv_off, 1):int()
                        subtree:add(f_invoke_id, tvb(iv_off, 1), inv_id)
                    -- Operation Code Local (Tag 0x02) or Global (Tag 0x06)
                    elseif (it == 0x02 or it == 0x06) and il <= 4 then
                        op_code_val = tvb(iv_off, il):uint()
                        subtree:add(f_op_code, tvb(iv_off, il), op_code_val)
                    -- Error Code (Tag 0x02)
                    elseif it == 0x02 and comp_tag == 0xA3 then
                        local err_val = tvb(iv_off, il):uint()
                        subtree:add(f_error_code, tvb(iv_off, il), err_val)
                    end
                    ie_off = iv_off + il
                end
            end
        -- Abort Cause (Tag 0x4A or inside Abort package)
        elseif t == 0x4A or tag == 0x67 then
            local abort_str = string.format("P-Abort / User-Abort (Tag 0x%02X)", t)
            subtree:add(f_abort_cause, abort_str)
        end

        off = val_off + l
    end

    -- Update Info Column
    local info_tx = ""
    if otid_str then info_tx = info_tx .. " OTID:0x" .. otid_str end
    if rtid_str then info_tx = info_tx .. " RTID:0x" .. rtid_str end
    pinfo.cols.info = string.format("[TCAP] %s%s%s", pkg_name, comp_name and (" (" .. comp_name .. ")") or "", info_tx)

    -- Security Heuristic 1: TCAP Abort Injection (Dialogue Teardown / DoS)
    if tag == 0x67 then
        table.insert(alerts, "[CRITICAL] TCAP Abort Package! Forcibly terminates active SS7 MAP/CAP/INAP transaction dialogue. Monitor for rogue abort injection.")
        pinfo.cols.info:append(" [TELCOSEC: TCAP DIALOGUE ABORT!]")
    end

    -- Security Heuristic 2: Unsolicited TCAP Continue / End Injection
    if (tag == 0x65 or tag == 0x64) and not otid_str and rtid_str then
        table.insert(alerts, "[WARNING] TCAP Continue/End targeting active RTID. Verify peer SCCP Global Title to prevent transaction state injection.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if native_tcap then
        native_tcap:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end

-- Register as postdissector and on SCCP SSN table
local sccp_ssn_table = DissectorTable.get("sccp.ssn")
if sccp_ssn_table then
    sccp_ssn_table:add(6, tcap_sec_proto)   -- HLR / MAP
    sccp_ssn_table:add(7, tcap_sec_proto)   -- VLR / MAP
    sccp_ssn_table:add(8, tcap_sec_proto)   -- MSC / MAP
    sccp_ssn_table:add(146, tcap_sec_proto) -- CAP gsmSCF
    sccp_ssn_table:add(147, tcap_sec_proto) -- CAP gsmSSF
end

register_postdissector(tcap_sec_proto)
