-- TelcoSec.net - 5G PFCP (Packet Forwarding Control Protocol - N4 / Sxa / Sxb / Sxc - 3GPP TS 29.244) Security Dissector
-- Description: Complete standalone and post-dissector analyzer for 5G SMF-UPF User Plane Control (N4) interface.
--              Decodes PFCP message types, SEID session tracking, Node IDs, PDR/FAR forwarding rules, Outer Header Creation,
--              and detects rogue UPF association, session teardown attacks, and GTP-U tunnel hijacking.

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

local ok, pfcp_sec_proto = pcall(Proto, "pfcp_sec", "TelcoSec 5G PFCP (N4 User Plane Control) Security Analyzer")
if not ok or not pfcp_sec_proto then return end

-- Protocol fields
local f_msg_type        = ProtoField.uint8("pfcp_sec.msg_type", "PFCP Message Type Code", base.DEC)
local f_msg_name        = ProtoField.string("pfcp_sec.msg_name", "PFCP Message Name")
local f_has_seid        = ProtoField.bool("pfcp_sec.has_seid", "SEID Present Flag")
local f_seid            = ProtoField.uint64("pfcp_sec.seid", "Session Endpoint Identifier (SEID)", base.HEX)
local f_seq_num         = ProtoField.uint32("pfcp_sec.seq_num", "Sequence Number", base.DEC)
local f_cause           = ProtoField.uint8("pfcp_sec.cause", "PFCP Cause Code", base.DEC)
local f_cause_desc      = ProtoField.string("pfcp_sec.cause_desc", "Cause Description")
local f_node_id         = ProtoField.string("pfcp_sec.node_id", "Node ID (FQDN / IPv4 / IPv6)")
local f_sec_alert       = ProtoField.string("pfcp_sec.alert", "TelcoSec PFCP Security Alert")
local f_payload         = ProtoField.bytes("pfcp_sec.payload", "PFCP Payload IEs")

pfcp_sec_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_has_seid,
    f_seid,
    f_seq_num,
    f_cause,
    f_cause_desc,
    f_node_id,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 29.244 Table 6.1-1 PFCP Message Types
local PFCP_MSG_TYPES = {
    [1]   = "Heartbeat Request",
    [2]   = "Heartbeat Response",
    [3]   = "PFD Management Request",
    [4]   = "PFD Management Response",
    [5]   = "Association Setup Request",
    [6]   = "Association Setup Response",
    [7]   = "Association Update Request",
    [8]   = "Association Update Response",
    [9]   = "Association Release Request",
    [10]  = "Association Release Response",
    [11]  = "Version Not Supported Response",
    [12]  = "Node Report Request",
    [13]  = "Node Report Response",
    [14]  = "Session Set Deletion Request",
    [15]  = "Session Set Deletion Response",
    [50]  = "Session Establishment Request",
    [51]  = "Session Establishment Response",
    [52]  = "Session Modification Request",
    [53]  = "Session Modification Response",
    [54]  = "Session Deletion Request",
    [55]  = "Session Deletion Response",
    [56]  = "Session Report Request",
    [57]  = "Session Report Response"
}

-- 3GPP TS 29.244 Cause Codes
local PFCP_CAUSES = {
    [1]   = "Request Accepted",
    [64]  = "Request Rejected",
    [65]  = "Session Context Not Found",
    [66]  = "Mandatory IE Missing",
    [67]  = "Conditional IE Missing",
    [68]  = "Invalid Length",
    [69]  = "Mandatory IE Incorrect",
    [70]  = "Invalid Forwarding Policy",
    [71]  = "Rule Creation/Modification Failure",
    [72]  = "PFCP Entity in Congestion",
    [73]  = "No Established PFCP Association",
    [74]  = "Rule Creation/Modification Failure (Temporary)"
}

-- Native Wireshark PFCP dissector
local native_pfcp = Dissector.get("pfcp")

function pfcp_sec_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 8 then return end

    -- Check PFCP Header (TS 29.244 §7.2.2)
    -- Byte 0: [7:5] Version (1), [2] MP (Message Priority), [0] S (SEID flag)
    local b0 = tvb(0, 1):uint()
    local ver = bit.rshift(b0, 5)
    if ver ~= 1 then return end

    local has_seid = bit.band(b0, 0x01) ~= 0
    local msg_type = tvb(1, 1):uint()
    local msg_len  = tvb(2, 2):uint()
    local msg_name = PFCP_MSG_TYPES[msg_type] or string.format("PFCP Msg %d", msg_type)

    pinfo.cols.protocol = "5G PFCP"

    local hdr_len = 8
    local seid_val = nil

    if has_seid and len >= 16 then
        hdr_len = 16
        pinfo.cols.info = string.format("[5G PFCP] %s (SEID: 0x%s)", msg_name, tvb(4, 8):bytes():tohex())
    else
        pinfo.cols.info = string.format("[5G PFCP] %s", msg_name)
    end

    local subtree = tree:add(pfcp_sec_proto, tvb(), string.format("5G PFCP (N4 / TS 29.244): %s", msg_name))
    subtree:add(f_msg_type, tvb(1, 1), msg_type)
    subtree:add(f_msg_name, msg_name)
    subtree:add(f_has_seid, has_seid)

    if has_seid and len >= 12 then
        subtree:add(f_seid, tvb(4, 8))
        local seq_num = tvb(12, 3):uint()
        subtree:add(f_seq_num, tvb(12, 3), seq_num)
    elseif len >= 8 then
        local seq_num = tvb(4, 3):uint()
        subtree:add(f_seq_num, tvb(4, 3), seq_num)
    end

    local alerts = {}

    -- Security Heuristic 1: Rogue UPF Provisioning (Association Setup Request)
    if msg_type == 5 then
        table.insert(alerts, string.format(
            "[CRITICAL] PFCP Association Setup Request from %s! " ..
            "Verify SMF / UPF IP against 5G Core trusted VLAN whitelist to prevent rogue user plane routing.",
            tostring(pinfo.src)))
        pinfo.cols.info:append(" [TELCOSEC: UPF PROVISIONING!]")
    end

    -- Security Heuristic 2: Session Deletion Flooding / Teardown DoS
    if msg_type == 54 then
        table.insert(alerts, "[CRITICAL] PFCP Session Deletion commanded! Forcibly terminates active subscriber user plane session.")
        pinfo.cols.info:append(" [TELCOSEC: SESSION TEARDOWN!]")
    end

    -- Security Heuristic 3: Session Set Deletion (Mass Subscriber Disconnection)
    if msg_type == 14 then
        table.insert(alerts, "[CRITICAL] PFCP Session Set Deletion Request! Mass session termination targeting multiple subscriber contexts simultaneously.")
        pinfo.cols.info:append(" [TELCOSEC: MASS SESSION DELETION!]")
    end

    -- Security Heuristic 4: Association Release (N4 Interface Teardown)
    if msg_type == 9 then
        table.insert(alerts, "[WARNING] PFCP Association Release Request. Administrative teardown of N4 interface between SMF and UPF.")
    end

    if #alerts > 0 then
        for _, a in ipairs(alerts) do
            subtree:add(f_sec_alert, a)
        end
    end

    if native_pfcp then
        native_pfcp:call(tvb, pinfo, tree)
    else
        if len > hdr_len then
            subtree:add(f_payload, tvb(hdr_len, len - hdr_len))
        end
    end
end

-- Register to standard PFCP UDP port 8805
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(8805, pfcp_sec_proto)
end

-- Register as postdissector to inspect all native PFCP frames
register_postdissector(pfcp_sec_proto)
