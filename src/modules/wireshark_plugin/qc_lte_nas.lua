-- TelcoSec.net - Qualcomm LTE NAS (EMM/ESM) OTA Dissector & Security Post-Dissector
-- Description: Dissects Qualcomm Log Code 0xB0E0 (LTE NAS Plain OTA) and 0xB0E1/0xB0E2 (Security Protected).
--              Analyzes EMM/ESM signaling for IMSI harvest probes, malicious Attach/TAU Rejections,
--              and Null-Ciphering (EEA0) configurations.

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

local ok, qc_lte_nas_proto = pcall(Proto, "qc_lte_nas", "Qualcomm LTE NAS Security Analyzer")
if not ok or not qc_lte_nas_proto then return end

-- Protocol fields
local f_direction     = ProtoField.string("qc_lte_nas.direction", "Direction")
local f_sec_hdr_type  = ProtoField.uint8("qc_lte_nas.sec_header_type", "Security Header Type", base.HEX)
local f_proto_disc    = ProtoField.uint8("qc_lte_nas.proto_disc", "Protocol Discriminator", base.HEX)
local f_msg_type      = ProtoField.uint8("qc_lte_nas.msg_type", "NAS Message Type", base.HEX)
local f_sec_alert     = ProtoField.string("qc_lte_nas.alert", "TelcoSec LTE NAS Alert")
local f_payload       = ProtoField.bytes("qc_lte_nas.payload", "NAS Payload")

qc_lte_nas_proto.fields = {
    f_direction,
    f_sec_hdr_type,
    f_proto_disc,
    f_msg_type,
    f_sec_alert,
    f_payload
}

-- LTE EMM Message Types
local EMM_MSG_TYPES = {
    [0x41] = "Attach Request",
    [0x42] = "Attach Accept",
    [0x43] = "Attach Complete",
    [0x44] = "Attach Reject",
    [0x45] = "Detach Request",
    [0x46] = "Detach Accept",
    [0x48] = "Tracking Area Update Request",
    [0x49] = "Tracking Area Update Accept",
    [0x4A] = "Tracking Area Update Complete",
    [0x4B] = "Tracking Area Update Reject",
    [0x52] = "Authentication Request",
    [0x53] = "Authentication Response",
    [0x54] = "Authentication Reject",
    [0x55] = "Identity Request",
    [0x56] = "Identity Response",
    [0x5D] = "Security Mode Command",
    [0x5E] = "Security Mode Complete"
}

-- Wireshark native NAS-EPS dissector
local nas_eps_dissector = Dissector.get("nas-eps")

function qc_lte_nas_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0xB0E0 / 0xB0E1 layout:
    -- [0]: Packet Version (1 byte)
    -- [1]: Direction (1 byte: 0=UL, 1=DL)
    -- [2-3]: Length (2 bytes LE)
    -- [4..N]: LTE NAS PDU
    if tvb:len() < 5 then return end

    pinfo.cols.protocol = "LTE NAS"

    local direction = tvb(1, 1):uint()
    local dir_str = (direction == 0) and "UL (UE -> MME)" or "DL (MME -> UE)"
    local nas_len = tvb(2, 2):le_uint()

    local subtree = tree:add(qc_lte_nas_proto, tvb(), string.format("Qualcomm LTE NAS OTA (%s, Len: %d)", dir_str, nas_len))
    subtree:add(f_direction, dir_str)

    local offset = 4
    local pdu_len = tvb:len() - offset

    if pdu_len >= 2 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()
        local sec_hdr = bit.rshift(pdu_tvb(0, 1):uint(), 4)
        local proto_disc = bit.band(pdu_tvb(0, 1):uint(), 0x0F)

        subtree:add(f_sec_hdr_type, sec_hdr)
        subtree:add(f_proto_disc, proto_disc)

        -- If plain NAS (Security Header Type == 0)
        local msg_offset = (sec_hdr == 0) and 1 or 6
        if pdu_len > msg_offset then
            local msg_type = pdu_tvb(msg_offset, 1):uint()
            local msg_name = EMM_MSG_TYPES[msg_type] or string.format("NAS Msg (0x%02X)", msg_type)

            subtree:add(f_msg_type, pdu_tvb(msg_offset, 1)):append_text(string.format(" (%s)", msg_name))
            pinfo.cols.info = string.format("[LTE NAS %s] %s", dir_str, msg_name)

            -- Security Heuristic 1: Identity Request probing for IMSI
            if msg_type == 0x55 then
                subtree:add(f_sec_alert, "[CRITICAL] Network-initiated Identity Request. Potential 4G IMSI Catcher probing subscriber identity!")
                pinfo.cols.info:append(" [TELCOSEC: IMSI HARVEST PROBE]")
            end

            -- Security Heuristic 2: Attach Reject / TAU Reject (Causing 2G Downgrade)
            if msg_type == 0x44 or msg_type == 0x4B then
                subtree:add(f_sec_alert, "[WARNING] Reject message received from network. Check EMM cause code for forced 2G downgrade.")
            end

            -- Security Heuristic 3: Unencrypted Security Mode Command
            if msg_type == 0x5D and sec_hdr == 0 then
                subtree:add(f_sec_alert, "[CRITICAL] Security Mode Command sent in plain unencrypted container!")
            end
        end

        -- Pass to native nas-eps dissector if available
        if nas_eps_dissector then
            nas_eps_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0xB0E0, qc_lte_nas_proto) -- LTE NAS Plain OTA
    qc_log_table:add(0xB0E1, qc_lte_nas_proto) -- LTE NAS Ciphered OTA
    qc_log_table:add(0xB0E2, qc_lte_nas_proto) -- LTE NAS Security Protected OTA
end
