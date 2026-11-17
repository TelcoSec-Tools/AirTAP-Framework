-- TelcoSec.net - Qualcomm 2G GSM Layer 3 / RR OTA Dissector & Security Post-Dissector
-- Description: Dissects Qualcomm Log Code 0x512F (GSM Layer 3 OTA), 0x5134 (GSM RR Signaling), and 0x5115 (Cell Info).
--              Detects 2G IMSI Catcher attacks forcing A5/0 (null cipher) or A5/1 (weak cipher),
--              fake Location Updating Rejects, and Silent SMS (Type 0) pings.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local chan_names = { [0]="BCCH", [1]="CCCH", [2]="SDCCH", [3]="SACCH", [4]="FACCH" }

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

local ok, qc_gsm_l3_proto = pcall(Proto, "qc_gsm_l3", "Qualcomm 2G GSM Layer 3 & RR Security Analyzer")
if not ok or not qc_gsm_l3_proto then return end

-- Protocol fields
local f_channel_type = ProtoField.string("qc_gsm_l3.chan_type", "Channel Type")
local f_arfcn        = ProtoField.uint16("qc_gsm_l3.arfcn", "ARFCN", base.DEC)
local f_proto_disc   = ProtoField.string("qc_gsm_l3.proto_disc", "Protocol Discriminator")
local f_msg_type     = ProtoField.uint8("qc_gsm_l3.msg_type", "GSM L3 Message Type", base.HEX)
local f_cipher_algo  = ProtoField.string("qc_gsm_l3.cipher_algo", "Ciphering Algorithm (A5)")
local f_sec_alert    = ProtoField.string("qc_gsm_l3.alert", "TelcoSec 2G Security Alert")
local f_payload      = ProtoField.bytes("qc_gsm_l3.payload", "GSM L3 Payload")

qc_gsm_l3_proto.fields = {
    f_channel_type,
    f_arfcn,
    f_proto_disc,
    f_msg_type,
    f_cipher_algo,
    f_sec_alert,
    f_payload
}

-- Protocol Discriminator Mapping
local GSM_PROTO_DISC = {
    [0x03] = "Call Control (CC)",
    [0x05] = "Mobility Management (MM)",
    [0x06] = "Radio Resource Management (RR)",
    [0x09] = "SMS Messages (SMS)",
    [0x0B] = "Non-Call Related SS"
}

-- GSM RR Message Types
local GSM_RR_MSG_TYPES = {
    [0x35] = "Ciphering Mode Command",
    [0x32] = "Ciphering Mode Complete",
    [0x3B] = "Immediate Assignment",
    [0x0D] = "Paging Request Type 1",
    [0x0E] = "Paging Request Type 2",
    [0x0F] = "Paging Request Type 3",
    [0x1A] = "System Information Type 1",
    [0x1B] = "System Information Type 2",
    [0x1C] = "System Information Type 3",
    [0x1D] = "System Information Type 4"
}

-- Wireshark native GSM L3 dissectors
local gsm_a_ccch_dissector = Dissector.get("gsm_a_ccch")
local gsm_a_dtap_dissector = Dissector.get("gsm_a_dtap")

function qc_gsm_l3_proto.dissector(tvb, pinfo, tree)
    -- Qualcomm 0x512F / 0x5134 layout:
    -- [0]: Packet Version (1 byte)
    -- [1]: Channel Type (1 byte: BCCH, CCCH, SDCCH, SACCH, FACCH)
    -- [2-3]: ARFCN (2 bytes LE)
    -- [4]: Message Length (1 byte)
    -- [5..N]: 3GPP TS 24.008 / 44.018 GSM L3 Frame
    if tvb:len() < 5 then return end

    pinfo.cols.protocol = "GSM L3"

    local chan_id = tvb(1, 1):uint()
    local raw_arfcn = tvb(2, 2):le_uint()
    local arfcn = bit.band(raw_arfcn, 0x3FFF)
    local msg_len = tvb(4, 1):uint()

    local chan_str = chan_names[chan_id] or string.format("Chan %d", chan_id)

    local subtree = tree:add(qc_gsm_l3_proto, tvb(), string.format("Qualcomm GSM L3 OTA (%s, ARFCN: %d)", chan_str, arfcn))
    subtree:add(f_channel_type, chan_str)
    subtree:add(f_arfcn, tvb(2, 2), arfcn)

    local offset = 5
    local pdu_len = tvb:len() - offset

    if pdu_len >= 2 then
        local pdu_tvb = tvb(offset, pdu_len):tvb()
        local pd_val = bit.band(pdu_tvb(0, 1):uint(), 0x0F)
        local pd_name = GSM_PROTO_DISC[pd_val] or string.format("PD 0x%02X", pd_val)
        subtree:add(f_proto_disc, pd_name)

        local msg_type = pdu_tvb(1, 1):uint()
        local msg_name = (pd_val == 0x06 and GSM_RR_MSG_TYPES[msg_type]) or string.format("Msg 0x%02X", msg_type)
        subtree:add(f_msg_type, pdu_tvb(1, 1)):append_text(string.format(" (%s)", msg_name))

        pinfo.cols.info = string.format("[QC GSM %s] %s | %s", chan_str, pd_name, msg_name)

        -- Security Heuristic 1: Ciphering Mode Command - A5/0 (No Encryption) or A5/1 (Broken)
        if pd_val == 0x06 and msg_type == 0x35 and pdu_len >= 3 then
            local cipher_setting = pdu_tvb(2, 1):uint()
            local cipher_algorithm = bit.rshift(bit.band(cipher_setting, 0x0E), 1)
            local cipher_start = bit.band(cipher_setting, 0x01)

            if cipher_start == 0 or cipher_algorithm == 0 then
                subtree:add(f_cipher_algo, "A5/0 (No Ciphering / Plaintext)")
                subtree:add(f_sec_alert, "[CRITICAL] Network forced A5/0 (No Encryption)! 2G IMSI Catcher active intercepting calls/SMS.")
                pinfo.cols.info:append(" [TELCOSEC: A5/0 NULL-CIPHER!]")
            elseif cipher_algorithm == 1 then
                subtree:add(f_cipher_algo, "A5/1 (Weak / Broken Cipher)")
                subtree:add(f_sec_alert, "[WARNING] A5/1 Cipher negotiated. Vulnerable to real-time cracking.")
            elseif cipher_algorithm == 2 then
                subtree:add(f_cipher_algo, "A5/2 (Export / Insecure Cipher)")
                subtree:add(f_sec_alert, "[CRITICAL] Deprecated A5/2 cipher commanded.")
            else
                subtree:add(f_cipher_algo, string.format("A5/%d", cipher_algorithm))
            end
        end

        -- Security Heuristic 2: Silent SMS / Type 0 ping detection.
        -- Handled by telcosec_vuln_audit_engine.lua (TELCOSEC-VULN-008), which
        -- post-dissects the native gsm_sms.tp_pid field and tests it for 0x40
        -- exactly. TP-PID sits after a variable-length address field, so its
        -- offset cannot be assumed; the native gsm_a_dtap dissector invoked
        -- below parses the TPDU and exposes the field.
        --
        -- The previous check here searched a hex dump of the whole L3 PDU for
        -- "40"/"c0" anywhere, unanchored. A single-byte pattern appears in
        -- roughly one in six arbitrary PDUs by chance, so ordinary SMS traffic
        -- was reported as covert location tracking.

        -- Delegate to native GSM dissectors
        if (chan_id == 0 or chan_id == 1) and gsm_a_ccch_dissector then
            gsm_a_ccch_dissector:call(pdu_tvb, pinfo, tree)
        elseif gsm_a_dtap_dissector then
            gsm_a_dtap_dissector:call(pdu_tvb, pinfo, tree)
        else
            subtree:add(f_payload, tvb(offset, pdu_len))
        end
    end
end

-- Register to Qualcomm DIAG Log Code table
local qc_log_table = DissectorTable.get("qc_diag.log_code")
if qc_log_table then
    qc_log_table:add(0x512F, qc_gsm_l3_proto) -- GSM L3 OTA
    qc_log_table:add(0x5134, qc_gsm_l3_proto) -- GSM RR Signaling
    qc_log_table:add(0x5115, qc_gsm_l3_proto) -- GSM Surrounding Cell Info
end
