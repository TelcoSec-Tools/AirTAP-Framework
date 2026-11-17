-- TelcoSec.net - GPRS Mobility & Session Management (GMM/SM) Security Dissector
-- Description: Dissects GPRS GMM/SM signaling (3GPP TS 24.008).
--              Inspects GPRS Attach, Routing Area Update (RAU), and PDP Context Activation.
--              Detects fake SGSN rogue attachments and malicious PDP context teardowns.

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

local ok, gprs_gmm_proto = pcall(Proto, "gprs_gmm_sm_sec", "TelcoSec GPRS GMM/SM Security Analyzer")
if not ok or not gprs_gmm_proto then return end

-- Protocol fields
local f_proto_disc   = ProtoField.string("gprs_gmm_sm_sec.proto_disc", "Protocol Discriminator")
local f_msg_type     = ProtoField.uint8("gprs_gmm_sm_sec.msg_type", "Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gprs_gmm_sm_sec.msg_name", "Message Name")
local f_ptmsi        = ProtoField.string("gprs_gmm_sm_sec.ptmsi", "Allocated P-TMSI")
local f_apn          = ProtoField.string("gprs_gmm_sm_sec.apn", "Access Point Name (APN)")
local f_cipher_algo  = ProtoField.string("gprs_gmm_sm_sec.cipher_algo", "Negotiated GEA Cipher")
local f_sec_alert    = ProtoField.string("gprs_gmm_sm_sec.alert", "TelcoSec GPRS Security Alert")
local f_payload      = ProtoField.bytes("gprs_gmm_sm_sec.payload", "GMM/SM Raw Payload")

gprs_gmm_proto.fields = {
    f_proto_disc,
    f_msg_type,
    f_msg_name,
    f_ptmsi,
    f_apn,
    f_cipher_algo,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 24.008 10.5.5.3, table 10.5.136: "Type of algorithm", bits 3..1 of
-- the Ciphering algorithm IE. 000 means ciphering is not applied at all.
local GEA_ALGORITHMS = {
    [0] = "GEA0 (No Encryption / Plaintext)",
    [1] = "GEA1 (Cryptographically Broken - 40-bit effective key)",
    [2] = "GEA2 (Legacy 64-bit Cipher)",
    [3] = "GEA3 (128-bit Kasumi)",
    [4] = "GEA4 (128-bit)",
    [5] = "GEA5 (128-bit SNOW 3G)",
    [6] = "GEA6 (128-bit)",
    [7] = "GEA7 (128-bit)"
}

-- GPRS GMM/SM Message Types
local GMM_SM_MSG_TYPES = {
    -- GMM (PD 8)
    [0x01] = "Attach Request",
    [0x02] = "Attach Accept",
    [0x03] = "Attach Complete",
    [0x04] = "Attach Reject",
    [0x05] = "Detach Request",
    [0x06] = "Detach Accept",
    [0x08] = "Routing Area Update Request",
    [0x09] = "Routing Area Update Accept",
    [0x0A] = "Routing Area Update Complete",
    [0x0B] = "Routing Area Update Reject",
    [0x12] = "Authentication and Ciphering Request",
    [0x13] = "Authentication and Ciphering Response",
    [0x14] = "Authentication and Ciphering Reject",
    -- SM (PD 10)
    [0x41] = "Activate PDP Context Request",
    [0x42] = "Activate PDP Context Accept",
    [0x43] = "Activate PDP Context Reject",
    [0x44] = "Deactivate PDP Context Request",
    [0x45] = "Deactivate PDP Context Accept"
}

function gprs_gmm_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    local pd = bit.band(tvb(0, 1):uint(), 0x0F)
    local msg_type = tvb(1, 1):uint()

    -- PD 8 = GPRS Mobility Management (GMM), PD 10 = GPRS Session Management (SM)
    if pd ~= 8 and pd ~= 10 then return end

    pinfo.cols.protocol = "GPRS GMM/SM"

    local pd_str = (pd == 8) and "GMM (Mobility)" or "SM (Session)"
    local msg_name = GMM_SM_MSG_TYPES[msg_type] or string.format("GPRS Msg (0x%02X)", msg_type)

    local subtree = tree:add(gprs_gmm_proto, tvb(), string.format("GPRS %s: %s", pd_str, msg_name))
    subtree:add(f_proto_disc, pd_str)
    subtree:add(f_msg_type, tvb(1, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GPRS %s] %s", pd_str, msg_name)

    -- Security Heuristic 1: Attach Reject or RAU Reject
    if msg_type == 0x04 or msg_type == 0x0B then
        subtree:add(f_sec_alert, "[WARNING] GPRS Attach/RAU Reject received. Base station denying packet data services.")
    end

    -- Security Heuristic 2: Plaintext IMSI in Attach Request
    if msg_type == 0x01 and tvb:len() >= 8 then
        local raw_id_type = bit.band(tvb(2, 1):uint(), 0x07)
        if raw_id_type == 1 then
            subtree:add(f_sec_alert, "[CRITICAL] Plaintext IMSI transmitted in GPRS Attach Request!")
            pinfo.cols.info:append(" [TELCOSEC: PLAIN IMSI IN GPRS ATTACH]")
        end
    end

    -- Security Heuristic 3: GEA cipher selection in Authentication & Ciphering
    -- Request. This is where GPRS ciphering is actually negotiated: 3GPP
    -- TS 24.008 table 9.4.9 puts the Ciphering algorithm IE (10.5.5.3) in the
    -- lower half of octet 3, immediately after the message type, as a type 1
    -- IE. Bits 3..1 carry the algorithm and bit 4 is spare.
    --
    -- Read at its defined offset rather than searched for. An earlier revision
    -- scanned a hex dump of LLC frames for the substring "0000", which was
    -- wrong twice over: unanchored matching flagged benign frames, and LLC XID
    -- carries no ciphering parameter at all (TS 44.064 XID types are version,
    -- IOV, T200, N200, N201, mD/mU, kD/kU, Layer-3 and Reset).
    if msg_type == 0x12 and tvb:len() >= 3 then
        local gea = bit.band(tvb(2, 1):uint(), 0x07)
        local gea_name = GEA_ALGORITHMS[gea] or string.format("GEA%d (unknown)", gea)
        subtree:add(f_cipher_algo, gea_name)
        pinfo.cols.info:append(string.format(" (%s)", gea_name))

        if gea == 0 then
            subtree:add(f_sec_alert, "[CRITICAL] Network commanded GEA0 (Null Encryption)! All GPRS user data, DNS and IP traffic will be transmitted in plaintext.")
            pinfo.cols.info:append(" [TELCOSEC: GEA0 NULL-CIPHER COMMANDED]")
        elseif gea == 1 then
            subtree:add(f_sec_alert, "[WARNING] GEA1 negotiated. GEA1 has a known 40-bit effective key weakness and is crackable in real time.")
            pinfo.cols.info:append(" [TELCOSEC: WEAK GEA1 CIPHER]")
        end
    end

    -- Security Heuristic 4: Deactivate PDP Context Request
    if msg_type == 0x44 then
        subtree:add(f_sec_alert, "[WARNING] PDP Context Deactivation commanded. Packet data session severed.")
    end

    if tvb:len() > 2 then
        subtree:add(f_payload, tvb(2, tvb:len() - 2))
    end
end
