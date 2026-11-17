-- TelcoSec.net - GSM A-Interface BSSMAP / BSSAP Security Dissector
-- Description: Dissects GSM A-Interface BSSMAP (3GPP TS 48.008) signaling between BSC and MSC.
--              Analyzes Cipher Mode Commands, Handover Requests, and cleartext IMSI transfers across the core network.

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

-- 3GPP TS 48.008 3.2.2.10: permitted-algorithms bitmask in the Encryption
-- Information IE, ordered by bit position (bit 0 first).
local A5_ALGORITHMS = {
    "A5/0 (No Encryption)",
    "A5/1",
    "A5/2 (Export-Weakened)",
    "A5/3 (Kasumi)",
    "A5/4",
    "A5/5",
    "A5/6",
    "A5/7"
}

local ok, gsm_bssmap_proto = pcall(Proto, "gsm_bssmap_sec", "TelcoSec GSM A-Interface BSSMAP Analyzer")
if not ok or not gsm_bssmap_proto then return end

-- Protocol fields
local f_msg_type     = ProtoField.uint8("gsm_bssmap.msg_type", "BSSMAP Message Type", base.HEX)
local f_msg_name     = ProtoField.string("gsm_bssmap.msg_name", "BSSMAP Message Name")
local f_cipher_info  = ProtoField.string("gsm_bssmap.cipher_info", "Permitted Encryption Algorithms")
local f_imsi         = ProtoField.string("gsm_bssmap.imsi", "Transferred IMSI")
local f_sec_alert    = ProtoField.string("gsm_bssmap.alert", "TelcoSec BSSMAP Security Alert")
local f_payload      = ProtoField.bytes("gsm_bssmap.payload", "BSSMAP Raw Payload")

gsm_bssmap_proto.fields = {
    f_msg_type,
    f_msg_name,
    f_cipher_info,
    f_imsi,
    f_sec_alert,
    f_payload
}

-- BSSMAP Message Types (3GPP TS 48.008)
local BSSMAP_MSG_TYPES = {
    [0x01] = "Assignment Request",
    [0x02] = "Assignment Complete",
    [0x03] = "Assignment Failure",
    [0x10] = "Handover Request",
    [0x11] = "Handover Required",
    [0x12] = "Handover Request Acknowledge",
    [0x13] = "Handover Command",
    [0x14] = "Handover Complete",
    [0x15] = "Handover Failure",
    [0x20] = "Clear Command",
    [0x21] = "Clear Complete",
    [0x22] = "Clear Request",
    [0x52] = "Cipher Mode Command",
    [0x53] = "Cipher Mode Complete",
    [0x54] = "Cipher Mode Reject",
    [0x58] = "Paging",
    [0x60] = "Reset",
    [0x61] = "Reset Acknowledge"
}

-- Native Wireshark BSSMAP dissector
local gsm_bssmap_dissector = Dissector.get("gsm_a_bssmap")

function gsm_bssmap_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "GSM BSSMAP"

    local msg_type = tvb(0, 1):uint()
    local msg_name = BSSMAP_MSG_TYPES[msg_type] or string.format("BSSMAP Msg (0x%02X)", msg_type)

    local subtree = tree:add(gsm_bssmap_proto, tvb(), string.format("GSM BSSMAP: %s", msg_name))
    subtree:add(f_msg_type, tvb(0, 1))
    subtree:add(f_msg_name, msg_name)

    pinfo.cols.info = string.format("[GSM BSSMAP] %s", msg_name)

    -- Security Heuristic 1: Cipher Mode Command permitting A5/0 (no encryption)
    --
    -- 3GPP TS 48.008 3.2.2.10: the Encryption Information element is a TLV
    -- with IEI 0x0A. Its first value octet is a permitted-algorithms bitmask
    -- (0x01 = no encryption, 0x02 = A5/1 ... 0x80 = A5/7), followed by the
    -- key. The IE is walked to its position rather than searched for: an
    -- earlier revision scanned a hex dump of the whole message for "0000" or
    -- "0101", which matched at any nibble offset and raised a [CRITICAL]
    -- forced-plaintext alert on ordinary traffic.
    if msg_type == 0x52 and tvb:len() >= 4 then
        local offset = 1          -- octet 0 is the message type
        local limit = tvb:len()
        local guard = 0

        while offset + 1 < limit and guard < 32 do
            guard = guard + 1
            local iei = tvb(offset, 1):uint()
            local ie_len = tvb(offset + 1, 1):uint()
            if offset + 2 + ie_len > limit then break end

            if iei == 0x0A and ie_len >= 1 then
                local mask = tvb(offset + 2, 1):uint()
                local permitted = {}
                for bit_index, name in ipairs(A5_ALGORITHMS) do
                    if bit.band(mask, bit.lshift(1, bit_index - 1)) ~= 0 then
                        permitted[#permitted + 1] = name
                    end
                end
                subtree:add(f_cipher_info, #permitted > 0
                    and table.concat(permitted, ", ")
                    or string.format("none (mask 0x%02X)", mask))

                -- Bit 0 set means the MSC is willing to run the call with no
                -- ciphering at all.
                if bit.band(mask, 0x01) ~= 0 then
                    subtree:add(f_sec_alert, "[CRITICAL] MSC permitted A5/0 (No Encryption) in BSSMAP Cipher Mode Command! Core network allowing plaintext over the radio link.")
                    pinfo.cols.info:append(" [TELCOSEC: A5/0 PERMITTED ON A-INTERFACE]")
                elseif bit.band(mask, 0x04) ~= 0 then
                    subtree:add(f_sec_alert, "[WARNING] A5/2 permitted. A5/2 is an export-weakened cipher broken in real time.")
                end
                break
            end

            offset = offset + 2 + ie_len
        end
    end

    -- Security Heuristic 2: Plaintext IMSI in Paging or Handover Request
    if (msg_type == 0x58 or msg_type == 0x10) and tvb:len() >= 10 then
        subtree:add(f_sec_alert, "[INFO] Subscriber Paging / Handover transaction between BSC and MSC.")
    end

    if gsm_bssmap_dissector then
        gsm_bssmap_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
