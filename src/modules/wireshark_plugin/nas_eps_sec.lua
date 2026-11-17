-- TelcoSec.net - NAS-EPS (4G LTE Non-Access Stratum) Security Dissector
-- Description: Dissects EPS Mobility Management (EMM) and Session Management (ESM) signaling (3GPP TS 24.301).
--              Detects plain IMSI Identity Requests, malicious Attach/TAU Rejections causing 2G downgrade,
--              and unencrypted / unauthenticated NAS Security Mode Commands.

-- Bitwise-operation compatibility shim (AirTap).
-- Wireshark <=3.4 bundles Lua 5.1 + LuaBitOp ('bit'); 3.6 ships Lua 5.2 ('bit32');
-- 4.x ships Lua 5.3/5.4 where BOTH are absent and native operators are required.
-- Globals resolve at call time, so without this a missing 'bit' only fails once a
-- packet reaches a heuristic: the dissector loads fine, then dies on live traffic.
-- Constant lookup tables, hoisted to module scope: building these
-- per packet allocated a short-lived table on every dissect call.
local id_names = { [1]="IMSI", [2]="IMEI", [3]="IMEISV", [4]="TMSI" }

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

local ok, nas_eps_proto = pcall(Proto, "nas_eps_sec", "TelcoSec LTE NAS (EMM/ESM) Security Analyzer")
if not ok or not nas_eps_proto then return end

-- Protocol fields
local f_sec_hdr_type = ProtoField.uint8("nas_eps_sec.sec_hdr_type", "Security Header Type", base.HEX)
local f_proto_disc   = ProtoField.uint8("nas_eps_sec.proto_disc", "Protocol Discriminator", base.HEX)
local f_msg_type     = ProtoField.uint8("nas_eps_sec.msg_type", "NAS Message Type", base.HEX)
local f_msg_name     = ProtoField.string("nas_eps_sec.msg_name", "Message Name")
local f_emm_cause    = ProtoField.uint8("nas_eps_sec.emm_cause", "EMM Cause Code", base.DEC)
local f_cause_desc   = ProtoField.string("nas_eps_sec.cause_desc", "Cause Description")
local f_id_type      = ProtoField.string("nas_eps_sec.id_type", "Identity Type (IMSI/IMEI/GUTI)")
local f_sec_alert    = ProtoField.string("nas_eps_sec.alert", "TelcoSec NAS-EPS Security Alert")
local f_payload      = ProtoField.bytes("nas_eps_sec.payload", "NAS Payload")

nas_eps_proto.fields = {
    f_sec_hdr_type,
    f_proto_disc,
    f_msg_type,
    f_msg_name,
    f_emm_cause,
    f_cause_desc,
    f_id_type,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 24.301 Table 9.8.1: EMM Message Types
local EMM_MESSAGES = {
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
    [0x4C] = "Service Request",
    [0x4E] = "Service Reject",
    [0x52] = "Authentication Request",
    [0x53] = "Authentication Response",
    [0x54] = "Authentication Reject",
    [0x55] = "Identity Request",
    [0x56] = "Identity Response",
    [0x5D] = "Security Mode Command",
    [0x5E] = "Security Mode Complete",
    [0x5F] = "Security Mode Reject",
    [0x60] = "EMM Status"
}

-- 3GPP TS 24.301 Table 9.9.3.9: EMM Cause Values
local EMM_CAUSES = {
    [2]  = "IMSI unknown in HSS (Forces SIM de-registration)",
    [3]  = "Illegal UE (Forces UE to delete EPS context)",
    [6]  = "Illegal ME (IMEI blacklisted)",
    [7]  = "EPS services not allowed (Forces phone down to 2G/3G GSM)",
    [8]  = "EPS services and non-EPS services not allowed (Total cellular disconnection)",
    [9]  = "UE identity cannot be derived by the network",
    [10] = "Implicitly detached",
    [11] = "PLMN not allowed",
    [12] = "Tracking Area not allowed",
    [13] = "Roaming not allowed in this tracking area",
    [14] = "EPS services not allowed in this PLMN (Forces 2G downgrade)",
    [15] = "No Suitable Cells In tracking area",
    [22] = "Congestion"
}

-- Native NAS-EPS dissector
local nas_eps_dissector = Dissector.get("nas-eps")

function nas_eps_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 2 then return end

    pinfo.cols.protocol = "LTE NAS"

    local byte0 = tvb(0, 1):uint()
    local sec_hdr = bit.rshift(byte0, 4)
    local proto_disc = bit.band(byte0, 0x0F)

    local sec_hdr_names = {
        [0] = "Plain NAS message (Not security protected)",
        [1] = "Integrity protected",
        [2] = "Integrity protected and ciphered",
        [3] = "Integrity protected with new EPS security context",
        [4] = "Integrity protected and ciphered with new EPS security context"
    }
    local sec_hdr_str = sec_hdr_names[sec_hdr] or string.format("Sec Type %d", sec_hdr)

    local subtree = tree:add(nas_eps_proto, tvb(), string.format("NAS-EPS Security: %s", sec_hdr_str))
    subtree:add(f_sec_hdr_type, tvb(0, 1), sec_hdr):append_text(string.format(" (%s)", sec_hdr_str))
    subtree:add(f_proto_disc, tvb(0, 1), proto_disc)

    local msg_offset = (sec_hdr == 0) and 1 or 6
    if tvb:len() > msg_offset then
        local msg_type = tvb(msg_offset, 1):uint()
        local msg_name = EMM_MESSAGES[msg_type] or string.format("NAS Msg (0x%02X)", msg_type)

        subtree:add(f_msg_type, tvb(msg_offset, 1), msg_type)
        subtree:add(f_msg_name, msg_name)
        pinfo.cols.info = string.format("[NAS-EPS] %s (%s)", msg_name, sec_hdr_str)

        -- Security Heuristic 1: Plain Identity Request probing for IMSI
        if msg_type == 0x55 and tvb:len() > (msg_offset + 1) then
            local raw_id = bit.band(tvb(msg_offset + 1, 1):uint(), 0x07)
            local id_str = id_names[raw_id] or string.format("Type %d", raw_id)
            subtree:add(f_id_type, id_str)

            if raw_id == 1 or raw_id == 2 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] Unprotected Identity Request querying plain %s! 4G IMSI Catcher subscriber probing.", id_str))
                pinfo.cols.info:append(" [TELCOSEC: IMSI PROBE DETECTED!]")
            end
        end

        -- Security Heuristic 2: Attach Reject / TAU Reject with Cause #7 / #8 / #14 (Forced 2G Downgrade)
        if (msg_type == 0x44 or msg_type == 0x4B) and tvb:len() > (msg_offset + 1) then
            local cause = tvb(msg_offset + 1, 1):uint()
            local cause_desc = EMM_CAUSES[cause] or string.format("Cause %d", cause)

            subtree:add(f_emm_cause, tvb(msg_offset + 1, 1), cause)
            subtree:add(f_cause_desc, cause_desc)

            if cause == 7 or cause == 8 or cause == 14 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] Malicious EMM Reject (Cause #%d: %s)! Exploited by IMSI Catchers to disable 4G LTE and force victim to 2G GSM.", cause, cause_desc))
                pinfo.cols.info:append(" [TELCOSEC: FORCED 2G DOWNGRADE INJECTION!]")
            elseif cause == 2 or cause == 3 or cause == 6 then
                subtree:add(f_sec_alert, string.format("[CRITICAL] SIM Bricking EMM Reject (Cause #%d: %s)!", cause, cause_desc))
            end
        end

        -- Security Heuristic 3: Security Mode Command without integrity protection
        if msg_type == 0x5D and sec_hdr == 0 then
            subtree:add(f_sec_alert, "[CRITICAL] Security Mode Command sent without mandatory integrity protection! Vulnerable to MITM ciphering downgrade.")
        end
    end

    if nas_eps_dissector then
        nas_eps_dissector:call(tvb, pinfo, tree)
    else
        subtree:add(f_payload, tvb())
    end
end
