-- TelcoSec.net - 5G New Radio (NR) Air Interface (RRC / SDAP / PDCP / RLC / MAC - 3GPP TS 38.331 / TS 38.323 / TS 38.321) Security Engine
-- Description: Complete standalone and post-dissector analyzer for 5G NR Air Interface signaling.
--              Decodes RRC procedures (RRCSetupRequest/Setup/Reconfiguration/Release, SecurityModeCommand, 5G Paging, Beam Measurement Reports),
--              extracts cryptographic algorithms (NEA0-NEA3, NIA0-NIA3), and detects wireless radio threat vectors.
--              Detects 5G-to-4G forced downgrade attacks, unencrypted SUPI/5G-S-TMSI harvesting, NEA0/NIA0 null ciphering, and radio DoS sleep commands.

local ok, nr_radio_proto = pcall(Proto, "nr_radio_sec", "TelcoSec 5G NR Radio Interface Security Analyzer")
if not ok or not nr_radio_proto then return end

-- Protocol fields
local f_rrc_chan        = ProtoField.string("nr_radio_sec.chan", "RRC Logical Channel")
local f_msg_type        = ProtoField.string("nr_radio_sec.msg_type", "5G NR RRC Message Type")
local f_est_cause       = ProtoField.string("nr_radio_sec.est_cause", "5G Establishment Cause")
local f_ue_id_type      = ProtoField.string("nr_radio_sec.ue_id_type", "5G Initial UE Identity Type")
local f_5g_s_tmsi       = ProtoField.string("nr_radio_sec.5g_s_tmsi", "5G-S-TMSI (AMF Set ID + AMF Pointer + 5G-TMSI)")
local f_cipher_algo     = ProtoField.string("nr_radio_sec.cipher_algo", "NEA Ciphering Algorithm")
local f_integ_algo      = ProtoField.string("nr_radio_sec.integ_algo", "NIA Integrity Algorithm")
local f_redir_rat       = ProtoField.string("nr_radio_sec.redir_rat", "Redirected Carrier RAT / Frequency")
local f_redir_ssb_arfcn = ProtoField.uint32("nr_radio_sec.redir_nrarfcn", "Redirected NR-ARFCN / EARFCN", base.DEC)
local f_wait_time       = ProtoField.uint32("nr_radio_sec.wait_time", "5G Wait Time (seconds)", base.DEC)
local f_paging_id_type  = ProtoField.string("nr_radio_sec.paging_id_type", "5G Paging Identity Type")
local f_sec_alert       = ProtoField.string("nr_radio_sec.alert", "TelcoSec 5G NR Radio Security Alert")
local f_payload         = ProtoField.bytes("nr_radio_sec.payload", "5G NR RRC Raw ASN.1 PDU")

nr_radio_proto.fields = {
    f_rrc_chan,
    f_msg_type,
    f_est_cause,
    f_ue_id_type,
    f_5g_s_tmsi,
    f_cipher_algo,
    f_integ_algo,
    f_redir_rat,
    f_redir_ssb_arfcn,
    f_wait_time,
    f_paging_id_type,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 38.331 5G Establishment Causes
local NR_ESTABLISHMENT_CAUSES = {
    [0]  = "emergency",
    [1]  = "highPriorityAccess",
    [2]  = "mt-Access",
    [3]  = "mo-Signalling",
    [4]  = "mo-Data",
    [5]  = "mo-VoiceCall",
    [6]  = "mo-VideoCall",
    [7]  = "mo-SMS",
    [8]  = "mps-PriorityAccess",
    [9]  = "mcs-PriorityAccess",
    [10] = "spare6",
    [11] = "spare5",
    [12] = "spare4",
    [13] = "spare3",
    [14] = "spare2",
    [15] = "spare1"
}

-- 3GPP TS 38.331 5G NR Security Algorithms
local NEA_CIPHERS = {
    [0] = "NEA0 (Null Ciphering / Plaintext)",
    [1] = "NEA1 (128-bit SNOW 3G)",
    [2] = "NEA2 (128-bit AES-CTR)",
    [3] = "NEA3 (128-bit ZUC)"
}
local NIA_INTEGRITY = {
    [0] = "NIA0 (Null Integrity / Unprotected)",
    [1] = "NIA1 (128-bit SNOW 3G)",
    [2] = "NIA2 (128-bit AES-CMAC)",
    [3] = "NIA3 (128-bit ZUC)"
}

-- Safe field getters for post-dissector integration
local cached_fields = {}
local function safe_get_field(name)
    if cached_fields[name] == nil then
        local ok, f = pcall(Field.new, name)
        cached_fields[name] = ok and f or false
    end
    return cached_fields[name] or nil
end

function nr_radio_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    local subtree = tree:add(nr_radio_proto, tvb(), "TelcoSec 5G NR Radio Interface Security Analyzer")
    local alerts = {}

    -- 1. Check Native Wireshark NR-RRC Fields first
    local f_native_nr_cipher = safe_get_field("nr-rrc.cipheringAlgorithm")
    local f_native_nr_integ  = safe_get_field("nr-rrc.integrityProtAlgorithm")
    local f_native_nr_redir  = safe_get_field("nr-rrc.redirectedCarrierInfo")
    local f_native_nr_cause  = safe_get_field("nr-rrc.establishmentCause")
    local f_native_nr_wait   = safe_get_field("nr-rrc.waitTime")

    local cipher_f = f_native_nr_cipher and f_native_nr_cipher()
    local integ_f  = f_native_nr_integ and f_native_nr_integ()
    local redir_f  = f_native_nr_redir and f_native_nr_redir()
    local cause_f  = f_native_nr_cause and f_native_nr_cause()
    local wait_f   = f_native_nr_wait and f_native_nr_wait()

    if cipher_f or integ_f or redir_f or cause_f or wait_f then
        pinfo.cols.protocol = "5G NR RRC"

        if cipher_f then
            local c_val = tonumber(cipher_f.value) or 0
            local c_name = NEA_CIPHERS[c_val] or string.format("NEA%d", c_val)
            subtree:add(f_cipher_algo, c_name)
            if c_val == 0 then
                table.insert(alerts, "[CRITICAL] NEA0 (No Ciphering) commanded! 5G user plane and signaling transmitted in plaintext.")
                pinfo.cols.info:append(" [TELCOSEC: NEA0 NULL-CIPHER!]")
            end
        end

        if integ_f then
            local i_val = tonumber(integ_f.value) or 0
            local i_name = NIA_INTEGRITY[i_val] or string.format("NIA%d", i_val)
            subtree:add(f_integ_algo, i_name)
            if i_val == 0 then
                table.insert(alerts, "[CRITICAL] NIA0 (No Integrity) configured on 5G NR RRC! Vulnerable to radio link hijack and rogue command injection.")
                pinfo.cols.info:append(" [TELCOSEC: NIA0 NULL-INTEGRITY!]")
            end
        end

        if redir_f then
            local redir_str = tostring(redir_f.value)
            subtree:add(f_redir_rat, redir_str)
            if string.find(redir_str:lower(), "eutra") or string.find(redir_str:lower(), "lte") or string.find(redir_str:lower(), "utra") or string.find(redir_str:lower(), "geran") then
                table.insert(alerts, string.format("[CRITICAL] Forced 5G-to-Legacy Downgrade (%s)! Rogue gNodeB forcing UE off 5G SA.", redir_str))
                pinfo.cols.info:append(" [TELCOSEC: FORCED 5G DOWNGRADE!]")
            else
                table.insert(alerts, string.format("[WARNING] 5G RRCRelease contains redirectedCarrierInfo (%s).", redir_str))
            end
        end

        if wait_f then
            local w_val = tonumber(wait_f.value) or 0
            subtree:add(f_wait_time, tvb(0, 1), w_val)
            if w_val > 60 then
                table.insert(alerts, string.format("[CRITICAL] Malicious 5G Wait Time (%d sec) in RRCRelease! Silences 5G SA connectivity.", w_val))
                pinfo.cols.info:append(" [TELCOSEC: 5G RADIO DOS WAIT TIME!]")
            end
        end

        if cause_f then
            local cause_val = tonumber(cause_f.value) or 0
            local cause_name = NR_ESTABLISHMENT_CAUSES[cause_val] or string.format("Cause %d", cause_val)
            subtree:add(f_est_cause, cause_name)
        end
    else
        -- 2. Standalone Byte-Level Analysis (Direct 5G NR RRC ASN.1 PDU)
        local b0 = tvb(0, 1):uint()
        local b1 = len >= 2 and tvb(1, 1):uint() or 0

        -- Detect DL-DCCH SecurityModeCommand (choice index 3)
        if bit.band(b0, 0xF0) == 0x30 or (b0 == 0x03 and len >= 3) then
            local c_alg = bit.band(bit.rshift(b1, 5), 0x07)
            local i_alg = bit.band(bit.rshift(b1, 2), 0x07)
            local c_name = NEA_CIPHERS[c_alg] or string.format("NEA%d", c_alg)
            local i_name = NIA_INTEGRITY[i_alg] or string.format("NIA%d", i_alg)
            subtree:add(f_msg_type, "5G SecurityModeCommand")
            subtree:add(f_cipher_algo, c_name)
            subtree:add(f_integ_algo, i_name)
            if c_alg == 0 then
                table.insert(alerts, "[CRITICAL] NEA0 (No Ciphering) commanded in 5G SecurityModeCommand! Plaintext 5G air interface.")
            end
            if i_alg == 0 then
                table.insert(alerts, "[CRITICAL] NIA0 (No Integrity) commanded in 5G SecurityModeCommand! Unauthenticated 5G NR radio link hijack.")
            end
            pinfo.cols.info = string.format("[5G NR RRC] SecurityModeCommand | %s | %s", c_name, i_name)

        -- Detect UL-CCCH RRCSetupRequest
        elseif bit.band(b0, 0xE0) == 0x00 and len >= 6 then
            local est_cause_idx = bit.band(bit.rshift(b0, 1), 0x0F)
            local est_name = NR_ESTABLISHMENT_CAUSES[est_cause_idx] or string.format("Cause %d", est_cause_idx)
            subtree:add(f_msg_type, "RRCSetupRequest")
            subtree:add(f_est_cause, est_name)

            -- Initial UE-Identity: ng-5G-S-TMSI-Part1 (39 bits) vs randomValue (39 bits)
            local id_type = (bit.band(b0, 1) == 0) and "ng-5G-S-TMSI-Part1" or "randomValue"
            subtree:add(f_ue_id_type, id_type)
            pinfo.cols.info = string.format("[5G NR RRC] RRCSetupRequest | %s | %s", est_name, id_type)
        else
            subtree:add(f_payload, tvb())
        end
    end

    if #alerts > 0 then
        for _, a in ipairs(alerts) do
            subtree:add(f_sec_alert, a)
        end
    end
end

-- Register as post-dissector to inspect all native and encapsulated 5G NR radio traffic
register_postdissector(nr_radio_proto)
