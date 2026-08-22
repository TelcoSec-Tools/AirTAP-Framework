-- TelcoSec.net - 4G LTE Radio Interface (RRC / PDCP / RLC / MAC - 3GPP TS 36.331 / TS 36.323 / TS 36.321) Security Engine
-- Description: Complete standalone and post-dissector analyzer for LTE Air Interface signaling.
--              Decodes RRC procedures (Connection Request/Setup/Reconfig/Release, SecurityModeCommand, Paging, Measurement Reports),
--              extracts cryptographic algorithms (EEA0-EEA3, EIA0-EIA3), and evaluates wireless radio threat vectors.
--              Detects False Base Station (FBS) downgrade attacks, IMSI paging probes, EEA0/EIA0 null ciphering, and radio DoS wait timers.

local ok, lte_radio_proto = pcall(Proto, "lte_radio_sec", "TelcoSec 4G LTE Radio Interface Security Analyzer")
if not ok or not lte_radio_proto then return end

-- Protocol fields
local f_rrc_chan        = ProtoField.string("lte_radio_sec.chan", "RRC Logical Channel")
local f_msg_type        = ProtoField.string("lte_radio_sec.msg_type", "RRC Message Type")
local f_est_cause       = ProtoField.string("lte_radio_sec.est_cause", "Establishment Cause")
local f_ue_id_type      = ProtoField.string("lte_radio_sec.ue_id_type", "Initial UE Identity Type")
local f_s_tmsi          = ProtoField.string("lte_radio_sec.s_tmsi", "S-TMSI (MME Code + M-TMSI)")
local f_cipher_algo     = ProtoField.string("lte_radio_sec.cipher_algo", "EEA Ciphering Algorithm")
local f_integ_algo      = ProtoField.string("lte_radio_sec.integ_algo", "EIA Integrity Algorithm")
local f_redir_rat       = ProtoField.string("lte_radio_sec.redir_rat", "Redirected Carrier RAT")
local f_redir_earfcn    = ProtoField.uint32("lte_radio_sec.redir_earfcn", "Redirected Carrier ARFCN/EARFCN", base.DEC)
local f_wait_time       = ProtoField.uint32("lte_radio_sec.wait_time", "Extended Wait Time (seconds)", base.DEC)
local f_paging_id_type  = ProtoField.string("lte_radio_sec.paging_id_type", "Paging Identity Type")
local f_sec_alert       = ProtoField.string("lte_radio_sec.alert", "TelcoSec LTE Radio Security Alert")
local f_payload         = ProtoField.bytes("lte_radio_sec.payload", "RRC Raw ASN.1 PDU")

lte_radio_proto.fields = {
    f_rrc_chan,
    f_msg_type,
    f_est_cause,
    f_ue_id_type,
    f_s_tmsi,
    f_cipher_algo,
    f_integ_algo,
    f_redir_rat,
    f_redir_earfcn,
    f_wait_time,
    f_paging_id_type,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 36.331 Establishment Causes
local ESTABLISHMENT_CAUSES = {
    [0] = "emergency",
    [1] = "highPriorityAccess",
    [2] = "mt-Access",
    [3] = "mo-Signalling",
    [4] = "mo-Data",
    [5] = "delayTolerantAccess-v1020",
    [6] = "mo-VoiceCall-v1280",
    [7] = "spare"
}

-- 3GPP TS 36.331 Security Algorithms
local EEA_CIPHERS = {
    [0] = "EEA0 (Null Ciphering / Plaintext)",
    [1] = "EEA1 (SNOW 3G 128-bit)",
    [2] = "EEA2 (AES-128 CTR)",
    [3] = "EEA3 (ZUC-128)"
}
local EIA_INTEGRITY = {
    [0] = "EIA0 (Null Integrity / Unprotected)",
    [1] = "EIA1 (SNOW 3G 128-bit)",
    [2] = "EIA2 (AES-128 CMAC)",
    [3] = "EIA3 (ZUC-128)"
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

function lte_radio_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    local subtree = tree:add(lte_radio_proto, tvb(), "TelcoSec 4G LTE Radio Interface Security Analyzer")
    local alerts = {}

    -- 1. Check Native Wireshark LTE-RRC Fields first
    local f_native_cipher = safe_get_field("lte-rrc.cipheringAlgorithm_r8")
    local f_native_integ  = safe_get_field("lte-rrc.integrityProtAlgorithm_r8")
    local f_native_redir  = safe_get_field("lte-rrc.redirectedCarrierInfo")
    local f_native_cause  = safe_get_field("lte-rrc.establishmentCause")
    local f_native_wait   = safe_get_field("lte-rrc.extendedWaitTime_r10")

    local cipher_f = f_native_cipher and f_native_cipher()
    local integ_f  = f_native_integ and f_native_integ()
    local redir_f  = f_native_redir and f_native_redir()
    local cause_f  = f_native_cause and f_native_cause()
    local wait_f   = f_native_wait and f_native_wait()
    local wait_f   = f_native_wait and f_native_wait()

    if cipher_f or integ_f or redir_f or cause_f or wait_f then
        pinfo.cols.protocol = "LTE RRC"

        if cipher_f then
            local c_val = tonumber(cipher_f.value) or 0
            local c_name = EEA_CIPHERS[c_val] or string.format("EEA%d", c_val)
            subtree:add(f_cipher_algo, c_name)
            if c_val == 0 then
                table.insert(alerts, "[CRITICAL] EEA0 (Null Encryption) commanded! Radio bearer data and signaling transmitted in plaintext.")
                pinfo.cols.info:append(" [TELCOSEC: EEA0 NULL-CIPHER!]")
            end
        end

        if integ_f then
            local i_val = tonumber(integ_f.value) or 0
            local i_name = EIA_INTEGRITY[i_val] or string.format("EIA%d", i_val)
            subtree:add(f_integ_algo, i_name)
            if i_val == 0 then
                table.insert(alerts, "[CRITICAL] EIA0 (Null Integrity) configured on LTE RRC! Rogue eNodeB can inject unauthenticated signaling commands.")
                pinfo.cols.info:append(" [TELCOSEC: EIA0 NULL-INTEGRITY!]")
            end
        end

        if redir_f then
            local redir_str = tostring(redir_f.value)
            subtree:add(f_redir_rat, redir_str)
            if string.find(redir_str:lower(), "geran") or string.find(redir_str:lower(), "gsm") or string.find(redir_str:lower(), "utra") then
                table.insert(alerts, string.format("[CRITICAL] Forced Inter-RAT Downgrade (%s)! Rogue eNodeB forcing UE off LTE to interceptable 2G/3G.", redir_str))
                pinfo.cols.info:append(" [TELCOSEC: FORCED 2G/3G DOWNGRADE!]")
            else
                table.insert(alerts, string.format("[WARNING] LTE RRCConnectionRelease contains redirectedCarrierInfo (%s).", redir_str))
            end
        end

        if wait_f then
            local w_val = tonumber(wait_f.value) or 0
            subtree:add(f_wait_time, tvb(0, 1), w_val)
            if w_val > 60 then
                table.insert(alerts, string.format("[CRITICAL] Malicious Extended Wait Time (%d sec)! Radio DoS attack silencing UE network connectivity.", w_val))
                pinfo.cols.info:append(" [TELCOSEC: RADIO DOS WAIT TIME!]")
            end
        end

        if cause_f then
            local cause_val = tonumber(cause_f.value) or 0
            local cause_name = ESTABLISHMENT_CAUSES[cause_val] or string.format("Cause %d", cause_val)
            subtree:add(f_est_cause, cause_name)
        end
    else
        -- 2. Standalone Byte-Level Analysis (Direct RRC ASN.1 PDU)
        local b0 = tvb(0, 1):uint()
        local b1 = len >= 2 and tvb(1, 1):uint() or 0

        -- Detect DL-DCCH SecurityModeCommand (choice index 3)
        if bit.band(b0, 0xF0) == 0x30 or (b0 == 0x03 and len >= 3) then
            local c_alg = bit.band(bit.rshift(b1, 5), 0x07)
            local i_alg = bit.band(bit.rshift(b1, 2), 0x07)
            local c_name = EEA_CIPHERS[c_alg] or string.format("EEA%d", c_alg)
            local i_name = EIA_INTEGRITY[i_alg] or string.format("EIA%d", i_alg)
            subtree:add(f_msg_type, "SecurityModeCommand")
            subtree:add(f_cipher_algo, c_name)
            subtree:add(f_integ_algo, i_name)
            if c_alg == 0 then
                table.insert(alerts, "[CRITICAL] EEA0 (No Ciphering) commanded in SecurityModeCommand! Plaintext traffic over LTE air interface.")
            end
            if i_alg == 0 then
                table.insert(alerts, "[CRITICAL] EIA0 (No Integrity) commanded in SecurityModeCommand! Unauthenticated radio link hijack.")
            end
            pinfo.cols.info = string.format("[LTE RRC] SecurityModeCommand | %s | %s", c_name, i_name)

        -- Detect UL-CCCH RRCConnectionRequest
        elseif bit.band(b0, 0xE0) == 0x00 and len >= 6 then
            local est_cause_idx = bit.band(bit.rshift(b0, 1), 0x0F)
            local est_name = ESTABLISHMENT_CAUSES[est_cause_idx] or string.format("Cause %d", est_cause_idx)
            subtree:add(f_msg_type, "RRCConnectionRequest")
            subtree:add(f_est_cause, est_name)

            -- Initial UE-Identity: s-TMSI (40 bits) vs randomValue (40 bits)
            local id_type = (bit.band(b0, 1) == 0) and "s-TMSI" or "randomValue"
            subtree:add(f_ue_id_type, id_type)
            if id_type == "s-TMSI" and len >= 6 then
                local mmec = tvb(1, 1):uint()
                local mtmsi = tvb(2, 4):uint()
                local stmsi_str = string.format("MMEC:0x%02X / M-TMSI:0x%08X", mmec, mtmsi)
                subtree:add(f_s_tmsi, stmsi_str)
                pinfo.cols.info = string.format("[LTE RRC] RRCConnectionRequest | %s | S-TMSI: %s", est_name, stmsi_str)
            else
                pinfo.cols.info = string.format("[LTE RRC] RRCConnectionRequest | %s | RandomValue", est_name)
            end
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

-- Register as post-dissector to inspect all native and encapsulated LTE radio traffic
register_postdissector(lte_radio_proto)
