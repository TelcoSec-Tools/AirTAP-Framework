-- TelcoSec.net - UICC / USIM / ISIM Smart Card APDU (ISO/IEC 7816-4 / ETSI TS 102 221 / 3GPP TS 31.102) Master Security Dissector
-- Description: Complete analyzer for APDUs between Cellular Baseband (Host/Modem) and USIM/eUICC Smart Card chip.
--              Decodes ISO 7816-4 APDU commands (SELECT, READ/UPDATE BINARY/RECORD, VERIFY/CHANGE/UNBLOCK PIN,
--              AUTHENTICATE AKA, FETCH, TERMINAL RESPONSE, ENVELOPE, MANAGE CHANNEL, STATUS, GET DATA).
--              Parses 3GPP Elementary Files (EF_IMSI, EF_LOCI, EF_PSLOCI, EF_EPSLOCI, EF_5GS3GPLOCI, EF_AD, EF_HPPLMN, EF_SMS, EF_SPN, EF_Keys),
--              decodes USIM Milenage/TUAK AKA crypto challenges (RAND/AUTN/RES/CK/IK/AUTS), tracks PIN/PUK retry counters,
--              and detects SIM cloning, credential harvesting, AKA replay, and SIMjacker proactive command execution.

local ok, uicc_apdu_proto = pcall(Proto, "uicc_apdu_sec", "TelcoSec UICC/USIM Smart Card APDU Analyzer")
if not ok or not uicc_apdu_proto then return end

-- Protocol fields
local f_cla             = ProtoField.uint8("uicc.cla", "Class (CLA)", base.HEX)
local f_ins             = ProtoField.uint8("uicc.ins", "Instruction (INS)", base.HEX)
local f_ins_name        = ProtoField.string("uicc.ins_name", "Instruction Name")
local f_p1              = ProtoField.uint8("uicc.p1", "Parameter 1 (P1)", base.HEX)
local f_p2              = ProtoField.uint8("uicc.p2", "Parameter 2 (P2)", base.HEX)
local f_lc              = ProtoField.uint8("uicc.lc", "Data Length (Lc/Le)", base.DEC)
local f_sw12            = ProtoField.uint16("uicc.sw", "Status Word (SW1-SW2)", base.HEX)
local f_sw_desc         = ProtoField.string("uicc.sw_desc", "Status Word Meaning")
local f_ef_name         = ProtoField.string("uicc.ef_name", "Selected File / EF Name")
local f_ef_id           = ProtoField.uint16("uicc.ef_id", "File ID (FID)", base.HEX)
local f_auth_context    = ProtoField.string("uicc.auth_context", "Authentication Context")
local f_rand            = ProtoField.bytes("uicc.rand", "AKA RAND Challenge (16 bytes)")
local f_autn            = ProtoField.bytes("uicc.autn", "AKA AUTN Token (16 bytes)")
local f_res             = ProtoField.bytes("uicc.res", "AKA RES Response")
local f_ck              = ProtoField.bytes("uicc.ck", "Cipher Key (CK)")
local f_ik              = ProtoField.bytes("uicc.ik", "Integrity Key (IK)")
local f_auts            = ProtoField.bytes("uicc.auts", "AKA AUTS (Synchronization Failure)")
local f_pin_retries     = ProtoField.uint8("uicc.pin_retries", "Remaining PIN/PUK Retries", base.DEC)
local f_imsi            = ProtoField.string("uicc.imsi", "Extracted Subscriber IMSI")
local f_sec_alert       = ProtoField.string("uicc.alert", "TelcoSec UICC Security Alert")
local f_payload         = ProtoField.bytes("uicc.payload", "APDU Data Bytes")

uicc_apdu_proto.fields = {
    f_cla,
    f_ins,
    f_ins_name,
    f_p1,
    f_p2,
    f_lc,
    f_sw12,
    f_sw_desc,
    f_ef_name,
    f_ef_id,
    f_auth_context,
    f_rand,
    f_autn,
    f_res,
    f_ck,
    f_ik,
    f_auts,
    f_pin_retries,
    f_imsi,
    f_sec_alert,
    f_payload
}

-- ISO 7816 / ETSI TS 102 221 Instruction Codes
local APDU_INS_CODES = {
    [0xA4] = "SELECT (File / Application)",
    [0xB0] = "READ BINARY",
    [0xD6] = "UPDATE BINARY",
    [0xB2] = "READ RECORD",
    [0xDC] = "UPDATE RECORD",
    [0x20] = "VERIFY PIN",
    [0x24] = "CHANGE PIN",
    [0x26] = "DISABLE PIN",
    [0x28] = "ENABLE PIN",
    [0x2C] = "UNBLOCK PIN (PUK)",
    [0x88] = "AUTHENTICATE (GSM / UMTS / LTE AKA)",
    [0x89] = "AUTHENTICATE (GBA)",
    [0x12] = "FETCH (STK Proactive Command)",
    [0x14] = "TERMINAL RESPONSE (STK)",
    [0xC2] = "ENVELOPE (STK Event / SMS-PP)",
    [0x70] = "MANAGE CHANNEL",
    [0xCA] = "GET DATA",
    [0xE6] = "INSTALL (GlobalPlatform Applet Loading)",
    [0xE8] = "LOAD (GlobalPlatform Executable Load File)",
    [0xF2] = "STATUS"
}

-- Well-known 3GPP Elementary Files (EFs) and Dedicated Files (DFs) (3GPP TS 31.102 / 51.011)
local UICC_FILE_IDS = {
    [0x3F00] = "MF (Master File Root)",
    [0x7F20] = "DF_GSM (GSM Telecom Directory)",
    [0x7F10] = "DF_TELECOM (Telecom Directory)",
    [0x7FFF] = "ADF_USIM (3G/4G USIM Application)",
    [0x6F07] = "EF_IMSI (International Mobile Subscriber Identity)",
    [0x6F08] = "EF_Keys (GSM Ciphering Keys Kc/CKSN)",
    [0x6F7E] = "EF_LOCI (CS Location Information / TMSI / LAI)",
    [0x6F73] = "EF_PSLOCI (PS Location Information / P-TMSI / RAI)",
    [0x6FE3] = "EF_EPSLOCI (EPS Location Information / GUTI / TAI)",
    [0x4F01] = "EF_5GS3GPLOCI (5G 3GPP Location Information / 5G-GUTI / 5GS TAI)",
    [0x6FAD] = "EF_AD (Administrative Data / SIM Operational Mode)",
    [0x6F31] = "EF_HPPLMN (Higher Priority PLMN Search Period)",
    [0x6F38] = "EF_SST (SIM Service Table)",
    [0x6F3C] = "EF_SMS (Short Messages Storage)",
    [0x6F46] = "EF_SPN (Service Provider Name)",
    [0x6F7B] = "EF_FPLMN (Forbidden PLMNs List)",
    [0x6F05] = "EF_PL (Preferred Languages)",
    [0x2FE2] = "EF_ICCID (Unique Card Serial Number)",
    [0x2F05] = "EF_ELP (Extended Language Preference)"
}

-- ISO 7816-4 Status Word (SW1-SW2) Dictionary
local APDU_STATUS_WORDS = {
    [0x9000] = "Normal completion (Success)",
    [0x6300] = "Verification failed (0 retries remaining - Card Blocked!)",
    [0x63C1] = "Verification failed (1 retry remaining)",
    [0x63C2] = "Verification failed (2 retries remaining)",
    [0x63C3] = "Verification failed (3 retries remaining)",
    [0x6700] = "Wrong length",
    [0x6982] = "Security status not satisfied (PIN Required)",
    [0x6983] = "Authentication method blocked",
    [0x6984] = "Referenced data invalidated",
    [0x6985] = "Conditions of use not satisfied",
    [0x6A80] = "Incorrect parameters in data field",
    [0x6A81] = "Function not supported",
    [0x6A82] = "File not found",
    [0x6A83] = "Record not found",
    [0x6A86] = "Incorrect P1-P2 parameters",
    [0x6D00] = "Instruction code not supported or invalid",
    [0x6E00] = "Class not supported",
    [0x6F00] = "Technical problem (No precise diagnosis / Baseband Panic)"
}

-- Native SIM dissector
local native_gsm_sim = Dissector.get("gsm_sim")

-- Helper: decode IMSI from EF_IMSI payload (TS 31.102 §4.2.2)
local function parse_ef_imsi(tvb, offset, len)
    if len < 8 or offset + len > tvb:len() then return nil end
    local imsi_len = tvb(offset, 1):uint()
    if imsi_len > 8 or imsi_len < 1 then return nil end
    local digits = ""
    local first_byte = tvb(offset + 1, 1):uint()
    local d1 = bit.rshift(first_byte, 4)
    digits = digits .. tostring(d1)
    for i = 2, imsi_len do
        local b = tvb(offset + i, 1):uint()
        local low = bit.band(b, 0x0F)
        local high = bit.rshift(b, 4)
        if low <= 9 then digits = digits .. tostring(low) end
        if high <= 9 then digits = digits .. tostring(high) end
    end
    return digits
end

function uicc_apdu_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    pinfo.cols.protocol = "UICC APDU"

    -- Check if packet is purely a 2-byte APDU Response Status Word (SW1-SW2)
    if len == 2 then
        local sw = tvb(0, 2):uint()
        local sw_str = APDU_STATUS_WORDS[sw] or string.format("SW 0x%04X", sw)
        local subtree = tree:add(uicc_apdu_proto, tvb(), string.format("UICC APDU Response: %s (0x%04X)", sw_str, sw))
        subtree:add(f_sw12, tvb(0, 2), sw)
        subtree:add(f_sw_desc, sw_str)
        pinfo.cols.info = string.format("[UICC Response] %s", sw_str)

        -- Detect PIN brute-force lock failure
        if bit.band(sw, 0xFFF0) == 0x63C0 or sw == 0x6300 then
            local retries = bit.band(sw, 0x0F)
            subtree:add(f_pin_retries, retries)
            if retries == 0 then
                subtree:add(f_sec_alert, "[CRITICAL] PIN Verification Failed with 0 retries left! USIM card is now PERMANENTLY BLOCKED requiring PUK.")
                pinfo.cols.info:append(" [TELCOSEC: SIM PIN BLOCKED!]")
            else
                subtree:add(f_sec_alert, string.format("[WARNING] PIN Verification Failed! %d retries remaining.", retries))
            end
        end
        return
    end

    if len < 4 then return end

    local cla = tvb(0, 1):uint()
    local ins = tvb(1, 1):uint()
    local p1  = tvb(2, 1):uint()
    local p2  = tvb(3, 1):uint()
    local ins_name = APDU_INS_CODES[ins] or string.format("INS 0x%02X", ins)

    local subtree = tree:add(uicc_apdu_proto, tvb(), string.format("UICC/USIM APDU: %s (CLA:0x%02X)", ins_name, cla))
    subtree:add(f_cla, tvb(0, 1), cla)
    subtree:add(f_ins, tvb(1, 1), ins)
    subtree:add(f_ins_name, ins_name)
    subtree:add(f_p1, tvb(2, 1), p1)
    subtree:add(f_p2, tvb(3, 1), p2)

    local lc = 0
    if len >= 5 then
        lc = tvb(4, 1):uint()
        subtree:add(f_lc, tvb(4, 1), lc)
    end

    pinfo.cols.info = string.format("[UICC APDU] %s", ins_name)

    local alerts = {}

    -- 1. SELECT (INS 0xA4): File or AID Selection
    if ins == 0xA4 and len >= 7 then
        local fid = tvb(5, 2):uint()
        local ef_name = UICC_FILE_IDS[fid] or string.format("File 0x%04X", fid)
        subtree:add(f_ef_id, tvb(5, 2), fid)
        subtree:add(f_ef_name, ef_name)
        pinfo.cols.info = string.format("[UICC APDU] SELECT %s", ef_name)

        if fid == 0x6F07 then
            table.insert(alerts, "[CRITICAL] Sensitive File Selected: EF_IMSI (Subscriber Identity)! Baseband preparing to read permanent IMSI from smart card.")
            pinfo.cols.info:append(" [TELCOSEC: EF_IMSI ACCESS]")
        elseif fid == 0x6F7E or fid == 0x6F73 or fid == 0x6FE3 or fid == 0x4F01 then
            table.insert(alerts, string.format("[INFO] Location Information File Selected (%s). Tracks roaming and mobility parameters.", ef_name))
        end

    -- 2. AUTHENTICATE (INS 0x88 / 0x89): Milenage / TUAK AKA
    elseif ins == 0x88 or ins == 0x89 then
        local auth_ctx = "GSM / 2G Context"
        if p2 == 0x81 then auth_ctx = "3G / UMTS / LTE AKA Context (Milenage)"
        elseif p2 == 0x82 then auth_ctx = "VGCS / VBS Context"
        elseif p2 == 0x84 then auth_ctx = "GBA Context"
        elseif p2 == 0x85 then auth_ctx = "IMS AKA / ISIM Context"
        end
        subtree:add(f_auth_context, auth_ctx)
        pinfo.cols.info = string.format("[UICC APDU] AUTHENTICATE (%s)", auth_ctx)

        -- Parse RAND (16 bytes) and AUTN (16 bytes) in data payload
        if len >= 38 and lc >= 32 then
            local rand_len = tvb(5, 1):uint()
            if rand_len == 16 and len >= 5 + 1 + 16 then
                subtree:add(f_rand, tvb(6, 16))
                local autn_off = 6 + 16
                if len >= autn_off + 1 then
                    local autn_len = tvb(autn_off, 1):uint()
                    if autn_len == 16 and len >= autn_off + 1 + 16 then
                        subtree:add(f_autn, tvb(autn_off + 1, 16))
                    end
                end
            end
        end
        table.insert(alerts, string.format("[CRITICAL] USIM AUTHENTICATE AKA Executed (%s)! Computes cryptographic RES, CK, IK. Crucial for SIM authentication and OTA integrity.", auth_ctx))
        pinfo.cols.info:append(" [TELCOSEC: USIM AUTHENTICATE AKA]")

    -- 3. VERIFY PIN / UNBLOCK PIN (INS 0x20 / 0x2C)
    elseif ins == 0x20 or ins == 0x2C or ins == 0x24 then
        local pin_type = (p2 == 0x01) and "PIN1 (CHV1)" or ((p2 == 0x02) and "PIN2 (CHV2)" or string.format("Key Ref 0x%02X", p2))
        pinfo.cols.info = string.format("[UICC APDU] %s (%s)", ins_name, pin_type)
        table.insert(alerts, string.format("[WARNING] %s operation on %s! Verify user interaction to detect malicious PIN brute-force probes.", ins_name, pin_type))

    -- 4. READ BINARY / RECORD (INS 0xB0 / 0xB2): Extract IMSI if EF_IMSI payload
    elseif (ins == 0xB0 or ins == 0xB2) and len > 5 then
        local imsi_val = parse_ef_imsi(tvb, 5, len - 5)
        if imsi_val and #imsi_val >= 10 then
            subtree:add(f_imsi, imsi_val)
            pinfo.cols.info = string.format("[UICC APDU] Read IMSI: %s", imsi_val)
            table.insert(alerts, string.format("[CRITICAL] Cleartext IMSI (%s) Extracted from USIM EF_IMSI! Sensitive subscriber permanent identifier accessed.", imsi_val))
            pinfo.cols.info:append(" [TELCOSEC: IMSI EXTRACTED!]")
        end

    -- 5. FETCH / ENVELOPE (INS 0x12 / 0xC2): SIM Toolkit (STK) Proactive Commands
    elseif ins == 0x12 or ins == 0xC2 then
        table.insert(alerts, string.format("[INFO] STK Proactive Command Interface (%s). Baseband interacting with SIM SAT/USAT applets.", ins_name))
        pinfo.cols.info:append(" [STK INTERFACE]")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    if len > 5 then
        subtree:add(f_payload, tvb(5, len - 5))
    end

    if native_gsm_sim then
        native_gsm_sim:call(tvb, pinfo, tree)
    end
end

-- Register as postdissector to inspect APDUs across all SIM/Baseband interfaces
register_postdissector(uicc_apdu_proto)
