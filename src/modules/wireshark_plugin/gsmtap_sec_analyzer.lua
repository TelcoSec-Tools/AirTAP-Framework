-- TelcoSec.net - GSMTAP Multi-RAT Air Interface & RF Security Analyzer
-- Description: Dissects GSMTAP encapsulation headers (UDP port 4729) emitted by AirTap, QCSuper,
--              OsmocomBB, and SDRs. Provides full decoding for 2G GSM, CBCH (Cell Broadcast),
--              GPRS (PACCH), 4G LTE (RRC/MAC/NAS), and 5G NR channels, along with RF distance tracking,
--              Carrier Frequency & Band calculations, and False Base Station / IMSI Catcher detection.

local ok, gsmtap_sec_proto = pcall(Proto, "gsmtap_sec", "TelcoSec GSMTAP Multi-RAT RF & Broadcast Analyzer")
if not ok or not gsmtap_sec_proto then return end

-- Protocol fields: Header
local f_version      = ProtoField.uint8("gsmtap_sec.version", "GSMTAP Version", base.DEC)
local f_hdr_len      = ProtoField.uint8("gsmtap_sec.hdr_len", "Header Length (words)", base.DEC)
local f_type         = ProtoField.string("gsmtap_sec.type", "Payload Type")
local f_timeslot     = ProtoField.uint8("gsmtap_sec.timeslot", "Timeslot (TN)", base.DEC)
local f_arfcn        = ProtoField.uint16("gsmtap_sec.arfcn", "ARFCN / EARFCN / NR-ARFCN", base.DEC)
local f_band         = ProtoField.string("gsmtap_sec.band", "Frequency Band")
local f_freq_dl_mhz  = ProtoField.float("gsmtap_sec.freq_dl_mhz", "Downlink Center Frequency (MHz)")
local f_freq_ul_mhz  = ProtoField.float("gsmtap_sec.freq_ul_mhz", "Uplink Center Frequency (MHz)")
local f_carrier_src  = ProtoField.string("gsmtap_sec.carrier_src", "Carrier Origin")
local f_uplink       = ProtoField.bool("gsmtap_sec.uplink", "Uplink Flag")
local f_snr          = ProtoField.uint8("gsmtap_sec.snr", "Signal-to-Noise Ratio (SNR dB)", base.DEC)
local f_signal_dbm   = ProtoField.int8("gsmtap_sec.signal_dbm", "Signal Level (dBm)", base.DEC)
local f_ta           = ProtoField.uint8("gsmtap_sec.ta", "Timing Advance (Distance)", base.DEC)
local f_distance_m   = ProtoField.float("gsmtap_sec.distance_m", "Estimated Distance (meters)")
local f_sub_type     = ProtoField.string("gsmtap_sec.sub_type", "Sub-type / Channel")
local f_sec_alert    = ProtoField.string("gsmtap_sec.alert", "TelcoSec GSMTAP RF Alert")
local f_payload      = ProtoField.bytes("gsmtap_sec.payload", "GSMTAP Payload")

-- Protocol fields: Cell Broadcast Service (CBS / CBCH TS 44.012 & TS 23.041)
local f_cbs_block_seq   = ProtoField.uint8("gsmtap_sec.cbs.block_seq",   "CBS Block Sequence",                 base.HEX)
local f_cbs_msg_id      = ProtoField.uint16("gsmtap_sec.cbs.msg_id",     "CBS Message Identifier",             base.HEX)
local f_cbs_msg_name    = ProtoField.string("gsmtap_sec.cbs.msg_name",   "CBS Message Name / Category")
local f_cbs_serial      = ProtoField.uint16("gsmtap_sec.cbs.serial",     "CBS Serial Number",                  base.HEX)
local f_cbs_geo_scope   = ProtoField.string("gsmtap_sec.cbs.geo_scope",  "Geographical Scope")
local f_cbs_update_num  = ProtoField.uint8("gsmtap_sec.cbs.update_num",  "Update Number",                      base.DEC)
local f_cbs_dcs         = ProtoField.uint8("gsmtap_sec.cbs.dcs",         "Data Coding Scheme (DCS)",           base.HEX)
local f_cbs_encoding    = ProtoField.string("gsmtap_sec.cbs.encoding",   "Character Encoding")
local f_cbs_lang        = ProtoField.string("gsmtap_sec.cbs.language",   "CBS Language")
local f_cbs_msg_class   = ProtoField.string("gsmtap_sec.cbs.msg_class",  "CBS Message Class")
local f_cbs_page        = ProtoField.uint8("gsmtap_sec.cbs.page",        "Current Page",                       base.DEC)
local f_cbs_total_pages = ProtoField.uint8("gsmtap_sec.cbs.total_pages", "Total Pages",                        base.DEC)
local f_cbs_text        = ProtoField.string("gsmtap_sec.cbs.text",       "Decoded CBS Alert Text")
local f_cbs_reassembled = ProtoField.string("gsmtap_sec.cbs.reassembled","Reassembled CBS Page Text")

gsmtap_sec_proto.fields = {
    f_version,
    f_hdr_len,
    f_type,
    f_timeslot,
    f_arfcn,
    f_band,
    f_freq_dl_mhz,
    f_freq_ul_mhz,
    f_carrier_src,
    f_uplink,
    f_snr,
    f_signal_dbm,
    f_ta,
    f_distance_m,
    f_sub_type,
    f_sec_alert,
    f_payload,
    f_cbs_block_seq,
    f_cbs_msg_id,
    f_cbs_msg_name,
    f_cbs_serial,
    f_cbs_geo_scope,
    f_cbs_update_num,
    f_cbs_dcs,
    f_cbs_encoding,
    f_cbs_lang,
    f_cbs_msg_class,
    f_cbs_page,
    f_cbs_total_pages,
    f_cbs_text,
    f_cbs_reassembled
}

-- Complete GSMTAP Types (3GPP / Osmocom / AirTap)
local GSMTAP_TYPES = {
    [1]  = "GSM Um",
    [2]  = "GSM Abis",
    [3]  = "GSM Um (Burst)",
    [4]  = "SIM (ISO 7816)",
    [5]  = "TETRA DMO",
    [6]  = "TETRA TMO",
    [7]  = "GMR-1 (Satellite)",
    [8]  = "WiMAX",
    [9]  = "U-Plane IP",
    [10] = "UMTS RRC",
    [11] = "LTE RRC",
    [12] = "LTE MAC",
    [13] = "LTE NAS",
    [14] = "E1/T1",
    [15] = "E2",
    [16] = "5G NR RRC",
    [17] = "5G NR MAC",
    [18] = "5GS NAS"
}

-- Channel Mapping for 2G GSM
local GSM_CHANNELS = {
    [0]  = "Unknown / Direct",
    [1]  = "BCCH",
    [2]  = "CCCH",
    [3]  = "RACH",
    [4]  = "AGCH",
    [5]  = "PCH",
    [6]  = "SDCCH/4",
    [7]  = "SDCCH/8",
    [8]  = "TCH/F",
    [9]  = "TCH/H",
    [10] = "PACCH",
    [11] = "CBCH",
    [12] = "SACCH"
}

-- ============================================================================
-- CBS Message Identifier Lookup (3GPP TS 23.041 Table 9.4.1.2.2-1)
-- Covers CMAS, ETWS, EU-Alert, WEA, J-Alert, Korean CBS, and operator ranges
-- ============================================================================
local CBS_MSG_EXACT = {
    [0x0000] = "Index / Channel Guide",
    [0x0001] = "CBS General Info",
    [0x0002] = "CBS General Async",
    [0x0003] = "CBS General Advice",
    [0x0004] = "CBS Regional Weather",
    [0x0005] = "CBS General News",
    [0x0006] = "CBS Regional News",
    [0x0007] = "CBS Local News",
    [0x0008] = "CBS Local Traffic",
    [0x0009] = "CBS GNSS",
    [0x0032] = "Channel 50 (Cell Broadcast / Local Cell Info)",
    -- EU-Alert (ETSI TS 102 900)
    [0x1100] = "EU-Alert Level 1 (National/Presidential)",
    [0x1101] = "EU-Alert Level 2 (Extreme)",
    [0x1102] = "EU-Alert Level 3 (Severe)",
    [0x1103] = "EU-Alert Amber Alert",
    [0x1104] = "EU-Alert Monthly Test",
    [0x1105] = "EU-Alert Exercise Alert",
    [0x1106] = "EU-Alert Operator Defined",
    [0x1107] = "EU-Alert Info Only",
    -- CMAS / WEA (3GPP TS 23.041 Section 9.4.1.2.2 Table)
    [0x1112] = "CMAS / Presidential Alert",
    [0x1113] = "CMAS / Extreme Imminent Threat",
    [0x1114] = "CMAS / Severe Threat Alert",
    [0x1115] = "CMAS / Child Abduction Emergency (Amber Alert)",
    [0x1116] = "CMAS / Required Monthly Test",
    [0x1117] = "CMAS / Exercise Alert",
    [0x1118] = "CMAS / Operator Defined",
    [0x1119] = "CMAS / Presidential Alert (Additional)",
    [0x111A] = "CMAS / Extreme Imminent Threat (Additional)",
    [0x111B] = "CMAS / Severe Threat (Additional)",
    [0x111C] = "CMAS / Child Abduction Emergency (Additional)",
    [0x111D] = "CMAS / Monthly Test (Additional)",
    [0x111E] = "CMAS / Exercise Alert (Additional)",
    [0x111F] = "CMAS / Operator Defined (Additional)",
    [0x1120] = "CMAS / Public Safety Alert",
    [0x1121] = "CMAS / State/Local Test",
    -- ETWS (3GPP TS 23.041)
    [0x1130] = "ETWS / Earthquake Warning",
    [0x1131] = "ETWS / Tsunami Warning",
    [0x1132] = "ETWS / Earthquake and Tsunami Warning",
    [0x1133] = "ETWS / Test",
    [0x1134] = "ETWS / Other Emergency",
}

-- Range-based CBS message category lookup (covers operator/national blocks)
local function lookup_cbs_msg_id(msg_id)
    -- Exact match first
    if CBS_MSG_EXACT[msg_id] then
        return CBS_MSG_EXACT[msg_id]
    end
    -- Range checks
    if msg_id >= 0x0000 and msg_id <= 0x03FF then
        return string.format("GSM Public Broadcast (0x%04X)", msg_id)
    elseif msg_id >= 0x0400 and msg_id <= 0x07FF then
        return string.format("GSM Local Broadcast (0x%04X)", msg_id)
    elseif msg_id >= 0x0800 and msg_id <= 0x0FFF then
        return string.format("Operator Broadcast (0x%04X)", msg_id)
    elseif msg_id >= 0x1000 and msg_id <= 0x10FF then
        return string.format("PLMN Operator Defined (0x%04X)", msg_id)
    elseif msg_id >= 0x1100 and msg_id <= 0x1107 then
        return string.format("EU-Alert (0x%04X)", msg_id)
    elseif msg_id >= 0x1112 and msg_id <= 0x1121 then
        return string.format("CMAS/WEA Alert (0x%04X)", msg_id)
    elseif msg_id >= 0x1130 and msg_id <= 0x1134 then
        return string.format("ETWS Warning (0x%04X)", msg_id)
    elseif msg_id >= 0x6000 and msg_id <= 0x60FF then
        return string.format("J-Alert Japan (0x%04X)", msg_id)
    elseif msg_id >= 0x7700 and msg_id <= 0x77FF then
        return string.format("Korean CBS Alert (0x%04X)", msg_id)
    elseif msg_id >= 0x8000 and msg_id <= 0xFFFF then
        return string.format("National/Operator Reserved (0x%04X)", msg_id)
    end
    return string.format("Unknown CBS ID (0x%04X)", msg_id)
end

-- Helper: is this a high-priority emergency alert ID?
local function is_emergency_alert_id(msg_id)
    return (msg_id >= 0x1100 and msg_id <= 0x1107) or  -- EU-Alert
           (msg_id >= 0x1112 and msg_id <= 0x1121) or  -- CMAS/WEA
           (msg_id >= 0x1130 and msg_id <= 0x1134) or  -- ETWS
           (msg_id >= 0x6000 and msg_id <= 0x60FF) or  -- J-Alert
           (msg_id >= 0x7700 and msg_id <= 0x77FF)     -- Korean
end

-- ============================================================================
-- GSM 7-bit Default Alphabet Table (3GPP TS 23.038 Table 1)
-- Uses a proper Lua array (0-indexed via offset 1) to avoid UTF-8 byte miscount
-- Each entry is the correct Unicode/UTF-8 glyph for septet value [0..127]
-- ============================================================================
local GSM7_TABLE = {
    [0]  = "@",  [1]  = "\xC2\xA3", -- £
    [2]  = "$",  [3]  = "\xC2\xA5", -- ¥
    [4]  = "\xC3\xA8", -- è
    [5]  = "\xC3\xA9", -- é
    [6]  = "\xC3\xB9", -- ù
    [7]  = "\xC3\xAC", -- ì
    [8]  = "\xC3\xB2", -- ò
    [9]  = "\xC3\x87", -- Ç
    [10] = "\n",
    [11] = "\xC3\x98", -- Ø
    [12] = "\xC3\xB8", -- ø
    [13] = "\r",
    [14] = "\xC3\x85", -- Å
    [15] = "\xC3\xA5", -- å
    [16] = "\xCE\x94", -- Δ
    [17] = "_",
    [18] = "\xCE\xA6", -- Φ
    [19] = "\xCE\x93", -- Γ
    [20] = "\xCE\x9B", -- Λ
    [21] = "\xCE\xA9", -- Ω
    [22] = "\xCE\xA0", -- Π
    [23] = "\xCE\xA8", -- Ψ
    [24] = "\xCE\xA3", -- Σ
    [25] = "\xCE\x98", -- Θ
    [26] = "\xCE\x9E", -- Ξ
    [27] = "[ESC]",    -- Escape (extension table prefix)
    [28] = "\xC3\x86", -- Æ
    [29] = "\xC3\xA6", -- æ
    [30] = "\xC3\x9F", -- ß
    [31] = "\xC3\x89", -- É
    [32] = " ",  [33] = "!",  [34] = "\"", [35] = "#",
    [36] = "\xC2\xA4", -- ¤
    [37] = "%",  [38] = "&",  [39] = "'",
    [40] = "(",  [41] = ")",  [42] = "*",  [43] = "+",
    [44] = ",",  [45] = "-",  [46] = ".",  [47] = "/",
    [48] = "0",  [49] = "1",  [50] = "2",  [51] = "3",
    [52] = "4",  [53] = "5",  [54] = "6",  [55] = "7",
    [56] = "8",  [57] = "9",  [58] = ":",  [59] = ";",
    [60] = "<",  [61] = "=",  [62] = ">",  [63] = "?",
    [64] = "\xC2\xA1", -- ¡
    [65] = "A",  [66] = "B",  [67] = "C",  [68] = "D",
    [69] = "E",  [70] = "F",  [71] = "G",  [72] = "H",
    [73] = "I",  [74] = "J",  [75] = "K",  [76] = "L",
    [77] = "M",  [78] = "N",  [79] = "O",  [80] = "P",
    [81] = "Q",  [82] = "R",  [83] = "S",  [84] = "T",
    [85] = "U",  [86] = "V",  [87] = "W",  [88] = "X",
    [89] = "Y",  [90] = "Z",
    [91] = "\xC3\x84", -- Ä
    [92] = "\xC3\x96", -- Ö
    [93] = "\xC3\x91", -- Ñ
    [94] = "\xC3\x9C", -- Ü
    [95] = "\xC2\xA7", -- §
    [96] = "\xC2\xBF", -- ¿
    [97] = "a",  [98] = "b",  [99] = "c",  [100] = "d",
    [101] = "e", [102] = "f", [103] = "g", [104] = "h",
    [105] = "i", [106] = "j", [107] = "k", [108] = "l",
    [109] = "m", [110] = "n", [111] = "o", [112] = "p",
    [113] = "q", [114] = "r", [115] = "s", [116] = "t",
    [117] = "u", [118] = "v", [119] = "w", [120] = "x",
    [121] = "y", [122] = "z",
    [123] = "\xC3\xA4", -- ä
    [124] = "\xC3\xB6", -- ö
    [125] = "\xC3\xB1", -- ñ
    [126] = "\xC3\xBC", -- ü
    [127] = "\xC3\xA0", -- à
}

-- Helper: unpack GSM 7-bit septets into a UTF-8 string.
-- Uses the GSM7_TABLE array to correctly resolve multi-byte glyphs.
-- Skips trailing CR (0x0D) and CBS fill character '+' (0x2B) padding per 3GPP TS 23.038 / TS 44.012.
local function unpack_gsm_7bit(tvb_data, offset, length)
    if length <= 0 then return "" end
    local bit_buffer   = 0
    local bits_in_buf  = 0
    local septets      = {}

    for i = 0, length - 1 do
        local byte = tvb_data(offset + i, 1):uint()
        bit_buffer  = bit_buffer + bit.lshift(byte, bits_in_buf)
        bits_in_buf = bits_in_buf + 8
        while bits_in_buf >= 7 do
            table.insert(septets, bit.band(bit_buffer, 0x7F))
            bit_buffer  = bit.rshift(bit_buffer, 7)
            bits_in_buf = bits_in_buf - 7
        end
    end

    -- Strip trailing CR (0x0D) and CBS fill character '+' (0x2B) padding
    while #septets > 0 and (septets[#septets] == 0x0D or septets[#septets] == 0x2B or septets[#septets] == 0x00) do
        table.remove(septets)
    end

    local parts = {}
    local i = 1
    while i <= #septets do
        local s = septets[i]
        if s == 0x1B then
            -- Extension table: skip the ESC and produce the literal next char
            i = i + 1
            if i <= #septets then
                parts[#parts + 1] = GSM7_TABLE[septets[i]] or "."
            end
        elseif s == 0x00 then
            -- Null byte — skip
        else
            parts[#parts + 1] = GSM7_TABLE[s] or "."
        end
        i = i + 1
    end
    return table.concat(parts)
end

-- ============================================================================
-- CBS DCS Parser (3GPP TS 23.038 Section 4 / TS 23.041 Section 9.4.1.2.1)
-- Returns: is_7bit (bool), encoding (string), language (string), msg_class (string)
-- ============================================================================
local CBS_DCS_LANGUAGES = {
    [0x00] = "German",     [0x01] = "English",    [0x02] = "Italian",
    [0x03] = "French",     [0x04] = "Spanish",    [0x05] = "Dutch",
    [0x06] = "Swedish",    [0x07] = "Danish",     [0x08] = "Portuguese",
    [0x09] = "Finnish",    [0x0A] = "Norwegian",  [0x0B] = "Greek",
    [0x0C] = "Turkish",    [0x0D] = "Hungarian",  [0x0E] = "Polish",
    [0x0F] = "Language Unspecified",
    [0x20] = "Czech",      [0x21] = "Hebrew",     [0x22] = "Arabic",
    [0x23] = "Russian",    [0x24] = "Icelandic",
}
local CBS_MSG_CLASSES = { [0] = "Class 0 (Flash)", [1] = "Class 1 (ME Default)", [2] = "Class 2 (SIM)", [3] = "Class 3 (TE)" }

local function parse_cbs_dcs(dcs)
    local encoding   = "GSM 7-bit Default"
    local language   = "Unspecified"
    local compressed = false
    local msg_class  = "Unspecified"
    local is_7bit    = true

    local coding_group = bit.rshift(bit.band(dcs, 0xF0), 4)

    if coding_group == 0x0 then
        -- Group 0x0X: Language + GSM 7-bit
        language = CBS_DCS_LANGUAGES[bit.band(dcs, 0x0F)] or "Unknown"
        encoding = "GSM 7-bit Default"
        is_7bit  = true

    elseif coding_group == 0x1 then
        -- Group 0x1X: Language using default alphabet + UCS2
        local lang_ind = bit.band(dcs, 0x0F)
        if lang_ind == 0x01 then
            encoding = "GSM 7-bit Default (language via UDH)"
            is_7bit  = true
        else
            language = CBS_DCS_LANGUAGES[lang_ind] or string.format("Language 0x%X", lang_ind)
            encoding = "UCS-2 (16-bit Unicode)"
            is_7bit  = false
        end

    elseif coding_group >= 0x4 and coding_group <= 0x7 then
        -- General Data Coding Indication (TS 23.038 Section 4)
        compressed = (bit.band(dcs, 0x20) ~= 0)
        local has_class = (bit.band(dcs, 0x10) ~= 0)
        local char_set  = bit.band(bit.rshift(dcs, 2), 0x03)
        if char_set == 0x00 then
            encoding = compressed and "GSM 7-bit (Compressed)" or "GSM 7-bit Default"
            is_7bit  = true
        elseif char_set == 0x01 then
            encoding = "8-bit Data"
            is_7bit  = false
        elseif char_set == 0x02 then
            encoding = compressed and "UCS-2 (Compressed)" or "UCS-2 (16-bit Unicode)"
            is_7bit  = false
        else
            encoding = "Reserved"
        end
        if has_class then
            msg_class = CBS_MSG_CLASSES[bit.band(dcs, 0x03)] or "Unknown Class"
        end

    elseif (coding_group >= 0x2 and coding_group <= 0x3) or (coding_group >= 0x8 and coding_group <= 0xE) then
        -- Reserved groups — treat as 7-bit
        encoding = string.format("Reserved DCS Group 0x%X — assumed 7-bit", coding_group)
        is_7bit  = true

    elseif coding_group == 0xF then
        -- Data coding / message handling group
        local char_set = bit.band(bit.rshift(dcs, 2), 0x01)
        if char_set == 0 then
            encoding = "GSM 7-bit Default"
            is_7bit  = true
        else
            encoding = "8-bit Data"
            is_7bit  = false
        end
        msg_class = CBS_MSG_CLASSES[bit.band(dcs, 0x03)] or "Unknown Class"
    end

    return is_7bit, encoding, language, msg_class
end

-- ============================================================================
-- CBS Security Heuristic Checker
-- Detects fake/spoofed emergency alerts and broadcast injection anomalies
-- ============================================================================
local function check_cbs_security(msg_id, geo_scope_bits, update_num, alert_text, cbs_tree, pinfo)
    local alerts = {}

    -- Heuristic 1: CMAS/PWS alert with wrong Geographical Scope
    -- Real CMAS uses GS=0 (Cell Wide Immediate). GS=3 (Cell Wide Normal) is suspicious.
    if is_emergency_alert_id(msg_id) then
        if geo_scope_bits == 3 then
            table.insert(alerts, string.format(
                "[CRITICAL] Emergency alert (0x%04X) uses GS=3 (Cell Wide Normal) instead of GS=0 (Cell Wide Immediate). " ..
                "Real CMAS/PWS alerts MUST use GS=0. Possible spoofed emergency broadcast injection!", msg_id))
        end
        -- Heuristic 2: Emergency alert with empty/whitespace-only text
        if alert_text == nil or #alert_text == 0 or alert_text:match("^%s*$") then
            table.insert(alerts, string.format(
                "[WARNING] Emergency alert (0x%04X) has empty or whitespace-only message body. " ..
                "May be a malformed injection probe or broadcast fuzzing attempt.", msg_id))
        end
        -- Heuristic 3: High update number on emergency alert (rapid re-broadcast / replay)
        if update_num >= 10 then
            table.insert(alerts, string.format(
                "[WARNING] Emergency alert (0x%04X) has high Update Number (%d). " ..
                "Rapid sequential update numbers may indicate a CBS replay / re-injection attack.", msg_id, update_num))
        end
    end

    -- Heuristic 4: ETWS Earthquake/Tsunami on non-emergency channel
    if msg_id >= 0x1130 and msg_id <= 0x1134 and geo_scope_bits ~= 0 then
        table.insert(alerts, string.format(
            "[CRITICAL] ETWS Warning (0x%04X) broadcast with non-immediate geographical scope (GS=%d). " ..
            "Verify cell origin for potential False Base Station emergency alert injection.", msg_id, geo_scope_bits))
    end

    for _, a in ipairs(alerts) do
        cbs_tree:add(f_sec_alert, a)
    end
    if #alerts > 0 then
        pinfo.cols.info:append(" [TELCOSEC: CBS SECURITY ALERT!]")
    end
end

-- ============================================================================
-- Multi-block CBCH Page Reassembly Cache (3GPP TS 44.012)
-- Key: msg_id .. "_" .. serial .. "_" .. page_num
-- Value: accumulated text segments from each 23-byte CBCH block
-- ============================================================================
local cbs_page_cache = {}

-- ============================================================================
-- RF Frequency & Carrier Band Calculation Engine (3GPP TS 45.005 / TS 36.101 / TS 38.101)
-- ============================================================================
local function calculate_gsm_carrier(arfcn, is_pcs)
    local band_name = "GSM-900"
    local f_dl = 0.0
    local f_ul = 0.0

    if is_pcs or (arfcn >= 512 and arfcn <= 810) then
        band_name = "DCS-1800 / PCS-1900"
        f_dl = 1805.2 + 0.2 * (arfcn - 512)
        f_ul = 1710.2 + 0.2 * (arfcn - 512)
    elseif arfcn >= 975 and arfcn <= 1023 then
        band_name = "E-GSM-900"
        f_dl = 925.2 + 0.2 * (arfcn - 975)
        f_ul = 880.2 + 0.2 * (arfcn - 975)
    else
        band_name = "P-GSM-900"
        f_dl = 935.0 + 0.2 * arfcn
        f_ul = 890.0 + 0.2 * arfcn
    end
    return band_name, f_dl, f_ul
end

local function calculate_lte_carrier(earfcn)
    local band_name = "LTE"
    local f_dl = 0.0
    local f_ul = 0.0

    if earfcn >= 0 and earfcn <= 599 then
        band_name = "Band 1 (2100 MHz FDD)"
        f_dl = 2110.0 + 0.1 * earfcn
        f_ul = 1920.0 + 0.1 * earfcn
    elseif earfcn >= 600 and earfcn <= 1199 then
        band_name = "Band 2 (1900 MHz PCS)"
        f_dl = 1930.0 + 0.1 * (earfcn - 600)
        f_ul = 1850.0 + 0.1 * (earfcn - 600)
    elseif earfcn >= 1200 and earfcn <= 1949 then
        band_name = "Band 3 (1800 MHz DCS)"
        f_dl = 1805.0 + 0.1 * (earfcn - 1200)
        f_ul = 1710.0 + 0.1 * (earfcn - 1200)
    elseif earfcn >= 1950 and earfcn <= 2399 then
        band_name = "Band 4 (1700/2100 MHz AWS-1)"
        f_dl = 2110.0 + 0.1 * (earfcn - 1950)
        f_ul = 1710.0 + 0.1 * (earfcn - 1950)
    elseif earfcn >= 2400 and earfcn <= 2649 then
        band_name = "Band 5 (850 MHz Cellular)"
        f_dl = 869.0 + 0.1 * (earfcn - 2400)
        f_ul = 824.0 + 0.1 * (earfcn - 2400)
    elseif earfcn >= 2750 and earfcn <= 3449 then
        band_name = "Band 7 (2600 MHz FDD)"
        f_dl = 2620.0 + 0.1 * (earfcn - 2750)
        f_ul = 2500.0 + 0.1 * (earfcn - 2750)
    elseif earfcn >= 3450 and earfcn <= 3799 then
        band_name = "Band 8 (900 MHz GSM)"
        f_dl = 925.0 + 0.1 * (earfcn - 3450)
        f_ul = 880.0 + 0.1 * (earfcn - 3450)
    elseif earfcn >= 5010 and earfcn <= 5179 then
        band_name = "Band 12 (700 MHz Lower a/b/c)"
        f_dl = 729.0 + 0.1 * (earfcn - 5010)
        f_ul = 699.0 + 0.1 * (earfcn - 5010)
    elseif earfcn >= 5180 and earfcn <= 5279 then
        band_name = "Band 13 (700 MHz Upper c)"
        f_dl = 746.0 + 0.1 * (earfcn - 5180)
        f_ul = 777.0 + 0.1 * (earfcn - 5180)
    elseif earfcn >= 5280 and earfcn <= 5379 then
        band_name = "Band 14 (700 MHz FirstNet)"
        f_dl = 758.0 + 0.1 * (earfcn - 5280)
        f_ul = 788.0 + 0.1 * (earfcn - 5280)
    elseif earfcn >= 5730 and earfcn <= 5849 then
        band_name = "Band 17 (700 MHz Lower b/c)"
        f_dl = 734.0 + 0.1 * (earfcn - 5730)
        f_ul = 704.0 + 0.1 * (earfcn - 5730)
    elseif earfcn >= 6000 and earfcn <= 6599 then
        band_name = "Band 20 (800 MHz Digital Dividend)"
        f_dl = 791.0 + 0.1 * (earfcn - 6000)
        f_ul = 832.0 + 0.1 * (earfcn - 6000)
    elseif earfcn >= 8040 and earfcn <= 8689 then
        band_name = "Band 25 (1900 MHz Extended PCS)"
        f_dl = 1930.0 + 0.1 * (earfcn - 8040)
        f_ul = 1850.0 + 0.1 * (earfcn - 8040)
    elseif earfcn >= 8690 and earfcn <= 9039 then
        band_name = "Band 26 (850 MHz Extended)"
        f_dl = 859.0 + 0.1 * (earfcn - 8690)
        f_ul = 814.0 + 0.1 * (earfcn - 8690)
    elseif earfcn >= 9210 and earfcn <= 9659 then
        band_name = "Band 28 (700 MHz APT)"
        f_dl = 758.0 + 0.1 * (earfcn - 9210)
        f_ul = 703.0 + 0.1 * (earfcn - 9210)
    elseif earfcn >= 37750 and earfcn <= 38249 then
        band_name = "Band 38 (2600 MHz TDD)"
        f_dl = 2570.0 + 0.1 * (earfcn - 37750)
        f_ul = f_dl
    elseif earfcn >= 38650 and earfcn <= 39649 then
        band_name = "Band 40 (2300 MHz TDD)"
        f_dl = 2300.0 + 0.1 * (earfcn - 38650)
        f_ul = f_dl
    elseif earfcn >= 39650 and earfcn <= 41589 then
        band_name = "Band 41 (2500 MHz BRS/EBS TDD)"
        f_dl = 2496.0 + 0.1 * (earfcn - 39650)
        f_ul = f_dl
    elseif earfcn >= 66436 and earfcn <= 67335 then
        band_name = "Band 66 (1700/2100 MHz AWS-3)"
        f_dl = 2110.0 + 0.1 * (earfcn - 66436)
        f_ul = 1710.0 + 0.1 * (earfcn - 66436)
    elseif earfcn >= 68586 and earfcn <= 68935 then
        band_name = "Band 71 (600 MHz US)"
        f_dl = 617.0 + 0.1 * (earfcn - 68586)
        f_ul = 663.0 + 0.1 * (earfcn - 68586)
    else
        band_name = string.format("LTE EARFCN %d", earfcn)
    end
    return band_name, f_dl, f_ul
end

local function calculate_nr_carrier(nrarfcn)
    local band_name = "5G NR"
    local f_mhz = 0.0
    if nrarfcn >= 0 and nrarfcn <= 599999 then
        f_mhz = nrarfcn * 0.005
    elseif nrarfcn >= 600000 and nrarfcn <= 2016666 then
        f_mhz = 3000.0 + (nrarfcn - 600000) * 0.015
    end
    if f_mhz >= 3300 and f_mhz <= 3800 then
        band_name = "Band n78 (3.5 GHz C-Band)"
    elseif f_mhz >= 700 and f_mhz <= 800 then
        band_name = "Band n28 (700 MHz)"
    elseif f_mhz >= 1700 and f_mhz <= 1900 then
        band_name = "Band n3 (1800 MHz)"
    else
        band_name = string.format("5G NR-ARFCN %d", nrarfcn)
    end
    return band_name, f_mhz, f_mhz
end

-- Stream Carrier Memory Tracking Table (remembers active carrier per source connection)
local stream_carrier_cache = {}

-- Native Wireshark sub-dissectors (cached for ultra-fast execution)
local lapdm_dissector        = Dissector.get("lapdm")
local gsm_a_ccch_dissector   = Dissector.get("gsm_a_ccch")
local gsm_a_dtap_dissector   = Dissector.get("gsm_a_dtap")
local gsm_cbs_dissector      = Dissector.get("gsm_cbs") or Dissector.get("gsm_cbch") or Dissector.get("gsm_sms")
local gsm_rlcmac_dl_dissector= Dissector.get("gsm_rlcmac_dl")
local gsm_rlcmac_ul_dissector= Dissector.get("gsm_rlcmac_ul")
local nas_eps_dissector      = Dissector.get("nas-eps")
local nas_5gs_dissector      = Dissector.get("nas-5gs")
local umts_rrc_dissector     = Dissector.get("rrc")

-- LTE RRC channels
local lte_rrc_bcch_bch       = Dissector.get("lte-rrc.bcch.bch") or Dissector.get("lte_rrc.bcch_bch")
local lte_rrc_bcch_dl_sch    = Dissector.get("lte-rrc.bcch.dl.sch") or Dissector.get("lte_rrc.bcch_dl_sch")
local lte_rrc_dl_ccch        = Dissector.get("lte-rrc.dl.ccch") or Dissector.get("lte_rrc.dl_ccch")
local lte_rrc_dl_dcch        = Dissector.get("lte-rrc.dl.dcch") or Dissector.get("lte_rrc.dl_dcch")
local lte_rrc_ul_ccch        = Dissector.get("lte-rrc.ul.ccch") or Dissector.get("lte_rrc.ul_ccch")
local lte_rrc_ul_dcch        = Dissector.get("lte-rrc.ul.dcch") or Dissector.get("lte_rrc.ul_dcch")
local lte_rrc_pcch           = Dissector.get("lte-rrc.pcch") or Dissector.get("lte_rrc.pcch")
local mac_lte_dissector      = Dissector.get("mac-lte") or Dissector.get("mac_lte")

-- 5G NR RRC channels
local nr_rrc_bcch_bch        = Dissector.get("nr-rrc.bcch.bch") or Dissector.get("nr_rrc.bcch_bch")
local nr_rrc_bcch_dl_sch     = Dissector.get("nr-rrc.bcch.dl.sch") or Dissector.get("nr_rrc.bcch_dl_sch")
local nr_rrc_dl_ccch         = Dissector.get("nr-rrc.dl.ccch") or Dissector.get("nr_rrc.dl_ccch")
local nr_rrc_dl_dcch         = Dissector.get("nr-rrc.dl.dcch") or Dissector.get("nr_rrc.dl_dcch")
local nr_rrc_ul_ccch         = Dissector.get("nr-rrc.ul.ccch") or Dissector.get("nr_rrc.ul_ccch")
local nr_rrc_ul_dcch         = Dissector.get("nr-rrc.ul.dcch") or Dissector.get("nr_rrc.ul_dcch")
local nr_rrc_pcch            = Dissector.get("nr-rrc.pcch") or Dissector.get("nr_rrc.pcch")
local mac_nr_dissector       = Dissector.get("mac-nr") or Dissector.get("mac_nr")

-- UICC / Smart card
local uicc_dissector         = Dissector.get("uicc_apdu_sec") or Dissector.get("gsm_sim")

function gsmtap_sec_proto.dissector(tvb, pinfo, tree)
    local tvb_len = tvb:len()
    if tvb_len < 16 then return end

    local version = tvb(0, 1):uint()
    if version ~= 1 and version ~= 2 then return end

    local hdr_words = tvb(1, 1):uint()
    local hdr_len = hdr_words * 4
    if tvb_len < hdr_len then return end

    local type_id = tvb(2, 1):uint()
    local timeslot = tvb(3, 1):uint()

    local raw_arfcn = tvb(4, 2):uint()
    local is_pcs = bit.band(raw_arfcn, 0x8000) ~= 0
    local is_uplink = bit.band(raw_arfcn, 0x4000) ~= 0
    local header_arfcn = bit.band(raw_arfcn, 0x3FFF)

    local signal_dbm = tvb(6, 1):int()
    local snr = tvb(7, 1):uint()
    local chan_id = tvb(12, 1):uint()
    local ta = tvb(14, 1):uint()

    -- Determine Type Name and RAT-Specific Channel Name with Direction Awareness
    local type_name = GSMTAP_TYPES[type_id] or string.format("Type %d", type_id)
    local chan_name = ""
    local proto_col_name = "GSMTAP"

    if type_id == 1 or type_id == 3 then
        chan_name = GSM_CHANNELS[chan_id] or string.format("GSM Chan %d", chan_id)
        if chan_id == 1 then
            proto_col_name = "GSM BCCH"
        elseif chan_id >= 2 and chan_id <= 5 then
            proto_col_name = "GSM CCCH"
        elseif chan_id == 6 or chan_id == 7 then
            proto_col_name = "GSM SDCCH"
        elseif chan_id == 10 then
            proto_col_name = "GPRS PACCH"
        elseif chan_id == 11 then
            proto_col_name = "GSM CBS"
        elseif chan_id == 12 then
            proto_col_name = "GSM SACCH"
        else
            proto_col_name = "GSM Um"
        end
    elseif type_id == 11 or type_id == 12 or type_id == 13 or type_id == 4 then
        if chan_id == 1 then
            chan_name = "LTE BCCH-BCH (MIB)"
            proto_col_name = "LTE RRC"
        elseif chan_id == 2 then
            chan_name = "LTE BCCH-DL-SCH (SIB)"
            proto_col_name = "LTE RRC"
        elseif chan_id == 3 or chan_id == 5 then
            chan_name = is_uplink and "LTE UL-CCCH" or "LTE DL-CCCH"
            proto_col_name = "LTE RRC"
        elseif chan_id == 4 or chan_id == 6 then
            chan_name = is_uplink and "LTE UL-DCCH" or "LTE DL-DCCH"
            proto_col_name = "LTE RRC"
        elseif chan_id == 7 then
            chan_name = "LTE PCCH (Paging)"
            proto_col_name = "LTE RRC"
        else
            chan_name = (type_id == 13) and "LTE NAS / Direct" or (is_uplink and "LTE UL-DCCH" or "LTE DL-DCCH")
            proto_col_name = (type_id == 13) and "LTE NAS" or "LTE RRC"
        end
    elseif type_id == 16 or type_id == 17 or type_id == 18 then
        if chan_id == 1 then
            chan_name = "5G BCCH-BCH (MIB)"
            proto_col_name = "5G NR RRC"
        elseif chan_id == 2 then
            chan_name = "5G BCCH-DL-SCH (SIB)"
            proto_col_name = "5G NR RRC"
        elseif chan_id == 3 or chan_id == 5 then
            chan_name = is_uplink and "5G UL-CCCH" or "5G DL-CCCH"
            proto_col_name = "5G NR RRC"
        elseif chan_id == 4 or chan_id == 6 then
            chan_name = is_uplink and "5G UL-DCCH" or "5G DL-DCCH"
            proto_col_name = (type_id == 18) and "5GS NAS" or "5G NR RRC"
        elseif chan_id == 7 then
            chan_name = "5G PCCH (Paging)"
            proto_col_name = "5G NR RRC"
        else
            chan_name = (type_id == 18) and "5GS NAS / Direct" or (is_uplink and "5G UL-DCCH" or "5G DL-DCCH")
            proto_col_name = (type_id == 18) and "5GS NAS" or "5G NR RRC"
        end
    else
        chan_name = type_name
        proto_col_name = type_name
    end

    pinfo.cols.protocol = proto_col_name

    -- ========================================================================
    -- Deep Carrier & ARFCN Tracking Engine
    -- ========================================================================
    local stream_key = tostring(pinfo.src) .. ":" .. tostring(type_id)
    local final_arfcn = header_arfcn
    local carrier_source = "GSMTAP Header"
    local band_str = "N/A"
    local f_dl = 0.0
    local f_ul = 0.0

    if header_arfcn > 0 then
        -- Valid carrier in GSMTAP header
        if type_id == 1 or type_id == 3 then
            band_str, f_dl, f_ul = calculate_gsm_carrier(header_arfcn, is_pcs)
        elseif type_id == 11 or type_id == 12 or type_id == 13 then
            band_str, f_dl, f_ul = calculate_lte_carrier(header_arfcn)
        elseif type_id == 16 or type_id == 17 or type_id == 18 then
            band_str, f_dl, f_ul = calculate_nr_carrier(header_arfcn)
        end
        -- Update stream cache
        stream_carrier_cache[stream_key] = {
            arfcn = header_arfcn,
            band = band_str,
            f_dl = f_dl,
            f_ul = f_ul
        }
    else
        -- Header has 0: Check stream memory cache from prior broadcast/cell-alloc packets
        local cached = stream_carrier_cache[stream_key]
        if cached ~= nil and cached.arfcn > 0 then
            final_arfcn = cached.arfcn
            band_str = cached.band
            f_dl = cached.f_dl
            f_ul = cached.f_ul
            carrier_source = "Carrier Memory Tracking"
        end
    end

    local dir_str = is_uplink and "UL (Phone -> BTS)" or "DL (BTS -> Phone)"
    local arfcn_str = (final_arfcn == 0) and "N/A" or tostring(final_arfcn)

    -- Dynamic RF Metadata Construction (Only append active, meaningful RF values)
    local rf_meta = {}
    if final_arfcn > 0 then
        table.insert(rf_meta, string.format("ARFCN: %d", final_arfcn))
    end
    if signal_dbm < 0 then
        table.insert(rf_meta, string.format("Signal: %d dBm", signal_dbm))
    end
    if ta > 0 then
        if type_id == 1 then
            table.insert(rf_meta, string.format("TA: %d (~%dm)", ta, math.floor(ta * 554.0)))
        else
            table.insert(rf_meta, string.format("TA: %d", ta))
        end
    end

    local rf_str = ""
    if #rf_meta > 0 then
        rf_str = " | " .. table.concat(rf_meta, ", ")
    end

    pinfo.cols.info = string.format("[%s %s] %s%s", type_name, dir_str, chan_name, rf_str)

    local subtree = tree:add(gsmtap_sec_proto, tvb(0, hdr_len), string.format("GSMTAP: %s | %s (%s, ARFCN: %s)", type_name, chan_name, dir_str, arfcn_str))
    subtree:add(f_version, tvb(0, 1), version)
    subtree:add(f_hdr_len, tvb(1, 1), hdr_words)
    subtree:add(f_type, type_name)
    subtree:add(f_sub_type, chan_name)
    subtree:add(f_timeslot, tvb(3, 1), timeslot)
    subtree:add(f_arfcn, tvb(4, 2), final_arfcn)
    subtree:add(f_carrier_src, carrier_source)

    if band_str ~= "N/A" then
        subtree:add(f_band, band_str)
        if f_dl > 0 then subtree:add(f_freq_dl_mhz, f_dl) end
        if f_ul > 0 then subtree:add(f_freq_ul_mhz, f_ul) end
    end

    subtree:add(f_uplink, tvb(4, 2), is_uplink)
    subtree:add(f_signal_dbm, tvb(6, 1), signal_dbm)
    subtree:add(f_snr, tvb(7, 1), snr)
    subtree:add(f_ta, tvb(14, 1), ta)
    if type_id == 1 and ta > 0 then
        subtree:add(f_distance_m, ta * 554.0)
    end

    -- Security Alert: Proximity IMSI Catcher Signal Surge
    if not is_uplink and signal_dbm < 0 and signal_dbm > -45 then
        subtree:add(f_sec_alert, string.format("[CRITICAL] Exceptionally high downlink signal (%d dBm)! Potential tactical IMSI Catcher nearby.", signal_dbm))
        pinfo.cols.info:append(" [TELCOSEC: PROXIMITY IMSI CATCHER!]")
    end

    -- Payload Sub-dissection with Direction-Aware Dispatch
    local payload_len = tvb_len - hdr_len
    if payload_len > 0 then
        local payload_tvb = tvb(hdr_len, payload_len):tvb()

        local function safe_call(subdissector)
            if not subdissector then return false end
            local success = pcall(function()
                subdissector:call(payload_tvb, pinfo, tree)
            end)
            return success
        end

        local dissected = false

        -- ====================================================================
        -- 1. 2G GSM & GPRS Air Interface (Type 1 or Type 3)
        -- ====================================================================
        if type_id == 1 or type_id == 3 then
            -- A. Common Channels: BCCH, CCCH, RACH, AGCH, PCH
            if (chan_id >= 1 and chan_id <= 5) then
                dissected = safe_call(gsm_a_ccch_dissector)

            -- B. Dedicated Channels: SDCCH/4, SDCCH/8, SACCH, TCH
            elseif (chan_id == 6 or chan_id == 7 or chan_id == 8 or chan_id == 9 or chan_id == 12) then
                dissected = safe_call(lapdm_dissector) or safe_call(gsm_a_dtap_dissector)

            -- C. GPRS Packet Associated Control Channel (PACCH)
            elseif chan_id == 10 then
                if is_uplink then
                    dissected = safe_call(gsm_rlcmac_ul_dissector)
                else
                    dissected = safe_call(gsm_rlcmac_dl_dissector)
                end

            -- D. Cell Broadcast Channel (CBCH - Full Built-in CBS Dissector with optimized fallback)
            elseif chan_id == 11 then
                if gsm_cbs_dissector then
                    safe_call(gsm_cbs_dissector)
                end

                -- Full Built-In 3GPP TS 44.012 & TS 23.041 CBS Security Analyzer
                local cbs_tree = tree:add(gsmtap_sec_proto, payload_tvb(), "GSM Cell Broadcast Security & Alert Analyzer")

                -- Determine if payload is TS 44.012 L2 block (1-byte Block Sequence, 23 bytes total)
                -- or direct TS 23.041 CBS Page (starts with 2-byte Serial Number)
                local byte0 = payload_tvb(0, 1):uint()
                local is_ts44012_l2 = (payload_len == 23 and byte0 < 0x10)

                local block_seq_byte = 0
                local block_pos = 0
                local is_last_block = true
                local serial_offset = 0

                if is_ts44012_l2 then
                    block_seq_byte = byte0
                    block_pos      = bit.band(block_seq_byte, 0x07)  -- 0..3
                    is_last_block  = bit.band(block_seq_byte, 0x08) ~= 0
                    serial_offset  = 1
                    cbs_tree:add(f_cbs_block_seq, payload_tvb(0, 1), block_seq_byte)
                end

                -- Decode Header: Serial Number (2B), Message ID (2B), DCS (1B), Page (1B)
                if (is_ts44012_l2 and block_pos == 0 and payload_len >= 7) or (not is_ts44012_l2 and payload_len >= 6) then
                    -- Serial Number (2 bytes): GS[15:14] | MsgCode[13:4] | UpdateNum[3:0]
                    local serial      = payload_tvb(serial_offset, 2):uint()
                    local gs_bits     = bit.rshift(bit.band(serial, 0xC000), 14)
                    local update_num  = bit.band(serial, 0x000F)
                    local gs_names    = { [0]="Cell Wide (Immediate)", [1]="PLMN Wide",
                                          [2]="Location Area Wide",    [3]="Cell Wide (Normal)" }
                    local gs_name     = gs_names[gs_bits] or "Unknown"
                    cbs_tree:add(f_cbs_serial,     payload_tvb(serial_offset, 2), serial)
                    cbs_tree:add(f_cbs_geo_scope,  gs_name)
                    cbs_tree:add(f_cbs_update_num, payload_tvb(serial_offset + 1, 1), update_num)

                    -- Message Identifier (2 bytes, big-endian)
                    local msg_id  = payload_tvb(serial_offset + 2, 2):uint()
                    local msg_cat = lookup_cbs_msg_id(msg_id)
                    cbs_tree:add(f_cbs_msg_id,   payload_tvb(serial_offset + 2, 2), msg_id)
                    cbs_tree:add(f_cbs_msg_name, msg_cat)

                    -- Data Coding Scheme — full parser
                    local dcs = payload_tvb(serial_offset + 4, 1):uint()
                    local is_7bit, encoding_str, language_str, class_str = parse_cbs_dcs(dcs)
                    cbs_tree:add(f_cbs_dcs,      payload_tvb(serial_offset + 4, 1), dcs)
                    cbs_tree:add(f_cbs_encoding, encoding_str)
                    if language_str and language_str ~= "Unspecified" then
                        cbs_tree:add(f_cbs_lang, language_str)
                    end
                    if class_str and class_str ~= "Unspecified" then
                        cbs_tree:add(f_cbs_msg_class, class_str)
                    end

                    -- Page indicator byte: CurrentPage[7:4] | TotalPages[3:0]
                    local page_byte   = payload_tvb(serial_offset + 5, 1):uint()
                    local page_num    = bit.rshift(bit.band(page_byte, 0xF0), 4)
                    local total_pages = bit.band(page_byte, 0x0F)
                    cbs_tree:add(f_cbs_page,        payload_tvb(serial_offset + 5, 1), page_num)
                    cbs_tree:add(f_cbs_total_pages, payload_tvb(serial_offset + 5, 1), total_pages)

                    -- Decode content bytes (6 bytes header, rest is CBS content)
                    local content_offset = serial_offset + 6
                    local content_len    = payload_len - content_offset
                    local block_text     = ""

                    if content_len > 0 then
                        if is_7bit then
                            block_text = unpack_gsm_7bit(payload_tvb, content_offset, content_len)
                        else
                            local ucs2_chars = {}
                            for i = 0, content_len - 2, 2 do
                                local c = payload_tvb(content_offset + i, 2):uint()
                                if c == 0x000D or c == 0x0000 or c == 0xFFFF then break end
                                if c < 128 and c >= 32 then
                                    table.insert(ucs2_chars, string.char(c))
                                else
                                    table.insert(ucs2_chars, string.format("\\u%04X", c))
                                end
                            end
                            block_text = table.concat(ucs2_chars)
                        end
                        if #block_text > 0 then
                            cbs_tree:add(f_cbs_text, block_text)
                        end
                    end

                    -- Multi-block CBCH page reassembly
                    local cache_key = string.format("%04X_%04X_%d", msg_id, serial, page_num)
                    if block_pos == 0 then
                        cbs_page_cache[cache_key] = { parts = {}, done = false }
                    end
                    local entry = cbs_page_cache[cache_key]
                    if entry and not entry.done then
                        entry.parts[block_pos + 1] = block_text
                        if is_last_block then
                            entry.done = true
                            local full_text = table.concat(entry.parts)
                            full_text = full_text:gsub("[\r\n]+$", "")
                            if #full_text > 0 then
                                cbs_tree:add(f_cbs_reassembled, full_text)
                                block_text = full_text
                            end
                        end
                    end

                    pinfo.cols.info = string.format(
                        "[GSM CBCH] %s | SN:0x%04X (%s) | %s",
                        msg_cat, serial, gs_name,
                        #block_text > 0 and block_text or
                            string.format("Page %d/%d Block %d%s",
                                page_num, total_pages, block_pos,
                                is_last_block and " [LAST]" or ""))

                    -- Security checks: fake/spoofed emergency alert detection
                    if is_emergency_alert_id(msg_id) then
                        cbs_tree:add(f_sec_alert,
                            string.format("[CRITICAL] High-priority Emergency Alert (0x%04X: %s) received over air! " ..
                                "Verify cell authenticity against False Base Station broadcast injection.",
                                msg_id, msg_cat))
                        pinfo.cols.info:append(" [TELCOSEC: EMERGENCY ALERT!]")
                    end
                    check_cbs_security(msg_id, gs_bits, update_num, block_text, cbs_tree, pinfo)

                    dissected = true
                elseif is_ts44012_l2 and block_pos > 0 and payload_len > 1 then
                    -- Continued CBCH block
                    local content_offset = 1
                    local content_len    = payload_len - 1
                    local block_text     = unpack_gsm_7bit(payload_tvb, content_offset, content_len)
                    if #block_text > 0 then
                        cbs_tree:add(f_cbs_text, block_text)
                    end
                    pinfo.cols.info = string.format("[GSM CBCH] Continued Block %d%s (%s)",
                        block_pos, is_last_block and " [LAST]" or "",
                        #block_text > 0 and block_text or string.format("%d bytes", content_len))
                    dissected = true
                else
                    dissected = true
                end
            else
                dissected = safe_call(gsm_a_ccch_dissector) or safe_call(gsm_a_dtap_dissector)
            end

        -- ====================================================================
        -- 2. 4G LTE Signaling (Direction-Aware RRC, MAC, NAS)
        -- ====================================================================
        elseif type_id == 13 then
            -- Direct LTE NAS (3GPP TS 24.301) vs 5GS NAS (3GPP TS 24.501) vs DCCH RRC Encapsulation
            local byte0 = payload_len >= 1 and payload_tvb(0, 1):uint() or 0
            local pd = bit.band(byte0, 0x0F)
            local sec = bit.band(bit.rshift(byte0, 4), 0x0F)

            if byte0 == 0x7E or byte0 == 0x2E then
                dissected = safe_call(nas_5gs_dissector)
            elseif (pd == 0x07 or pd == 0x02 or pd == 0x0D) and (sec <= 4 or sec == 12 or pd == 0x02) then
                -- Genuine LTE EPS NAS (EMM 0x07 / ESM 0x02 / ESM 0x0D - TS 24.301)
                dissected = safe_call(nas_eps_dissector)
            elseif payload_len > 8 then
                -- Standard RRC DL-DCCH message (e.g. rrcConnectionReconfiguration)
                if is_uplink then
                    dissected = safe_call(lte_rrc_ul_dcch)
                else
                    dissected = safe_call(lte_rrc_dl_dcch)
                end
            else
                -- Short AirTap LTE DCCH Control Frame (Avoid legacy PER CounterCheck malformed error)
                pinfo.cols.protocol = "LTE RRC/DCCH"
                pinfo.cols.info = string.format("[LTE RRC DL] AirTap DCCH Control (%d bytes)", payload_len)
                local dcch_tree = tree:add(gsmtap_sec_proto, payload_tvb(), string.format("AirTap LTE DCCH Control Frame (0x%s)", payload_tvb():bytes():tohex()))
                dcch_tree:add(f_carrier_src, "AirTap LTE DCCH Signaling")
                dissected = true
            end

        elseif type_id == 12 then
            -- LTE MAC (3GPP TS 36.321)
            dissected = safe_call(mac_lte_dissector)

        elseif type_id == 11 or type_id == 4 then
            -- LTE RRC (3GPP TS 36.331)
            if chan_id == 1 then
                dissected = safe_call(lte_rrc_bcch_bch) or safe_call(lte_rrc_bcch_dl_sch)
            elseif chan_id == 2 then
                dissected = safe_call(lte_rrc_bcch_dl_sch)
            elseif chan_id == 3 or chan_id == 5 then
                if is_uplink then
                    dissected = safe_call(lte_rrc_ul_ccch)
                else
                    dissected = safe_call(lte_rrc_dl_ccch)
                end
            elseif chan_id == 4 or chan_id == 6 then
                if payload_len > 8 then
                    if is_uplink then
                        dissected = safe_call(lte_rrc_ul_dcch)
                    else
                        dissected = safe_call(lte_rrc_dl_dcch)
                    end
                else
                    -- Short DCCH Control PDU
                    pinfo.cols.protocol = "LTE RRC/DCCH"
                    pinfo.cols.info = string.format("[LTE RRC DL] AirTap DCCH Control (%d bytes)", payload_len)
                    local dcch_tree = tree:add(gsmtap_sec_proto, payload_tvb(), string.format("AirTap LTE DCCH Control Frame (0x%s)", payload_tvb():bytes():tohex()))
                    dcch_tree:add(f_carrier_src, "AirTap LTE DCCH Signaling")
                    dissected = true
                end
            elseif chan_id == 7 then
                dissected = safe_call(lte_rrc_pcch)
            else
                -- Fallback
                if is_uplink then
                    dissected = safe_call(lte_rrc_ul_dcch) or safe_call(lte_rrc_ul_ccch)
                else
                    dissected = safe_call(lte_rrc_dl_dcch) or safe_call(lte_rrc_dl_ccch) or safe_call(lte_rrc_bcch_dl_sch)
                end
            end

        -- ====================================================================
        -- 3. 5G NR Signaling (Direction-Aware RRC, MAC, NAS)
        -- ====================================================================
        elseif type_id == 18 then
            -- Direct 5GS NAS (3GPP TS 24.501) vs LTE NAS (3GPP TS 24.301)
            local byte0 = payload_len >= 1 and payload_tvb(0, 1):uint() or 0
            local pd = bit.band(byte0, 0x0F)
            if byte0 == 0x7E or byte0 == 0x2E then
                dissected = safe_call(nas_5gs_dissector)
            elseif pd == 0x07 or pd == 0x02 or pd == 0x0D then
                -- AirTap tagged LTE NAS (EMM 0x07 / ESM 0x02 / 0x0D) as 5GS NAS -> Route cleanly to nas-eps
                dissected = safe_call(nas_eps_dissector)
            else
                dissected = safe_call(nas_5gs_dissector) or safe_call(nas_eps_dissector)
            end

        elseif type_id == 16 then
            if chan_id == 1 then
                dissected = safe_call(nr_rrc_bcch_bch) or safe_call(nr_rrc_bcch_dl_sch)
            elseif chan_id == 2 then
                dissected = safe_call(nr_rrc_bcch_dl_sch)
            elseif chan_id == 3 or chan_id == 5 then
                if is_uplink then
                    dissected = safe_call(nr_rrc_ul_ccch)
                else
                    dissected = safe_call(nr_rrc_dl_ccch)
                end
            elseif chan_id == 4 or chan_id == 6 then
                if is_uplink then
                    dissected = safe_call(nr_rrc_ul_dcch)
                else
                    dissected = safe_call(nr_rrc_dl_dcch)
                end
            elseif chan_id == 7 then
                dissected = safe_call(nr_rrc_pcch)
            else
                if is_uplink then
                    dissected = safe_call(nr_rrc_ul_dcch) or safe_call(nr_rrc_ul_ccch)
                else
                    dissected = safe_call(nr_rrc_dl_dcch) or safe_call(nr_rrc_dl_ccch) or safe_call(nr_rrc_bcch_dl_sch)
                end
            end

        -- 5G MAC (Type 17)
        elseif type_id == 17 then
            dissected = safe_call(mac_nr_dissector)

        -- ====================================================================
        -- 4. UMTS 3G RRC (Type 10)
        -- ====================================================================
        elseif type_id == 10 then
            dissected = safe_call(umts_rrc_dissector)

        -- ====================================================================
        -- 5. SIM / Smart Card APDU (Type 4)
        -- ====================================================================
        elseif type_id == 4 then
            dissected = safe_call(uicc_dissector)
        end

        if not dissected then
            subtree:add(f_payload, tvb(hdr_len, payload_len))
        end
    end
end

-- Clear caches on capture reload
function gsmtap_sec_proto.init()
    stream_carrier_cache = {}
    cbs_page_cache = {}
end

-- Register to GSMTAP UDP port 4729
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(4729, gsmtap_sec_proto)
end
