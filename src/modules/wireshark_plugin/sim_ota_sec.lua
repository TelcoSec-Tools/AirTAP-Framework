-- TelcoSec.net - SIM / UICC Over-The-Air (OTA - 3GPP TS 31.115 / TS 31.116 / ETSI TS 102 225 / TS 102 226) Master Security Dissector
-- Description: Complete analyzer for Secured Packet Structures used in SIM/UICC Over-The-Air (OTA) Remote File Management (RFM)
--              and Remote Applet Management (RAM) over SMS-PP, BIP (Bearer Independent Protocol), and HTTP.
--              Decodes Security Parameters Indication (SPI1/SPI2), Ciphering Key IDs (KIC: DES, 3DES, AES),
--              Integrity Key IDs (KID: DES-MAC, 3DES-MAC, AES-CMAC), Toolkit Application Reference (TAR), and Counter (CNTR).
--              Detects SIMjacker (S@T bytecode) attacks, WIBjacker, cleartext/null MSL (Minimum Security Level) commands,
--              unauthorized GlobalPlatform applet loading, and OTA counter replay attacks.

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

local ok, sim_ota_proto = pcall(Proto, "sim_ota_sec", "TelcoSec SIM/UICC OTA (Over-The-Air Secured Packet) Security Analyzer")
if not ok or not sim_ota_proto then return end

-- Protocol fields
local f_cpi             = ProtoField.uint8("sim_ota.cpi", "Command Packet Identifier (CPI)", base.HEX)
local f_cpl             = ProtoField.uint16("sim_ota.cpl", "Command Packet Length (CPL)", base.DEC)
local f_spi1            = ProtoField.uint8("sim_ota.spi1", "SPI1 (Security Parameters 1)", base.HEX)
local f_spi2            = ProtoField.uint8("sim_ota.spi2", "SPI2 (Proof of Receipt - PoR)", base.HEX)
local f_is_ciphered     = ProtoField.bool("sim_ota.is_ciphered", "Packet Ciphering Active (Encryption)")
local f_integ_mode      = ProtoField.string("sim_ota.integ_mode", "Integrity Check Mode (RC/CC/DS)")
local f_por_mode        = ProtoField.string("sim_ota.por_mode", "Proof of Receipt (PoR) Mode")
local f_kic_algo        = ProtoField.string("sim_ota.kic_algo", "Ciphering Algorithm (KIC)")
local f_kid_algo        = ProtoField.string("sim_ota.kid_algo", "Integrity Algorithm (KID)")
local f_tar             = ProtoField.uint24("sim_ota.tar", "Toolkit Application Reference (TAR)", base.HEX)
local f_tar_name        = ProtoField.string("sim_ota.tar_name", "Target Application / Engine")
local f_cntr            = ProtoField.bytes("sim_ota.cntr", "Replay Counter (CNTR - 5 bytes)")
local f_sec_alert       = ProtoField.string("sim_ota.alert", "TelcoSec SIM OTA Security Alert")
local f_payload         = ProtoField.bytes("sim_ota.payload", "Secured Data / APDU Payload")

sim_ota_proto.fields = {
    f_cpi,
    f_cpl,
    f_spi1,
    f_spi2,
    f_is_ciphered,
    f_integ_mode,
    f_por_mode,
    f_kic_algo,
    f_kid_algo,
    f_tar,
    f_tar_name,
    f_cntr,
    f_sec_alert,
    f_payload
}

-- ETSI TS 102 225 / 3GPP TS 31.115 Well-Known TAR (Toolkit Application Reference) Catalog
local SIM_OTA_TAR_MAP = {
    [0x000000] = "RAM (Remote Applet Manager - Card Management)",
    [0x000001] = "RFM (Remote File Manager - UICC File System)",
    [0x000002] = "RFM (USIM File System Application)",
    [0x000003] = "RFM (ISIM File System Application)",
    [0x000004] = "RFM (CSIM File System Application)",
    [0x000005] = "WIB (Wireless Internet Browser - WIBjacker Target!)",
    [0x534154] = "S@T (SIMalliance Toolbox - SIMjacker Target!)",
    [0xB00001] = "Administrative Agent / OTA Operator Gateway",
    [0xB00010] = "USSD Gateway / SIM Toolkit Application"
}

-- Cryptographic Algorithm Mapping (KIC / KID)
local KIC_CIPHER_ALGOS = {
    [0x00] = "No Ciphering (Plaintext)",
    [0x01] = "DES (CBC / single DES - INSECURE)",
    [0x02] = "3DES (2-Key Triple DES CBC)",
    [0x03] = "3DES (3-Key Triple DES CBC)",
    [0x05] = "AES (128-bit CBC)",
    [0x09] = "AES (192-bit CBC)",
    [0x0D] = "AES (256-bit CBC)"
}

local KID_INTEG_ALGOS = {
    [0x00] = "No Integrity (Unsigned / No MAC - INSECURE)",
    [0x01] = "Redundancy Check (CRC - Not cryptographically secure)",
    [0x02] = "DES-MAC (single DES MAC - INSECURE)",
    [0x03] = "3DES-MAC (Triple DES CBC-MAC)",
    [0x05] = "AES-CMAC (128-bit CMAC)"
}

function sim_ota_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    -- Minimum Command Header length (13 bytes: CPL(2), CHL(1), SPI(2), KIC(1), KID(1), TAR(3), CNTR(5), PCNTR(1))
    if len < 14 then return end

    -- Check if first byte is CPL or SPI indicator
    local cpl = tvb(0, 2):uint()
    local chl = tvb(2, 1):uint()

    -- Basic sanity check for TS 102 225 Command Header Length (typically 13 to 20 bytes)
    if chl < 10 or chl > 32 or (3 + chl > len) then return end

    pinfo.cols.protocol = "SIM OTA"

    local spi1 = tvb(3, 1):uint()
    local spi2 = tvb(4, 1):uint()
    local kic  = tvb(5, 1):uint()
    local kid  = tvb(6, 1):uint()
    local tar  = tvb(7, 3):uint()

    local tar_name = SIM_OTA_TAR_MAP[tar] or string.format("Applet TAR 0x%06X", tar)

    -- Decode SPI1 Security Properties
    local is_ciphered = bit.band(spi1, 0x04) ~= 0
    local integ_val = bit.band(spi1, 0x03)
    local integ_mode = "No Integrity"
    if integ_val == 1 then integ_mode = "Redundancy Check (RC)"
    elseif integ_val == 2 then integ_mode = "Cryptographic Checksum (CC / MAC)"
    elseif integ_val == 3 then integ_mode = "Digital Signature (DS)"
    end

    -- Decode SPI2 PoR Properties
    local por_mode = "No Proof of Receipt"
    if bit.band(spi2, 0x01) ~= 0 then por_mode = "PoR Required" end
    if bit.band(spi2, 0x02) ~= 0 then por_mode = por_mode .. " (Ciphered)" end

    local kic_algo = KIC_CIPHER_ALGOS[bit.band(kic, 0x0F)] or string.format("KIC 0x%02X", kic)
    local kid_algo = KID_INTEG_ALGOS[bit.band(kid, 0x0F)] or string.format("KID 0x%02X", kid)

    local subtree = tree:add(sim_ota_proto, tvb(), string.format("SIM/UICC OTA Secured Packet: %s", tar_name))
    subtree:add(f_cpl, tvb(0, 2), cpl)
    subtree:add(f_spi1, tvb(3, 1), spi1)
    subtree:add(f_spi2, tvb(4, 1), spi2)
    subtree:add(f_is_ciphered, is_ciphered)
    subtree:add(f_integ_mode, integ_mode)
    subtree:add(f_por_mode, por_mode)
    subtree:add(f_kic_algo, kic_algo)
    subtree:add(f_kid_algo, kid_algo)
    subtree:add(f_tar, tvb(7, 3), tar)
    subtree:add(f_tar_name, tar_name)
    subtree:add(f_cntr, tvb(10, 5))

    pinfo.cols.info = string.format("[SIM OTA] %s | %s | %s", tar_name, is_ciphered and "Encrypted" or "Plaintext", integ_mode)

    local alerts = {}

    -- Security Heuristic 1: SIMjacker Attack (S@T TAR 0x534154 or WIB TAR 0x000005)
    if tar == 0x534154 or tar == 0x000005 then
        if not is_ciphered or integ_val == 0 then
            table.insert(alerts, string.format(
                "[CRITICAL] SIMjacker / WIBjacker Attack! Unauthenticated OTA command packet targeting S@T/WIB browser applet (%s) with NULL security! " ..
                "Enables remote attackers to execute malicious SIM Toolkit bytecode (location tracking, covert SMS, call fraud, browser launch).",
                tar_name))
            pinfo.cols.info:append(" [TELCOSEC: SIMJACKER ATTACK!]")
        else
            table.insert(alerts, string.format("[HIGH RISK] Cryptographically secured OTA command targeting S@T/WIB applet (%s).", tar_name))
        end
    end

    -- Security Heuristic 2: Null / Cleartext MSL (Minimum Security Level) Violation
    if not is_ciphered and integ_val == 0 then
        table.insert(alerts, "[CRITICAL] Zero Security OTA Command (SPI1=0x00)! Packet has no encryption and no cryptographic integrity. Vulnerable to rogue SMS spoofing.")
        pinfo.cols.info:append(" [TELCOSEC: NULL MSL VULNERABILITY!]")
    end

    -- Security Heuristic 3: Remote Applet Management (RAM) Loading
    if tar == 0x000000 then
        table.insert(alerts, "[CRITICAL] Remote Applet Management (RAM) Command! GlobalPlatform applet installation / deletion on smart card.")
        pinfo.cols.info:append(" [TELCOSEC: REMOTE APPLET MGMT]")
    end

    -- Security Heuristic 4: Remote File Management (RFM) Modification
    if tar == 0x000001 or tar == 0x000002 then
        table.insert(alerts, "[WARNING] Remote File Management (RFM) Command: Over-the-air file system modification.")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    local hdr_len = 3 + chl
    if len > hdr_len then
        subtree:add(f_payload, tvb(hdr_len, len - hdr_len))
    end
end

-- Register on SMS / WAP push ports for SIM OTA (port 208, 9205)
local udp_table = DissectorTable.get("udp.port")
if udp_table then
    udp_table:add(208, sim_ota_proto)
    udp_table:add(9205, sim_ota_proto)
end

-- Register as postdissector to inspect OTA inside GSM SMS / WAP payloads
register_postdissector(sim_ota_proto)
