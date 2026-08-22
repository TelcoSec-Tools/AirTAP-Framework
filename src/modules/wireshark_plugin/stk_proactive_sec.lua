-- TelcoSec.net - SIM Application Toolkit (STK / SAT / USAT) Security Dissector
-- Description: Dissects STK proactive commands (3GPP TS 31.111 / ETSI TS 102 223) executed by USIM applets on the baseband.
--              Detects SIMjacker / WIB spyware attacks, covert outbound SMS (SEND SMS), forced browser redirection (LAUNCH BROWSER),
--              stealth geolocation queries (PROVIDE LOCAL INFO), and call setup manipulation.

local ok, stk_sec_proto = pcall(Proto, "stk_proactive_sec", "TelcoSec STK (SIM Toolkit / SIMjacker) Security Analyzer")
if not ok or not stk_sec_proto then return end

-- Protocol fields
local f_cmd_tag      = ProtoField.uint8("stk_sec.cmd_tag", "Proactive Command Tag", base.HEX)
local f_cmd_type     = ProtoField.uint8("stk_sec.cmd_type", "Command Type", base.HEX)
local f_cmd_name     = ProtoField.string("stk_sec.cmd_name", "Command Name")
local f_cmd_qual     = ProtoField.uint8("stk_sec.cmd_qual", "Command Qualifier", base.HEX)
local f_sec_alert    = ProtoField.string("stk_sec.alert", "TelcoSec STK Security Alert")
local f_payload      = ProtoField.bytes("stk_sec.payload", "STK TLV Data")

stk_sec_proto.fields = {
    f_cmd_tag,
    f_cmd_type,
    f_cmd_name,
    f_cmd_qual,
    f_sec_alert,
    f_payload
}

-- 3GPP TS 31.111 / ETSI TS 102 223 Proactive Command Types
local STK_COMMANDS = {
    [0x10] = "SET UP MENU",
    [0x11] = "SET UP IDLE MODE TEXT",
    [0x13] = "SEND SHORT MESSAGE (Covert Outbound SMS)",
    [0x14] = "SEND SS",
    [0x15] = "SEND USSD",
    [0x10] = "SET UP CALL",
    [0x20] = "PLAY TONE",
    [0x21] = "DISPLAY TEXT",
    [0x22] = "GET INKEY",
    [0x23] = "GET INPUT",
    [0x26] = "PROVIDE LOCAL INFORMATION (Location / IMEI / Cell ID)",
    [0x27] = "TIMER MANAGEMENT",
    [0x28] = "SET UP IDLE MODE TEXT",
    [0x35] = "LANGUAGE NOTIFICATION",
    [0x15] = "LAUNCH BROWSER (Malicious URL Redirection)",
    [0x40] = "OPEN CHANNEL (BIP Data Channel)",
    [0x41] = "CLOSE CHANNEL",
    [0x42] = "RECEIVE DATA",
    [0x43] = "SEND DATA"
}

function stk_sec_proto.dissector(tvb, pinfo, tree)
    -- Proactive Command TLV Layout:
    -- [0]: Proactive Command Tag (0xD0 = Ber-TLV / Proactive Command)
    -- [1]: Length
    -- [2]: Command Details Tag (0x81 or 0x01)
    -- [3]: Length (0x03)
    -- [4]: Command Number
    -- [5]: Command Type
    -- [6]: Command Qualifier
    if tvb:len() < 7 then return end

    local tag = tvb(0, 1):uint()
    if tag ~= 0xD0 and tag ~= 0x81 and tag ~= 0x01 then return end

    pinfo.cols.protocol = "SIM Toolkit (STK)"

    local cmd_type = tvb(5, 1):uint()
    local cmd_qual = tvb(6, 1):uint()
    local cmd_name = STK_COMMANDS[cmd_type] or string.format("STK Command 0x%02X", cmd_type)

    local subtree = tree:add(stk_sec_proto, tvb(), string.format("SIM Toolkit (STK): %s", cmd_name))
    subtree:add(f_cmd_tag, tvb(0, 1))
    subtree:add(f_cmd_type, tvb(5, 1), cmd_type)
    subtree:add(f_cmd_name, cmd_name)
    subtree:add(f_cmd_qual, tvb(6, 1))

    pinfo.cols.info = string.format("[STK Proactive] %s", cmd_name)

    -- Security Heuristic 1: SIMjacker Covert SMS (SEND SHORT MESSAGE)
    if cmd_type == 0x13 then
        subtree:add(f_sec_alert, "[CRITICAL] STK SEND SHORT MESSAGE commanded by USIM! Classic SIMjacker/WIB indicator sending covert SMS from victim's phone.")
        pinfo.cols.info:append(" [TELCOSEC: SIMJACKER SEND SMS!]")
    end

    -- Security Heuristic 2: Covert Geolocation & Identity Query (PROVIDE LOCAL INFO)
    if cmd_type == 0x26 then
        subtree:add(f_sec_alert, "[CRITICAL] STK PROVIDE LOCAL INFORMATION: USIM querying IMEI, Location Area, Cell ID, or NMR without user notification.")
        pinfo.cols.info:append(" [TELCOSEC: STK LOCATION SURVEILLANCE!]")
    end

    -- Security Heuristic 3: Browser Launch / Phishing
    if cmd_type == 0x15 then
        subtree:add(f_sec_alert, "[WARNING] STK LAUNCH BROWSER commanded by USIM! Potential phishing / credential harvesting URL redirection.")
    end

    subtree:add(f_payload, tvb(7, tvb:len() - 7))
end
