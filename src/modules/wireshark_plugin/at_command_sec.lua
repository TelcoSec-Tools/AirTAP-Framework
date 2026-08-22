-- TelcoSec.net - AT Command Interface (3GPP TS 27.007 / TS 27.005 / ITU-T V.250 & Vendor) Master Security Dissector
-- Description: Complete analyzer for Hayes AT commands and Unsolicited Result Codes (URCs) across USB serial, CDC-ACM, and baseband UARTs.
--              Decodes SIM/UICC management (+CRSM, +CSIM, +CGLA, +CPIN, +CLCK), Network Registration (+COPS, +CREG, +CGREG, +CEREG, +C5GREG),
--              Packet Domain (+CGDCONT APN injection, +CGACT), Call Control (ATD, ATA, ATH, +CLCC), SMS (+CMGS, +CMGR),
--              and Vendor Baseband Engineering extensions (Qualcomm $QCRMCALL, Quectel +QENG, Huawei ^SETPORT, Sierra !BAND).
--              Detects direct smart card APDU theft, rogue APN provisioning, silent call/SMS toll fraud, and baseband debug escalations.

local ok, at_cmd_proto = pcall(Proto, "at_command_sec", "TelcoSec AT Command Interface Security Analyzer")
if not ok or not at_cmd_proto then return end

-- Protocol fields
local f_raw_cmd         = ProtoField.string("at_sec.raw_cmd", "Raw AT Command / Response Line")
local f_cmd_category    = ProtoField.string("at_sec.category", "Command Category")
local f_cmd_name        = ProtoField.string("at_sec.cmd_name", "Command / Verb Name")
local f_direction       = ProtoField.string("at_sec.direction", "Direction (Command vs Response/URC)")
local f_apn             = ProtoField.string("at_sec.apn", "Configured APN / DNN Name")
local f_dial_num        = ProtoField.string("at_sec.dial_num", "Dialed Phone Number")
local f_pdp_type        = ProtoField.string("at_sec.pdp_type", "PDP Context Type (IP/IPV6/IPV4V6)")
local f_rat_pref        = ProtoField.string("at_sec.rat_pref", "Configured RAT / Band Selection")
local f_sec_alert       = ProtoField.string("at_sec.alert", "TelcoSec AT Security Alert")
local f_payload         = ProtoField.bytes("at_sec.payload", "AT Raw Payload Bytes")

at_cmd_proto.fields = {
    f_raw_cmd,
    f_cmd_category,
    f_cmd_name,
    f_direction,
    f_apn,
    f_dial_num,
    f_pdp_type,
    f_rat_pref,
    f_sec_alert,
    f_payload
}

-- Standard AT Commands Dictionary (3GPP TS 27.007 / 27.005)
local AT_COMMAND_CATALOG = {
    -- SIM & Smart Card Management
    ["+CRSM"]    = { name = "Restricted SIM Access",       cat = "SIM & Smart Card Security",   risk = "CRITICAL" },
    ["+CSIM"]    = { name = "Generic SIM Access",          cat = "SIM & Smart Card Security",   risk = "CRITICAL" },
    ["+CGLA"]    = { name = "Generic Logical Channel SIM", cat = "SIM & Smart Card Security",   risk = "CRITICAL" },
    ["+CPIN"]    = { name = "Enter PIN / PUK",             cat = "SIM Security & Auth",         risk = "HIGH" },
    ["+CLCK"]    = { name = "Facility Lock / Unlock",      cat = "SIM & Network Locking",       risk = "HIGH" },
    ["+CPWD"]    = { name = "Change Password",             cat = "SIM Security & Auth",         risk = "MEDIUM" },
    ["+CPINR"]   = { name = "Remaining PIN Retries",       cat = "SIM Security & Auth",         risk = "INFO" },
    ["+CCID"]    = { name = "Card Identification (ICCID)", cat = "Hardware Identification",     risk = "INFO" },
    ["+QCCID"]   = { name = "Quectel Card ID (ICCID)",     cat = "Hardware Identification",     risk = "INFO" },
    ["+CIMI"]    = { name = "Request IMSI",                cat = "Subscriber Identity",         risk = "HIGH" },

    -- Network Registration & Radio Control
    ["+COPS"]    = { name = "Operator Selection",          cat = "Network Selection & RAT",     risk = "MEDIUM" },
    ["+CREG"]    = { name = "2G/3G Network Registration",  cat = "Network Registration Status", risk = "INFO" },
    ["+CGREG"]   = { name = "GPRS Network Registration",   cat = "Network Registration Status", risk = "INFO" },
    ["+CEREG"]   = { name = "LTE EPS Registration",        cat = "Network Registration Status", risk = "INFO" },
    ["+C5GREG"]  = { name = "5G NR Registration",          cat = "Network Registration Status", risk = "INFO" },
    ["+CFUN"]    = { name = "Set Phone Functionality",     cat = "Radio Power State",           risk = "MEDIUM" },
    ["+CSQ"]     = { name = "Signal Quality Report",       cat = "Radio Quality",               risk = "INFO" },
    ["+CESQ"]    = { name = "Extended Signal Quality",     cat = "Radio Quality",               risk = "INFO" },
    ["+WS46"]    = { name = "Select Wireless Network",     cat = "Network Selection & RAT",     risk = "MEDIUM" },

    -- Packet Data & APN
    ["+CGDCONT"] = { name = "Define PDP Context / APN",    cat = "Packet Data & APN Provisioning", risk = "CRITICAL" },
    ["+CGACT"]   = { name = "PDP Context Activate/Deact",  cat = "Packet Data Connection",      risk = "MEDIUM" },
    ["+CGDATA"]  = { name = "Enter Data State",            cat = "Packet Data Connection",      risk = "INFO" },
    ["+CGPADDR"] = { name = "Show PDP Address",            cat = "Packet Data Connection",      risk = "INFO" },

    -- Call & Audio Control
    ["ATD"]      = { name = "Dial Voice/Data Call",        cat = "Call Control",                risk = "HIGH" },
    ["ATA"]      = { name = "Answer Call",                 cat = "Call Control",                risk = "MEDIUM" },
    ["ATH"]      = { name = "Hook / Hangup Call",          cat = "Call Control",                risk = "INFO" },
    ["+CLCC"]    = { name = "List Current Calls",          cat = "Call Control & Monitoring",   risk = "MEDIUM" },
    ["+CHLD"]    = { name = "Call Related Supplementary",  cat = "Call Control",                risk = "INFO" },
    ["+VTS"]     = { name = "Send DTMF Tone",              cat = "Voice & Audio Signaling",     risk = "MEDIUM" },

    -- SMS & Messaging
    ["+CMGS"]    = { name = "Send SMS Message",            cat = "SMS & Messaging",             risk = "HIGH" },
    ["+CMSS"]    = { name = "Send SMS from Storage",       cat = "SMS & Messaging",             risk = "HIGH" },
    ["+CMGW"]    = { name = "Write SMS to Memory",         cat = "SMS & Messaging",             risk = "MEDIUM" },
    ["+CMGR"]    = { name = "Read SMS Message",            cat = "SMS & Messaging",             risk = "HIGH" },
    ["+CMGL"]    = { name = "List SMS Messages",           cat = "SMS & Messaging",             risk = "HIGH" },
    ["+CSMS"]    = { name = "Select Message Service",      cat = "SMS & Messaging",             risk = "INFO" },
    ["+CNMI"]    = { name = "New Message Indications",     cat = "SMS & Messaging",             risk = "INFO" },

    -- Device Identity & Hardware
    ["+CGSN"]    = { name = "Request IMEI Serial",         cat = "Hardware Identification",     risk = "HIGH" },
    ["+CGMR"]    = { name = "Request Firmware Revision",   cat = "Hardware Identification",     risk = "INFO" },
    ["+CGMI"]    = { name = "Request Manufacturer ID",     cat = "Hardware Identification",     risk = "INFO" },
    ["+CGMM"]    = { name = "Request Model ID",            cat = "Hardware Identification",     risk = "INFO" },

    -- Vendor Baseband Proprietary Extensions
    ["+QENG"]    = { name = "Quectel Engineering Mode",    cat = "Baseband Engineering Mode",   risk = "HIGH" },
    ["+QNWINFO"] = { name = "Quectel Network Info",        cat = "Baseband Engineering Mode",   risk = "INFO" },
    ["+QCFG"]    = { name = "Quectel Advanced Config",     cat = "Modem Hardware Config",      risk = "HIGH" },
    ["$QCRMCALL"]= { name = "Qualcomm RMNET Call Setup",   cat = "Qualcomm Proprietary Data",   risk = "MEDIUM" },
    ["$QCSIMAPP"]= { name = "Qualcomm Select SIM App",     cat = "Qualcomm SIM Control",        risk = "HIGH" },
    ["^SETPORT"] = { name = "Huawei USB Port Mode Set",    cat = "Huawei Modem Control",        risk = "HIGH" },
    ["!BAND"]    = { name = "Sierra Band Locking",         cat = "Sierra Wireless Control",     risk = "HIGH" },
    ["!CUSTOM"]  = { name = "Sierra Factory Configuration",cat = "Sierra Wireless Control",     risk = "CRITICAL" }
}

function at_cmd_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 2 then return end

    local text = tvb:raw()
    local clean_text = text:gsub("[\r\n]", " ")
    pinfo.cols.protocol = "Cellular AT"

    local is_response = (string.find(text, "^OK") or string.find(text, "^ERROR") or string.find(text, "^%+") or string.find(text, "^RING"))
    local dir_str = is_response and "Response / URC" or "Command (TE -> ME)"

    local subtree = tree:add(at_cmd_proto, tvb(), string.format("Cellular AT Interface: %s", clean_text))
    subtree:add(f_raw_cmd, clean_text)
    subtree:add(f_direction, dir_str)

    pinfo.cols.info = string.format("[AT %s] %s", is_response and "RSP" or "CMD", clean_text)

    local alerts = {}
    local matched_cmd = nil
    local upper_text = string.upper(text)

    -- Match against AT catalog
    for verb, meta in pairs(AT_COMMAND_CATALOG) do
        if string.find(upper_text, verb, 1, true) then
            matched_cmd = verb
            subtree:add(f_cmd_name, string.format("%s (%s)", verb, meta.name))
            subtree:add(f_cmd_category, meta.cat)

            -- 1. Direct Smart Card APDU / Crypto Key Extraction (+CRSM, +CSIM, +CGLA)
            if verb == "+CRSM" or verb == "+CSIM" or verb == "+CGLA" then
                table.insert(alerts, string.format("[CRITICAL] Direct Smart Card APDU Execution (%s)! Host application issuing raw ISO-7816 APDUs to SIM. Potential crypto key extraction or SIM cloning probe.", verb))
                pinfo.cols.info:append(" [TELCOSEC: SIM APDU EXECUTION!]")

            -- 2. Rogue APN Injection (+CGDCONT)
            elseif verb == "+CGDCONT" then
                local apn_match = string.match(text, '"+CGDCONT"[^,]+,[^,]+,"([^"]+)"') or string.match(text, '%+CGDCONT:[^,]+,[^,]+,"([^"]+)"') or string.match(text, '%+CGDCONT=[^,]+,[^,]+,"([^"]+)"')
                if apn_match then
                    subtree:add(f_apn, apn_match)
                    table.insert(alerts, string.format("[CRITICAL] APN Profile Defined (%s)! Verify APN name against carrier whitelist to prevent ad-fraud, proxy redirection, or mobile malware tunneling.", apn_match))
                    pinfo.cols.info:append(string.format(" [APN: %s]", apn_match))
                else
                    table.insert(alerts, "[HIGH RISK] AT+CGDCONT PDP context definition executed.")
                end

            -- 3. Dial Voice Call (ATD) / Silent SMS (+CMGS)
            elseif verb == "ATD" then
                local dial_num = string.match(text, "ATD%s*([^;]+);") or string.match(text, "ATD%s*([^;]+)")
                if dial_num then
                    subtree:add(f_dial_num, dial_num)
                    table.insert(alerts, string.format("[HIGH RISK] Outbound Call Dialed (%s) via AT command! Potential automated toll fraud / silent call initiation.", dial_num))
                    pinfo.cols.info:append(string.format(" [DIAL: %s]", dial_num))
                end
            elseif verb == "+CMGS" or verb == "+CMSS" then
                table.insert(alerts, "[HIGH RISK] Outbound SMS Dispatch via AT+CMGS/CMSS! Verify application authorization to detect covert premium-rate SMS malware.")
                pinfo.cols.info:append(" [TELCOSEC: OUTBOUND SMS!]")

            -- 4. Baseband Engineering Mode / Band Lock Escalation (+QENG, ^SETPORT, !BAND)
            elseif verb == "+QENG" or verb == "^SETPORT" or verb == "!BAND" or verb == "!CUSTOM" then
                table.insert(alerts, string.format("[HIGH RISK] Baseband Engineering / Port Configuration Command (%s)! Overrides modem factory mode or radio band selection.", verb))
                pinfo.cols.info:append(" [TELCOSEC: MODEM CONFIG OVERRIDE!]")

            -- 5. Radio Power State / Airplane Mode (+CFUN)
            elseif verb == "+CFUN" then
                table.insert(alerts, "[WARNING] Baseband Radio Functionality (+CFUN) power state modified.")
            end

            break
        end
    end

    if not matched_cmd then
        subtree:add(f_cmd_category, "Standard AT Command / Unsolicited Code")
    end

    if #alerts > 0 then
        for _, alert_msg in ipairs(alerts) do
            subtree:add(f_sec_alert, alert_msg)
        end
    end

    subtree:add(f_payload, tvb())
end

-- Register to TCP/UDP ports 8000, 2000, 5000 (virtual serial sockets)
local tcp_table = DissectorTable.get("tcp.port")
if tcp_table then
    tcp_table:add(8000, at_cmd_proto)
    tcp_table:add(2000, at_cmd_proto)
    tcp_table:add(5000, at_cmd_proto)
end

-- Register as postdissector
register_postdissector(at_cmd_proto)
