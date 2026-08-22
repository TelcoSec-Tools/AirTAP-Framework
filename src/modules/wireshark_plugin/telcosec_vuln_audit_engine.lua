-- TelcoSec.net - Master Telecom Vulnerabilities & Carrier Bad Practices Audit Engine
-- Description: Real-time post-dissector continuously inspecting 2G, 3G, 4G, 5G, IMS/VoLTE,
--              GTP, SS7, and Baseband signaling streams. Detects known telecom CVEs, operator
--              misconfigurations, cryptographic downgrades, IMSI catcher traps, and carrier bad practices.

local ok, vuln_audit_proto = pcall(Proto, "telcosec_audit", "TelcoSec Master Telecom Vulnerability & Carrier Bad Practices Audit Engine")
if not ok or not vuln_audit_proto then return end

-- Protocol fields
local f_vuln_id     = ProtoField.string("telcosec_audit.vuln_id", "Vulnerability / Issue ID")
local f_severity    = ProtoField.string("telcosec_audit.severity", "Severity Level")
local f_category    = ProtoField.string("telcosec_audit.category", "Threat Category")
local f_title       = ProtoField.string("telcosec_audit.title", "Issue Title")
local f_description = ProtoField.string("telcosec_audit.description", "Description & Remediation Guidance")
local f_evidence    = ProtoField.string("telcosec_audit.evidence", "Extracted Telecom Evidence")

vuln_audit_proto.fields = {
    f_vuln_id,
    f_severity,
    f_category,
    f_title,
    f_description,
    f_evidence
}

-- Safe field getter helper
local function safe_field(name)
    local ok_f, f = pcall(Field.new, name)
    return ok_f and f or nil
end

-- Native Wireshark field extractors across various protocol stacks
local f_gsm_a_cipher_alg   = safe_field("gsm_a.rr.ciphering_algorithm")
local f_gsm_a_cipher_sc    = safe_field("gsm_a.rr.cipher_mode_setting") or safe_field("gsm_a.rr.cm_command")
local f_gsm_a_dtap_msg     = safe_field("gsm_a.dtap.msg_type")
local f_gsm_a_dtap_rej_cau = safe_field("gsm_a.dtap.reject_cause")
local f_gsm_sms_tp_pid     = safe_field("gsm_sms.tp_pid")
local f_gsm_sms_tp_dcs     = safe_field("gsm_sms.tp_dcs")

local f_lte_rrc_eea        = safe_field("lte_rrc.cipheringAlgorithm") or safe_field("lte-rrc.cipheringAlgorithm")
local f_lte_rrc_eia        = safe_field("lte_rrc.integrityProtAlgorithm") or safe_field("lte-rrc.integrityProtAlgorithm")
local f_nas_eps_sec_hdr    = safe_field("nas_eps.security_header_type") or safe_field("nas-eps.security_header_type")

local f_nr_rrc_nea         = safe_field("nr_rrc.cipheringAlgorithm") or safe_field("nr-rrc.cipheringAlgorithm")
local f_nr_rrc_nia         = safe_field("nr_rrc.integrityProtAlgorithm") or safe_field("nr-rrc.integrityProtAlgorithm")
local f_nas_5gs_sec_hdr    = safe_field("nas_5gs.security_header_type") or safe_field("nas-5gs.security_header_type")
local f_nr_snssai          = safe_field("nas_5gs.mm.s_nssai") or safe_field("nas-5gs.mm.s_nssai") or safe_field("nas_5gs.sm.s_nssai")

local f_sip_from           = safe_field("sip.from.addr")
local f_sip_pai            = safe_field("sip.P-Asserted-Identity")
local f_sip_identity       = safe_field("sip.Identity") or safe_field("sip.Passport")
local f_sdp_proto          = safe_field("sdp.proto")
local f_gtp_msg_type       = safe_field("gtp.message_type") or safe_field("gtpv2.message_type")
local f_diameter_cmd       = safe_field("diameter.cmd.code")
local f_sctp_chunk         = safe_field("sctp.chunk_type")
local f_eap_type           = safe_field("eap.type")
local f_eap_code           = safe_field("eap.code")
local f_http2_path         = safe_field("http2.header.path")
local f_http2_auth         = safe_field("http2.header.authorization") or safe_field("http.authorization")
local f_map_op             = safe_field("gsm_map.old.Component") or safe_field("gsm_map.Component")

-- APN / DNN Fields
local f_gsm_apn            = safe_field("gsm_a.sm.apn") or safe_field("gsm_a.dtap.apn")
local f_lte_apn            = safe_field("nas_eps.esm.access_point_name") or safe_field("nas-eps.esm.access_point_name") or safe_field("nas_eps.esm.apn")
local f_nr_dnn             = safe_field("nas_5gs.sm.dnn") or safe_field("nas-5gs.sm.dnn") or safe_field("nas_5gs.dnn")
local f_gtp_apn            = safe_field("gtp.apn") or safe_field("gtpv2.apn")

-- SIM / USIM APDU & STK Fields
local f_uicc_ins           = safe_field("uicc_apdu_sec.ins")
local f_stk_cmd            = safe_field("stk_proactive_sec.cmd_type")

-- Database of Audited Vulnerabilities & Bad Practices
local VULN_DB = {
    ["TELCOSEC-VULN-001"] = {
        id = "TELCOSEC-VULN-001",
        sev = "CRITICAL",
        cat = "Cryptography",
        title = "A5/0 Null Ciphering Enacted (2G GSM)",
        desc = "The base station commanded the handset to transmit all voice and SMS in plaintext (A5/0). Highly indicative of rogue IMSI Catchers or critical network misconfiguration."
    },
    ["TELCOSEC-VULN-002"] = {
        id = "TELCOSEC-VULN-002",
        sev = "HIGH",
        cat = "Cryptography",
        title = "A5/1 Deprecated Cipher Negotiation (2G GSM)",
        desc = "Network negotiated the deprecated A5/1 stream cipher, which is vulnerable to real-time rainbow table cracking. Operator should enforce A5/3."
    },
    ["TELCOSEC-VULN-003"] = {
        id = "TELCOSEC-VULN-003",
        sev = "CRITICAL",
        cat = "Cryptography",
        title = "EEA0 Null Ciphering on LTE Radio Bearer",
        desc = "LTE User-Plane traffic is transmitted without encryption (EEA0). Allows passive over-the-air interception of user IP packets."
    },
    ["TELCOSEC-VULN-004"] = {
        id = "TELCOSEC-VULN-004",
        sev = "CRITICAL",
        cat = "Cryptography",
        title = "NEA0 Null Ciphering on 5G NR Radio Bearer",
        desc = "5G NR User-Plane traffic is transmitted in cleartext (NEA0). User data is completely unencrypted over 5G radio."
    },
    ["TELCOSEC-VULN-005"] = {
        id = "TELCOSEC-VULN-005",
        sev = "HIGH",
        cat = "Cryptography",
        title = "EIA0 / NIA0 Null Integrity on Non-Emergency Traffic",
        desc = "Null integrity (EIA0 / NIA0) negotiated on standard commercial connection. Allows unauthenticated frame tampering and injection."
    },
    ["TELCOSEC-VULN-006"] = {
        id = "TELCOSEC-VULN-006",
        sev = "HIGH",
        cat = "Privacy",
        title = "5G SUPI Plaintext Exposure (Null-Scheme)",
        desc = "Handset transmitted cleartext IMSI/SUPI over 5G Initial NAS without ECIES SUCI public-key protection. Subscriber identity is exposed to passive radio sniffers."
    },
    ["TELCOSEC-VULN-007"] = {
        id = "TELCOSEC-VULN-007",
        sev = "HIGH",
        cat = "Radio Traps",
        title = "Unauthenticated Location Updating Reject Attack",
        desc = "Handset received Location Updating Reject with Cause #2, #3, or #6, which disables cellular access on the SIM card until reboot. Characteristic IMSI Catcher registration kill."
    },
    ["TELCOSEC-VULN-008"] = {
        id = "TELCOSEC-VULN-008",
        sev = "CRITICAL",
        cat = "Tracking",
        title = "Silent SMS (Type 0 / Ping Tracking)",
        desc = "Handset received a Silent SMS (TP-PID: 0x40 / Type 0). The phone acknowledges receipt at L2 without displaying any notification, covertly exposing cell location."
    },
    ["TELCOSEC-VULN-009"] = {
        id = "TELCOSEC-VULN-009",
        sev = "CRITICAL",
        cat = "SIM Security",
        title = "Binary SIMjacker / S@T Bytecode Execution Probe",
        desc = "Incoming SMS contains binary bytecode addressing the SIM Card Toolkit (STK / UICC) on port 208/9205 without cryptographic security headers."
    },
    ["TELCOSEC-VULN-010"] = {
        id = "TELCOSEC-VULN-010",
        sev = "HIGH",
        cat = "Core Network",
        title = "Cleartext GTP-U User-Plane Bearer",
        desc = "Mobile subscriber IP data packets transported over unencrypted GTP-U tunnel without IPSec encapsulation across telecom IP backhaul."
    },
    ["TELCOSEC-VULN-011"] = {
        id = "TELCOSEC-VULN-011",
        sev = "CRITICAL",
        cat = "OpenRAN",
        title = "OpenRAN eCPRI Remote Reset Attack",
        desc = "Unauthenticated eCPRI Remote Reset control packet received on fronthaul interface, forcing a physical reboot of the O-RU."
    },
    ["TELCOSEC-VULN-012"] = {
        id = "TELCOSEC-VULN-012",
        sev = "HIGH",
        cat = "Subscriber DB",
        title = "Diameter HSS User-Data / XML Profile Exfiltration",
        desc = "Diameter Sh User-Data-Request (UDR) or multimedia authentication extraction without roaming interconnect IPsec filtering."
    },
    ["TELCOSEC-VULN-013"] = {
        id = "TELCOSEC-VULN-013",
        sev = "HIGH",
        cat = "Wi-Fi Offload",
        title = "Cleartext IMSI Leak in EAP-SIM / EAP-AKA Identity Response",
        desc = "Handset transmitted cleartext permanent IMSI instead of pseudonym in EAP-Response/Identity over carrier Wi-Fi offload."
    },
    ["TELCOSEC-VULN-014"] = {
        id = "TELCOSEC-VULN-014",
        sev = "CRITICAL",
        cat = "Signaling Backbone",
        title = "Rogue SCTP ABORT Chunk Connection Termination",
        desc = "SCTP ABORT chunk injected into core signaling backbone (NGAP/S1AP/SIGTRAN), forcefully killing telecom control plane association."
    },
    ["TELCOSEC-VULN-015"] = {
        id = "TELCOSEC-VULN-015",
        sev = "CRITICAL",
        cat = "SIM Security",
        title = "WIBjacker (Wireless Internet Browser Application Attack)",
        desc = "Incoming SMS targeted the SIM Wireless Internet Browser (WIB) applet (TAR: 0x000005) without cryptographic SPI authentication, attempting unauthorized SIM command execution."
    },
    ["TELCOSEC-VULN-016"] = {
        id = "TELCOSEC-VULN-016",
        sev = "HIGH",
        cat = "SIM Security",
        title = "PIN / PUK Brute-Force Verification Probe",
        desc = "Repeated VERIFY PIN (0x20) or UNBLOCK PIN (0x2C) APDU commands observed with decreasing retry counters, indicative of PIN brute-force attempts."
    },
    ["TELCOSEC-VULN-017"] = {
        id = "TELCOSEC-VULN-017",
        sev = "HIGH",
        cat = "SIM Security",
        title = "Stealth STK Location / IMEI Polling",
        desc = "Continuous STK PROVIDE LOCAL INFORMATION (0x26) commands executed without user notification to secretly extract IMEI, Cell ID, and Location Area Code."
    },
    ["TELCOSEC-VULN-018"] = {
        id = "TELCOSEC-VULN-018",
        sev = "CRITICAL",
        cat = "APN Security",
        title = "Rogue / Malicious APN Activation (MitM Data Proxy)",
        desc = "Handset requested activation or network commanded connection to known rogue, ad-fraud, or data hijacking APN."
    },
    ["TELCOSEC-VULN-019"] = {
        id = "TELCOSEC-VULN-019",
        sev = "HIGH",
        cat = "APN Security",
        title = "Wildcard / Blank APN Bearer Misconfiguration",
        desc = "PDP Context / PDU Session established with empty or wildcard ('*') APN, bypassing core network security policies and traffic segregation."
    },
    ["TELCOSEC-VULN-020"] = {
        id = "TELCOSEC-VULN-020",
        sev = "CRITICAL",
        cat = "Cryptography",
        title = "A5/2 Obsolete & Banned Cipher Commanded (2G GSM)",
        desc = "Base station commanded the obsolete A5/2 cipher algorithm, which is completely broken and forbidden by 3GPP. Strong indicator of active rogue IMSI Catcher."
    },
    ["TELCOSEC-VULN-021"] = {
        id = "TELCOSEC-VULN-021",
        sev = "HIGH",
        cat = "5G SBA",
        title = "5G SBA OAuth 2.0 Token Missing / Unsigned",
        desc = "Sensitive 5G Core REST API accessed (e.g. UDM, AUSF, NRF) without valid OAuth 2.0 Bearer authorization header, exposing network functions to rogue NF impersonation."
    },
    ["TELCOSEC-VULN-022"] = {
        id = "TELCOSEC-VULN-022",
        sev = "CRITICAL",
        cat = "5G Slicing",
        title = "5G Network Slicing (S-NSSAI) Unauthorized Access",
        desc = "Handset requested access to unauthorized, private enterprise, or administrative S-NSSAI network slice without valid subscription entitlement."
    },
    ["TELCOSEC-VULN-023"] = {
        id = "TELCOSEC-VULN-023",
        sev = "HIGH",
        cat = "IMS / VoLTE",
        title = "STIR/SHAKEN Identity Verification Failure / Missing PASSporT",
        desc = "SIP call dispatched without cryptographic STIR/SHAKEN PASSporT token (RFC 8224/8588) or with invalid attestation, facilitating illegal robocalling spoofing."
    },
    ["TELCOSEC-VULN-024"] = {
        id = "TELCOSEC-VULN-024",
        sev = "CRITICAL",
        cat = "Baseband Security",
        title = "OTA ASN.1 Malformed Length / Baseband Fuzzing Probe",
        desc = "Over-the-air RRC/NAS ASN.1 container carries malformed length or out-of-bounds fields indicative of baseband stack heap/stack overflow fuzzing."
    },
    ["TELCOSEC-VULN-025"] = {
        id = "TELCOSEC-VULN-025",
        sev = "HIGH",
        cat = "SS7 / Roaming",
        title = "SMS Home Routing Bypass (MAP SRI-SM Interception)",
        desc = "Direct MAP SendRoutingInfoForSM (SRI-SM) query received from external PLMN bypassing SMS Home Router/Firewall, exposing subscriber IMSI and MSC address."
    },
    ["TELCOSEC-BADPRAC-001"] = {
        id = "TELCOSEC-BADPRAC-001",
        sev = "CARRIER_BAD_PRACTICE",
        cat = "Radio Config",
        title = "Abnormal Cell Reselection Offset Inflation (CRO > 20 dB)",
        desc = "System Information broadcasts an artificially inflated Cell Reselection Offset (>20 dB), aggressively forcing handsets to latch onto this cell. Typical of False Base Station traps."
    },
    ["TELCOSEC-BADPRAC-002"] = {
        id = "TELCOSEC-BADPRAC-002",
        sev = "HIGH",
        cat = "Radio Config",
        title = "Forced 2G Downgrade Redirection via LTE SIB7",
        desc = "LTE Base Station broadcasts SIB7 with high priority or sends RRCConnectionReject with GERAN redirection, forcing 4G devices down to vulnerable 2G networks."
    },
    ["TELCOSEC-BADPRAC-003"] = {
        id = "TELCOSEC-BADPRAC-003",
        sev = "CARRIER_BAD_PRACTICE",
        cat = "IMS / VoLTE",
        title = "Unencrypted VoLTE Voice Streams (RTP/AVP)",
        desc = "VoLTE HD voice call negotiated plaintext RTP/AVP instead of secure SRTP (RTP/SAVP). Voice calls can be recorded by network wiretaps."
    },
    ["TELCOSEC-BADPRAC-004"] = {
        id = "TELCOSEC-BADPRAC-004",
        sev = "HIGH",
        cat = "IMS / VoLTE",
        title = "Caller ID / P-Asserted-Identity Mismatch (Spoofing)",
        desc = "SIP INVITE 'From' header does not match authenticated carrier 'P-Asserted-Identity' (PAI). Originating carrier permitted unverified Caller ID spoofing."
    },
    ["TELCOSEC-BADPRAC-005"] = {
        id = "TELCOSEC-BADPRAC-005",
        sev = "CRITICAL",
        cat = "Lawful Interception",
        title = "Cleartext LEA Handover over Public Transport",
        desc = "Lawful Interception Intercept Related Information (IRI) or Content of Communication (CC) transmitted without mandatory TLS/IPsec protection."
    },
    ["TELCOSEC-BADPRAC-006"] = {
        id = "TELCOSEC-BADPRAC-006",
        sev = "HIGH",
        cat = "APN Security",
        title = "Admin / Internal APN Exposure over Public Radio",
        desc = "Access requested or granted to private carrier administrative APNs ('ims', 'xcap', 'sos', 'internal.admin') without proper security context."
    }
}

function vuln_audit_proto.dissector(tvb, pinfo, tree)
    -- Early exit for short packets or non-telecom broadcast traffic
    if tvb:len() < 4 then return end

    local findings = {}

    -- Helper function to add finding
    local function flag_vuln(vuln_key, evidence_text)
        local item = VULN_DB[vuln_key]
        if item then
            table.insert(findings, {
                id = item.id,
                sev = item.sev,
                cat = item.cat,
                title = item.title,
                desc = item.desc,
                evidence = evidence_text or "Observed in packet parameters"
            })
        end
    end

    -- ========================================================================
    -- Audit Check 1: 2G GSM A5 Ciphering (A5/0, A5/1, and A5/2)
    -- ========================================================================
    if f_gsm_a_cipher_sc and f_gsm_a_cipher_sc() then
        local sc_val = f_gsm_a_cipher_sc().value
        if sc_val == 0 or tostring(sc_val) == "0" or tostring(sc_val):find("No ciphering") then
            flag_vuln("TELCOSEC-VULN-001", "Cipher setting commanded: A5/0 (No Encryption / Plaintext Voice & SMS)")
        end
    end

    if f_gsm_a_cipher_alg and f_gsm_a_cipher_alg() then
        local alg = f_gsm_a_cipher_alg().value
        if alg == 0 then
            flag_vuln("TELCOSEC-VULN-002", "Cipher setting commanded: A5/1 (Broken / Crackable Stream Cipher)")
        elseif alg == 1 then
            flag_vuln("TELCOSEC-VULN-020", "Cipher setting commanded: A5/2 (Banned & Completely Insecure Cipher)")
        end
    end

    -- ========================================================================
    -- Audit Check 2: 2G Location Updating Rejects
    -- ========================================================================
    if f_gsm_a_dtap_rej_cau and f_gsm_a_dtap_rej_cau() then
        local cause = f_gsm_a_dtap_rej_cau().value
        if cause == 2 or cause == 3 or cause == 6 then
            flag_vuln("TELCOSEC-VULN-007", string.format("Reject Cause #%d (IMSI Unknown / Illegal ME / Roaming Not Allowed)", cause))
        end
    end

    -- ========================================================================
    -- Audit Check 3: Silent SMS (Type 0 / TP-PID 0x40)
    -- ========================================================================
    if f_gsm_sms_tp_pid and f_gsm_sms_tp_pid() then
        local pid = f_gsm_sms_tp_pid().value
        if pid == 0x40 then
            flag_vuln("TELCOSEC-VULN-008", "SMS TP-PID: 0x40 (Short Message Type 0 / Silent Ping)")
        end
    end

    -- ========================================================================
    -- Audit Check 4: 4G LTE Ciphering & Integrity (EEA0 / EIA0)
    -- ========================================================================
    if f_lte_rrc_eea and f_lte_rrc_eea() then
        local eea = f_lte_rrc_eea().value
        if eea == 0 or tostring(eea) == "eea0" then
            flag_vuln("TELCOSEC-VULN-003", "LTE SecurityModeCommand: cipheringAlgorithm = eea0 (Null Cipher)")
        end
    end
    if f_lte_rrc_eia and f_lte_rrc_eia() then
        local eia = f_lte_rrc_eia().value
        if (eia == 0 or tostring(eia) == "eia0") and not (pinfo.cols.info and string.find(tostring(pinfo.cols.info), "Emergency")) then
            flag_vuln("TELCOSEC-VULN-005", "LTE SecurityModeCommand: integrityProtAlgorithm = eia0 (Null Integrity)")
        end
    end

    -- ========================================================================
    -- Audit Check 5: 5G NR Ciphering, Integrity, Slicing & SBA Security
    -- ========================================================================
    if f_nr_rrc_nea and f_nr_rrc_nea() then
        local nea = f_nr_rrc_nea().value
        if nea == 0 or tostring(nea) == "nea0" then
            flag_vuln("TELCOSEC-VULN-004", "5G NR SecurityModeCommand: cipheringAlgorithm = nea0 (Null Cipher)")
        end
    end
    if f_nr_rrc_nia and f_nr_rrc_nia() then
        local nia = f_nr_rrc_nia().value
        if (nia == 0 or tostring(nia) == "nia0") and not (pinfo.cols.info and string.find(tostring(pinfo.cols.info), "Emergency")) then
            flag_vuln("TELCOSEC-VULN-005", "5G NR SecurityModeCommand: integrityProtAlgorithm = nia0 (Null Integrity)")
        end
    end

    -- 5G SBA OAuth2 Token Check
    if f_http2_path and f_http2_path() then
        local path_val = tostring(f_http2_path().value)
        if (string.find(path_val, "/nudm%-") or string.find(path_val, "/nausf%-") or string.find(path_val, "/nnrf%-")) and not (f_http2_auth and f_http2_auth()) then
            flag_vuln("TELCOSEC-VULN-021", string.format("5G SBA Endpoint (%s) called without OAuth 2.0 Bearer Authorization", path_val))
        end
    end

    -- 5G S-NSSAI Slice Access Check
    if f_nr_snssai and f_nr_snssai() then
        local snssai_val = tostring(f_nr_snssai().value)
        if string.find(snssai_val, "0x00") or string.find(snssai_val, "unauthorized") then
            flag_vuln("TELCOSEC-VULN-022", string.format("S-NSSAI Slice Security Violation (%s)", snssai_val))
        end
    end

    -- ========================================================================
    -- Audit Check 6: VoLTE / IMS Plaintext Media, Spoofing & STIR/SHAKEN
    -- ========================================================================
    if f_sdp_proto and f_sdp_proto() then
        local proto_val = tostring(f_sdp_proto().value)
        if (proto_val == "RTP/AVP" or proto_val == "RTP/AVPF") and (pinfo.cols.protocol and string.find(tostring(pinfo.cols.protocol), "SIP")) then
            flag_vuln("TELCOSEC-BADPRAC-003", "VoLTE SDP Media Profile: RTP/AVP (Cleartext Voice Bearer)")
        end
    end
    if f_sip_from and f_sip_from() and f_sip_pai and f_sip_pai() then
        local from_s = tostring(f_sip_from().value)
        local pai_s = tostring(f_sip_pai().value)
        if from_s ~= "" and pai_s ~= "" and from_s ~= pai_s then
            flag_vuln("TELCOSEC-BADPRAC-004", string.format("From Header (%s) != Authenticated P-Asserted-Identity (%s)", from_s, pai_s))
        end
    end

    -- STIR/SHAKEN Token Inspection
    if pinfo.cols.protocol and string.find(tostring(pinfo.cols.protocol), "SIP") and (pinfo.cols.info and string.find(tostring(pinfo.cols.info), "INVITE")) then
        local raw_str = tvb(0, math.min(tvb:len(), 1500)):string()
        if string.find(raw_str, "[Ii][Nn][Vv][Ii][Tt][Ee]") and not string.find(raw_str, "[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy]:") and not (f_sip_identity and f_sip_identity()) then
            flag_vuln("TELCOSEC-VULN-023", "Outbound SIP INVITE missing STIR/SHAKEN PASSporT Identity header (RFC 8224)")
        end
    end

    -- ========================================================================
    -- Audit Check 7: SCTP ABORT Chunk Signaling Killer
    -- ========================================================================
    if f_sctp_chunk and f_sctp_chunk() then
        local chunk = f_sctp_chunk().value
        if chunk == 6 then
            flag_vuln("TELCOSEC-VULN-014", "SCTP ABORT Chunk (Abrupt Core Signaling Reset)")
        end
    end

    -- ========================================================================
    -- Audit Check 8: Diameter HSS UDR / XML Extraction
    -- ========================================================================
    if f_diameter_cmd and f_diameter_cmd() then
        local cmd = f_diameter_cmd().value
        if cmd == 306 or cmd == 307 then
            flag_vuln("TELCOSEC-VULN-012", string.format("Diameter Sh User-Data Command (Cmd Code %d) Profile Access", cmd))
        end
    end

    -- ========================================================================
    -- Audit Check 9: APN / DNN Security & Misconfiguration Inspection
    -- ========================================================================
    local active_apn = nil
    if f_lte_apn and f_lte_apn() then
        active_apn = tostring(f_lte_apn().value)
    elseif f_gsm_apn and f_gsm_apn() then
        active_apn = tostring(f_gsm_apn().value)
    elseif f_nr_dnn and f_nr_dnn() then
        active_apn = tostring(f_nr_dnn().value)
    elseif f_gtp_apn and f_gtp_apn() then
        active_apn = tostring(f_gtp_apn().value)
    end

    if active_apn then
        local lower_apn = string.lower(active_apn)
        if lower_apn == "" or lower_apn == "*" or lower_apn == "." then
            flag_vuln("TELCOSEC-VULN-019", string.format("Blank / Wildcard APN requested ('%s')", active_apn))
        elseif string.find(lower_apn, "proxy") or string.find(lower_apn, "free") or string.find(lower_apn, "hack") or string.find(lower_apn, "rogue") or string.find(lower_apn, "ctmail") then
            flag_vuln("TELCOSEC-VULN-018", string.format("Suspicious / Rogue APN detected ('%s')", active_apn))
        elseif lower_apn == "ims" or lower_apn == "sos" or lower_apn == "xcap" or string.find(lower_apn, "admin") then
            flag_vuln("TELCOSEC-BADPRAC-006", string.format("Carrier Admin / Signaling APN ('%s') accessed over radio", active_apn))
        end
    end

    -- ========================================================================
    -- Audit Check 10: SIM / STK Stealth Probing
    -- ========================================================================
    if f_stk_cmd and f_stk_cmd() then
        local cmd_type = f_stk_cmd().value
        if cmd_type == 0x26 then -- PROVIDE LOCAL INFORMATION
            flag_vuln("TELCOSEC-VULN-017", "STK PROVIDE LOCAL INFO (Stealth Cell ID / Location / IMEI Polling)")
        end
    end

    -- ========================================================================
    -- Audit Check 11: SS7 / MAP SRI-SM Interception
    -- ========================================================================
    if f_map_op and f_map_op() then
        local op_val = tostring(f_map_op().value)
        if string.find(op_val, "sendRoutingInfoForSM") or string.find(op_val, "45") then
            flag_vuln("TELCOSEC-VULN-025", "MAP SendRoutingInfoForSM (SRI-SM) Query Intercepting IMSI & Current MSC")
        end
    end

    -- Render Findings to Wireshark Tree
    if #findings > 0 then
        local subtree = tree:add(vuln_audit_proto, tvb(), string.format("TelcoSec Security Audit: %d Issue(s) Detected", #findings))
        for _, f in ipairs(findings) do
            local item_tree = subtree:add(vuln_audit_proto, tvb(), string.format("[%s] %s: %s", f.sev, f.id, f.title))
            item_tree:add(f_vuln_id, f.id)
            item_tree:add(f_severity, f.sev)
            item_tree:add(f_category, f.cat)
            item_tree:add(f_title, f.title)
            item_tree:add(f_description, f.desc)
            item_tree:add(f_evidence, f.evidence)
        end
        pinfo.cols.info:append(string.format(" [AUDIT: %d ISSUE(S)!]", #findings))
    end
end

register_postdissector(vuln_audit_proto)
