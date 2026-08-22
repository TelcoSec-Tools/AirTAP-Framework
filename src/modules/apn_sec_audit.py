#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    AirTap - APN & 5G Data Network Name (DNN) Security Testing Suite
    Powered by TelcoSec.net (https://telcosec.net)
    
    Comprehensive telecom security auditor for 2G/3G/4G/5G Access Point Names (APN)
    and 5G Data Network Names (DNN). Implements 3GPP TS 23.003, TS 23.060, TS 23.401,
    TS 23.501, TS 29.274, and GSMA PRD IR.88 / FS.31 specifications.
"""

import re
import sys
import json
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any


class ApnSecurityAuditor:
    """
    Evaluates cellular APN / 5G DNN parameters against telecom security standards,
    identifying misconfigurations, rogue proxy injections, slice isolation flaws,
    and carrier administrative exposure.
    """

    # 3GPP APN Restriction Levels (TS 29.274 Section 8.57)
    APN_RESTRICTION_LEVELS = {
        0: {"name": "NO_RESTRICTION", "desc": "Unrestricted public or general data access (Level 0)"},
        1: {"name": "PUBLIC_1", "desc": "Public-1: Basic carrier internet services (Level 1)"},
        2: {"name": "PUBLIC_2", "desc": "Public-2: Premium or high-priority consumer data (Level 2)"},
        3: {"name": "PRIVATE_1", "desc": "Private-1: Enterprise or MVNO intranet partition (Level 3)"},
        4: {"name": "PRIVATE_2", "desc": "Private-2: Secure operator core / IMS / mission-critical (Level 4)"}
    }

    # Standard 3GPP 5G Slice Service Types (SST) (TS 23.501 Section 5.15.2.2)
    SST_PROFILES = {
        1: {"name": "eMBB", "desc": "Enhanced Mobile Broadband (High Data Rate Consumer Access)"},
        2: {"name": "URLLC", "desc": "Ultra-Reliable & Low Latency Communication (Mission-Critical / Industrial)"},
        3: {"name": "MIoT", "desc": "Massive Internet of Things (Smart Metering / Sensors)"},
        4: {"name": "V2X", "desc": "Vehicle-to-Everything & Autonomous Telematics (PC5/Uu Sidelink)"},
        5: {"name": "High Data Rate eMBB", "desc": "Specialized Ultra-High Bandwidth / AR-VR"}
    }

    # Known Carrier Well-Known Administrative & Functional APN Profiles
    WELL_KNOWN_APNS = {
        "ims": {
            "category": "IMS_VOLTE",
            "title": "IP Multimedia Subsystem (VoLTE / VoNR / RCS)",
            "spec": "3GPP TS 24.229 / TS 23.228",
            "expected_restr": 4,
            "min_pdp": "IPv4v6",
            "expected_sst": 1,
            "notes": "Dedicated administrative APN for VoLTE/VoNR voice and SIP signaling. Must never route general public internet traffic."
        },
        "sos": {
            "category": "EMERGENCY",
            "title": "Emergency Services (3GPP SOS)",
            "spec": "3GPP TS 23.167 / TS 24.501",
            "expected_restr": 4,
            "min_pdp": "IPv4v6",
            "expected_sst": 2,
            "notes": "Emergency PDU session for eCall / SOS dialing. Guaranteed priority without standard authentication."
        },
        "xcap": {
            "category": "UT_XCAP",
            "title": "VoLTE Supplementary Services (Ut Interface / HTTP XCAP)",
            "spec": "3GPP TS 24.623 / RFC 4825",
            "expected_restr": 3,
            "min_pdp": "IPv4v6",
            "expected_sst": 1,
            "notes": "Carries user settings (call forwarding, barring). Vulnerable to credential interception if TLS is disabled."
        },
        "mms": {
            "category": "MMS_MESSAGING",
            "title": "Multimedia Messaging Service (WAP / MMSC)",
            "spec": "3GPP TS 23.140 / OMA-MMS",
            "expected_restr": 1,
            "min_pdp": "IPv4",
            "expected_sst": 1,
            "notes": "Legacy MMS proxy APN. Historically prone to proxy manipulation and WAP header injection."
        },
        "dun": {
            "category": "TETHERING",
            "title": "Dial-Up Networking / Mobile Hotspot Tethering",
            "spec": "3GPP TS 27.060",
            "expected_restr": 0,
            "min_pdp": "IPv4v6",
            "expected_sst": 1,
            "notes": "Tethering traffic often subject to operator DPI throttling and TTL enforcement."
        },
        "rcs": {
            "category": "RCS_MESSAGING",
            "title": "Rich Communication Services (RCS / MSRP)",
            "spec": "GSMA RCC.07 / 3GPP TS 24.247",
            "expected_restr": 2,
            "min_pdp": "IPv4v6",
            "expected_sst": 1,
            "notes": "Universal profile messaging channel. Enforces MSRP TLS encryption."
        },
        "hos": {
            "category": "CARRIER_MANAGEMENT",
            "title": "Carrier Over-The-Air Management & Firmware Update (FOTA)",
            "spec": "OMA-DM / TR-069",
            "expected_restr": 4,
            "min_pdp": "IPv4v6",
            "expected_sst": 3,
            "notes": "Internal carrier maintenance APN. High privilege; must be strictly isolated from user access."
        }
    }

    def __init__(self):
        self.findings = []
        self.risk_score = 0 # 0 to 100 scale

    def audit_apn(self, apn_name: str,
                  mcc: Optional[str] = None,
                  mnc: Optional[str] = None,
                  pdn_type: str = "IPv4v6",
                  proxy_host: Optional[str] = None,
                  proxy_port: Optional[int] = None,
                  dns_servers: Optional[List[str]] = None,
                  restriction_level: int = 0,
                  sst: Optional[int] = None,
                  sd: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes comprehensive telecom security evaluation on the provided APN configuration.
        """
        self.findings = []
        self.risk_score = 0
        raw_apn = (apn_name or "").strip()

        # 1. Structure & 3GPP TS 23.003 Compliance Analysis
        structure_info = self._parse_apn_structure(raw_apn)
        net_id = structure_info.get("net_id", raw_apn)
        op_id = structure_info.get("op_id", "")
        extracted_mcc = structure_info.get("extracted_mcc") or mcc
        extracted_mnc = structure_info.get("extracted_mnc") or mnc

        # 2. Syntax & FQDN Label Verification
        self._check_syntax_and_length(raw_apn, net_id, op_id)

        # 3. Categorization & Carrier Profile Matching
        profile = self._match_carrier_profile(net_id)

        # 4. PDP / PDU Session Type Security Verification
        self._check_pdn_type(pdn_type, profile)

        # 5. APN Restriction Level Enforcement
        self._check_restriction_level(net_id, restriction_level, profile)

        # 6. 5G Network Slice (S-NSSAI) Isolation & Verification
        self._check_5g_slicing(net_id, sst, sd, profile)

        # 7. Proxy & MitM Inspection
        self._check_proxy_and_mitm(proxy_host, proxy_port, net_id)

        # 8. DNS Resolver Auditing
        self._check_dns_resolvers(dns_servers, net_id)

        # 9. Compute Normalized Risk Score
        self._calculate_risk_score()

        return {
            "status": "ok",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "target_apn": raw_apn,
            "network_id": net_id,
            "operator_id": op_id,
            "mcc": extracted_mcc,
            "mnc": extracted_mnc,
            "pdn_type": pdn_type,
            "restriction_level": restriction_level,
            "restriction_desc": self.APN_RESTRICTION_LEVELS.get(restriction_level, {}).get("name", f"Level {restriction_level}"),
            "profile_category": profile.get("category", "GENERAL_INTERNET"),
            "profile_title": profile.get("title", "Standard Public Mobile Internet"),
            "is_sensitive_carrier_apn": profile.get("category") in ("IMS_VOLTE", "EMERGENCY", "UT_XCAP", "CARRIER_MANAGEMENT"),
            "s_nssai": {
                "sst": sst,
                "sd": f"0x{sd:06X}" if sd is not None else None,
                "slice_type": self.SST_PROFILES.get(sst, {}).get("name", "Standard eMBB") if sst else "Default (SST 1: eMBB)"
            },
            "risk_score": self.risk_score,
            "risk_level": "CRITICAL" if self.risk_score >= 75 else ("HIGH" if self.risk_score >= 50 else ("MEDIUM" if self.risk_score >= 25 else "LOW")),
            "findings_count": len(self.findings),
            "findings": self.findings,
            "training_portal": "https://app.telcosec.net"
        }

    def _parse_apn_structure(self, raw_apn: str) -> Dict[str, Any]:
        """
        Parses APN into Network Identifier (NI) and Operator Identifier (OI).
        According to 3GPP TS 23.003 §9:
        Example: internet.mnc001.mcc001.gprs
                 ims.mnc020.mcc310.3gppnetwork.org
        """
        result = {"raw": raw_apn, "net_id": raw_apn, "op_id": "", "extracted_mcc": None, "extracted_mnc": None}
        
        # Match standard GPRS / EPC / 5GC Operator Identifier patterns
        gprs_match = re.search(r'^(.*?)\.(mnc(\d{2,3})\.mcc(\d{3})\.gprs)$', raw_apn, re.IGNORECASE)
        network_org_match = re.search(r'^(.*?)\.(mnc(\d{2,3})\.mcc(\d{3})\.3gppnetwork\.org)$', raw_apn, re.IGNORECASE)

        if gprs_match:
            result["net_id"] = gprs_match.group(1)
            result["op_id"] = gprs_match.group(2)
            result["extracted_mnc"] = gprs_match.group(3)
            result["extracted_mcc"] = gprs_match.group(4)
        elif network_org_match:
            result["net_id"] = network_org_match.group(1)
            result["op_id"] = network_org_match.group(2)
            result["extracted_mnc"] = network_org_match.group(3)
            result["extracted_mcc"] = network_org_match.group(4)
        else:
            parts = raw_apn.split('.')
            if len(parts) > 1 and any(p.startswith(('mnc', 'mcc')) for p in parts):
                for p in parts:
                    if p.startswith('mcc') and len(p) == 6 and p[3:].isdigit():
                        result["extracted_mcc"] = p[3:]
                    if p.startswith('mnc') and len(p) in (5, 6) and p[3:].isdigit():
                        result["extracted_mnc"] = p[3:]

        return result

    def _check_syntax_and_length(self, raw_apn: str, net_id: str, op_id: str):
        """Validates 3GPP TS 23.003 label syntax, length constraints, and encoding."""
        if not raw_apn:
            self._add_finding(
                rule_id="TELCOSEC-APN-001",
                severity="CRITICAL",
                title="Null or Empty APN String",
                spec="3GPP TS 23.003 Section 9.1",
                desc="The APN configuration is completely blank. The UE will fall back to default carrier subscription APN without explicit security policies.",
                impact="Uncontrolled default gateway attachment and lack of traffic isolation.",
                remediation="Configure an explicit, validated APN profile matching your carrier deployment specifications."
            )
            return

        if len(raw_apn) > 100: # 3GPP allows up to 100 octets for APN NI + OI in GTP
            self._add_finding(
                rule_id="TELCOSEC-APN-002",
                severity="MEDIUM",
                title="APN Name Length Exceeds Standard Recommendation (>100 octets)",
                spec="3GPP TS 23.003 / TS 29.274 Section 8.6",
                desc=f"APN length is {len(raw_apn)} characters, which risks truncation in legacy SGSN/MME signaling IEs.",
                impact="Signaling rejection or session establishment failure in roaming scenarios.",
                remediation="Ensure APN Network Identifier is concise and within standard 3GPP length recommendations."
            )

        # Validate label characters (must be alphanumeric or hyphen, no leading/trailing hyphen)
        labels = raw_apn.split('.')
        for lbl in labels:
            if not lbl:
                self._add_finding(
                    rule_id="TELCOSEC-APN-003",
                    severity="HIGH",
                    title="Malformed APN: Empty Label / Consecutive Dots",
                    spec="3GPP TS 23.003 Section 9.1",
                    desc=f"APN '{raw_apn}' contains an empty label or consecutive dots (..).",
                    impact="ASN.1 / TLV decoder crash or session reject at PGW/UPF gateway.",
                    remediation="Remove consecutive dots and trailing separators from the APN string."
                )
                break
            if len(lbl) > 63:
                self._add_finding(
                    rule_id="TELCOSEC-APN-004",
                    severity="HIGH",
                    title=f"APN Label '{lbl[:12]}...' Exceeds 63 Octets Limit",
                    spec="RFC 1035 / 3GPP TS 23.003",
                    desc="DNS and 3GPP standard dictates that individual FQDN labels must not exceed 63 octets.",
                    impact="DNS resolution failure at GGSN/S-GW during APN-to-PGW IP lookup.",
                    remediation="Shorten the individual label to 63 octets or less."
                )
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', lbl):
                self._add_finding(
                    rule_id="TELCOSEC-APN-005",
                    severity="HIGH",
                    title=f"Invalid Characters in APN Label '{lbl}'",
                    spec="3GPP TS 23.003 Section 9.1",
                    desc="APN labels must strictly consist of letters, digits, and non-leading/non-trailing hyphens.",
                    impact="Baseband modem AT+CGDCONT parsing rejection or gateway rejection.",
                    remediation="Sanitize APN string to remove special characters, underscores, and spaces."
                )

    def _match_carrier_profile(self, net_id: str) -> Dict[str, Any]:
        """Identifies well-known carrier functional profiles."""
        lower_net = net_id.lower()
        for key, prof in self.WELL_KNOWN_APNS.items():
            if key in lower_net or lower_net.startswith(key):
                return prof
        return {
            "category": "GENERAL_INTERNET",
            "title": "General Mobile Internet Access",
            "spec": "3GPP TS 23.401 / TS 23.501",
            "expected_restr": 0,
            "min_pdp": "IPv4v6",
            "expected_sst": 1,
            "notes": "Standard public consumer data network."
        }

    def _check_pdn_type(self, pdn_type: str, profile: Dict[str, Any]):
        """Evaluates PDP / PDU session address family security."""
        norm_pdp = (pdn_type or "").upper().strip()
        if norm_pdp == "IPV4":
            self._add_finding(
                rule_id="TELCOSEC-APN-006",
                severity="MEDIUM",
                title="Legacy IPv4-Only PDP Context Assigned",
                spec="3GPP TS 23.401 Section 4.3.8.1 / GSMA IR.88",
                desc=f"APN uses legacy IPv4-only PDP type instead of dual-stack IPv4v6 or IPv6. Modern 3GPP and GSMA standards mandate dual-stack to mitigate CGNAT session correlation and address exhaustion.",
                impact="Vulnerability to subscriber IP tracking via shared CGNAT pool, and lack of end-to-end encryption addressability.",
                remediation="Upgrade PDP / PDU session type in device and HSS/UDM profile to 'IPV4V6'."
            )

        if profile.get("category") == "IMS_VOLTE" and norm_pdp not in ("IPV6", "IPV4V6"):
            self._add_finding(
                rule_id="TELCOSEC-APN-007",
                severity="HIGH",
                title="VoLTE / IMS APN Configured Without IPv6 Support",
                spec="3GPP TS 24.229 Section 9.2.1 / GSMA PRD IR.92",
                desc="GSMA IR.92 mandates IPv6 support for all IMS and VoLTE voice bearers. Running IMS over IPv4-only creates SIP registration instability and NAT keepalive battery drain.",
                impact="VoLTE call setup drops, emergency call failure, and SIP registration desynchronization.",
                remediation="Set IMS APN PDN Type to 'IPv6' or 'IPv4v6' per GSMA IR.92 standard."
            )

    def _check_restriction_level(self, net_id: str, restriction_level: int, profile: Dict[str, Any]):
        """Enforces 3GPP APN Restriction Level isolation."""
        expected_restr = profile.get("expected_restr", 0)
        
        if profile.get("category") in ("IMS_VOLTE", "EMERGENCY", "CARRIER_MANAGEMENT") and restriction_level == 0:
            self._add_finding(
                rule_id="TELCOSEC-APN-008",
                severity="HIGH",
                title="Privileged Carrier APN Configured Without 3GPP Restriction Level (Level 0 Assigned)",
                spec="3GPP TS 29.274 Section 8.57",
                desc=f"APN '{net_id}' is a high-privilege {profile.get('category')} bearer but has APN Restriction set to 'No Restriction (Level 0)'. This allows non-isolated consumer traffic to intermingle on the same gateway context.",
                impact="Cross-bearer data exfiltration and potential exposure of IMS SIP core to unauthenticated handset apps.",
                remediation=f"Enforce APN Restriction Level {expected_restr} ('{self.APN_RESTRICTION_LEVELS[expected_restr]['name']}') in PGW/SMF QoS and policy definitions."
            )

    def _check_5g_slicing(self, net_id: str, sst: Optional[int], sd: Optional[int], profile: Dict[str, Any]):
        """Verifies 5G Network Slicing (S-NSSAI) configuration."""
        if sst is not None:
            expected_sst = profile.get("expected_sst", 1)
            if profile.get("category") == "EMERGENCY" and sst != 2:
                self._add_finding(
                    rule_id="TELCOSEC-APN-009",
                    severity="HIGH",
                    title=f"5G Emergency SOS DNN Assigned to Non-URLLC Slice (SST={sst})",
                    spec="3GPP TS 23.501 Section 5.15 / TS 23.167",
                    desc=f"Emergency services DNN requires Ultra-Reliable Low Latency (SST 2) slice priority. Assigned SST {sst} ({self.SST_PROFILES.get(sst, {}).get('name', 'Unknown')}) does not guarantee sub-millisecond preemption.",
                    impact="Emergency service latency or connection preemption during cellular cell congestion.",
                    remediation="Map the SOS Emergency DNN to S-NSSAI with SST=2 (URLLC)."
                )

    def _check_proxy_and_mitm(self, proxy_host: Optional[str], proxy_port: Optional[int], net_id: str):
        """Audits for rogue proxy injection and transparent traffic interception."""
        if proxy_host:
            clean_host = proxy_host.strip().lower()
            
            # Check for suspicious or cleartext proxies
            is_private = (clean_host.startswith("10.") or clean_host.startswith("192.168.")
                          or clean_host.startswith("172.16.") or clean_host == "127.0.0.1" or clean_host == "localhost")
            
            self._add_finding(
                rule_id="TELCOSEC-APN-010",
                severity="HIGH" if is_private else "MEDIUM",
                title=f"Static HTTP Proxy Configured on Cellular APN ({clean_host}:{proxy_port or 8080})",
                spec="3GPP TS 33.401 / GSMA FS.31",
                desc=f"The APN is configured to force all mobile data through a proxy at '{clean_host}:{proxy_port or 8080}'. While historically used for legacy WAP/MMS, static proxies in general data APNs enable Man-in-the-Middle (MitM) inspection, header enrichment (MSISDN leakage), and caching attacks.",
                impact="Unencrypted HTTP traffic interception, user tracking via injected X-Forwarded-For / MSISDN headers, and single point of failure.",
                remediation="Remove static proxy configurations from general internet APNs. Direct IP routing must be used."
            )

    def _check_dns_resolvers(self, dns_servers: Optional[List[str]], net_id: str):
        """Evaluates DNS server addresses configured for the APN."""
        if dns_servers:
            for dns in dns_servers:
                dns_clean = (dns or "").strip()
                if dns_clean in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
                    continue # Standard public secure resolvers
                if dns_clean.startswith("127.") or dns_clean == "0.0.0.0":
                    self._add_finding(
                        rule_id="TELCOSEC-APN-011",
                        severity="CRITICAL",
                        title=f"Invalid / Rogue Loopback DNS Server Configured ({dns_clean})",
                        spec="3GPP TS 23.060 / TS 23.401",
                        desc=f"APN specifies loopback DNS resolver '{dns_clean}', which will cause complete domain resolution failure or local DNS poisoning.",
                        impact="Denial of cellular internet service or local rogue DNS hijacking.",
                        remediation="Configure carrier-provided primary/secondary DNS resolvers or reputable secure DNS servers."
                    )

    def _add_finding(self, rule_id: str, severity: str, title: str, spec: str, desc: str, impact: str, remediation: str):
        """Appends a structured security finding."""
        weights = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
        self.risk_score += weights.get(severity.upper(), 10)
        self.findings.append({
            "rule_id": rule_id,
            "severity": severity.upper(),
            "title": title,
            "specification": spec,
            "description": desc,
            "attack_impact": impact,
            "remediation_guidance": remediation,
            "academy_lab": f"https://app.telcosec.net?rule={rule_id}"
        })

    def _calculate_risk_score(self):
        """Normalizes risk score to 0-100 range."""
        self.risk_score = min(100, max(0, self.risk_score))

    def format_cli_report(self, audit_result: Dict[str, Any]) -> str:
        """Formats the audit results as a high-visibility terminal report."""
        apn = audit_result.get("target_apn", "-")
        score = audit_result.get("risk_score", 0)
        level = audit_result.get("risk_level", "LOW")
        findings = audit_result.get("findings", [])

        color_code = "\033[1;32m" if level == "LOW" else ("\033[1;33m" if level == "MEDIUM" else ("\033[1;31m" if level == "HIGH" else "\033[1;35m"))
        reset = "\033[0m"

        lines = [
            "",
            "+" + "=" * 76 + "+",
            "|      AirTap - APN & 5G Data Network Name Security Auditor (TelcoSec.net)   |",
            "+" + "=" * 76 + "+",
            f"[*] Target APN / DNN     : {apn}",
            f"[*] Network Identifier   : {audit_result.get('network_id', '-')}",
            f"[*] Operator Identifier  : {audit_result.get('operator_id') or 'N/A (Local Breakout)'}",
            f"[*] Profile Category     : {audit_result.get('profile_title', '-')}",
            f"[*] PDN / Session Type   : {audit_result.get('pdn_type', 'IPv4v6')}",
            f"[*] 3GPP APN Restriction : {audit_result.get('restriction_desc', 'Level 0')}",
            f"[*] 5G Slice Service Type: {audit_result.get('s_nssai', {}).get('slice_type', '-')}",
            f"[*] Security Risk Level  : {color_code}{level} (Score: {score}/100){reset}",
            f"[*] Total Findings       : {len(findings)}",
            "-" * 78
        ]

        if not findings:
            lines.append("  [✓] All 3GPP and GSMA APN security checks PASSED. No vulnerabilities detected.")
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "HIGH")
                sev_color = "\033[1;31m" if sev == "CRITICAL" else ("\033[0;31m" if sev == "HIGH" else "\033[1;33m")
                lines.append(f"  {idx}. [{sev_color}{sev}{reset}] [{f.get('rule_id')}] {f.get('title')}")
                lines.append(f"     3GPP Spec Citation : {f.get('specification')}")
                lines.append(f"     Vulnerability Mech : {f.get('description')}")
                lines.append(f"     Security Impact    : {f.get('attack_impact')}")
                lines.append(f"     Remediation Advice : {f.get('remediation_guidance')}")
                lines.append(f"     TelcoSec Lab       : {f.get('academy_lab')}")
                lines.append("")

        lines.append("=" * 78)
        lines.append("Practice live 3GPP exploit scenarios at TelcoSec Academy -> https://app.telcosec.net")
        lines.append("")
        return "\n".join(lines)
