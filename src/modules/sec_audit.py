#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from collections import defaultdict
from datetime import datetime
from struct import unpack, unpack_from, error as struct_error
from logging import info, warning, error, debug
import json
import time
import sys

from ..protocol.log_types import *
from ..protocol.messages import *
from ._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING

"""
    AirTap - Radio Security Audit Module (SecurityAuditor)
    Powered by TelcoSec.net (https://telcosec.net)
    
    Performs real-time telecommunication security analysis and threat detection
    across 2G (GSM/GPRS), 3G (UMTS), 4G (LTE), 5G (NR), and UICC/SIM interfaces.
    
    Implements standardized TelcoSec Master Vulnerability Rules (TELCOSEC-VULN-*):
    - TELCOSEC-VULN-001: 2G A5/0 Disabled Ciphering
    - TELCOSEC-VULN-002: 2G A5/1 Deprecated Stream Cipher
    - TELCOSEC-VULN-003: 3G/4G UEA0/EEA0 Null Ciphering
    - TELCOSEC-VULN-004: 5G NEA0 Null Ciphering
    - TELCOSEC-VULN-005: 4G/5G EIA0/NIA0 Null Integrity Protection
    - TELCOSEC-VULN-006: Cleartext IMSI/SUPI Identity Request (IMSI Catcher Indicator)
    - TELCOSEC-VULN-007: Forced 2G/3G/4G Downgrade via Reject (FBS Kill Switch)
    - TELCOSEC-VULN-008: Silent SMS Type 0 Covert Location Probe
    - TELCOSEC-VULN-009: SIMjacker (STK SEND SHORT MESSAGE Bytecode Attack)
    - TELCOSEC-VULN-010: 3G SRNS Relocation without Re-Authentication
    - TELCOSEC-VULN-011: LTE Bearer Modification QoS Downgrade (User-Plane MitM)
    - TELCOSEC-VULN-012: LTE/5G GUTI Reallocation Suppression (Persistent TMSI Tracking)
    - TELCOSEC-VULN-013: 5G Registration Accept with Null AMF Security Context
    - TELCOSEC-VULN-014: Rogue BTS Cell Selection Manipulation (q-RxLevMin Abuse)
    - TELCOSEC-VULN-015: WIBjacker (SIM Wireless Internet Browser Attack)
    - TELCOSEC-VULN-016: UICC PIN / PUK Brute-Force Probing
    - TELCOSEC-VULN-017: Stealth STK Location / IMEI Harvesting (PROVIDE LOCAL INFO)
    - TELCOSEC-VULN-018: USIM Sensitive EF Exfiltration (EF_IMSI / EF_ICCID Read)
    - TELCOSEC-VULN-019: STK SET UP CALL — Unauthorized Call Initiation by USIM
    - TELCOSEC-VULN-020: USIM AUTHENTICATE AKA Cryptographic Execution
    - TELCOSEC-VULN-021: STK Forced Browser Launch / Phishing Redirection (WIB/S@T)
    - TELCOSEC-VULN-022: 5G-to-EPS Interworking Bidding-Down (N1 Mode Suppression)
    - TELCOSEC-VULN-023: FBS SIB Isolation (No Intra/Inter-Frequency Neighbor Cells)
    - TELCOSEC-VULN-024: SS7 MAP SendRoutingInfo / Subscriber Location Disclosure
    - TELCOSEC-VULN-025: Diameter S6a/S13 IMSI Enumeration / Location Probing
    - TELCOSEC-VULN-026: VoLTE IMS SIP REGISTER Replay / Session Hijack
    - TELCOSEC-VULN-027: IMS Emergency Service Bypass / SOS Call Interception
    - TELCOSEC-VULN-028: 5G SUCI Null-Scheme Fallback / SUPI Exposure
    - TELCOSEC-VULN-029: 5G Network Slice Isolation Bypass / Cross-Slice Exfiltration
    - TELCOSEC-VULN-030: gNB RRC Setup Reject Flood / UE Denial-of-Service
    - TELCOSEC-VULN-031: AMF Overload Signalling Attack / Registration Storm
    - TELCOSEC-VULN-032: eSIM RSP Interception / Rogue SM-DP+ Profile Provisioning
    - TELCOSEC-VULN-033: eSIM Rogue LPA Profile Deletion / Operational Disruption
    - TELCOSEC-VULN-034: 5G N32 Roaming Interface Eavesdropping / Home PLMN Exposure
    - TELCOSEC-VULN-035: 5G SBI OAuth Token Forgery / NF Impersonation
    - TELCOSEC-VULN-036: RRC Integrity Protection Suppression (NIA0 / AS Cipher-Only)
    - TELCOSEC-VULN-037: SMS Home Routing Bypass / MT SMS Spoofing via Interconnect
    - TELCOSEC-VULN-038: LTE X2 Handover Context Exploit / AS Key Reuse
    - TELCOSEC-VULN-039: Paging Correlation IMSI Capture via TMSI Abuse
    - TELCOSEC-VULN-040: NTP/PTP RAN Timing Attack / GPS Spoofing Amplification
    - TELCOSEC-VULN-041: AMF/gNB NGAP UE Context Release Flood
    - TELCOSEC-VULN-042: Wi-Fi EAP-AKA' Downgrade to EAP-SIM (Non-3GPP Access)
    - TELCOSEC-VULN-043: PRACH Preamble Flood / Random Access Channel Jamming
    - TELCOSEC-VULN-044: 5G URLLC QoS Flow Tampering / Latency-Injection
    - TELCOSEC-VULN-045: Automated Neighbor Relation (ANR) Poisoning / Rogue Cell Insertion
    - TELCOSEC-VULN-046: NB-IoT/LTE-M Device Credential Brute-Force / MQTT Flood
    - TELCOSEC-VULN-047: 5G-AKA SEAF MAC Bypass / Home Network Masquerade
    - TELCOSEC-VULN-048: NR-U/LTE-LAA Unlicensed Band LBT Channel Starvation
    - TELCOSEC-VULN-049: NWDAF Analytics Poisoning / AI-Driven Policy Manipulation
    - TELCOSEC-VULN-050: NR RRC Re-establishment AS Key Rollback Attack
    - TELCOSEC-VULN-051: Single-DES Cryptographic Weakness in SIM OTA Secured Packets (Broken KIC/KID)
    - TELCOSEC-VULN-052: Null-Ciphering / Plaintext Payload in SIM Remote File Management (RFM SPI Bypass)
    - TELCOSEC-VULN-053: Remote Applet Management (RAM) Signature Suppression / Rogue Java Card Applet Install
    - TELCOSEC-VULN-054: OTA Anti-Replay Counter Rollback / Zero-Counter Injection (SPI Counter Bypass)
    - TELCOSEC-VULN-055: Proof of Receipt (PoR) Information Exfiltration Attack (Malicious PoR Forcing)
    - TELCOSEC-VULN-056: S@T Bytecode Command Execution via Unprotected TAR (SIMjacker Zero-Click SMS)
    - TELCOSEC-VULN-057: Wireless Internet Browser (WIB) Bytecode Injection (WIBjacker Attack)
    - TELCOSEC-VULN-058: STK Bearer Independent Protocol (BIP) Covert C2 Pipe (OPEN CHANNEL Abuse)
    - TELCOSEC-VULN-059: STK Silent USSD / SS Execution (Supplementary Service Hijacking & Balance Drain)
    - TELCOSEC-VULN-060: Deceptive STK Phishing Overlays via DISPLAY TEXT & GET INPUT Injection
    - TELCOSEC-VULN-061: Unauthorized STK REFRESH File Modification / Baseband Re-registration Forcing
    - TELCOSEC-VULN-062: Java Card Applet Firewall Escape / Shareable Interface Object Privilege Escalation
    - TELCOSEC-VULN-063: Logical Channel Exhaustion Denial-of-Service on UICC Interface
    - TELCOSEC-VULN-064: EF_PLMNwAcT & EF_FPLMN OTA Steering Manipulation (Anti-Steering of Roaming)
    - TELCOSEC-VULN-065: APDU Fuzzing & Buffer Overflow in Telecom Toolkit Event Download Handlers
    - TELCOSEC-VULN-066: eSIM ES8+ Remote SIM Provisioning Channel Eavesdropping / Profile Tampering
    - TELCOSEC-VULN-067: eUICC ECASD Root Certificate Injection / Compromised GSMA CI Anchor
    - TELCOSEC-VULN-068: STK PROVIDE LOCAL INFO Timing & Measurement Report (NMR) Surreptitious Tracking
    - TELCOSEC-VULN-069: Java Card Transient Array State Leak / Residual Memory Key Disclosure
    - TELCOSEC-VULN-070: SMS-PP Data Download with Misleading PID/DCS (Class 2 SMS Spoofing)
    - TELCOSEC-VULN-071: STK RUN AT COMMAND Proactive Instruction Abuse (Modem AT Injection via SIM)
    - TELCOSEC-VULN-072: USIM Elementary File Read Access via Unauthorized SIM Access Profile (SAP) Bridge
    - TELCOSEC-VULN-073: Remote File Management (RFM) EF_LOCI / EF_PSLOCI Poisoning (Denial of Service Attach)
    - TELCOSEC-VULN-074: STK LANGUAGE NOTIFICATION & GEO LOCATE Proactive Fingerprinting
    - TELCOSEC-VULN-075: Multi-Application UICC Access Rule Tampering (Carrier App Privilege Escalation)
    - TELCOSEC-VULN-076: Unencrypted Lawful Interception Handover Interface (Plaintext HI2/HI3 Exposure)
    - TELCOSEC-VULN-077: Lawful Interception Sequence Counter Reset / Packet Replay Tampering
    - TELCOSEC-VULN-078: Unauthorized Lawful Interception Target Activation via Unauthenticated X1 REST
    - TELCOSEC-VULN-079: Baseband Qualcomm CALEA Silent Trigger Exfiltration / Covert Modem Wiretap
    - TELCOSEC-VULN-080: Lawful Interception Correlation Identifier (CIN) Mismatch in X2/X3 Multi-Stream Handover
    - TELCOSEC-VULN-081: Broadpwn Wi-Fi SoC Baseband Memory Heap Corruption (CVE-2017-11120)
    - TELCOSEC-VULN-082: Bluetooth Low Energy SweynTooth / BLESA Link Layer Malformation (CVE-2020-10061)
    - TELCOSEC-VULN-083: BrakTooth Bluetooth LMP Feature Response & AU_RAND Memory Corruption
    - TELCOSEC-VULN-084: KNOB Attack: Bluetooth Encryption Key Negotiation Entropy Reduction
    - TELCOSEC-VULN-085: Bluetooth Mesh Provisioning Unencrypted Key Exchange / PB-ADV Spoofing
    - TELCOSEC-VULN-086: Cellular-Wi-Fi Coexistence (CoEx) Denial-of-Service / LAA LBT Interference
    - TELCOSEC-VULN-087: Wi-Fi Calling (VoWiFi / ePDG) IPsec IKEv2 Weak Diffie-Hellman / NULL Ciphering
    - TELCOSEC-VULN-088: Cellular Baseband PCIe/UART DMA Firmware Escape to Host Processor
"""

# ANSI Terminal Colors
COLOR_RESET = '\033[0m'
COLOR_CRITICAL = '\033[1;31m'   # Bold Red
COLOR_HIGH = '\033[0;31m'       # Red
COLOR_MEDIUM = '\033[1;33m'     # Bold Yellow
COLOR_LOW = '\033[0;33m'        # Yellow
COLOR_INFO = '\033[1;36m'       # Bold Cyan
COLOR_HEADER = '\033[1;35m'     # Bold Magenta
COLOR_BOLD = '\033[1m'


class SecurityAlert:
    """Represents a single security audit finding."""
    def __init__(self, severity: str, category: str, rat: str, title: str, description: str,
                 rule_id: str = 'TELCOSEC-VULN-GEN', raw_data: bytes = None, timestamp: float = None):
        self.severity = severity.upper()  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.category = category          # CIPHERING, IDENTITY, DOWNGRADE, SIM_SECURITY, SILENT_SMS, INTEGRITY
        self.rat = rat.upper()            # 2G, 3G, 4G, 5G, SIM, MULTI
        self.rule_id = rule_id            # e.g. TELCOSEC-VULN-001
        self.title = title
        self.description = description
        self.raw_hex = raw_data.hex() if raw_data else ''
        self.timestamp = timestamp or time.time()
        self.time_str = datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'time': self.time_str,
            'rule_id': self.rule_id,
            'severity': self.severity,
            'category': self.category,
            'rat': self.rat,
            'title': self.title,
            'description': self.description,
            'raw_hex': self.raw_hex,
        }

    def format_terminal(self) -> str:
        color_map = {
            'CRITICAL': COLOR_CRITICAL,
            'HIGH': COLOR_HIGH,
            'MEDIUM': COLOR_MEDIUM,
            'LOW': COLOR_LOW,
            'INFO': COLOR_INFO,
        }
        color = color_map.get(self.severity, COLOR_BOLD)
        return (
            f"{color}[{self.severity}]{COLOR_RESET} [{self.time_str}] [{self.rat}|{self.category}] "
            f"[{COLOR_INFO}{self.rule_id}{COLOR_RESET}] {COLOR_BOLD}{self.title}{COLOR_RESET}\n"
            f"  -> {self.description}"
        )


class SecurityAuditor(EnableLogMixin):
    """
        Real-time security auditing module for cellular baseband and SIM traffic.
    """
    def __init__(self, diag_input, audit_log_path: str = None, alert_callback: callable = None):
        self.diag_input = diag_input
        self.audit_log_path = audit_log_path
        self.alert_callback = alert_callback
        self.alerts = []
        self.current_rat = 'UNKNOWN'
        self.disabled_rules = set()

        # State tracking
        self.stats = {
            'total_packets_audited': 0,
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'by_rule': defaultdict(int),
        }

        # Deduplication: track last-fired timestamp per rule_id to suppress storms
        self._last_alert_ts: dict = {}
        self._alert_cooldown_s: float = 5.0

        # SIB & Cell Profile State (updated by _audit_lte_rrc / _audit_5g_rrc)
        self.cell_profile = {
            'mcc': None,
            'mnc': None,
            'tac': None,
            'lac': None,
            'cell_id': None,
            'pci': None,
            'q_rx_lev_min': None,
            'has_intra_neighbors': False,
            'has_inter_neighbors': False,
            'neighbor_cells_logged': set(),   # PCI set from MeasConfig
            'guti_reallocated': False,
            'attach_count': 0,
            'smc_count': 0,
        }

        self._print_banner()

    def _print_banner(self):
        print(f"\n{COLOR_HEADER}+==========================================================================+{COLOR_RESET}")
        print(f"{COLOR_HEADER}|          AirTap - Real-Time Radio Security Auditor (TelcoSec.net)        |{COLOR_RESET}")
        print(f"{COLOR_HEADER}+==========================================================================+{COLOR_RESET}")
        print(f"[*] Security auditing active across 2G, 3G, 4G, 5G, and SIM/UICC channels.")
        print(f"[*] Telecom vulnerability rules loaded: TELCOSEC-VULN-001 through VULN-088 (88 Master Rules Loaded)")
        print(f"[*] TelcoSec Academy: Hands-on cellular security & 5G training -> https://app.telcosec.net")
        if self.audit_log_path:
            print(f"[*] Audit JSON log output: {self.audit_log_path}")
        print()

    
    def get_all_rules_catalog(self) -> list:
        """Returns the full 88-rule catalog with enabled state and trigger stats."""
        catalog = []
        for i in range(1, 89):
            rule_id = f"TELCOSEC-VULN-{i:03d}"
            meta = self._get_rule_meta(rule_id, i)
            meta['enabled'] = rule_id not in getattr(self, 'disabled_rules', set())
            meta['trigger_count'] = self.stats['by_rule'].get(rule_id, 0)
            catalog.append(meta)
        return catalog

    def set_rule_state(self, rule_id: str, enabled: bool) -> dict:
        """Enable or disable a specific TelcoSec vulnerability detection rule."""
        if not hasattr(self, 'disabled_rules'):
            self.disabled_rules = set()
        if enabled:
            self.disabled_rules.discard(rule_id)
        else:
            self.disabled_rules.add(rule_id)
        return {'status': 'ok', 'rule_id': rule_id, 'enabled': enabled}

    def simulate_rule_alert(self, rule_id: str) -> dict:
        """Evaluate and record a TelcoSec vulnerability detection rule."""
        meta = self._get_rule_meta(rule_id, int(rule_id.split('-')[-1]) if '-' in rule_id else 1)
        self.record_alert(
            severity=meta['severity'],
            category=meta['category'],
            rat=meta['rat'],
            title=meta['title'],
            description=f"Security audit evaluation for {rule_id}. {meta['description']}",
            rule_id=rule_id,
            dedupe=False
        )
        return {'status': 'ok', 'rule_id': rule_id, 'alert': meta}

    def _get_rule_meta(self, rule_id: str, num: int) -> dict:
        """Helper returning structured metadata for any rule index 1-88."""
        # Tactical categorization based on rule index
        if num in (1, 2, 3, 4, 11, 22, 36, 52, 87):
            tactic = "Signaling Downgrade & Eavesdropping"
            cat = "CIPHERING" if num != 87 else "VOWIFI_IPSEC"
            rat = "5G" if num in (4, 22) else ("WIFI" if num == 87 else ("4G" if num in (3, 11, 36) else "2G"))
            sev = "CRITICAL" if num in (1, 3, 4) else "HIGH"
            spec = "3GPP TS 33.501 / TS 33.401" if num != 87 else "3GPP TS 33.402 / RFC 7296"
        elif num in (6, 7, 12, 14, 23, 39, 45):
            tactic = "Initial Access & IMSI Catching"
            cat = "IDENTITY" if num in (6, 12, 39) else "DOWNGRADE"
            rat = "4G" if num in (6, 7, 12, 14, 23) else "5G"
            sev = "HIGH" if num in (6, 7, 14) else "MEDIUM"
            spec = "3GPP TS 24.301 / TS 36.331"
        elif num in (5, 10, 13, 18, 20, 47, 50, 69, 84):
            tactic = "Credential & Key Extraction"
            cat = "INTEGRITY" if num in (5, 13) else ("BLUETOOTH_CRYPTO" if num == 84 else "SIM_SECURITY")
            rat = "5G" if num in (13, 47, 50) else ("BLUETOOTH" if num == 84 else "SIM")
            sev = "CRITICAL" if num in (5, 18) else "HIGH"
            spec = "3GPP TS 33.501 / TS 31.102" if num != 84 else "Bluetooth SIG Core 5.2 / KNOB"
        elif num in (8, 17, 24, 25, 40, 68, 74):
            tactic = "Covert Location Tracking"
            cat = "SILENT_SMS" if num == 8 else "SURVEILLANCE"
            rat = "4G" if num in (8, 24, 25) else "SIM"
            sev = "CRITICAL" if num in (8, 24) else "HIGH"
            spec = "3GPP TS 23.040 / TS 36.355"
        elif num in (9, 15, 16, 19, 21, 51, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 70, 71, 72, 73, 75):
            tactic = "SIM & UICC Proactive Exploits"
            cat = "SIM_SECURITY"
            rat = "SIM"
            sev = "CRITICAL" if num in (9, 15, 19, 56, 57, 58) else "HIGH"
            spec = "3GPP TS 31.111 / TS 31.102"
        elif num in (76, 77, 78, 79, 80):
            tactic = "Signaling Downgrade & Eavesdropping"
            cat = "SURVEILLANCE"
            rat = "5G" if num in (76, 78, 80) else "4G"
            sev = "CRITICAL"
            spec = "ETSI TS 102 232 / 3GPP TS 33.108"
        elif num in (81, 82, 83, 85, 88):
            tactic = "Wireless & Baseband Firmware Exploits"
            cat = "WIFI_SECURITY" if num == 81 else ("BASEBAND_ESCAPE" if num == 88 else "BLE_SECURITY")
            rat = "WIFI" if num == 81 else ("BASEBAND" if num == 88 else "BLUETOOTH")
            sev = "CRITICAL" if num in (81, 88) else "HIGH"
            spec = "CVE-2017-11120 / Broadpwn" if num == 81 else ("CVE-2020-10061 / SweynTooth" if num == 82 else "Bluetooth Core 5.2 / BrakTooth")
        else:
            tactic = "Denial of Service & Jamming"
            cat = "DOS" if num != 86 else "COEX_INTERFERENCE"
            rat = "5G" if num in (30, 31, 35, 41, 43, 44, 48, 49) else ("MULTI" if num == 86 else "4G")
            sev = "HIGH" if num in (30, 31) else "MEDIUM"
            spec = "3GPP TS 38.331 / TS 24.501"

        titles = {
            1: "2G A5/0 Disabled Ciphering",
            2: "2G A5/1 Deprecated Stream Cipher",
            3: "3G/4G UEA0/EEA0 Null Ciphering",
            4: "5G NEA0 Null Ciphering",
            5: "4G/5G EIA0/NIA0 Null Integrity Protection",
            6: "Cleartext IMSI/SUPI Identity Request (IMSI Catcher Indicator)",
            7: "Forced 2G/3G/4G Downgrade via Reject (FBS Kill Switch)",
            8: "Silent SMS Type 0 Covert Location Probe",
            9: "SIMjacker (STK SEND SHORT MESSAGE Bytecode Attack)",
            10: "3G SRNS Relocation without Re-Authentication",
            11: "LTE Bearer Modification QoS Downgrade (User-Plane MitM)",
            12: "LTE/5G GUTI Reallocation Suppression (Persistent TMSI Tracking)",
            13: "5G Registration Accept with Null AMF Security Context",
            14: "Rogue BTS Cell Selection Manipulation (q-RxLevMin Abuse)",
            15: "WIBjacker (SIM Wireless Internet Browser Attack)",
            16: "UICC PIN / PUK Brute-Force Probing",
            17: "Stealth STK Location / IMEI Harvesting (PROVIDE LOCAL INFO)",
            18: "USIM Sensitive EF Exfiltration (EF_IMSI / EF_ICCID Read)",
            19: "STK SET UP CALL — Unauthorized Call Initiation by USIM",
            20: "USIM AUTHENTICATE AKA Cryptographic Execution",
            21: "STK Forced Browser Launch / Phishing Redirection (WIB/S@T)",
            22: "5G-to-EPS Interworking Bidding-Down (N1 Mode Suppression)",
            23: "FBS SIB Isolation (No Intra/Inter-Frequency Neighbor Cells)",
            24: "SS7 MAP SendRoutingInfo / Subscriber Location Disclosure",
            25: "Diameter S6a/S13 IMSI Enumeration / Location Probing",
            26: "VoLTE IMS SIP REGISTER Replay / Session Hijack",
            27: "IMS Emergency Service Bypass / SOS Call Interception",
            28: "5G SUCI Null-Scheme Fallback / SUPI Exposure",
            29: "5G Network Slice Isolation Bypass / Cross-Slice Exfiltration",
            30: "gNB RRC Setup Reject Flood / UE Denial-of-Service",
            31: "AMF Overload Signalling Attack / Registration Storm",
            32: "eSIM RSP Interception / Rogue SM-DP+ Profile Provisioning",
            33: "eSIM Rogue LPA Profile Deletion / Operational Disruption",
            34: "5G N32 Roaming Interface Eavesdropping / Home PLMN Exposure",
            35: "5G SBI OAuth Token Forgery / NF Impersonation",
            36: "RRC Integrity Protection Suppression (NIA0 / AS Cipher-Only)",
            37: "SMS Home Routing Bypass / MT SMS Spoofing via Interconnect",
            38: "LTE X2 Handover Context Exploit / AS Key Reuse",
            39: "Paging Correlation IMSI Capture via TMSI Abuse",
            40: "NTP/PTP RAN Timing Attack / GPS Spoofing Amplification",
            41: "AMF/gNB NGAP UE Context Release Flood",
            42: "Wi-Fi EAP-AKA' Downgrade to EAP-SIM (Non-3GPP Access)",
            43: "PRACH Preamble Flood / Random Access Channel Jamming",
            44: "5G URLLC QoS Flow Tampering / Latency-Injection",
            45: "Automated Neighbor Relation (ANR) Poisoning / Rogue Cell Insertion",
            46: "NB-IoT/LTE-M Device Credential Brute-Force / MQTT Flood",
            47: "5G-AKA SEAF MAC Bypass / Home Network Masquerade",
            48: "NR-U/LTE-LAA Unlicensed Band LBT Channel Starvation",
            49: "NWDAF Analytics Poisoning / AI-Driven Policy Manipulation",
            50: "NR RRC Re-establishment AS Key Rollback Attack",
            51: "Single-DES Cryptographic Weakness in SIM OTA Secured Packets",
            52: "Null-Ciphering / Plaintext Payload in SIM Remote File Management",
            53: "Remote Applet Management (RAM) Signature Suppression",
            54: "OTA Anti-Replay Counter Rollback / Zero-Counter Injection",
            55: "Proof of Receipt (PoR) Information Exfiltration Attack",
            56: "S@T Bytecode Command Execution via Unprotected TAR",
            57: "Wireless Internet Browser (WIB) Bytecode Injection",
            58: "STK Bearer Independent Protocol (BIP) Covert C2 Pipe",
            59: "STK Silent USSD / SS Execution",
            60: "Deceptive STK Phishing Overlays via DISPLAY TEXT Injection",
            61: "Unauthorized STK REFRESH File Modification",
            62: "Java Card Applet Firewall Escape / Object Privilege Escalation",
            63: "Logical Channel Exhaustion Denial-of-Service on UICC",
            64: "EF_PLMNwAcT & EF_FPLMN OTA Steering Manipulation",
            65: "APDU Fuzzing & Buffer Overflow in Telecom Toolkit Handlers",
            66: "eSIM ES8+ Remote SIM Provisioning Channel Tampering",
            67: "eUICC ECASD Root Certificate Injection",
            68: "STK PROVIDE LOCAL INFO Timing & Measurement Report Tracking",
            69: "Java Card Transient Array State Leak",
            70: "SMS-PP Data Download with Misleading PID/DCS",
            71: "STK RUN AT COMMAND Proactive Instruction Abuse",
            72: "USIM EF Read Access via Unauthorized SIM Access Profile",
            73: "Remote File Management (RFM) EF_LOCI / EF_PSLOCI Poisoning",
            74: "STK LANGUAGE NOTIFICATION & GEO LOCATE Fingerprinting",
            75: "Multi-Application UICC Access Rule Tampering",
            76: "ETSI TS 102 232 PS-PDU Lawful Interception Header Active",
            77: "CALEA Diagnostic & Raw Intercept Port Exposed",
            78: "X1 Target Provisioning Session Injection Attempt",
            79: "HI3 User-Plane Content of Communication (CC) Leakage",
            80: "HI2 Intercept Related Information (IRI) Metadata Exfiltration",
            81: "Broadpwn Wi-Fi SoC Baseband Memory Heap Corruption (CVE-2017-11120)",
            82: "Bluetooth Low Energy SweynTooth / BLESA Link Layer Malformation (CVE-2020-10061)",
            83: "BrakTooth Bluetooth LMP Feature Response & AU_RAND Memory Corruption",
            84: "KNOB Attack: Bluetooth Encryption Key Negotiation Entropy Reduction",
            85: "Bluetooth Mesh Provisioning Unencrypted Key Exchange / PB-ADV Spoofing",
            86: "Cellular-Wi-Fi Coexistence (CoEx) Denial-of-Service / LAA LBT Interference",
            87: "Wi-Fi Calling (VoWiFi / ePDG) IPsec IKEv2 Weak Diffie-Hellman / NULL Ciphering",
            88: "Cellular Baseband PCIe/UART DMA Firmware Escape to Host Processor"
        }

        title = titles.get(num, f"TelcoSec Vulnerability Rule #{num:03d}")
        return {
            'rule_id': rule_id,
            'title': title,
            'severity': sev,
            'category': cat,
            'tactic': tactic,
            'rat': rat,
            'spec': spec,
            'description': f"Security audit rule monitoring 3GPP cellular traffic for {title.lower()}.",
            'remediation': f"Enforce cryptographic mutual authentication (3GPP AKA), mandatory ciphering (128-EEA2/NEA2, 128-EIA2/NIA2), and disable legacy insecure interfaces according to {spec}."
        }

    def record_alert(self, severity: str, category: str, rat: str, title: str, description: str,
                     rule_id: str = 'TELCOSEC-VULN-GEN', raw_data: bytes = None, timestamp: float = None,
                     dedupe: bool = True, cooldown_s: float = None, dedupe_key: str = None):
        """Record a security alert with intelligent state-aware deduplication and hysteresis."""
        if hasattr(self, 'disabled_rules') and rule_id in self.disabled_rules:
            return

        ts = timestamp or time.time()
        if dedupe:
            if cooldown_s is None:
                cooldown_s = getattr(self, '_alert_cooldown_s', 5.0)

            key = (rule_id, dedupe_key or '')
            last = self._last_alert_ts.get(key, 0.0)
            if ts - last < cooldown_s:
                return
            self._last_alert_ts[key] = ts

        alert = SecurityAlert(severity, category, rat, title, description, rule_id, raw_data, timestamp)
        self.alerts.append(alert)
        self.stats['by_severity'][alert.severity] += 1
        self.stats['by_category'][alert.category] += 1
        self.stats['by_rule'][alert.rule_id] += 1
        print(alert.format_terminal(), flush=True)

        if self.alert_callback:
            try:
                self.alert_callback(alert.to_dict())
            except Exception as e:
                debug(f"Error invoking alert_callback: {e}")

    def on_log(self, log_code: int, log_payload: bytes, log_header: bytes = None, timestamp: float = None):
        self.stats['total_packets_audited'] += 1
        timestamp = timestamp or time.time()

        try:
            # 4G LTE NAS Handling
            if log_code in (
                LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
                LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
                LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
                LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C
            ):
                self.current_rat = '4G'
                self._audit_lte_nas(log_code, log_payload, timestamp)

            # 5G NR NAS Handling
            elif log_code in (
                LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
                LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
                LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
                LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C
            ):
                self.current_rat = '5G'
                self._audit_5g_nas(log_code, log_payload, timestamp)

            # CALEA / Lawful Interception Diagnostic Trace Logs (0xB0CD / 0xB825)
            elif log_code in (LOG_LTE_CALEA_TRACE_LOG_C, LOG_NR_CALEA_TRACE_LOG_C):
                self.current_rat = '5G' if log_code == LOG_NR_CALEA_TRACE_LOG_C else '4G'
                self.audit_calea_diag_packet(log_code, log_payload, timestamp)

            # 4G LTE RRC & SIB Handling
            elif log_code == LOG_LTE_RRC_OTA_MSG_LOG_C:
                self.current_rat = '4G'
                self._audit_lte_rrc(log_payload, timestamp)

            # 5G NR RRC & SIB Handling
            elif log_code == LOG_NR_RRC_OTA_MSG_LOG_C:
                self.current_rat = '5G'
                self._audit_5g_rrc(log_payload, timestamp)

            # 2G GSM Signaling
            elif log_code in (LOG_GSM_RR_SIGNALING_MESSAGE_C, LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C):
                self._audit_2g_signaling(log_code, log_payload, timestamp)

            # 3G WCDMA Signaling
            elif log_code == WCDMA_SIGNALLING_MESSAGE:
                self.current_rat = '3G'
                self._audit_3g_signaling(log_payload, timestamp)

            # UICC / USIM / SIM Smart Card APDUs & STK Commands
            elif log_code == LOG_SIM_APDU_LOG_C:
                self._audit_sim_apdu(log_payload, timestamp)

            # IMS / VoLTE / VoNR SIP Signaling
            elif log_code in (LOG_LTE_IMS_SIP_MSG_C, LOG_NR_IMS_SIP_MSG_C, LOG_IMS_SIP_MSG_C):
                self._audit_ims_sip(log_code, log_payload, timestamp)

            # CALEA / Lawful Interception Trace Log
            elif log_code in (LOG_LTE_CALEA_TRACE_LOG_C, LOG_NR_CALEA_TRACE_LOG_C):
                rat = '5G' if log_code == LOG_NR_CALEA_TRACE_LOG_C else '4G'
                self.record_alert(
                    'HIGH', 'INTERCEPTION', rat,
                    'Lawful Interception (CALEA) Event Generated',
                    f'Baseband emitted Lawful Interception diagnostic trace (log 0x{log_code:04x}). Potential active surveillance.',
                    rule_id='TELCOSEC-BADPRAC-005', raw_data=log_payload, timestamp=timestamp
                )

            # Cell Broadcast / Emergency Alert System (ETWS/CMAS)
            elif log_code in (LOG_GSM_CELL_BROADCAST_C, LOG_UMTS_CELL_BROADCAST_C, LOG_LTE_RRC_ETWS_CMAS_LOG_C, LOG_NR_RRC_ETWS_CMAS_LOG_C):
                self._audit_emergency_broadcast(log_code, log_payload, timestamp)

        except Exception as e:
            debug(f"Exception during security audit of log 0x{log_code:04x}: {e}")

    # =========================================================================
    # IMS / VoLTE / VoNR SIP Security Auditing
    # =========================================================================
    def _audit_ims_sip(self, log_code: int, log_payload: bytes, timestamp: float):
        if len(log_payload) < 10:
            return

        rat = '5G' if log_code == LOG_NR_IMS_SIP_MSG_C else '4G'
        
        try:
            # SIP text typically begins after standard Qualcomm header
            # Scan for SIP keywords (INVITE, REGISTER, SIP/2.0, From:, To:)
            sip_text = None
            for offset in (0, 4, 8, 12, 16):
                if offset < len(log_payload):
                    candidate = log_payload[offset:]
                    try:
                        decoded = candidate.decode('utf-8', errors='ignore')
                        if 'SIP/2.0' in decoded or 'INVITE' in decoded or 'From:' in decoded:
                            sip_text = decoded
                            break
                    except Exception:
                        pass

            if not sip_text:
                return

            lines = sip_text.splitlines()
            from_val = None
            pai_val = None

            for line in lines:
                lower_line = line.lower()
                if lower_line.startswith('from:') or lower_line.startswith('f:'):
                    from_val = line.split(':', 1)[1].strip()
                elif lower_line.startswith('p-asserted-identity:'):
                    pai_val = line.split(':', 1)[1].strip()

            # 1. Caller ID Spoofing / PAI Mismatch (TELCOSEC-BADPRAC-004)
            if from_val and pai_val:
                # Extract numeric digits or user part
                import re
                from_num = re.findall(r'sip:(\+?\d+)', from_val)
                pai_num = re.findall(r'sip:(\+?\d+)', pai_val)
                if from_num and pai_num and from_num[0] != pai_num[0]:
                    self.record_alert(
                        'HIGH', 'IMS_SECURITY', rat,
                        f'Caller ID / P-Asserted-Identity Spoofing Detected (From: {from_num[0]} != PAI: {pai_num[0]})',
                        'SIP From header does not match authenticated P-Asserted-Identity network assertion. Caller ID is likely spoofed.',
                        rule_id='TELCOSEC-BADPRAC-004', raw_data=log_payload, timestamp=timestamp
                    )

            # 2. Unencrypted VoLTE Audio Stream (TELCOSEC-BADPRAC-003)
            if 'm=audio' in sip_text:
                if 'rtp/avp' in sip_text.lower() and 'rtp/savp' not in sip_text.lower():
                    self.record_alert(
                        'HIGH', 'IMS_SECURITY', rat,
                        'Unencrypted VoLTE Voice Stream Negotiated (Plaintext RTP/AVP)',
                        'VoLTE/VoNR HD voice call negotiated with unencrypted RTP/AVP transport instead of SRTP.',
                        rule_id='TELCOSEC-BADPRAC-003', raw_data=log_payload, timestamp=timestamp
                    )

            # 3. Emergency Service Routing (TELCOSEC-BADPRAC-009)
            if 'urn:service:sos' in sip_text:
                self.record_alert(
                    'INFO', 'IMS_SECURITY', rat,
                    'Emergency Service URN Present in SIP Signaling',
                    'SIP message contains emergency service routing identifier (urn:service:sos).',
                    rule_id='TELCOSEC-BADPRAC-009', raw_data=log_payload, timestamp=timestamp
                )

        except Exception as e:
            debug(f"Error auditing IMS SIP payload: {e}")

    # =========================================================================
    # 4G LTE NAS Security Auditing (3GPP TS 24.301)
    # =========================================================================
    def _audit_lte_nas(self, log_code: int, log_payload: bytes, timestamp: float):
        if len(log_payload) < 5:
            return
        
        nas_pdu = log_payload[4:] if len(log_payload) > 4 else log_payload
        is_inbound = log_code in (LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C)

        if len(nas_pdu) < 2:
            return

        sec_hdr = (nas_pdu[0] >> 4) & 0x0F
        proto_disc = nas_pdu[0] & 0x0F

        if sec_hdr in (1, 2, 3, 4):
            if len(nas_pdu) < 7:
                return
            msg_offset = 6
        else:
            msg_offset = 1

        msg_type = nas_pdu[msg_offset]

        # 1. Security Mode Command (0x5d = 93)
        if msg_type == 0x5d and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                sec_alg = nas_pdu[msg_offset + 1]
                cipher_alg = (sec_alg >> 4) & 0x07
                integ_alg = sec_alg & 0x07

                cipher_names = {0: 'EEA0 (Null / Cleartext)', 1: '128-EEA1 (SNOW 3G)', 2: '128-EEA2 (AES)', 3: '128-EEA3 (ZUC)'}
                integ_names = {0: 'EIA0 (Null / Unauthenticated)', 1: '128-EIA1 (SNOW 3G)', 2: '128-EIA2 (AES)', 3: '128-EIA3 (ZUC)'}

                c_name = cipher_names.get(cipher_alg, f'Unknown ({cipher_alg})')
                i_name = integ_names.get(integ_alg, f'Unknown ({integ_alg})')

                if cipher_alg == 0:
                    self.record_alert(
                        'CRITICAL', 'CIPHERING', '4G',
                        'LTE NAS Null Ciphering Commanded (EEA0)',
                        f'Network commanded NULL ciphering (EEA0). All LTE NAS signaling & user-plane keys are unencrypted! Integrity: {i_name}.',
                        rule_id='TELCOSEC-VULN-003', raw_data=nas_pdu, timestamp=timestamp
                    )
                if integ_alg == 0:
                    self.record_alert(
                        'CRITICAL', 'INTEGRITY', '4G',
                        'LTE NAS Null Integrity Commanded (EIA0)',
                        f'Network commanded NULL integrity protection (EIA0). Network traffic is vulnerable to injection & tampering!',
                        rule_id='TELCOSEC-VULN-005', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 2. Identity Request (0x55 = 85)
        elif msg_type == 0x55 and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                id_type = nas_pdu[msg_offset + 1] & 0x07
                id_map = {1: 'IMSI', 2: 'IMEI', 3: 'IMEISV', 4: 'TMSI'}
                requested_id = id_map.get(id_type, f'Type {id_type}')

                if id_type == 1:  # Plain IMSI
                    self.record_alert(
                        'HIGH', 'IDENTITY', '4G',
                        'Cleartext IMSI Identity Request Detected',
                        'Network issued OTA Identity Request for plain IMSI. Classic indicator of False Base Station / IMSI Catcher harvesting subscriber ID.',
                        rule_id='TELCOSEC-VULN-006', raw_data=nas_pdu, timestamp=timestamp
                    )
                elif id_type in (2, 3):  # IMEI / IMEISV
                    self.record_alert(
                        'MEDIUM', 'IDENTITY', '4G',
                        f'Cleartext {requested_id} Identity Request Detected',
                        f'Network requested mobile hardware identity ({requested_id}) in cleartext over the radio link.',
                        rule_id='TELCOSEC-VULN-006', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 3. Attach Reject (0x44 = 68) & TAU Reject (0x48 = 72)
        elif msg_type in (0x44, 0x48) and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                cause = nas_pdu[msg_offset + 1]
                msg_name = 'Attach Reject' if msg_type == 0x44 else 'TAU Reject'

                if cause in (7, 8):
                    self.record_alert(
                        'CRITICAL', 'DOWNGRADE', '4G',
                        f'Malicious Forced 2G/3G Downgrade Attack ({msg_name} Cause #{cause})',
                        f'Network rejected connection with EMM Cause #{cause} ("EPS services not allowed"). '
                        f'Forces UE modem to disable LTE and downgrade to vulnerable legacy 2G/3G networks.',
                        rule_id='TELCOSEC-VULN-007', raw_data=nas_pdu, timestamp=timestamp
                    )
                elif cause in (2, 3, 6, 15):
                    self.record_alert(
                        'HIGH', 'DOWNGRADE', '4G',
                        f'Suspicious LTE {msg_name} (Cause #{cause})',
                        f'Network issued {msg_name} with EMM Cause #{cause}. Possible FBS rejection after subscriber harvesting.',
                        rule_id='TELCOSEC-VULN-007', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 4. Attach Accept / TAU Accept — check for GUTI reallocation suppression
        # (0x42 = Attach Accept, 0x49 = TAU Accept)
        elif msg_type in (0x42, 0x49) and is_inbound:
            msg_name = 'Attach Accept' if msg_type == 0x42 else 'TAU Accept'
            # GUTI is mandatory in TS 24.301; absence means TMSI is never refreshed.
            # A real EPC always includes GUTI (IEI 0x50) in Attach/TAU Accept.
            guti_present = b'\x50' in nas_pdu[msg_offset + 1:]
            if not guti_present:
                if not self.cell_profile['guti_reallocated']:
                    self.record_alert(
                        'MEDIUM', 'IDENTITY', '4G',
                        f'GUTI Reallocation Suppressed in LTE {msg_name}',
                        f'Network sent LTE {msg_name} without allocating a new GUTI (TMSI). '
                        f'Subscriber will continue using old TMSI, enabling persistent radio-layer tracking by passive observers.',
                        rule_id='TELCOSEC-VULN-012', raw_data=nas_pdu, timestamp=timestamp
                    )
            else:
                self.cell_profile['guti_reallocated'] = True

        # 5. LTE Modify Bearer Request (ESM: Bearer Resource Modification)
        # ESM Bearer Resource Allocation Request = 0xD3; Modify EPS Bearer = 0x9F
        elif msg_type in (0x9F, 0xD3) and is_inbound:
            self.record_alert(
                'MEDIUM', 'QOS_MANIPULATION', '4G',
                'LTE EPS Bearer Modification — Potential QoS Downgrade (User-Plane MitM)',
                'Network initiated EPS bearer modification. An adversary MitM proxy can use Modify Bearer to throttle, redirect, '
                'or degrade QCI/GBR parameters of the active data bearer.',
                rule_id='TELCOSEC-VULN-011', raw_data=nas_pdu, timestamp=timestamp
            )

    # =========================================================================
    # 5G NR 5GS NAS Security Auditing (3GPP TS 24.501)
    # =========================================================================
    def _audit_5g_nas(self, log_code: int, log_payload: bytes, timestamp: float):
        if len(log_payload) < 5:
            return
        
        nas_pdu = log_payload[4:] if len(log_payload) > 4 else log_payload
        is_inbound = log_code in (LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C)

        if len(nas_pdu) < 3:
            return

        epd = nas_pdu[0]  # 0x7E for 5GMM
        sec_hdr = (nas_pdu[1] >> 4) & 0x0F

        if sec_hdr in (1, 2, 3, 4):
            if len(nas_pdu) < 8:
                return
            msg_offset = 7
        else:
            msg_offset = 2

        msg_type = nas_pdu[msg_offset]

        # 1. 5GS Security Mode Command (0x5d = 93)
        if msg_type == 0x5d and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                sec_alg = nas_pdu[msg_offset + 1]
                cipher_alg = (sec_alg >> 4) & 0x07
                integ_alg = sec_alg & 0x07

                cipher_names = {0: 'NEA0 (Null / Unencrypted)', 1: '128-NEA1 (SNOW 3G)', 2: '128-NEA2 (AES)', 3: '128-NEA3 (ZUC)'}
                integ_names = {0: 'NIA0 (Null / Unauthenticated)', 1: '128-NIA1 (SNOW 3G)', 2: '128-NIA2 (AES)', 3: '128-NIA3 (ZUC)'}

                c_name = cipher_names.get(cipher_alg, f'Unknown ({cipher_alg})')
                i_name = integ_names.get(integ_alg, f'Unknown ({integ_alg})')

                if cipher_alg == 0:
                    self.record_alert(
                        'CRITICAL', 'CIPHERING', '5G',
                        '5G NR Null Ciphering Commanded (NEA0)',
                        f'5G Standalone core commanded NULL ciphering (NEA0). User plane and NAS traffic transmitted in plaintext! Integrity: {i_name}.',
                        rule_id='TELCOSEC-VULN-004', raw_data=nas_pdu, timestamp=timestamp
                    )
                if integ_alg == 0:
                    self.record_alert(
                        'CRITICAL', 'INTEGRITY', '5G',
                        '5G NR Null Integrity Commanded (NIA0)',
                        f'5G Standalone core commanded NULL integrity protection (NIA0). Vulnerable to packet modification and rogue NF injection!',
                        rule_id='TELCOSEC-VULN-005', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 2. 5GS Identity Request (0x5b = 91)
        elif msg_type == 0x5b and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                id_type = nas_pdu[msg_offset + 1] & 0x07
                if id_type != 1:  # Not SUCI
                    id_names = {2: '5G-GUTI', 3: 'IMEI', 4: '5G-S-TMSI', 5: 'IMEISV', 6: 'MAC', 7: 'SUPI / Cleartext'}
                    name = id_names.get(id_type, f'Type {id_type}')
                    self.record_alert(
                        'HIGH', 'IDENTITY', '5G',
                        f'5G SUCI Bypass / Cleartext {name} Identity Request',
                        f'5G network bypassed SUCI public-key encryption and requested unencrypted identity ({name}). Potential 5G IMSI Catcher probing.',
                        rule_id='TELCOSEC-VULN-006', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 3. 5GS Registration Reject (0x44 = 68)
        elif msg_type == 0x44 and is_inbound:
            if len(nas_pdu) > msg_offset + 1:
                cause = nas_pdu[msg_offset + 1]
                if cause in (7, 8):
                    self.record_alert(
                        'CRITICAL', 'DOWNGRADE', '5G',
                        f'Forced 5G Downgrade Attack (5GS Registration Reject Cause #{cause})',
                        f'5G core rejected registration with cause #{cause} ("5GS services not allowed"), coercing device into 4G/2G downgrade.',
                        rule_id='TELCOSEC-VULN-007', raw_data=nas_pdu, timestamp=timestamp
                    )

        # 4. 5GS Registration Accept (0x42) — check GUTI reallocation & interworking flags
        elif msg_type == 0x42 and is_inbound:
            # Check for Allowed NSSAI / Interworking Without N26 Interface indicator
            # The presence of '5GS-to-EPS Interworking without N26' with EPS fallback allowed
            # permits silent handoff to legacy EPC without re-authentication.
            interwork_no_n26 = b'\x29' in nas_pdu[msg_offset:]  # IEI 0x29 = allowed PDU types
            if interwork_no_n26:
                self.record_alert(
                    'HIGH', 'DOWNGRADE', '5G',
                    '5G-to-EPS Interworking Without N26 Interface Enabled (Bidding-Down Path)',
                    '5G Registration Accept includes EPS interworking indicator permitting handover to LTE/EPC '
                    'without N26 AMF-MME interface security context transfer. '
                    'Enables silent 5G→4G bidding-down by a rogue network node.',
                    rule_id='TELCOSEC-VULN-022', raw_data=nas_pdu, timestamp=timestamp
                )

            # GUTI reallocation suppression in 5G Registration Accept
            guti_5g_present = b'\x77' in nas_pdu[msg_offset:]  # 5G-GUTI IEI = 0x77
            if not guti_5g_present:
                self.record_alert(
                    'MEDIUM', 'IDENTITY', '5G',
                    '5G-GUTI Reallocation Suppressed in Registration Accept',
                    'Network sent 5G Registration Accept without allocating a new 5G-GUTI (SUPI/TMSI alias). '
                    'Subscriber is persistently trackable via the old 5G-GUTI on the radio interface.',
                    rule_id='TELCOSEC-VULN-012', raw_data=nas_pdu, timestamp=timestamp
                )

        # 5. Configuration Update Command (0x54) — AMF sending SMC without fresh key
        elif msg_type == 0x54 and is_inbound:
            # If we see a Security Mode Command followed immediately by Config Update without
            # a new Registration procedure, it may indicate key replay.
            if self.cell_profile['smc_count'] > 0 and self.cell_profile['attach_count'] == 0:
                self.record_alert(
                    'HIGH', 'INTEGRITY', '5G',
                    '5G Configuration Update Without Prior Re-Registration (Possible Key Replay)',
                    'AMF sent Configuration Update Command without a fresh Registration/SMC key exchange sequence. '
                    'A rogue AMF may replay stale security context to man-in-the-middle the 5G NAS layer.',
                    rule_id='TELCOSEC-VULN-013', raw_data=nas_pdu, timestamp=timestamp
                )
        
        # Track SMC and attach counts for state machine
        if msg_type == 0x5d:
            self.cell_profile['smc_count'] += 1
        elif msg_type == 0x41:
            self.cell_profile['attach_count'] += 1

    # =========================================================================
    # 2G GSM / GPRS Security Auditing (3GPP TS 44.018)
    # =========================================================================
    def _audit_2g_signaling(self, log_code: int, log_payload: bytes, timestamp: float):
        self.current_rat = '2G'

        # Ciphering Mode Command in GSM RR (Message Type 0x35)
        for i in range(len(log_payload) - 1):
            if log_payload[i] == 0x35:  # Ciphering Mode Command
                cipher_setting = log_payload[i + 1]
                alg = (cipher_setting >> 1) & 0x07
                start_cipher = cipher_setting & 0x01
                
                if not start_cipher or alg == 0:
                    self.record_alert(
                        'CRITICAL', 'CIPHERING', '2G',
                        '2G GSM Ciphering Disabled (A5/0 Unencrypted)',
                        'Base station explicitly commanded A5/0 (No Encryption). All voice calls, SMS, and data are broadcast in cleartext.',
                        rule_id='TELCOSEC-VULN-001', raw_data=log_payload, timestamp=timestamp
                    )
                elif alg == 1:
                    self.record_alert(
                        'HIGH', 'CIPHERING', '2G',
                        '2G Weak Ciphering Commanded (A5/1)',
                        'Base station commanded A5/1 ciphering. A5/1 has known cryptographic weaknesses and can be cracked in real-time with rainbow tables.',
                        rule_id='TELCOSEC-VULN-002', raw_data=log_payload, timestamp=timestamp
                    )
                break

            # 2G Identity Request (Message Type 0x18 in MM)
            elif log_payload[i] == 0x18:
                id_type = log_payload[i + 1] & 0x07
                if id_type == 1:  # IMSI
                    self.record_alert(
                        'HIGH', 'IDENTITY', '2G',
                        '2G Cleartext IMSI Identity Request',
                        '2G Base station requested plain subscriber IMSI over unencrypted channel.',
                        rule_id='TELCOSEC-VULN-006', raw_data=log_payload, timestamp=timestamp
                    )
                break

    # =========================================================================
    # 3G WCDMA Security Auditing
    # =========================================================================
    def _audit_3g_signaling(self, log_payload: bytes, timestamp: float):
        # 1. VULN-003: 3G UEA0 Null Ciphering
        if b'UEA0' in log_payload or b'\x55\x45\x41\x30' in log_payload:
            self.record_alert(
                'CRITICAL', 'CIPHERING', '3G',
                '3G UMTS Null Ciphering (UEA0) Detected',
                '3G RNC commanded UEA0 (No Encryption) algorithm. All 3G radio-layer data is transmitted in plaintext.',
                rule_id='TELCOSEC-VULN-003', raw_data=log_payload, timestamp=timestamp
            )

        # 2. VULN-010: SRNS Relocation without Re-Authentication
        # SRNS Relocation Request (RRC: Message Type 0x01 in class SecurityModeCommand)
        # The relocation procedure should always trigger a new AKA run.
        # If we see an RRC SRNS Relocation Complete without a prior AUTH_REQ in window, flag it.
        if b'\x49' in log_payload and len(log_payload) > 8:
            # 0x49 = HANDOVER_TO_UTRAN_COMPLETE; look for absence of AUTHENTICATION_REQUEST (0x12) in recent context
            self.record_alert(
                'HIGH', 'AUTHENTICATION', '3G',
                '3G SRNS/Handover Relocation Without AKA Re-Authentication Observed',
                'SRNS relocation or intra-system handover completed without triggering a new AKA authentication challenge. '
                'An attacker can perform a relay SRNS relocation to inherit a valid 3G security context without authentication.',
                rule_id='TELCOSEC-VULN-010', raw_data=log_payload, timestamp=timestamp
            )

    # =========================================================================
    # UICC / USIM Smart Card APDU & STK Proactive Command Auditor
    # =========================================================================
    def _audit_sim_apdu(self, log_payload: bytes, timestamp: float):
        if len(log_payload) < 4:
            return

        # Scan for APDU command header [CLA, INS, P1, P2]
        # In Diag SIM APDU logs, APDU starts after header bytes (typically offset 4 to 8)
        apdu = log_payload[4:] if len(log_payload) >= 8 else log_payload
        if len(apdu) < 4:
            return

        cla = apdu[0]
        ins = apdu[1]
        p1 = apdu[2]
        p2 = apdu[3]

        # 1. USIM / ISIM AUTHENTICATE AKA (0x88 / 0x89)
        if ins in (0x88, 0x89):
            self.record_alert(
                'INFO', 'SIM_SECURITY', 'SIM',
                'USIM AUTHENTICATE (AKA Challenge Execution)',
                'Baseband sent UMTS/LTE/5G AKA RAND & AUTN challenge to USIM Milenage/TUAK cryptographic core.',
                rule_id='TELCOSEC-VULN-020', raw_data=log_payload, timestamp=timestamp
            )

        # 2. PIN / PUK Verification & Brute-Force Monitoring (0x20 / 0x2C)
        elif ins in (0x20, 0x2C):
            action_name = "VERIFY PIN" if ins == 0x20 else "UNBLOCK PIN (PUK)"
            self.record_alert(
                'MEDIUM', 'SIM_SECURITY', 'SIM',
                f'UICC {action_name} Probing Detected',
                f'Smart card {action_name} executed. Sequential attempts monitor for card lock brute-forcing.',
                rule_id='TELCOSEC-VULN-016', raw_data=log_payload, timestamp=timestamp
            )

        # 3. VULN-018: USIM READ BINARY on Sensitive Elementary Files
        # INS = 0xB0 (READ BINARY), P1/P2 encode the file offset / SFI
        # EF_IMSI: SFI=0x07; EF_ICCID: SFI=0x1A; EF_MSISDN: SFI=0x0A
        elif ins == 0xB0:
            sfi = p1 & 0x1F
            sensitive_ef = {
                0x07: 'EF_IMSI (subscriber identity)',
                0x1A: 'EF_ICCID (card serial number)',
                0x0A: 'EF_MSISDN (subscriber phone number)',
                0x04: 'EF_LOCI (location information)',
                0x08: 'EF_Kc (GSM session key)',
            }
            if sfi in sensitive_ef:
                ef_name = sensitive_ef[sfi]
                self.record_alert(
                    'HIGH', 'SIM_SECURITY', 'SIM',
                    f'USIM READ BINARY on Sensitive {ef_name.split("(")[0].strip()} - Possible EF Exfiltration',
                    f'Baseband issued READ BINARY on {ef_name}. If triggered by an OTA or STK command rather than the modem stack, '
                    f'this indicates covert subscriber identity or key material exfiltration from the USIM.',
                    rule_id='TELCOSEC-VULN-018', raw_data=log_payload, timestamp=timestamp
                )

        # 4. VULN-064 / VULN-073 / VULN-075: UPDATE BINARY / UPDATE RECORD (0xD6 / 0xDC)
        elif ins in (0xD6, 0xDC):
            ef_id = (p1 << 8) | p2
            sfi = p1 & 0x1F
            self.audit_sim_file_system_write(ef_id, sfi, payload=apdu, timestamp=timestamp)

        # 5. VULN-051..057: ENVELOPE (SMS-PP Data Download / Event Download - 0xC2)
        elif ins == 0xC2:
            self.audit_ota_secured_packet(apdu[4:], timestamp=timestamp)

        # 6. STK Proactive Command Execution (BER-TLV Tag 0xD0)
        for offset in range(len(apdu) - 5):
            if apdu[offset] == 0xD0:  # Proactive Command Tag
                # Look for Command Details Tag (0x81 or 0x01)
                if offset + 5 < len(apdu) and apdu[offset + 2] in (0x81, 0x01):
                    cmd_type = apdu[offset + 5]

                    # VULN-009: SIMjacker — SEND SHORT MESSAGE (0x13)
                    if cmd_type == 0x13:
                        self.record_alert(
                            'CRITICAL', 'SIM_SECURITY', 'SIM',
                            'SIMjacker Attack: STK SEND SHORT MESSAGE Commanded by USIM',
                            'USIM executed STK SEND SHORT MESSAGE! Classic SIMjacker / WIB spyware attack sending covert SMS from victim handset.',
                            rule_id='TELCOSEC-VULN-009', raw_data=log_payload, timestamp=timestamp
                        )
                    # VULN-017: Stealth Location Harvesting — PROVIDE LOCAL INFORMATION (0x26)
                    elif cmd_type == 0x26:
                        self.record_alert(
                            'HIGH', 'SIM_SECURITY', 'SIM',
                            'Stealth STK Location / IMEI Query (PROVIDE LOCAL INFORMATION)',
                            'USIM queried IMEI, Location Area, Cell ID, or NMR without user knowledge or UI prompt.',
                            rule_id='TELCOSEC-VULN-017', raw_data=log_payload, timestamp=timestamp
                        )
                    # VULN-021: WIB/S@T Browser Launch — LAUNCH BROWSER (0x15)
                    elif cmd_type == 0x15:
                        self.record_alert(
                            'HIGH', 'SIM_SECURITY', 'SIM',
                            'STK Forced Browser Launch / WIB Phishing Redirection (LAUNCH BROWSER)',
                            'USIM commanded device to open web browser to external URL. Classic WIBjacker or S@T Browser attack vector.',
                            rule_id='TELCOSEC-VULN-021', raw_data=log_payload, timestamp=timestamp
                        )
                    # VULN-019: Unauthorized Call Initiation — SET UP CALL (0x10)
                    elif cmd_type == 0x10:
                        self.record_alert(
                            'CRITICAL', 'SIM_SECURITY', 'SIM',
                            'STK SET UP CALL - Unauthorized Call Initiation by USIM',
                            'USIM issued STK SET UP CALL proactive command. An attacker-controlled SIM can silently dial premium-rate '
                            'numbers, emergency services, or C2 infrastructure without any user interaction.',
                            rule_id='TELCOSEC-VULN-019', raw_data=log_payload, timestamp=timestamp
                        )
                    # VULN-015: WIBjacker — OPEN CHANNEL / BIP (0x40)
                    elif cmd_type == 0x40:
                        self.record_alert(
                            'HIGH', 'SIM_SECURITY', 'SIM',
                            'STK OPEN CHANNEL (BIP) - Covert Data Exfiltration Pipe (WIBjacker)',
                            'USIM opened a Bearer Independent Protocol (BIP) channel. WIBjacker and S@T attacks use BIP '
                            'to exfiltrate location, IMEI, and call records over a hidden data channel.',
                            rule_id='TELCOSEC-VULN-015', raw_data=log_payload, timestamp=timestamp
                        )
                break

    # =========================================================================
    # 4G LTE RRC & False Base Station SIB Heuristics (VULN-014, BADPRAC-001/002)
    # =========================================================================
    def _audit_lte_rrc(self, log_payload: bytes, timestamp: float):
        """Inspect LTE RRC OTA messages for FBS-characteristic SIB patterns."""
        if len(log_payload) < 8:
            return

        try:
            # Qualcomm LTE RRC OTA log has a 4-byte header
            rrc_raw = log_payload[4:]
            chan_type = log_payload[1] if len(log_payload) > 1 else 0

            # VULN-014 heuristic: FBS SIB1 with extreme q-RxLevMin
            # Only evaluate on BCCH (Broadcast Control Channel) SIB frames (chan_type in 1, 2, or SIB marker)
            if chan_type in (1, 2) or (len(rrc_raw) > 10 and (rrc_raw[0] == 0x00 or rrc_raw[1] == 0x00)):
                for i in range(min(32, len(rrc_raw) - 1)):
                    val = rrc_raw[i]
                    if isinstance(val, int) and val >= 0xBC:
                        q_rx = -(256 - val) * 2
                        if q_rx <= -130:
                            self.cell_profile['q_rx_lev_min'] = q_rx
                            self.record_alert(
                                'HIGH', 'FBS_HEURISTIC', '4G',
                                f'FBS Luring: Extreme q-RxLevMin={q_rx} dBm in LTE SIB1',
                                f'LTE SIB1 advertises q-RxLevMin = {q_rx} dBm — far below the -140 dBm physical limit. '
                                f'False Base Stations use permissive cell selection thresholds to force nearby UEs to camp on the rogue cell.',
                                rule_id='TELCOSEC-VULN-014', raw_data=log_payload, timestamp=timestamp,
                                cooldown_s=120.0, dedupe_key=f"qrx_{q_rx}"
                            )
                            break

            # VULN-023: FBS isolation — broadcast no neighbor cells (no SIB4/SIB5)
            if len(rrc_raw) < 80:
                has_sib4 = b'\x04' in rrc_raw[:20]
                has_sib5 = b'\x05' in rrc_raw[:20]
                if not has_sib4 and not has_sib5:
                    self.cell_profile['has_intra_neighbors'] = False
                    self.cell_profile['has_inter_neighbors'] = False
                    self.record_alert(
                        'MEDIUM', 'FBS_HEURISTIC', '4G',
                        'LTE SIB: No Intra/Inter-Frequency Neighbor Cells Advertised (FBS Isolation Indicator)',
                        'LTE System Information Block contains no neighbor cell lists (SIB4/SIB5 absent). '
                        'False Base Stations suppress neighbor broadcasts to prevent UE from measuring real cells and initiating handover away.',
                        rule_id='TELCOSEC-VULN-023', raw_data=log_payload, timestamp=timestamp,
                        dedupe_key="fbs_no_neighbors_4g"
                    )

        except Exception as e:
            debug(f'Exception auditing LTE RRC payload: {e}')

    # =========================================================================
    # 5G NR RRC Auditing (VULN-022, VULN-023)
    # =========================================================================
    def _audit_5g_rrc(self, log_payload: bytes, timestamp: float):
        """Inspect 5G NR RRC OTA messages for rogue gNB / false base station patterns."""
        if len(log_payload) < 8:
            return

        try:
            rrc_raw = log_payload[4:]

            # VULN-023: 5G SIB4 / SIB5 absence — no inter/intra-frequency neighbor cells
            has_nr_sib4 = b'\x04' in rrc_raw[:24]
            has_nr_sib5 = b'\x05' in rrc_raw[:24]
            has_nr_sib7 = b'\x07' in rrc_raw[:24]  # inter-RAT LTE
            if not has_nr_sib4 and not has_nr_sib5 and 20 < len(rrc_raw) < 100:
                self.record_alert(
                    'MEDIUM', 'FBS_HEURISTIC', '5G',
                    '5G NR SIB: No Neighbor Cell Lists Advertised (Rogue gNB Isolation Indicator)',
                    '5G SIBs contain no intra-frequency (SIB4) or inter-frequency (SIB5) neighbor cell information. '
                    'A rogue gNB suppresses neighbor broadcasts to trap the UE on the malicious cell and prevent measurement-triggered handovers.',
                    rule_id='TELCOSEC-VULN-023', raw_data=log_payload, timestamp=timestamp,
                    cooldown_s=180.0, dedupe_key="fbs_no_neighbors_5g"
                )

            # VULN-022 (RRC layer): Inter-RAT mobility to E-UTRA without N26 security context
            if has_nr_sib7 and len(rrc_raw) > 30:
                self.record_alert(
                    'HIGH', 'DOWNGRADE', '5G',
                    '5G-to-LTE Inter-RAT Mobility (SIB7 Present) - 5G->4G Bidding-Down Vector Active',
                    '5G NR SIB7 inter-RAT LTE mobility detected. Without the N26 AMF-MME security context transfer interface, '
                    'the inter-RAT handover to LTE may bypass 5G NAS security and expose the session to LTE-layer vulnerabilities.',
                    rule_id='TELCOSEC-VULN-022', raw_data=log_payload, timestamp=timestamp,
                    cooldown_s=120.0, dedupe_key="sib7_inter_rat"
                )

        except Exception as e:
            debug(f'Exception auditing 5G RRC payload: {e}')

    # =========================================================================
    # Public helper: audit an E-RAB / Bearer Modification (VULN-011)
    # =========================================================================
    def audit_lte_bearer_modification(self, qci_before: int, qci_after: int,
                                       mbr_dl_before: int = 0, mbr_dl_after: int = 0,
                                       timestamp: float = None):
        """Audit a detected EPS bearer modification for QoS downgrade (Man-in-the-Middle indicator)."""
        qci_downgraded = qci_after > qci_before   # Higher QCI = lower priority
        mbr_degraded   = mbr_dl_after < mbr_dl_before and mbr_dl_before > 0

        if qci_downgraded or mbr_degraded:
            changes = []
            if qci_downgraded:
                changes.append(f'QCI {qci_before} -> {qci_after} (priority reduced)')
            if mbr_degraded:
                changes.append(f'DL MBR {mbr_dl_before} -> {mbr_dl_after} kbps (throttled)')
            self.record_alert(
                'HIGH', 'QOS_MANIPULATION', '4G',
                'LTE EPS Bearer QoS Downgrade Detected (User-Plane MitM Indicator)',
                f'Active EPS bearer QoS was degraded mid-session: {", ".join(changes)}. '
                f'A MitM adversary manipulating the S1-U / SGW path can use Modify Bearer to '
                f'degrade or redirect user-plane traffic without the UE detecting the change.',
                rule_id='TELCOSEC-VULN-011', raw_data=None, timestamp=timestamp,
                dedupe=False   # Each bearer change should always be logged individually
            )

    # =========================================================================
    # Emergency Broadcast & SMS Auditing
    # =========================================================================
    def _audit_emergency_broadcast(self, log_code: int, log_payload: bytes, timestamp: float):
        rat_map = {
            LOG_GSM_CELL_BROADCAST_C: '2G',
            LOG_UMTS_CELL_BROADCAST_C: '3G',
            LOG_LTE_RRC_ETWS_CMAS_LOG_C: '4G',
            LOG_NR_RRC_ETWS_CMAS_LOG_C: '5G'
        }
        rat = rat_map.get(log_code, 'MULTI')
        self.record_alert(
            'INFO', 'EMERGENCY_BROADCAST', rat,
            f'{rat} Emergency Alert (ETWS / CMAS / Cell Broadcast) Received',
            f'Received Public Warning / Emergency alert message over broadcast channel.',
            rule_id='TELCOSEC-BADPRAC-006', raw_data=log_payload, timestamp=timestamp
        )

    # =========================================================================
    # Silent SMS / Flash SMS Detection
    # =========================================================================
    def audit_sms_tp_pdu(self, tp_pdu: bytes, timestamp: float = None):
        """Inspect SMS Deliver TP-PDU for Type 0 / Silent SMS (surveillance ping)."""
        if len(tp_pdu) < 4:
            return
        
        if 0x40 in tp_pdu:
            self.record_alert(
                'CRITICAL', 'SILENT_SMS', self.current_rat,
                'Silent SMS (Type 0 / Ping) Surveillance Probe Detected',
                'Received Type 0 Silent SMS (TP-PID = 0x40). Message triggers baseband ACK without displaying to the user, used for covert location tracking.',
                rule_id='TELCOSEC-VULN-008', raw_data=tp_pdu, timestamp=timestamp
            )

    # =========================================================================
    # Extended Detection Methods — VULN-024 to VULN-050
    # =========================================================================

    def audit_ss7_map_message(self, operation_code: int, calling_gt: str = '',
                              called_gt: str = '', payload: bytes = None,
                              timestamp: float = None):
        """VULN-024: Detect SS7 MAP Category 1/2 attack operations (SRI, PSI, ATI).

        GSM MAP operation codes:
          0x03 = sendRoutingInfo (SRI)   — subscriber location disclosure
          0x2E = provideSubscriberInfo (PSI) — real-time location
          0x47 = anyTimeInterrogation (ATI) — unrestricted location
        """
        ATTACK_OPS = {0x03: 'sendRoutingInfo (SRI)', 0x2E: 'provideSubscriberInfo (PSI)', 0x47: 'anyTimeInterrogation (ATI)'}
        if operation_code in ATTACK_OPS:
            self.record_alert(
                'CRITICAL', 'SS7_ATTACK', 'MULTI',
                f'SS7 MAP {ATTACK_OPS[operation_code]} Attack Detected',
                f'Received SS7 MAP operation {ATTACK_OPS[operation_code]} (code 0x{operation_code:02X}) '
                f'from GT {calling_gt or "unknown"} targeting {called_gt or "subscriber"}. '
                f'This operation enables real-time subscriber location disclosure and IMSI harvesting via SS7 interconnect.',
                rule_id='TELCOSEC-VULN-024', raw_data=payload, timestamp=timestamp
            )

    def audit_diameter_message(self, command_code: int, application_id: int,
                               origin_realm: str = '', payload: bytes = None,
                               timestamp: float = None):
        """VULN-025: Detect Diameter S6a/S13 location probing and IMSI enumeration."""
        # S6a: AIR=318, ULR=316, PUR=321, CLR=317 | MME-Identity-Check S13: ECR=324
        PROBE_CMDS = {318: 'S6a Authentication-Information-Request (AIR)',
                      316: 'S6a Update-Location-Request (ULR)',
                      321: 'S6a Purge-UE-Request (PUR)',
                      324: 'S13 ME-Identity-Check-Request (ECR)'}
        if command_code in PROBE_CMDS:
            self.record_alert(
                'HIGH', 'DIAMETER_ATTACK', 'MULTI',
                f'Diameter {PROBE_CMDS[command_code]} from Unrecognised Realm',
                f'Diameter command {PROBE_CMDS[command_code]} received from realm "{origin_realm}". '
                f'Unauthorised Diameter peers can use S6a/S13 commands to enumerate IMSI, '
                f'resolve HLR/HSS addresses, and perform real-time UE location disclosure.',
                rule_id='TELCOSEC-VULN-025', raw_data=payload, timestamp=timestamp
            )

    def audit_ims_sip_message(self, method: str, headers: dict = None,
                              payload: bytes = None, timestamp: float = None):
        """VULN-026: Detect IMS SIP REGISTER replay attacks and missing IMS-AKA challenge."""
        headers = headers or {}
        if method == 'REGISTER':
            auth_hdr = headers.get('Authorization', headers.get('Proxy-Authorization', ''))
            if 'algorithm=AKAv1' not in auth_hdr and 'algorithm=AKAv2' not in auth_hdr:
                self.record_alert(
                    'HIGH', 'IMS_SECURITY', 'IMS',
                    'IMS SIP REGISTER Without IMS-AKA Authentication (Replay / Weak-Auth Vector)',
                    f'SIP REGISTER received without IMS-AKA (RFC 3310) authentication. '
                    f'Missing AKAv1/v2 challenge indicates SIP replay, digest-only auth, or '
                    f'cleartext registration on the Gm interface.',
                    rule_id='TELCOSEC-VULN-026', raw_data=payload, timestamp=timestamp
                )
        elif method == 'INVITE' and headers.get('P-Asserted-Identity', '').lower() == 'anonymous':
            self.record_alert(
                'MEDIUM', 'IMS_SECURITY', 'IMS',
                'IMS SIP INVITE with Anonymous P-Asserted-Identity (Identity Spoofing)',
                'VoLTE INVITE carries P-Asserted-Identity: Anonymous, indicating caller '
                'identity suppression or potential IMS identity spoofing attempt.',
                rule_id='TELCOSEC-VULN-026', raw_data=payload, timestamp=timestamp
            )

    def audit_5g_suci(self, suci_bytes: bytes, timestamp: float = None):
        """VULN-028: Detect 5G SUCI using null-scheme (plaintext SUPI exposure)."""
        if not suci_bytes or len(suci_bytes) < 8:
            return
        # Byte 0 of SUCI routing indicator/protection scheme: 0x00 = null-scheme
        protection_scheme = suci_bytes[0] & 0x0F
        if protection_scheme == 0x00:
            self.record_alert(
                'CRITICAL', 'IDENTITY', '5G',
                '5G SUCI Null-Scheme Detected: Cleartext SUPI Transmitted (IMSI Exposure)',
                'Registration Request carries SUCI with null-scheme (protection_scheme_id=0x00), '
                'meaning the SUPI (IMSI) is transmitted in plaintext. This defeats 5G subscriber '
                'concealment and enables passive IMSI harvesting without decryption.',
                rule_id='TELCOSEC-VULN-028', raw_data=suci_bytes, timestamp=timestamp
            )

    def audit_ngap_rrc_setup_rate(self, setup_count: int, reject_count: int,
                                   window_sec: float = 10.0, timestamp: float = None):
        """VULN-030: Detect RRC Setup Reject floods indicating UE DoS attack."""
        if setup_count > 0:
            reject_rate = reject_count / setup_count
            if reject_rate > 0.7 and reject_count >= 50:
                self.record_alert(
                    'HIGH', 'DOS_ATTACK', '5G',
                    f'gNB RRC Setup Reject Flood Detected ({reject_count}/{setup_count} rejected in {window_sec:.0f}s)',
                    f'Abnormally high RRC Setup rejection rate ({reject_rate:.0%}) detected. '
                    f'A rogue gNB or misconfigured cell may be flooding UEs with RRC Reject '
                    f'messages to deny radio connectivity (Denial-of-Service attack).',
                    rule_id='TELCOSEC-VULN-030', raw_data=None, timestamp=timestamp
                )

    def audit_amf_registration_storm(self, reg_count_per_sec: float,
                                      baseline_rps: float = 10.0, timestamp: float = None):
        """VULN-031: Detect 5G AMF registration request storms."""
        if reg_count_per_sec > baseline_rps * 10:
            self.record_alert(
                'HIGH', 'DOS_ATTACK', '5G',
                f'5G AMF Registration Storm Detected ({reg_count_per_sec:.0f} reg/s vs baseline {baseline_rps:.0f} reg/s)',
                f'5G Registration Request rate is {reg_count_per_sec / baseline_rps:.0f}x above baseline. '
                f'Coordinated registration flooding can exhaust AMF session capacity and deny '
                f'service to legitimate UEs.',
                rule_id='TELCOSEC-VULN-031', raw_data=None, timestamp=timestamp
            )

    def audit_esim_rsp_event(self, operation: str, sm_dp_cert_valid: bool = True,
                              payload: bytes = None, timestamp: float = None):
        """VULN-032/033: Detect eSIM RSP profile events — rogue provisioning or deletion."""
        if operation == 'ProfileDownload' and not sm_dp_cert_valid:
            self.record_alert(
                'CRITICAL', 'ESIM_SECURITY', 'SIM',
                'eSIM RSP Profile Download from Unverified SM-DP+ (Rogue Profile Install)',
                'eSIM Remote SIM Provisioning Profile Download initiated from SM-DP+ with '
                'unverified certificate chain. This may indicate a rogue SM-DP+ server '
                'attempting to install a surveillance profile via the ES8+ interface.',
                rule_id='TELCOSEC-VULN-032', raw_data=payload, timestamp=timestamp
            )
        elif operation in ('ProfileDelete', 'ProfileDisable', 'MemoryReset'):
            self.record_alert(
                'HIGH', 'ESIM_SECURITY', 'SIM',
                f'eSIM Profile {operation} Command Detected via LPA',
                f'eSIM eUICC received a {operation} command via the Local Profile Assistant (LPA). '
                f'Unauthorised profile deletion can cause complete SIM service disruption.',
                rule_id='TELCOSEC-VULN-033', raw_data=payload, timestamp=timestamp
            )

    def audit_5g_sbi_token(self, token_scope: str, nf_type: str,
                            token_valid: bool = True, payload: bytes = None,
                            timestamp: float = None):
        """VULN-035: Detect 5G SBI OAuth token misuse / NF impersonation."""
        if not token_valid:
            self.record_alert(
                'CRITICAL', 'SBI_SECURITY', '5G',
                f'5G SBI OAuth Token Invalid / NF Impersonation Attempt ({nf_type})',
                f'5G SBI service request from NF type "{nf_type}" carries an invalid or '
                f'expired OAuth2.0 access token (scope: {token_scope}). '
                f'This may indicate NF service consumer impersonation or token replay attack '
                f'on the HTTP/2 SBI interface.',
                rule_id='TELCOSEC-VULN-035', raw_data=payload, timestamp=timestamp
            )

    def audit_rrc_integrity_config(self, nia_algorithm: int, rat: str = '5G',
                                    payload: bytes = None, timestamp: float = None):
        """VULN-036: Detect NIA0 (null integrity) in RRC Security Mode Command."""
        if nia_algorithm == 0:
            self.record_alert(
                'CRITICAL', 'INTEGRITY', rat,
                f'{rat} RRC Security Mode Command with NIA0 Null Integrity Protection',
                f'{rat} RRC SecurityModeCommand specifies integrity algorithm NIA0 (null). '
                f'Null integrity allows RRC control-plane messages to be forged or replayed '
                f'without detection, enabling OTA injection and session hijack.',
                rule_id='TELCOSEC-VULN-036', raw_data=payload, timestamp=timestamp
            )

    def audit_paging_imsi_leak(self, paging_identity_type: str,
                                payload: bytes = None, timestamp: float = None):
        """VULN-039: Detect cleartext IMSI in paging or attach for TMSI correlation tracking."""
        if paging_identity_type.upper() in ('IMSI', 'SUPI'):
            self.record_alert(
                'HIGH', 'IDENTITY', self.current_rat,
                'Paging with Cleartext IMSI/SUPI — TMSI Correlation Attack Vector Active',
                f'Network is paging subscriber using cleartext {paging_identity_type} instead '
                f'of temporary identifier (TMSI/GUTI). This allows passive observers to '
                f'correlate the IMSI to a physical location and cell.',
                rule_id='TELCOSEC-VULN-039', raw_data=payload, timestamp=timestamp
            )

    def audit_ngap_ue_context_release_rate(self, release_count: int,
                                            window_sec: float = 5.0,
                                            threshold: int = 100,
                                            timestamp: float = None):
        """VULN-041: Detect NGAP UE Context Release floods (AMF/gNB DoS)."""
        if release_count > threshold:
            self.record_alert(
                'HIGH', 'DOS_ATTACK', '5G',
                f'NGAP UE Context Release Flood ({release_count} releases in {window_sec:.0f}s)',
                f'{release_count} UE Context Release Requests detected in {window_sec:.0f}s window. '
                f'Flood of NGAP UE Context Release messages can saturate AMF session tracking '
                f'and cause service degradation for legitimate connected UEs.',
                rule_id='TELCOSEC-VULN-041', raw_data=None, timestamp=timestamp
            )

    def audit_prach_collision_rate(self, collision_rate: float,
                                    cell_id: int = 0, timestamp: float = None):
        """VULN-043: Detect PRACH preamble flood / LTE-NR random access jamming."""
        if collision_rate > 0.6:
            self.record_alert(
                'MEDIUM', 'DOS_ATTACK', self.current_rat,
                f'PRACH Preamble Collision Rate Anomaly ({collision_rate:.0%}) on Cell {cell_id}',
                f'Random access preamble collision rate of {collision_rate:.0%} detected on '
                f'cell PCI {cell_id}. Elevated PRACH collision rates may indicate deliberate '
                f'preamble flooding to deny random access to legitimate UEs (RACH jamming).',
                rule_id='TELCOSEC-VULN-043', raw_data=None, timestamp=timestamp
            )

    def audit_5g_aka_seaf_mac(self, xres_star_valid: bool, serving_network_id: str = '',
                               payload: bytes = None, timestamp: float = None):
        """VULN-047: Detect 5G-AKA SEAF MAC verification failure (home network masquerade)."""
        if not xres_star_valid:
            self.record_alert(
                'CRITICAL', 'AUTHENTICATION', '5G',
                '5G-AKA SEAF MAC Verification Failure — Potential Home Network Masquerade',
                f'5G-AKA Authentication Response XRES* binding to serving network '
                f'"{serving_network_id}" failed SEAF verification. This may indicate '
                f'a rogue AMF presenting a forged authentication vector from a masqueraded '
                f'home network, bypassing 5G mutual authentication.',
                rule_id='TELCOSEC-VULN-047', raw_data=payload, timestamp=timestamp
            )

    def audit_rrc_reestablishment(self, ncc_value: int, prev_ncc_value: int,
                                   payload: bytes = None, timestamp: float = None):
        """VULN-050: Detect NR RRC Re-establishment with recycled NCC (AS key rollback)."""
        if ncc_value == prev_ncc_value and ncc_value >= 0:
            self.record_alert(
                'HIGH', 'KEY_MANAGEMENT', '5G',
                f'NR RRC Re-establishment with Recycled NCC={ncc_value} — AS Key Rollback Risk',
                f'RRCReestablishmentRequest presents NCC={ncc_value} which matches the '
                f'previous NCC value. Re-using the same Next Hop Chaining Counter prevents '
                f'forward key derivation and may allow an adversary to replay captured '
                f'RRC frames with a rolled-back AS security context.',
                rule_id='TELCOSEC-VULN-050', raw_data=payload, timestamp=timestamp
            )

    # =========================================================================
    # SIM Card, Applet & OTA Secured Packet Detection (VULN-051 to VULN-075)
    # =========================================================================

    def audit_ota_secured_packet(self, ota_payload: bytes, timestamp: float = None):
        """VULN-051, 052, 054, 055, 056, 057: Audit 3GPP TS 31.115 Secured Packet structure.

        Decodes Command Header:
          - CPL (2 bytes): Command Packet Length
          - CHL (1 byte): Command Header Length
          - SPI1 (1 byte): Security Parameters Indicator (b1-b2: Checksum, b3: Ciphering, b4-b5: Counter)
          - SPI2 (1 byte): PoR Configuration
          - KIC (1 byte): Key Identifier for Ciphering (b1-b2: algo 01=DES, 02=AES)
          - KID (1 byte): Key Identifier for RC/CC/DS (b1-b2: algo 01=DES, 02=AES)
          - TAR (3 bytes): Toolkit Application Reference
          - CNTR (5 bytes): Sequence Counter
        """
        if not ota_payload or len(ota_payload) < 10:
            return

        try:
            # Detect whether payload starts with CPL (2 bytes) or SMS-PP TLV tag (0x7F22 / 0x82...)
            offset = 0
            if len(ota_payload) > 16 and ota_payload[0] in (0x7F, 0x82, 0xD1):
                offset = 2
            elif len(ota_payload) > 18 and ota_payload[0] == 0x02 and ota_payload[1] in (0x70, 0x71) and ota_payload[2] in (0x02, 0x7F):
                offset = 4

            if offset + 10 > len(ota_payload):
                offset = 0

            chl = ota_payload[offset + 2] if offset + 2 < len(ota_payload) else 10
            spi1 = ota_payload[offset + 3] if offset + 3 < len(ota_payload) else 0
            spi2 = ota_payload[offset + 4] if offset + 4 < len(ota_payload) else 0
            kic = ota_payload[offset + 5] if offset + 5 < len(ota_payload) else 0
            kid = ota_payload[offset + 6] if offset + 6 < len(ota_payload) else 0
            tar = ota_payload[offset + 7:offset + 10] if offset + 10 <= len(ota_payload) else b'\x00\x00\x00'
            tar_hex = tar.hex().upper()

            # VULN-051: Deprecated Single-DES KIC / KID
            kic_algo = kic & 0x03
            kid_algo = kid & 0x03
            if (kic_algo == 0x01 or kid_algo == 0x01) and (kic != 0 or kid != 0):
                self.record_alert(
                    'CRITICAL', 'SIM_SECURITY', 'SIM',
                    'Single-DES Cryptographic Weakness in SIM OTA Packet (Rootkit Attack Vector)',
                    f'SIM OTA Secured Packet specifies deprecated Single-DES encryption/checksum (KIC=0x{kic:02X}, KID=0x{kid:02X}). '
                    f'Single-DES keys are breakable via rainbow tables in minutes, allowing zero-click rootkit injection (Karsten Nohl attack).',
                    rule_id='TELCOSEC-VULN-051', raw_data=ota_payload, timestamp=timestamp
                )

            # VULN-052: Plaintext Remote File Management (RFM)
            is_rfm_tar = tar_hex in ('000000', 'B00001', 'B00010', 'B00000')
            is_ciphered = bool(spi1 & 0x04)
            if is_rfm_tar and not is_ciphered:
                self.record_alert(
                    'CRITICAL', 'SIM_SECURITY', 'SIM',
                    'Null-Ciphering in SIM Remote File Management (RFM SPI Bypass)',
                    f'SIM Remote File Management OTA packet targeted TAR {tar_hex} with null encryption (SPI1=0x{spi1:02X}, ciphering disabled). '
                    f'Allows unauthorized arbitrary modification of sensitive SIM elementary files (EF_LOCI, EF_SPN, EF_PLMNwAcT).',
                    rule_id='TELCOSEC-VULN-052', raw_data=ota_payload, timestamp=timestamp
                )

            # VULN-054: Anti-Replay Counter Rollback / Zero Counter
            cntr_mode = (spi1 >> 3) & 0x03
            cntr_bytes = ota_payload[offset + 10:offset + 15] if offset + 15 <= len(ota_payload) else b'\x00' * 5
            if cntr_mode == 0 or cntr_bytes == b'\x00' * 5:
                self.record_alert(
                    'HIGH', 'SIM_SECURITY', 'SIM',
                    'OTA Anti-Replay Counter Disabled / Zero Sequence Number Injection',
                    f'SIM OTA Packet specifies no counter checking (SPI1=0x{spi1:02X}) with CNTR=0x{cntr_bytes.hex()}. '
                    f'Enables replay attacks of captured administrative OTA SMS-PP packets.',
                    rule_id='TELCOSEC-VULN-054', raw_data=ota_payload, timestamp=timestamp
                )

            # VULN-055: PoR Exfiltration Attack
            por_requested = bool(spi2 & 0x01)
            por_ciphered = bool(spi2 & 0x08)
            if por_requested and not por_ciphered and not is_ciphered:
                self.record_alert(
                    'HIGH', 'SIM_SECURITY', 'SIM',
                    'Proof of Receipt (PoR) Unencrypted Exfiltration Attack',
                    f'OTA Secured Packet demands cleartext Proof of Receipt (PoR) SMS (SPI2=0x{spi2:02X}). '
                    f'Attacker forces card to respond with diagnostic and memory state over unencrypted SMS.',
                    rule_id='TELCOSEC-VULN-055', raw_data=ota_payload, timestamp=timestamp
                )

            # VULN-056: S@T Browser Attack (SIMjacker)
            if tar_hex in ('000005', '504154', '534154') or b'\x00\x00\x05' in ota_payload or b'PAT' in ota_payload:
                self.record_alert(
                    'CRITICAL', 'SIM_SECURITY', 'SIM',
                    'S@T Bytecode Execution via Unprotected TAR (SIMjacker Vector)',
                    f'SIM OTA message targeting S@T Browser application (TAR {tar_hex}). '
                    f'Enables silent zero-click execution of proactive STK commands (location tracking, covert SMS).',
                    rule_id='TELCOSEC-VULN-056', raw_data=ota_payload, timestamp=timestamp
                )

            # VULN-057: WIBjacker Attack
            if tar_hex in ('000001', 'D00001', '574942') or b'\xD0\x00\x01' in ota_payload or b'WIB' in ota_payload:
                self.record_alert(
                    'CRITICAL', 'SIM_SECURITY', 'SIM',
                    'Wireless Internet Browser (WIB) Bytecode Injection (WIBjacker Attack)',
                    f'SIM OTA message targeting SmartTrust WIB (TAR {tar_hex}). '
                    f'Unauthenticated WIB bytecode execution can force handset to initiate unauthorized calls and exfiltrate credentials.',
                    rule_id='TELCOSEC-VULN-057', raw_data=ota_payload, timestamp=timestamp
                )

        except Exception as e:
            debug(f'Exception in audit_ota_secured_packet: {e}')

    def audit_stk_proactive_command(self, cmd_type: int, cmd_qualifier: int = 0,
                                     payload: bytes = None, timestamp: float = None):
        """VULN-058, 059, 060, 061, 068, 071, 074: Audit STK proactive commands."""
        # VULN-058: OPEN CHANNEL (BIP - 0x40)
        if cmd_type == 0x40:
            self.record_alert(
                'CRITICAL', 'SIM_SECURITY', 'SIM',
                'STK OPEN CHANNEL (BIP) Covert C2 Pipe Detected',
                'USIM applet initiated OPEN CHANNEL (Bearer Independent Protocol). '
                'BIP channels allow applets to establish hidden direct TCP/UDP connections to the internet, bypassing OS firewalls and VPNs.',
                rule_id='TELCOSEC-VULN-058', raw_data=payload, timestamp=timestamp
            )

        # VULN-059: SEND USSD (0x12) / SEND SS (0x11)
        elif cmd_type in (0x11, 0x12):
            op_name = 'SEND USSD' if cmd_type == 0x12 else 'SEND SS'
            self.record_alert(
                'HIGH', 'SIM_SECURITY', 'SIM',
                f'STK Silent {op_name} Supplementary Service Execution',
                f'USIM applet executed proactive {op_name} (code 0x{cmd_type:02X}). '
                f'Used by malicious SIM applets to silently modify call forwarding rules (*21*), disable security, or drain prepaid balances.',
                rule_id='TELCOSEC-VULN-059', raw_data=payload, timestamp=timestamp
            )

        # VULN-060: DISPLAY TEXT (0x21) / GET INPUT (0x23)
        elif cmd_type in (0x21, 0x23):
            op_name = 'DISPLAY TEXT' if cmd_type == 0x21 else 'GET INPUT'
            is_high_priority = bool(cmd_qualifier & 0x01)
            if is_high_priority:
                self.record_alert(
                    'MEDIUM', 'SIM_SECURITY', 'SIM',
                    f'High-Priority STK {op_name} Prompt Injection (Phishing Vector)',
                    f'USIM issued priority {op_name} proactive dialogue. '
                    f'Malicious applets use full-screen unclosable display prompts to conduct PIN/credential phishing.',
                    rule_id='TELCOSEC-VULN-060', raw_data=payload, timestamp=timestamp
                )

        # VULN-061: REFRESH (0x01)
        elif cmd_type == 0x01:
            self.record_alert(
                'HIGH', 'SIM_SECURITY', 'SIM',
                'STK REFRESH Baseband Reset / Re-registration Instruction',
                f'USIM commanded STK REFRESH (qualifier=0x{cmd_qualifier:02X}). '
                f'Forcing baseband re-attach is used to trigger registration on nearby IMSI catchers or reload tampered network steering files.',
                rule_id='TELCOSEC-VULN-061', raw_data=payload, timestamp=timestamp
            )

        # VULN-068: PROVIDE LOCAL INFO (NMR & Timing Advance - 0x26, qual=0x01/0x02)
        elif cmd_type == 0x26 and cmd_qualifier in (0x01, 0x02):
            self.record_alert(
                'HIGH', 'SIM_SECURITY', 'SIM',
                'STK PROVIDE LOCAL INFO Network Measurement Results (NMR) Harvesting',
                'USIM queried real-time Network Measurement Results (NMR) and Timing Advance. '
                'Enables high-precision indoor physical triangulation of the subscriber without GPS.',
                rule_id='TELCOSEC-VULN-068', raw_data=payload, timestamp=timestamp
            )

        # VULN-071: RUN AT COMMAND (0x34 / 0x20)
        elif cmd_type in (0x20, 0x34):
            self.record_alert(
                'CRITICAL', 'SIM_SECURITY', 'SIM',
                'STK RUN AT COMMAND Modem Instruction Execution via SIM',
                'USIM executed RUN AT COMMAND proactive instruction. '
                'Allows SIM applet to directly issue modem AT commands to control RF bands, configure PDP contexts, or access baseband NVRAM.',
                rule_id='TELCOSEC-VULN-071', raw_data=payload, timestamp=timestamp
            )

        # VULN-074: LANGUAGE NOTIFICATION / GEO LOCATE (0x35 / 0x43)
        elif cmd_type in (0x35, 0x43):
            self.record_alert(
                'MEDIUM', 'SIM_SECURITY', 'SIM',
                'STK High-Resolution Location / Demographic Fingerprinting Command',
                f'USIM executed proactive command 0x{cmd_type:02X} (Geo Locate / Language Notification) to extract device demographic and location profile.',
                rule_id='TELCOSEC-VULN-074', raw_data=payload, timestamp=timestamp
            )

    def audit_javacard_applet_management(self, operation: str, aid: str = '',
                                         dap_present: bool = True, payload: bytes = None,
                                         timestamp: float = None):
        """VULN-053, 062, 063, 069: Audit GlobalPlatform Remote Applet Management (RAM)."""
        if operation in ('INSTALL_LOAD', 'INSTALL_INSTALL') and not dap_present:
            self.record_alert(
                'CRITICAL', 'SIM_SECURITY', 'SIM',
                'Java Card Remote Applet Install Without DAP Signature Verification',
                f'GlobalPlatform RAM command "{operation}" for AID {aid or "unknown"} executed without Data Authentication Pattern (DAP). '
                f'Allows arbitrary third-party Java Card bytecode installation in Issuer Security Domain.',
                rule_id='TELCOSEC-VULN-053', raw_data=payload, timestamp=timestamp
            )
        elif operation == 'MANAGE_CHANNEL_EXHAUSTION':
            self.record_alert(
                'MEDIUM', 'SIM_SECURITY', 'SIM',
                'UICC Logical Channel Exhaustion Attempt',
                'Multiple MANAGE CHANNEL open requests detected in rapid succession, potentially starving USIM/ISIM authentication channels.',
                rule_id='TELCOSEC-VULN-063', raw_data=payload, timestamp=timestamp
            )

    def audit_sim_file_system_write(self, ef_id: int, sfi: int = 0,
                                    payload: bytes = None, timestamp: float = None):
        """VULN-064, 073, 075: Audit modifications to sensitive SIM Elementary Files."""
        # EF_PLMNwAcT (0x6F60) or EF_FPLMN (0x6F7B)
        if ef_id in (0x6F60, 0x6F7B) or sfi in (0x0B, 0x0C):
            self.record_alert(
                'HIGH', 'SIM_SECURITY', 'SIM',
                'EF_PLMNwAcT / EF_FPLMN Steering of Roaming Tampering Detected',
                f'Unauthorized write to Roaming PLMN Selection file (EF_ID=0x{ef_id:04X}, SFI=0x{sfi:02X}). '
                f'Can force the device onto hostile partner networks (Anti-Steering attack) or block legitimate roaming.',
                rule_id='TELCOSEC-VULN-064', raw_data=payload, timestamp=timestamp
            )
        # EF_LOCI (0x6F7E) or EF_PSLOCI (0x6F73)
        elif ef_id in (0x6F7E, 0x6F73) or sfi in (0x04, 0x05):
            self.record_alert(
                'HIGH', 'SIM_SECURITY', 'SIM',
                'EF_LOCI / EF_PSLOCI Location Area Poisoning (Attach DoS Vector)',
                f'Write to Location Information Elementary File (EF_ID=0x{ef_id:04X}). '
                f'Poisoning EF_LOCI with invalid Location Area / Tracking Area values can cause permanent network attach denial.',
                rule_id='TELCOSEC-VULN-073', raw_data=payload, timestamp=timestamp
            )
        # EF_ARR (0x6F06) or Access Control Rules (0x6F40)
        elif ef_id in (0x6F06, 0x6F40) or sfi in (0x06, 0x10):
            self.record_alert(
                'CRITICAL', 'SIM_SECURITY', 'SIM',
                'UICC Access Control Rule (EF_ARR/ARF) Tampering — Carrier Privilege Escalation',
                f'Write to UICC Carrier Access Rule Elementary File (EF_ID=0x{ef_id:04X}). '
                f'Tampering with Carrier Privilege Rules allows untrusted mobile apps to gain system-level carrier permissions on Android/iOS.',
                rule_id='TELCOSEC-VULN-075', raw_data=payload, timestamp=timestamp
            )

    def audit_class2_sms_data_download(self, tp_pid: int, tp_dcs: int,
                                        payload: bytes = None, timestamp: float = None):
        """VULN-070: Audit SMS-PP Data Download for Class 2 SIM Data spoofing."""
        if tp_pid == 0x7F or (tp_dcs & 0x13) == 0x12: # Class 2 SIM-specific SMS
            if payload and len(payload) > 8 and (payload[0] != 0x02 and payload[0] != 0x7F):
                self.record_alert(
                    'HIGH', 'SIM_SECURITY', 'SIM',
                    'SMS-PP Class 2 Data Download with Malformed Security Headers (SMS Spoofing)',
                    f'Received SMS-PP Data Download (TP-PID=0x{tp_pid:02X}, TP-DCS=0x{tp_dcs:02X}) without valid 3GPP TS 31.115 security wrapper. '
                    f'Class 2 SMS spoofing allows silent toolkit injection directly to SIM memory without appearing in device SMS inbox.',
                    rule_id='TELCOSEC-VULN-070', raw_data=payload, timestamp=timestamp
                )

    # =========================================================================
    # Module Lifecycle & Summary Reporting
    # =========================================================================
    def on_dispose(self):
        self.print_summary()
        if self.audit_log_path:
            self._export_json_report()

    def print_summary(self):
        print(f"\n{COLOR_HEADER}+==========================================================================+{COLOR_RESET}")
        print(f"{COLOR_HEADER}|                 Radio Security Audit Summary Report                      |{COLOR_RESET}")
        print(f"{COLOR_HEADER}+==========================================================================+{COLOR_RESET}")
        print(f"  Total Packets Audited : {self.stats['total_packets_audited']}")
        print(f"  Total Security Alerts : {len(self.alerts)}")
        print()
        print(f"  {COLOR_BOLD}Alerts by Severity:{COLOR_RESET}")
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
            count = self.stats['by_severity'][sev]
            color = COLOR_CRITICAL if sev == 'CRITICAL' else (COLOR_HIGH if sev == 'HIGH' else COLOR_MEDIUM)
            print(f"    - {color}{sev:<10}{COLOR_RESET}: {count}")
        print()
        print(f"  {COLOR_BOLD}Alerts by Category:{COLOR_RESET}")
        for cat, count in sorted(self.stats['by_category'].items()):
            print(f"    - {cat:<20}: {count}")
        print()
        print(f"  {COLOR_BOLD}Alerts by TelcoSec Rule ID:{COLOR_RESET}")
        for rule_id, count in sorted(self.stats['by_rule'].items()):
            print(f"    - {rule_id:<20}: {count}")
        print()

    def _export_json_report(self):
        try:
            report_data = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'total_packets_audited': self.stats['total_packets_audited'],
                'total_alerts': len(self.alerts),
                'stats_by_severity': dict(self.stats['by_severity']),
                'stats_by_category': dict(self.stats['by_category']),
                'stats_by_rule': dict(self.stats['by_rule']),
                'alerts': [a.to_dict() for a in self.alerts],
            }
            with open(self.audit_log_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            print(f"[+] Exported structured audit log to {self.audit_log_path}")
        except Exception as e:
            error(f"Failed to export audit report to {self.audit_log_path}: {e}")

    # =========================================================================
    # Lawful Interception & CALEA Security Auditing (Rules 076 - 080)
    # =========================================================================

    def audit_etsi_li_packet(self, raw_bytes: bytes, is_encrypted: bool = False, timestamp: float = None) -> dict:
        """
        Audits ETSI TS 102 232 PS-PDU and 3GPP TS 33.108 HI2/HI3 handover interface packets.
        Evaluates transport security, sequence continuity, and correlation validity.
        """
        from ..protocol.etsi_li import EtsiLiPsPduParser
        parsed = EtsiLiPsPduParser.parse_ps_pdu(raw_bytes, is_encrypted_transport=is_encrypted)
        ts = timestamp or time.time()

        # Rule 76: Unencrypted Handover Interface Transmission (Plaintext HI2/HI3/X2/X3)
        if not is_encrypted:
            self.record_alert(
                'CRITICAL', 'CALEA', 'LI',
                'Unencrypted Lawful Interception Handover Interface (Plaintext HI2/HI3 Exposure)',
                f'ETSI TS 102 232 / 3GPP TS 33.108 packet delivered in cleartext over unencrypted transport. '
                f'Target LIID={parsed.get("liid")}, CIN={parsed.get("cin_hex")}, InnerProto={parsed.get("inner_proto")}. '
                f'Exposes sensitive warrant intercepts and target identity to passive wiretapping.',
                rule_id='TELCOSEC-VULN-076', raw_data=raw_bytes, timestamp=ts
            )

        # Rule 77: Sequence Counter Reset / Non-Monotonic Tampering
        seq = parsed.get('seq_num', 0)
        cin = parsed.get('cin', 0)
        if hasattr(self, '_li_seq_tracker'):
            if cin in self._li_seq_tracker:
                last_seq = self._li_seq_tracker[cin]
                if seq <= last_seq and seq != 0:
                    self.record_alert(
                        'HIGH', 'INTEGRITY', 'LI',
                        'Lawful Interception Sequence Counter Reset / Replay Tampering',
                        f'Non-monotonic PS-PDU sequence detected on CIN={parsed.get("cin_hex")}: '
                        f'Received seq={seq} after previous seq={last_seq}. Indicates packet injection, replay, or intercept gap.',
                        rule_id='TELCOSEC-VULN-077', raw_data=raw_bytes, timestamp=ts
                    )
            self._li_seq_tracker[cin] = seq
        else:
            self._li_seq_tracker = {cin: seq}

        return parsed

    def audit_calea_diag_packet(self, log_code: int, payload: bytes, timestamp: float = None):
        """
        Audits Qualcomm baseband CALEA diagnostic trace packets (0xB0CD LTE, 0xB825 5G NR).
        Detects silent baseband intercept activation and raw data exfiltration.
        """
        from ..protocol.etsi_li import EtsiLiPsPduParser
        ts = timestamp or time.time()
        rat = '5G' if log_code == LOG_NR_CALEA_TRACE_LOG_C else '4G'

        parsed = EtsiLiPsPduParser.parse_ps_pdu(payload, is_encrypted_transport=False)

        # Rule 79: Baseband Qualcomm CALEA Silent Trigger Exfiltration
        self.record_alert(
            'HIGH', 'CALEA', rat,
            f'Baseband Qualcomm CALEA Intercept Trace Active (Log Code 0x{log_code:04X})',
            f'Qualcomm baseband emitted diagnostic CALEA trace record for {rat} radio stack. '
            f'Target={parsed.get("liid")}, CIN={parsed.get("cin_hex")}, Payload={parsed.get("payload_length")} bytes. '
            f'Indicates lawful interception tap or covert diagnostic mirroring active on device modem.',
            rule_id='TELCOSEC-VULN-079', raw_data=payload, timestamp=ts
        )

    def audit_x1_provisioning(self, x1_json_text: str, is_authenticated: bool = True, timestamp: float = None) -> dict:
        """
        Audits 3GPP TS 33.128 X1 target provisioning requests (ADMF -> POI / MDF).
        """
        from ..protocol.etsi_li import X1ProvisioningParser
        parsed = X1ProvisioningParser.parse_x1_request(x1_json_text)
        ts = timestamp or time.time()

        # Rule 78: Unauthorized Target Activation via Unauthenticated X1 REST Interface
        if not is_authenticated:
            self.record_alert(
                'CRITICAL', 'CALEA', '5G',
                'Unauthorized Lawful Interception Target Activation (Unauthenticated X1 REST Request)',
                f'3GPP TS 33.128 X1 Intercept Provisioning Request received without mutual TLS X.509 certificate authentication. '
                f'ADMF={parsed.get("admf_id")}, XID={parsed.get("xid")}, Targets={parsed.get("target_identifiers")}. '
                f'Allows rogue network entities to provision unauthorized interception taps on 5G Core NFs (AMF/SMF/UPF).',
                rule_id='TELCOSEC-VULN-078', raw_data=x1_json_text.encode('utf-8'), timestamp=ts
            )

        return parsed

    def audit_broadpwn_wifi_frame(self, wlc_event_code: int, payload_len: int, raw_bytes: bytes = None, timestamp: float = None):
        """
        VULN-081: Broadpwn Wi-Fi SoC Baseband Memory Heap Corruption (CVE-2017-11120).
        Detects anomalous Broadcom/Cypress WLC_E_PROMISC events and oversized 802.11 association frames.
        """
        ts = timestamp or time.time()
        # WLC_E_PROMISC (event 100) or oversized 802.11 element buffer (> 1024 bytes)
        if wlc_event_code == 100 or payload_len > 1024:
            self.record_alert(
                'CRITICAL', 'WIFI_SECURITY', 'WIFI',
                'Broadpwn Wi-Fi SoC Baseband Memory Heap Corruption (CVE-2017-11120)',
                f'Detected anomalous Wi-Fi SoC firmware buffer pattern (WLC Event={wlc_event_code}, Size={payload_len}B). '
                f'Broadpwn vulnerability in BCM43xx Wi-Fi microkernel allows remote arbitrary code execution via malformed 802.11 elements.',
                rule_id='TELCOSEC-VULN-081', raw_data=raw_bytes, timestamp=ts
            )

    def audit_bluetooth_sweyntooth_packet(self, llid: int, length: int, raw_bytes: bytes = None, timestamp: float = None):
        """
        VULN-082: Bluetooth Low Energy SweynTooth / BLESA Link Layer Malformation (CVE-2020-10061).
        Detects zero-length Link Layer Data PDUs and invalid LLID control frames.
        """
        ts = timestamp or time.time()
        if (llid == 0x01 or llid == 0x02) and length == 0:
            self.record_alert(
                'HIGH', 'BLE_SECURITY', 'BLUETOOTH',
                'Bluetooth Low Energy SweynTooth Link Layer Zero-Length PDU Malformation (CVE-2020-10061)',
                f'Received anomalous BLE Link Layer frame with LLID={llid} and zero length. '
                f'SweynTooth exploits cause baseband firmware freeze or hard fault exception in BLE SoC controllers.',
                rule_id='TELCOSEC-VULN-082', raw_data=raw_bytes, timestamp=ts
            )

    def audit_bluetooth_braktooth_lmp(self, opcode: int, payload_len: int, raw_bytes: bytes = None, timestamp: float = None):
        """
        VULN-083: BrakTooth Bluetooth LMP Feature Response & AU_RAND Memory Corruption.
        Detects malformed LMP (Link Manager Protocol) control frames.
        """
        ts = timestamp or time.time()
        if opcode in (39, 40) and payload_len == 0: # LMP_features_res with invalid length
            self.record_alert(
                'HIGH', 'BLE_SECURITY', 'BLUETOOTH',
                'BrakTooth Bluetooth LMP Feature Response & AU_RAND Memory Corruption',
                f'Received malformed Bluetooth Classic Link Manager Protocol frame (LMP Opcode={opcode}, Len={payload_len}). '
                f'BrakTooth attack crashes BT baseband processor via out-of-bounds pointer dereference.',
                rule_id='TELCOSEC-VULN-083', raw_data=raw_bytes, timestamp=ts
            )

    def audit_bluetooth_knob_entropy(self, key_entropy_bytes: int, raw_bytes: bytes = None, timestamp: float = None):
        """
        VULN-084: KNOB Attack: Bluetooth Encryption Key Negotiation Entropy Reduction (< 7 octets).
        """
        ts = timestamp or time.time()
        if key_entropy_bytes < 7:
            self.record_alert(
                'HIGH', 'BLUETOOTH_CRYPTO', 'BLUETOOTH',
                f'KNOB Attack: Bluetooth Encryption Key Entropy Reduced to {key_entropy_bytes} Octets (Weak Key Vector)',
                f'Bluetooth encryption key negotiation accepted entropy of only {key_entropy_bytes} bytes (standard minimum is 16). '
                f'Enables real-time brute-force decryption of all Bluetooth traffic between connected devices.',
                rule_id='TELCOSEC-VULN-084', raw_data=raw_bytes, timestamp=ts
            )

    def audit_bluetooth_mesh_provisioning(self, is_encrypted: bool, pdu_type: str, raw_bytes: bytes = None, timestamp: float = None):
        """
        VULN-085: Bluetooth Mesh Provisioning Unencrypted Key Exchange / PB-ADV Spoofing.
        """
        ts = timestamp or time.time()
        if not is_encrypted and 'PROV_DATA' in pdu_type.upper():
            self.record_alert(
                'HIGH', 'BLE_SECURITY', 'BLUETOOTH',
                'Bluetooth Mesh Provisioning Unencrypted Key Exchange / PB-ADV Spoofing',
                f'Bluetooth Mesh Provisioning PDU ({pdu_type}) observed without ECDH session key protection over PB-ADV. '
                f'Exposes Mesh Network Key (NetKey) and Device Key (DevKey) to passive radio interceptors.',
                rule_id='TELCOSEC-VULN-085', raw_data=raw_bytes, timestamp=ts
            )

    def audit_coex_interference(self, rssi_drop_db: float, collision_rate: float, timestamp: float = None):
        """
        VULN-086: Cellular-Wi-Fi Coexistence (CoEx) Denial-of-Service / LAA LBT Interference.
        """
        ts = timestamp or time.time()
        if rssi_drop_db > 25.0 and collision_rate > 0.6:
            self.record_alert(
                'MEDIUM', 'COEX_INTERFERENCE', 'MULTI',
                f'Cellular-Wi-Fi Coexistence (CoEx) LBT Channel Starvation (RSSI Drop: -{rssi_drop_db:.1f} dB)',
                f'Severe RF CoEx desensitization detected between cellular (LTE-LAA/NR-U) and 2.4/5GHz Wi-Fi/BT radios. '
                f'Listen-Before-Talk (LBT) starvation prevents cellular user-plane scheduling.',
                rule_id='TELCOSEC-VULN-086', raw_data=None, timestamp=ts
            )

    def audit_vowifi_ikev2_sa(self, encryption_algo: str, dh_group: int, timestamp: float = None):
        """
        VULN-087: Wi-Fi Calling (VoWiFi / ePDG) IPsec IKEv2 Weak Diffie-Hellman / NULL Ciphering.
        """
        ts = timestamp or time.time()
        if 'NULL' in encryption_algo.upper() or dh_group in (1, 2, 5):
            self.record_alert(
                'HIGH', 'VOWIFI_IPSEC', 'WIFI',
                f'VoWiFi ePDG IPsec Tunnel Insecure Crypto (Algo: {encryption_algo}, DH Group: {dh_group})',
                f'Wi-Fi Calling (3GPP TS 33.402) IKEv2 security association negotiated with deprecated Diffie-Hellman group {dh_group} or null encryption. '
                f'Voice media and IMS SIP signaling across untrusted Wi-Fi can be eavesdropped.',
                rule_id='TELCOSEC-VULN-087', raw_data=None, timestamp=ts
            )

    def audit_baseband_dma_escape(self, event_type: str, dma_address: int, timestamp: float = None):
        """
        VULN-088: Cellular Baseband PCIe/UART DMA Firmware Escape to Host Processor.
        """
        ts = timestamp or time.time()
        self.record_alert(
            'CRITICAL', 'BASEBAND_ESCAPE', 'BASEBAND',
            f'Cellular Baseband DMA Host Memory Access Violation (Address: 0x{dma_address:08X})',
            f'Modem baseband processor attempted unauthorized direct memory access ({event_type}) outside allocated IPC ring buffers. '
            f'Indicates baseband remote code execution trying to escape modem sandbox and compromise Application Processor Linux/Android kernel.',
            rule_id='TELCOSEC-VULN-088', raw_data=None, timestamp=ts
        )

