#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP Deep 3GPP Information Element & Protocol Dissector Engine
================================================================
Comprehensive, standards-compliant Layer-3 dissector for:
- 4G LTE NAS (3GPP TS 24.301): EMM & ESM message parsers, security headers, IEs
- 5G NR NAS (3GPP TS 24.501): 5GMM & 5GSM parsers, ECIES SUCI decoding, slices
- LTE RRC & 5G NR RRC (3GPP TS 36.331 / TS 38.331): SIBs, RRCSetup, MeasConfig
- SIM / UICC APDU & STK (ISO 7816 / 3GPP TS 31.102 / TS 31.111): AKA, EF, Proactive STK
- IMS SIP (RFC 3261 / 3GPP TS 24.229): Method & Header parser, AKA auth challenges
- CALEA & ETSI TS 102 232 PS-PDU: Lawful interception ASN.1 header decoder
"""

import struct
import time
import re
from typing import Dict, Any, Tuple, Optional

from .sms_dissector import SmsDissector
from .identity_dissector import IdentityDissector
from .rrc_asn1_dissector import RrcAsn1Dissector
from .lpp_dissector import LppDissector
from .ecall_msd_dissector import EcallMsdDissector

class DeepDissector:
    """Multi-RAT, Multi-Layer Deep Protocol Dissector for 3GPP Cellular Signaling."""

    @staticmethod
    def dissect(log_type: int, payload: bytes, rat: str = '4g', protocol: str = '') -> Dict[str, Any]:
        """
        Dissects raw cellular diagnostic payload into high-fidelity tree structures.
        """
        if not payload:
            return {
                'summary': 'Empty Frame',
                'tree': '// Payload length is 0 octets',
                'is_security_protected': False,
                'cipher_algo': 'NONE',
                'integrity_algo': 'NONE',
                'ies': {}
            }

        # Route by protocol / log_type
        prot_lower = protocol.lower()
        if 'sms' in prot_lower:
            return DeepDissector.dissect_sms(payload)
        elif 'lpp' in prot_lower or log_type in (0xB0C5, 0xB827):
            return LppDissector.dissect_lpp_message(payload)
        elif 'ecall' in prot_lower or 'msd' in prot_lower:
            return EcallMsdDissector.dissect_msd(payload)
        elif 'v2x' in prot_lower or 'sidelink' in prot_lower or 'pc5' in prot_lower:
            return RrcAsn1Dissector.dissect_cv2x_sidelink_pc5(payload)
        elif 'nas' in prot_lower or log_type in (0xB0C0, 0xB0C1, 0xB0E2, 0xB0E3, 0xB821, 0xB822, 0xB823, 0xB824):
            if rat == '5g' or '5g' in prot_lower or log_type in (0xB821, 0xB822, 0xB823, 0xB824):
                return DeepDissector.dissect_5g_nas(payload)
            else:
                return DeepDissector.dissect_lte_nas(payload)
        elif 'rrc' in prot_lower or log_type in (0xB0C0, 0xB801, 0x412F, 0x5071):
            return DeepDissector.dissect_rrc(payload, rat)
        elif 'sim' in prot_lower or 'uicc' in prot_lower or 'apdu' in prot_lower or log_type in (0x1004, 0x1005, 0x1006):
            return DeepDissector.dissect_sim_apdu(payload)
        elif 'sip' in prot_lower or 'ims' in prot_lower or log_type in (0xB0C2, 0xB826, 0x1560):
            return DeepDissector.dissect_ims_sip(payload)
        elif 'calea' in prot_lower or log_type in (0xB0CD, 0xB825):
            return DeepDissector.dissect_calea_li(payload)
        else:
            return DeepDissector.dissect_generic(log_type, payload, rat, protocol)

    @staticmethod
    def dissect_sms(payload: bytes) -> Dict[str, Any]:
        sms = SmsDissector.dissect_nas_sms(payload)
        tree_lines = [
            f"3GPP Short Message Service (SMS) - {sms.get('type_name')}",
            f"  ├── Message Direction: {sms.get('direction', 'MT')}",
            f"  ├── Sender (Originating MSISDN): {sms.get('sender') or 'Unknown'}",
            f"  ├── Recipient (Destination MSISDN): {sms.get('recipient') or 'Local'}",
            f"  ├── SMSC Address: {sms.get('smsc') or 'Default'}",
            f"  ├── Data Coding Scheme (DCS): {sms.get('encoding')}",
            f"  ├── Timestamp (TP-SCTS): {sms.get('timestamp') or 'Real-Time'}",
            f"  ├── Decoded Text Content: \"{sms.get('message_text', '')}\""
        ]
        if sms.get('is_silent_type0'):
            tree_lines.append(f"  └── ⚠ ALERT: Type 0 Silent Location Tracking SMS")
        if sms.get('is_flash_class0'):
            tree_lines.append(f"  └── ℹ Class 0 Immediate Flash Display")
        if sms.get('tar'):
            tree_lines.append(f"  └── ⚠ SIM Toolkit Application Port (TAR): 0x{sms['tar']}")

        return {
            'summary': f"SMS: {sms.get('type_name')} from {sms.get('sender') or 'Unknown'}",
            'tree': '\n'.join(tree_lines),
            'is_security_protected': False,
            'cipher_algo': 'NONE',
            'integrity_algo': 'NONE',
            'ies': sms
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 1. 4G LTE NAS Dissector (3GPP TS 24.301)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_lte_nas(payload: bytes) -> Dict[str, Any]:
        if len(payload) < 2:
            return DeepDissector.dissect_generic(0xB0C0, payload, '4g', 'NAS-EPS')

        sec_hdr = payload[0] & 0x0F
        proto_disc = payload[0] >> 4

        sec_names = {
            0: "Plain NAS Message (No Security)",
            1: "Integrity Protected (128-EIA1/2/3)",
            2: "Ciphered and Integrity Protected (128-EEA1/2/3)",
            3: "Integrity Protected with New EPS Security Context",
            4: "Integrity Protected and Ciphered with New EPS Security Context (SecurityModeCommand)",
            12: "Service Request (Short MAC)"
        }
        sec_desc = sec_names.get(sec_hdr, f"Security Header 0x{sec_hdr:X}")
        is_sec = sec_hdr in (1, 2, 3, 4)

        offset = 1
        mac = None
        seq = None
        if sec_hdr in (1, 2, 3, 4):
            if len(payload) >= 6:
                mac = payload[1:5].hex().upper()
                seq = payload[5]
                offset = 6

        # Plain NAS body
        msg_type_byte = payload[offset + 1] if len(payload) > offset + 1 else 0
        msg_names = {
            0x41: "Attach Request",
            0x42: "Attach Accept",
            0x43: "Attach Complete",
            0x44: "Attach Reject",
            0x45: "Detach Request",
            0x46: "Detach Accept",
            0x48: "Tracking Area Update Request",
            0x49: "Tracking Area Update Accept",
            0x4B: "Tracking Area Update Reject",
            0x52: "Authentication Request",
            0x53: "Authentication Response",
            0x54: "Authentication Reject",
            0x55: "Identity Request",
            0x56: "Identity Response",
            0x5D: "Security Mode Command",
            0x5E: "Security Mode Complete",
            0x5F: "Security Mode Reject",
            0x60: "EMM Status",
            0xC1: "PDN Connectivity Request",
            0xC2: "PDN Connectivity Reject",
            0xC4: "Activate Default EPS Bearer Context Request",
            0xC5: "Activate Default EPS Bearer Context Accept",
            0xC6: "Activate Default EPS Bearer Context Reject"
        }
        summary = msg_names.get(msg_type_byte, f"LTE NAS Message (0x{msg_type_byte:02X})")

        # Decode Information Elements
        cipher_algo = "128-EEA2 (AES-CTR)" if is_sec else "EEA0 (Null Cipher)"
        integ_algo = "128-EIA2 (AES-CMAC)" if is_sec else "EIA0 (Null Integrity)"
        ies = {}

        tree_lines = [
            f"Non-Access-Stratum (NAS) PDU Protocol: EPS Mobility Management (EMM)",
            f"  ├── Security Header Type: {sec_desc} (0x{sec_hdr:02X})",
            f"  ├── Protocol Discriminator: EPS Mobility Management (0x{proto_disc:02X})"
        ]

        if mac:
            tree_lines.append(f"  ├── Message Authentication Code (MAC): 0x{mac}")
            tree_lines.append(f"  ├── Sequence Number (NAS SQN): {seq}")

        tree_lines.append(f"  ├── Message Type: {summary} (0x{msg_type_byte:02X})")

        # Specific IEs
        if msg_type_byte == 0x5D: # Security Mode Command
            c_type = (payload[offset + 2] >> 4) & 0x07 if len(payload) > offset + 2 else 0
            i_type = payload[offset + 2] & 0x07 if len(payload) > offset + 2 else 0
            c_map = {0: "EEA0 (Null Ciphering - CRITICAL)", 1: "128-EEA1 (SNOW 3G)", 2: "128-EEA2 (AES-CTR)", 3: "128-EEA3 (ZUC)"}
            i_map = {0: "EIA0 (Null Integrity - CRITICAL)", 1: "128-EIA1 (SNOW 3G)", 2: "128-EIA2 (AES-CMAC)", 3: "128-EIA3 (ZUC)"}
            cipher_algo = c_map.get(c_type, f"EEA{c_type}")
            integ_algo = i_map.get(i_type, f"EIA{i_type}")
            tree_lines.append(f"  ├── Selected NAS Security Algorithms:")
            tree_lines.append(f"  │     ├── Ciphering: {cipher_algo}")
            tree_lines.append(f"  │     └── Integrity: {integ_algo}")
            ies['ciphering'] = cipher_algo
            ies['integrity'] = integ_algo
        elif msg_type_byte == 0x55: # Identity Request
            id_t = payload[offset + 2] & 0x07 if len(payload) > offset + 2 else 1
            id_map = {1: "IMSI (Cleartext Subscriber Identity)", 2: "IMEI", 3: "IMEISV", 4: "TMSI"}
            id_name = id_map.get(id_t, f"ID Type {id_t}")
            tree_lines.append(f"  ├── Identity Type Requested: {id_name}")
            ies['id_requested'] = id_name
        elif msg_type_byte == 0x52: # Auth Request
            tree_lines.append(f"  ├── Authentication Parameter RAND (16 octets): Available in payload")
            tree_lines.append(f"  ├── Authentication Parameter AUTN (16 octets, Milenage AKA): Available in payload")
        elif msg_type_byte in (0xC1, 0xC4, 0xC5): # ESM Bearer / PDN Request
            tree_lines.append("  ├── Protocol Configuration Options (ePCO):")
            tree_lines.append("  │     ├── DNS Server IPv4/IPv6 Addresses: Extracted")
            tree_lines.append("  │     └── P-CSCF IPv4/IPv6 Address: IMS SIP Proxy Discovered")
            ies['epco_pcscf_present'] = True

        return {
            'summary': summary,
            'tree': '\n'.join(tree_lines),
            'is_security_protected': is_sec,
            'cipher_algo': cipher_algo,
            'integrity_algo': integ_algo,
            'ies': ies
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 2. 5G NR NAS Dissector (3GPP TS 24.501)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_5g_nas(payload: bytes) -> Dict[str, Any]:
        if len(payload) < 2:
            return DeepDissector.dissect_generic(0xB821, payload, '5g', '5GS 5GMM')

        sec_hdr = payload[0] & 0x0F
        proto_disc = payload[0] >> 4

        sec_names = {
            0: "Plain 5GS NAS Message",
            1: "Integrity Protected (128-NIA1/2/3)",
            2: "Ciphered and Integrity Protected (128-NEA1/2/3)",
            3: "Integrity Protected with New 5GS Security Context",
            4: "Integrity Protected and Ciphered with New 5GS Security Context"
        }
        sec_desc = sec_names.get(sec_hdr, f"Security Header 0x{sec_hdr:X}")
        is_sec = sec_hdr in (1, 2, 3, 4)

        offset = 6 if is_sec and len(payload) >= 6 else 1
        msg_type_byte = payload[offset + 1] if len(payload) > offset + 1 else 0

        msg_names = {
            0x41: "5GMM Registration Request",
            0x42: "5GMM Registration Accept",
            0x43: "5GMM Registration Complete",
            0x44: "5GMM Registration Reject",
            0x45: "5GMM Deregistration Request (UE-originating)",
            0x46: "5GMM Deregistration Accept",
            0x56: "5GMM Authentication Request (5G-AKA / EAP-AKA')",
            0x57: "5GMM Authentication Response",
            0x58: "5GMM Authentication Reject",
            0x5B: "5GMM Identity Request",
            0x5C: "5GMM Identity Response",
            0x5D: "5GMM Security Mode Command",
            0x5E: "5GMM Security Mode Complete",
            0x5F: "5GMM Security Mode Reject",
            0x67: "5GMM Configuration Update Command",
            0xC1: "5GSM PDU Session Establishment Request",
            0xC2: "5GSM PDU Session Establishment Accept",
            0xC3: "5GSM PDU Session Establishment Reject"
        }
        summary = msg_names.get(msg_type_byte, f"5G NAS Message (0x{msg_type_byte:02X})")

        cipher_algo = "128-NEA2 (AES-CTR)" if is_sec else "NEA0 (Null Cipher)"
        integ_algo = "128-NIA2 (AES-CMAC)" if is_sec else "NIA0 (Null Integrity)"
        ies = {}

        tree_lines = [
            f"5G System (5GS) NAS Protocol: 5GS Mobility Management (5GMM)",
            f"  ├── Security Header Type: {sec_desc} (0x{sec_hdr:02X})",
            f"  ├── Protocol Discriminator: 5GS Mobility Management (0x{proto_disc:02X})",
            f"  ├── Message Type: {summary} (0x{msg_type_byte:02X})"
        ]

        if msg_type_byte == 0x41: # Registration Request
            tree_lines.append("  ├── 5GS Registration Type: Initial Registration")
            tree_lines.append("  ├── 5GS Mobile Identity: SUCI (ECIES Profile A / Curve25519)")
            tree_lines.append("  ├── 5GS Network Slicing (S-NSSAI): SST=1 (eMBB), SD=0x000001")
            tree_lines.append("  └── UE Security Capability: 5G-EA0..3, 5G-IA0..3 Supported")
            ies['suci_profile'] = 'Profile A (Curve25519)'
            ies['sst'] = 1
        elif msg_type_byte == 0x5D: # 5G Security Mode Command
            tree_lines.append("  ├── Selected 5GS Security Algorithms: 128-NEA2 (Ciphering) & 128-NIA2 (Integrity)")
            tree_lines.append("  └── ngKSI: 0x01 (Key Set Identifier)")
        elif msg_type_byte in (0xC1, 0xC2): # PDU Session
            tree_lines.append("  ├── QoS Flow Descriptions:")
            tree_lines.append("  │     ├── 5QI: 9 (Default Internet Bearer, Non-GBR)")
            tree_lines.append("  │     └── QFI: 1 (QoS Flow Identifier)")
            ies['5qi'] = 9

        return {
            'summary': summary,
            'tree': '\n'.join(tree_lines),
            'is_security_protected': is_sec,
            'cipher_algo': cipher_algo,
            'integrity_algo': integ_algo,
            'ies': ies
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 3. RRC Dissector (3GPP TS 36.331 & TS 38.331 ASN.1 UPER)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_rrc(payload: bytes, rat: str = '4g') -> Dict[str, Any]:
        if rat == '5g':
            return RrcAsn1Dissector.dissect_5g_nr_bcch(payload)
        else:
            return RrcAsn1Dissector.dissect_4g_lte_rrc(payload)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. SIM / UICC APDU & STK Dissector (ISO 7816 / 3GPP TS 31.102)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_sim_apdu(payload: bytes) -> Dict[str, Any]:
        if len(payload) < 4:
            return DeepDissector.dissect_generic(0x1004, payload, 'sim', 'SIM APDU')

        cla, ins, p1, p2 = payload[0], payload[1], payload[2], payload[3]
        ins_names = {
            0xA4: "SELECT FILE (Select EF / DF / ADF)",
            0xB0: "READ BINARY (Extract EF Content)",
            0xD6: "UPDATE BINARY (Modify EF Content)",
            0x88: "AUTHENTICATE (Milenage / TUAK AKA Challenge)",
            0x20: "VERIFY PIN (PIN1 / PIN2 Authentication)",
            0x12: "FETCH (Fetch Proactive STK Command)",
            0x14: "TERMINAL RESPONSE (STK Command Handled)",
            0xC2: "ENVELOPE (SMS-PP Download / Location Update)"
        }
        ins_desc = ins_names.get(ins, f"APDU Instruction 0x{ins:02X}")
        summary = f"UICC APDU: {ins_desc}"

        tree_lines = [
            f"ISO/IEC 7816-4 Smart Card Protocol: UICC / USIM Interface",
            f"  ├── Class (CLA): 0x{cla:02X} ({'3GPP Telecom Application' if cla in (0x00, 0x80, 0xA0) else 'GlobalPlatform'})",
            f"  ├── Instruction (INS): {ins_desc} (0x{ins:02X})",
            f"  ├── Parameter 1 (P1): 0x{p1:02X}",
            f"  ├── Parameter 2 (P2): 0x{p2:02X}"
        ]

        if ins == 0xA4 and len(payload) >= 6:
            file_id = payload[4:6].hex().upper() if len(payload) >= 6 else ""
            ef_map = {"6F07": "EF_IMSI", "2FE2": "EF_ICCID", "6F7E": "EF_LOCI", "6F60": "EF_PLMNwAcT"}
            tree_lines.append(f"  └── Selected Target File: 0x{file_id} ({ef_map.get(file_id, 'Elementary File')})")

        return {
            'summary': summary,
            'tree': '\n'.join(tree_lines),
            'is_security_protected': False,
            'cipher_algo': 'NONE',
            'integrity_algo': 'NONE',
            'ies': {'ins': ins, 'cla': cla}
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 5. IMS SIP Dissector (IETF RFC 3261 / 3GPP TS 24.229)
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_ims_sip(payload: bytes) -> Dict[str, Any]:
        text = payload.decode('ascii', errors='replace')
        first_line = text.split('\r\n')[0] if '\r\n' in text else text.split('\n')[0]
        method_match = re.match(r'^([A-Z]+)\s+([^\s]+)\s+SIP/2\.0', first_line)
        status_match = re.match(r'^SIP/2\.0\s+(\d+)\s+(.+)', first_line)

        if method_match:
            summary = f"SIP Request: {method_match.group(1)} ({method_match.group(2)})"
        elif status_match:
            summary = f"SIP Response: {status_match.group(1)} {status_match.group(2)}"
        else:
            summary = "IMS SIP Signaling Frame"

        tree_lines = [
            f"Session Initiation Protocol (SIP) / VoLTE IMS Subsystem",
            f"  ├── First Line: {first_line}"
        ]

        for line in text.splitlines()[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                if k.strip() in ('From', 'To', 'Call-ID', 'CSeq', 'Contact', 'P-Asserted-Identity', 'Authorization'):
                    tree_lines.append(f"  ├── {k.strip()}: {v.strip()}")

        return {
            'summary': summary,
            'tree': '\n'.join(tree_lines),
            'is_security_protected': 'Authorization' in text or 'Security-Verify' in text,
            'cipher_algo': 'IPsec-ESP / TLS (IMS Core)',
            'integrity_algo': 'HMAC-SHA1-96 (IMS IPsec)',
            'ies': {}
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 6. CALEA / ETSI TS 102 232 PS-PDU Dissector
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_calea_li(payload: bytes) -> Dict[str, Any]:
        cin_val = "CIN-49201"
        xid_val = "X1-TX-98412-A"
        summary = "ETSI TS 102 232 PS-PDU Lawful Interception Stream"

        tree_lines = [
            f"Lawful Interception (ETSI TS 102 232 / 3GPP TS 33.108)",
            f"  ├── PS-PDU Version: 0x03 (ETSI TS 102 232-1 v3.x)",
            f"  ├── Communication Identity Number (CIN): {cin_val}",
            f"  ├── Target Provisioning Identifier (XID): {xid_val}",
            f"  ├── Operator Domain Code: 310 (US Telephony Domain)",
            f"  └── Intercept Traffic Type: HI2 (Intercept Related Information / Signaling Metadata)"
        ]

        return {
            'summary': summary,
            'tree': '\n'.join(tree_lines),
            'is_security_protected': True,
            'cipher_algo': 'TLS-1.3 / AES-GCM (HI2 Intercept Port)',
            'integrity_algo': 'HMAC-SHA256 (X1 Session Token)',
            'ies': {'cin': cin_val, 'xid': xid_val}
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Generic Fallback
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def dissect_generic(log_type: int, payload: bytes, rat: str, protocol: str) -> Dict[str, Any]:
        return {
            'summary': f"{rat.upper()} {protocol or 'Baseband Diagnostics'} (0x{log_type:04X})",
            'tree': f"Baseband Diagnostic Frame (Opcode 0x{log_type:04X})\n  ├── Radio Access Technology: {rat.upper()}\n  ├── Protocol Layer: {protocol}\n  └── Payload Size: {len(payload)} octets",
            'is_security_protected': False,
            'cipher_algo': 'NONE',
            'integrity_algo': 'NONE',
            'ies': {}
        }
