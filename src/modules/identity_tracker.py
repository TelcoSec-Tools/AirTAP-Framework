#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP Real-Time Subscriber Identity, SMS & OTA Management Tracker
===================================================================
Orchestrates live capture, indexing, correlation, and alerting for:
- TMSI / M-TMSI / 5G-S-TMSI temporary radio identifiers
- IMSI / SUPI / SUCI permanent subscriber identifiers
- MSISDN subscriber dialing numbers (from SMS, SIM, SIP)
- SMS messages (Inbound MT, Outbound MO, Type 0 Silent Pings, Flash SMS)
- OTA SIM Remote Management (RFM / RAM) & Proactive STK Commands
"""

import time
from datetime import datetime
from collections import deque
from typing import Dict, Any, List, Optional
import threading

from ..protocol.log_types import *
from ..protocol.sms_dissector import SmsDissector
from ..protocol.identity_dissector import IdentityDissector


class IdentitySmsOtaTracker:
    """Real-time subscriber identity, SMS, and OTA management engine."""

    def __init__(self, server_instance=None):
        self.server = server_instance
        self.lock = threading.Lock()

        # In-memory storage collections
        self.identities: Dict[str, Dict[str, Any]] = {}  # Key: "TYPE:VALUE"
        self.sms_history = deque(maxlen=1000)
        self.ota_events = deque(maxlen=1000)

        self._sms_id_counter = 0
        self._ota_id_counter = 0
        self._id_counter = 0

    def process_log(self, log_code: int, log_payload: bytes, timestamp: float = None):
        """Dispatches an incoming Qualcomm Diag log to relevant extractors."""
        if not log_payload:
            return

        ts = timestamp or time.time()

        try:
            # 1. 4G LTE NAS (0xB0E0, 0xB0E1, 0xB0E2, 0xB0E3)
            if log_code in (
                LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
                LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
                LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
                LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C
            ):
                is_outbound = log_code in (LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C, LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C)
                direction = 'OUTBOUND (MO)' if is_outbound else 'INBOUND (MT)'
                self._extract_lte_nas(log_payload, direction, ts)

            # 2. 5G NR NAS (0xB800, 0xB801, 0xB802, 0xB803)
            elif log_code in (
                LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
                LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
                LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
                LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C
            ):
                is_outbound = log_code in (LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C, LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C)
                direction = 'OUTBOUND (MO)' if is_outbound else 'INBOUND (MT)'
                self._extract_5g_nas(log_payload, direction, ts)

            # 3. 2G / 3G NAS (0x512F, 0x713A)
            elif log_code in (LOG_GSM_RR_SIGNALING_MESSAGE_C, LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C):
                self._extract_legacy_nas(log_payload, ts)

            # 4. SIM / UICC APDU & STK (0x1188)
            elif log_code == LOG_SIM_APDU_LOG_C:
                self._extract_sim_apdu(log_payload, ts)

            # 5. LTE RRC (0xB0C0) / 5G RRC (0xB821) for Paging & RRC Setup identities
            elif log_code in (LOG_LTE_RRC_OTA_MSG_LOG_C, LOG_NR_RRC_OTA_MSG_LOG_C):
                rat = '5G' if log_code == LOG_NR_RRC_OTA_MSG_LOG_C else '4G'
                self._extract_rrc_identities(log_payload, rat, ts)

        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Extraction Helpers
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_lte_nas(self, payload: bytes, direction: str, ts: float):
        nas_pdu = payload[4:] if len(payload) > 4 else payload
        if len(nas_pdu) < 2:
            return

        proto_disc = nas_pdu[0] & 0x0F
        sec_hdr = (nas_pdu[0] >> 4) & 0x0F
        offset = 6 if sec_hdr in (1, 2, 3, 4) and len(nas_pdu) >= 6 else 1

        if offset >= len(nas_pdu):
            return

        # Check for SMS transport (Protocol Discriminator 0x09 = SMS)
        if proto_disc == 0x09 or (len(nas_pdu) > offset and (nas_pdu[offset] & 0x0F) == 0x09):
            sms_data = SmsDissector.dissect_nas_sms(nas_pdu[offset:], 'MO' if 'OUTBOUND' in direction else 'MT')
            if sms_data and sms_data.get('type_name') != 'UNKNOWN':
                self.record_sms(sms_data, '4G', ts)

        # Check for EMM Message Types
        if len(nas_pdu) > offset:
            msg_type = nas_pdu[offset]

            # 1. Attach Request (0x41) / TAU Request (0x48)
            if msg_type in (0x41, 0x48):
                # EPS Mobile Identity follows security header & type
                id_res, _ = IdentityDissector.dissect_mobile_identity(nas_pdu, offset + 2)
                if id_res:
                    self.record_identity(id_res['type_name'], id_res['value'], id_res['formatted'], '4G', direction, id_res['details'], ts)

            # 2. Attach Accept (0x42) / GUTI Reallocation Command (0x4D) / TAU Accept (0x49)
            elif msg_type in (0x42, 0x4D, 0x49):
                # Scan for GUTI (IEI 0x50) or assigned M-TMSI
                for i in range(offset + 1, len(nas_pdu) - 11):
                    if nas_pdu[i] == 0x50 and nas_pdu[i + 1] == 11:
                        id_res, _ = IdentityDissector.dissect_mobile_identity(nas_pdu, i + 1)
                        if id_res:
                            self.record_identity('GUTI', id_res['value'], id_res['formatted'], '4G', direction, id_res['details'], ts)
                            if 'm_tmsi' in id_res['details']:
                                self.record_identity('M-TMSI', id_res['details']['m_tmsi'], f"M-TMSI: {id_res['details']['m_tmsi']}", '4G', direction, {}, ts)
                            break

            # 3. Identity Response (0x56)
            elif msg_type == 0x56:
                id_res, _ = IdentityDissector.dissect_mobile_identity(nas_pdu, offset + 1)
                if id_res:
                    self.record_identity(id_res['type_name'], id_res['value'], id_res['formatted'], '4G', direction, id_res['details'], ts)

    def _extract_5g_nas(self, payload: bytes, direction: str, ts: float):
        nas_pdu = payload[4:] if len(payload) > 4 else payload
        if len(nas_pdu) < 2:
            return

        sec_hdr = (nas_pdu[0] >> 4) & 0x0F
        offset = 6 if sec_hdr in (1, 2, 3, 4) and len(nas_pdu) >= 6 else 1

        if offset >= len(nas_pdu):
            return

        # Check for 5G SMS transport
        proto_disc = nas_pdu[0] & 0x0F
        if proto_disc == 0x09 or (len(nas_pdu) > offset and (nas_pdu[offset] & 0x0F) == 0x09):
            sms_data = SmsDissector.dissect_nas_sms(nas_pdu[offset:], 'MO' if 'OUTBOUND' in direction else 'MT')
            if sms_data and sms_data.get('type_name') != 'UNKNOWN':
                self.record_sms(sms_data, '5G', ts)

        if len(nas_pdu) > offset:
            msg_type = nas_pdu[offset]

            # 1. 5GS Registration Request (0x41) / Identity Response (0x5C)
            if msg_type in (0x41, 0x5C):
                id_res, _ = IdentityDissector.dissect_5g_mobile_identity(nas_pdu, offset + 2)
                if id_res:
                    self.record_identity(id_res['type_name'], id_res['value'], id_res['formatted'], '5G', direction, id_res['details'], ts)

            # 2. 5GS Registration Accept (0x42) / Configuration Update Command (0x67)
            elif msg_type in (0x42, 0x67):
                # Search for 5G-GUTI (IEI 0x77)
                for i in range(offset + 1, len(nas_pdu) - 13):
                    if nas_pdu[i] == 0x77 and nas_pdu[i + 1] == 0x00 and nas_pdu[i + 2] >= 11:
                        id_res, _ = IdentityDissector.dissect_5g_mobile_identity(nas_pdu, i + 1)
                        if id_res:
                            self.record_identity('5G-GUTI', id_res['value'], id_res['formatted'], '5G', direction, id_res['details'], ts)
                            if '5g_tmsi' in id_res['details']:
                                self.record_identity('5G-S-TMSI', id_res['details']['5g_tmsi'], f"5G-S-TMSI: {id_res['details']['5g_tmsi']}", '5G', direction, {}, ts)
                            break

    def _extract_legacy_nas(self, payload: bytes, ts: float):
        # Scan for Location Updating Accept / TMSI Reallocation / Identity Response
        if len(payload) < 8:
            return

        for i in range(len(payload) - 5):
            # Location Updating Accept (0x02) carrying TMSI (IEI 0x17)
            if payload[i] == 0x17 and i + 5 <= len(payload):
                tmsi_hex = payload[i + 1 : i + 5].hex().upper()
                if tmsi_hex != 'FFFFFFFF':
                    self.record_identity('TMSI', f"0x{tmsi_hex}", f"2G/3G TMSI: 0x{tmsi_hex}", '2G/3G', 'INBOUND (MT)', {}, ts)

    def _extract_sim_apdu(self, payload: bytes, ts: float):
        if len(payload) < 10:
            return

        # Check for EF_IMSI read response (0x6F07)
        imsi_str = IdentityDissector.dissect_usim_imsi(payload)
        if imsi_str:
            self.record_identity('IMSI', imsi_str, f"USIM Permanent IMSI: {imsi_str}", 'SIM/UICC', 'LOCAL (SIM)', {}, ts)

        # Check for EF_MSISDN read response (0x6F40)
        msisdn_str = IdentityDissector.dissect_usim_msisdn(payload)
        if msisdn_str:
            self.record_identity('MSISDN', msisdn_str, f"USIM Phone Number (MSISDN): {msisdn_str}", 'SIM/UICC', 'LOCAL (SIM)', {}, ts)

        # Check for Proactive STK Command (Tag 0xD0 or proactive indicator)
        if b'\xD0' in payload[:8]:
            idx = payload.find(b'\xD0')
            if idx != -1 and idx + 4 < len(payload):
                cmd_tag = payload[idx + 3]
                stk_names = {
                    0x13: "SEND SHORT MESSAGE (SIMjacker Vector)",
                    0x26: "PROVIDE LOCAL INFORMATION (Covert Tracking)",
                    0x10: "SET UP CALL (Unauthorized Call Setup)",
                    0x40: "OPEN CHANNEL (BIP / WIBjacker Data Pipe)",
                    0x21: "DISPLAY TEXT (Phishing Overlay)",
                    0x01: "REFRESH (SIM File Reset)"
                }
                cmd_name = stk_names.get(cmd_tag, f"STK Command 0x{cmd_tag:02X}")
                self.record_ota_event(cmd_name, "UICC Proactive Command", payload[idx:], "HIGH" if cmd_tag in (0x13, 0x40, 0x10) else "MEDIUM", ts)

    def _extract_rrc_identities(self, payload: bytes, rat: str, ts: float):
        rrc_raw = payload[4:] if len(payload) > 4 else payload
        if len(rrc_raw) < 8:
            return

        # Paging identity scans (e.g. S-TMSI in PagingRecord or RRCConnectionRequest)
        if len(rrc_raw) >= 6 and rrc_raw[0] in (0x00, 0x40, 0x80):
            # Check for 40-bit or 32-bit S-TMSI signature
            for i in range(min(12, len(rrc_raw) - 5)):
                candidate = rrc_raw[i : i + 4]
                tmsi_val = candidate.hex().upper()
                if tmsi_val not in ('00000000', 'FFFFFFFF'):
                    # Probable S-TMSI in RRC Connection / Paging
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # Recording & WebSocket Dispatch
    # ─────────────────────────────────────────────────────────────────────────
    def record_identity(self, id_type: str, value: str, formatted: str, rat: str, direction: str, details: dict, ts: float):
        if not value or value in ('—', '0x00000000', '0xFFFFFFFF'):
            return

        key = f"{id_type.upper()}:{value}"
        time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        with self.lock:
            if key in self.identities:
                item = self.identities[key]
                item['last_seen'] = time_str
                item['seen_count'] += 1
                item['rat'] = rat or item['rat']
            else:
                self._id_counter += 1
                item = {
                    'id': self._id_counter,
                    'type': id_type.upper(),
                    'value': value,
                    'formatted': formatted or f"{id_type}: {value}",
                    'rat': rat,
                    'direction': direction,
                    'first_seen': time_str,
                    'last_seen': time_str,
                    'seen_count': 1,
                    'details': details or {}
                }
                self.identities[key] = item

        if self.server:
            self.server.broadcast('identity_event', item)

    def record_sms(self, sms_data: dict, rat: str, ts: float):
        self._sms_id_counter += 1
        time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        record = {
            'id': self._sms_id_counter,
            'timestamp': sms_data.get('timestamp') or time_str,
            'direction': sms_data.get('direction', 'MT'),
            'type': sms_data.get('type_name', 'SMS-DELIVER'),
            'sender': sms_data.get('sender') or 'Unknown Sender',
            'recipient': sms_data.get('recipient') or 'Local Subscriber',
            'smsc': sms_data.get('smsc') or '—',
            'encoding': sms_data.get('encoding', '7-bit GSM'),
            'message': sms_data.get('message_text', ''),
            'is_silent': sms_data.get('is_silent_type0', False),
            'is_flash': sms_data.get('is_flash_class0', False),
            'is_sim_ota': sms_data.get('is_sim_ota', False),
            'tar': sms_data.get('tar'),
            'rat': rat,
            'raw_hex': sms_data.get('user_data_hex', '')
        }

        with self.lock:
            self.sms_history.append(record)

        # If it's a phone number, also correlate as MSISDN in identity tracker
        if record['sender'] and record['sender'].startswith('+'):
            self.record_identity('MSISDN', record['sender'], f"Sender MSISDN: {record['sender']}", rat, 'REMOTE', {}, ts)
        if record['recipient'] and record['recipient'].startswith('+'):
            self.record_identity('MSISDN', record['recipient'], f"Recipient MSISDN: {record['recipient']}", rat, 'REMOTE', {}, ts)

        if self.server:
            self.server.broadcast('sms_event', record)

    def record_ota_event(self, command: str, target: str, payload: bytes, threat_level: str, ts: float):
        self._ota_id_counter += 1
        time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        record = {
            'id': self._ota_id_counter,
            'timestamp': time_str,
            'command': command,
            'target': target,
            'threat_level': threat_level,
            'raw_hex': payload.hex().upper() if payload else '',
            'summary': f"{command} on {target}"
        }

        with self.lock:
            self.ota_events.append(record)

        if self.server:
            self.server.broadcast('ota_event', record)

    def get_identities_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return sorted(list(self.identities.values()), key=lambda x: x['seen_count'], reverse=True)

    def get_sms_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.sms_history)

    def get_ota_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.ota_events)
