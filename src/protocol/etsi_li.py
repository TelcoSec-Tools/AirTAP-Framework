#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - ETSI TS 102 232 & 3GPP TS 33.108 / TS 33.128 Protocol Dissector
    ========================================================================
    Full parser and security decoder for Lawful Interception Handover Interfaces
    (HI2 / HI3) and Service-Based Interception Interfaces (X1, X2, X3).

    Standards Supported:
      - ETSI TS 102 232-1 (General IP PDU / PS-PDU Specification)
      - ETSI TS 102 232-3 (IP Access), Part 5 (IP Multimedia), Part 7 (Mobile 3G/4G/5G)
      - 3GPP TS 33.108 (3G/4G Lawful Interception Handover Interface)
      - 3GPP TS 33.128 (5G Service-Based Architecture X1/X2/X3 Interfaces)
"""

import struct
import datetime
import json
from typing import Dict, Any, Optional, Tuple, List

# Standard ASN.1 OIDs for ETSI LI and 3GPP LI
OID_MAP = {
    '0.4.0.2.2.3.2': 'ETSI TS 102 232 (General IP Delivery)',
    '0.4.0.2.2.3.2.1': 'ETSI TS 102 232-1 (PS-PDU Header)',
    '0.4.0.2.2.3.2.2': 'ETSI TS 102 232-2 (Email / Messaging)',
    '0.4.0.2.2.3.2.3': 'ETSI TS 102 232-3 (IP Access Network)',
    '0.4.0.2.2.3.2.4': 'ETSI TS 102 232-4 (L2 Services)',
    '0.4.0.2.2.3.2.5': 'ETSI TS 102 232-5 (IP Multimedia / SIP / VoLTE)',
    '0.4.0.2.2.3.2.7': 'ETSI TS 102 232-7 (3G/4G/5G Mobile Services)',
    '0.4.0.1.6.7.1': 'ETSI TS 101 671 (HI2/HI3 Handover)',
    '1.3.12.2.1010.5.2': '3GPP TS 33.108 (3GPP Handover Interface)',
}

DIRECTION_MAP = {
    0: 'fromTarget (Uplink / Sent by Target)',
    1: 'toTarget (Downlink / Delivered to Target)',
    2: 'combined (Bidirectional Stream)',
    3: 'notAvailable / Undetermined',
}

PDU_TYPE_MAP = {
    1: 'IRI (Intercept Related Information / Signaling)',
    2: 'CC (Content of Communication / User Payload)',
    3: 'HI1 (Administrative Notification)',
}

INNER_PROTO_MAP = {
    0x01: 'IPv4 (Internet Protocol v4)',
    0x02: 'IPv6 (Internet Protocol v6)',
    0x03: 'Ethernet (L2 Frame)',
    0x04: 'SIP Signaling (RFC 3261)',
    0x05: 'RTP Media Stream (Voice / Audio)',
    0x06: 'Email / SMTP / IMAP',
    0x07: 'SMS / MAP Message',
    0x08: 'RADIUS / Diameter AAA',
    0x09: 'GTP-U Encapsulated PDU',
}


class EtsiLiPsPduParser:
    """
    Parser for ETSI TS 102 232-1 PS-PDU and 3GPP TS 33.108 / TS 33.128 Packets.
    Decodes both ASN.1 BER encapsulated streams and compact binary framing.
    """

    @staticmethod
    def parse_ps_pdu(raw_bytes: bytes, is_encrypted_transport: bool = False) -> Dict[str, Any]:
        """
        Dissects a raw packet buffer into a structured ETSI TS 102 232 PS-PDU representation.
        """
        if not raw_bytes or len(raw_bytes) < 4:
            return {'status': 'error', 'error': 'Buffer too short for PS-PDU'}

        res: Dict[str, Any] = {
            'status': 'ok',
            'standard': 'ETSI TS 102 232 / 3GPP TS 33.108',
            'is_asn1_ber': False,
            'is_encrypted_transport': is_encrypted_transport,
            'version': 1,
            'pdu_type': 'IRI',
            'pdu_type_id': 1,
            'liid': 'UNKNOWN',
            'operator_id': 'UNKNOWN',
            'cin': 0,
            'cin_hex': '0x0',
            'seq_num': 0,
            'direction': 'notAvailable / Undetermined',
            'direction_id': 3,
            'timestamp': '',
            'timestamp_epoch': 0.0,
            'inner_proto': 'Unknown',
            'inner_proto_id': 0,
            'payload_length': 0,
            'inner_payload_hex': '',
            'inner_payload_ascii': '',
            'target_identifiers': {},
            'security_flags': []
        }

        first_byte = raw_bytes[0]

        # Case 1: ASN.1 BER Encapsulation (0x30 SEQUENCE)
        if first_byte == 0x30:
            res['is_asn1_ber'] = True
            EtsiLiPsPduParser._decode_ber_ps_pdu(raw_bytes, res)
        # Case 2: Binary Compact Framing (AirTap / CALEA Diag Stream Format)
        else:
            EtsiLiPsPduParser._decode_compact_binary(raw_bytes, res)

        # Security posture evaluation
        if not is_encrypted_transport:
            res['security_flags'].append('PLAINTEXT_TRANSMISSION')

        if res['seq_num'] == 0:
            res['security_flags'].append('ZERO_SEQUENCE_COUNTER')

        return res

    @staticmethod
    def _decode_ber_ps_pdu(raw: bytes, res: Dict[str, Any]):
        """Decodes ASN.1 BER Tag-Length-Value hierarchy for PS-PDU."""
        idx = 0
        total_len = len(raw)

        # Outer SEQUENCE tag 0x30
        idx += 1
        seq_len, len_bytes = EtsiLiPsPduParser._parse_ber_length(raw, idx)
        idx += len_bytes

        # Look for headers and tagged elements inside PSHeader [1] and Payload [2]
        while idx < total_len - 2:
            tag = raw[idx]
            tag_len, len_b = EtsiLiPsPduParser._parse_ber_length(raw, idx + 1)
            content_start = idx + 1 + len_b
            content_end = min(total_len, content_start + tag_len)
            chunk = raw[content_start:content_end]

            # Tag 0xA1: PSHeader
            if tag == 0xA1:
                EtsiLiPsPduParser._decode_ber_ps_header(chunk, res)
            # Tag 0xA2: Payload (IRI or CC)
            elif tag == 0xA2:
                res['payload_length'] = len(chunk)
                res['inner_payload_hex'] = chunk.hex()
                res['inner_payload_ascii'] = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk[:256])
                # Guess inner protocol
                if len(chunk) >= 20 and (chunk[0] >> 4) == 4:
                    res['inner_proto'] = 'IPv4'
                    res['inner_proto_id'] = 0x01
                elif len(chunk) >= 40 and (chunk[0] >> 4) == 6:
                    res['inner_proto'] = 'IPv6'
                    res['inner_proto_id'] = 0x02
                elif b'SIP/2.0' in chunk or b'INVITE sip:' in chunk or b'REGISTER sip:' in chunk:
                    res['inner_proto'] = 'SIP'
                    res['inner_proto_id'] = 0x04
                elif b'GTP' in chunk or (len(chunk) > 8 and chunk[0] == 0x30 and chunk[1] == 0xFF):
                    res['inner_proto'] = 'GTP-U'
                    res['inner_proto_id'] = 0x09
            # Tag 0x81: Direct LIID OCTET STRING
            elif tag == 0x81:
                try:
                    res['liid'] = chunk.decode('latin1', errors='replace').strip()
                except Exception:
                    res['liid'] = chunk.hex()
            # Tag 0x84: Sequence Number INTEGER
            elif tag == 0x84 or tag == 0x02:
                if len(chunk) == 4:
                    res['seq_num'] = struct.unpack('>I', chunk)[0]
                elif len(chunk) == 2:
                    res['seq_num'] = struct.unpack('>H', chunk)[0]
                elif len(chunk) == 1:
                    res['seq_num'] = chunk[0]

            idx = content_end

        if not res['timestamp']:
            now = datetime.datetime.utcnow()
            res['timestamp'] = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + 'Z'
            res['timestamp_epoch'] = now.timestamp()

    @staticmethod
    def _decode_ber_ps_header(hdr_bytes: bytes, res: Dict[str, Any]):
        """Parses elements within PSHeader."""
        idx = 0
        hdr_len = len(hdr_bytes)

        while idx < hdr_len - 2:
            tag = hdr_bytes[idx]
            tag_len, len_b = EtsiLiPsPduParser._parse_ber_length(hdr_bytes, idx + 1)
            c_start = idx + 1 + len_b
            c_end = min(hdr_len, c_start + tag_len)
            c_data = hdr_bytes[c_start:c_end]

            # Tag 0x81: lawfulInterceptionIdentifier
            if tag == 0x81:
                try:
                    res['liid'] = c_data.decode('latin1', errors='replace').strip()
                except Exception:
                    res['liid'] = c_data.hex()
            # Tag 0x84 / 0x02: sequenceNumber
            elif tag == 0x84 or tag == 0x02:
                if len(c_data) == 4:
                    res['seq_num'] = struct.unpack('>I', c_data)[0]
                elif len(c_data) == 2:
                    res['seq_num'] = struct.unpack('>H', c_data)[0]
            # Tag 0x85 / 0x18: GeneralizedTime (ISO timestamp)
            elif tag == 0x85 or tag == 0x18:
                try:
                    res['timestamp'] = c_data.decode('latin1', errors='replace').strip()
                except Exception:
                    pass
            # Tag 0x89 / 0x0A: pS-PDU-direction ENUMERATED
            elif tag == 0x89 or tag == 0x0A:
                dir_val = c_data[0] if c_data else 3
                res['direction_id'] = dir_val
                res['direction'] = DIRECTION_MAP.get(dir_val, 'notAvailable / Undetermined')
            # Tag 0xA3: communicationIdentifier (CIN)
            elif tag == 0xA3:
                if len(c_data) >= 4:
                    cin_int = struct.unpack('>I', c_data[-4:])[0]
                    res['cin'] = cin_int
                    res['cin_hex'] = f"0x{cin_int:08X}"

            idx = c_end

    @staticmethod
    def _decode_compact_binary(raw: bytes, res: Dict[str, Any]):
        """Decodes binary packed CALEA / Qualcomm Diag LI log framing."""
        if len(raw) < 16:
            return

        version = raw[0]
        pdu_type_id = raw[1]
        res['version'] = version
        res['pdu_type_id'] = pdu_type_id
        res['pdu_type'] = PDU_TYPE_MAP.get(pdu_type_id, 'IRI')

        direction_id = raw[2]
        res['direction_id'] = direction_id
        res['direction'] = DIRECTION_MAP.get(direction_id, 'notAvailable / Undetermined')

        inner_proto_id = raw[3]
        res['inner_proto_id'] = inner_proto_id
        res['inner_proto'] = INNER_PROTO_MAP.get(inner_proto_id, f'Proto_0x{inner_proto_id:02X}')

        # CIN (4B) and Sequence Number (4B)
        cin, seq_num = struct.unpack('>II', raw[4:12])
        res['cin'] = cin
        res['cin_hex'] = f"0x{cin:08X}"
        res['seq_num'] = seq_num

        # Payload offset
        payload_bytes = raw[16:]
        res['payload_length'] = len(payload_bytes)
        res['inner_payload_hex'] = payload_bytes.hex()
        res['inner_payload_ascii'] = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload_bytes[:256])

        # Generate LIID from CIN
        res['liid'] = f"CALEA-TARGET-{cin:08X}"
        now = datetime.datetime.utcnow()
        res['timestamp'] = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + 'Z'
        res['timestamp_epoch'] = now.timestamp()

    @staticmethod
    def _parse_ber_length(data: bytes, offset: int) -> Tuple[int, int]:
        """Parses single-byte and multi-byte ASN.1 BER length fields."""
        if offset >= len(data):
            return 0, 1

        b0 = data[offset]
        if (b0 & 0x80) == 0:
            return b0, 1

        num_len_bytes = b0 & 0x7F
        if num_len_bytes == 0:
            return 0, 1  # Indefinite length
        if offset + 1 + num_len_bytes > len(data):
            return 0, 1

        val = 0
        for i in range(num_len_bytes):
            val = (val << 8) | data[offset + 1 + i]

        return val, 1 + num_len_bytes


class X1ProvisioningParser:
    """
    Parser for 3GPP TS 33.128 X1 Interface (ADMF -> POI / MDF)
    Decodes target activation, modification, and deactivation JSON/REST payloads.
    """

    @staticmethod
    def parse_x1_request(json_text: str) -> Dict[str, Any]:
        """Parses an X1 JSON target provisioning request."""
        try:
            doc = json.loads(json_text)
        except Exception as e:
            return {'status': 'error', 'error': f"Invalid X1 JSON schema: {e}"}

        req = doc.get('x1RequestMessage', doc)
        task = req.get('taskDetails', {})

        target_ids = []
        for t in task.get('targetIdentifiers', []):
            if 'supi' in t: target_ids.append(f"SUPI: {t['supi']}")
            if 'imsi' in t: target_ids.append(f"IMSI: {t['imsi']}")
            if 'guti' in t: target_ids.append(f"5G-GUTI: {t['guti']}")
            if 'pei' in t: target_ids.append(f"PEI / IMEI: {t['pei']}")
            if 'msisdn' in t: target_ids.append(f"MSISDN: {t['msisdn']}")

        return {
            'status': 'ok',
            'interface': '3GPP TS 33.128 X1',
            'admf_id': req.get('admfIdentifier', 'ADMF_UNKNOWN'),
            'request_id': req.get('requestIdentifier', 'REQ_0'),
            'xid': task.get('xId', 'XID_0'),
            'delivery_type': task.get('deliveryType', 'X2andX3'),
            'target_identifiers': target_ids,
            'delivery_destinations': task.get('deliveryAddresses', {})
        }
