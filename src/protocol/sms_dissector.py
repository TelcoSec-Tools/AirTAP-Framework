#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP 3GPP Short Message Service (SMS) Protocol Dissector
=========================================================
Standards-compliant dissector for:
- 3GPP TS 24.011: Point-to-Point (PP) Short Message Service (CP / RP Layer)
- 3GPP TS 23.040: Technical Realization of the Short Message Service (SMS-TPDU)
- 3GPP TS 23.038: Alphabets and language-specific information (7-bit GSM, UCS-2, 8-bit)
"""

import struct
from typing import Dict, Any, Optional, Tuple

# Standard 7-bit GSM 03.38 Default Alphabet Character Map
GSM_7BIT_ALPHABET = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ`¿abcdefghijklmnopqrstuvwxyzäöñüà"
)

GSM_7BIT_EXTENDED = {
    0x0A: "\x0C",  # Form Feed
    0x14: "^",
    0x28: "{",
    0x29: "}",
    0x2F: "\\",
    0x3C: "[",
    0x3D: "~",
    0x3E: "]",
    0x40: "|",
    0x65: "€",
}


def decode_semi_octet_bcd(data: bytes) -> str:
    """Decodes 3GPP semi-octet BCD encoded number (e.g. phone numbers, IMSI)."""
    digits = []
    for b in data:
        low = b & 0x0F
        high = (b >> 4) & 0x0F
        if low <= 9:
            digits.append(str(low))
        elif low == 0x0A:
            digits.append('*')
        elif low == 0x0B:
            digits.append('#')
        elif low == 0x0C:
            digits.append('a')
        elif low == 0x0D:
            digits.append('b')
        elif low == 0x0E:
            digits.append('c')
        # 0x0F is filler

        if high <= 9:
            digits.append(str(high))
        elif high == 0x0A:
            digits.append('*')
        elif high == 0x0B:
            digits.append('#')
        elif high == 0x0C:
            digits.append('a')
        elif high == 0x0D:
            digits.append('b')
        elif high == 0x0E:
            digits.append('c')
        # 0x0F is filler
    return "".join(digits)


def decode_address_field(data: bytes, offset: int = 0) -> Tuple[Optional[str], int]:
    """
    Decodes 3GPP TS 23.040 Address-Field (TP-DA, TP-OA, SMSC Address).
    Returns (formatted_number, bytes_consumed).
    """
    if offset >= len(data):
        return None, 0

    addr_len = data[offset]
    if addr_len == 0:
        return "", 1

    ton_npi = data[offset + 1] if offset + 1 < len(data) else 0x81
    ton = (ton_npi >> 4) & 0x07
    is_international = (ton == 1)

    byte_count = (addr_len + 1) // 2
    raw_digits = data[offset + 2 : offset + 2 + byte_count]

    decoded = decode_semi_octet_bcd(raw_digits)[:addr_len]
    if is_international and decoded and not decoded.startswith('+'):
        decoded = '+' + decoded

    return decoded, 2 + byte_count


def decode_gsm_7bit_packed(data: bytes, septet_count: int, bit_offset: int = 0) -> str:
    """Unpacks 7-bit packed GSM alphabet into a UTF-8 string."""
    chars = []
    bit_buf = 0
    bits_in_buf = 0
    byte_idx = 0
    extended_escape = False

    if bit_offset > 0 and data:
        bit_buf = data[0] >> bit_offset
        bits_in_buf = 8 - bit_offset
        byte_idx = 1

    for _ in range(septet_count):
        while bits_in_buf < 7:
            if byte_idx < len(data):
                bit_buf |= (data[byte_idx] << bits_in_buf)
                bits_in_buf += 8
                byte_idx += 1
            else:
                break

        if bits_in_buf < 7:
            break

        septet = bit_buf & 0x7F
        bit_buf >>= 7
        bits_in_buf -= 7

        if septet == 0x1B:
            extended_escape = True
            continue

        if extended_escape:
            char = GSM_7BIT_EXTENDED.get(septet, GSM_7BIT_ALPHABET[septet] if septet < len(GSM_7BIT_ALPHABET) else '?')
            extended_escape = False
        else:
            char = GSM_7BIT_ALPHABET[septet] if septet < len(GSM_7BIT_ALPHABET) else '?'
        chars.append(char)

    return "".join(chars)


def decode_timestamp(data: bytes) -> str:
    """Decodes 3GPP TS 23.040 TP-Service-Centre-Time-Stamp (7 semi-octets: YYMMDDhhmmss±tz)."""
    if len(data) < 7:
        return ""
    digits = decode_semi_octet_bcd(data[:7])
    if len(digits) >= 12:
        yy, mm, dd = digits[0:2], digits[2:4], digits[4:6]
        hh, mi, ss = digits[6:8], digits[8:10], digits[10:12]
        year = int(yy) + (2000 if int(yy) < 70 else 1900)
        return f"{year:04d}-{mm}-{dd} {hh}:{mi}:{ss}"
    return digits


class SmsDissector:
    """Comprehensive 3GPP SMS Protocol Dissector."""

    @staticmethod
    def dissect_tpdu(tpdu: bytes, direction: str = 'MT') -> Dict[str, Any]:
        """
        Dissects a raw 3GPP TS 23.040 SMS-TPDU.
        direction: 'MT' (Mobile Terminated / SMS-DELIVER) or 'MO' (Mobile Originated / SMS-SUBMIT)
        """
        if not tpdu or len(tpdu) < 1:
            return {'status': 'error', 'error': 'Empty TPDU'}

        first_octet = tpdu[0]
        tp_mti = first_octet & 0x03
        tp_mms = bool(first_octet & 0x04)
        tp_vpf = (first_octet >> 3) & 0x03
        tp_srr = bool(first_octet & 0x20)
        tp_udhi = bool(first_octet & 0x40)
        tp_rp = bool(first_octet & 0x80)

        result = {
            'mti': tp_mti,
            'direction': direction,
            'udhi': tp_udhi,
            'rp': tp_rp,
            'srr': tp_srr,
            'type_name': 'UNKNOWN',
            'sender': None,
            'recipient': None,
            'smsc': None,
            'pid': 0x00,
            'is_silent_type0': False,
            'is_flash_class0': False,
            'is_sim_ota': False,
            'encoding': '7-bit GSM',
            'timestamp': '',
            'message_text': '',
            'user_data_hex': '',
            'tar': None
        }

        offset = 1

        if tp_mti == 0:  # SMS-DELIVER (Inbound to phone)
            result['type_name'] = 'SMS-DELIVER (Inbound MT)'
            sender, consumed = decode_address_field(tpdu, offset)
            result['sender'] = sender
            offset += consumed

            if offset < len(tpdu):
                result['pid'] = tpdu[offset]
                if result['pid'] == 0x40:
                    result['is_silent_type0'] = True
                    result['type_name'] = 'Silent SMS Type 0 (Location Ping)'
                elif result['pid'] == 0x7F:
                    result['is_sim_ota'] = True
                    result['type_name'] = 'SMS-PP Data Download (SIM OTA)'
                offset += 1

            dcs = tpdu[offset] if offset < len(tpdu) else 0
            offset += 1

            if offset + 7 <= len(tpdu):
                result['timestamp'] = decode_timestamp(tpdu[offset:offset + 7])
                offset += 7

        elif tp_mti == 1:  # SMS-SUBMIT (Outbound from phone)
            result['type_name'] = 'SMS-SUBMIT (Outbound MO)'
            mr = tpdu[offset] if offset < len(tpdu) else 0
            offset += 1

            recipient, consumed = decode_address_field(tpdu, offset)
            result['recipient'] = recipient
            offset += consumed

            if offset < len(tpdu):
                result['pid'] = tpdu[offset]
                if result['pid'] == 0x40:
                    result['is_silent_type0'] = True
                elif result['pid'] == 0x7F:
                    result['is_sim_ota'] = True
                offset += 1

            dcs = tpdu[offset] if offset < len(tpdu) else 0
            offset += 1

            if tp_vpf == 2:
                offset += 1
            elif tp_vpf == 1 or tp_vpf == 3:
                offset += 7

        elif tp_mti == 2:
            result['type_name'] = 'SMS-STATUS-REPORT'
            mr = tpdu[offset] if offset < len(tpdu) else 0
            offset += 1
            recipient, consumed = decode_address_field(tpdu, offset)
            result['recipient'] = recipient
            offset += consumed
            if offset + 7 <= len(tpdu):
                result['timestamp'] = decode_timestamp(tpdu[offset:offset + 7])
                offset += 7
            dcs = 0
        else:
            dcs = 0

        alphabet = (dcs >> 2) & 0x03
        msg_class = dcs & 0x03
        is_class_defined = bool(dcs & 0x10)

        if is_class_defined and msg_class == 0:
            result['is_flash_class0'] = True
            result['type_name'] += ' [Class 0 Flash SMS]'

        if (dcs & 0xC0) == 0:
            if alphabet == 0:
                result['encoding'] = '7-bit GSM'
            elif alphabet == 1:
                result['encoding'] = '8-bit Binary'
            elif alphabet == 2:
                result['encoding'] = 'UCS-2 (Unicode 16-bit)'
        elif (dcs & 0xF0) == 0xF0:
            result['encoding'] = '8-bit Binary' if (dcs & 0x04) else '7-bit GSM'

        if offset < len(tpdu):
            udl = tpdu[offset]
            offset += 1
            user_data = tpdu[offset:]
            result['user_data_hex'] = user_data.hex().upper()

            ud_offset = 0
            if tp_udhi and user_data:
                udhl = user_data[0]
                udh = user_data[1 : 1 + udhl]
                ud_offset = 1 + udhl

                if len(udh) >= 4 and udh[0] == 0x70:
                    result['tar'] = udh[2:5].hex().upper()
                    result['is_sim_ota'] = True

            actual_text_data = user_data[ud_offset:]

            if result['encoding'] == '7-bit GSM':
                septet_count = udl - (int(ud_offset * 8 / 7) if tp_udhi else 0)
                bit_offset = (7 - ((ud_offset * 8) % 7)) % 7 if tp_udhi else 0
                result['message_text'] = decode_gsm_7bit_packed(actual_text_data, max(0, septet_count), bit_offset)
            elif result['encoding'] == 'UCS-2 (Unicode 16-bit)':
                try:
                    result['message_text'] = actual_text_data.decode('utf-16-be', errors='replace')
                except Exception:
                    result['message_text'] = actual_text_data.decode('latin-1', errors='replace')
            else:
                try:
                    result['message_text'] = actual_text_data.decode('utf-8', errors='replace')
                except Exception:
                    result['message_text'] = f"// Binary Data ({len(actual_text_data)} bytes): {actual_text_data.hex().upper()}"

        return result

    @staticmethod
    def dissect_nas_sms(payload: bytes, direction: str = 'MT') -> Dict[str, Any]:
        """
        Dissects a 3GPP TS 24.011 NAS CP/RP Short Message frame.
        Handles CP-DATA -> RP-DATA -> SMS-TPDU hierarchy.
        """
        if not payload or len(payload) < 2:
            return {'status': 'error', 'error': 'Invalid SMS Frame'}

        # Look for CP-DATA / RP-DATA user data
        if len(payload) > 3:
            for i in range(len(payload) - 4):
                if payload[i] in (0x00, 0x01) and payload[i + 1] <= 0xFF:
                    rp_offset = i + 2
                    if rp_offset < len(payload):
                        orig_len = payload[rp_offset]
                        rp_offset += 1 + orig_len
                        if rp_offset < len(payload):
                            dest_len = payload[rp_offset]
                            rp_offset += 1 + dest_len
                            if rp_offset + 1 < len(payload):
                                rp_udl = payload[rp_offset]
                                tpdu_bytes = payload[rp_offset + 1 : rp_offset + 1 + rp_udl]
                                if tpdu_bytes:
                                    dissected = SmsDissector.dissect_tpdu(tpdu_bytes, direction)
                                    dissected['raw_nas_hex'] = payload.hex().upper()
                                    return dissected

        dissected = SmsDissector.dissect_tpdu(payload, direction)
        dissected['raw_nas_hex'] = payload.hex().upper()
        return dissected
