#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP 3GPP Subscriber Identity Dissector (IMSI, TMSI, GUTI, MSISDN, IMEI, SUCI)
================================================================================
Standards-compliant parser for:
- 3GPP TS 24.008 § 10.5.1.4: Mobile Identity (IMSI, IMEI, IMEISV, TMSI, P-TMSI)
- 3GPP TS 24.301 § 9.9.3.12: EPS Mobile Identity (GUTI, IMSI, IMEI, M-TMSI)
- 3GPP TS 24.501 § 9.11.3.4: 5GS Mobile Identity (5G-GUTI, SUCI, SUPI, 5G-S-TMSI)
- 3GPP TS 31.102 § 4.2.2 & 4.2.26: USIM EF_IMSI & EF_MSISDN
"""

import struct
from typing import Dict, Any, Optional, List, Tuple
from .sms_dissector import decode_semi_octet_bcd


class IdentityDissector:
    """Dissects 3GPP Mobile & Subscriber Identity Information Elements."""

    @staticmethod
    def dissect_mobile_identity(data: bytes, offset: int = 0) -> Tuple[Optional[Dict[str, Any]], int]:
        """
        Dissects a 3GPP TS 24.008 / TS 24.301 Mobile Identity IE.
        Returns (identity_dict, bytes_consumed).
        """
        if offset >= len(data):
            return None, 0

        ie_len = data[offset]
        if ie_len == 0 or offset + 1 + ie_len > len(data):
            return None, 1

        raw_id = data[offset + 1 : offset + 1 + ie_len]
        if not raw_id:
            return None, 1 + ie_len

        type_of_id = raw_id[0] & 0x07
        odd_even = bool(raw_id[0] & 0x08)

        res = {
            'type_code': type_of_id,
            'type_name': 'UNKNOWN',
            'value': '',
            'formatted': '',
            'raw_hex': raw_id.hex().upper(),
            'details': {}
        }

        # 1. IMSI (Type 0x01)
        if type_of_id == 1:
            res['type_name'] = 'IMSI'
            digits = []
            # First digit is high nibble of byte 0
            d1 = (raw_id[0] >> 4) & 0x0F
            if d1 <= 9:
                digits.append(str(d1))
            for b in raw_id[1:]:
                low = b & 0x0F
                high = (b >> 4) & 0x0F
                if low <= 9:
                    digits.append(str(low))
                if high <= 9:
                    digits.append(str(high))
            imsi_str = "".join(digits)
            res['value'] = imsi_str
            res['formatted'] = f"IMSI: {imsi_str}"
            if len(imsi_str) >= 5:
                mcc = imsi_str[:3]
                mnc_len = 3 if mcc.startswith(('302', '310', '311', '312', '313', '314', '315', '316', '334', '732')) else 2
                res['details']['mcc'] = mcc
                res['details']['mnc'] = imsi_str[3:3 + mnc_len]
                res['details']['msin'] = imsi_str[3 + mnc_len:]

        # 2. IMEI (Type 0x02)
        elif type_of_id == 2:
            res['type_name'] = 'IMEI'
            digits = []
            d1 = (raw_id[0] >> 4) & 0x0F
            if d1 <= 9:
                digits.append(str(d1))
            for b in raw_id[1:]:
                low = b & 0x0F
                high = (b >> 4) & 0x0F
                if low <= 9:
                    digits.append(str(low))
                if high <= 9:
                    digits.append(str(high))
            imei_str = "".join(digits)[:15]
            res['value'] = imei_str
            res['formatted'] = f"IMEI: {imei_str}"

        # 3. IMEISV (Type 0x03)
        elif type_of_id == 3:
            res['type_name'] = 'IMEISV'
            digits = []
            d1 = (raw_id[0] >> 4) & 0x0F
            if d1 <= 9:
                digits.append(str(d1))
            for b in raw_id[1:]:
                low = b & 0x0F
                high = (b >> 4) & 0x0F
                if low <= 9:
                    digits.append(str(low))
                if high <= 9:
                    digits.append(str(high))
            imeisv_str = "".join(digits)[:16]
            res['value'] = imeisv_str
            res['formatted'] = f"IMEISV: {imeisv_str}"

        # 4. TMSI / P-TMSI / M-TMSI (Type 0x04)
        elif type_of_id == 4:
            res['type_name'] = 'TMSI'
            tmsi_bytes = raw_id[1:5] if len(raw_id) >= 5 else raw_id[1:]
            tmsi_hex = tmsi_bytes.hex().upper()
            tmsi_int = int.from_bytes(tmsi_bytes, byteorder='big') if tmsi_bytes else 0
            res['value'] = f"0x{tmsi_hex}"
            res['formatted'] = f"TMSI: 0x{tmsi_hex} ({tmsi_int})"
            res['details']['tmsi_dec'] = tmsi_int

        # 5. EPS GUTI (Type 0x06 in 4G)
        elif type_of_id == 6 and len(raw_id) >= 11:
            res['type_name'] = 'GUTI'
            # MCC & MNC
            mcc1 = raw_id[1] & 0x0F
            mcc2 = (raw_id[1] >> 4) & 0x0F
            mcc3 = raw_id[2] & 0x0F
            mnc3 = (raw_id[2] >> 4) & 0x0F
            mnc1 = raw_id[3] & 0x0F
            mnc2 = (raw_id[3] >> 4) & 0x0F
            mcc = f"{mcc1}{mcc2}{mcc3}"
            mnc = f"{mnc1}{mnc2}" + (f"{mnc3}" if mnc3 != 0x0F else "")

            mmegi = int.from_bytes(raw_id[4:6], byteorder='big')
            mmec = raw_id[6]
            m_tmsi = raw_id[7:11].hex().upper()
            m_tmsi_int = int.from_bytes(raw_id[7:11], byteorder='big')

            res['value'] = f"{mcc}-{mnc}-{mmegi:04X}-{mmec:02X}-{m_tmsi}"
            res['formatted'] = f"GUTI: {mcc}-{mnc} MMEGI:0x{mmegi:04X} MMEC:0x{mmec:02X} M-TMSI:0x{m_tmsi}"
            res['details'] = {
                'mcc': mcc,
                'mnc': mnc,
                'mmegi': f"0x{mmegi:04X}",
                'mmec': f"0x{mmec:02X}",
                'm_tmsi': f"0x{m_tmsi}",
                'm_tmsi_dec': m_tmsi_int
            }

        return res, 1 + ie_len

    @staticmethod
    def dissect_5g_mobile_identity(data: bytes, offset: int = 0) -> Tuple[Optional[Dict[str, Any]], int]:
        """
        Dissects a 3GPP TS 24.501 § 9.11.3.4 5GS Mobile Identity IE.
        """
        if offset >= len(data):
            return None, 0

        ie_len = int.from_bytes(data[offset:offset + 2], byteorder='big') if offset + 2 <= len(data) else 0
        if ie_len == 0 or offset + 2 + ie_len > len(data):
            return None, 2

        raw_id = data[offset + 2 : offset + 2 + ie_len]
        if not raw_id:
            return None, 2 + ie_len

        type_of_id = raw_id[0] & 0x07

        res = {
            'type_code': type_of_id,
            'type_name': 'UNKNOWN',
            'value': '',
            'formatted': '',
            'raw_hex': raw_id.hex().upper(),
            'details': {}
        }

        # 1. SUCI (Type 0x01 in 5G)
        if type_of_id == 1:
            res['type_name'] = '5G-SUCI'
            mcc1 = raw_id[1] & 0x0F
            mcc2 = (raw_id[1] >> 4) & 0x0F
            mcc3 = raw_id[2] & 0x0F
            mnc3 = (raw_id[2] >> 4) & 0x0F
            mnc1 = raw_id[3] & 0x0F
            mnc2 = (raw_id[3] >> 4) & 0x0F
            mcc = f"{mcc1}{mcc2}{mcc3}"
            mnc = f"{mnc1}{mnc2}" + (f"{mnc3}" if mnc3 != 0x0F else "")

            scheme = (raw_id[6] >> 4) & 0x0F if len(raw_id) > 6 else 0
            scheme_name = {0: "Null-Scheme (Cleartext SUPI / IMSI)", 1: "Profile A (Curve25519)", 2: "Profile B (secp256r1)"}.get(scheme, f"Scheme {scheme}")

            res['value'] = f"suci-0-{mcc}-{mnc}-{raw_id[4:].hex().upper()}"
            res['formatted'] = f"5G SUCI ({scheme_name}) PLMN: {mcc}-{mnc}"
            res['details'] = {'mcc': mcc, 'mnc': mnc, 'scheme': scheme_name, 'is_null_scheme': (scheme == 0)}

        # 2. 5G-GUTI (Type 0x02 in 5G)
        elif type_of_id == 2 and len(raw_id) >= 11:
            res['type_name'] = '5G-GUTI'
            mcc1 = raw_id[1] & 0x0F
            mcc2 = (raw_id[1] >> 4) & 0x0F
            mcc3 = raw_id[2] & 0x0F
            mnc3 = (raw_id[2] >> 4) & 0x0F
            mnc1 = raw_id[3] & 0x0F
            mnc2 = (raw_id[3] >> 4) & 0x0F
            mcc = f"{mcc1}{mcc2}{mcc3}"
            mnc = f"{mnc1}{mnc2}" + (f"{mnc3}" if mnc3 != 0x0F else "")

            amf_region = raw_id[4]
            amf_set = ((raw_id[5] << 2) | ((raw_id[6] >> 6) & 0x03))
            amf_ptr = raw_id[6] & 0x3F
            tmsi_5g = raw_id[7:11].hex().upper()

            res['value'] = f"{mcc}-{mnc}-{amf_region:02X}-{amf_set:03X}-{amf_ptr:02X}-{tmsi_5g}"
            res['formatted'] = f"5G-GUTI: {mcc}-{mnc} AMF:0x{amf_region:02X}.{amf_set:03X} 5G-TMSI:0x{tmsi_5g}"
            res['details'] = {
                'mcc': mcc,
                'mnc': mnc,
                'amf_region': f"0x{amf_region:02X}",
                'amf_set': f"0x{amf_set:03X}",
                '5g_tmsi': f"0x{tmsi_5g}"
            }

        # 4. 5G-S-TMSI (Type 0x04 in 5G)
        elif type_of_id == 4 and len(raw_id) >= 6:
            res['type_name'] = '5G-S-TMSI'
            amf_set = ((raw_id[1] << 2) | ((raw_id[2] >> 6) & 0x03))
            amf_ptr = raw_id[2] & 0x3F
            tmsi_5g = raw_id[3:7].hex().upper() if len(raw_id) >= 7 else raw_id[3:].hex().upper()
            res['value'] = f"0x{amf_set:03X}-{amf_ptr:02X}-{tmsi_5g}"
            res['formatted'] = f"5G-S-TMSI: AMF-Set:0x{amf_set:03X} 5G-TMSI:0x{tmsi_5g}"
            res['details'] = {'amf_set': f"0x{amf_set:03X}", '5g_tmsi': f"0x{tmsi_5g}"}

        return res, 2 + ie_len

    @staticmethod
    def dissect_usim_msisdn(ef_data: bytes) -> Optional[str]:
        """
        Decodes USIM EF_MSISDN (3GPP TS 31.102 § 4.2.26).
        Format: Alpha Identifier (X bytes) + Length of BCD (1 byte) + TON/NPI (1 byte) + Dialling Number (BCD).
        """
        if not ef_data or len(ef_data) < 14:
            return None

        # Search for TON/NPI & BCD length byte
        for i in range(len(ef_data) - 4):
            bcd_len = ef_data[i]
            if 2 <= bcd_len <= 11 and (i + 1 + bcd_len) <= len(ef_data):
                ton_npi = ef_data[i + 1]
                if (ton_npi & 0x80):  # Valid TON/NPI bit
                    ton = (ton_npi >> 4) & 0x07
                    digits = decode_semi_octet_bcd(ef_data[i + 2 : i + 1 + bcd_len])
                    if digits and len(digits) >= 4:
                        return ('+' if ton == 1 else '') + digits
        return None

    @staticmethod
    def dissect_usim_imsi(ef_data: bytes) -> Optional[str]:
        """
        Decodes USIM EF_IMSI (3GPP TS 31.102 § 4.2.2).
        Format: Length of IMSI (1 byte) + parity/digits (8 bytes).
        """
        if not ef_data or len(ef_data) < 9:
            return None

        imsi_len = ef_data[0]
        if 5 <= imsi_len <= 8:
            digits = []
            d1 = (ef_data[1] >> 4) & 0x0F
            if d1 <= 9:
                digits.append(str(d1))
            for b in ef_data[2 : 1 + imsi_len]:
                low = b & 0x0F
                high = (b >> 4) & 0x0F
                if low <= 9:
                    digits.append(str(low))
                if high <= 9:
                    digits.append(str(high))
            return "".join(digits)
        return None
