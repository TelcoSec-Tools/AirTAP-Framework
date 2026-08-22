#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP Unit Tests: Subscriber Identities, SMS Interceptor & OTA Management
==========================================================================
Tests for:
- 3GPP SMS-TPDU & 7-bit / UCS-2 / Silent Type 0 decoding
- 3GPP Mobile Identity (IMSI, IMEI, TMSI, GUTI, SUCI, 5G-S-TMSI, MSISDN)
- Real-time IdentitySmsOtaTracker engine & REST endpoints
"""

import unittest
import time
from src.protocol.sms_dissector import SmsDissector, decode_gsm_7bit_packed, decode_semi_octet_bcd
from src.protocol.identity_dissector import IdentityDissector
from src.modules.identity_tracker import IdentitySmsOtaTracker
from src.protocol.log_types import *


class TestSmsDissector(unittest.TestCase):
    """Tests for 3GPP TS 23.040 & TS 24.011 SMS Protocol Dissector."""

    def test_semi_octet_bcd(self):
        # 0x21 0x43 0x65 -> "123456"
        raw = bytes([0x21, 0x43, 0x65])
        self.assertEqual(decode_semi_octet_bcd(raw), "123456")

    def test_gsm_7bit_packed_decoding(self):
        # "Hello!" packed in 7-bit GSM (6 septets)
        text = decode_gsm_7bit_packed(bytes.fromhex("C8329BFD0E01"), 6)
        self.assertEqual(text, "Hello!")

    def test_sms_deliver_7bit(self):
        # Standard SMS-DELIVER: sender +14155550199, text "Hello"
        tpdu = bytes.fromhex("040B914151550591F900002090313162040005C8329BFD0E")
        res = SmsDissector.dissect_tpdu(tpdu, 'MT')
        self.assertEqual(res['type_name'], 'SMS-DELIVER (Inbound MT)')
        self.assertIn('+14155550199', res['sender'])
        self.assertFalse(res['is_silent_type0'])
        self.assertEqual(res['message_text'], 'Hello')

    def test_silent_sms_type0_detection(self):
        # Silent SMS: TP-PID = 0x40
        tpdu = bytes.fromhex("040B914151550591F940002090313162040000")
        res = SmsDissector.dissect_tpdu(tpdu, 'MT')
        self.assertTrue(res['is_silent_type0'])
        self.assertIn('Silent SMS Type 0', res['type_name'])

    def test_flash_sms_class0_detection(self):
        # Flash SMS: TP-DCS = 0x10 (Class 0)
        tpdu = bytes.fromhex("040B914151550591F900102090313162040005C8329BFD0E")
        res = SmsDissector.dissect_tpdu(tpdu, 'MT')
        self.assertTrue(res['is_flash_class0'])
        self.assertIn('Class 0 Flash SMS', res['type_name'])

    def test_sms_submit_outbound(self):
        # SMS-SUBMIT: recipient +351912345678 (semi-octet BCD: 53 91 21 43 65 87)
        tpdu = bytes.fromhex("01000C91539121436587000005C8329BFD0E")
        res = SmsDissector.dissect_tpdu(tpdu, 'MO')
        self.assertEqual(res['direction'], 'MO')
        self.assertIn('+351912345678', res['recipient'])


class TestIdentityDissector(unittest.TestCase):
    """Tests for 3GPP Mobile Identity (IMSI, TMSI, GUTI, SUCI, MSISDN)."""

    def test_dissect_imsi(self):
        # Length = 8, Identity Type = 1 (IMSI), Parity = 1 (Odd), Digits = 268011234567890
        # Byte 0 = 0x29 (high nibble 2, low nibble 9)
        # Digits: 2 (byte 0), 6 8 (byte 1: 0x86), 0 1 (byte 2: 0x10), 1 2 (byte 3: 0x21), 3 4 (byte 4: 0x43), 5 6 (byte 5: 0x65), 7 8 (byte 6: 0x87), 9 0 (byte 7: 0x09)
        data = bytes.fromhex("082986102143658709")
        id_res, consumed = IdentityDissector.dissect_mobile_identity(data, 0)
        self.assertIsNotNone(id_res)
        self.assertEqual(id_res['type_name'], 'IMSI')
        self.assertEqual(id_res['value'], '268011234567890')
        self.assertEqual(id_res['details']['mcc'], '268')
        self.assertEqual(id_res['details']['mnc'], '01')

    def test_dissect_tmsi(self):
        # Length = 5, Type = 4 (TMSI), Value = 0x8A4F12C0
        data = bytes.fromhex("05F48A4F12C0")
        id_res, consumed = IdentityDissector.dissect_mobile_identity(data, 0)
        self.assertIsNotNone(id_res)
        self.assertEqual(id_res['type_name'], 'TMSI')
        self.assertEqual(id_res['value'], '0x8A4F12C0')

    def test_dissect_4g_guti(self):
        # Length = 11, Type = 6 (GUTI), MCC=310, MNC=410, MMEGI=0x8001, MMEC=0x01, M-TMSI=0x12345678
        data = bytes.fromhex("0Bf613001480010112345678")
        id_res, consumed = IdentityDissector.dissect_mobile_identity(data, 0)
        self.assertIsNotNone(id_res)
        self.assertEqual(id_res['type_name'], 'GUTI')
        self.assertIn('310-410', id_res['value'])
        self.assertEqual(id_res['details']['m_tmsi'], '0x12345678')

    def test_dissect_5g_s_tmsi(self):
        # 5GS Mobile Identity: Type = 4 (5G-S-TMSI), AMF Set = 0x1A2, AMF Ptr = 0x03, 5G-TMSI = 0x87654321
        data = bytes.fromhex("000704068387654321")
        id_res, consumed = IdentityDissector.dissect_5g_mobile_identity(data, 0)
        self.assertIsNotNone(id_res)
        self.assertEqual(id_res['type_name'], '5G-S-TMSI')
        self.assertEqual(id_res['details']['5g_tmsi'], '0x87654321')

    def test_dissect_usim_msisdn(self):
        # EF_MSISDN (Alpha tag + length + TON/NPI + BCD phone number)
        # "My Number" (9 bytes) + Len 0x07 + TON 0x91 (+) + 351912345678 (53 91 21 43 65 87)
        raw = b"My Number" + bytes([0x07, 0x91]) + bytes.fromhex("539121436587")
        msisdn = IdentityDissector.dissect_usim_msisdn(raw)
        self.assertIsNotNone(msisdn)
        self.assertEqual(msisdn, "+351912345678")


class TestIdentitySmsOtaTracker(unittest.TestCase):
    """Tests for IdentitySmsOtaTracker real-time indexing & correlation."""

    def setUp(self):
        self.tracker = IdentitySmsOtaTracker()

    def test_record_and_retrieve_identity(self):
        self.tracker.record_identity('IMSI', '268011234567890', 'IMSI: 268011234567890', '4G', 'INBOUND', {}, time.time())
        self.tracker.record_identity('TMSI', '0x8A4F12C0', 'TMSI: 0x8A4F12C0', '4G', 'INBOUND', {}, time.time())
        
        id_list = self.tracker.get_identities_list()
        self.assertEqual(len(id_list), 2)
        types = [x['type'] for x in id_list]
        self.assertIn('IMSI', types)
        self.assertIn('TMSI', types)

    def test_record_and_retrieve_sms(self):
        sms_data = {
            'type_name': 'SMS-DELIVER (Inbound MT)',
            'sender': '+351912345678',
            'recipient': '+351919876543',
            'message_text': 'Security test OTP: 849201',
            'is_silent_type0': False,
            'is_flash_class0': False,
            'is_sim_ota': False
        }
        self.tracker.record_sms(sms_data, '4G', time.time())
        
        sms_list = self.tracker.get_sms_list()
        self.assertEqual(len(sms_list), 1)
        self.assertEqual(sms_list[0]['sender'], '+351912345678')
        self.assertEqual(sms_list[0]['message'], 'Security test OTP: 849201')

        # Check that sender MSISDN was also indexed as an identity
        id_list = self.tracker.get_identities_list()
        msisdns = [x['value'] for x in id_list if x['type'] == 'MSISDN']
        self.assertIn('+351912345678', msisdns)

    def test_record_and_retrieve_ota_event(self):
        self.tracker.record_ota_event('SEND SHORT MESSAGE (SIMjacker)', 'USIM Proactive', bytes.fromhex("D0120102"), 'HIGH', time.time())
        ota_list = self.tracker.get_ota_list()
        self.assertEqual(len(ota_list), 1)
        self.assertIn('SIMjacker', ota_list[0]['command'])
        self.assertEqual(ota_list[0]['threat_level'], 'HIGH')


if __name__ == '__main__':
    unittest.main()
