#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP ASN.1, RRC, LPP, and eCall MSD Protocol Unit Tests
=========================================================
"""

import unittest
import struct
from src.protocol.asn1_uper import BitStream
from src.protocol.rrc_asn1_dissector import RrcAsn1Dissector
from src.protocol.lpp_dissector import LppDissector
from src.protocol.ecall_msd_dissector import EcallMsdDissector
from src.protocol.deep_dissector import DeepDissector

class TestAsn1AndDeepDissectors(unittest.TestCase):

    def test_bitstream_operations(self):
        # 0xA5 = 10100101, 0x3C = 00111100
        raw = bytes([0xA5, 0x3C])
        bs = BitStream(raw)
        
        self.assertEqual(bs.remaining_bits, 16)
        self.assertEqual(bs.read_bit(), 1)
        self.assertEqual(bs.read_bit(), 0)
        self.assertEqual(bs.read_bits(2), 2) # '10' = 2
        self.assertEqual(bs.read_bits(4), 5) # '0101' = 5
        
        # Second byte (0x3C = 00111100), reading 7 bits for range [0..100] gives '0011110' = 30
        self.assertEqual(bs.read_constrained_int(0, 100), 30)

    def test_5g_nr_rrc_sib1_decoding(self):
        # Test 5G NR BCCH SIB1 PDU
        # Choice 0 (c1) -> Choice 0 (sib1) -> has_cell_sel (1) -> q_rx_raw
        # 0x20 = 00100000 (bit0=0, bit1=0, bit2=1 [has_cell_sel])
        raw_sib1 = bytes([0x20, 0x80, 0x1A, 0x4B, 0x00, 0x00])
        res = RrcAsn1Dissector.dissect_5g_nr_bcch(raw_sib1)
        
        self.assertEqual(res['status'], 'ok')
        self.assertIn('5G NR RRC', res['protocol'])
        self.assertIn('SIB1', res['message_type'])
        self.assertIn('q_rx_lev_min_dbm', res['ies'])

    def test_4g_lte_rrc_decoding(self):
        raw_lte = bytes([0x00, 0x10, 0x20, 0x30])
        res = RrcAsn1Dissector.dissect_4g_lte_rrc(raw_lte)
        
        self.assertEqual(res['status'], 'ok')
        self.assertIn('4G LTE RRC', res['protocol'])
        self.assertIn('LTE SIB1', res['summary'])

    def test_cv2x_sidelink_pc5_decoding(self):
        raw_pc5 = bytes([0x12, 0x34, 0x56, 0x78])
        res = RrcAsn1Dissector.dissect_cv2x_sidelink_pc5(raw_pc5)
        
        self.assertEqual(res['status'], 'ok')
        self.assertIn('PC5 Sidelink', res['protocol'])
        self.assertIn('sl-BWP-Config', res['tree'])

    def test_lpp_location_query_dissection(self):
        # Transaction ID 12, endTransaction 0, choice 4 (RequestLocationInformation)
        # Choice 4 in 8 choices is 3 bits: 100 (4)
        raw_lpp = bytes([0x0C, 0x80, 0x40, 0x00])
        res = LppDissector.dissect_lpp_message(raw_lpp)
        
        self.assertEqual(res['status'], 'ok')
        self.assertIn('3GPP LPP', res['protocol'])
        self.assertIn('lpp-MessageBody', res['tree'])

    def test_ecall_msd_dissection(self):
        # 1-byte version (1), 1-byte control (0x01 = automatic crash), 1-byte prop (0x40 = EV), 17-byte VIN, 8-byte lat/lng
        vin = b"VF1ABCDEF12345678"
        raw_lat = int(37.7749 * 3600000)
        raw_lng = int(-122.4194 * 3600000)
        coords = struct.pack('>ii', raw_lat, raw_lng)
        payload = bytes([1, 0x01, 0x40]) + vin + coords

        res = EcallMsdDissector.dissect_msd(payload)
        
        self.assertEqual(res['status'], 'ok')
        self.assertIn('eCall MSD', res['protocol'])
        self.assertIn('AUTOMATIC', res['ies']['activation_mode'])
        self.assertEqual(res['ies']['vin'], "VF1ABCDEF12345678")
        self.assertAlmostEqual(res['ies']['latitude'], 37.7749, places=3)
        self.assertAlmostEqual(res['ies']['longitude'], -122.4194, places=3)

    def test_deep_dissector_integration(self):
        # Test routing via DeepDissector
        res_rrc = DeepDissector.dissect(0xB801, bytes([0x00, 0x80, 0x1A]), rat='5g', protocol='rrc')
        self.assertIn('5G NR RRC', res_rrc.get('protocol', ''))

        res_lpp = DeepDissector.dissect(0xB827, bytes([0x0C, 0x80]), protocol='lpp')
        self.assertIn('3GPP LPP', res_lpp.get('protocol', ''))

        res_ecall = DeepDissector.dissect(0x0, bytes([1, 0x01, 0x40]) + b"WAUZZZ8V1GA123456" + struct.pack('>ii', 0, 0), protocol='ecall')
        self.assertIn('eCall MSD', res_ecall.get('protocol', ''))

if __name__ == '__main__':
    unittest.main()
