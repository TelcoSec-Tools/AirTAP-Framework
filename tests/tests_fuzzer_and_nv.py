#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP Protocol Fuzzer & NV Item Manager Unit Tests
==================================================
"""

import unittest
from src.modules.protocol_fuzzer import ProtocolFuzzerEngine, SIGNALING_TEMPLATES
from src.modules.nv_manager import NvManager, NV_STATUS_DONE

class MockDiagInput:
    def __init__(self):
        self.sent_frames = []

    def send_raw_pdu(self, raw_bytes: bytes):
        self.sent_frames.append(raw_bytes)
        return b"\x06" # ACK

    def send_recv(self, opcode, payload, accept_error=True):
        # Return success with 128-byte zero buffer and status 0
        return opcode, payload[:2] + b"\x00" * 128 + b"\x00\x00"

class TestProtocolFuzzerAndNv(unittest.TestCase):

    def setUp(self):
        self.mock_diag = MockDiagInput()
        self.fuzzer = ProtocolFuzzerEngine(self.mock_diag)
        self.nv = NvManager(self.mock_diag)

    def test_fuzzer_asn1_templates_present(self):
        templates = self.fuzzer.get_templates()
        self.assertIn("nr_sib19_ntn", templates)
        self.assertIn("lpp_prov_loc", templates)
        self.assertIn("lpp_req_loc", templates)
        self.assertIn("ecall_msd_sos", templates)
        self.assertIn("cv2x_pc5_sidelink", templates)

    def test_fuzzer_asn1_mutation_strategies(self):
        strategies = [
            "bit_flip",
            "byte_boundary",
            "length_tamper",
            "truncation",
            "ie_injection",
            "asn1_tag_corrupt",
            "asn1_uper_overflow",
            "asn1_choice_tamper",
            "gps_coord_spoof",
            "suci_ecies_tamper"
        ]
        for strat in strategies:
            res = self.fuzzer.generate_mutated_vector("lpp_prov_loc", strategy=strat, intensity=3)
            self.assertEqual(res['template'], 'lpp_prov_loc')
            self.assertEqual(res['strategy'], strat)
            self.assertTrue(len(res['mutated_hex']) > 0)
            self.assertIn("baseband_status", res)

    def test_fuzzer_campaign_and_pcap(self):
        campaign = self.fuzzer.generate_campaign("ecall_msd_sos", count=5, strategy="gps_coord_spoof")
        self.assertEqual(campaign['campaign_count'], 5)
        self.assertEqual(len(campaign['vectors']), 5)

        data, ctype, filename = self.fuzzer.export_fuzz_pcap()
        self.assertEqual(ctype, 'application/vnd.tcpdump.pcap')
        self.assertTrue(filename.endswith('.pcap'))
        self.assertTrue(len(data) > 0)

    def test_nv_lte_band_mask_encoder(self):
        mask_bytes = NvManager.encode_lte_band_mask(['B1', 'B3', 'B7', 'B20', 'B28'])
        self.assertEqual(len(mask_bytes), 128)
        # B1 (bit 0), B3 (bit 2), B7 (bit 6), B20 (bit 19), B28 (bit 27)
        import struct
        val = struct.unpack('<Q', mask_bytes[:8])[0]
        self.assertTrue(bool(val & (1 << 0)))  # B1
        self.assertTrue(bool(val & (1 << 2)))  # B3
        self.assertTrue(bool(val & (1 << 6)))  # B7
        self.assertTrue(bool(val & (1 << 19))) # B20
        self.assertTrue(bool(val & (1 << 27))) # B28

    def test_nv_nr5g_band_mask_encoder(self):
        mask_bytes = NvManager.encode_nr5g_band_mask(['n78', 'n41', 'n1', 'n28'])
        self.assertEqual(len(mask_bytes), 128)
        import struct
        val = struct.unpack('<Q', mask_bytes[:8])[0]
        # n1 (bit 0), n28 (bit 7), n41 (bit 10), n78 (bit 14)
        self.assertTrue(bool(val & (1 << 0)))
        self.assertTrue(bool(val & (1 << 7)))
        self.assertTrue(bool(val & (1 << 10)))
        self.assertTrue(bool(val & (1 << 14)))

    def test_nv_band_lock_execution(self):
        res_5g = self.nv.set_band_lock('5G', ['n78', 'n41'])
        self.assertEqual(res_5g['status'], 'ok')
        self.assertEqual(res_5g['nv_id'], 71502)

        res_4g = self.nv.set_band_lock('4G', ['B1', 'B3', 'B20'])
        self.assertEqual(res_4g['status'], 'ok')
        self.assertEqual(res_4g['nv_id'], 6828)

    def test_nv_formatting(self):
        data = NvManager.encode_nr5g_band_mask(['n78', 'n77'])
        formatted = self.nv.format_nv_item(71502, NV_STATUS_DONE, data)
        self.assertIn("Configured 5G NR Bands", formatted)
        self.assertIn("n78", formatted)

if __name__ == '__main__':
    unittest.main()
