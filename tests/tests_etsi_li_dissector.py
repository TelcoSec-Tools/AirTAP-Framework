#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - ETSI TS 102 232 & 3GPP TS 33.108 / TS 33.128 Dissector Test Suite
    Tests ASN.1 BER parsing, compact framing, X1 provisioning, and TelcoSec audit rules.
"""

import unittest
import struct
import json
import time

from src.protocol.etsi_li import EtsiLiPsPduParser, X1ProvisioningParser
from src.protocol.log_types import LOG_LTE_CALEA_TRACE_LOG_C, LOG_NR_CALEA_TRACE_LOG_C
from src.modules.sec_audit import SecurityAuditor


class TestEtsiLiDissector(unittest.TestCase):

    def test_asn1_ber_ps_pdu_decoding(self):
        # Construct valid ASN.1 BER PS-PDU buffer:
        # 0x30 (SEQUENCE), len=36
        #   0xA1 (PSHeader), len=20
        #     0x81 (LIID), len=10, "WARR-8910"
        #     0x84 (Seq), len=4, 0x00000042
        #     0x89 (Direction), len=1, 0x00 (fromTarget)
        #   0xA2 (Payload), len=12, "HELLO_TARGET"
        liid_bytes = b"WARR-8910"
        hdr_bytes = (
            b'\x81' + bytes([len(liid_bytes)]) + liid_bytes +
            b'\x84\x04\x00\x00\x00\x42' +
            b'\x89\x01\x00'
        )
        payload_bytes = b"HELLO_TARGET"
        pdu_body = (
            b'\xA1' + bytes([len(hdr_bytes)]) + hdr_bytes +
            b'\xA2' + bytes([len(payload_bytes)]) + payload_bytes
        )
        raw_ber = b'\x30' + bytes([len(pdu_body)]) + pdu_body

        res = EtsiLiPsPduParser.parse_ps_pdu(raw_ber, is_encrypted_transport=True)
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(res['is_asn1_ber'])
        self.assertEqual(res['liid'], "WARR-8910")
        self.assertEqual(res['seq_num'], 66)
        self.assertEqual(res['direction_id'], 0)
        self.assertIn("fromTarget", res['direction'])
        self.assertEqual(res['payload_length'], len(payload_bytes))

    def test_compact_binary_calea_framing(self):
        # Compact 16-byte header + inner payload:
        # [0]=version 1, [1]=pdu_type 1 (IRI), [2]=direction 1 (toTarget), [3]=inner_proto 1 (IPv4)
        # [4..7]=CIN (0x00A38F12), [8..11]=Seq (1001), [12..15]=reserved
        cin = 0x00A38F12
        seq = 1001
        header = struct.pack('>BBBBII4s', 1, 1, 1, 1, cin, seq, b'\x00'*4)
        inner_ip = b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xcd\x7f\x00\x00\x01\x7f\x00\x00\x01' # 20B IPv4
        raw_packet = header + inner_ip

        res = EtsiLiPsPduParser.parse_ps_pdu(raw_packet, is_encrypted_transport=False)
        self.assertEqual(res['status'], 'ok')
        self.assertFalse(res['is_asn1_ber'])
        self.assertEqual(res['cin'], cin)
        self.assertEqual(res['seq_num'], seq)
        self.assertEqual(res['direction_id'], 1)
        self.assertIn("toTarget", res['direction'])
        self.assertEqual(res['inner_proto_id'], 1)
        self.assertIn("IPv4", res['inner_proto'])
        self.assertIn('PLAINTEXT_TRANSMISSION', res['security_flags'])

    def test_x1_provisioning_json_parsing(self):
        x1_json = json.dumps({
            "x1RequestMessage": {
                "admfIdentifier": "ADMF-NORTH-01",
                "requestIdentifier": "REQ-778899",
                "taskDetails": {
                    "xId": "XID-UUID-1234",
                    "deliveryType": "X2andX3",
                    "targetIdentifiers": [
                        {"supi": "208950000000001"},
                        {"guti": "5G-GUTI-208-95-001"}
                    ]
                }
            }
        })

        parsed = X1ProvisioningParser.parse_x1_request(x1_json)
        self.assertEqual(parsed['status'], 'ok')
        self.assertEqual(parsed['admf_id'], "ADMF-NORTH-01")
        self.assertEqual(parsed['xid'], "XID-UUID-1234")
        self.assertEqual(len(parsed['target_identifiers']), 2)
        self.assertIn("SUPI: 208950000000001", parsed['target_identifiers'])

    def test_sec_audit_li_rules(self):
        auditor = SecurityAuditor(diag_input=None)

        # 1. Test TELCOSEC-VULN-076 (Plaintext Handover Interface Transmission)
        sample_raw = b'\x01\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0A\x00\x00\x00\x00' + b'RAW_DATA'
        auditor.audit_etsi_li_packet(sample_raw, is_encrypted=False)

        alerts_76 = [a for a in auditor.alerts if a.rule_id == 'TELCOSEC-VULN-076']
        self.assertGreaterEqual(len(alerts_76), 1)
        self.assertEqual(alerts_76[0].severity, 'CRITICAL')

        # 2. Test TELCOSEC-VULN-077 (Non-Monotonic Sequence Replay)
        sample_seq_10 = b'\x01\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0A\x00\x00\x00\x00' + b'DATA_1'
        sample_seq_5 = b'\x01\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00' + b'DATA_2'
        auditor.audit_etsi_li_packet(sample_seq_10, is_encrypted=True)
        auditor.audit_etsi_li_packet(sample_seq_5, is_encrypted=True) # Sequence rollback from 10 to 5

        alerts_77 = [a for a in auditor.alerts if a.rule_id == 'TELCOSEC-VULN-077']
        self.assertGreaterEqual(len(alerts_77), 1)
        self.assertEqual(alerts_77[0].severity, 'HIGH')

        # 3. Test TELCOSEC-VULN-078 (Unauthenticated X1 Target Activation)
        x1_payload = '{"x1RequestMessage": {"admfIdentifier": "ROGUE_ADMF", "taskDetails": {"targetIdentifiers": [{"imsi": "001010123456789"}]}}}'
        auditor.audit_x1_provisioning(x1_payload, is_authenticated=False)

        alerts_78 = [a for a in auditor.alerts if a.rule_id == 'TELCOSEC-VULN-078']
        self.assertGreaterEqual(len(alerts_78), 1)
        self.assertEqual(alerts_78[0].severity, 'CRITICAL')

        # 4. Test TELCOSEC-VULN-079 (Baseband CALEA Diagnostic Trace 0xB825)
        auditor.on_log(LOG_NR_CALEA_TRACE_LOG_C, sample_raw)
        alerts_79 = [a for a in auditor.alerts if a.rule_id == 'TELCOSEC-VULN-079']
        self.assertGreaterEqual(len(alerts_79), 1)
        self.assertEqual(alerts_79[0].severity, 'HIGH')


if __name__ == '__main__':
    unittest.main()
