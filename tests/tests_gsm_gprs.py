#!/usr/bin/python3
import unittest
from src.protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    LOG_GSM_SACCH_C,
    LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,
    LOG_GPRS_RLC_UL_COMMAND_C,
    LOG_GPRS_RLC_DL_COMMAND_C,
    LOG_GPRS_LLC_ME_LOG_PACKET_C,
    LOG_GPRS_SNDCP_PDU_C,
)
from src.modules.stats_dump import StatsDumper, LOG_CODES_2G
from src.modules.pcap_dump import PcapDumper

class MockFile:
    def __init__(self):
        self.appending_to_file = False
        self.data = b''

    def write(self, data):
        self.data += data

    def close(self):
        pass

class TestGsmGprs(unittest.TestCase):

    def test_2g_log_codes_registered(self):
        self.assertIn(LOG_GSM_RR_SIGNALING_MESSAGE_C, LOG_CODES_2G)
        self.assertIn(LOG_GSM_SACCH_C, LOG_CODES_2G)
        self.assertIn(LOG_GPRS_MAC_SIGNALLING_MESSAGE_C, LOG_CODES_2G)
        self.assertIn(LOG_GPRS_RLC_UL_COMMAND_C, LOG_CODES_2G)
        self.assertIn(LOG_GPRS_RLC_DL_COMMAND_C, LOG_CODES_2G)
        self.assertIn(LOG_GPRS_LLC_ME_LOG_PACKET_C, LOG_CODES_2G)
        self.assertIn(LOG_GPRS_SNDCP_PDU_C, LOG_CODES_2G)

    def test_stats_dumper_2g_classification(self):
        dumper = StatsDumper(diag_input=None)
        self.assertEqual(dumper.classify_log_type(LOG_GSM_SACCH_C), '2g')
        self.assertEqual(dumper.classify_log_type(LOG_GPRS_SNDCP_PDU_C), '2g')

    def test_pcap_dumper_2g_sacch_and_gprs(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)

        payload = b'\x01\x02\x03\x04\x05\x06'
        dumper.on_log(LOG_GSM_SACCH_C, payload, log_header=None, timestamp=1600000000)
        self.assertEqual(dumper.current_rat, '2g')

        dumper.on_log(LOG_GPRS_SNDCP_PDU_C, payload, log_header=None, timestamp=1600000001)
        self.assertEqual(dumper.current_rat, '2g')

if __name__ == '__main__':
    unittest.main()
