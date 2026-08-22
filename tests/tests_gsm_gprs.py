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

    def flush(self):
        pass

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

    def test_pcap_dumper_gprs_mac_channel_variations(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)

        # Test DL PACCH (channel_type=129 / 0x81, message_type=1, length=4)
        payload = b'\x81\x01\x04\xaa\xbb\xcc\xdd'
        dumper.on_log(LOG_GPRS_MAC_SIGNALLING_MESSAGE_C, payload, log_header=None, timestamp=1600000002)
        self.assertGreater(len(mock_pcap.data), 0)

        # Test UL PACCH (channel_type=4 / 0x04, message_type=1, length=4)
        payload2 = b'\x04\x01\x04\x11\x22\x33\x44'
        dumper.on_log(LOG_GPRS_MAC_SIGNALLING_MESSAGE_C, payload2, log_header=None, timestamp=1600000003)
        self.assertGreater(len(mock_pcap.data), 0)

if __name__ == '__main__':
    unittest.main()
