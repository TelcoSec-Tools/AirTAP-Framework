#!/usr/bin/python3
import unittest
from src.protocol.log_types import (
    LOG_GSM_CELL_BROADCAST_C,
    LOG_UMTS_CELL_BROADCAST_C,
    LOG_LTE_RRC_ETWS_CMAS_LOG_C,
    LOG_NR_RRC_ETWS_CMAS_LOG_C,
    LOG_LTE_CALEA_TRACE_LOG_C,
    LOG_NR_CALEA_TRACE_LOG_C,
    LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C,
    LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C,
)
from src.modules.stats_dump import (
    StatsDumper,
    LOG_CODES_2G,
    LOG_CODES_3G,
    LOG_CODES_4G,
    LOG_CODES_5G,
)
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

class TestSosEtwsCalea(unittest.TestCase):

    def test_log_codes_registered(self):
        self.assertIn(LOG_GSM_CELL_BROADCAST_C, LOG_CODES_2G)
        self.assertIn(LOG_UMTS_CELL_BROADCAST_C, LOG_CODES_3G)
        self.assertIn(LOG_LTE_RRC_ETWS_CMAS_LOG_C, LOG_CODES_4G)
        self.assertIn(LOG_LTE_CALEA_TRACE_LOG_C, LOG_CODES_4G)
        self.assertIn(LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C, LOG_CODES_4G)
        self.assertIn(LOG_NR_RRC_ETWS_CMAS_LOG_C, LOG_CODES_5G)
        self.assertIn(LOG_NR_CALEA_TRACE_LOG_C, LOG_CODES_5G)
        self.assertIn(LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C, LOG_CODES_5G)

    def test_stats_dumper_classification(self):
        dumper = StatsDumper(diag_input=None)
        self.assertEqual(dumper.classify_log_type(LOG_GSM_CELL_BROADCAST_C), '2g')
        self.assertEqual(dumper.classify_log_type(LOG_UMTS_CELL_BROADCAST_C), '3g')
        self.assertEqual(dumper.classify_log_type(LOG_LTE_RRC_ETWS_CMAS_LOG_C), '4g')
        self.assertEqual(dumper.classify_log_type(LOG_NR_RRC_ETWS_CMAS_LOG_C), '5g')

    def test_pcap_dumper_etws_and_calea(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)

        payload = b'\x00\x01\x02\x03\x04\x05'
        dumper.on_log(LOG_NR_RRC_ETWS_CMAS_LOG_C, payload, log_header=None, timestamp=1600000000)
        self.assertEqual(dumper.current_rat, '5g')

        dumper.on_log(LOG_NR_CALEA_TRACE_LOG_C, payload, log_header=None, timestamp=1600000001)
        self.assertEqual(dumper.current_rat, '5g')

if __name__ == '__main__':
    unittest.main()
