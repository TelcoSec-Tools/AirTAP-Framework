#!/usr/bin/python3
import unittest
from src.protocol.log_types import (
    LOG_LTE_IMS_SIP_MSG_C,
    LOG_NR_IMS_SIP_MSG_C,
    LOG_SIM_APDU_LOG_C,
)
from src.modules.stats_dump import (
    StatsDumper,
    LOG_CODES_2G,
    LOG_CODES_4G,
    LOG_CODES_5G,
)
from src.modules.pcap_dump import PcapDumper
from src.inputs._base_input import BaseInput

class MockFile:
    def __init__(self):
        self.appending_to_file = False
        self.data = b''

    def write(self, data):
        self.data += data

    def close(self):
        pass

class MockModule:
    def __init__(self):
        self.events = []

    def on_event(self, event_id, event_payload, timestamp):
        self.events.append((event_id, event_payload, timestamp))

class TestImsSimEvents(unittest.TestCase):

    def test_log_codes_registered(self):
        self.assertIn(LOG_SIM_APDU_LOG_C, LOG_CODES_2G)
        self.assertIn(LOG_LTE_IMS_SIP_MSG_C, LOG_CODES_4G)
        self.assertIn(LOG_NR_IMS_SIP_MSG_C, LOG_CODES_5G)

    def test_stats_dumper_classification(self):
        dumper = StatsDumper(diag_input=None)
        self.assertEqual(dumper.classify_log_type(LOG_SIM_APDU_LOG_C), '2g')
        self.assertEqual(dumper.classify_log_type(LOG_LTE_IMS_SIP_MSG_C), '4g')
        self.assertEqual(dumper.classify_log_type(LOG_NR_IMS_SIP_MSG_C), '5g')

    def test_pcap_dumper_ims_and_sim(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)

        payload = b'\x00\x01\x02\x03REGISTER sip:ims.mnc001.mcc208.pub.3gppnetwork.org SIP/2.0'
        dumper.on_log(LOG_LTE_IMS_SIP_MSG_C, payload, log_header=None, timestamp=1600000000)
        self.assertEqual(dumper.current_rat, '4g')

        dumper.on_log(LOG_NR_IMS_SIP_MSG_C, payload, log_header=None, timestamp=1600000001)
        self.assertEqual(dumper.current_rat, '5g')

        sim_apdu = b'\x00\x00\x00\x00\xa0\x88\x00\x00\x04\x01\x02\x03\x04'
        dumper.on_log(LOG_SIM_APDU_LOG_C, sim_apdu, log_header=None, timestamp=1600000002)
        self.assertEqual(dumper.current_rat, '2g')

    def test_base_input_event_dispatch(self):
        inp = BaseInput()
        mod = MockModule()
        inp.modules.append(mod)

        inp.dispatch_diag_event(0x0123, b'\xaa\xbb', 1600000000)
        self.assertEqual(len(mod.events), 1)
        self.assertEqual(mod.events[0][0], 0x0123)
        self.assertEqual(mod.events[0][1], b'\xaa\xbb')

if __name__ == '__main__':
    unittest.main()
