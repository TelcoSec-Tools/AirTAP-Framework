#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from io import BytesIO
from struct import pack

from src.inputs.pcap_read import PcapReader
from src.protocol.gsmtap import build_gsmtap_ip, GSMTAP_TYPE_LTE_RRC, GSMTAP_LTE_RRC_SUB_DL_DCCH_Message
from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C

class TestPcapRead(TestCase):

    def test_pcap_reader_dispatch(self):
        # Build synthetic GSMTAP PCAP in memory
        pcap_stream = BytesIO()

        # Global header: magic, 2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=228 (IPv4)
        pcap_stream.write(pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 228))

        # Build 1 GSMTAP IP frame
        rrc_payload = b'\x08\x00\x01\x02'
        ip_frame = build_gsmtap_ip(GSMTAP_TYPE_LTE_RRC, GSMTAP_LTE_RRC_SUB_DL_DCCH_Message, rrc_payload, is_uplink=False)

        # Write packet record: ts_sec=1600000000, ts_usec=500000, incl_len, orig_len
        pcap_stream.write(pack('<IIII', 1600000000, 500000, len(ip_frame), len(ip_frame)) + ip_frame)
        pcap_stream.seek(0)

        reader = PcapReader(pcap_stream)
        dispatched_logs = []

        class MockModule:
            def on_init(self): pass
            def on_log(self, log_type, log_payload, log_header, timestamp=0):
                dispatched_logs.append((log_type, log_payload, timestamp))

        mod = MockModule()
        reader.add_module(mod)
        reader.read_loop()

        self.assertEqual(len(dispatched_logs), 1)
        log_type, log_payload, timestamp = dispatched_logs[0]
        self.assertEqual(log_type, LOG_LTE_RRC_OTA_MSG_LOG_C)
        self.assertEqual(log_payload, rrc_payload)
        self.assertEqual(timestamp, 1600000000.5)

if __name__ == '__main__':
    main()
