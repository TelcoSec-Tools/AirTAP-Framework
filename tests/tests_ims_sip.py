#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from io import BytesIO
from struct import unpack

from src.modules.pcap_dump import PcapDumper
from src.protocol.log_types import LOG_IMS_SIP_MSG_C, LOG_LTE_IMS_SIP_MSG_C
from src.protocol.gsmtap import build_sip_udp_ip

class TestImsSip(TestCase):

    def test_build_sip_udp_ip(self):
        sip_text = b'SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n\r\n'
        packet = build_sip_udp_ip(sip_text, is_uplink=False)

        # Total packet = 20 (IP) + 8 (UDP) + len(sip_text)
        self.assertEqual(len(packet), 28 + len(sip_text))

        # Check UDP destination port 5060 (offset 20 + 2 = 22)
        src_port, dst_port = unpack('>HH', packet[20:24])
        self.assertEqual(src_port, 5060)
        self.assertEqual(dst_port, 5060)
        self.assertEqual(packet[28:], sip_text)

    def test_pcap_dumper_ims_sip_log(self):
        pcap_file = BytesIO()
        dumper = PcapDumper(diag_input=None, pcap_file=pcap_file, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)

        sip_text = b'INVITE sip:alice@example.com SIP/2.0\r\n'
        raw_log = b'\x01\x00\x00\x00' + sip_text

        dumper.on_log(LOG_IMS_SIP_MSG_C, raw_log, None, timestamp=1000.0)

        data = pcap_file.getvalue()
        # Should contain PCAP global header (24 bytes) + packet record header (16 bytes) + IP packet
        self.assertGreater(len(data), 40)
        self.assertIn(b'INVITE sip:alice@example.com', data)

if __name__ == '__main__':
    main()
