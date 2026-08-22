#!/usr/bin/python3
import unittest
from struct import pack, unpack_from
import io

from src.protocol.gsmtap import (
    GSMTAP_TYPE_NR_RRC,
    GSMTAP_TYPE_NR_NAS,
    GSMTAP_NR_RRC_SUB_DL_DCCH,
    GSMTAP_NR_RRC_SUB_UL_DCCH,
    GSMTAP_NR_NAS_PLAIN,
    build_gsmtap_ip,
)
from src.protocol.log_types import (
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
    NR_DL_DCCH,
    NR_UL_DCCH,
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


class Test5GNR(unittest.TestCase):

    def test_gsmtap_5g_nr_constants_and_headers(self):
        payload = b'\x40\x01\x02\x03'
        ip_pkt = build_gsmtap_ip(GSMTAP_TYPE_NR_RRC, GSMTAP_NR_RRC_SUB_DL_DCCH, payload, is_uplink=False)
        
        # IP header is 20 bytes, UDP header is 8 bytes, GSMTAP header is 16 bytes
        gsmtap_hdr = ip_pkt[28:44]
        version, hdr_len, proto = unpack_from('>BBB', gsmtap_hdr[:3])
        sub_type = gsmtap_hdr[12]
        
        self.assertEqual(version, 2)
        self.assertEqual(hdr_len, 4)
        self.assertEqual(proto, GSMTAP_TYPE_NR_RRC)
        self.assertEqual(sub_type, GSMTAP_NR_RRC_SUB_DL_DCCH)

    def test_pcap_dumper_5g_nr_rrc_log(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)
        
        # Construct synthetic 5G NR RRC log payload:
        # Header: version=1 (1B), sfn=100 (2B), slot=5 (2B), channel_type=NR_DL_DCCH (2B), pdu_len=4 (2B)
        hdr = pack('<BHHHH', 1, 100, 5, NR_DL_DCCH, 4)
        rrc_pdu = b'\x00\x08\x12\x34'
        log_payload = hdr + rrc_pdu
        
        dumper.on_log(LOG_NR_RRC_OTA_MSG_LOG_C, log_payload, log_header=None, timestamp=1600000000)
        
        self.assertEqual(dumper.current_rat, '5g')
        self.assertGreater(len(mock_pcap.data), 24) # Contains PCAP file header + packet header + payload

    def test_pcap_dumper_5g_nr_nas_log(self):
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=False, include_ip_traffic=False)
        
        nas_pdu = b'\x7e\x00\x41\x01\x02\x03'
        hdr = pack('<BBBB', 1, 0, 0, 0)
        log_payload = hdr + nas_pdu
        
        dumper.on_log(LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, log_payload, log_header=None, timestamp=1600000000)
        self.assertEqual(dumper.current_rat, '5g')
        
        dumper.on_log(LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C, log_payload, log_header=None, timestamp=1600000001)
        self.assertEqual(dumper.current_rat, '5g')

    def test_pcap_dumper_lte_nas_sec_header(self):
        from src.protocol.log_types import (
            LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_EMM_SEC_OTA_IN_MSG_LOG_C,
        )
        from src.protocol.gsmtap import GSMTAP_LTE_NAS_SEC_HEADER, GSMTAP_LTE_NAS_PLAIN
        mock_pcap = MockFile()
        dumper = PcapDumper(diag_input=None, pcap_file=mock_pcap, reassemble_sibs=False, decrypt_nas=True, include_ip_traffic=False)

        # Plain NAS message (EMM Attach Request)
        plain_nas = b'\x07\x41\x01\x02\x03\x04'
        hdr = pack('<BBBB', 1, 0, 0, 0)
        dumper.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, hdr + plain_nas, log_header=None, timestamp=1600000000)
        
        # Security protected NAS message (Security Header Type = 1, Protocol Discriminator = 7)
        sec_nas = b'\x17\xaa\xbb\xcc\xdd\x01\x07\x41\x01\x02\x03\x04'
        dumper.on_log(LOG_LTE_NAS_EMM_SEC_OTA_IN_MSG_LOG_C, hdr + sec_nas, log_header=None, timestamp=1600000001)
        self.assertEqual(dumper.current_rat, '4g')
        self.assertGreater(len(mock_pcap.data), 100)


if __name__ == '__main__':
    unittest.main()
