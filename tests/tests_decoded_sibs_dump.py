#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from struct import pack

from src.modules.decoded_sibs_dump import DecodedSibsDumper
from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C, LOG_NR_RRC_OTA_MSG_LOG_C, LTE_BCCH_BCH_v0, NR_BCCH_BCH

class TestDecodedSibsDump(TestCase):

    def test_lte_and_nr_log_handling_without_errors(self):
        diag_input = MagicMock()
        callback = MagicMock()
        dumper = DecodedSibsDumper(diag_input, on_decoded_sib=callback)

        # Build mock LTE RRC frame
        # ext_header_ver=0, rrc_rel=9, rrc_ver=0, bearer_id=0, phy_cellid=100
        # freq=1000, sfn=50, channel_type=LTE_BCCH_BCH_v0(1), length=4
        base_header = pack('<BBBBH', 0, 9, 0, 0, 100)
        ext_header = pack('<HHBH', 1000, 50, LTE_BCCH_BCH_v0, 4)
        dummy_payload = base_header + ext_header + b'\x00\x00\x00\x00'

        dumper.on_log(LOG_LTE_RRC_OTA_MSG_LOG_C, dummy_payload, None)

        # Build mock NR RRC frame
        # version=1, sfn=10, slot=1, channel_type=NR_BCCH_BCH(1), pdu_len=3
        nr_payload = pack('<BHHHH', 1, 10, 1, NR_BCCH_BCH, 3) + b'\x00\x00\x00'
        dumper.on_log(LOG_NR_RRC_OTA_MSG_LOG_C, nr_payload, None)

    def test_format_sib_summary(self):
        from src.modules.decoded_sibs_dump import format_sib_summary
        mock_sib1 = {
            'cellAccessRelatedInfo': {
                'plmn-IdentityList': [{
                    'plmn-Identity': {'mcc': [2, 6, 8], 'mnc': [0, 1]},
                    'cellReservedForOperatorUse': 'notReserved'
                }],
                'trackingAreaCode': 18962,
                'cellIdentity': 99752449
            },
            'sib-TypeAndInfo': [('sibType3', {}), ('sibType5', {})]
        }
        res = format_sib_summary('LTE_SystemInformationBlockType1', mock_sib1, sfn=104)
        self.assertIn('LTE_SystemInformationBlockType1', res)
        self.assertIn('268', res)
        self.assertIn('18962', res)

if __name__ == '__main__':
    main()
