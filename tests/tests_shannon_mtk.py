#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
from io import BytesIO
from struct import pack

from src.inputs.shannon_read import (
    ShannonReader,
    SHANNON_CH_5G_NR_RRC,
    SHANNON_CH_LTE_RRC,
    SHANNON_CH_IMS_SIP,
    SHANNON_FRAME_DELIMITER,
    SHANNON_FRAME_ESCAPE
)
from src.inputs.mtk_read import (
    MediaTekReader,
    MTK_TAG_HEADER,
    MTK_SAP_5G_NR_RRC,
    MTK_SAP_LTE_RRC
)
from src.protocol.log_types import (
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_IMS_SIP_MSG_C
)


class TestMultiVendorBasebandReaders(unittest.TestCase):

    def test_shannon_hdlc_unescape(self):
        # 0x7D 0x5E should decode to 0x7E, 0x7D 0x5D should decode to 0x7D
        escaped = b'\x01\x02\x7D\x5E\x03\x7D\x5D\x04'
        unescaped = ShannonReader.unescape_hdlc(escaped)
        self.assertEqual(unescaped, b'\x01\x02\x7E\x03\x7D\x04')

    def test_shannon_reader_demux(self):
        dispatched = []
        class MockModule:
            def on_log(self, log_type, payload, hdr, ts):
                dispatched.append((log_type, payload))

        # Build Shannon frame: [ch_id(1B), sub_id(1B), len(2B), ts(8B), payload(6B)]
        payload = b'\x11\x22\x33\x44\x55\x66'
        raw_frame = pack('<BBHQ', SHANNON_CH_5G_NR_RRC, 0, len(payload), 1600000000000) + payload
        stream = bytes([SHANNON_FRAME_DELIMITER]) + raw_frame + bytes([SHANNON_FRAME_DELIMITER])

        reader = ShannonReader(BytesIO(stream))
        reader.add_module(MockModule())
        reader.read_loop()

        self.assertEqual(len(dispatched), 1)
        self.assertEqual(dispatched[0][0], LOG_NR_RRC_OTA_MSG_LOG_C)
        self.assertEqual(dispatched[0][1], payload)

    def test_mtk_reader_demux(self):
        dispatched = []
        class MockModule:
            def on_log(self, log_type, payload, hdr, ts):
                dispatched.append((log_type, payload))

        payload = b'\xaa\xbb\xcc\xdd'
        # 'MTK\0' + [sap(2B), len(2B), ts(4B)] + payload
        mtk_frame = MTK_TAG_HEADER + pack('<HHI', MTK_SAP_LTE_RRC, len(payload), 1600000000) + payload

        reader = MediaTekReader(BytesIO(mtk_frame))
        reader.add_module(MockModule())
        reader.read_loop()

        self.assertEqual(len(dispatched), 1)
        self.assertEqual(dispatched[0][0], LOG_LTE_RRC_OTA_MSG_LOG_C)
        self.assertEqual(dispatched[0][1], payload)


if __name__ == '__main__':
    unittest.main()
