#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from io import BytesIO
from struct import unpack

from src.modules.qmdl_dump import QmdlDumper
from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C

class TestQmdlDump(TestCase):

    def test_qmdl_dumper_writes_valid_header_and_records(self):
        diag_input = MagicMock()
        qmdl_file = BytesIO()

        dumper = QmdlDumper(diag_input, qmdl_file)
        # Verify initial QMDL magic
        data = qmdl_file.getvalue()
        self.assertEqual(data[:8], b'QMDL\x02\x00\x00\x00')

        # Emit log
        log_payload = b'\x01\x02\x03\x04'
        log_header = b'\x10\x00\xc0\xb0\x00\x00\x00\x00\x00\x00\x00\x00'
        dumper.on_log(LOG_LTE_RRC_OTA_MSG_LOG_C, log_payload, log_header, timestamp=1600000000.123)

        data = qmdl_file.getvalue()
        # Record at offset 8: record_type (uint32), length (uint32), ts_sec (uint32), ts_usec (uint32)
        rec_type, rec_len, ts_sec, ts_usec = unpack('<IIII', data[8:24])
        self.assertEqual(rec_type, 1)
        self.assertEqual(rec_len, 1 + len(log_header) + len(log_payload)) # DIAG_LOG_F opcode (1 byte) + header + payload
        self.assertEqual(ts_sec, 1600000000)
        self.assertAlmostEqual(ts_usec, 123000, delta=1000)

        # Check payload
        payload = data[24:24 + rec_len]
        self.assertEqual(payload[0], 0x10) # DIAG_LOG_F
        self.assertEqual(payload[1:13], log_header)
        self.assertEqual(payload[13:], log_payload)

if __name__ == '__main__':
    main()
