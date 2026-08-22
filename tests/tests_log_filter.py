#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from struct import pack

from src.modules._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING, RAT_TO_LOG_CODES
from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C, LOG_NR_RRC_OTA_MSG_LOG_C, LOG_GSM_RR_SIGNALING_MESSAGE_C
from src.protocol.messages import DIAG_LOG_CONFIG_F

class DummyModule(EnableLogMixin):
    def __init__(self, diag_input):
        self.diag_input = diag_input
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING.copy()

class TestLogFilter(TestCase):

    def setUp(self):
        self.diag_input = MagicMock()
        header_spec = '<3xII'
        ranges_payload = pack(header_spec, 1, 0) + pack('<16I', *([512] * 16))
        set_mask_payload = pack(header_spec, 3, 0)

        def mock_send_recv(opcode, payload):
            op = payload[3] if len(payload) > 3 else 1
            if op == 1:
                return DIAG_LOG_CONFIG_F, ranges_payload
            else:
                return DIAG_LOG_CONFIG_F, set_mask_payload

        self.diag_input.send_recv.side_effect = mock_send_recv

    def test_filter_rat_4g(self):
        self.diag_input.filter_rat = ['4g']
        self.diag_input.filter_logs = None

        mod = DummyModule(self.diag_input)
        mod.on_init()

        # Should only contain 4G log codes
        self.assertIn(LOG_LTE_RRC_OTA_MSG_LOG_C, mod.limit_registered_logs)
        self.assertNotIn(LOG_GSM_RR_SIGNALING_MESSAGE_C, mod.limit_registered_logs)
        self.assertNotIn(LOG_NR_RRC_OTA_MSG_LOG_C, mod.limit_registered_logs)

    def test_filter_logs_specific_codes(self):
        self.diag_input.filter_rat = None
        self.diag_input.filter_logs = [LOG_LTE_RRC_OTA_MSG_LOG_C]

        mod = DummyModule(self.diag_input)
        mod.on_init()

        self.assertEqual(mod.limit_registered_logs, [LOG_LTE_RRC_OTA_MSG_LOG_C])

if __name__ == '__main__':
    main()
