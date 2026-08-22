#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from struct import pack
import tempfile
import os

from src.protocol.dmc_parser import DmcParser
from src.modules.nv_manager import NvManager, NV_STATUS_DONE, NV_STATUS_BADPARM
from src.modules.qxdm_streamer import QxdmStreamer
from src.modules.mode_control import ModeController, MODE_OFFLINE_D_F, MODE_RESET_F
from src.protocol.messages import DIAG_NV_READ_F, DIAG_CONTROL_F, DIAG_EXT_MSG_F, DIAG_MSG_F

class TestQxdmFeatures(TestCase):

    def test_dmc_parser(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.dmc') as tmp:
            tmp.write("""# QXDM Mask File
LOG_CODE 0xB0C0
LOG_CODE 0xB821
LOG 0x512F
EVENT 1000
EVENT 2000
MSG SSID 300 LEVEL 2
""")
            tmp_path = tmp.name

        try:
            parser = DmcParser(tmp_path)
            res = parser.parse()
            self.assertIn(0xB0C0, res['log_codes'])
            self.assertIn(0xB821, res['log_codes'])
            self.assertIn(0x512F, res['log_codes'])
            self.assertIn(1000, res['event_ids'])
            self.assertIn(2000, res['event_ids'])
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_nv_manager_read_and_format(self):
        diag_input = MagicMock()
        # Mock response: [38 (cmd)][1877 (2B item_id)][data (128B with band mask)][0 (2B status)]
        mock_data = pack('<Q', 0x0000000000000005) + b'\x00' * 120
        mock_resp = pack('<H', 1877) + mock_data + pack('<H', 0)
        diag_input.send_recv.return_value = (DIAG_NV_READ_F, mock_resp)

        nvm = NvManager(diag_input)
        status, data = nvm.read_nv_item(1877)
        self.assertEqual(status, NV_STATUS_DONE)
        self.assertEqual(len(data), 128)

        formatted = nvm.format_nv_item(1877, status, data)
        self.assertIn('NV_RF_BC_CONFIG_I', formatted)
        self.assertIn('SUCCESS', formatted)

    def test_qxdm_f3_streamer_parsing(self):
        diag_input = MagicMock()
        streamer = QxdmStreamer(diag_input, show_messages=True, show_events=True)

        # Build synthetic F3 DIAG_EXT_MSG_F payload
        # cmd=121(1B), num_args=0(1B), drop_cnt=0(1B), ver=1(1B), ssid=300(2B, LTE_RRC), mask=0x04(2B), line=1420(2B), ts=0(8B)
        hdr = pack('<BBBBHHHQ', 121, 0, 0, 1, 300, 0x04, 1420, 0)
        payload = hdr + b"LTE RRC Cell Selection Succeeded\x00lte_rrc_csp.c\x00"
        
        # Test that on_message processes without error
        streamer.on_message(DIAG_EXT_MSG_F, payload)

        # Test on_event processes without error
        streamer.on_event(1000, b'\x01\x02', 1600000000)

    def test_mode_controller(self):
        diag_input = MagicMock()
        diag_input.send_recv.return_value = (DIAG_CONTROL_F, b'\x00\x00')

        ctl = ModeController(diag_input)
        res = ctl.switch_mode(MODE_OFFLINE_D_F)
        self.assertTrue(res)
        diag_input.send_recv.assert_called_with(DIAG_CONTROL_F, pack('<H', MODE_OFFLINE_D_F), accept_error=True)

if __name__ == '__main__':
    main()
