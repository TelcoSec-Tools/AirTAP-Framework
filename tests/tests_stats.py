#!/usr/bin/python3
import unittest
import time

from src.modules.stats_dump import StatsDumper
from src.protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
)


class TestStatsDumper(unittest.TestCase):

    def test_stats_classification_and_counters(self):
        dumper = StatsDumper(diag_input=None)
        
        # Simulating 2G packet
        dumper.on_log(LOG_GSM_RR_SIGNALING_MESSAGE_C, b'\x00' * 50, log_header=None)
        
        # Simulating 3G packet
        dumper.on_log(WCDMA_SIGNALLING_MESSAGE, b'\x00' * 100, log_header=None)
        
        # Simulating 4G packet
        dumper.on_log(LOG_LTE_RRC_OTA_MSG_LOG_C, b'\x00' * 150, log_header=None)
        
        # Simulating 5G packet
        dumper.on_log(LOG_NR_RRC_OTA_MSG_LOG_C, b'\x00' * 200, log_header=None)
        
        # Simulating IP packet
        dumper.on_log(LOG_DATA_PROTOCOL_LOGGING_C, b'\x00' * 500, log_header=None)
        
        self.assertEqual(dumper.total_packets, 5)
        self.assertEqual(dumper.total_bytes, 1000)
        
        self.assertEqual(dumper.rat_stats['2g']['packets'], 1)
        self.assertEqual(dumper.rat_stats['2g']['bytes'], 50)
        
        self.assertEqual(dumper.rat_stats['3g']['packets'], 1)
        self.assertEqual(dumper.rat_stats['3g']['bytes'], 100)
        
        self.assertEqual(dumper.rat_stats['4g']['packets'], 1)
        self.assertEqual(dumper.rat_stats['4g']['bytes'], 150)
        
        self.assertEqual(dumper.rat_stats['5g']['packets'], 1)
        self.assertEqual(dumper.rat_stats['5g']['bytes'], 200)
        
        self.assertEqual(dumper.rat_stats['ip']['packets'], 1)
        self.assertEqual(dumper.rat_stats['ip']['bytes'], 500)

    def test_format_summary_output(self):
        dumper = StatsDumper(diag_input=None)
        dumper.on_log(LOG_NR_RRC_OTA_MSG_LOG_C, b'\x01\x02\x03\x04', log_header=None)
        
        summary_str = dumper.format_summary()
        self.assertIn("AirTap Telemetry & Capture Summary", summary_str)
        self.assertIn("Total Packets:     1", summary_str)
        self.assertIn("5G   :", summary_str)


if __name__ == '__main__':
    unittest.main()
