#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
from struct import pack
import time
import os

from src.inputs.session_replay import SessionReplayer, ReplayFrame
from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C, LOG_NR_RRC_OTA_MSG_LOG_C
from src.protocol.gsmtap import build_gsmtap_ip, GSMTAP_TYPE_LTE_RRC


class TestSessionReplay(unittest.TestCase):

    def setUp(self):
        # Create a mock PCAP in memory with 5 packets
        self.pcap_bytes = bytearray()
        # PCAP Global Header: magic 0xa1b2c3d4, ver 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 101 (Raw IP)
        self.pcap_bytes.extend(pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))

        base_ts = 1600000000.0
        for i in range(5):
            ts = base_ts + i * 0.5
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1e6)

            raw_pdu = b'\x08\x00' + bytes([i] * 6)
            pkt_data = build_gsmtap_ip(GSMTAP_TYPE_LTE_RRC, 0, raw_pdu, False)
            pkt_hdr = pack('<IIII', ts_sec, ts_usec, len(pkt_data), len(pkt_data))

            self.pcap_bytes.extend(pkt_hdr + pkt_data)

    def test_replayer_load_and_indexing(self):
        events = []
        replayer = SessionReplayer(raw_bytes=bytes(self.pcap_bytes), on_event_callback=lambda evt, data: events.append((evt, data)))

        self.assertEqual(len(replayer.frames), 5)
        self.assertAlmostEqual(replayer.get_duration(), 2.0, places=2)
        self.assertEqual(replayer.state, SessionReplayer.STATE_PAUSED)
        self.assertTrue(any(e[0] == 'loaded' for e in events))

    def test_replayer_step_and_seek(self):
        dispatched = []
        class MockModule:
            def on_log(self, log_type, payload, hdr, ts):
                dispatched.append((log_type, payload))

        replayer = SessionReplayer(raw_bytes=bytes(self.pcap_bytes))
        mod = MockModule()
        replayer.add_module(mod)

        # Step first frame
        replayer.step()
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(replayer.current_idx, 1)

        # Seek to percentage 60%
        replayer.seek_to_percentage(60.0)
        self.assertEqual(replayer.current_idx, 3)

        # Seek to index 0
        replayer.seek_to_index(0)
        self.assertEqual(replayer.current_idx, 0)

    def test_replayer_speed_control(self):
        replayer = SessionReplayer(raw_bytes=bytes(self.pcap_bytes))
        replayer.set_speed(5.0)
        self.assertEqual(replayer.speed, 5.0)

        status = replayer.get_status()
        self.assertEqual(status['total_frames'], 5)
        self.assertEqual(status['speed'], 5.0)

    def test_read_loop_dispatches_all_frames_and_returns(self):
        # Regression: `airtap -r FILE` died with
        # "'SessionReplayer' object has no attribute 'read_loop'".
        # read_loop() must start playback itself (load() leaves the replayer
        # PAUSED) and block until every frame has been dispatched.
        dispatched = []
        class MockModule:
            def on_log(self, log_type, payload, hdr, ts):
                dispatched.append(log_type)

        replayer = SessionReplayer(raw_bytes=bytes(self.pcap_bytes))
        replayer.add_module(MockModule())
        replayer.set_speed(0)  # unthrottled, keep the test fast

        replayer.read_loop()

        self.assertEqual(len(dispatched), 5)
        self.assertEqual(replayer.state, SessionReplayer.STATE_COMPLETED)

    def test_read_loop_on_empty_capture_returns_immediately(self):
        replayer = SessionReplayer(raw_bytes=b'')
        replayer.read_loop()  # must not raise or hang
        self.assertEqual(replayer.frames, [])


if __name__ == '__main__':
    unittest.main()
