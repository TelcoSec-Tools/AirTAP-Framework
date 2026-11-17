#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    Re-dumping a PCAP with --pcap-dump used to silently drop most frames: GSMTAP
    PDUs are not in the Qualcomm DIAG framing PcapDumper parses (250 of 2040
    frames survived on the bundled sample). main() now refuses that combination
    up front. DLF/QMDL/JSON replays are Qualcomm-framed and stay allowed.
"""

import os
import sys
import tempfile
import unittest
from struct import pack
from unittest.mock import patch

from src import main as airtap_main


PCAP_HEADER = pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)


class TestPcapRedumpGuard(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pcap_in = os.path.join(self.tmp.name, 'in.pcap')
        self.out = os.path.join(self.tmp.name, 'out.pcap')
        with open(self.pcap_in, 'wb') as f:
            f.write(PCAP_HEADER)

    def run_main(self, *argv):
        # main() calls logging.basicConfig, which defeats assertLogs, so
        # capture the error message at the call site instead.
        with patch.object(sys, 'argv', ['airtap', *argv]), \
             patch.object(airtap_main, 'error') as error:
            rc = airtap_main.main()
        return rc, '\n'.join(str(c.args[0]) for c in error.call_args_list)

    def test_pcap_read_with_pcap_dump_is_rejected(self):
        rc, log = self.run_main('--pcap-read', self.pcap_in, '--pcap-dump', self.out)
        self.assertEqual(rc, 1)
        self.assertIn('already a PCAP', log)

    def test_replay_of_a_pcap_with_pcap_dump_is_rejected(self):
        rc, log = self.run_main('-r', self.pcap_in, '--pcap-dump', self.out)
        self.assertEqual(rc, 1)
        self.assertIn('already a PCAP', log)

    def test_input_is_pcap_helper(self):
        class Args:
            pcap_read = None
            replay = None

        args = Args()
        self.assertFalse(airtap_main._input_is_pcap(args))

        with open(self.pcap_in, 'rb') as f:
            args.replay = f
            self.assertTrue(airtap_main._input_is_pcap(args))
            self.assertEqual(f.tell(), 0)  # position restored for the replayer

        # A Qualcomm-framed capture (QMDL magic) is not a PCAP.
        qmdl = os.path.join(self.tmp.name, 'in.qmdl')
        with open(qmdl, 'wb') as f:
            f.write(b'QMDL' + b'\x00' * 8)
        with open(qmdl, 'rb') as f:
            args.replay = f
            self.assertFalse(airtap_main._input_is_pcap(args))


if __name__ == '__main__':
    unittest.main()
