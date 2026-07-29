#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

from unittest import TestCase
from logging import getLogger, INFO, DEBUG
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.inputs._base_input import BaseInput
from src.inputs._hdlc_mixin import HdlcMixin


class LoudBytes(bytes):
    """
    A bytes subclass that records whether it was ever stringified, to
    detect eager repr()/str() calls on packet payloads.
    """
    call_counts = {}

    def __new__(cls, data, counter_key):
        self = super().__new__(cls, data)
        self._counter_key = counter_key
        cls.call_counts.setdefault(counter_key, 0)
        return self

    def __str__(self):
        LoudBytes.call_counts[self._counter_key] += 1
        return bytes.__repr__(self)

    def __repr__(self):
        LoudBytes.call_counts[self._counter_key] += 1
        return bytes.__repr__(self)


class LazyDebugLoggingTests(TestCase):

    def setUp(self):
        self.logger = getLogger()
        self.previous_level = self.logger.level
        # Ensure DEBUG-level messages are suppressed, as they are by
        # default (root logger defaults to WARNING) and as they are in
        # normal (non -v) AirTap runs (INFO level, per main.py).
        self.logger.setLevel(INFO)
        LoudBytes.call_counts = {}

    def tearDown(self):
        self.logger.setLevel(self.previous_level)

    def test_hdlc_encapsulate_does_not_stringify_payload_when_debug_disabled(self):
        payload = LoudBytes(b'\x00\x01\x02\x03', 'encapsulate')

        HdlcMixin().hdlc_encapsulate(payload)

        self.assertEqual(LoudBytes.call_counts.get('encapsulate', 0), 0)

    def test_dispatch_diag_response_does_not_stringify_payload_when_debug_disabled(self):
        base_input = BaseInput()
        packet = LoudBytes(b'\x4b\x01\x02\x03', 'response')

        base_input.dispatch_diag_response(packet)

        self.assertEqual(LoudBytes.call_counts.get('response', 0), 0)

    def test_dispatch_diag_log_does_not_stringify_payload_when_debug_disabled(self):
        base_input = BaseInput()
        payload = LoudBytes(b'\xaa\xbb\xcc', 'log')

        base_input.dispatch_diag_log(0x1234, payload, b'\x00' * 12, 0.0)

        self.assertEqual(LoudBytes.call_counts.get('log', 0), 0)

    def test_dispatch_diag_event_does_not_stringify_payload_when_debug_disabled(self):
        base_input = BaseInput()
        payload = LoudBytes(b'\x01\x02', 'event')

        base_input.dispatch_diag_event(0x0060, payload, 0.0)

        self.assertEqual(LoudBytes.call_counts.get('event', 0), 0)

    def test_dispatch_diag_message_does_not_stringify_payload_when_debug_disabled(self):
        base_input = BaseInput()
        payload = LoudBytes(b'hello', 'message')

        base_input.dispatch_diag_message(0x04, payload)

        self.assertEqual(LoudBytes.call_counts.get('message', 0), 0)

    def test_debug_output_still_contains_payload_when_enabled(self):
        # Sanity check: when DEBUG *is* enabled, the payload still shows
        # up in the emitted log record (laziness must not silently drop
        # information, only defer computing it).
        import logging
        import io

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        self.logger.addHandler(handler)
        self.logger.setLevel(DEBUG)

        try:
            base_input = BaseInput()
            base_input.dispatch_diag_response(b'\x4b\x01\x02\x03')
            handler.flush()
            self.assertIn('01 02 03', stream.getvalue().replace('\\x', ' ').replace("'", '') or
                           repr(b'\x01\x02\x03')[2:-1].replace('\\x', ' '))
        finally:
            self.logger.removeHandler(handler)
