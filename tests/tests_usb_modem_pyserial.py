#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

from unittest import TestCase
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.inputs.usb_modem_pyserial import UsbModemPyserialConnector
from src.inputs._hdlc_mixin import HdlcMixin


class FakeSerial:
    """
    A minimal stand-in for pyserial's Serial object, exposing just the
    ``in_waiting`` property and ``read(size)`` method used by
    UsbModemPyserialConnector._read_frame.

    :param chunks: A list of byte strings. Each call to read() consumes
        bytes from the front of the concatenated stream. ``in_waiting``
        reports the total number of bytes remaining across all
        not-yet-consumed chunks, matching real pyserial semantics where
        in_waiting reports the entire OS receive buffer, not just the
        current burst.
    """

    def __init__(self, chunks):
        self._chunks = [bytearray(c) for c in chunks]
        self.read_call_count = 0

    @property
    def in_waiting(self):
        return sum(len(c) for c in self._chunks)

    def read(self, size=1):
        self.read_call_count += 1
        if not self._chunks:
            return b''
        chunk = self._chunks[0]
        taken = bytes(chunk[:size])
        del chunk[:size]
        if not chunk:
            self._chunks.pop(0)
        return taken


class FrameReaderUnderTest(UsbModemPyserialConnector):
    """
    Bypasses the real __init__ (which touches actual devices), keeping
    only what _read_frame needs: self.serial and the HdlcMixin class
    attributes (TRAILER_CHAR etc.), which are inherited unchanged.
    """

    def __init__(self, serial):
        self.serial = serial
        self.packet_buffer = b''


class UsbModemPyserialReadFrameTests(TestCase):

    def test_read_frame_returns_bytes_available_in_one_chunk(self):
        # A full HDLC frame arrives in a single OS-level read chunk.
        hdlc = HdlcMixin()
        frame = hdlc.hdlc_encapsulate(b'\x00\x01\x02\x03\x04\x05')

        serial = FakeSerial([frame])
        reader = FrameReaderUnderTest(serial)

        result = reader._read_frame()

        self.assertEqual(result, frame)
        # The whole frame was available at once (in_waiting reports its
        # full length), so only one read() call should have occurred -
        # proving this is not a byte-at-a-time loop.
        self.assertEqual(serial.read_call_count, 1)

    def test_read_frame_handles_trickling_bytes(self):
        # Bytes arrive one at a time (in_waiting == 1 each call), as
        # would happen under worst-case OS buffering. Correctness must
        # still hold even though this degrades to one read() per byte.
        hdlc = HdlcMixin()
        frame = hdlc.hdlc_encapsulate(b'\x10\x20\x30')

        serial = FakeSerial([bytes([b]) for b in frame])
        reader = FrameReaderUnderTest(serial)

        result = reader._read_frame()

        self.assertEqual(result, frame)
        self.assertEqual(serial.read_call_count, len(frame))

    def test_read_frame_stops_at_real_trailer_not_escaped_one(self):
        # A payload containing an escaped trailer byte (0x7d 0x5e) in the
        # middle must not cause _read_frame to stop early - only the
        # final, unescaped 0x7e should terminate the frame.
        hdlc = HdlcMixin()
        payload_with_trailer_byte = b'\x01\x7e\x02'
        frame = hdlc.hdlc_encapsulate(payload_with_trailer_byte)

        self.assertIn(hdlc.ESC_TRAILER, frame[:-1])  # sanity check on the fixture

        serial = FakeSerial([frame])
        reader = FrameReaderUnderTest(serial)

        result = reader._read_frame()

        self.assertEqual(result, frame)
        decapsulated = hdlc.hdlc_decapsulate(result)
        self.assertEqual(decapsulated, payload_with_trailer_byte)

    def test_read_frame_raises_on_closed_port(self):
        # An empty read() (port closed or preempted) must surface as an
        # exception so read_loop's error-handling path can catch it.
        serial = FakeSerial([])
        reader = FrameReaderUnderTest(serial)

        with self.assertRaises(ConnectionError):
            reader._read_frame()

    def test_read_frame_returns_one_frame_at_a_time_when_multiple_are_buffered(self):
        # Multiple full HDLC frames arrive in the OS receive buffer at
        # once (the normal case under load). _read_frame must return
        # them one at a time, not merge them into a single blob.
        hdlc = HdlcMixin()
        frame1 = hdlc.hdlc_encapsulate(b'\x01\x02\x03')
        frame2 = hdlc.hdlc_encapsulate(b'\x04\x05\x06')
        frame3 = hdlc.hdlc_encapsulate(b'\x07\x08\x09')

        serial = FakeSerial([frame1 + frame2 + frame3])
        reader = FrameReaderUnderTest(serial)
        reader.packet_buffer = b''

        self.assertEqual(reader._read_frame(), frame1)
        self.assertEqual(reader._read_frame(), frame2)
        self.assertEqual(reader._read_frame(), frame3)

    def test_read_frame_retains_partial_trailing_frame_for_next_call(self):
        # A batch containing one full frame plus the start of a second
        # (incomplete) frame must return only the complete frame, and
        # retain the partial bytes for the next call.
        hdlc = HdlcMixin()
        frame1 = hdlc.hdlc_encapsulate(b'\xaa\xbb')
        frame2 = hdlc.hdlc_encapsulate(b'\xcc\xdd')
        partial_frame2 = frame2[:2]  # incomplete - no trailer yet

        serial = FakeSerial([frame1 + partial_frame2, frame2[2:]])
        reader = FrameReaderUnderTest(serial)
        reader.packet_buffer = b''

        self.assertEqual(reader._read_frame(), frame1)
        self.assertEqual(reader._read_frame(), frame2)
