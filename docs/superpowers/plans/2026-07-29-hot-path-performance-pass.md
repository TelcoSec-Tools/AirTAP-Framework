# Hot-Path Performance Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove two identified hot-path inefficiencies in AirTap's live-capture path (byte-at-a-time serial reads; eager debug-string formatting on every packet) without touching any protocol-parsing logic.

**Architecture:** Two independent, additive changes. Task 1 replaces the byte-loop in `UsbModemPyserialConnector.read_loop` with a chunked read using `serial.in_waiting`, extracted into a separately-testable `_read_frame` method. Task 2 converts eager `%`-pre-formatted `debug(...)` calls in the packet-dispatch hot path to the stdlib `logging` lazy form, so no formatting/`str()` work happens when `-v`/`--verbose` is off.

**Tech Stack:** Python 3, `pyserial`, stdlib `unittest`, stdlib `logging`.

## Global Constraints

- No changes to protocol parsing/decoding logic (struct layouts, log-type dispatch, GSMTAP/pcap encoding).
- No changes to the threading model.
- No changes to `adb.py`/`tcp_connector.py` read loops (already bulk reads, not bottlenecks) or to pcap file writing (not flushed per-packet already).
- Existing tests (`tests/tests_hdlc.py`, `tests/tests_tcp_connector.py`, `tests/tests_usbmodem_argparser.py`) must continue to pass unmodified.
- Run tests from the repo root with: `python -m pytest tests/<file>.py -v` (or `python -m unittest tests.<file>` — check which the repo's existing tests use; `tests/tests_hdlc.py` uses `unittest.TestCase`, so use `python -m unittest tests.tests_hdlc -v` style invocations for consistency).

---

## Task 1: Chunked serial framing in `UsbModemPyserialConnector`

**Files:**
- Modify: `src/inputs/usb_modem_pyserial.py:227-272` (replace `read_loop`, add `_read_frame`)
- Test: Create `tests/tests_usb_modem_pyserial.py`

**Interfaces:**
- Consumes: `HdlcMixin.TRAILER_CHAR` (class attribute, `b'\x7e'`), `HdlcMixin.hdlc_encapsulate`/`hdlc_decapsulate`/`InvalidFrameError` (unchanged, from `src/inputs/_hdlc_mixin.py`).
- Produces: `UsbModemPyserialConnector._read_frame(self) -> bytes` — reads from `self.serial` into a residual `self.packet_buffer` until a trailer byte is found, then returns exactly one frame (up to and including the first trailer byte), retaining any bytes read past that trailer for the next call. This is necessary because `in_waiting` reports the entire OS receive buffer, not just the current frame's bytes — under load, multiple frames are commonly buffered at once, and returning them all concatenated would corrupt CRC validation downstream. Raises `ConnectionError` if the serial port returns no data (closed/preempted). Used internally by `read_loop`; also the target of direct unit testing since `read_loop` itself runs an unbounded `while True` and calls `exit()` on error paths, making it unsuitable to unit test directly.

### Step 1: Write the failing tests

Create `tests/tests_usb_modem_pyserial.py`:

```python
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
```

### Step 2: Run the tests to verify they fail

Run: `python -m unittest tests.tests_usb_modem_pyserial -v`

Expected: `ImportError` or `AttributeError` — `_read_frame` does not exist yet on `UsbModemPyserialConnector`.

### Step 3: Implement `_read_frame` and rewrite `read_loop`

`in_waiting` reports the size of pyserial's *entire* OS receive buffer,
not just the bytes belonging to the frame currently being assembled.
Under load it is normal for two or more Diag frames to already be
sitting in that buffer at once, so a naive
`while not raw_payload.endswith(TRAILER_CHAR): raw_payload += serial.read(serial.in_waiting)`
loop will read past the first frame's trailer into the next frame(s),
return a multi-frame blob as if it were one frame, and cause
`hdlc_decapsulate` to fail CRC validation (silently dropping the whole
batch via `read_loop`'s `except InvalidFrameError: continue`).

To avoid this, `_read_frame` keeps a residual buffer (`self.packet_buffer`)
across calls: it accumulates chunks into that buffer until at least one
trailer byte is present, then splits off and returns exactly one frame
(everything up to and including the first trailer byte), leaving any
extra bytes — which belong to the next frame — buffered for the next
call. This is the same accumulate-and-split-on-trailer pattern already
used by `tcp_connector.py` and `adb.py`.

In `src/inputs/usb_modem_pyserial.py`, add `self.packet_buffer = b''` in
`__init__` (alongside `self.received_first_packet = False`, before the
`super().__init__()` call), and replace lines 227-272 (the existing
`read_loop` method) with:

```python
    def _read_frame(self):
        
        """
            Read bytes from the serial port until a trailer byte is found,
            minimizing the number of read() calls by consuming all bytes
            already buffered by the OS/driver at once (via in_waiting),
            instead of reading one byte per call. Any bytes read past the
            first trailer (belonging to the next frame) are retained in
            self.packet_buffer for the next call.
            
            :returns: The raw (still HDLC-escaped) frame, including the
                trailing 0x7e byte.
            :raises ConnectionError: if the serial port returned no data
                (closed or preempted by another process).
        """
        
        while self.TRAILER_CHAR not in self.packet_buffer:
            
            bytes_waiting = self.serial.in_waiting
            
            chunk = self.serial.read(bytes_waiting if bytes_waiting > 0 else 1)
            
            if not chunk:
                raise ConnectionError('Serial port returned no data (closed or preempted)')
            
            self.packet_buffer += chunk
        
        raw_payload, self.packet_buffer = self.packet_buffer.split(self.TRAILER_CHAR, 1)
        
        return raw_payload + self.TRAILER_CHAR
    
    def read_loop(self):
        
        while True:
            
            try:
                raw_payload = self._read_frame()
            
            except Exception:
                error('\nThe serial port was closed or preempted by another process.')
                
                exit()
            
            # Decapsulate and dispatch
            
            if raw_payload == self.TRAILER_CHAR:
                error('The modem seems to be unavailable.')
                
                exit()
            
            try:
            
                unframed_message = self.hdlc_decapsulate(
                    payload = raw_payload
                )
            
            except self.InvalidFrameError:
                
                # The first packet that we receive over the Diag input may
                # be partial
                
                continue
            
            finally:
                
                self.received_first_packet = True
            
            self.dispatch_received_diag_packet(unframed_message)
```

### Step 4: Run the tests to verify they pass

Run: `python -m unittest tests.tests_usb_modem_pyserial -v`

Expected: all 6 tests PASS.

### Step 5: Run the existing HDLC test suite to confirm no regression

Run: `python -m unittest tests.tests_hdlc -v`

Expected: all tests PASS (unchanged, since `_read_frame` doesn't touch `HdlcMixin`).

### Step 6: Commit

```bash
git add src/inputs/usb_modem_pyserial.py tests/tests_usb_modem_pyserial.py
git commit -m "perf: read serial frames in chunks instead of byte-at-a-time"
```

---

## Task 2: Lazy debug logging on the packet-dispatch hot path

**Files:**
- Modify: `src/inputs/_base_input.py:399,410,419,429`
- Modify: `src/inputs/_hdlc_mixin.py:35`
- Test: Create `tests/tests_lazy_debug_logging.py`

**Interfaces:**
- Consumes: `BaseInput` (`src/inputs/_base_input.py`, constructible standalone via `BaseInput()` — its `__init__` only sets up threading primitives and lists, no device I/O), `HdlcMixin` (`src/inputs/_hdlc_mixin.py`).
- Produces: no new public interface — behavior-preserving change to what arguments are passed to the stdlib `logging.debug()` calls already present at the 5 call sites above.

**Note on scope:** `src/inputs/adb.py`'s two `debug()` calls (lines 61, 65) were checked during planning and are **not** included here: the string they log (`result_string` on line 63) is computed unconditionally before the `debug()` call regardless of log level (it's also used in the `if result and result_string:` condition right after), so converting that specific call to lazy form would not remove any work — there's nothing to fix there. `src/modules/pcap_dump.py` has no `debug()` calls at all (verified via grep). The spec's intent — removing eager `repr()`/formatting cost from the per-packet path — is fully addressed by the two files below, which are the ones actually invoked once per received Diag packet/log/message/event.

### Step 1: Write the failing tests

Create `tests/tests_lazy_debug_logging.py`:

```python
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
```

Note on the last test: it's intentionally loose (checks the payload bytes appear in *some* recognizable form in the emitted text) since the exact `%s`-vs-`%r` rendering of a `bytes` object depends on the format spec chosen in Step 3 — it exists to catch the failure mode where laziness is implemented by silently dropping the argument rather than deferring its formatting.

### Step 2: Run the tests to verify they fail

Run: `python -m unittest tests.tests_lazy_debug_logging -v`

Expected: the five `does_not_stringify` tests FAIL (call counts are 1, not 0) against the current eager-formatting code; the sanity-check test PASSES already.

### Step 3: Convert the 5 call sites to lazy form

In `src/inputs/_hdlc_mixin.py`, line 35, replace:

```python
    def hdlc_encapsulate(self, payload: bytes) -> bytes:
        if payload:
            debug('[>] Sending request %s of length %d: %s' % (get_message_name(payload[0]), len(payload[1:]), payload[1:]))
```

with:

```python
    def hdlc_encapsulate(self, payload: bytes) -> bytes:
        if payload:
            debug('[>] Sending request %s of length %d: %s', get_message_name(payload[0]), len(payload[1:]), payload[1:])
```

In `src/inputs/_base_input.py`, replace the four call sites:

Line 399:
```python
        debug('[<] Received response %s of length %d: %s' % (get_message_name(opcode), len(payload), repr(payload)))
```
becomes:
```python
        debug('[<] Received response %s of length %d: %s', get_message_name(opcode), len(payload), payload)
```

Line 410:
```python
        debug('[<] Received log 0x%04x of length %d: %s' % (log_type, len(log_payload), repr(log_payload)))
```
becomes:
```python
        debug('[<] Received log 0x%04x of length %d: %s', log_type, len(log_payload), log_payload)
```

Line 419:
```python
        debug('[<] Received event 0x%04x of length %d: %s' % (event_id, len(event_payload), repr(event_payload)))
```
becomes:
```python
        debug('[<] Received event 0x%04x of length %d: %s', event_id, len(event_payload), event_payload)
```

Line 429:
```python
        debug('[<] Received message with opcode %s of length %d: %s' % (get_message_name(opcode), len(payload), repr(payload)))
```
becomes:
```python
        debug('[<] Received message with opcode %s of length %d: %s', get_message_name(opcode), len(payload), payload)
```

(Dropping the explicit `repr(...)` wrapper is intentional and behavior-preserving: `bytes` has no `__str__` override, so `%s` formatting of a raw `bytes` object already produces the same output as `repr()` — moving the value itself into the lazy `*args` is what defers the cost; wrapping it in `repr(...)` here would defeat the laziness, since `repr()` would still run eagerly as a function-call argument.)

### Step 4: Run the tests to verify they pass

Run: `python -m unittest tests.tests_lazy_debug_logging -v`

Expected: all 6 tests PASS.

### Step 5: Run the full existing test suite to confirm no regression

Run:
```bash
python -m unittest tests.tests_hdlc tests.tests_tcp_connector tests.tests_usbmodem_argparser tests.tests_usb_modem_pyserial tests.tests_lazy_debug_logging -v
```

Expected: all tests PASS.

### Step 6: Commit

```bash
git add src/inputs/_base_input.py src/inputs/_hdlc_mixin.py tests/tests_lazy_debug_logging.py
git commit -m "perf: defer debug-log payload formatting until logging is enabled"
```
