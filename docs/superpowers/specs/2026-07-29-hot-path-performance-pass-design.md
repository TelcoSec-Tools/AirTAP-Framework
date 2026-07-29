# Hot-path performance pass for live capture

Date: 2026-07-29

## Problem

Live capture throughput/latency (`--usb-modem`, `--adb`, `--tcp` combined with `--pcap-dump`/`--wireshark-live`) can fall behind under sustained traffic. A full codebase rewrite was considered but rejected as disproportionate: correctness of the protocol parsers is safety/research-critical and a rewrite risks silent decoding regressions for a performance problem that is actually caused by two narrow, identifiable hot-path inefficiencies.

## Root causes identified

1. **Byte-at-a-time serial reads** — [src/inputs/usb_modem_pyserial.py:227-272](../../../src/inputs/usb_modem_pyserial.py#L227-L272) (`UsbModemPyserialConnector.read_loop`). Each iteration calls `self.serial.read()` (one byte, one syscall) and appends via `raw_payload += char_read`, which is O(n²) for the accumulated frame. This is the input path used for `--usb-modem` and for `--adb`/`--adb-wsl2` whenever a chardev is mounted (the `resolve_usb_connector` branch in `src/main.py`), making it the most common live-capture path.

2. **Eager debug-string formatting** — `debug('...' % (..., repr(payload), ...))` call sites in `src/inputs/_base_input.py`, `src/inputs/_hdlc_mixin.py`, `src/inputs/adb.py`, and `src/modules/pcap_dump.py`. Because the `%`-formatting (including `repr()` of full packet payloads) happens as a Python expression *before* being passed to `logging.debug`, the cost is paid on every packet regardless of whether `-v`/`--verbose` is enabled.

## Non-goals

- No changes to protocol parsing/decoding logic (struct layouts, log-type dispatch, GSMTAP/pcap encoding).
- No changes to the threading model described in `docs/AirTap architecture.md`.
- No changes to `adb.py`/`tcp_connector.py` read loops — both already read in bulk chunks (10 MB `recv()` for ADB, buffered socket reads for TCP) and are not bottlenecks.
- No changes to pcap file writing — writes are not flushed per-packet already.

## Design

### 1. Buffered serial framing

Replace the manual byte-loop in `UsbModemPyserialConnector.read_loop` with `self.serial.read_until(self.TRAILER_CHAR)` (pyserial's built-in read-until-terminator, which reads in larger chunks internally rather than one Python-level `read()` call per byte). Behavior preserved exactly:
- `assert char_read` / empty-read handling → checked on the result of `read_until` instead (empty/short result still triggers the same "serial port was closed or preempted" error path).
- The `raw_payload == self.TRAILER_CHAR` ("modem seems to be unavailable") check is preserved.
- `hdlc_decapsulate` / `InvalidFrameError` / `received_first_packet` handling downstream is unchanged.

### 2. Lazy debug logging

Convert eager `%`-pre-formatted `debug(...)` calls to the stdlib `logging` lazy form: `debug('...%s...', arg1, arg2)` instead of `debug('...%s...' % (arg1, arg2))`. The `logging` module only performs the substitution if the DEBUG level is actually enabled, so `repr()`/formatting cost on packet payloads disappears entirely in the default (non-verbose) run. Applies to the identified call sites in `_base_input.py`, `_hdlc_mixin.py`, `adb.py`, `pcap_dump.py`. `info`/`warning`/`error` call sites are not in scope (not per-packet hot path).

## Testing

- Existing suite (`tests/tests_hdlc.py`, `tests/tests_tcp_connector.py`, `tests/tests_usbmodem_argparser.py`) must continue to pass unmodified — framing/CRC behavior is not changing.
- New test: confirm `read_until`-based framing in `UsbModemPyserialConnector` produces byte-identical output to the previous byte-loop implementation for (a) a clean frame, and (b) a frame containing an escaped trailer byte (`0x7d 0x5e`) mid-payload, using a mocked/fake serial object.
