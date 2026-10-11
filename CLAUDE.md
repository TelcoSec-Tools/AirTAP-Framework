# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AirTap is a cellular radio diagnostics, packet capture, and security auditing framework. It talks to Qualcomm basebands over the Diag protocol (via rooted Android/ADB, USB modems, or TCP) and decodes raw 2G/3G/4G/5G NR signaling into GSMTAP v2 PCAP/live Wireshark streams. It also includes a security auditor (null ciphering/integrity, IMSI catchers, Silent SMS, SIMjacker, CALEA/LI detection), a pure-Python 3GPP ASN.1 UPER/PER engine, an EFS filesystem shell, NVRAM/band-locking tools, a protocol fuzzer, and a web-based GUI ("Visual Operations Suite").

## Commands

```bash
# Install in editable mode (dev)
pip install -e .[dev]

# Run full test suite (pytest is canonical; CI also runs the unittest runner)
pytest
python tests/tests.py
python -m unittest discover -s tests

# Run a single test file / test case
pytest tests/tests_sec_audit.py
pytest tests/tests_sec_audit.py::ClassName::test_method
python -m unittest tests.tests_sec_audit

# Syntax / lint check (what CI's lint job runs)
python -m compileall src tests
flake8 src tests --count --select=E9,F63,F7,F82 --show-source --statistics

# Build distribution artifacts
python -m build
twine check dist/*
```

Entry point: `airtap.py` (also installed as the `airtap` console script via `src/main.py:main`). Run `airtap --help` vs `airtap --help-advanced` — most forensic/low-level flags are hidden from standard `--help` (see `build_parser(advanced=...)` in `src/main.py`).

CI (`.github/workflows/ci.yml`) runs lint → test (matrix across ubuntu/windows/macos × Python 3.8–3.13) → build, and the build job explicitly verifies the wheel contains the `.lua` dissectors and that `adb_linux`/`adb_macos` keep their executable bit (this is why the build job intentionally runs on Linux only — Windows checkouts lose the exec bit on NTFS).

## Architecture

The codebase splits into two building blocks under `src/`, documented in `docs/AirTap architecture.md` and `docs/The Diag protocol.md` (read these for anything involving threading or the wire protocol — don't re-derive it from scratch):

- **`src/inputs/`** — classes providing a source of Diag protocol data: live devices (`adb.py`, `adb_wsl2.py`, USB modem via pyserial/pyusb) or file replay (`dlf_read.py`, `pcap_read.py`, `shannon_read.py`, `mtk_read.py`, `json_geo_read.py`, `session_replay.py`). All inherit from `_base_input.py:BaseInput`, which provides `send_recv` (synchronous request/response) and dispatches received packets. HDLC framing/deframing lives in `_hdlc_mixin.py`.
- **`src/modules/`** — classes that use an input to perform one task each (PCAP dump, live Wireshark, security audit, EFS shell, NV manager, fuzzer, GUI server, etc.), selected and wired up by CLI flags in `src/main.py`.
- **`src/protocol/`** — protocol constants/decoders shared by modules: GSMTAP encapsulation (`gsmtap.py`), the ASN.1 UPER/PER engine (`asn1_uper.py`, `rrc_asn1_dissector.py`), identity/SMS/LPP/eCall dissectors, EFS format (`efs2.py`), ETSI LI (`etsi_li.py`), QXDM constants.

### Threading model

Threading (not asyncio/polling) is the deliberate concurrency choice, because polling a serial port alongside a command prompt/thread queue isn't portable. Three thread roles:
- **Main thread**: the only place that reads from the device; dispatches `on_log`/`on_message` callbacks to modules and `on_deinit` at teardown.
- **Background thread**: initializes modules (`on_init` callbacks, which may write to the device).
- **Interactive prompt thread** (`--cli`): edge case, also initializes modules it invokes.

A real Diag device accepts only one client at a time, so `send_recv` pauses the calling callback's thread using a shared synchronization primitive until the response arrives.

### Module API contract

Modules (`src/modules/*.py`) are plain classes, not required to subclass anything, instantiated with `(diag_input, *cli_args)`:
- `on_init(self)` — called once the Diag device connection is established (skipped when replaying from a file).
- `on_log(self, log_type, log_payload, log_header, timestamp)` — async "log" structures (raw traffic); requires mixing in `_enable_log_mixin.py:EnableLogMixin`.
- `on_message(self, ...)` — async text "message" structures.
- `on_deinit(self)` — connection teardown (not called on file replay).
- `__del__(self)` — unconditional cleanup, called in all cases including file replay.

### Input API contract

Inputs (`src/inputs/*.py`) subclass `BaseInput` and implement:
- `send_request(self, packet_type, packet_payload)` — send a Diag request (uses `HdlcMixin.hdlc_encapsulate` where framing applies).
- `read_loop(self)` — reads from the device/file and calls `self.dispatch_received_diag_packet(unframed_packet)` per packet.

Modules should only call `send_recv` on the input directly; everything else is internal plumbing.

### CLI wiring

`src/main.py` resolves exactly one `diag_input` from the mutually-exclusive source flags (replay, Shannon/MTK/PCAP/DLF/JSON-geo file reads, ADB/ADB-WSL2, TCP, USB modem), falling back to auto-detection (USB DIAG probe, then ADB) if none is given. It then attaches zero or more modules via `diag_input.add_module(...)` based on action flags (`-o`/`-l`/`-s`/`--audit`/`--shell`/`--gui`/etc.) before calling `diag_input.run()`. `--cli` and `--shell` (EFS shell) are mutually exclusive with other standalone modules — check `parse_modules_args` in `src/main.py` before adding a new action flag.

## Conventions (from CONTRIBUTING.md)

- Support Python 3.6+ through 3.13 — avoid syntax/stdlib features exclusive to newer versions without a fallback.
- Lazy logging on hot capture paths (`_base_input.py`, `usb_modem_pyserial.py`): defer byte-formatting/debug string construction so it costs nothing when debug logging is off.
- Diag/serial streams deliver partial, corrupt, or interleaved frames — parsers must degrade gracefully, never crash the main capture loop.
- No stub/mockup code; new features need accompanying tests in `tests/tests_<module_name>.py` covering boundary conditions and malformed frames, not just the happy path.
