# Architecture

Two building blocks under `src/`, plus a shared protocol layer.

```
  Hardware / files
        │
        ▼
┌───────────────────┐   src/inputs/   — provide DIAG data
│   Input           │   BaseInput: send_recv(), read_loop()
│   (one per run)   │   HdlcMixin:  framing / deframing
└─────────┬─────────┘
          │  dispatch_received_diag_packet()
          ▼
┌───────────────────┐   src/modules/  — one task each
│   Modules         │   on_init / on_log / on_message / on_deinit
│   (zero or more)  │
└─────────┬─────────┘
          ▼
   PCAP · Wireshark · JSON · GUI · shell
```

`src/protocol/` holds what both share: GSMTAP encapsulation, the ASN.1 UPER/PER engine,
identity/SMS/LPP/eCall dissectors, EFS2 structures, ETSI LI, and QXDM constants.

---

## Threading

Threading, not asyncio. Polling a serial port alongside a command prompt and a thread
queue is not portable, so AirTap uses three explicit roles:

| Thread | Responsibility |
| :--- | :--- |
| **Main** | The only thread that reads from the device. Dispatches `on_log` / `on_message`, and `on_deinit` at teardown. |
| **Background** | Runs module `on_init` callbacks, which may write to the device. |
| **Interactive prompt** | `--cli` only; also initialises the modules it invokes. |

A real DIAG device accepts **one client at a time**. `send_recv` therefore pauses the
calling thread on a shared synchronisation primitive until its response arrives, rather
than interleaving requests.

---

## Input contract

Inputs subclass `BaseInput` (`src/inputs/_base_input.py`) and implement:

```python
send_request(self, packet_type, packet_payload)   # uses HdlcMixin where framing applies
read_loop(self)                                   # calls dispatch_received_diag_packet()
```

`BaseInput` supplies `send_recv` for synchronous request/response and dispatches
received packets to attached modules. Modules should call **only** `send_recv` on an
input; everything else is internal plumbing.

Implementations: `adb.py`, `adb_wsl2.py`, `usb_modem_pyserial.py`, `tcp_connector.py`
for live sources; `pcap_read.py`, `dlf_read.py`, `shannon_read.py`, `mtk_read.py`,
`json_geo_read.py`, `session_replay.py` for files.

---

## Module contract

Modules are plain classes — no base class required — constructed as
`(diag_input, *cli_args)`:

| Hook | When |
| :--- | :--- |
| `on_init(self)` | Connection established. **Skipped on file replay.** |
| `on_log(self, log_type, log_payload, log_header, timestamp)` | Async log structures (raw traffic). Requires `EnableLogMixin`. |
| `on_message(self, ...)` | Async text message structures |
| `on_deinit(self)` | Teardown. **Not called on file replay.** |
| `__del__(self)` | Unconditional cleanup, including replay |

The replay asymmetry matters: anything that must happen in every mode belongs in
`__del__`, not `on_deinit`.

---

## CLI wiring

`src/main.py` resolves **exactly one** `diag_input` from the mutually exclusive source
flags, falling back to auto-detection (USB DIAG probe, then ADB). It then attaches zero
or more modules via `diag_input.add_module(...)` and calls `diag_input.run()`.

`--cli` and `--shell` are standalone and cannot combine with other action flags — check
`parse_modules_args` before adding a new action flag.

---

## Design constraints

**Degrade, never crash.** DIAG and serial streams deliver partial, corrupt and
interleaved frames. Parsers must tolerate all three; an exception escaping into the
main capture loop ends the capture.

**Lazy logging on hot paths.** In `_base_input.py` and `usb_modem_pyserial.py`, defer
byte-formatting and debug-string construction so it costs nothing when debug logging is
off.

**Deterministic decoding.** Fields are read at their specified offsets or through
decoded-field lookups, never located by scanning for byte patterns. See
[Security Auditing](Security-Auditing.md).

## Further reading

- `docs/AirTap architecture.md` — the long-form design document
- `docs/The Diag protocol.md` — wire protocol details
