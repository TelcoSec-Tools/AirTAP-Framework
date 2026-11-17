# CLI Reference

```bash
airtap [source] [outputs] [filters]
airtap --help              # common options
airtap --help-advanced     # every expert, forensic and low-level flag
```

Most forensic and low-level flags are hidden from the standard `--help` to keep it
readable. `--help-advanced` is the complete surface.

---

## Input sources

Auto-detected if omitted: AirTap probes for a USB DIAG interface first, then ADB.

| Flag | Purpose |
| :--- | :--- |
| `-a`, `--adb` | Capture from a rooted Android phone over ADB |
| `-m [DEV]`, `--usb-modem [DEV]` | USB modem or COM/tty port (default `auto`) |
| `-t IP:PORT`, `--tcp IP:PORT` | Remote TCP DIAG service |
| `-r FILE`, `--replay FILE` | Replay a recording (`.pcap`, `.dlf`, `.json`) |
| `-w [PATH]`, `--adb-wsl2 [PATH]` | Android via the WSL2 ADB bridge |
| `--shannon-read FILE` | Samsung Shannon / Exynos trace |
| `--mtk-read FILE` | MediaTek Dimensity / Helio trace |

## Outputs and modules

| Flag | Purpose |
| :--- | :--- |
| `-g`, `--gui` | Launch the Visual Operations Suite |
| `-l`, `--wireshark-live` | Open Wireshark and stream live |
| `-s`, `--stats` | Real-time packet statistics and RF telemetry |
| `-o FILE`, `--pcap FILE` | Write GSMTAP frames to PCAP |
| `-q FILE`, `--qmdl FILE` | Write a Qualcomm QMDL2 container |
| `--sec-audit` | Enable the 88-rule security auditor |
| `--audit-log FILE` | Write structured findings to JSON |
| `--install-plugins` | Deploy the Wireshark Lua dissectors |
| `--shell` | Interactive EFS filesystem shell |
| `--info` | Query modem model, firmware and chip ID |
| `--messages`, `--f3` | Stream baseband F3 debug messages |
| `--events` | Stream asynchronous modem events |
| `--benchmark` | Dissection throughput and latency benchmark |
| `--fuzz` | Run a 3GPP protocol fuzzing campaign |

## Filters and tuning

| Flag | Purpose |
| :--- | :--- |
| `--rat RATS`, `--filter-rat RATS` | Limit to RATs, e.g. `4g,5g` or `2g,3g` |
| `--logs CODES`, `--filter-logs CODES` | Limit to hex log codes, e.g. `0xb0c0,0xb821` |
| `--reassemble-sibs` | Rebuild segmented 3G/4G SIBs before encapsulation |
| `--decrypt-nas` | Attempt LTE NAS deciphering with extracted keys |
| `--include-ip` | Include user-plane IP traffic |
| `--replay-speed N` | Playback rate, e.g. `0.5`, `2.0`, `10` |
| `-v`, `--verbose` | Verbose debug logging |
| `--version` | Print version and exit |

## Baseband tools

| Flag | Purpose |
| :--- | :--- |
| `--nv-read ITEM_ID` | Read a Qualcomm NV item |
| `--nv-dump DIR` | Dump common NV items to a directory |
| `--dump-fs DIR` | Dump the modem EFS to a local directory |
| `--decoded-sibs-dump` | Print ASN.1-decoded System Information Blocks |
| `--at-cmd CMD` | Execute a single AT / DIAG command |
| `--at-macro NAME` | Run an automated diagnostic macro |

---

## Mutually exclusive

`--cli` and `--shell` are standalone modules and cannot be combined with other action
flags. Exactly one input source is used per run; if several are given, the first
matching one wins.

---

## Worked examples

```bash
# Live capture to Wireshark with telemetry
airtap -l -s

# Record and audit simultaneously
airtap -o capture.pcap --sec-audit --audit-log findings.json

# 5G NR only, reassembling SIBs, into a PCAP
airtap --rat 5g --reassemble-sibs -o nr.pcap

# Replay at double speed into the GUI
airtap -r capture.pcap --replay-speed 2.0 --gui

# Read a single NV item from an attached modem
airtap --nv-read 850

# One-shot modem interrogation
airtap --info
airtap --at-cmd "AT+CSQ"
```

## See also

- [Quick Start](Quick-Start.md) — the common combinations in context
- [Capture Sources](Capture-Sources.md) — getting each source working
