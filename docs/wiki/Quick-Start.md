# Quick Start

Five minutes from install to a decoded capture.

---

## 1. Confirm a device is reachable

```bash
airtap --info
```

Prints the modem model, firmware revision and chip ID. If this works, everything else
will. If it does not, go to [Troubleshooting](Troubleshooting.md) before anything else —
most problems are DIAG access, not AirTap.

With no source flag, AirTap auto-detects: it probes for a USB DIAG interface first,
then falls back to ADB.

---

## 2. Pick what you want to do

### Watch traffic live in Wireshark

```bash
airtap -l -s
```

`-l` opens Wireshark and streams into it; `-s` prints packet rates, RAT breakdown and
RF telemetry (RSRP/RSRQ/PCI) to the terminal.

### Record to a PCAP

```bash
airtap -o capture.pcap -s
```

The file is standard GSMTAP v2 — openable in Wireshark, `tshark`, or anything that
reads pcap.

### Open the web GUI

```bash
airtap --gui
```

Serves the Visual Operations Suite on `http://127.0.0.1:5000` and opens a browser.
See [Visual Operations Suite](Visual-Operations-Suite.md).

> The GUI is **unauthenticated** and binds to loopback deliberately. Do not expose it
> to a network.

### Audit for threats while capturing

```bash
airtap --sec-audit --audit-log findings.json -s
```

Runs the 88-rule auditor against live traffic and writes structured findings to JSON.
See [Security Auditing](Security-Auditing.md).

### Replay a recorded capture

```bash
airtap -r capture.pcap -s
airtap -r capture.pcap --gui          # scrub and step through it in the GUI
```

Replay needs no hardware, which makes it the easiest way to try AirTap.

---

## 3. Common combinations

```bash
# Rooted Android phone, live to Wireshark
airtap -a -l

# USB modem, auto-detect the port, record and audit at once
airtap -m auto -o capture.pcap --sec-audit

# 5G only, with SIB reassembly
airtap --rat 5g --reassemble-sibs -o nr.pcap

# Specific log codes only (LTE RRC OTA + NAS)
airtap --logs 0xb0c0,0xb0e2 -l

# Remote DIAG over TCP
airtap -t 192.168.1.50:2500 -l
```

---

## 4. Reading the output

A GSMTAP capture in Wireshark shows one frame per signaling message. Useful display
filters:

| Filter | Shows |
| :--- | :--- |
| `gsmtap` | everything AirTap produced |
| `lte-rrc` / `nr-rrc` | 4G / 5G radio resource control |
| `nas-eps` / `nas-5gs` | 4G / 5G non-access stratum |
| `gsm_a.dtap` | 2G Layer 3 signaling |
| `telcosec` | findings from the bundled security dissectors |

The bundled dissectors add a `TelcoSec ... Alert` field to frames they consider
suspicious, so `telcosec` alone surfaces every flagged frame in a capture.

---

## Next

- [Capture Sources](Capture-Sources.md) — getting DIAG access from each hardware type
- [CLI Reference](CLI-Reference.md) — the full flag set
- [Security Auditing](Security-Auditing.md) — what the rules detect and how to verify a finding
