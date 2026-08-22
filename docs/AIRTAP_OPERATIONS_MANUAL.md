# AirTap Visual Operations Suite — Technical Operations & Architecture Manual
**Copyright (C) 2026 TelcoSec.net — Telecom Security Intelligence & Research**
*Version: 3.2.0-STABLE | Release Target: 3GPP Rel-17 / Qualcomm Snapdragon X65/X70/X75*

---

## 1. Executive Framework Overview

The **AirTap Visual Operations Suite** is an enterprise-grade cellular intelligence, baseband diagnostics, and wireless penetration testing framework. It interfaces with commercial cellular basebands (Qualcomm DIAG, Samsung Shannon, MediaTek) and Software-Defined Radios (SDR) to provide real-time 3GPP protocol dissection, vulnerability detection, and hardware inspection across 2G (GSM), 3G (UMTS), 4G (LTE), and 5G NR (SA/NSA).

```
+-----------------------------------------------------------------------------------+
|                        AirTap Operations Architecture                             |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Qualcomm Baseband / SDR] ---> [DIAG HDLC Engine] ---> [Dissector Pipeline]       |
|                                        |                        |                 |
|                                        v                        v                 |
|                                [AtTerminalEngine]       [TelcoSec 80 Rules]       |
|                                        |                        |                 |
|                                        +----------+-------------+                 |
|                                                   |                               |
|                                                   v                               |
|                                    [Fast HTTP / WebSocket Server]                 |
|                                                   |                               |
|                                                   v                               |
|                     [AirTap Visual Operations Web Console (10 Tabs)]               |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Dedicated Operational Subsystems (10 Tabs)

### Tab 1: Live Signaling Stream (`/live`)
- **Real-Time Protocol Dissection**: Decodes 2G, 3G, 4G, and 5G NR signaling across RRC, NAS-5GS, NAS-EPS, MAC, RLC, and SIB channels.
- **Wireshark GSMTAP PCAP Exporter**: Streams live frames encapsulated in GSMTAP over UDP port 4729 (`GET /api/packets/export_pcap`).
- **Baseband Attach State Machine**: 6-stage cellular connection timeline (`RRC Setup` -> `Security Mode` -> `5G AKA` -> `Registration Accept` -> `PDU Session` -> `DRX`).
- **Multi-Metric RF Sparklines**: Dynamic RF telemetry tracking RSRP, SINR, and KB/s throughput.

### Tab 2: Radio Security Threat Radar & 3GPP Attack Matrix (`/security`)
- **80 TelcoSec Master Vulnerability Rules (`TELCOSEC-VULN-001` through `VULN-080`)**:
  - Null Ciphering & Integrity Downgrade Detection (`EEA0`, `EIA0`, `NEA0`, `NIA0`).
  - False Base Station (IMSI Catcher) Heuristics: SIB neighbor suppression, blind redirects, TAU rejections.
  - Silent SMS (Type 0 / Ping) and stealth location probing.
  - SIMjacker & WIB proactive STK attacks.
  - ETSI TS 102 232 Lawful Interception PS-PDU surveillance detection.
- **Threat Dossier Modal**: Deep-dive remediation guidance with exact 3GPP citations.

### Tab 3: Device Subsystems & SIM Health (`/device`)
- **Hardware & Firmware Telemetry**: Qualcomm chipset identification, QFPROM secure boot state, baseband baseline revision.
- **Rel-16/17 Band Support Matrix**: Visual matrix across FR1 (sub-6GHz) and FR2 (mmWave) bands.
- **SIM / Smart Card EF Inspector**: Decodes `EF_IMSI`, `EF_LOCI`, `EF_5GS3GPPLOCI`, `EF_HPPLMN`.
- **Automated 5-Stage Diagnostic Self-Test Suite**.

### Tab 4: Cell Tower & RF Propagation Map (`/map`)
- **Cell Intel HUD**: Real-time Serving Cell PCI, EARFCN/NR-ARFCN, MNC, MCC, TAC, and Timing Advance (TA).
- **RF Propagation Analysis**: Free Space Path Loss (FSPL) and 3GPP Urban Macro path loss models.
- **Distance & Azimuth Surveillance Vectors**: Inter-tower distance, bearing, and line-of-sight analysis.
- **Tactical Transmitters Drawer & GeoJSON Export**.

### Tab 5: Qualcomm EFS Explorer (`/efs`)
- **Visual Partition Tree**: Hierarchical exploration of `/policyman`, `/nv`, `/ims`, `/sd`, `/security`, `/rrc`.
- **4-Mode File Inspector**: Text/XML viewer, 16-byte dual Hex Dump with ASCII sidecar, POSIX stat attributes, and SHA-256 integrity verification.

### Tab 6: Baseband NVRAM Manager (`/nv`)
- **Interactive 64-Bit / 128-Bit Band Mask Editor**: Bitwise visualizer with live bit-flipping and hex synchronization.
- **Pre-Configured Operator Profiles**: One-click band configurations for AT&T, Verizon, T-Mobile, Vodafone EU, DT, and 3GPP Rel-17 Global.
- **Expanded NV Catalog**: 26+ parameters including LTE B1-B85, 5G NR n1-n261, UE Cap, and VoLTE config.

### Tab 7: QXDM F3 Debug Log Console (`/f3`)
- **Real-Time Regex & Search Match Engine**: Regex jumper with next/previous matching navigation.
- **Subsystem Filter Chips**: Live counters for `RRC`, `NAS`, `PHY`, `SIM`, `IMS`, `SEC`, `CORE`, `GPS`.
- **F3 Trace Inspector Drawer**: Inspects source file origin (`modem_rrc.c:142`), line number, severity, and decoded parameters.

### Tab 8: Qualcomm DIAG & Baseband AT Terminal (`/terminal`)
- **Dual-Mode Interactive Shell**:
  - `AT>`: 3GPP AT Command Shell (`AT+CSQ`, `AT+COPS?`, `AT+CPIN?`, `AT+CRSM`).
  - `DIAG>`: Raw Qualcomm DIAG HDLC frame dispatcher (`0x00 Version`, `0x1C GUID`, `0x29 Mode Control`, `0x4B Subsystem`, `0x79 F3 Mask`).
- **Macro Engine**: Automated execution of 11-step security audits and DIAG probe sweeps.
- **Categorized 30+ Command Library**.

### Tab 9 / Tab 10: 3GPP Protocol Compliance & Mutation Fuzzer (`/fuzzer`)
- **12+ 3GPP Protocol Templates**: 5G NR RRC Reconfig, 5GMM Registration Reject, 5GMM Auth Request, LTE NAS SMC, LTE SIB1/SIB2, IMS SIP INVITE, SIM APDU.
- **6 Mutation Strategies**: Boundary values, length tamper, bit flip, truncation, extraneous IE injection, ASN.1 corruption.
- **Continuous Campaign Runner**: 1 to 50 vectors/sec with anomaly response classification.
- **Fuzz PCAP Exporter**: GSMTAP capture files for SDR replay.

### Tab 10: ETSI TS 102 232 & 3GPP TS 33.108 Lawful Interception (`/calea`)
- **PS-PDU Dissection**: Decodes Intercept Related Information (IRI) and Content of Communication (CC) headers.
- **X1 Provisioning Simulator**: `ActivateTaskRequest`, `ModifyTaskRequest`, `DeactivateTaskRequest`.
- **Anti-Wiretap Rules 076–080**: Immediate alerts on active lawful intercept taps.

---

## 3. High-Rate Telemetry & Benchmark Engine

The framework includes a built-in benchmark engine (`src/modules/benchmark_engine.py`) capable of stress-testing dissection pipelines at over **2,000 packets/sec** with sub-millisecond latency:

```bash
# Run benchmark via API
curl -X POST http://localhost:8080/api/benchmark/run -H "Content-Type: application/json" -d '{"count": 2000, "rate": 3000}'
```

---

## 4. REST API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/live`, `/security`, `/device`, `/map`, `/efs`, `/nv`, `/f3`, `/terminal`, `/calea`, `/fuzzer` | Dedicated visual page routes |
| `GET` | `/api/packets/list` | List captured packets in memory buffer |
| `GET` | `/api/packets/export_pcap` | Download standard Wireshark GSMTAP PCAP |
| `POST` | `/api/packets/clear` | Clear packet buffer |
| `GET` | `/api/geo/towers` | List cell towers and geo telemetry |
| `GET` | `/api/geo/export?format=geojson` | Export tower map data to GeoJSON |
| `GET` | `/api/efs/tree` | Fetch EFS partition directory hierarchy |
| `GET` | `/api/efs/file?path=/path` | Inspect EFS file contents with hex & SHA-256 |
| `GET` | `/api/nv/catalog` | Fetch Qualcomm NVRAM catalog & bit masks |
| `POST` | `/api/nv/write` | Write updated NV item value |
| `GET` | `/api/f3/list`, `/api/f3/export` | Fetch or export QXDM F3 trace logs |
| `POST` | `/api/terminal/exec` | Execute AT diagnostic command |
| `POST` | `/api/terminal/diag_raw` | Execute raw Qualcomm DIAG HDLC hex frame |
| `POST` | `/api/terminal/macro` | Execute automated diagnostic macro |
| `GET` | `/api/fuzzer/templates` | Discover 3GPP signaling templates |
| `POST` | `/api/fuzzer/campaign/start` | Start continuous fuzzing campaign |
| `GET` | `/api/fuzzer/export_pcap` | Download mutated fuzz test suite PCAP |
| `POST` | `/api/calea/x1/send` | Send ETSI TS 103 221-1 X1 provisioning request |
| `POST` | `/api/benchmark/run` | Execute high-throughput latency benchmark |

---

## 4. Professional Training & Certification

Hands-on training, interactive live simulation labs, and certified curriculums for baseband security auditing, 5G standalone architecture, and radio threat mitigation are available at **[TelcoSec Academy (app.telcosec.net)](https://app.telcosec.net)**.

