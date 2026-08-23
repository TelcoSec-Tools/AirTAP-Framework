# Changelog

All notable changes to AirTap are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-08-23

### Added

- **3GPP ASN.1 UPER / PER / BER Dissection Engine**:
  - Implemented high-performance, pure-Python bit-stream parser (`src/protocol/asn1_uper.py`) supporting integer constraints, extensible choice discriminants, enumerated types, and variable-length determinants with integer overflow guards.
  - **5G NR RRC Dissector (3GPP TS 38.331 Rel-15..17)**: Deep ASN.1 decoding for `SIB1` (`q-RxLevMin`, `q-QualMin`, `ssb-PositionsInBurst`), `SIB2`..`SIB5` neighbor cell lists, and **SIB19 (Satellite 5G Non-Terrestrial Networks)** ephemeris and Doppler compensation.
  - **4G LTE RRC Dissector (3GPP TS 36.331)**: ASN.1 UPER decoding for `SystemInformationBlockType1`..`Type21` and `RRCConnectionReconfiguration`.
  - **C-V2X Sidelink Direct RRC (3GPP TS 38.331 PC5)**: Direct vehicle-to-vehicle telematics, `sl-BWP-Config`, and autonomous resource allocation.
  - **3GPP Positioning Protocol (LPP - 3GPP TS 37.355)**: ASN.1 PER decoding for `ProvideAssistanceData`, `RequestLocationInformation`, and `ProvideLocationInformation` (A-GNSS, RTK, OTDOA, PRS, and E-CID).
  - **eCall Minimum Set of Data (MSD - EN 15722 / ISO 24978)**: ASN.1 BER parser extracting vehicle VIN (17-char ASCII), vehicle propulsion storage type (Gasoline, Diesel, EV Battery Pack, Hydrogen Fuel Cell), automatic crash vs. manual SOS trigger, and high-precision WGS-84 coordinates.
  - **Deep Compound NAS Information Elements**: Extended Protocol Configuration Options (ePCO DNS / P-CSCF addresses), 5G Network Slicing (`S-NSSAI` SST & SD), ECIES SUCI profiles, and 5QI/QFI QoS Flow Descriptions.

- **Subscriber Identity & Silent SMS Protocol Suite**:
  - Real-time identity dissector for IMSI, IMEI, IMEISV, TMSI, P-TMSI, M-TMSI, 4G GUTI, 5G-GUTI, 5G-S-TMSI, 5G-SUCI, and USIM APDU `EF_IMSI` / `EF_MSISDN`.
  - Standards-compliant SMS dissector for 7-bit GSM, UCS-2, 8-bit binary, Type 0 Silent SMS (`PID=0x40`), Flash Class 0 (`DCS=0x10`), and SIM OTA commands (`PID=0x7F` / TAR payload).
  - Global PLMN carrier resolution dictionary (`GLOBAL_PLMN_MAP`) mapping captured MCC/MNC codes to carrier names and countries.

- **88 Master Telecom Vulnerability & Threat Auditing Rules**:
  - Expanded rule catalog from 80 to 88 rules (`TELCOSEC-VULN-001` through `VULN-088`), including Bluetooth SweynTooth Link Layer anomalies (`VULN-082`) and VoWiFi IPsec weak cryptographic tunnel auditing (`VULN-087`).

- **Geospatial Wardrive & Tactical Map Suite**:
  - Real-time baseband RF telemetry synchronizer pushing RSRP/RSRQ/SINR/TA measurements directly to GPS heatmap contour layers.
  - Multi-sector cell tower radiation wedges (30°, 150°, 270°) and Log-Distance Path Loss tower triangulation.
  - 3GPP Timing Advance (TA) physical perimeter distance rings (`TA * 78.12m`).
  - Discovered Transmitters slide-out drawer with one-click map focusing and export in GeoJSON, KML, and WiGLE CSV formats.

- **Baseband NVRAM Studio & Hardware Band Lock**:
  - Direct modem NV item writing (`DIAG_NV_WRITE_F` opcode `0x27`) with automatic padding and 16-bit / 32-bit extended NV ID routing.
  - 5G NR band preference bitmask encoders for n1, n2, n3, n5, n7, n8, n20, n28, n38, n40, n41, n66, n71, n77, n78, n79, n257, n258, n260, n261 (mmWave).
  - 5G Standalone (`NV_NR5G_SA_ENABLE_I`), Non-Standalone (`NV_NR5G_NSA_ENABLE_I`), and VoLTE/VoNR IMS stack configuration.

- **Enhanced 3GPP Protocol Fuzzing Engine**:
  - Added canonical signaling templates for 5G Satellite SIB19, LPP Positioning, eCall Emergency MSD, and C-V2X Sidelink PC5.
  - Added specialized mutation strategies: `asn1_uper_overflow`, `asn1_choice_tamper`, `gps_coord_spoof`, and `suci_ecies_tamper`.

- **Mobile Device Connection Hardening**:
  - Implemented exponential backoff retry loop and automated background watchdog in ADB bridge stream to self-heal and reconnect on USB connection resets.

- **229 Automated Unit Tests**:
  - Expanded test coverage to 229 automated unit tests across 36 test suites with 100% pass rate.

## [2.0.1] - 2026-08-22

### Added

- **Real-Time Radio Security Auditor (`--sec-audit`)**: Embedded telecom vulnerability detection engine loaded with 80 master rules (`TELCOSEC-VULN-001` through `VULN-080`) detecting IMSI catchers, forced 2G/3G downgrade attacks, LTE/5G null ciphering (`EEA0`/`NEA0`), null integrity (`EIA0`/`NIA0`), Type 0 Silent SMS surveillance probes, SIMjacker / WIB STK attacks, covert SIM location/IMEI queries, and CALEA / ETSI TS 102 232 Lawful Interception anomalies.
- **AirTap Visual Operations Suite (`--gui`)**: Real-time interactive web GUI featuring live telemetry, map wardriving, signaling tree dissector, telecom threat matrix, F3 Qualcomm debug logs, NV memory viewer, and baseband EFS explorer.
- **Wireshark Plugin Manager (`--install-plugins`)**: Automated multi-platform installer for over 107 bundled Wireshark Lua cellular radio and security dissectors.
- **3GPP Protocol Fuzzing & Mutation Engine (`--fuzz`)**: Grammar-aware 3GPP signaling mutator supporting boundary integers, bit-flipping, length tampering, truncation, and GSMTAP PCAP export.
- **High-Throughput Dissection Benchmark (`--benchmark`)**: Automated latency stress-testing suite evaluating dissection pipelines and computing p50/p95/p99 latency percentiles.
- **Interactive AT & DIAG Diagnostic Terminal (`--at-cmd`, `--at-macro`)**: Direct baseband AT and Qualcomm DIAG HDLC dispatch engine with macro audit routines.
- **Multi-Vendor Diagnostic Input Readers**: Support for Samsung Shannon (Exynos/Tensor) and MediaTek (Dimensity/Helio) baseband trace formats alongside Qualcomm DIAG.
- **Interactive Session Replay Engine (`-r`, `--replay`)**: Timeline scrubbing, seeking, and variable-speed playback across PCAP, DLF, QMDL, and JSON captures.
- **IMS / VoLTE / VoNR SIP Dissection**: Automatic extraction of SIP session signaling from diagnostic logs wrapped into native UDP/SIP port 5060 frames in Wireshark.
- **Enhanced EFS Shell Utilities**: Recursive downloads (`get -r`), file search (`find <path> -name <pattern>`), in-file pattern search (`grep`), filesystem space reporting (`statfs`), MD5 checksum calculation (`md5sum`), and hierarchical tree visualization (`tree`).
- **QXDM DMC Mask Loader & QMDL Exporter**: Load vendor QXDM `.dmc` configuration masks (`--dmc`) and export `.qmdl` containers (`--qmdl`).
- **Standardized Community Governance**: Added `CONTRIBUTING.md`, `SECURITY.md`, GitHub issue templates (`bug_report.md`, `feature_request.md`), and PR template.
- **PEP 621 Packaging & Modern Dependencies**: Modernized `pyproject.toml` with complete `[project]` metadata, URLs, classifiers, console scripts, and standardized `requirements.txt` / `requirements-dev.txt`.

### Fixed

- **Capture files no longer lose their tail**: `--pcap-dump` and `--dlf-dump` flush every 32 records to prevent truncation on process termination.
- **Source Distribution (sdist) Build**: Fixed `MANIFEST.in` to recursively include all Python sources, preventing missing `__init__.py` errors during `python -m build`.
- **EFS Shell `md5sum` Command**: Corrected opcode from `EFS2_DIAG_MKDIR` to `EFS2_DIAG_MD5SUM` and re-enabled the command in the interactive EFS shell.
- **Wireshark Plugin Tests**: Created missing `install_plugins.py` and aligned unit tests with canonical dissector naming conventions.
- **Output-sink error handling**: Output-sink failures are cleanly handled to prevent unbounded traceback loops on closed pipes.
- **Lazy Logging & Deprecations**: Updated `logging.warn` deprecations and modernized Setuptools configuration.

### Packaging

- **Wireshark Lua Dissectors Shipped**: Over 107 Wireshark dissectors declared in package data, bundled in wheels and source distributions.
- **Explicit Package Inits**: Added missing `__init__.py` files to `inputs`, `protocol`, `modules`, `modules/efs_shell_commands`, and `modules/wireshark_plugin`.
- **Executable Tracking**: Tracked executable mode bits on `run.sh`, `airtap.py`, `update_tools.sh`, and bundled ADB binaries.
- **Single-Source Versioning**: Version is single-sourced from `src/__init__.py` and accessible via `airtap --version`.

### Testing & CI

- **Multi-OS / Multi-Python CI Matrix**: GitHub Actions matrix runs tests across Ubuntu, Windows, and macOS on Python 3.8, 3.9, 3.10, 3.11, 3.12, and 3.13.
- **Code Quality & Packaging Validation**: CI includes automated syntax checking, flake8 linting, `python -m build`, `twine check`, and wheel contents inspection.
- **182 Automated Unit Tests**: Comprehensive unit test suite with 100% test pass rate across 34 test suites.
