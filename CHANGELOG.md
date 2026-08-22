# Changelog

All notable changes to AirTap are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
