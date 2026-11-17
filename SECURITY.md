# Security Policy

## Supported Versions

The following versions of AirTap are actively maintained with security and protocol updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.6.x   | :white_check_mark: |
| 2.5.x   | :white_check_mark: |
| < 2.5.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of AirTap and the integrity of telecommunications diagnostics seriously. If you discover a security vulnerability within AirTap (e.g., privilege escalation in helper scripts, parsing vulnerabilities that lead to arbitrary code execution, or credential handling flaws):

1. **Do not create a public GitHub issue.**
2. Report the vulnerability privately via email to: **security@telcosec.net** or **contact@telcosec.net**.
3. Please include:
   - A detailed description of the vulnerability.
   - Steps to reproduce or a Proof-of-Concept (PoC) trace.
   - The affected component (e.g., ADB bridge, serial parser, Wireshark dissector).
   - Any proposed remediation if available.

### Response Timeline
- **Initial Response**: Within 48 hours.
- **Status Update & Assessment**: Within 5 business days.
- **Remediation & Advisory**: Coordinated release with a patched version.

---

## Telecommunications Privacy & Legal Notice

AirTap is designed for security research, lawful diagnostics, and network auditing on devices and infrastructure you own or have explicit written authorization to evaluate.

- **Subscriber Identifiers**: Traces routinely contain sensitive identifiers such as IMSI, IMEI, TMSI, and GPS/Cell IDs. Treat capture files as sensitive personal data.
- **Interception Laws**: In many jurisdictions, unauthorized interception or recording of cellular radio communications is strictly regulated or prohibited. Users are responsible for complying with all applicable local, national, and international laws.

---

## Telecom Security Education

For authorized defensive security training, baseline hardening, and baseband audit courses, visit **[TelcoSec Academy (app.telcosec.net)](https://app.telcosec.net)**.

