# AirTap Wiki

Cellular radio diagnostics, packet capture, and security auditing for 2G/3G/4G/5G NR basebands.

> **Mirror of the GitHub wiki.** These pages live in `docs/wiki/` so they are versioned
> alongside the code and reviewed in the same pull requests. They can be pushed to the
> GitHub wiki verbatim once it is available (wikis on private repositories require a
> paid plan; public repositories get them on the free plan).

---

## Start here

| Page | What it covers |
| :--- | :--- |
| [Installation](Installation.md) | Install from source or wheel, deploy the Wireshark dissectors, platform prerequisites |
| [Quick Start](Quick-Start.md) | First capture in under five minutes |
| [Capture Sources](Capture-Sources.md) | Rooted Android, USB modems, remote TCP, offline trace replay |
| [Visual Operations Suite](Visual-Operations-Suite.md) | The web GUI, tab by tab, and its security model |
| [CLI Reference](CLI-Reference.md) | Every flag, grouped by purpose |
| [Security Auditing](Security-Auditing.md) | How the 88 rules work and how to read a finding |
| [Wireshark Dissectors](Wireshark-Dissectors.md) | The 107 bundled Lua dissectors and how they load |
| [EFS & NV Tools](EFS-and-NV-Tools.md) | Filesystem shell, NV item access, band locking |
| [Troubleshooting](Troubleshooting.md) | Permissions, DIAG access, dissector loading |
| [Architecture](Architecture.md) | Threading model, module contracts, data flow |
| [Contributing](Contributing.md) | Development setup, testing, conventions |
| [FAQ](FAQ.md) | Short answers to recurring questions |

---

## What AirTap is

AirTap speaks the Qualcomm **DIAG protocol** to a baseband modem, decodes the raw
signaling it emits, and re-encapsulates it as **GSMTAP v2** so standard tools can read
it. Everything else — the auditor, the GUI, the EFS shell — is built on that one
capability.

It is a **local operator tool**. Captures stay on your machine, nothing is uploaded,
and the only network listener is a loopback-bound GUI you start explicitly.

## What AirTap is not

- **Not an AI/ML product.** There is no model, no inference, no training data, and no
  ML dependency. Detection is deterministic: fields are decoded at their 3GPP-specified
  offsets and evaluated by readable rules. See [Security Auditing](Security-Auditing.md).
- **Not a transmitter.** AirTap reads diagnostic output from a modem. It does not
  synthesise or transmit radio signals, and it is not a base station.
- **Not a multi-user service.** The GUI has no authentication by design. See the
  security note in [Visual Operations Suite](Visual-Operations-Suite.md).

## Legal

Capturing radio signaling exposes subscriber identifiers (IMSI, IMEI) and location
data. Use AirTap only on networks and devices you own or are explicitly authorised to
test. Interception of third-party communications is a criminal offence in most
jurisdictions. See [SECURITY.md](../../SECURITY.md) and the Responsible Use section of
the [README](../../README.md).
