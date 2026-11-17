# Security Auditing

AirTap ships an auditor of **88 rules** (`TELCOSEC-VULN-001` … `TELCOSEC-VULN-088`) that
evaluates decoded signaling in real time.

```bash
airtap --sec-audit -s                          # audit live traffic
airtap --sec-audit --audit-log findings.json   # write structured findings
airtap -r capture.pcap --sec-audit             # audit a recorded capture
```

---

## How a finding is produced

Three deterministic stages. No model, no scoring, no inference.

```
   DIAG frame
       │
       ▼
┌──────────────────┐   ASN.1 UPER/PER engine + Lua dissectors parse the PDU
│  1. Decode       │   into named 3GPP fields at their specified offsets.
└────────┬─────────┘
         ▼
┌──────────────────┐   88 rules test the decoded values:
│  2. Evaluate     │   cipheringAlgorithm == 0, tp_pid == 0x40,
└────────┬─────────┘   redirectedCarrierInfo == geran, …
         ▼
┌──────────────────┐   Alert cites the rule ID, the field, and the
│  3. Report       │   3GPP clause that defines it.
└──────────────────┘
```

A field is **read where the specification says it lives**, never searched for. That
distinction is the whole design:

> An earlier revision matched cipher codes as substrings of a hex-dumped PDU. Measured
> against random release messages, **292 of 400 (73%)** tripped a `[CRITICAL]`
> IMSI-catcher alert. Those heuristics were replaced with positional field reads and
> decoded-field lookups. In an auditing tool a false critical is worse than a miss,
> because it trains the operator to dismiss the real ones.

Consequences you can rely on:

- **Auditable** — every alert maps to a rule ID and a spec clause.
- **Reproducible** — the same capture always yields the same findings.
- **Offline** — nothing is uploaded; captures never leave your machine.
- **Tested** — dissectors run under a real Lua 5.3+ interpreter in CI.

---

## Severities

| Severity | Count | Meaning |
| :--- | ---: | :--- |
| `CRITICAL` | 32 | Active compromise of confidentiality, integrity or identity |
| `HIGH` | 44 | Strong indicator of attack or serious misconfiguration |
| `MEDIUM` | 15 | Weak or deprecated configuration worth investigating |
| `LOW` | 2 | Minor deviation |
| `INFO` | 5 | Noteworthy event, not inherently a problem |

Treat `CRITICAL` as "verify immediately", not "you are definitely under attack" —
a lab network or a test SIM can legitimately produce several of them.

---

## What the rules cover

**Ciphering and integrity.** Null ciphering and null integrity across every generation:
A5/0 (2G), GEA0 (GPRS), UEA0 (3G), EEA0/EIA0 (4G), NEA0/NIA0 (5G). Also deprecated
ciphers that are broken in practice — A5/1, A5/2, GEA1.

**Identity exposure.** Cleartext IMSI identity requests, IMEI/IMEISV harvesting,
plaintext identity in attach procedures, SUCI/SUPI handling.

**False base stations and downgrades.** Forced inter-RAT redirection (5G→4G→2G),
malicious `RRCConnectionRelease` with `redirectedCarrierInfo`, abnormal location
updating rejects that strand a subscriber (`#2`, `#3`, `#6`), and malicious extended
wait times used as a radio denial of service.

**SMS and SIM attack surface.** Type 0 Silent SMS (`TP-PID 0x40`) used for covert
location pings, Flash Class 0, SIM OTA / SMS-PP data download (`TP-PID 0x7F`),
SIMjacker-style STK abuse including `RUN AT COMMAND` and unauthorised `SET UP CALL`,
and null-ciphered Remote File Management.

**Core network and interconnect.** SS7/MAP and Diameter abuse (`S6a` Update-Location,
`S13` ME-Identity-Check), SIP/IMS identity spoofing via `P-Asserted-Identity`.

**Lawful interception.** ETSI TS 102 232 / 3GPP TS 33.108 HI2/HI3 detection, plaintext
intercept leakage, and sequence-counter reset or replay tampering.

The authoritative list is the rule catalogue in `src/modules/sec_audit.py`, and the GUI
exposes it with per-rule trigger counts.

---

## Reading a finding

Each alert carries the rule ID, severity, the field that triggered it, and the decoded
value. To verify one:

1. **Find the frame.** Filter the capture on `telcosec` in Wireshark; flagged frames
   carry a `TelcoSec ... Alert` field.
2. **Check the field.** Expand the decoded tree — the alert names the field it read
   (for example `lte-rrc.cipheringAlgorithm_r8`).
3. **Check the clause.** The rule description cites the 3GPP specification and section.
4. **Decide.** A test network, a lab SIM or an engineering build can legitimately use
   null ciphering. Context is yours to supply; the tool reports what the bytes said.

## Managing rules

Rules can be toggled individually at runtime, and the GUI's Threat Radar tab shows the
catalogue with live trigger statistics. Disabling a rule suppresses its findings for
the session without affecting the others — useful when a known-benign lab condition
would otherwise flood the log.

---

## Audit log format

`--audit-log FILE` writes structured JSON suitable for ingestion. Each entry records the
rule ID, severity, human-readable title, the decoded evidence, and a timestamp, so
findings can be diffed between runs or fed into a SIEM.

## See also

- [Wireshark Dissectors](Wireshark-Dissectors.md) — the dissectors that produce the decoded fields
- [Visual Operations Suite](Visual-Operations-Suite.md) — Threat Radar and the geospatial threat view
- [CLI Reference](CLI-Reference.md) — audit-related flags
