# Visual Operations Suite

The web GUI. Launch it with:

```bash
airtap --gui                      # http://127.0.0.1:5000
airtap -r capture.pcap --gui      # drive it from a recorded capture
```

---

## Security model — read this first

The GUI **binds to `127.0.0.1` and has no authentication.** That is deliberate: it is a
local operator console, not a multi-user service.

Its API can:

- write persistent baseband NVRAM (`/api/nv/write`)
- execute AT and raw DIAG commands (`/api/terminal/exec`, `/api/terminal/diag_raw`)
- read the modem filesystem (`/api/efs/*`)
- stream live captured signaling

**Anyone who can reach the port has all of that, unauthenticated.** Do not bind to
`0.0.0.0`, forward the port, or put it behind a reverse proxy without adding your own
authentication and TLS.

Requests from other web origins are rejected — a page you visit while AirTap is running
cannot drive the API, and the wildcard CORS header that previously allowed it is gone.
That guard protects against a hostile web page; it is **not** a substitute for network
isolation.

---

## Tabs

The nav is grouped into three domains.

### ⚡ Signaling & Threats

| Tab | Purpose |
| :--- | :--- |
| **Live Signaling** | Real-time frame feed with RAT breakdown, per-protocol counters and an RF sparkline |
| **Threat Radar** | The 88-rule catalogue with live trigger counts; rules can be toggled individually |
| **Identities & SMS** | Observed IMSI / TMSI / GUTI / SUCI, the SMS stream, and SIM OTA commands |
| **Wardrive & Map** | Tower map with RSRP heatmap contours, timing-advance rings and geolocated threat pins |

### 📱 Modem & Baseband

| Tab | Purpose |
| :--- | :--- |
| **Device Info** | Hardware dossier: model, chipset, firmware build, subsystem status, self-test |
| **QXDM F3 Logs** | Internal baseband debug messages with subsystem and severity filtering |
| **EFS Explorer** | Browse, read and download the modem filesystem |
| **NV & Bands** | NV item read/write and RF band-mask configuration |
| **SIM & Keys** | UICC card profile and key material inventory (see below) |

### 🛡️ Ops & Forensics

| Tab | Purpose |
| :--- | :--- |
| **AT Terminal** | Interactive AT and raw DIAG command console with macros |
| **CALEA / LI** | ETSI TS 102 232 lawful-interception dissection and X1 provisioning view |
| **Protocol Fuzzer** | 3GPP protocol mutation campaigns with PCAP/JSON export |

---

## SIM & Keys

Inventories the UICC card profile and the key material the baseband holds, grouped by
security boundary:

| Group | Contents |
| :--- | :--- |
| USIM / UICC long-term | Ki, OPc, TOPc (Milenage / TUAK) |
| Session keys (RAM) | CK, IK, KASME, KAUSF, KSEAF, KAMF, KNAS\*, KgNB/KeNB |
| IMS / VoLTE / VoNR | AKAv1-MD5 credential, IMS CK/IK, SIP Digest |
| IPsec & VoWiFi (ePDG) | IMS ESP SAs, IKEv2 SK_e\*/SK_a\*, child SA, EAP-AKA′ MSK |

**Key bytes are redacted at the source.** They are returned only on an explicit
per-field reveal, so the default API response, the rendered page and the JSON export
never contain secrets — those artefacts outlive the session that produced them.

**Ki and OPc are reported as `SEALED`, not blank.** They are not extractable in
principle: `EF_K` is not an ISO 7816 readable file and the AKA computation runs inside
the card, so the key never crosses the ME interface. A blank value would wrongly imply
a later read might succeed.

---

## Session replay

Loading a capture turns the GUI into a forensic timeline — scrub, step frame by frame,
and play back at 0.5× to 10×. Every tab reflects the replay position, so you can watch
identities appear and threats fire in sequence.

## See also

- [Security Auditing](Security-Auditing.md) — what Threat Radar is showing
- [EFS & NV Tools](EFS-and-NV-Tools.md) — the CLI equivalents of the EFS and NV tabs
