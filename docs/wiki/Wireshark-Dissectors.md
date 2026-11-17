# Wireshark Dissectors

AirTap bundles **107 Lua dissectors** covering 2G through 5G, core-network interfaces,
SIM/UICC, and vendor baseband framing.

```bash
airtap --install-plugins      # deploy them
```

Then restart Wireshark, or press **Ctrl+Shift+L** to reload Lua plugins.

---

## Lua version compatibility

Wireshark's embedded Lua changed across releases, and it matters:

| Wireshark | Lua | `bit` | `bit32` |
| :--- | :--- | :--- | :--- |
| ≤ 3.4 | 5.1 | ✅ (LuaBitOp) | ❌ |
| 3.6 | 5.2 | ❌ | ✅ |
| 4.x | 5.3 / 5.4 | ❌ | ❌ |

Lua resolves globals at **call** time, so a dissector referencing a missing library
loads and registers perfectly, then throws `attempt to index a nil value (global
'bit')` the moment a packet reaches a heuristic — appearing installed while decoding
nothing.

Every bundled dissector therefore carries a self-contained compatibility shim that
prefers native 5.3 operators and defers to a host-provided `bit` or `bit32` when one
exists. The shim is per-file rather than a shared module because Wireshark loads plugin
`.lua` files flat, in unspecified order, and the plugin directory is not on
`package.path`.

---

## What is covered

**Radio access** — 5G NR RRC/NAS/L2/ML1, LTE RRC/NAS/L2/ML1, WCDMA RRC, GSM
RR/MM/CC/SMS/LAPDm, GPRS LLC/SNDCP/RLC-MAC/BSSGP/NS.

**Core and interconnect** — NGAP, S1AP, X2AP, XnAP, F1AP, E1AP, NRPPa, GTPv1-C/U,
GTPv2-C, PFCP, Diameter (S6a, Gx/Gy, IMS), SS7/SIGTRAN (MAP, TCAP, INAP, CAMEL, ISUP,
MTP, SCTP).

**IMS and voice** — SIP, SDP/RTP, AMR/EVS, MSRP, XCAP/Ut, IMS IPsec, MCPTT.

**SIM and provisioning** — UICC APDU, STK proactive commands, SIM OTA, eSIM RSP,
EAP-SIM/AKA.

**Lawful interception** — ETSI TS 102 232 PS-PDU, 3GPP TS 33.108 / 33.128 X2/X3.

**Vendor framing** — Qualcomm DIAG, Samsung Shannon (IPC, DM, crash), MediaTek
MobileLog, HiSilicon Balong, Unisoc, Apple ARI/CommCenter.

**Security analysis** — `telcosec_vuln_audit_engine.lua` is a post-dissector that
evaluates decoded fields from the native Wireshark dissectors and annotates frames with
findings.

---

## Finding flagged frames

The security dissectors add a `TelcoSec ... Alert` field. In Wireshark:

```
telcosec
```

shows every frame any of them flagged. Narrow by protocol with the usual filters
(`lte-rrc`, `nr-rrc`, `nas-eps`, `nas-5gs`, `gsm_a.dtap`, `gsm_sms`).

---

## Detection style

Alerts come from **decoded fields**, not from pattern-matching raw bytes.

Where Wireshark's native dissector already decodes a field, the analyser reads it
through `Field.new()` — for example `lte-rrc.cipheringAlgorithm_r8`,
`nr-rrc.redirectedCarrierInfo`, `gsm_sms.tp_pid`. Where no decoded field exists, the
dissector walks the TLV structure to the element's defined position.

Neither path searches for a byte pattern. Searching a bit-packed ASN.1 payload for a
cipher code matches at any nibble offset regardless of field position; measured, that
approach flagged 73% of ordinary release messages as IMSI-catcher activity.

---

## Writing your own

`template_dissector.lua` is a minimal starting point. If your dissector uses bitwise
operations, copy the compatibility shim from any bundled file — without it the
dissector will work on your Wireshark and fail silently on someone else's.

Tests live in `tests/tests_wireshark_lua_runtime.py` and run dissectors under a real
Lua 5.3+ interpreter via `tests/lua_harness/wsstub.lua`, so a decoder that dies on the
first packet fails CI rather than failing quietly on live traffic.

## See also

- [Security Auditing](Security-Auditing.md) — the rule engine these feed
- [Contributing](Contributing.md) — dissector conventions and testing
