# Sample captures

Two GSMTAP captures used by the documentation and as hardware-free demo data:

| File | Contents |
| :--- | :--- |
| `sample_2g_3g_4g_xperia.pcap` | 2G/3G/4G signaling from a Sony Xperia handset |
| `sample_2g_3g_4g_xperia_with_sib_and_nas.pcap` | The same, with SIB reassembly and NAS decoding applied |

Replay either without any hardware:

```bash
airtap -r docs/sample_pcaps/sample_2g_3g_4g_xperia.pcap -s
airtap -r docs/sample_pcaps/sample_2g_3g_4g_xperia_with_sib_and_nas.pcap --gui
```

## Provenance

These files are inherited **verbatim** from the upstream
[QCSuper](https://github.com/P1sec/QCSuper) project (`docs/sample_pcaps/`), which
AirTap is derived from, and are byte-identical to the copies published there under
GPL-3.0. They were not captured by this project.

## Privacy note

They are recordings of a real handset on a live network, so they are **not synthetic
test vectors**. An audit of their contents found:

- **No IMSI, IMEI, TMSI or GUTI.** Verified with `tshark` against `e212.imsi`,
  `gsm_a.imsi`, `e212.imei`, `gsm_a.imei`, `nas_eps.emm.imsi`, `gsm_a.tmsi`,
  `nas_eps.emm.m_tmsi` and `e212.guti` — all empty.
- **One SMS** in the second capture (frame 2004): body `"Sms 4g"`, a test message,
  addressed to MSISDN `0768987654` with SMSC `33609001390`.

That MSISDN and SMSC are real numbers rather than reserved test ranges. They are
retained only because these files are already public upstream and removing them here
would not un-publish them, while diverging from upstream would break byte-for-byte
comparison with the project AirTap is derived from.

**If you contribute your own captures, do not do this.** Use the reserved ranges —
MCC/MNC `001/01` for the test PLMN, `+1555-01xx` for North American numbers — or
redact identifiers before committing. A capture from a live network contains
subscriber identifiers that cannot be recalled once published.
