# FAQ

**Does AirTap use AI or machine learning?**
No. There is no model, no inference, no training data and no ML dependency. Detection
is deterministic: the ASN.1 engine decodes each field at its 3GPP-specified offset and
88 readable rules evaluate those values. Every alert traces to a named field and a spec
clause. See [Security Auditing](Security-Auditing.md).

**Do I need a rooted phone?**
For live capture from an Android device, yes — `/dev/diag` is not accessible otherwise.
A USB modem with a DIAG interface needs no root, and replaying a capture file needs no
hardware at all.

**Does it work with non-Qualcomm basebands?**
Live capture is Qualcomm-only. Samsung Shannon and MediaTek traces can be decoded
offline via `--shannon-read` and `--mtk-read`.

**Can AirTap transmit, jam, or act as a base station?**
No. It reads diagnostic output from a modem. It has no transmit path.

**Can it decrypt traffic?**
It can attempt LTE NAS deciphering with keys the baseband itself exposes
(`--decrypt-nas`). It does not break ciphers. Its security value is detecting when
encryption is *absent or weak* — null ciphering, downgrades, broken algorithms.

**Is any data sent anywhere?**
No. Captures stay on your machine. The only network listener is the GUI, bound to
loopback and started explicitly.

**Why does the GUI have no password?**
It is a local operator console, not a service. It binds to `127.0.0.1` and rejects
cross-origin requests. Do not expose it to a network — see
[Visual Operations Suite](Visual-Operations-Suite.md#security-model--read-this-first).

**A capture shows null ciphering. Am I under attack?**
Not necessarily. Test networks, lab SIMs and engineering builds legitimately use null
ciphering. The tool reports what the bytes said; context is yours to supply. Verify the
finding against the frame and the cited spec clause before concluding anything.

**Why do I get fewer alerts than an older version?**
Deliberately. Several heuristics matched byte patterns anywhere in a packet; measured,
73% of ordinary release messages produced false `[CRITICAL]` alerts. They now read
decoded fields at defined offsets. Fewer alerts, all of them meaningful.

**Dissectors work on my machine but not a colleague's.**
Almost certainly the Wireshark Lua version. See
[Wireshark Dissectors](Wireshark-Dissectors.md#lua-version-compatibility).

**Which Python versions are supported?**
3.9 through 3.13 — the versions CI exercises on Linux, Windows and macOS. 3.8 is end of
life and no longer supported.

**Is it legal to use?**
Using it on networks and devices you own or are explicitly authorised to test is
legitimate. Intercepting third-party communications is a criminal offence in most
jurisdictions. The capability to decode signaling does not confer authorisation to do
so.

**How do I report a vulnerability in AirTap?**
Privately, per [SECURITY.md](../../SECURITY.md) — not via a public issue.
