# AirTap

**AirTap** is a tool communicating with Qualcomm-based phones and modems, allowing to **capture raw 2G/3G/4G** (and for certain models 5G) radio frames.

It will allow you to **generate PCAP** captures of radio traffic using either a rooted Android phone, a USB dongle, or an existing capture in another format.

![Screenshot of using AirTap along with Wireshark](docs/sample_pcaps/Wireshark%20screenshot.png?raw=true)

## Quick Start

### 1. Launch with Automated WSL / Linux Runner
After plugging in your phone or device:
```bash
./run.sh
```

Or pass custom flags:
```bash
./run.sh --adb --pcap-dump airtap_s5_capture.pcap --reassemble-sibs --decrypt-nas
```

### 2. Standalone Python Command Line
```bash
python3 airtap.py --adb --wireshark-live --stats
```

Or for USB serial modems:
```bash
python3 airtap.py --usb-modem auto --wireshark-live --stats
```

## Supported Protocols

* **2G (GSM)**: Layer 3 and upwards (RR/...)
* **2.5G (GPRS / EDGE)**: Layer 2 and upwards (MAC-RLC/...)
* **3G (UMTS)**: Layer 3 and upwards (RRC/...) with SIB reassembly (`--reassemble-sibs`)
* **4G (LTE)**: Layer 3 and upwards (RRC/...) with NAS decryption (`--decrypt-nas`)
* **5G (NR)**: Layer 3 and upwards (RRC & 5GMM/5GSM NAS) with GSMTAP v2 encapsulation (`GSMTAP_TYPE_NR_RRC`, `GSMTAP_TYPE_NR_NAS`)
* **Telemetry**: Real-time packet throughput, rate metrics, and RAT distribution breakdown (`--stats`)

## License and attribution

AirTap is licensed under the **GNU General Public License v3.0**. The full text is in [LICENSE](LICENSE).

AirTap is a derivative work of [QCSuper](https://github.com/P1sec/QCSuper), created by
[P1sec](https://github.com/P1sec) and released under the GPL-3.0. The Diag protocol
implementation, GSMTAP encapsulation and EFS shell originate in that project; AirTap
renames the tool and builds on it. Because the GPL-3.0 is a copyleft license, AirTap is
distributed under those same terms, and this attribution and the accompanying license
text must be retained in any further redistribution.

QCSuper in turn credits the Osmocom project (GSMTAP), Wireshark, ModemManager,
SnoopSnitch / gsm-parser, diag-parser, MobileInsight, OpenPST and SCAT — see the
upstream README for the full acknowledgements.
