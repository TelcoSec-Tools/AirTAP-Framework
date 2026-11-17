# Capture Sources

AirTap needs a path to a baseband's DIAG interface. There are five, and getting one of
them working is the only hard part of using AirTap.

With no source flag, AirTap auto-detects: it probes for a USB DIAG interface first,
then falls back to ADB.

---

## 1. Rooted Android (Qualcomm Snapdragon)

```bash
airtap -a -l
```

**Requirements**

- USB debugging enabled
- **Root** — `/dev/diag` is not accessible otherwise
- A Qualcomm chipset (Snapdragon / MDM / SDX)

**Checklist**

```bash
adb devices                 # device must show "device", not "unauthorized"
adb root                    # or grant root via Magisk / KernelSU
adb shell ls -l /dev/diag   # must exist and be readable
```

If SELinux blocks access:

```bash
adb shell su -c 'setenforce 0'
```

This lowers device security for the session. Set it back with `setenforce 1`.

**WSL2** cannot see USB devices directly; bridge to the Windows ADB server:

```bash
airtap --adb-wsl2 -l
```

---

## 2. USB modems and PCIe dongles

```bash
airtap -m auto -l                    # auto-detect the DIAG port
airtap -m /dev/ttyUSB0 -l            # Linux, explicit
airtap -m COM3 -l                    # Windows, explicit
airtap -m /dev/tty.usbserial-1 -l    # macOS, explicit
```

Any modem exposing a Qualcomm DIAG serial interface works — Quectel (EC25, EG25,
RM500Q, RM520N), Sierra Wireless, Telit, Fibocom, Huawei and others.

**Modem not exposing DIAG?** Many ship with it disabled. Vendor AT commands toggle the
USB composition, for example `AT+QCFG="usbcfg"` on Quectel. Consult your modem's AT
command reference; the exact value differs per model and firmware.

**Linux permissions:**

```bash
sudo usermod -aG dialout $USER       # then log out and back in
ls -l /dev/ttyUSB*                   # confirm group access
```

---

## 3. Remote TCP DIAG service

```bash
airtap -t 192.168.1.50:2500 -l
```

For a modem on another machine, a test rig, or a device exporting DIAG over the
network. AirTap is the client.

> The stream is unauthenticated and unencrypted — it carries subscriber identifiers in
> clear. Use it only on a trusted network segment, or tunnel it over SSH.

---

## 4. Offline trace files

Replaying needs no hardware at all, which makes it the easiest way to evaluate AirTap.

```bash
airtap -r capture.pcap -s            # GSMTAP PCAP
airtap -r trace.dlf -s               # Qualcomm DLF
airtap -r session.json --gui         # recorded JSON session
airtap --shannon-read trace.sdm      # Samsung Shannon / Exynos
airtap --mtk-read trace.log          # MediaTek Dimensity / Helio
```

Playback speed is adjustable (`--replay-speed 2.0`), and the GUI adds scrubbing and
single-stepping.

---

## 5. Multi-vendor basebands

| Vendor | Flag | Notes |
| :--- | :--- | :--- |
| Qualcomm | `-a`, `-m`, `-t` | Live capture, full feature set |
| Samsung Shannon (Exynos / Tensor) | `--shannon-read` | Offline trace decoding |
| MediaTek (Dimensity / Helio) | `--mtk-read` | Offline trace decoding |

Live capture is Qualcomm-only; Shannon and MediaTek support is trace decoding, with
dedicated dissectors for their framing.

---

## Filtering what you capture

```bash
airtap --rat 4g,5g -o capture.pcap          # only LTE and NR
airtap --logs 0xb0c0,0xb0e2 -l              # only specific log codes
airtap --reassemble-sibs -o nr.pcap         # rebuild segmented SIBs
```

Filtering at the source reduces volume substantially on a busy network and is worth
doing before you record a long session.

## See also

- [Troubleshooting](Troubleshooting.md) — when a source will not connect
- [CLI Reference](CLI-Reference.md) — every source and filter flag
