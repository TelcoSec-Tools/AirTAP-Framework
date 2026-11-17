# Troubleshooting

Most problems are DIAG access, not AirTap. Work top to bottom.

---

## Nothing is detected

```bash
airtap --info -v
```

`--info` is the smallest possible round trip to the modem. If it fails, no capture will
work. `-v` shows the probe sequence.

With no source flag AirTap probes USB DIAG first, then ADB. Force one to see the real
error:

```bash
airtap -a --info          # ADB only
airtap -m auto --info     # USB only
```

---

## Android / ADB

**"Device unauthorized or offline"**
Run `adb devices` and accept the RSA prompt on the phone. If no prompt appears, revoke
USB debugging authorisations in Developer Options and reconnect.

**"Permission denied on /dev/diag"**
The device must be rooted:

```bash
adb root
adb shell ls -l /dev/diag
```

On Magisk/KernelSU, grant root to the shell explicitly.

**SELinux blocking access**

```bash
adb shell su -c 'setenforce 0'
```

Lowers device security for the session; restore with `setenforce 1`.

**`/dev/diag` does not exist**
The chipset is not Qualcomm, or the kernel does not expose the DIAG node. Some vendors
ship it disabled. Live capture requires it.

**WSL2 sees no devices**
WSL2 has no direct USB access. Use the bridge:

```bash
airtap --adb-wsl2 -l
```

---

## USB modems

**Port not found**

```bash
airtap -m auto -v        # shows what was probed
lsusb                    # Linux: confirm the device enumerates
dmesg | tail             # Linux: see which tty was assigned
```

**Permission denied on the serial port (Linux)**

```bash
sudo usermod -aG dialout $USER    # log out and back in
```

**Modem exposes no DIAG interface**
Many modems ship with DIAG disabled in their USB composition. Vendor AT commands switch
it — for example `AT+QCFG="usbcfg"` on Quectel. The exact value differs per model and
firmware; check your modem's AT reference.

**Port opens but no data arrives**
Something else holds the port — ModemManager is the usual culprit:

```bash
sudo systemctl stop ModemManager
```

---

## Wireshark

**Dissectors not loading**
Confirm deployment and reload:

```bash
airtap --install-plugins
python -m airtap.modules.wireshark_plugin.install_plugins --list
```

Then **Ctrl+Shift+L** in Wireshark, or restart it. Check
**Help → About → Folders → Personal Lua Plugins** for the path actually in use.

**"Lua: Error during loading"**
Ensure Lua is enabled — `enable_lua = true` in Wireshark's `init.lua`. Some
distribution packages disable it.

**Frames show as raw GSMTAP with no decode**
The bundled dissectors are not loaded, or the payload is a RAT whose native dissector
is disabled. Check **Analyze → Enabled Protocols**.

**Dissector works here but not on another machine**
Almost always the Lua version difference between Wireshark 3.4, 3.6 and 4.x. See
[Wireshark Dissectors](Wireshark-Dissectors.md#lua-version-compatibility).

---

## GUI

**Page loads but tabs are empty**
Open the browser console. A `ReferenceError` means a stale cached asset — hard-reload
with **Ctrl+Shift+R**.

**"Cross-origin request rejected"**
Reach the GUI at `http://127.0.0.1:5000`, not via a LAN IP or hostname. The API accepts
only its own loopback origin. This is intentional; see
[Visual Operations Suite](Visual-Operations-Suite.md#security-model--read-this-first).

**Port already in use**
Another process holds 5000. Stop it, or run AirTap's GUI after freeing the port.

---

## Still stuck

Run with `-v` and include the output when opening an issue, along with your OS,
Python version (`python --version`), AirTap version (`airtap --version`), and the
device or modem model. Do not paste captures containing real subscriber identifiers.
