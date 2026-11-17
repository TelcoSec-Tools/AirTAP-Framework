# Installation

## Requirements

| | |
| :--- | :--- |
| **Python** | 3.9 – 3.13 (the versions CI exercises on Linux, Windows and macOS) |
| **Wireshark** | 3.0+ recommended, 4.x fully supported, for live streaming and the bundled dissectors |
| **ADB** | Only when capturing from an Android device; binaries are bundled |
| **OS** | Linux, macOS, Windows, WSL2 |

Runtime dependencies are `pyserial`, `pyusb`, `crcmod` and `pycrate`. They install
automatically.

---

## From source (recommended)

```bash
git clone https://github.com/TelcoSec-Tools/AirTAP-Framework.git
cd AirTAP-Framework

# Optional but advised
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .
airtap --install-plugins           # deploy the 107 Wireshark Lua dissectors
```

`-e` installs in editable mode, so edits to `src/` take effect without reinstalling.

## From a release wheel

```bash
pip install airtap-2.6.0-py3-none-any.whl
airtap --install-plugins
```

Wheels are attached to each [GitHub release](https://github.com/TelcoSec-Tools/AirTAP-Framework/releases).

## Verify

```bash
airtap --version        # -> AirTap 2.6.0
airtap --info           # queries an attached modem, if one is present
```

If `airtap` is not on your `PATH`, the console script landed in a directory your shell
does not search. `python -m airtap.main --version` works regardless.

---

## Deploying the Wireshark dissectors

```bash
airtap --install-plugins
```

This copies all 107 `.lua` files into Wireshark's personal plugin directory:

| Platform | Destination |
| :--- | :--- |
| Linux | `$XDG_DATA_HOME/wireshark/plugins` or `~/.local/lib/wireshark/plugins` |
| macOS | `~/Library/Application Support/Wireshark/plugins` |
| Windows | `%APPDATA%\Wireshark\plugins` |

Restart Wireshark afterwards, or press **Ctrl+Shift+L** to reload Lua plugins.

To preview without writing anything:

```bash
python -m airtap.modules.wireshark_plugin.install_plugins --dry-run
python -m airtap.modules.wireshark_plugin.install_plugins --list
```

> **Wireshark 3.6 and newer** ship Lua 5.3/5.4, where the old `bit` and `bit32`
> libraries no longer exist. Every bundled dissector carries a compatibility shim, so
> they work on both old and new builds. If you maintain your own dissectors against
> this tree, see [Contributing](Contributing.md#lua-dissectors).

---

## Platform notes

### Linux

Serial access to a USB modem needs group membership:

```bash
sudo usermod -aG dialout $USER     # log out and back in
```

### Windows

Use PowerShell or Windows Terminal. The bundled ADB binary is used automatically; no
separate Android SDK install is required.

### WSL2

ADB inside WSL2 cannot see USB devices directly. AirTap bridges to the Windows-side ADB
server:

```bash
airtap --adb-wsl2 -l
```

### macOS

Modems appear as `/dev/tty.usbserial-*` or `/dev/tty.usbmodem*`. `--usb-modem auto`
finds them.

---

## Development install

```bash
pip install -e ".[dev]"
pytest                             # 302 tests
python -m compileall src tests
flake8 src tests --select=E9,F63,F7,F82
```

Some tests need optional tooling and skip cleanly without it: the Lua interpreter
suites require `lupa` (`pip install lupa`), and the frontend checks require Node.
See [Contributing](Contributing.md).
