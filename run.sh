#!/usr/bin/env bash
# ==============================================================================
# AirTap Runner Script for Kali WSL / WSL2 (Samsung Galaxy S5 & Qualcomm Devices)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDIR="$PWD"

echo "=== AirTap Kali WSL Automated Launcher ==="

# 1. Check if running under WSL/WSL2
IS_WSL=0
if grep -qi microsoft /proc/version 2>/dev/null || [ -n "$WSL_DISTRO_NAME" ]; then
    IS_WSL=1
    echo "[+] Detected WSL environment: ${WSL_DISTRO_NAME:-Kali}"
fi

# 2. Automated USB Device Attachment via usbipd (for Samsung Galaxy S5 - VID: 04e8)
attach_usb_device() {
    if [ "$IS_WSL" -eq 1 ] && command -v powershell.exe >/dev/null 2>&1; then
        echo "[*] Checking connected USB devices via Windows usbipd..."
        
        # Check if usbipd is installed on Windows host
        if powershell.exe -Command "Get-Command usbipd" >/dev/null 2>&1; then
            echo "[*] Searching for Samsung device (VID 04e8) or Qualcomm USB interface..."
            
            # Find BUSID for Samsung (04e8) or Qualcomm (05c6)
            BUSID=$(powershell.exe -Command "usbipd list" | grep -iE "04e8|05c6|Samsung|Qualcomm" | awk '{print $1}' | head -n 1)
            
            if [ -n "$BUSID" ]; then
                echo "[+] Found device on Bus ID: $BUSID. Ensuring device is bound & attaching to WSL..."
                powershell.exe -Command "usbipd bind --busid $BUSID" 2>/dev/null || true
                powershell.exe -Command "usbipd attach --wsl --busid $BUSID" || powershell.exe -Command "usbipd wsl attach --busid $BUSID" || echo "[!] Notice: usbipd attach reported warning or device already attached."
            else
                echo "[!] No unattached Samsung (04e8) / Qualcomm (05c6) USB device found in usbipd list."
                echo "    Ensure phone is plugged in via USB with USB Debugging enabled."
            fi
        else
            echo "[!] usbipd.exe not found on Windows host. (Optional: install usbipd-win for direct USB passthrough)."
        fi
    fi
}

# 3. Check ADB Connection
check_adb() {
    echo "[*] Checking ADB connection..."
    
    # Locate adb executable (linux native or Windows adb)
    if command -v adb >/dev/null 2>&1; then
        ADB_BIN="adb"
    elif [ -f "/mnt/c/platform-tools/adb.exe" ]; then
        ADB_BIN="/mnt/c/platform-tools/adb.exe"
    elif command -v adb.exe >/dev/null 2>&1; then
        ADB_BIN="adb.exe"
    else
        echo "[!] ADB binary not found in PATH. Installing android-tools-adb if needed..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y android-tools-adb
            ADB_BIN="adb"
        fi
    fi

    if [ -n "$ADB_BIN" ]; then
        $ADB_BIN start-server >/dev/null 2>&1 || true
        DEVICES=$($ADB_BIN devices | grep -v "List of devices" | grep -v "^$")
        echo "[+] Connected ADB Devices:"
        echo "$DEVICES"
        
        # Request ADB root if supported by Samsung S5
        echo "[*] Attempting adb root..."
        $ADB_BIN root 2>/dev/null || true
    fi
}

# 4. Environment and dependencies check
check_python_env() {
    echo "[*] Checking Python environment and dependencies..."
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_EXEC="python3"
    elif command -v py >/dev/null 2>&1; then
        PYTHON_EXEC="py"
    else
        PYTHON_EXEC="python"
    fi

    # Verify dependencies
    $PYTHON_EXEC -c 'import serial, usb, crcmod' 2>/dev/null || {
        echo "[!] Installing missing dependencies..."
        $PYTHON_EXEC -m pip install --break-system-packages --upgrade pyserial pyusb crcmod pycrate 2>/dev/null || \
        $PYTHON_EXEC -m pip install --user --upgrade pyserial pyusb crcmod pycrate
    }
}

# Run setup steps
attach_usb_device
check_adb
check_python_env

# 5. Add Wireshark path if installed on Windows
if [ -d "/c/Program Files/Wireshark" ]; then
    export PATH="$PATH:/c/Program Files/Wireshark"
fi
if [ -d "/mnt/c/Program Files/Wireshark" ]; then
    export PATH="$PATH:/mnt/c/Program Files/Wireshark"
fi

# 6. Execute AirTap tool
echo "=================================================================="
echo "[+] AirTap Baseband Packet Capture Running (Samsung Galaxy S5)"
echo "=================================================================="

ENTRYPOINT="$SCRIPT_DIR/airtap.py"

if [ $# -gt 0 ]; then
    $PYTHON_EXEC "$ENTRYPOINT" "$@"
else
    if command -v wireshark >/dev/null 2>&1 || command -v wireshark.exe >/dev/null 2>&1 || command -v Wireshark.exe >/dev/null 2>&1; then
        echo "[+] Wireshark detected! Launching live capture window with telemetry..."
        $PYTHON_EXEC "$ENTRYPOINT" --adb --wireshark-live --reassemble-sibs --decrypt-nas --stats
    else
        DEFAULT_PCAP="$SCRIPT_DIR/airtap_s5_capture.pcap"
        echo "[+] Capturing 2G/3G/4G/5G radio frames directly to file:"
        echo "    --> $DEFAULT_PCAP"
        echo "[+] Logging enabled for: GSM, WCDMA, UMTS, LTE NAS & RRC, 5G NR RRC & 5G NAS."
        echo "[+] Press Ctrl+C at any time to stop capture."
        echo "=================================================================="
        $PYTHON_EXEC "$ENTRYPOINT" --adb --pcap-dump "$DEFAULT_PCAP" --reassemble-sibs --decrypt-nas --stats -v
    fi
fi
