#!/system/bin/sh
# ==============================================================================
# AirTAP S5 Hardware Initialization Script (Samsung Galaxy S5 / LineageOS 18.1)
# ==============================================================================

echo "[*] Initializing Qualcomm Diag & AT interfaces on Samsung Galaxy S5 (MSM8974)..."

# 1. Ensure Root Access
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (su)."
    exit 1
fi

# 2. Configure USB Diagnostic Mode & Serial SMD Channels
echo "[*] Setting USB properties for Qualcomm Diag..."
setprop sys.usb.config diag,serial_smd,rmnet_bam,adb
sleep 1

# 3. Set Device Node Permissions
if [ -e /dev/diag ]; then
    chmod 666 /dev/diag
    echo "[+] /dev/diag permissions set to 666."
else
    echo "[-] /dev/diag not found, creating mknod if driver exists..."
    mknod /dev/diag c 10 230
    chmod 666 /dev/diag
fi

if [ -e /dev/smd0 ]; then
    chmod 666 /dev/smd0
    echo "[+] /dev/smd0 (AT command channel) ready."
fi

if [ -e /dev/smd11 ]; then
    chmod 666 /dev/smd11
    echo "[+] /dev/smd11 (AT data channel) ready."
fi

# 4. Display Current Telephony State
echo "[*] Current Modem State:"
getprop gsm.version.baseband
getprop gsm.network.type

echo "[+] Samsung Galaxy S5 Qualcomm Diagnostic Stack Ready for AirTAP."
