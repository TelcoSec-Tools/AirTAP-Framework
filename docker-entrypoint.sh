#!/usr/bin/env bash
# ==============================================================================
# AirTap container entrypoint - TelcoSec
#
# Prepares the hardware path (USB visibility, adb server, GUI relay) and then
# execs airtap with whatever arguments the container was given.
#
# Any argument that is not one of the helper verbs below is passed straight
# through to airtap, so `docker run ... --adb --pcap-dump /captures/x.pcap`
# behaves exactly like the native CLI.
# ==============================================================================
set -euo pipefail

log()  { printf '\033[36m[airtap]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[airtap]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[airtap]\033[0m %s\n' "$*" >&2; }

# ------------------------------------------------------------------------------
# Hardware access diagnostics
#
# Rather than failing opaquely deep inside pyusb, say up front which of the
# three access paths (raw USB / adb / replay-only) is actually available.
# ------------------------------------------------------------------------------
check_hardware() {
    local have_usb=0

    if [ -d /dev/bus/usb ]; then
        have_usb=1
        if command -v lsusb >/dev/null 2>&1; then
            local devs
            # Qualcomm 05c6, Samsung 04e8, MediaTek 0e8d, Intel/Fibocom 8087,
            # Quectel 2c7c, Sierra 1199, Telit 1bc7, Huawei 12d1, ZTE 19d2.
            devs=$(lsusb 2>/dev/null | grep -iE '05c6|04e8|0e8d|8087|2c7c|1199|1bc7|12d1|19d2|qualcomm|samsung|mediatek|quectel|sierra|telit|huawei|zte' || true)
            if [ -n "$devs" ]; then
                log "Baseband-capable USB devices visible:"
                printf '%s\n' "$devs" | sed 's/^/           /' >&2
            else
                warn "/dev/bus/usb is mounted but no known baseband VID/PID is present."
                warn "Plug the device in, or check it is not claimed by the host."
            fi
        fi
    else
        warn "/dev/bus/usb is NOT mounted - raw USB DIAG access is unavailable."
        warn "Re-run with: --privileged -v /dev/bus/usb:/dev/bus/usb"
    fi

    if [ ! -e /dev/bus/usb ] && [ -z "$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true)" ]; then
        warn "No USB serial nodes (/dev/ttyUSB*, /dev/ttyACM*) either."
    fi

    return 0
}

# ------------------------------------------------------------------------------
# adb
#
# The container shares the host's USB bus, so the adb server must run here.
# Two servers competing for the same device is the usual cause of
# 'device unauthorized' loops: stop the one on the host, or use ADB_SERVER_SOCKET
# to point this container at it instead (see the compose file).
# ------------------------------------------------------------------------------
start_adb() {
    command -v adb >/dev/null 2>&1 || { warn "adb not found; skipping."; return 0; }

    if [ -n "${ADB_SERVER_SOCKET:-}" ]; then
        log "Using external adb server at ${ADB_SERVER_SOCKET}"
    else
        log "Starting adb server in-container..."
        adb start-server >/dev/null 2>&1 || warn "adb server failed to start."
    fi

    local out
    out=$(adb devices 2>/dev/null | sed '1d' | grep -v '^$' || true)
    if [ -n "$out" ]; then
        log "ADB devices:"
        printf '%s\n' "$out" | sed 's/^/           /' >&2
        # DIAG over adb needs root on the device; harmless when unsupported.
        if [ "${AIRTAP_ADB_ROOT:-1}" = "1" ]; then
            adb root >/dev/null 2>&1 || true
        fi
    else
        warn "No ADB devices. Check the cable, USB debugging, and that the host"
        warn "adb server is stopped (host: 'adb kill-server')."
    fi
    return 0
}

# ------------------------------------------------------------------------------
# GUI relay
#
# GuiServer is constructed as GuiServer(diag_input) in src/main.py, which binds
# host='127.0.0.1' with no CLI or env override. From outside the container that
# is unreachable, so relay 0.0.0.0:5000 -> 127.0.0.1:5000 when --gui is used.
# This keeps the framework source untouched.
# ------------------------------------------------------------------------------
start_gui_relay() {
    command -v socat >/dev/null 2>&1 || { warn "socat missing; GUI will be loopback-only."; return 0; }
    # GuiServer always binds 127.0.0.1:5000 (hardcoded in src/main.py), so that
    # is the fixed relay target.
    local internal=5000
    # The relay MUST listen on a different port: the kernel refuses
    # 0.0.0.0:5000 while anything holds 127.0.0.1:5000 ("Address already in
    # use"), so reusing 5000 here would kill socat the moment the GUI starts.
    local ext="${AIRTAP_GUI_PORT:-5080}"

    if [ "$ext" = "$internal" ]; then
        err "AIRTAP_GUI_PORT must not be ${internal}; the GUI already owns that"
        err "port on loopback. Pick another (e.g. 5080) and publish it."
        return 0
    fi

    log "Relaying GUI 0.0.0.0:${ext} -> 127.0.0.1:${internal}"
    log "Publish it with -p 5000:${ext} and open http://localhost:5000"
    socat "TCP-LISTEN:${ext},fork,reuseaddr,bind=0.0.0.0" "TCP:127.0.0.1:${internal}" &
    return 0
}

wants_gui() {
    for a in "$@"; do
        case "$a" in
            -g|--gui) return 0 ;;
        esac
    done
    return 1
}

# ------------------------------------------------------------------------------
# Helper verbs
# ------------------------------------------------------------------------------
case "${1:-}" in
    shell|bash)
        shift
        check_hardware; start_adb
        exec /bin/bash "$@"
        ;;
    lsusb)
        exec lsusb -v
        ;;
    tshark)
        shift
        exec tshark "$@"
        ;;
    selftest)
        log "AirTap container self-test"
        python -c "\
import airtap, serial, usb.core, crcmod; \
from pycrate_core.utils import pack_val; \
from pycrate_asn1dir import RRC3G, RRCLTE, RRCNR; \
print('[airtap] imports OK (incl. LTE/NR RRC ASN.1), version', airtap.__version__)"
        command -v tshark >/dev/null && log "tshark: $(tshark --version 2>/dev/null | head -1)"
        command -v adb   >/dev/null && log "adb:    $(adb --version 2>/dev/null | head -1)"
        ls /root/.local/lib/wireshark/plugins/*.lua >/dev/null 2>&1 \
            && log "GSMTAP Lua dissectors installed" \
            || warn "No Lua dissectors found"
        check_hardware
        exit 0
        ;;
esac

# ------------------------------------------------------------------------------
# Normal path: prepare hardware, then hand off to airtap
# ------------------------------------------------------------------------------
check_hardware

if [ "${AIRTAP_SKIP_ADB:-0}" != "1" ]; then
    start_adb
fi

if wants_gui "$@"; then
    start_gui_relay
fi

# --wireshark-live spawns the Wireshark GUI, which needs an X display.
if printf '%s\n' "$@" | grep -qE '^(-l|--live|--wireshark-live)$'; then
    if [ -z "${DISPLAY:-}" ]; then
        err "--wireshark-live needs the Wireshark GUI and no DISPLAY is set."
        err "Either pass -e DISPLAY and mount /tmp/.X11-unix, or write a file"
        err "with --pcap-dump /captures/capture.pcap and open it on the host."
        exit 1
    fi
fi

log "exec airtap $*"
exec airtap "$@"
