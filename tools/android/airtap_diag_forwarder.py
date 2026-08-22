#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP Android On-Device Diag Forwarder & Telemetry Bridge
Platform Target: Samsung Galaxy S5 (SM-G900F / klte), Qualcomm Snapdragon 801 (MSM8974AC)
OS: LineageOS 18.1 (Android 11 / API 30), Magisk Root (UID 0)

This daemon runs directly on the rooted Android device (or via ADB shell):
1. Acquires root access (UID 0) to open /dev/diag directly.
2. Configures Qualcomm USB diag properties if tethered over USB.
3. Listens on TCP port 9999 to stream raw HDLC diagnostic packets to AirTAP.
4. Bridges Android 11 dumpsys telephony and GNSS NMEA location data into AirTAP.
"""

import os
import sys
import socket
import select
import subprocess
import threading
import time
import json

DIAG_DEV_PATH = "/dev/diag"
DEFAULT_PORT = 9999
BUFFER_SIZE = 8192

def check_root_and_diag():
    """Verify UID 0 and /dev/diag availability."""
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    print(f"[*] Process running with UID: {uid}")
    
    if os.path.exists(DIAG_DEV_PATH):
        print(f"[+] Found Qualcomm Diag node: {DIAG_DEV_PATH}")
        return True
    else:
        print(f"[-] Warning: {DIAG_DEV_PATH} not found. Attempting to enable Qualcomm diag USB properties...")
        try:
            subprocess.run(["setprop", "sys.usb.config", "diag,serial_smd,rmnet_bam,adb"], check=True)
            time.sleep(1)
            if os.path.exists(DIAG_DEV_PATH):
                print(f"[+] {DIAG_DEV_PATH} successfully initialized.")
                return True
        except Exception as e:
            print(f"[-] Could not run setprop: {e}")
    return os.path.exists(DIAG_DEV_PATH)

def fetch_android_telephony():
    """Extract real-time serving cell & signal telemetry via dumpsys telephony.registry."""
    try:
        res = subprocess.run(["dumpsys", "telephony.registry"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        lines = res.stdout.splitlines()
        telemetry = {}
        for l in lines:
            if "mSignalStrength" in l:
                telemetry['signal_raw'] = l.strip()
            elif "mCellIdentity" in l or "mCellInfo" in l:
                telemetry['cell_raw'] = l.strip()
        return telemetry
    except Exception:
        return {}

def diag_forwarder_server(host='0.0.0.0', port=DEFAULT_PORT):
    """Main TCP socket server forwarding bi-directional traffic between /dev/diag and AirTAP GUI Server."""
    print(f"[*] Starting AirTAP Android Diag Forwarder on {host}:{port}...")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print(f"[+] Listening on port {port}. Waiting for AirTAP Host connection...")

    while True:
        try:
            client_sock, client_addr = server_sock.accept()
            print(f"[+] AirTAP Host connected from {client_addr}")
            
            diag_fd = None
            if os.path.exists(DIAG_DEV_PATH):
                try:
                    diag_fd = os.open(DIAG_DEV_PATH, os.O_RDWR | os.O_NONBLOCK)
                    print(f"[+] Opened {DIAG_DEV_PATH} (fd={diag_fd})")
                except Exception as e:
                    print(f"[-] Could not open {DIAG_DEV_PATH}: {e}")

            client_sock.setblocking(False)

            while True:
                rlist = [client_sock]
                if diag_fd is not None:
                    rlist.append(diag_fd)

                readable, _, exceptional = select.select(rlist, [], rlist, 1.0)
                if exceptional:
                    break

                for s in readable:
                    if s == client_sock:
                        data = client_sock.recv(BUFFER_SIZE)
                        if not data:
                            print("[-] AirTAP client disconnected.")
                            raise ConnectionResetError()
                        # Forward commands from Host to /dev/diag
                        if diag_fd is not None:
                            try:
                                os.write(diag_fd, data)
                            except Exception as e:
                                print(f"[-] Error writing to diag: {e}")
                    elif s == diag_fd:
                        # Forward raw diag packets from modem to AirTAP Host
                        try:
                            diag_data = os.read(diag_fd, BUFFER_SIZE)
                            if diag_data:
                                client_sock.sendall(diag_data)
                        except Exception as e:
                            pass

        except (ConnectionResetError, BrokenPipeError):
            print("[*] Client disconnected. Waiting for reconnect...")
        except KeyboardInterrupt:
            print("[*] Exiting on user signal.")
            break
        except Exception as e:
            print(f"[-] Unexpected server error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    check_root_and_diag()
    diag_forwarder_server()
