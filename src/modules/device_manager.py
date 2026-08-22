#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTap — Physical Mobile Device Connection & Live Traffic Manager
Enables seamless discovery, connection, diag mode switching, and real-time
baseband traffic streaming from Android/Qualcomm handsets (ADB, Serial COM, USB).
"""

import threading
import time
import re
from typing import Optional, Dict, List, Any
from shutil import which
from subprocess import run, PIPE, STDOUT, DEVNULL

from ..inputs.adb import AdbConnector, AIRTAP_TCP_PORT
from ..inputs.usb_modem_pyserial import UsbModemPyserialConnector
from ..inputs.tcp_connector import TcpConnector
from ..inputs.usb_modem_pyusb_devfinder import PyusbDevInterface
from ..inputs._base_input import BaseInput

class DeviceManager:
    """Manages physical mobile device discovery, connectivity, and real traffic streaming."""

    def __init__(self, gui_server = None):
        self.gui_server = gui_server
        self.active_input: Optional[BaseInput] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.is_streaming = False
        self.current_device: Dict[str, Any] = {
            'connected': False,
            'type': None,
            'id': None,
            'name': 'No device connected',
            'baseband': None,
            'transport': None,
            'packets_streamed': 0,
            'error': None
        }
        self.lock = threading.Lock()

    def scan_devices(self) -> List[Dict[str, Any]]:
        """Scan all attached physical mobile devices via ADB, Serial COM, and PyUSB."""
        results = []
        adb_exe = which('adb')

        # 1. Scan ADB attached Android devices
        if adb_exe:
            try:
                proc = run([adb_exe, 'devices', '-l'], stdout=PIPE, stderr=STDOUT, stdin=DEVNULL, timeout=4)
                output = proc.stdout.decode('utf-8', 'ignore') if proc.stdout else ''
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith('List of devices') or line.startswith('*'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        dev_id = parts[0]
                        model = 'Android Device'
                        product = ''
                        for p in parts[2:]:
                            if p.startswith('model:'):
                                model = p.split('model:')[1]
                            elif p.startswith('product:'):
                                product = p.split('product:')[1]

                        # Query detailed device telemetry
                        brand = ''
                        baseband = ''
                        diag_exists = False
                        is_root = False

                        try:
                            prop_proc = run(
                                [adb_exe, '-s', dev_id, 'shell',
                                 'getprop ro.product.brand; getprop gsm.version.baseband; test -e /dev/diag && echo DIAG_YES; id'],
                                stdout=PIPE, stderr=STDOUT, stdin=DEVNULL, timeout=3
                            )
                            prop_out = prop_proc.stdout.decode('utf-8', 'ignore').splitlines() if prop_proc.stdout else []
                            if len(prop_out) >= 1:
                                brand = prop_out[0].strip()
                            if len(prop_out) >= 2:
                                baseband = prop_out[1].strip()
                            diag_exists = any('DIAG_YES' in l for l in prop_out)
                            is_root = any('uid=0' in l for l in prop_out)
                        except Exception:
                            pass

                        device_name = f"{brand} {model}".strip() if brand else model
                        results.append({
                            'type': 'adb',
                            'id': dev_id,
                            'name': device_name,
                            'model': model,
                            'brand': brand,
                            'product': product,
                            'baseband': baseband or 'Qualcomm Baseband',
                            'diag_ready': diag_exists,
                            'is_root': is_root,
                            'transport': 'ADB (/dev/diag bridge)',
                            'status': 'Online (Ready to Stream)' if diag_exists else 'Online (Needs Diag Mode)'
                        })
            except Exception:
                pass

        # 2. Scan Serial COM / TTY ports
        try:
            import serial.tools.list_ports
            for port in serial.tools.list_ports.comports():
                dev_path = port.device
                desc = port.description or ''
                hwid = port.hwid or ''
                is_qc = any(k in (desc + hwid).lower() for k in ('qualcomm', 'diag', '9008', '901d', '9091', 'modem', 'samsung'))
                results.append({
                    'type': 'serial',
                    'id': dev_path,
                    'name': f"{desc} ({dev_path})",
                    'model': desc,
                    'brand': 'Serial / USB Modem',
                    'product': hwid,
                    'baseband': 'Qualcomm QC-Diag Serial',
                    'diag_ready': True,
                    'is_root': True,
                    'transport': f"Serial Port ({dev_path})",
                    'status': 'Qualcomm Diag Port' if is_qc else 'Serial COM Port'
                })
        except Exception:
            pass

        return results

    def connect(self, device_type: str, device_id: str) -> Dict[str, Any]:
        """Connect to a physical mobile device and begin streaming live cellular signaling frames."""
        with self.lock:
            if self.is_streaming:
                self.disconnect()

            try:
                if device_type == 'adb':
                    diag_input = AdbConnector(device_serial=device_id)
                elif device_type == 'serial':
                    diag_input = UsbModemPyserialConnector(device_id)
                elif device_type == 'tcp':
                    diag_input = TcpConnector(device_id)
                else:
                    raise ValueError(f"Unknown device transport type: {device_type}")

                self.active_input = diag_input

                # Attach GUI server as receiver module
                if self.gui_server:
                    self.active_input.add_module(self.gui_server)
                    if hasattr(self.gui_server, 'sec_auditor') and self.gui_server.sec_auditor:
                        self.active_input.add_module(self.gui_server.sec_auditor)

                self.is_streaming = True
                self.current_device = {
                    'connected': True,
                    'type': device_type,
                    'id': device_id,
                    'name': f"{device_type.upper()}: {device_id}",
                    'baseband': getattr(self.gui_server, 'device_info', {}).get('chipset', 'Active Qualcomm Baseband'),
                    'transport': f"{device_type.upper()} ({device_id})",
                    'packets_streamed': 0,
                    'error': None
                }

                # Start real-time background read loop
                self.reader_thread = threading.Thread(target=self._read_loop_worker, daemon=True)
                self.reader_thread.start()

                # Broadcast device update
                if self.gui_server:
                    self.gui_server.broadcast('device_status', self.current_device)

                return {'status': 'ok', 'message': f'Connected to {device_id}', 'device': self.current_device}

            except Exception as e:
                self.is_streaming = False
                self.active_input = None
                self.current_device['connected'] = False
                self.current_device['error'] = str(e)
                return {'status': 'error', 'message': str(e)}

    def _read_loop_worker(self):
        """Worker thread executing the real hardware HDLC packet read loop."""
        try:
            if self.active_input:
                self.active_input.read_loop()
        except Exception as e:
            self.current_device['error'] = str(e)
        finally:
            self.is_streaming = False
            self.current_device['connected'] = False
            if self.gui_server:
                self.gui_server.broadcast('device_status', self.current_device)

    def disconnect(self) -> Dict[str, Any]:
        """Disconnect the active mobile device input cleanly."""
        with self.lock:
            if self.active_input:
                try:
                    self.active_input.dispose()
                except Exception:
                    pass
            self.active_input = None
            self.is_streaming = False
            self.current_device = {
                'connected': False,
                'type': None,
                'id': None,
                'name': 'No device connected',
                'baseband': None,
                'transport': None,
                'packets_streamed': 0,
                'error': None
            }
            if self.gui_server:
                self.gui_server.broadcast('device_status', self.current_device)
            return {'status': 'ok', 'message': 'Device disconnected'}

    def switch_diag_mode(self, device_id: str) -> Dict[str, Any]:
        """Trigger root Qualcomm diag mode-switch on an Android device over ADB."""
        adb_exe = which('adb') or 'adb'
        cmd = [
            adb_exe, '-s', device_id, 'shell',
            'setprop sys.usb.config diag,adb ; chmod 666 /dev/diag 2>/dev/null ; ls -l /dev/diag'
        ]
        try:
            res = run(cmd, stdout=PIPE, stderr=STDOUT, stdin=DEVNULL, timeout=5)
            out = res.stdout.decode('utf-8', 'ignore') if res.stdout else ''
            success = '/dev/diag' in out
            return {
                'status': 'ok' if success else 'error',
                'output': out.strip(),
                'diag_ready': success
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def get_status(self) -> Dict[str, Any]:
        """Return current real device status."""
        return {
            'status': 'ok',
            'device': self.current_device,
            'is_streaming': self.is_streaming,
            'total_packets': len(self.gui_server.packet_history) if self.gui_server else 0
        }
