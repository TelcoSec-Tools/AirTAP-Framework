#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from subprocess import Popen, run, PIPE, DEVNULL, STDOUT, TimeoutExpired, list2cmdline
from socket import socket, AF_INET, SOCK_STREAM
from logging import debug, error, info, warning
from os.path import realpath, dirname, exists
from sys import stderr, platform
from traceback import print_exc
from functools import partial
from typing import Optional
from shutil import which
from time import sleep
from re import search

try:
    from os import setpgrp, getenv, setresgid, setresuid, setgroups, getgrouplist
    from pwd import getpwuid
    IS_UNIX = True

except Exception:
    IS_UNIX = False

from .usb_modem_pyusb_devfinder import PyusbDevInterface
from ._hdlc_mixin import HdlcMixin
from ._base_input import BaseInput

INPUTS_DIR = dirname(realpath(__file__))
ADB_BRIDGE_DIR = realpath(INPUTS_DIR + '/adb_bridge')
ADB_BIN_DIR = realpath(INPUTS_DIR + '/external/adb')

ANDROID_TMP_DIR = '/data/local/tmp'

def drop_privileges(detach_process = False):

    try:
        # Don't be hit by CTRL+C

        if detach_process:
            setpgrp()
        
        # Drop privileges if needed

        uid, gid = getenv('SUDO_UID'), getenv('SUDO_GID')
        
        if uid and gid:
            uid, gid = int(uid), int(gid)

            setgroups(getgrouplist(getpwuid(uid).pw_name, gid))
            setresgid(gid, gid, -1)
            setresuid(uid, uid, -1)
    
    except Exception:
        print_exc()

if not IS_UNIX:
    drop_privileges = None

# Print adb output to stdout when "-v" is passed to AirTap

def run_safe(args, **kwargs):
    debug('[>] Running adb command: ' + list2cmdline(args))
    result = run(args, preexec_fn = drop_privileges, **kwargs)
    result_string = ((result.stdout or b'') + (result.stderr or b''))
    if result and result_string:
        debug('[<] Obtained result for running "%s": %s' % (list2cmdline(args), result_string))
    return result

"""
    This class implements reading Qualcomm DIAG data from a the /dev/diag
    character device, on a remote Android device connected through ADB.
    
    For this, it uploads the C program located in "./adb_bridge/" which
    creates a TCP socket acting as a proxy to /dev/diag.
"""

AIRTAP_TCP_PORT = 43555

class AdbConnector(HdlcMixin, BaseInput):
    
    def __init__(self, adb_exe = None, adb_host = 'localhost', device_serial = None):
        self._disposed = False
        self.device_serial = device_serial

        if not adb_exe:
            self.adb_exe = which('adb')
            if not self.adb_exe:
                if platform in ('cygwin', 'win32'):
                    self.adb_exe = ADB_BIN_DIR + '/adb_windows.exe'
                elif platform == 'darwin':
                    self.adb_exe = which('adb') or (ADB_BIN_DIR + '/adb_macos')
                else:
                    self.adb_exe = which('adb') or (ADB_BIN_DIR + '/adb_linux')
        else:
            self.adb_exe = adb_exe

        self.adb_host = adb_host
        self.su_command = '%s'
        self.can_use_exec_out = None
        self.ADB_TIMEOUT = 10

        # Use Diag-over-USB if available for the device.
        self.usb_modem : Optional[PyusbDevInterface] = self._check_for_usb_diag_interface()
        if self.usb_modem:
            return
        
        # Check current shell user and root capabilities
        id_out = self.adb_shell('id')
        if 'uid=0' in id_out:
            self.su_command = '%s'
        elif 'uid=0' in self.adb_shell("su -c id 2>/dev/null"):
            self.su_command = "su -c '%s'"
        elif 'uid=0' in self.adb_shell("su 0,0 sh -c id 2>/dev/null"):
            self.su_command = "su 0,0 sh -c '%s'"
        else:
            run_safe(self.adb_cmd_prefix() + ['root'], stdout = PIPE, stderr = STDOUT, stdin = DEVNULL)
            run_safe(self.adb_cmd_prefix() + ['wait-for-device'], stdin = DEVNULL)
            id_out = self.adb_shell('id')
            if 'uid=0' in id_out:
                self.su_command = '%s'
            elif 'uid=0' in self.adb_shell("su -c id 2>/dev/null"):
                self.su_command = "su -c '%s'"

        # Send batch commands to check for the presence of /dev/diag through adb
        bash_output = self.adb_shell(
            'test -w /dev/diag; echo DIAG_NOT_WRITEABLE=$?; ' +
            'test -e /dev/diag; echo DIAG_NOT_EXISTS=$?; ' +
            'test -e /dev/ffs-diag; echo FFS_DIAG_NOT_HERE=$?'
        )

        if 'DIAG_NOT_EXISTS=1' in bash_output and 'FFS_DIAG_NOT_HERE=0' in bash_output:
            # Mode-switch the device
            for command in ['setprop sys.usb.config diag,adb']:
                self.adb_shell(self.su_command % command)
                sleep(2)
                self.usb_modem = self._check_for_usb_diag_interface()
                if self.usb_modem:
                    return
                if platform in ('cygwin', 'win32'):
                    self.usb_modem = PyusbDevInterface.auto_find()
                    if not self.usb_modem.not_found_reason:
                        return

        # Upload the adb_bridge
        adb = run_safe(self.adb_cmd_prefix() + ['push', ADB_BRIDGE_DIR + '/adb_bridge', ANDROID_TMP_DIR],
            stdin = DEVNULL, stdout = PIPE, stderr = STDOUT
        )
        
        if b'error' in (adb.stdout or b'') and adb.returncode != 0:
            error('Could not transfer "adb_bridge" onto the device: ' + (adb.stdout or b'').decode('utf8', 'ignore'))
            raise RuntimeError('Failed to push adb_bridge to mobile handset')
        
        # Launch the adb_bridge
        self._relaunch_adb_bridge()
        self.packet_buffer = b''
        super().__init__()

    def adb_cmd_prefix(self):
        cmd = [self.adb_exe]
        if self.device_serial:
            cmd.extend(['-s', self.device_serial])
        return cmd

    def _check_for_usb_diag_interface(self) -> Optional[PyusbDevInterface]:
        devices_list = run_safe(self.adb_cmd_prefix() + ['devices', '-l'],
            stdin = DEVNULL, stdout = PIPE, stderr = STDOUT).stdout.decode('utf8', 'ignore')

        device_num = search(r'usb:(\d+)-(\d+)', devices_list)
        if device_num and exists('/sys/bus/usb/devices'):
            bus_idx = int(device_num.group(1), 10)
            port_idx = int(device_num.group(2), 10)
            dev_intf = PyusbDevInterface.from_bus_port(bus_idx, port_idx)
            if not dev_intf.not_found_reason:
                return dev_intf
        return None

    def _relaunch_adb_bridge(self, max_retries=8):
        if hasattr(self, 'adb_proc') and self.adb_proc:
            try:
                self.adb_proc.terminate()
            except Exception:
                pass
            self.adb_proc = None

        if hasattr(self, 'socket') and self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        # Ensure execute permissions and kill old instances
        self.adb_shell('chmod 777 ' + ANDROID_TMP_DIR + '/adb_bridge')
        self.adb_shell(self.su_command % ('chmod 777 ' + ANDROID_TMP_DIR + '/adb_bridge'))
        self.adb_shell('killall -9 adb_bridge 2>/dev/null || pkill -9 -f adb_bridge 2>/dev/null || true')
        sleep(0.3)

        run_safe(self.adb_cmd_prefix() + ['forward', 'tcp:' + str(AIRTAP_TCP_PORT), 'tcp:' + str(AIRTAP_TCP_PORT)],
                stdout = DEVNULL, stdin = DEVNULL)

        self.adb_proc = Popen(self.adb_cmd_prefix() + ['exec-out' if self.can_use_exec_out else 'shell', self.su_command % (ANDROID_TMP_DIR + '/adb_bridge')],
            stdin = DEVNULL, stdout = PIPE, stderr = STDOUT,
            preexec_fn = (lambda: partial(drop_privileges, True)) if drop_privileges else None,
            bufsize = 0, universal_newlines = True
        )

        for line in self.adb_proc.stdout:
            clean_line = line.strip()
            if 'Connection to Diag established' in clean_line:
                break
            elif 'DIAG_IOCTL_PERIPHERAL_BUF_CONFIG' in clean_line or 'Address already in use' in clean_line:
                debug('adb_bridge notice: ' + clean_line)
            else:
                debug('adb_bridge output: ' + clean_line)

        # Retry connecting to mobile adb_bridge with backoff to handle device boot/bridge initialization
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.settimeout(2.0)
        connected = False
        last_error = None

        for attempt in range(max_retries):
            try:
                self.socket.connect((self.adb_host, AIRTAP_TCP_PORT))
                self.socket.settimeout(None)
                connected = True
                break
            except Exception as e:
                last_error = e
                sleep(0.25)

        if not connected:
            if hasattr(self, 'adb_proc') and self.adb_proc:
                try:
                    self.adb_proc.terminate()
                except Exception:
                    pass
                self.adb_proc = None
            error('Could not communicate with the adb_bridge through TCP: %s' % last_error)
            raise RuntimeError('Could not establish TCP connection to mobile adb_bridge on port %s (%s)' % (AIRTAP_TCP_PORT, last_error))

        self.received_first_packet = False

    def adb_shell(self, command):
        try:
            if self.can_use_exec_out is None:
                adb = run_safe(self.adb_cmd_prefix() + ['exec-out', 'id'],
                    stdin = DEVNULL, stdout = PIPE, stderr = STDOUT, timeout = self.ADB_TIMEOUT
                )
                self.can_use_exec_out = (adb.returncode == 0)

            adb = run_safe(self.adb_cmd_prefix() + ['exec-out' if self.can_use_exec_out else 'shell', self.su_command % command],
                stdin = DEVNULL, stdout = PIPE, stderr = STDOUT, timeout = self.ADB_TIMEOUT
            )
        except TimeoutExpired:
            error('Communication with adb timed out.')
            return ''

        if (adb.stdout and (b'device not found' in adb.stdout or b'no devices' in adb.stdout)):
            error('Could not connect to adb device.')
            return ''
        
        return (adb.stdout or b'').decode('utf8', 'ignore').strip()
    
    def send_request(self, packet_type, packet_payload):
        raw_payload = self.hdlc_encapsulate(bytes([packet_type]) + packet_payload)
        if hasattr(self, 'socket') and self.socket:
            try:
                self.socket.send(raw_payload)
            except Exception as e:
                debug('Failed to send Diag request: %s' % e)
    
    def get_gps_location(self):
        lat = None
        lng = None
        
        gps_info = run_safe([self.adb_exe, 'exec-out' if self.can_use_exec_out else 'shell', 'dumpsys', 'location'], stdout = PIPE)
        gps_info = gps_info.stdout.decode('utf8')
        
        gps_info = search(r'(\d+\.\d+),(\d+\.\d+)', gps_info)
        if gps_info:
            lat, lng = map(float, gps_info.groups())
        
        return lat, lng
    
    def read_loop(self):
        while not getattr(self, 'program_is_terminating', False):
            try:
                while self.TRAILER_CHAR not in self.packet_buffer:
                    try:
                        socket_read = self.socket.recv(1024 * 1024 * 10) if self.socket else b''
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError, OSError) as sock_err:
                        debug('Socket read exception on mobile bridge: %s' % sock_err)
                        socket_read = b''

                    if not socket_read:
                        if getattr(self, 'program_is_terminating', False):
                            return

                        warning('\n[!] Mobile baseband connection lost on ADB bridge. Initiating auto-reconnect...')
                        reconnected = False
                        backoff = 1.0

                        while not getattr(self, 'program_is_terminating', False) and not reconnected:
                            try:
                                # Poll for mobile handset presence on ADB
                                dev_check = run_safe(self.adb_cmd_prefix() + ['devices'], stdout=PIPE, stderr=STDOUT)
                                dev_out = (dev_check.stdout or b'').decode('utf8', 'ignore')
                                if 'device\n' in dev_out or '\tdevice' in dev_out:
                                    self._relaunch_adb_bridge()
                                    reconnected = True
                                    info('[+] Mobile device successfully reconnected! Resuming live telemetry capture.')
                                    if hasattr(self, '_init_modules'):
                                        self._init_modules()
                                    break
                            except Exception as rec_err:
                                debug('Reconnection attempt failed: %s' % rec_err)

                            sleep(backoff)
                            backoff = min(backoff * 1.5, 5.0)

                        if reconnected:
                            continue
                        else:
                            return

                    self.packet_buffer += socket_read

                while self.TRAILER_CHAR in self.packet_buffer:
                    raw_payload, self.packet_buffer = self.packet_buffer.split(self.TRAILER_CHAR, 1)

                    try:
                        unframed_message = self.hdlc_decapsulate(
                            payload = raw_payload + self.TRAILER_CHAR
                        )
                    except self.InvalidFrameError:
                        continue
                    finally:
                        self.received_first_packet = True

                    self.dispatch_received_diag_packet(unframed_message)

            except Exception as loop_err:
                if getattr(self, 'program_is_terminating', False):
                    return
                debug('Exception in mobile read loop: %s' % loop_err)
                sleep(0.5)

    def dispose(self, disposing=True):

        if not self._disposed:
            if hasattr(self, 'adb_proc'):
                self.adb_proc.terminate()

            self._disposed = True
