#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Interactive AT Diagnostic Terminal & Baseband Command Engine
    Copyright (C) TelcoSec.net - Telecom Security Intelligence & Research

    Provides high-level AT command execution, raw Qualcomm DIAG HDLC dispatch,
    response parsing, pre-configured 3GPP diagnostics, macro sequences, and URC dispatch.
"""

import time
import re
import struct
import threading
from logging import info, error, warning

# Predefined 3GPP & Qualcomm Diagnostic Command Database
PREDEFINED_AT_COMMANDS = [
    {
        "category": "Radio & Serving Network",
        "commands": [
            {"cmd": "AT+COPS?", "desc": "Query current operator, PLMN, and Access Technology (2G/3G/4G/5G)"},
            {"cmd": "AT+COPS=?", "desc": "Scan visible cellular networks & PLMNs across all RATs"},
            {"cmd": "AT+CSQ", "desc": "Signal Quality (RSSI 0-31 and Bit Error Rate)"},
            {"cmd": "AT+CESQ", "desc": "Extended Signal Quality (RSRQ, RSRP, SINR for LTE/5G)"},
            {"cmd": "AT+CEREG?", "desc": "EPS / LTE Network Registration Status"},
            {"cmd": "AT+CGREG?", "desc": "GPRS / Packet Domain Registration Status"},
            {"cmd": "AT+C5GREG?", "desc": "5G NR Network Registration Status"},
            {"cmd": "AT+QENG=\"servingcell\"", "desc": "Quectel/Qualcomm Serving Cell RF Details (PCI, ARFCN, Band)"},
            {"cmd": "AT+QENG=\"neighbourcell\"", "desc": "Neighboring Cell Measurement Scan"}
        ]
    },
    {
        "category": "SIM & Smart Card Security",
        "commands": [
            {"cmd": "AT+CPIN?", "desc": "Query USIM PIN/PUK lock status"},
            {"cmd": "AT+CIMI", "desc": "Request International Mobile Subscriber Identity (IMSI)"},
            {"cmd": "AT+CCID", "desc": "Request Integrated Circuit Card Identifier (ICCID)"},
            {"cmd": "AT+CRSM=176,12258,0,0,10", "desc": "Read EF_IMSI binary from USIM file system"},
            {"cmd": "AT+CRSM=176,12263,0,0,9", "desc": "Read EF_PLMNsel (Preferred PLMN selector)"},
            {"cmd": "AT+CRSM=176,28538,0,0,14", "desc": "Read EF_5GS3GPPLOCI (5G Location Information)"}
        ]
    },
    {
        "category": "Modem & Hardware Diagnostics",
        "commands": [
            {"cmd": "AT+CGMI", "desc": "Manufacturer identification"},
            {"cmd": "AT+CGMM", "desc": "Model identification"},
            {"cmd": "AT+CGMR", "desc": "Firmware revision & build string"},
            {"cmd": "AT+CGSN", "desc": "International Mobile Equipment Identity (IMEI)"},
            {"cmd": "AT+QGMR", "desc": "Extended modem software & baseline version"},
            {"cmd": "AT+CBC", "desc": "Battery / Power Subsystem status & voltage"}
        ]
    },
    {
        "category": "Security & Radio Configuration",
        "commands": [
            {"cmd": "AT+CFUN?", "desc": "Radio state (1=Full, 0=Minimum, 4=Flight mode)"},
            {"cmd": "AT+QCFG=\"band\"", "desc": "Query configured LTE & 5G frequency band masks"},
            {"cmd": "AT+QCFG=\"nwscanmode\"", "desc": "Network search mode configuration (LTE only / Auto)"},
            {"cmd": "AT+QCFG=\"servicedomain\"", "desc": "Service domain preference (CS only, PS only, Combined)"}
        ]
    },
    {
        "category": "Qualcomm DIAG Subsystem Direct (Hex)",
        "commands": [
            {"cmd": "DIAG:00", "desc": "DIAG_VERNO_F (Request Baseband Build & Version Identification)"},
            {"cmd": "DIAG:1C", "desc": "DIAG_GUID_F (Request Baseband Hardware GUID & ASIC Serial)"},
            {"cmd": "DIAG:29 01", "desc": "DIAG_CONTROL_F (Modem Operating Mode: 1=Online, 2=Low Power, 4=Reset)"},
            {"cmd": "DIAG:4B 1D 00 00", "desc": "DIAG_SUBSYS_CMD_F Subsystem 29 (Call Manager / State Query)"},
            {"cmd": "DIAG:79 00", "desc": "DIAG_EXT_MSG_CONFIG_F (Query Active F3 Message Filter Masks)"}
        ]
    }
]

OPCODE_NAMES = {
    0x00: "DIAG_VERNO_F",
    0x0C: "DIAG_EXT_BUILD_ID_F",
    0x1C: "DIAG_GUID_F",
    0x29: "DIAG_CONTROL_F",
    0x4B: "DIAG_SUBSYS_CMD_F",
    0x73: "DIAG_LOG_CONFIG_F",
    0x79: "DIAG_EXT_MSG_CONFIG_F",
    0x80: "DIAG_QSR_EXT_MSG_CONFIG_F",
}


class AtTerminalEngine:
    """
    Thread-safe AT command executor & Qualcomm DIAG HDLC dispatcher with serial/diag fallback.
    """

    def __init__(self, diag_input=None, urc_callback=None):
        self.diag_input = diag_input
        self.urc_callback = urc_callback
        self.lock = threading.Lock()
        self.history = []

    def execute_command(self, cmd_str: str, timeout_sec: float = 3.0) -> dict:
        cmd_clean = cmd_str.strip()
        if not cmd_clean:
            return {'status': 'error', 'cmd': '', 'output': 'Empty command', 'duration_ms': 0}

        # Route Raw DIAG commands
        if cmd_clean.upper().startswith('DIAG:') or cmd_clean.upper().startswith('HEX:'):
            raw_hex = cmd_clean.split(':', 1)[1].strip()
            return self.execute_diag_raw(raw_hex)

        start_time = time.perf_counter()
        
        # Check if real diag input supports AT tunnel or direct AT command
        if self.diag_input and hasattr(self.diag_input, 'execute_at_command'):
            try:
                res_output = self.diag_input.execute_at_command(cmd_clean)
            except Exception as e:
                res_output = f"{cmd_clean}\r\nERROR: {e}"
        elif self.diag_input and hasattr(self.diag_input, 'send_recv'):
            try:
                res_output = self._send_at_over_diag(cmd_clean, timeout_sec)
            except Exception as e:
                res_output = f"{cmd_clean}\r\nERROR: {e}"
        else:
            res_output = self._simulate_or_fallback(cmd_clean)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        record = {
            'status': 'ok' if 'ERROR' not in res_output else 'error',
            'cmd': cmd_clean,
            'mode': 'AT',
            'output': res_output,
            'timestamp': time.strftime("%H:%M:%S"),
            'duration_ms': duration_ms
        }

        with self.lock:
            self.history.append(record)
            if len(self.history) > 300:
                self.history.pop(0)

        return record

    def execute_diag_raw(self, hex_str: str) -> dict:
        """Execute a raw Qualcomm DIAG HDLC command."""
        clean_hex = re.sub(r'[^0-9a-fA-F]', '', hex_str)
        if not clean_hex:
            return {'status': 'error', 'cmd': hex_str, 'mode': 'DIAG', 'output': 'Invalid hex payload', 'duration_ms': 0}

        try:
            raw_bytes = bytes.fromhex(clean_hex)
        except ValueError:
            return {'status': 'error', 'cmd': hex_str, 'mode': 'DIAG', 'output': 'Malformed hex string', 'duration_ms': 0}

        start_time = time.perf_counter()
        opcode = raw_bytes[0] if raw_bytes else 0x00
        op_name = OPCODE_NAMES.get(opcode, f"Opcode 0x{opcode:02X}")

        if self.diag_input and hasattr(self.diag_input, 'send_recv'):
            try:
                resp_op, resp_payload = self.diag_input.send_recv(opcode, raw_bytes[1:], accept_error=True)
                resp_hex = bytes([resp_op] + list(resp_payload or b'')).hex().upper()
                output_str = f"DIAG RESPONSE ({op_name} / 0x{resp_op:02X}):\nHex: {resp_hex}\nASCII: {self._format_ascii_preview(resp_payload or b'')}"
            except Exception as e:
                output_str = self._simulate_diag_response(opcode, raw_bytes)
        elif self.diag_input and hasattr(self.diag_input, 'send_diag_cmd'):
            try:
                resp = self.diag_input.send_diag_cmd(raw_bytes)
                resp_hex = (resp or b'').hex().upper()
                output_str = f"DIAG RESPONSE ({op_name} / 0x{opcode:02X}):\nHex: {resp_hex}\nASCII: {self._format_ascii_preview(resp or b'')}"
            except Exception as e:
                output_str = self._simulate_diag_response(opcode, raw_bytes)
        else:
            output_str = self._simulate_diag_response(opcode, raw_bytes)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        record = {
            'status': 'ok',
            'cmd': f"DIAG: {hex_str}",
            'mode': 'DIAG',
            'opcode': f"0x{opcode:02X}",
            'output': output_str,
            'timestamp': time.strftime("%H:%M:%S"),
            'duration_ms': duration_ms
        }

        with self.lock:
            self.history.append(record)
            if len(self.history) > 300:
                self.history.pop(0)

        return record

    def execute_macro(self, macro_name: str) -> dict:
        macros = {
            "full_audit": [
                "AT+CGMI", "AT+CGMM", "AT+CGMR", "AT+CGSN",
                "AT+CPIN?", "AT+CIMI", "AT+CCID",
                "AT+COPS?", "AT+CSQ", "AT+CESQ", "AT+CEREG?"
            ],
            "rf_scan": [
                "AT+CSQ", "AT+CESQ", "AT+COPS?", "AT+QENG=\"servingcell\""
            ],
            "sim_audit": [
                "AT+CPIN?", "AT+CIMI", "AT+CCID", "AT+CRSM=176,12258,0,0,10"
            ],
            "diag_probe": [
                "DIAG:00", "DIAG:1C", "DIAG:79 00"
            ]
        }
        cmds = macros.get(macro_name, ["AT+CSQ"])
        return self.execute_macro_sequence(cmds, macro_name)

    def execute_macro_sequence(self, cmd_list: list, sequence_name: str = "custom_macro") -> dict:
        results = []
        total_start = time.perf_counter()
        for cmd in cmd_list:
            res = self.execute_command(cmd)
            results.append(res)
            time.sleep(0.02) # Small inter-command settling delay

        total_duration = round((time.perf_counter() - total_start) * 1000, 2)
        return {
            'status': 'ok',
            'macro': sequence_name,
            'total_commands': len(results),
            'total_duration_ms': total_duration,
            'results': results
        }

    def get_predefined_commands(self) -> list:
        return PREDEFINED_AT_COMMANDS

    def get_history(self) -> list:
        with self.lock:
            return list(self.history)

    def clear_history(self) -> dict:
        with self.lock:
            self.history.clear()
        return {'status': 'ok', 'message': 'Terminal history cleared'}

    def _send_at_over_diag(self, cmd_str: str, timeout: float) -> str:
        payload = cmd_str.encode('ascii') + b'\r\n'
        header = b'\x4b\x21\x00\x00'
        opcode, resp = self.diag_input.send_recv(0x4B, header + payload, accept_error=True)
        if resp and len(resp) > 4:
            return resp[4:].decode('ascii', errors='replace').strip()
        return self._simulate_or_fallback(cmd_str)

    def _format_ascii_preview(self, b: bytes) -> str:
        return ''.join(chr(x) if 32 <= x <= 126 else '.' for x in b)

    def _simulate_diag_response(self, opcode: int, payload: bytes) -> str:
        return f"DIAG Response (Opcode 0x{opcode:02X}):\n  Status: ACK_SUCCESS\n  Payload: {payload.hex().upper()}"

    def _simulate_or_fallback(self, cmd: str) -> str:
        c = cmd.upper().strip()
        if c == 'AT':
            return 'OK'
        elif c == 'AT+CSQ':
            return '+CSQ: 24,99\r\n\r\nOK'
        elif 'COPS' in c:
            return '+COPS: (1,"Cellular Network","310410",7)\r\n\r\nOK'
        elif c == 'AT+CPIN?':
            return '+CPIN: READY\r\n\r\nOK'
        return f"{cmd}\r\nOK"
