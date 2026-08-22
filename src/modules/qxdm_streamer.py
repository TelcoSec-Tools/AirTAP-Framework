#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from struct import unpack_from, calcsize
from datetime import datetime
import time

from ._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING
from ..protocol.messages import (
    DIAG_MSG_F,
    DIAG_EXT_MSG_F,
    DIAG_EXT_MSG_TERSE_F,
    DIAG_QSR_EXT_MSG_TERSE_F,
    DIAG_QSR4_EXT_MSG_TERSE_F,
)
from ..protocol.qxdm_constants import (
    SSID_NAMES,
    MSG_SEV_NAMES,
    MSG_SEV_LOW,
    MSG_SEV_MED,
    MSG_SEV_HIGH,
    MSG_SEV_ERROR,
    MSG_SEV_FATAL,
    EVENT_NAMES,
)

class QxdmStreamer(EnableLogMixin):
    """
    AirTap QXDM Streamer:
    Decodes real-time Qualcomm F3 Extended Diagnostic Messages and
    Asynchronous Event Reports directly to console and structured logs.
    """

    def __init__(self, diag_input, show_messages = True, show_events = True, min_severity = MSG_SEV_LOW):
        self.diag_input = diag_input
        self.show_messages = show_messages
        self.show_events = show_events
        self.min_severity = min_severity
        
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING

    def on_message(self, opcode, payload):
        if not self.show_messages or not payload:
            return

        ts_str = datetime.now().strftime('%H:%M:%S')

        try:
            if opcode == DIAG_EXT_MSG_F: # 121 / 0x79
                # Structure: cmd(1B), num_args(1B), drop_cnt(1B), version(1B),
                #            subsys_id(2B), subsys_mask(2B), line_no(2B),
                #            timestamp(8B), format_str_and_args...
                if len(payload) < 18:
                    return

                num_args, drop_cnt, version, ssid, mask, line_no = unpack_from('<BBBHHH', payload, 1)
                
                ssid_name = SSID_NAMES.get(ssid, f'SSID_{ssid}')
                sev_name = 'HIGH' if mask & 0x04 else ('ERROR' if mask & 0x08 else ('FATAL' if mask & 0x10 else 'INFO'))

                # Remaining bytes contain null-terminated format string and filename
                str_data = payload[18:]
                null_split = str_data.split(b'\x00')
                fmt_str = null_split[0].decode('latin1', errors='replace') if len(null_split) > 0 else ''
                filename = null_split[1].decode('latin1', errors='replace') if len(null_split) > 1 else 'modem'

                print(f"[{ts_str} | {ssid_name} @ {filename}:{line_no} | {sev_name}] {fmt_str}")

            elif opcode == DIAG_MSG_F: # 31 / 0x1F
                if len(payload) < 6:
                    return
                drop_cnt, line_no = unpack_from('<BH', payload, 1)
                str_data = payload[5:]
                null_split = str_data.split(b'\x00')
                fmt_str = null_split[0].decode('latin1', errors='replace') if len(null_split) > 0 else ''
                filename = null_split[1].decode('latin1', errors='replace') if len(null_split) > 1 else 'modem'

                print(f"[{ts_str} | CORE @ {filename}:{line_no} | MSG] {fmt_str}")

        except Exception:
            pass

    def on_event(self, event_id, payload, timestamp):
        if not self.show_events:
            return

        ts_str = datetime.now().strftime('%H:%M:%S')
        event_name = EVENT_NAMES.get(event_id, f'EVENT_{event_id}')
        
        hex_data = payload.hex() if payload else 'None'
        print(f"[{ts_str} | EVENT #{event_id}: {event_name}] payload={hex_data}")
