#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from struct import pack
from time import time
import os

from ._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING
from ..protocol.messages import DIAG_LOG_F

class QmdlDumper(EnableLogMixin):

    """
        This module dumps Qualcomm DIAG frames into a QMDL/QMDL2 container
        compatible with modern QXDM Professional and Qualcomm analysis tools.
    """

    QMDL_MAGIC = b'QMDL\x02\x00\x00\x00'
    REC_TYPE_DIAG_LOG = 0x00000001

    def __init__(self, diag_input, qmdl_file):
        self.diag_input = diag_input
        self.qmdl_file = qmdl_file
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING

        # Write QMDL v2 container header
        if not getattr(self.qmdl_file, 'appending_to_file', False):
            self.qmdl_file.write(self.QMDL_MAGIC)
            self.qmdl_file.flush()

    def on_log(self, log_type, log_payload, log_header, timestamp=0):
        if not log_payload:
            return

        ts = timestamp if timestamp else time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)

        # Reconstruct DIAG_LOG_F frame payload
        frame_payload = bytes([DIAG_LOG_F]) + log_header + log_payload
        record_len = len(frame_payload)

        # Write QMDL record: record_type (uint32), length (uint32), ts_sec (uint32), ts_usec (uint32)
        try:
            self.qmdl_file.write(pack('<IIII', self.REC_TYPE_DIAG_LOG, record_len, ts_sec, ts_usec) + frame_payload)
            self.qmdl_file.flush()
        except Exception:
            pass

    def on_deinit(self):
        if self.qmdl_file:
            try:
                self.qmdl_file.flush()
                self.qmdl_file.close()
            except Exception:
                pass
        super().on_deinit()
