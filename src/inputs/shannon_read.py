#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Samsung Shannon (Exynos) Baseband Diagnostic Input Reader
    Powered by TelcoSec.net (https://telcosec.net)

    Decodes Samsung Shannon baseband diagnostic frames (Exynos 980, 990, 2100, 2200, 2400,
    and Google Tensor Shannon modems 5123, 5300, 5400).

    Handles HDLC framing (0x7E delimiter, 0x7D escape), channel demultiplexing,
    timestamp normalization, and translation to unified 3GPP OTA signaling streams.
"""

from struct import unpack, unpack_from, pack
from datetime import datetime
import time
import os

from ._base_input import BaseInput
from ..protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
    LOG_IMS_SIP_MSG_C,
    LOG_SIM_APDU_LOG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
    LOG_LTE_SERVING_CELL_INFO_C,
    LOG_NR_ML1_SERVING_CELL_BEAM_C,
)

# Shannon Frame Constants
SHANNON_FRAME_DELIMITER = 0x7E
SHANNON_FRAME_ESCAPE    = 0x7D

# Shannon Channel IDs
SHANNON_CH_GSM_WCDMA    = 0x01
SHANNON_CH_LTE_RRC      = 0x02
SHANNON_CH_LTE_NAS      = 0x04
SHANNON_CH_5G_NR_RRC    = 0x03
SHANNON_CH_5G_NR_NAS    = 0x05
SHANNON_CH_IMS_SIP      = 0x06
SHANNON_CH_SIM_APDU     = 0x08
SHANNON_CH_RF_MEAS      = 0x0B
SHANNON_CH_F3_DEBUG     = 0x0F


class ShannonReader(BaseInput):
    """
    Reads Samsung Shannon diagnostic streams from file, pipe, or serial device.
    """

    def __init__(self, shannon_file):
        self.shannon_file = shannon_file
        self.timestamp = 0
        self.packet_count = 0
        super().__init__()

    @staticmethod
    def unescape_hdlc(data: bytes) -> bytes:
        """Unescapes Shannon HDLC stream (0x7D 0x5E -> 0x7E, 0x7D 0x5D -> 0x7D)."""
        out = bytearray()
        escaped = False
        for b in data:
            if escaped:
                out.append(b ^ 0x20)
                escaped = False
            elif b == SHANNON_FRAME_ESCAPE:
                escaped = True
            else:
                out.append(b)
        return bytes(out)

    def read_loop(self):
        """Sequential HDLC frame reader loop."""
        buffer = bytearray()

        while True:
            chunk = self.shannon_file.read(4096)
            if not chunk:
                break

            buffer.extend(chunk)

            # Extract frames delimited by 0x7E
            while SHANNON_FRAME_DELIMITER in buffer:
                idx = buffer.index(SHANNON_FRAME_DELIMITER)
                raw_frame = buffer[:idx]
                buffer = buffer[idx + 1:]

                if len(raw_frame) > 4:
                    frame = self.unescape_hdlc(raw_frame)
                    self._process_shannon_frame(frame)

    def _process_shannon_frame(self, frame: bytes):
        """Decodes Shannon frame and dispatches to AirTAP modules."""
        if len(frame) < 6:
            return

        channel_id = frame[0]
        sub_id = frame[1]
        msg_len = unpack_from('<H', frame, 2)[0]
        
        # Optional timestamp in header (ms since Unix epoch or modem boot)
        if len(frame) >= 12:
            raw_ts = unpack_from('<Q', frame, 4)[0]
            if raw_ts > 1000000000: # Realistic epoch ms
                ts = raw_ts / 1000.0
            else:
                ts = time.time()
            payload = frame[12:]
        else:
            ts = time.time()
            payload = frame[4:]

        self.timestamp = ts
        self.packet_count += 1

        # Channel mapping to standard 3GPP Diag log types
        if channel_id == SHANNON_CH_5G_NR_RRC:
            log_type = LOG_NR_RRC_OTA_MSG_LOG_C
        elif channel_id == SHANNON_CH_5G_NR_NAS:
            log_type = LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C if sub_id == 0 else LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C
        elif channel_id == SHANNON_CH_LTE_RRC:
            log_type = LOG_LTE_RRC_OTA_MSG_LOG_C
        elif channel_id == SHANNON_CH_LTE_NAS:
            log_type = LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C if sub_id == 0 else LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C
        elif channel_id == SHANNON_CH_GSM_WCDMA:
            log_type = WCDMA_SIGNALLING_MESSAGE if sub_id >= 0x10 else LOG_GSM_RR_SIGNALING_MESSAGE_C
        elif channel_id == SHANNON_CH_IMS_SIP:
            log_type = LOG_IMS_SIP_MSG_C
        elif channel_id == SHANNON_CH_SIM_APDU:
            log_type = LOG_SIM_APDU_LOG_C
        elif channel_id == SHANNON_CH_RF_MEAS:
            log_type = LOG_NR_ML1_SERVING_CELL_BEAM_C if sub_id == 0x50 else LOG_LTE_SERVING_CELL_INFO_C
        else:
            log_type = LOG_DATA_PROTOCOL_LOGGING_C

        log_header = pack('<HHQ', len(payload) + 12, log_type, int(ts))
        self.dispatch_diag_log(log_type, payload, log_header, ts)
