#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - MediaTek (Dimensity & Helio) Baseband Diagnostic Input Reader
    Powered by TelcoSec.net (https://telcosec.net)

    Decodes MediaTek baseband diagnostic log streams (Dimensity 700/900/1200/8000/9000/9300
    and Helio platforms via ELT / Catcher trace formats).

    Extracts 3GPP Layer 3 OTA signaling across 5G NR, LTE, UMTS, GSM, IMS SIP, and UICC APDU.
"""

from struct import unpack, unpack_from, pack
import time
import os

from ._base_input import BaseInput
from ..protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_IMS_SIP_MSG_C,
    LOG_SIM_APDU_LOG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
    LOG_LTE_SERVING_CELL_INFO_C,
    LOG_NR_ML1_SERVING_CELL_BEAM_C,
)

# MTK Sync Header Constants
MTK_SYNC_MAGIC_1 = 0x55AA
MTK_SYNC_MAGIC_2 = 0xBB01
MTK_TAG_HEADER   = b'MTK\x00'

# MTK Service Access Point (SAP) Subsystem IDs
MTK_SAP_5G_NR_RRC   = 0x01
MTK_SAP_5G_NR_NAS   = 0x05
MTK_SAP_LTE_RRC     = 0x02
MTK_SAP_LTE_NAS     = 0x04
MTK_SAP_UMTS_RRC    = 0x03
MTK_SAP_GSM_RR      = 0x07
MTK_SAP_IMS_SIP     = 0x06
MTK_SAP_SIM_APDU    = 0x08
MTK_SAP_PHY_MEAS    = 0x0E


class MediaTekReader(BaseInput):
    """
    Reads MediaTek baseband trace streams from file, pipe, or ELT diagnostic interface.
    """

    def __init__(self, mtk_file):
        self.mtk_file = mtk_file
        self.timestamp = 0
        self.packet_count = 0
        super().__init__()

    def read_loop(self):
        """Sequential MTK frame reader loop."""
        buffer = bytearray()

        while True:
            chunk = self.mtk_file.read(4096)
            if not chunk:
                break

            buffer.extend(chunk)

            while len(buffer) >= 8:
                # Seek sync header (0x55AA, 0xBB01, or 'MTK\0')
                if buffer.startswith(MTK_TAG_HEADER):
                    if len(buffer) < 16:
                        break
                    sap_id, msg_len, ts_val = unpack_from('<HHI', buffer, 4)
                    total_len = 12 + msg_len
                    if len(buffer) < total_len:
                        break
                    payload = bytes(buffer[12:total_len])
                    buffer = buffer[total_len:]
                    self._dispatch_mtk_packet(sap_id, payload, ts_val / 1000.0 if ts_val > 1000000 else time.time())
                elif buffer[0] == 0xAA and buffer[1] == 0x55:
                    if len(buffer) < 10:
                        break
                    sap_id, msg_len = unpack_from('<HH', buffer, 2)
                    total_len = 6 + msg_len
                    if len(buffer) < total_len:
                        break
                    payload = bytes(buffer[6:total_len])
                    buffer = buffer[total_len:]
                    self._dispatch_mtk_packet(sap_id, payload, time.time())
                else:
                    # Slide forward looking for sync byte
                    idx = buffer.find(b'\xAA\x55')
                    if idx != -1:
                        buffer = buffer[idx:]
                    else:
                        idx_tag = buffer.find(MTK_TAG_HEADER)
                        if idx_tag != -1:
                            buffer = buffer[idx_tag:]
                        else:
                            buffer = buffer[-4:]
                            break

    def _dispatch_mtk_packet(self, sap_id: int, payload: bytes, ts: float):
        """Translates MTK SAP payload to unified 3GPP OTA log types."""
        self.timestamp = ts
        self.packet_count += 1

        if sap_id == MTK_SAP_5G_NR_RRC:
            log_type = LOG_NR_RRC_OTA_MSG_LOG_C
        elif sap_id == MTK_SAP_5G_NR_NAS:
            log_type = LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C
        elif sap_id == MTK_SAP_LTE_RRC:
            log_type = LOG_LTE_RRC_OTA_MSG_LOG_C
        elif sap_id == MTK_SAP_LTE_NAS:
            log_type = LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C
        elif sap_id == MTK_SAP_UMTS_RRC:
            log_type = WCDMA_SIGNALLING_MESSAGE
        elif sap_id == MTK_SAP_GSM_RR:
            log_type = LOG_GSM_RR_SIGNALING_MESSAGE_C
        elif sap_id == MTK_SAP_IMS_SIP:
            log_type = LOG_IMS_SIP_MSG_C
        elif sap_id == MTK_SAP_SIM_APDU:
            log_type = LOG_SIM_APDU_LOG_C
        elif sap_id == MTK_SAP_PHY_MEAS:
            log_type = LOG_NR_ML1_SERVING_CELL_BEAM_C
        else:
            log_type = LOG_DATA_PROTOCOL_LOGGING_C

        log_header = pack('<HHQ', len(payload) + 12, log_type, int(ts))
        self.dispatch_diag_log(log_type, payload, log_header, ts)
