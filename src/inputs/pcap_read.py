#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from struct import unpack, pack, calcsize, unpack_from
from datetime import datetime
import os

from ._base_input import BaseInput
from ..protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_IMS_SIP_MSG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
)
from ..protocol.gsmtap import (
    GSMTAP_TYPE_UM,
    GSMTAP_TYPE_UMTS_RRC,
    GSMTAP_TYPE_LTE_RRC,
    GSMTAP_TYPE_LTE_NAS,
    GSMTAP_TYPE_NR_RRC,
    GSMTAP_TYPE_NR_NAS,
    GSMTAP_PORT,
    NR_RRC_UDP_PORT,
)

class PcapReader(BaseInput):

    """
        This input reads an existing GSMTAP PCAP file and dispatches packets
        to active AirTap modules (such as --stats or --decoded-sibs-dump).
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.timestamp = 0
        super().__init__()

    def read_loop(self):
        header = self.pcap_file.read(24)
        if len(header) < 24:
            return

        magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, linktype = unpack('<IHHiIII', header)

        is_be = False
        is_nano = False

        if magic == 0xa1b2c3d4:
            is_be = False
        elif magic == 0xd4c3b2a1:
            is_be = True
        elif magic == 0xa1b23c4d:
            is_be = False
            is_nano = True
        elif magic == 0x4d3cb2a1:
            is_be = True
            is_nano = True
        else:
            return

        pkt_header_fmt = '>IIII' if is_be else '<IIII'

        while True:
            pkt_hdr_data = self.pcap_file.read(16)
            if len(pkt_hdr_data) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = unpack(pkt_header_fmt, pkt_hdr_data)
            pkt_data = self.pcap_file.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            timestamp = ts_sec + (ts_usec / 1e9 if is_nano else ts_usec / 1e6)
            self.timestamp = timestamp

            # Parse LinkType: 228 (IPv4), 1 (Ethernet), 101 (Raw IP), or raw GSMTAP
            payload = pkt_data
            if linktype == 1: # Ethernet
                payload = payload[14:]

            if len(payload) >= 20 and (payload[0] >> 4) == 4: # IPv4
                ihl = (payload[0] & 0x0f) * 4
                protocol = payload[9]
                if protocol == 17 and len(payload) >= ihl + 8: # UDP
                    src_port, dst_port, udp_len = unpack('>HHH', payload[ihl:ihl + 6])
                    udp_data = payload[ihl + 8:ihl + udp_len]

                    if src_port == GSMTAP_PORT or dst_port == GSMTAP_PORT:
                        self._process_gsmtap(udp_data, timestamp)
                    elif src_port == NR_RRC_UDP_PORT or dst_port == NR_RRC_UDP_PORT:
                        self.dispatch_diag_log(LOG_NR_RRC_OTA_MSG_LOG_C, udp_data, b'\x00' * 12, timestamp)
                    elif src_port == 5060 or dst_port == 5060:
                        self.dispatch_diag_log(LOG_IMS_SIP_MSG_C, udp_data, b'\x00' * 12, timestamp)
                    else:
                        self.dispatch_diag_log(LOG_DATA_PROTOCOL_LOGGING_C, payload, b'\x00' * 12, timestamp)
                else:
                    self.dispatch_diag_log(LOG_DATA_PROTOCOL_LOGGING_C, payload, b'\x00' * 12, timestamp)
            elif len(payload) >= 16 and payload[0] == 2: # Raw GSMTAP header
                self._process_gsmtap(payload, timestamp)

    def _process_gsmtap(self, gsmtap_data: bytes, timestamp: float):
        if len(gsmtap_data) < 16:
            return

        version, hdr_len, gsmtap_type, sub_type = unpack_from('>BBBH', gsmtap_data, 0)[:4]
        raw_payload = gsmtap_data[hdr_len * 4:]

        type_map = {
            GSMTAP_TYPE_UM: LOG_GSM_RR_SIGNALING_MESSAGE_C,
            GSMTAP_TYPE_UMTS_RRC: WCDMA_SIGNALLING_MESSAGE,
            GSMTAP_TYPE_LTE_RRC: LOG_LTE_RRC_OTA_MSG_LOG_C,
            GSMTAP_TYPE_LTE_NAS: LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
            GSMTAP_TYPE_NR_RRC: LOG_NR_RRC_OTA_MSG_LOG_C,
            GSMTAP_TYPE_NR_NAS: LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
        }

        log_type = type_map.get(gsmtap_type, LOG_DATA_PROTOCOL_LOGGING_C)
        log_header = pack('<HHQ', len(raw_payload) + 12, log_type, int(timestamp))
        self.dispatch_diag_log(log_type, raw_payload, log_header, timestamp)
