#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
import time
from logging import info
from struct import unpack

from ._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING
from ..protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    LOG_GSM_SACCH_C,
    LOG_GSM_CELL_BROADCAST_C,
    LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,
    LOG_GPRS_RLC_UL_COMMAND_C,
    LOG_GPRS_RLC_DL_COMMAND_C,
    LOG_GPRS_LLC_ME_LOG_PACKET_C,
    LOG_GPRS_SNDCP_PDU_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_UMTS_CELL_BROADCAST_C,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C,
    LOG_LTE_RRC_ETWS_CMAS_LOG_C,
    LOG_LTE_CALEA_TRACE_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
    LOG_LTE_IMS_SIP_MSG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C,
    LOG_NR_RRC_ETWS_CMAS_LOG_C,
    LOG_NR_CALEA_TRACE_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
    LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C,
    LOG_NR_MAC_PDU_LOG_C,
    LOG_NR_MAC_RACH_TRIGGER_LOG_C,
    LOG_NR_SDAP_PDU_LOG_C,
    LOG_NR_IMS_SIP_MSG_C,
    LOG_SIM_APDU_LOG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
)

LOG_CODES_2G = {
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    LOG_GSM_SACCH_C,
    LOG_GSM_CELL_BROADCAST_C,
    LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,
    LOG_GPRS_RLC_UL_COMMAND_C,
    LOG_GPRS_RLC_DL_COMMAND_C,
    LOG_GPRS_LLC_ME_LOG_PACKET_C,
    LOG_GPRS_SNDCP_PDU_C,
    LOG_SIM_APDU_LOG_C,
}
LOG_CODES_3G = {
    WCDMA_SIGNALLING_MESSAGE,
    LOG_UMTS_CELL_BROADCAST_C,
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
}
LOG_CODES_4G = {
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C,
    LOG_LTE_RRC_ETWS_CMAS_LOG_C,
    LOG_LTE_CALEA_TRACE_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
    LOG_LTE_IMS_SIP_MSG_C,
}
LOG_CODES_5G = {
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C,
    LOG_NR_RRC_ETWS_CMAS_LOG_C,
    LOG_NR_CALEA_TRACE_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
    LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
    LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C,
    LOG_NR_MAC_PDU_LOG_C,
    LOG_NR_MAC_RACH_TRIGGER_LOG_C,
    LOG_NR_SDAP_PDU_LOG_C,
    LOG_NR_IMS_SIP_MSG_C,
}

class StatsDumper(EnableLogMixin):
    
    def __init__(self, diag_input):
        self.diag_input = diag_input
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        
        self.rat_stats = {
            '2g': {'packets': 0, 'bytes': 0},
            '3g': {'packets': 0, 'bytes': 0},
            '4g': {'packets': 0, 'bytes': 0},
            '5g': {'packets': 0, 'bytes': 0},
            'ip': {'packets': 0, 'bytes': 0},
            'other': {'packets': 0, 'bytes': 0},
        }
        
        self.log_code_counts = {}

    def classify_log_type(self, log_type):
        if log_type in LOG_CODES_2G:
            return '2g'
        elif log_type in LOG_CODES_3G:
            return '3g'
        elif log_type in LOG_CODES_4G:
            return '4g'
        elif log_type in LOG_CODES_5G:
            return '5g'
        elif log_type == LOG_DATA_PROTOCOL_LOGGING_C:
            return 'ip'
        return 'other'

    def on_log(self, log_type, log_payload, log_header, timestamp=0):
        length = len(log_payload) if log_payload else 0
        self.total_packets += 1
        self.total_bytes += length
        
        rat = self.classify_log_type(log_type)
        self.rat_stats[rat]['packets'] += 1
        self.rat_stats[rat]['bytes'] += length
        
        self.log_code_counts[log_type] = self.log_code_counts.get(log_type, 0) + 1

    def get_summary_dict(self):
        duration = max(time.time() - self.start_time, 0.001)
        pkt_rate = self.total_packets / duration
        byte_rate_kb = (self.total_bytes / 1024.0) / duration
        
        return {
            'duration_sec': round(duration, 2),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_sec': round(pkt_rate, 2),
            'kb_per_sec': round(byte_rate_kb, 2),
            'rat_stats': self.rat_stats,
            'log_code_counts': self.log_code_counts,
        }

    def format_summary(self):
        summary = self.get_summary_dict()
        lines = [
            "==================================================",
            "        AirTap Telemetry & Capture Summary        ",
            "==================================================",
            f" Capture Duration:  {summary['duration_sec']} sec",
            f" Total Packets:     {summary['total_packets']}",
            f" Total Data Size:   {summary['total_bytes']} bytes ({round(summary['total_bytes'] / 1024.0, 2)} KB)",
            f" Average Throughput:{summary['packets_per_sec']} pkt/s | {summary['kb_per_sec']} KB/s",
            "--------------------------------------------------",
            " RAT Distribution:",
        ]
        for rat, stat in summary['rat_stats'].items():
            pkts = stat['packets']
            b = stat['bytes']
            lines.append(f"   - {rat.upper():<5}: {pkts:>6} packets | {b:>8} bytes")
        lines.append("==================================================")
        return "\n".join(lines)

    def on_deinit(self):
        report = self.format_summary()
        info("\n" + report)
        super().on_deinit()
