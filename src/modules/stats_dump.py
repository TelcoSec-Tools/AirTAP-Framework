#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
import time
from logging import info
from struct import unpack, unpack_from

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
    LOG_LTE_SERVING_CELL_INFO_C,
    LOG_LTE_ML1_SERVING_CELL_MEAS_C,
    LOG_NR_ML1_SERVING_CELL_BEAM_C,
    LOG_WCDMA_CELL_ID_C,
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
    LOG_WCDMA_CELL_ID_C,
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
    LOG_LTE_SERVING_CELL_INFO_C,
    LOG_LTE_ML1_SERVING_CELL_MEAS_C,
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
    LOG_NR_ML1_SERVING_CELL_BEAM_C,
}

# Standard 3GPP Bandwidth Mapping (in MHz)
BW_ENUM_TO_MHZ = {
    0: 1.4,
    1: 3.0,
    2: 5.0,
    3: 10.0,
    4: 15.0,
    5: 20.0,
    6: 40.0,
    7: 50.0,
    8: 100.0,
}


class StatsDumper(EnableLogMixin):
    
    def __init__(self, diag_input):
        self.diag_input = diag_input
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING + [
            LOG_LTE_SERVING_CELL_INFO_C,
            LOG_LTE_ML1_SERVING_CELL_MEAS_C,
            LOG_NR_ML1_SERVING_CELL_BEAM_C,
            LOG_WCDMA_CELL_ID_C,
        ]
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
        self.rf_metrics = {
            'rat': 'Unknown',
            'pci': None,
            'band': None,
            'earfcn': None,
            'rsrp': None,
            'rsrq': None,
            'rssi': None,
            'sinr': None,
        }

        # 5G NR Multi-Beam Management Metrics
        self.nr_beam_metrics = {
            'pci': None,
            'nr_arfcn': None,
            'best_beam_id': None,
            'best_beam_rsrp': None,
            'beams': [],  # list of {'beam_id': int, 'rsrp': float, 'rsrq': float, 'sinr': float}
        }

        # Carrier Aggregation (CA) Metrics
        self.ca_metrics = {
            'pcc': {
                'band': None,
                'earfcn': None,
                'bandwidth_mhz': 20.0,
                'mimo_layers': 4,
            },
            'sccs': [],  # list of {'scc_idx': int, 'band': int, 'earfcn': int, 'bandwidth_mhz': float, 'mimo_layers': int}
            'total_ca_bandwidth_mhz': 20.0,
            'ca_state': 'SINGLE_CARRIER',
        }

        self.security_events = []

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

        # Real-time cellular security analysis
        if log_type in (LOG_LTE_RRC_ETWS_CMAS_LOG_C, LOG_NR_RRC_ETWS_CMAS_LOG_C):
            self.security_events.append({
                'type': 'SOS_EMERGENCY_ALERT',
                'severity': 'HIGH',
                'desc': 'Cellular Emergency Broadcast (ETWS/CMAS) received',
                'rat': '5G' if log_type == LOG_NR_RRC_ETWS_CMAS_LOG_C else '4G'
            })
        elif log_type in (LOG_LTE_CALEA_TRACE_LOG_C, LOG_NR_CALEA_TRACE_LOG_C):
            self.security_events.append({
                'type': 'CALEA_INTERCEPT_TRACE',
                'severity': 'CRITICAL',
                'desc': 'Baseband CALEA / Lawful Interception Trace Event active',
                'rat': '5G' if log_type == LOG_NR_CALEA_TRACE_LOG_C else '4G'
            })

        # Process physical layer RF measurements, Carrier Aggregation & 5G Beams
        if log_payload and len(log_payload) >= 7:
            try:
                if log_type == LOG_LTE_SERVING_CELL_INFO_C:
                    self._parse_lte_serving_cell_info(log_payload)
                elif log_type == LOG_LTE_ML1_SERVING_CELL_MEAS_C:
                    self._parse_lte_ml1_meas(log_payload)
                elif log_type == LOG_NR_ML1_SERVING_CELL_BEAM_C:
                    self._parse_nr_ml1_beam(log_payload)
            except Exception:
                pass

    def _parse_lte_serving_cell_info(self, log_payload: bytes):
        if len(log_payload) >= 9:
            pci, earfcn, band = unpack_from('<HIH', log_payload, 1)
            self.rf_metrics['rat'] = 'LTE (4G)'
            self.rf_metrics['pci'] = pci
            self.rf_metrics['earfcn'] = earfcn
            self.rf_metrics['band'] = band

            # Update PCC in Carrier Aggregation
            self.ca_metrics['pcc']['band'] = band
            self.ca_metrics['pcc']['earfcn'] = earfcn
            
            # Check for Carrier Aggregation Secondary Cells (SCells) in extended payload
            if len(log_payload) >= 15:
                bw_enum = log_payload[9] if len(log_payload) > 9 else 5
                pcc_bw = BW_ENUM_TO_MHZ.get(bw_enum, 20.0)
                self.ca_metrics['pcc']['bandwidth_mhz'] = pcc_bw

                num_scells = log_payload[10] if len(log_payload) > 10 else 0
                sccs = []
                offset = 11
                for scell_idx in range(min(num_scells, 4)):
                    if len(log_payload) >= offset + 7:
                        scc_pci, scc_earfcn, scc_bw_enum = unpack_from('<HIB', log_payload, offset)
                        scc_bw = BW_ENUM_TO_MHZ.get(scc_bw_enum, 20.0)
                        sccs.append({
                            'scc_idx': scell_idx + 1,
                            'pci': scc_pci,
                            'earfcn': scc_earfcn,
                            'bandwidth_mhz': scc_bw,
                            'mimo_layers': 4,
                        })
                        offset += 7

                self.ca_metrics['sccs'] = sccs
                total_bw = pcc_bw + sum(s['bandwidth_mhz'] for s in sccs)
                self.ca_metrics['total_ca_bandwidth_mhz'] = round(total_bw, 1)
                
                num_carriers = 1 + len(sccs)
                if num_carriers == 1:
                    self.ca_metrics['ca_state'] = 'SINGLE_CARRIER'
                else:
                    self.ca_metrics['ca_state'] = f'{num_carriers}xCA (Active)'

    def _parse_lte_ml1_meas(self, log_payload: bytes):
        offset = 4 if len(log_payload) >= 10 else 1
        if len(log_payload) >= offset + 6:
            rsrp_raw, rsrq_raw, rssi_raw = unpack_from('<hhh', log_payload, offset)
            self.rf_metrics['rat'] = 'LTE (4G)'
            self.rf_metrics['rsrp'] = round(rsrp_raw * 0.0625, 1) if abs(rsrp_raw) < 3000 else rsrp_raw
            self.rf_metrics['rsrq'] = round(rsrq_raw * 0.0625, 1) if abs(rsrq_raw) < 1000 else rsrq_raw
            self.rf_metrics['rssi'] = round(rssi_raw * 0.0625, 1) if abs(rssi_raw) < 3000 else rssi_raw

    def _parse_nr_ml1_beam(self, log_payload: bytes):
        if len(log_payload) >= 9:
            pci, arfcn, rsrp_raw = unpack_from('<HIh', log_payload, 1)
            self.rf_metrics['rat'] = 'NR (5G)'
            self.rf_metrics['pci'] = pci
            self.rf_metrics['earfcn'] = arfcn
            rsrp_val = round(rsrp_raw * 0.0625, 1) if abs(rsrp_raw) < 3000 else rsrp_raw
            self.rf_metrics['rsrp'] = rsrp_val

            self.nr_beam_metrics['pci'] = pci
            self.nr_beam_metrics['nr_arfcn'] = arfcn

            # Extended 5G Multi-Beam Management parsing
            # Format with num_beams: [ver(1B), pci(2B), arfcn(4B), num_beams(1B), beams...]
            if len(log_payload) >= 10:
                num_beams = log_payload[9]
                beams = []
                offset = 10
                for _ in range(min(num_beams, 8)):
                    if len(log_payload) >= offset + 7:
                        beam_id, b_rsrp_raw, b_rsrq_raw, b_sinr_raw = unpack_from('<Bhhh', log_payload, offset)
                        b_rsrp = round(b_rsrp_raw * 0.0625, 1) if abs(b_rsrp_raw) < 3000 else b_rsrp_raw
                        b_rsrq = round(b_rsrq_raw * 0.0625, 1) if abs(b_rsrq_raw) < 1000 else b_rsrq_raw
                        b_sinr = round(b_sinr_raw * 0.0625, 1) if abs(b_sinr_raw) < 1000 else b_sinr_raw
                        beams.append({
                            'beam_id': beam_id,
                            'rsrp': b_rsrp,
                            'rsrq': b_rsrq,
                            'sinr': b_sinr,
                        })
                        offset += 7

                if beams:
                    # Sort beams by highest RSRP
                    beams.sort(key=lambda b: b['rsrp'], reverse=True)
                    self.nr_beam_metrics['beams'] = beams
                    self.nr_beam_metrics['best_beam_id'] = beams[0]['beam_id']
                    self.nr_beam_metrics['best_beam_rsrp'] = beams[0]['rsrp']
                else:
                    self.nr_beam_metrics['best_beam_rsrp'] = rsrp_val

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
            'rf_metrics': self.rf_metrics,
            'nr_beam_metrics': self.nr_beam_metrics,
            'ca_metrics': self.ca_metrics,
            'security_events': self.security_events,
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
        
        rf = summary.get('rf_metrics', {})
        if rf.get('pci') is not None or rf.get('rsrp') is not None:
            lines.append("--------------------------------------------------")
            lines.append(" RF Serving Cell & Signal Quality:")
            lines.append(f"   - RAT:           {rf.get('rat', 'Unknown')}")
            if rf.get('pci') is not None:
                lines.append(f"   - Physical Cell ID (PCI): {rf.get('pci')}")
            if rf.get('band') is not None:
                lines.append(f"   - Operating Band:         {rf.get('band')}")
            if rf.get('earfcn') is not None:
                lines.append(f"   - ARFCN / Channel:        {rf.get('earfcn')}")
            if rf.get('rsrp') is not None:
                lines.append(f"   - RSRP:                   {rf.get('rsrp')} dBm")
            if rf.get('rsrq') is not None:
                lines.append(f"   - RSRQ:                   {rf.get('rsrq')} dB")
            if rf.get('rssi') is not None:
                lines.append(f"   - RSSI:                   {rf.get('rssi')} dBm")

        # 5G NR Beamforming Telemetry Display
        nr_beams = summary.get('nr_beam_metrics', {})
        if nr_beams.get('beams'):
            lines.append("--------------------------------------------------")
            lines.append(" 5G NR Beam Management (SSB / CSI-RS Beams):")
            lines.append(f"   - Best Serving Beam:      Beam #{nr_beams.get('best_beam_id')} ({nr_beams.get('best_beam_rsrp')} dBm)")
            lines.append("   - Active Beamforming Matrix:")
            for b in nr_beams['beams']:
                lines.append(f"     * Beam #{b['beam_id']:<2}: RSRP {b['rsrp']:>6.1f} dBm | RSRQ {b['rsrq']:>5.1f} dB | SINR {b['sinr']:>5.1f} dB")

        # Carrier Aggregation (CA) Display
        ca = summary.get('ca_metrics', {})
        if ca.get('sccs'):
            lines.append("--------------------------------------------------")
            lines.append(f" Carrier Aggregation (CA):  {ca.get('ca_state', 'Active')}")
            lines.append(f"   - Total CA Bandwidth:     {ca.get('total_ca_bandwidth_mhz')} MHz")
            pcc = ca.get('pcc', {})
            lines.append(f"   - Primary Carrier (PCC):  Band {pcc.get('band')} | EARFCN {pcc.get('earfcn')} ({pcc.get('bandwidth_mhz')} MHz)")
            for scc in ca['sccs']:
                lines.append(f"   - Secondary SCell #{scc['scc_idx']}:  PCI {scc.get('pci')} | EARFCN {scc.get('earfcn')} ({scc.get('bandwidth_mhz')} MHz)")

        sec = summary.get('security_events', [])
        lines.append("--------------------------------------------------")
        lines.append(" Cellular Security & Threat Analysis:")
        if not sec:
            # This module only watches for ETWS/CMAS emergency broadcasts and
            # CALEA trace events (see on_log() above) - it never checks
            # ciphering/integrity algorithms or runs spoofing heuristics
            # (that's sec_audit.py's job), so don't claim it did.
            lines.append("   - Status:         [OK] No emergency broadcast or CALEA trace events detected")
        else:
            lines.append(f"   - Status:         [ALERT] {len(sec)} security event(s) detected!")
            for ev in sec[:5]:
                lines.append(f"     * [{ev['severity']}] {ev['rat']} - {ev['desc']}")

        lines.append("==================================================")
        return "\n".join(lines)

    def on_deinit(self):
        report = self.format_summary()
        info("\n" + report)
        super().on_deinit()
