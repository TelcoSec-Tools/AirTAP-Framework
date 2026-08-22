#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from struct import pack

from src.modules.stats_dump import StatsDumper
from src.protocol.log_types import (
    LOG_LTE_SERVING_CELL_INFO_C,
    LOG_LTE_ML1_SERVING_CELL_MEAS_C,
    LOG_NR_ML1_SERVING_CELL_BEAM_C,
)

class TestRfStats(TestCase):

    def setUp(self):
        self.diag_input = MagicMock()
        self.dumper = StatsDumper(self.diag_input)

    def test_lte_serving_cell_info_parsing(self):
        # Version 0, PCI 123, EARFCN 1650, Band 3
        payload = pack('<BHIH', 0, 123, 1650, 3)
        self.dumper.on_log(LOG_LTE_SERVING_CELL_INFO_C, payload, None)

        self.assertEqual(self.dumper.rf_metrics['rat'], 'LTE (4G)')
        self.assertEqual(self.dumper.rf_metrics['pci'], 123)
        self.assertEqual(self.dumper.rf_metrics['earfcn'], 1650)
        self.assertEqual(self.dumper.rf_metrics['band'], 3)
        self.assertEqual(self.dumper.ca_metrics['pcc']['band'], 3)
        self.assertEqual(self.dumper.ca_metrics['pcc']['earfcn'], 1650)

    def test_lte_carrier_aggregation_parsing(self):
        # Version 0, PCI 123, EARFCN 1650, Band 3 (PCC), bw_enum=5 (20MHz), num_scells=2
        # SCC 1: PCI 124, EARFCN 300, bw_enum=5 (20MHz)
        # SCC 2: PCI 125, EARFCN 2850, bw_enum=3 (10MHz)
        hdr = pack('<BHIHBB', 0, 123, 1650, 3, 5, 2)
        scc1 = pack('<HIB', 124, 300, 5)
        scc2 = pack('<HIB', 125, 2850, 3)
        payload = hdr + scc1 + scc2

        self.dumper.on_log(LOG_LTE_SERVING_CELL_INFO_C, payload, None)

        self.assertEqual(self.dumper.ca_metrics['ca_state'], '3xCA (Active)')
        self.assertEqual(self.dumper.ca_metrics['total_ca_bandwidth_mhz'], 50.0) # 20 + 20 + 10
        self.assertEqual(len(self.dumper.ca_metrics['sccs']), 2)
        self.assertEqual(self.dumper.ca_metrics['sccs'][0]['pci'], 124)
        self.assertEqual(self.dumper.ca_metrics['sccs'][0]['bandwidth_mhz'], 20.0)
        self.assertEqual(self.dumper.ca_metrics['sccs'][1]['pci'], 125)
        self.assertEqual(self.dumper.ca_metrics['sccs'][1]['bandwidth_mhz'], 10.0)

    def test_lte_serving_cell_meas_parsing(self):
        # Version 0, RSRP -1440 (=-90.0 dBm), RSRQ -160 (=-10.0 dB), RSSI -1040 (=-65.0 dBm)
        payload = pack('<B3xhhh', 0, -1440, -160, -1040)
        self.dumper.on_log(LOG_LTE_ML1_SERVING_CELL_MEAS_C, payload, None)

        self.assertEqual(self.dumper.rf_metrics['rsrp'], -90.0)
        self.assertEqual(self.dumper.rf_metrics['rsrq'], -10.0)
        self.assertEqual(self.dumper.rf_metrics['rssi'], -65.0)

    def test_nr_serving_cell_beam_simple_parsing(self):
        # Version 0, PCI 500, ARFCN 632000, RSRP -1280 (=-80.0 dBm)
        payload = pack('<BHIh', 0, 500, 632000, -1280)
        self.dumper.on_log(LOG_NR_ML1_SERVING_CELL_BEAM_C, payload, None)

        self.assertEqual(self.dumper.rf_metrics['rat'], 'NR (5G)')
        self.assertEqual(self.dumper.rf_metrics['pci'], 500)
        self.assertEqual(self.dumper.rf_metrics['earfcn'], 632000)
        self.assertEqual(self.dumper.rf_metrics['rsrp'], -80.0)

    def test_nr_multi_beam_management_parsing(self):
        # Version 0, PCI 500, ARFCN 632000, RSRP -1280 (=-80.0 dBm), num_beams=3
        # Beam 0: ID=1, RSRP -1440 (-90.0), RSRQ -160 (-10.0), SINR 240 (15.0)
        # Beam 1: ID=5, RSRP -1200 (-75.0), RSRQ -140 (-8.75), SINR 320 (20.0)  <- Best
        # Beam 2: ID=7, RSRP -1600 (-100.0), RSRQ -200 (-12.5), SINR 160 (10.0)
        hdr = pack('<BHIhB', 0, 500, 632000, -1280, 3)
        b0 = pack('<Bhhh', 1, -1440, -160, 240)
        b1 = pack('<Bhhh', 5, -1200, -140, 320)
        b2 = pack('<Bhhh', 7, -1600, -200, 160)
        payload = hdr + b0 + b1 + b2

        self.dumper.on_log(LOG_NR_ML1_SERVING_CELL_BEAM_C, payload, None)

        self.assertEqual(self.dumper.nr_beam_metrics['pci'], 500)
        self.assertEqual(self.dumper.nr_beam_metrics['best_beam_id'], 5)
        self.assertEqual(self.dumper.nr_beam_metrics['best_beam_rsrp'], -75.0)
        self.assertEqual(len(self.dumper.nr_beam_metrics['beams']), 3)
        # Beams sorted by highest RSRP
        self.assertEqual(self.dumper.nr_beam_metrics['beams'][0]['beam_id'], 5)
        self.assertEqual(self.dumper.nr_beam_metrics['beams'][1]['beam_id'], 1)
        self.assertEqual(self.dumper.nr_beam_metrics['beams'][2]['beam_id'], 7)

    def test_format_summary_includes_beams_and_ca(self):
        # Setup RF + CA + Beams
        self.dumper.rf_metrics = {
            'rat': 'NR (5G)',
            'pci': 500,
            'band': 78,
            'earfcn': 632000,
            'rsrp': -75.0,
            'rsrq': -8.7,
            'rssi': -55.0,
            'sinr': 20.0,
        }
        self.dumper.nr_beam_metrics = {
            'pci': 500,
            'nr_arfcn': 632000,
            'best_beam_id': 5,
            'best_beam_rsrp': -75.0,
            'beams': [
                {'beam_id': 5, 'rsrp': -75.0, 'rsrq': -8.7, 'sinr': 20.0},
                {'beam_id': 1, 'rsrp': -90.0, 'rsrq': -10.0, 'sinr': 15.0},
            ]
        }
        self.dumper.ca_metrics = {
            'pcc': {'band': 78, 'earfcn': 632000, 'bandwidth_mhz': 100.0, 'mimo_layers': 4},
            'sccs': [{'scc_idx': 1, 'pci': 501, 'earfcn': 640000, 'bandwidth_mhz': 40.0, 'mimo_layers': 4}],
            'total_ca_bandwidth_mhz': 140.0,
            'ca_state': '2xCA (Active)',
        }

        summary = self.dumper.format_summary()
        self.assertIn('5G NR Beam Management', summary)
        self.assertIn('Beam #5', summary)
        self.assertIn('Carrier Aggregation (CA)', summary)
        self.assertIn('140.0 MHz', summary)

if __name__ == '__main__':
    main()
