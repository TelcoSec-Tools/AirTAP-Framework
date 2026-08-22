#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
from struct import pack
import io
import json

from src.protocol.log_types import (
    LOG_GNSS_POSITION_REPORT_C,
    LOG_GNSS_NMEA_REPORT_C,
    LOG_CG_LCS_POSITION_ESTIMATE_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
)
from src.modules.json_geo_dump import JsonGeoDumper


class TestJsonGeoDumper(unittest.TestCase):

    def setUp(self):
        self.output = io.StringIO()
        self.dumper = JsonGeoDumper(diag_input=None, json_geo_file=self.output)

    def test_gnss_binary_position_report_parsing(self):
        # Layout: version=1 (1B), fix_type=2 (3D Fix, 1B), sat_count=9 (1B), lat=48.858844 (8B double), lon=2.294351 (8B double), alt=35.5 (4B float)
        payload = pack('<BBBddf', 1, 2, 9, 48.858844, 2.294351, 35.5)
        self.dumper.on_log(LOG_GNSS_POSITION_REPORT_C, payload, None, timestamp=1600000000.0)

        self.assertEqual(self.dumper.lat, 48.858844)
        self.assertEqual(self.dumper.lng, 2.294351)
        self.assertEqual(self.dumper.alt, 35.5)
        self.assertEqual(self.dumper.fix_type, '3D Fix')
        self.assertEqual(self.dumper.sat_count, 9)
        self.assertEqual(self.dumper.gnss_source, 'BASEBAND_GNSS')

        lines = self.output.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record['geo_source'], 'BASEBAND_GNSS')
        self.assertEqual(record['lat'], 48.858844)
        self.assertEqual(record['lng'], 2.294351)
        self.assertEqual(record['alt_m'], 35.5)

    def test_gnss_nmea_stream_parsing(self):
        # NMEA $GPGGA Sentence: 48 deg 51.53064 min N, 2 deg 17.66106 min E, Fix=1, Sats=8, Alt=42.0m
        nmea_payload = b"$GPGGA,123519,4851.53064,N,00217.66106,E,1,08,0.9,42.0,M,46.9,M,,*47\r\n"
        self.dumper.on_log(LOG_GNSS_NMEA_REPORT_C, nmea_payload, None, timestamp=1600000000.0)

        self.assertAlmostEqual(self.dumper.lat, 48.858844, places=4)
        self.assertAlmostEqual(self.dumper.lng, 2.294351, places=4)
        self.assertEqual(self.dumper.sat_count, 8)
        self.assertEqual(self.dumper.fix_type, '3D Fix')
        self.assertEqual(self.dumper.gnss_source, 'BASEBAND_NMEA')

    def test_cellular_packet_tagged_with_gnss_coordinates(self):
        # Set baseband position
        payload = pack('<BBBddf', 1, 2, 7, 51.5074, -0.1278, 15.0)
        self.dumper.on_log(LOG_GNSS_POSITION_REPORT_C, payload, None, timestamp=1600000000.0)

        # Log a cellular signaling frame
        cell_payload = b"\x01\x02\x03\x04"
        self.dumper.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, cell_payload, b"\x00\x00", timestamp=1600000001.0)

        lines = self.output.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 2)
        cell_record = json.loads(lines[1])
        self.assertEqual(cell_record['log_type'], LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C)
        self.assertEqual(cell_record['lat'], 51.5074)
        self.assertEqual(cell_record['lng'], -0.1278)
        self.assertEqual(cell_record['geo_source'], 'BASEBAND_GNSS')


if __name__ == '__main__':
    unittest.main()
