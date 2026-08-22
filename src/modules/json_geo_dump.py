#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from ..protocol.gsmtap import build_gsmtap_ip
from ..protocol.log_types import *
from struct import pack, unpack, unpack_from, error as struct_error
from base64 import b64encode
from subprocess import run
from json import dumps
from time import time
import re

from ._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING

"""
    AirTap - Baseband GNSS / A-GPS & Geolocation Correlation Module (JsonGeoDumper)
    Powered by TelcoSec.net (https://telcosec.net)
    
    Generates a structured JSON stream correlating:
    1. Qualcomm Baseband GNSS Position Reports (0x1476, 0x1478, 0x196e).
    2. Baseband NMEA Stream ($GPGGA, $GPRMC, $GNGNS) (0x1477).
    3. Host-level ADB GPS location fallback.
    4. Raw decoded cellular signaling and PHY measurements tagged with GPS coordinates.
"""

DELAY_CHECK_GEOLOCATION = 10  # Check ADB GPS location every 10 seconds

GNSS_LOG_TYPES = [
    LOG_GNSS_POSITION_REPORT_C,
    LOG_GNSS_NMEA_REPORT_C,
    LOG_CG_LCS_POSITION_ESTIMATE_C,
    LOG_GNSS_CLOCK_REPORT_C,
]


class JsonGeoDumper(EnableLogMixin):
    
    def __init__(self, diag_input, json_geo_file):
        self.json_geo_file = json_geo_file
        self.diag_input = diag_input
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING + GNSS_LOG_TYPES
        
        self.last_time_geolocation_was_checked = 0
        self.lat = None
        self.lng = None
        self.alt = None
        self.fix_type = 'No Fix'
        self.sat_count = 0
        self.gnss_source = 'NONE'

    def on_log(self, log_type, log_payload, log_header, timestamp = 0):
        ts = time() if not timestamp else timestamp

        # 1. Process Qualcomm Hardware Baseband GNSS / A-GPS Logs
        if log_type in (LOG_GNSS_POSITION_REPORT_C, LOG_CG_LCS_POSITION_ESTIMATE_C):
            self._parse_gnss_position_report(log_payload, ts)
        elif log_type == LOG_GNSS_NMEA_REPORT_C:
            self._parse_gnss_nmea_report(log_payload, ts)

        # 2. Host ADB GPS Fallback (if no baseband GNSS is received)
        if self.gnss_source != 'BASEBAND_GNSS' and hasattr(self.diag_input, 'get_gps_location'):
            if self.last_time_geolocation_was_checked < time() - DELAY_CHECK_GEOLOCATION:
                lat, lng = self.diag_input.get_gps_location()
                if lat and lng and (lat, lng) != (self.lat, self.lng):
                    self.lat, self.lng = lat, lng
                    self.gnss_source = 'HOST_ADB'
                    self._emit_geo_record(ts)
                self.last_time_geolocation_was_checked = time()

        # 3. Log Raw Cellular Packet tagged with high-precision geolocation
        if log_type in TYPES_FOR_RAW_PACKET_LOGGING:
            record_dict = {
                'log_type': log_type,
                'log_frame': b64encode((log_header or b'') + (log_payload or b'')).decode('ascii'),
                'timestamp': ts
            }
            if self.lat is not None and self.lng is not None:
                record_dict['lat'] = self.lat
                record_dict['lng'] = self.lng
                if self.alt is not None:
                    record_dict['alt_m'] = self.alt
                record_dict['fix_type'] = self.fix_type
                record_dict['sat_count'] = self.sat_count
                record_dict['geo_source'] = self.gnss_source

            json_record = dumps(record_dict, sort_keys = True)
            self.json_geo_file.write(json_record + '\n')
            if hasattr(self.json_geo_file, 'flush'):
                self.json_geo_file.flush()

    def _parse_gnss_position_report(self, log_payload: bytes, timestamp: float):
        if not log_payload or len(log_payload) < 19:
            return

        try:
            # Layout: [version(1B), fix_type(1B), sat_count(1B), lat(8B double LE), lon(8B double LE), alt(4B float LE)]
            version, fix_id, sat_count, lat, lon = unpack_from('<BBBdd', log_payload, 0)
            
            fix_map = {0: 'No Fix', 1: '2D Fix', 2: '3D Fix', 3: 'DGPS / High Accuracy'}
            fix_str = fix_map.get(fix_id, f'Fix #{fix_id}')

            alt_val = None
            if len(log_payload) >= 23:
                alt_val = round(unpack_from('<f', log_payload, 19)[0], 2)

            # Validate coordinate bounds
            if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
                self.lat = round(lat, 6)
                self.lng = round(lon, 6)
                self.alt = alt_val
                self.sat_count = sat_count
                self.fix_type = fix_str
                self.gnss_source = 'BASEBAND_GNSS'
                self._emit_geo_record(timestamp)
        except Exception:
            pass

    def _parse_gnss_nmea_report(self, log_payload: bytes, timestamp: float):
        if not log_payload:
            return

        try:
            nmea_text = log_payload.decode('ascii', errors='ignore')
            # Extract NMEA sentences ($GPGGA, $GPRMC, $GNGNS)
            for line in nmea_text.splitlines():
                line = line.strip()
                if line.startswith('$GPGGA') or line.startswith('$GNGGA'):
                    parts = line.split(',')
                    if len(parts) >= 10 and parts[2] and parts[4]:
                        raw_lat, lat_dir = float(parts[2]), parts[3]
                        raw_lon, lon_dir = float(parts[4]), parts[5]
                        fix_quality = int(parts[6]) if parts[6] else 0
                        sats = int(parts[7]) if parts[7] else 0
                        alt = float(parts[9]) if parts[9] else None

                        lat_deg = int(raw_lat / 100) + (raw_lat % 100) / 60.0
                        if lat_dir == 'S':
                            lat_deg = -lat_deg
                        lon_deg = int(raw_lon / 100) + (raw_lon % 100) / 60.0
                        if lon_dir == 'W':
                            lon_deg = -lon_deg

                        self.lat = round(lat_deg, 6)
                        self.lng = round(lon_deg, 6)
                        self.alt = alt
                        self.sat_count = sats
                        self.fix_type = '3D Fix' if fix_quality > 0 else 'No Fix'
                        self.gnss_source = 'BASEBAND_NMEA'
                        self._emit_geo_record(timestamp)
                        break
        except Exception:
            pass

    def _emit_geo_record(self, timestamp: float):
        record = {
            'geo_source': self.gnss_source,
            'lat': self.lat,
            'lng': self.lng,
            'alt_m': self.alt,
            'fix_type': self.fix_type,
            'sat_count': self.sat_count,
            'timestamp': timestamp,
        }
        json_record = dumps(record, sort_keys = True)
        self.json_geo_file.write(json_record + '\n')
        if hasattr(self.json_geo_file, 'flush'):
            self.json_geo_file.flush()

    def __del__(self):
        try:
            if hasattr(self, 'json_geo_file') and self.json_geo_file:
                self.json_geo_file.close()
        except Exception:
            pass
