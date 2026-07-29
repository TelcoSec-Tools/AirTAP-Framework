#!/usr/bin/python3
import unittest
import io
import json
from base64 import b64encode
from src.modules.json_geo_dump import JsonGeoDumper
from src.inputs.json_geo_read import JsonGeoReader

class MockInput:
    def __init__(self):
        self.lat = 48.8566
        self.lng = 2.3522

    def get_gps_location(self):
        return self.lat, self.lng

class TestJsonGeo(unittest.TestCase):

    def test_json_geo_dumper_and_reader(self):
        buf = io.StringIO()
        mock_input = MockInput()
        dumper = JsonGeoDumper(diag_input=mock_input, json_geo_file=buf)
        dumper.lat, dumper.lng = 48.8566, 2.3522

        # Create dummy log frame: 12B header + payload
        dummy_header = b'\x00' * 12
        dummy_payload = b'\x01\x02\x03\x04'
        log_code = 0xb0c0 # LOG_LTE_RRC_OTA_MSG_LOG_C

        dumper.on_log(log_code, dummy_payload, dummy_header, timestamp=1600000000)

        json_output = buf.getvalue()
        self.assertTrue(len(json_output) > 0)
        lines = json_output.strip().split('\n')
        self.assertEqual(len(lines), 1)

        record = json.loads(lines[0])
        self.assertEqual(record['log_type'], log_code)
        self.assertEqual(record['lat'], 48.8566)
        self.assertEqual(record['lng'], 2.3522)

        # Test reading back with JsonGeoReader
        buf_read = io.StringIO(json_output)
        reader = JsonGeoReader(buf_read)

        dispatched_logs = []
        def mock_dispatch(log_type, payload, header, timestamp):
            dispatched_logs.append((log_type, payload, header, timestamp))

        reader.dispatch_diag_log = mock_dispatch
        reader.read_loop()

        self.assertEqual(len(dispatched_logs), 1)
        self.assertEqual(dispatched_logs[0][0], log_code)
        self.assertEqual(dispatched_logs[0][1], dummy_payload)
        self.assertEqual(dispatched_logs[0][2], dummy_header)
        self.assertEqual(reader.latitude, 48.8566)
        self.assertEqual(reader.longitude, 2.3522)

if __name__ == '__main__':
    unittest.main()
