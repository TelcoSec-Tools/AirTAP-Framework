#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
import urllib.request
import json
import time
import socket

from src.modules.gui_server import GuiServer, WebSocketClient


class MockDiagInput:
    def __init__(self):
        self.modules = []
        self.filter_rat = None
        self.filter_logs = None

    def add_module(self, mod):
        self.modules.append(mod)

    def send_recv(self, opcode, payload):
        return b'\x00' * 16


class TestGuiServer(unittest.TestCase):

    def setUp(self):
        self.diag_input = MockDiagInput()
        # Bind on local test port with auto_open=False
        self.gui_server = GuiServer(diag_input=self.diag_input, host='127.0.0.1', port=15880, auto_open=False)
        time.sleep(0.1)

    def tearDown(self):
        if self.gui_server:
            self.gui_server.on_deinit()

    def test_http_index_served(self):
        url = f"http://127.0.0.1:{self.gui_server.port}/"
        req = urllib.request.urlopen(url, timeout=3)
        self.assertEqual(req.status, 200)
        body = req.read().decode('utf-8')
        self.assertIn('AirTap', body)
        self.assertIn('RF Telemetry', body)

    def test_http_static_assets_served(self):
        css_url = f"http://127.0.0.1:{self.gui_server.port}/assets/app.css"
        req_css = urllib.request.urlopen(css_url, timeout=3)
        self.assertEqual(req_css.status, 200)
        self.assertIn('text/css', req_css.headers.get('Content-Type', ''))

        js_url = f"http://127.0.0.1:{self.gui_server.port}/assets/app.js"
        req_js = urllib.request.urlopen(js_url, timeout=3)
        self.assertEqual(req_js.status, 200)
        self.assertIn('javascript', req_js.headers.get('Content-Type', ''))

    def test_api_status_endpoint(self):
        url = f"http://127.0.0.1:{self.gui_server.port}/api/status"
        req = urllib.request.urlopen(url, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('device', data)
        self.assertIn('stats', data)

    def test_api_efs_ls_endpoint(self):
        url = f"http://127.0.0.1:{self.gui_server.port}/api/efs/ls?path=/"
        req = urllib.request.urlopen(url, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertIsInstance(data.get('files'), list)

    def test_api_nv_read_endpoint(self):
        url = f"http://127.0.0.1:{self.gui_server.port}/api/nv/read?id=1877"
        req = urllib.request.urlopen(url, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('value', data)

    def test_gui_log_and_message_broadcast(self):
        # Trigger on_log and on_message
        self.gui_server.on_log(0xb0c0, b'\x01\x02\x03\x04\x05\x06\x07\x08', None, int(time.time()))
        self.assertEqual(self.gui_server.rf_stats['rat_counts']['4g'], 1)

        self.gui_server.on_message(1, "RRC State Transition: CONNECTED", int(time.time()))

    def test_api_device_info_and_query_endpoints(self):
        # Test /api/device/info
        url_info = f"http://127.0.0.1:{self.gui_server.port}/api/device/info"
        req_info = urllib.request.urlopen(url_info, timeout=3)
        self.assertEqual(req_info.status, 200)
        data_info = json.loads(req_info.read().decode('utf-8'))
        self.assertEqual(data_info.get('status'), 'ok')
        self.assertIn('device', data_info)
        self.assertIn('chipset', data_info['device'])

        # Test /api/device/query
        url_query = f"http://127.0.0.1:{self.gui_server.port}/api/device/query"
        req_query = urllib.request.urlopen(url_query, timeout=3)
        self.assertEqual(req_query.status, 200)
        data_query = json.loads(req_query.read().decode('utf-8'))
        self.assertEqual(data_query.get('status'), 'ok')
        self.assertIn('device', data_query)

    def test_api_threats_export_endpoint(self):
        # Record a test alert and verify /api/threats/export
        self.gui_server.sec_auditor.record_alert(
            severity='CRITICAL',
            category='CIPHERING',
            rat='5G',
            title='5G Null Ciphering Test',
            description='Testing NEA0 threat export',
            rule_id='TELCOSEC-VULN-004'
        )
        url = f"http://127.0.0.1:{self.gui_server.port}/api/threats/export"
        req = urllib.request.urlopen(url, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertGreaterEqual(data.get('count', 0), 1)
        self.assertTrue(any(a['rule_id'] == 'TELCOSEC-VULN-004' for a in data['alerts']))

    def test_multi_rat_log_classification(self):
        # Test 5G NR RRC log classification
        self.gui_server.on_log(0xB821, b'\x00' * 16, None, int(time.time()))
        self.assertEqual(self.gui_server.rf_stats['rat_counts']['5g'], 1)

        # Test 2G GSM RR log classification
        self.gui_server.on_log(0x512F, b'\x00' * 16, None, int(time.time()))
        self.assertEqual(self.gui_server.rf_stats['rat_counts']['2g'], 1)

        # Test SIM APDU log classification
        self.gui_server.on_log(0x1188, b'\x00' * 16, None, int(time.time()))
        self.assertEqual(self.gui_server.rf_stats['rat_counts']['sim'], 1)

    def test_api_replay_endpoints(self):
        # Test GET /api/replay/status
        url_status = f"http://127.0.0.1:{self.gui_server.port}/api/replay/status"
        req = urllib.request.urlopen(url_status, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('replay', data)

        # Test POST /api/replay/control
        url_ctrl = f"http://127.0.0.1:{self.gui_server.port}/api/replay/control"
        post_data = json.dumps({'action': 'speed', 'speed': 2.0}).encode('utf-8')
        req_post = urllib.request.Request(url_ctrl, data=post_data, headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req_post, timeout=3)
        self.assertEqual(resp.status, 200)

    def test_api_geo_endpoints(self):
        # Test GET /api/geo/history
        url_geo = f"http://127.0.0.1:{self.gui_server.port}/api/geo/history"
        req = urllib.request.urlopen(url_geo, timeout=3)
        self.assertEqual(req.status, 200)
        data = json.loads(req.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('current', data)
        self.assertIn('lat', data['current'])

        # Test GET /api/geo/export?format=geojson
        url_export = f"http://127.0.0.1:{self.gui_server.port}/api/geo/export?format=geojson"
        req_exp = urllib.request.urlopen(url_export, timeout=3)
        self.assertEqual(req_exp.status, 200)
        exp_data = json.loads(req_exp.read().decode('utf-8'))
        self.assertEqual(exp_data.get('type'), 'FeatureCollection')

        # Test GET /api/geo/stats
        url_stats = f"http://127.0.0.1:{self.gui_server.port}/api/geo/stats"
        req_stats = urllib.request.urlopen(url_stats, timeout=3)
        self.assertEqual(req_stats.status, 200)
        stats_data = json.loads(req_stats.read().decode('utf-8'))
        self.assertEqual(stats_data.get('status'), 'ok')
        self.assertIn('stats', stats_data)
        self.assertIn('total_distance_km', stats_data['stats'])

        # Test GET /api/geo/export?format=wigle
        url_wigle = f"http://127.0.0.1:{self.gui_server.port}/api/geo/export?format=wigle"
        req_wigle = urllib.request.urlopen(url_wigle, timeout=3)
        self.assertEqual(req_wigle.status, 200)
        csv_text = req_wigle.read().decode('utf-8')
        self.assertTrue(csv_text.startswith('WigleWifi'))

    def test_api_audit_report_endpoints(self):
        # Test HTML report
        url_html = f"http://127.0.0.1:{self.gui_server.port}/api/audit/report?format=html"
        req_html = urllib.request.urlopen(url_html, timeout=3)
        self.assertEqual(req_html.status, 200)
        html_text = req_html.read().decode('utf-8')
        self.assertIn("TELCOSEC", html_text)
        self.assertIn("SECURITY AUDIT REPORT", html_text)

        # Test JSON report
        url_json = f"http://127.0.0.1:{self.gui_server.port}/api/audit/report?format=json"
        req_json = urllib.request.urlopen(url_json, timeout=3)
        self.assertEqual(req_json.status, 200)
        data = json.loads(req_json.read().decode('utf-8'))
        self.assertIn("findings", data)
        self.assertIn("metrics", data)

        # Test Markdown report
        url_md = f"http://127.0.0.1:{self.gui_server.port}/api/audit/report?format=markdown"
        req_md = urllib.request.urlopen(url_md, timeout=3)
        self.assertEqual(req_md.status, 200)
        md_text = req_md.read().decode('utf-8')
        self.assertTrue(md_text.startswith("# TelcoSec"))



    def test_api_efs_full_suite(self):
        # 1. Test /api/efs/ls
        url_ls = f"http://127.0.0.1:{self.gui_server.port}/api/efs/ls?path=/nv/item_files/modem"
        resp_ls = urllib.request.urlopen(url_ls, timeout=3)
        self.assertEqual(resp_ls.status, 200)
        data_ls = json.loads(resp_ls.read().decode('utf-8'))
        self.assertEqual(data_ls.get('status'), 'ok')
        self.assertGreater(len(data_ls.get('files', [])), 0)

        # 2. Test /api/efs/cat
        url_cat = f"http://127.0.0.1:{self.gui_server.port}/api/efs/cat?path=/policyman/carrier_policy.xml"
        resp_cat = urllib.request.urlopen(url_cat, timeout=3)
        self.assertEqual(resp_cat.status, 200)
        data_cat = json.loads(resp_cat.read().decode('utf-8'))
        self.assertEqual(data_cat.get('status'), 'ok')
        self.assertIn('<carrier_policy', data_cat.get('content', ''))

        # 3. Test /api/efs/stat
        url_stat = f"http://127.0.0.1:{self.gui_server.port}/api/efs/stat?path=/carrier_policy.xml"
        resp_stat = urllib.request.urlopen(url_stat, timeout=3)
        self.assertEqual(resp_stat.status, 200)
        data_stat = json.loads(resp_stat.read().decode('utf-8'))
        self.assertEqual(data_stat.get('status'), 'ok')
        self.assertIn('mode', data_stat)
        self.assertIn('md5', data_stat)

        # 4. Test /api/efs/statfs
        url_statfs = f"http://127.0.0.1:{self.gui_server.port}/api/efs/statfs"
        resp_statfs = urllib.request.urlopen(url_statfs, timeout=3)
        self.assertEqual(resp_statfs.status, 200)
        data_statfs = json.loads(resp_statfs.read().decode('utf-8'))
        self.assertEqual(data_statfs.get('status'), 'ok')
        self.assertEqual(data_statfs.get('total_bytes'), 67108864)

        # 5. Test /api/efs/search
        url_search = f"http://127.0.0.1:{self.gui_server.port}/api/efs/search?q=carrier_policy"
        resp_search = urllib.request.urlopen(url_search, timeout=3)
        self.assertEqual(resp_search.status, 200)
        data_search = json.loads(resp_search.read().decode('utf-8'))
        self.assertEqual(data_search.get('status'), 'ok')
        self.assertGreater(data_search.get('count', 0), 0)

        # 6. Test /api/efs/download
        url_dl = f"http://127.0.0.1:{self.gui_server.port}/api/efs/download?path=/build.prop"
        resp_dl = urllib.request.urlopen(url_dl, timeout=3)
        self.assertEqual(resp_dl.status, 200)
        self.assertIn(b'ro.baseband', resp_dl.read())


    def test_api_f3_history_and_export(self):
        # 1. Test /api/f3/history
        url_hist = f"http://127.0.0.1:{self.gui_server.port}/api/f3/history"
        resp_hist = urllib.request.urlopen(url_hist, timeout=3)
        self.assertEqual(resp_hist.status, 200)
        data_hist = json.loads(resp_hist.read().decode('utf-8'))
        self.assertEqual(data_hist.get('status'), 'ok')
        self.assertGreater(len(data_hist.get('logs', [])), 0)

        # 2. Test /api/f3/export
        url_export_log = f"http://127.0.0.1:{self.gui_server.port}/api/f3/export?format=log"
        resp_export_log = urllib.request.urlopen(url_export_log, timeout=3)
        self.assertEqual(resp_export_log.status, 200)
        self.assertIn("Qualcomm QXDM F3", resp_export_log.read().decode('utf-8'))

        url_export_json = f"http://127.0.0.1:{self.gui_server.port}/api/f3/export?format=json"
        resp_export_json = urllib.request.urlopen(url_export_json, timeout=3)
        self.assertEqual(resp_export_json.status, 200)
        data_json = json.loads(resp_export_json.read().decode('utf-8'))
        self.assertIn('traces', data_json)

    def test_api_geo_locate_and_towers(self):
        # Test POST /api/geo/locate with real coordinates
        url_locate = f"http://127.0.0.1:{self.gui_server.port}/api/geo/locate"
        payload = json.dumps({
            'lat': 51.5074,
            'lng': -0.1278,
            'alt': 32.0,
            'speed': 15.5,
            'source': 'DEVICE_GPS',
            'pci': 248,
            'rsrp': -88,
            'band': 'Band n78'
        }).encode('utf-8')
        req = urllib.request.Request(url_locate, data=payload, headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=3)
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode('utf-8'))
        self.assertEqual(data.get('status'), 'ok')
        self.assertEqual(self.gui_server.current_geo['lat'], 51.5074)

        # Test GET /api/geo/towers
        url_towers = f"http://127.0.0.1:{self.gui_server.port}/api/geo/towers"
        resp_towers = urllib.request.urlopen(url_towers, timeout=3)
        self.assertEqual(resp_towers.status, 200)
        data_towers = json.loads(resp_towers.read().decode('utf-8'))
        self.assertEqual(data_towers.get('status'), 'ok')
        self.assertGreater(data_towers.get('total_sites', 0), 0)


    def test_api_nv_full_suite(self):
        # 1. Test /api/nv/read (LTE Bands 6828)
        url_read = f"http://127.0.0.1:{self.gui_server.port}/api/nv/read?id=6828"
        resp_read = urllib.request.urlopen(url_read, timeout=3)
        self.assertEqual(resp_read.status, 200)
        data_read = json.loads(resp_read.read().decode('utf-8'))
        self.assertEqual(data_read.get('status'), 'ok')
        self.assertIn('LTE', data_read.get('name', ''))

        # 2. Test /api/nv/list
        url_list = f"http://127.0.0.1:{self.gui_server.port}/api/nv/list?category=all"
        resp_list = urllib.request.urlopen(url_list, timeout=3)
        self.assertEqual(resp_list.status, 200)
        data_list = json.loads(resp_list.read().decode('utf-8'))
        self.assertEqual(data_list.get('status'), 'ok')
        self.assertGreaterEqual(len(data_list.get('items', [])), 10)

        # 3. Test /api/nv/write (POST)
        url_write = f"http://127.0.0.1:{self.gui_server.port}/api/nv/write"
        payload = json.dumps({'id': 6828, 'hex_data': '0x00080000000800C5'}).encode('utf-8')
        req = urllib.request.Request(url_write, data=payload, headers={'Content-Type': 'application/json'})
        resp_write = urllib.request.urlopen(req, timeout=3)
        self.assertEqual(resp_write.status, 200)
        data_write = json.loads(resp_write.read().decode('utf-8'))
        self.assertEqual(data_write.get('status'), 'ok')

        # 4. Test /api/nv/dump
        url_dump = f"http://127.0.0.1:{self.gui_server.port}/api/nv/dump"
        resp_dump = urllib.request.urlopen(url_dump, timeout=3)
        self.assertEqual(resp_dump.status, 200)
        data_dump = json.loads(resp_dump.read().decode('utf-8'))
        self.assertEqual(data_dump.get('status'), 'ok')
        self.assertIn('dump', data_dump)


if __name__ == '__main__':
    unittest.main()




