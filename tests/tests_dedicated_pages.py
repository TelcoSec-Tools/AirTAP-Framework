import unittest
import json
import urllib.request
import urllib.parse
from os.path import join, dirname, exists
import time

from src.modules.gui_server import GuiServer
from src.modules.sec_audit import SecurityAlert
from tests_gui import MockDiagInput as BaseMockDiagInput


class MockDiagInput(BaseMockDiagInput):
    """
    Extends the protocol-correct EFS2 mock from tests_gui.py (real
    OPENDIR/READDIR/STAT/OPEN/READ/STATFS decode paths) with the AT-command
    and raw-PDU stubs this test file's other endpoints rely on.
    """

    def __init__(self):
        super().__init__()
        self.filter_type = None

    def register_module(self, module):
        self.modules.append(module)

    def send_diag_cmd(self, cmd_bytes):
        return b'\x00' * 16

    def execute_at_command(self, cmd):
        if 'CSQ' in cmd:
            return '+CSQ: 24,99\r\n\r\nOK'
        return 'OK\r\n'

    def send_raw_pdu(self, raw_payload):
        return b'\x00' * 16


class TestDedicatedPagesAndCalea(unittest.TestCase):
    _port_counter = 16100

    def setUp(self):
        self.diag_input = MockDiagInput()
        TestDedicatedPagesAndCalea._port_counter += 2
        initial_port = TestDedicatedPagesAndCalea._port_counter
        self.server = GuiServer(diag_input=self.diag_input, host='127.0.0.1', port=initial_port, auto_open=False)
        self.port = self.server.port
        self.base_url = f'http://127.0.0.1:{self.port}'
        time.sleep(0.05)

    def tearDown(self):
        if self.server:
            self.server.on_deinit()
            time.sleep(0.05)

    def test_dedicated_page_routes_serve_html(self):
        routes = ['/live', '/security', '/threats', '/device', '/dossier', '/map', '/wardrive', '/efs', '/nv', '/bands', '/f3', '/qxdm', '/terminal', '/fuzzer', '/calea', '/li']
        for r in routes:
            req = urllib.request.Request(f"{self.base_url}{r}")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read().decode('utf-8')
                self.assertIn('AirTap', body, f"Route {r} failed to serve index.html")
                self.assertIn('TELCOSEC', body, f"Route {r} missing brand")
                self.assertIn('tab-calea', body, f"Route {r} missing tab-calea")
                self.assertIn('tab-device', body, f"Route {r} missing tab-device")
                self.assertIn('tab-efs', body, f"Route {r} missing tab-efs")
                self.assertIn('tab-nv', body, f"Route {r} missing tab-nv")

    def test_calea_api_list_and_stats(self):
        # 1. Initial GET when no real alerts captured yet
        req = urllib.request.Request(f"{self.base_url}/api/calea/list")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['count'], 0)
            self.assertEqual(data['sessions'], [])

        # 2. Inject real captured CALEA alert into security auditor
        alert = SecurityAlert(
            severity='CRITICAL',
            category='CALEA',
            rat='5G',
            title='ETSI TS 102 232 PS-PDU Lawful Interception Header Active',
            description='Captured live PS-PDU with CIN: 0x58A3B291 targeting UE on UPF-CORE-GW-01',
            rule_id='TELCOSEC-VULN-076',
            timestamp=1755302400.0
        )
        self.server.sec_auditor.alerts.append(alert)

        # 3. GET /api/calea/list returns real captured session
        req = urllib.request.Request(f"{self.base_url}/api/calea/list")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['count'], 1)
            self.assertEqual(data['sessions'][0]['cin'], '0x58A3B291')
            self.assertEqual(data['sessions'][0]['vulnerability_rule'], 'TELCOSEC-VULN-076')

        # 4. GET /api/calea/stats returns real stats
        req = urllib.request.Request(f"{self.base_url}/api/calea/stats")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['total_intercepts'], 1)
            self.assertEqual(data['active_cin_sessions'], 1)
            self.assertIn('TELCOSEC-VULN-076', data['telcosec_li_rules'])

    def test_calea_x1_send_endpoint(self):
        # AirTap has no outbound ADMF/X1 transport, so this endpoint only
        # builds and schema-validates a TS 33.128 X1 request locally - it
        # must report 'preview_only', never claim a network element was
        # actually provisioned.
        req_data = json.dumps({
            'task_type': 'ACTIVATE_TASK',
            'target_id': '310410123456789',
            'ne_id': 'AMF-SIG-01',
            'hi_type': 'HI2_IRI'
        }).encode('utf-8')

        req = urllib.request.Request(
            f"{self.base_url}/api/calea/x1/send",
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'preview_only')
            self.assertEqual(data['task_type'], 'ACTIVATE_TASK')
            self.assertEqual(data['target_id'], '310410123456789')
            self.assertIn('request_schema', data)
            self.assertEqual(data['request_schema']['status'], 'ok')
            self.assertNotIn('response_code', data)

        # Missing target_id/ne_id must be rejected, not silently defaulted
        req_missing = json.dumps({'task_type': 'ACTIVATE_TASK'}).encode('utf-8')
        req2 = urllib.request.Request(
            f"{self.base_url}/api/calea/x1/send",
            data=req_missing,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req2, timeout=3.0) as resp2:
            data2 = json.loads(resp2.read().decode('utf-8'))
            self.assertEqual(data2['status'], 'error')

    def test_device_bands_endpoint(self):
        req = urllib.request.Request(f"{self.base_url}/api/device/bands")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreater(data['count'], 20)
            self.assertIn('bands', data)
            band_ids = [b['id'] for b in data['bands']]
            self.assertIn('n78', band_ids)
            self.assertIn('B3', band_ids)

    def test_device_selftest_endpoint(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/device/selftest",
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['total_count'], 5)
            self.assertIn('tests', data)

            # Secure-boot/QFPROM state is never actually queried over DIAG
            # anywhere in AirTap, so that test must honestly report SKIP
            # rather than a fabricated PASS - verify it still does.
            sec_test = next(t for t in data['tests'] if 'QFPROM' in t['name'])
            self.assertEqual(sec_test['status'], 'SKIP')
            # The other 4 real checks (DIAG bus, AT ping, SIM identity,
            # NVRAM STATFS) should all genuinely pass against the mock.
            self.assertEqual(data['passed_count'], 4)

    def test_device_at_probe_endpoint(self):
        req_data = json.dumps({'cmd': 'AT+CGMI'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/device/at_probe",
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('latency_ms', data)

    def test_efs_endpoints(self):
        # 1. EFS LS
        req = urllib.request.Request(f"{self.base_url}/api/efs/ls?path=/")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('files', data)
            self.assertGreater(len(data['files']), 0)

        # 2. EFS StatFS
        req = urllib.request.Request(f"{self.base_url}/api/efs/statfs")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('total_bytes', data)
            self.assertIn('free_bytes', data)

        # 3. EFS Cat
        req = urllib.request.Request(f"{self.base_url}/api/efs/cat?path=/carrier_policy.xml")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('content', data)

        # 4. EFS Search
        req = urllib.request.Request(f"{self.base_url}/api/efs/search?q=policy&path=/")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('results', data)

    def test_nv_endpoints(self):
        # 1. NV List
        req = urllib.request.Request(f"{self.base_url}/api/nv/list?category=all")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreater(data['total'], 15)

        # 2. NV Read (LTE BC Config 6828)
        req = urllib.request.Request(f"{self.base_url}/api/nv/read?id=6828")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['name'], 'NV_LTE_BC_CONFIG_I')
            self.assertIn('raw_hex', data)

        # 3. NV Write
        write_data = json.dumps({'id': 6828, 'hex_data': 'C5 00 08 00 00 00 08 00'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/nv/write",
            data=write_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

        # 4. NV Dump
        req = urllib.request.Request(f"{self.base_url}/api/nv/dump")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('dump', data)

    def test_packets_endpoints(self):
        # 1. Inject test packet into history
        self.server.packet_history.append({
            'time': '12:00:00',
            'timestamp': 1755302400.0,
            'rat': '5g',
            'layer': 'NAS',
            'is_uplink': False,
            'channel': '5GMM',
            'protocol': 'NAS-5GS',
            'summary': '5G Registration Accept (SUCI Protected)',
            'tree': '// 5G NAS Registration Accept Structure',
            'length': 48,
            'raw': '7e0042010102030405060708'
        })

        # 2. GET /api/packets/list
        req = urllib.request.Request(f"{self.base_url}/api/packets/list")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreaterEqual(data['count'], 1)
            self.assertEqual(data['packets'][0]['rat'], '5g')

        # 3. GET /api/packets/export_pcap
        req = urllib.request.Request(f"{self.base_url}/api/packets/export_pcap")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            pcap_bytes = resp.read()
            self.assertGreaterEqual(len(pcap_bytes), 24)
            # Verify libpcap magic header (0xa1b2c3d4)
            self.assertEqual(pcap_bytes[:4], b'\xd4\xc3\xb2\xa1')

        # 4. POST /api/packets/clear
        req = urllib.request.Request(
            f"{self.base_url}/api/packets/clear",
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(len(self.server.packet_history), 0)

    def test_traffic_simulate_endpoints(self):
        # 1. GET /api/traffic/status
        req = urllib.request.Request(f"{self.base_url}/api/traffic/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('simulating', data)

        # 2. POST /api/traffic/simulate (burst of 5 frames)
        sim_data = json.dumps({'action': 'burst', 'count': 5}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/traffic/simulate",
            data=sim_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

        # 3. GET /api/traffic/simulate?action=start&rate=20
        req = urllib.request.Request(f"{self.base_url}/api/traffic/simulate?action=start&rate=20")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertTrue(data['simulating'])

        # 4. Stop simulation
        req = urllib.request.Request(f"{self.base_url}/api/traffic/simulate?action=stop")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertFalse(data['simulating'])

    def test_device_manager_endpoints(self):
        # 1. GET /api/devices/scan
        req = urllib.request.Request(f"{self.base_url}/api/devices/scan")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('devices', data)
            self.assertIsInstance(data['devices'], list)

        # 2. GET /api/devices/status
        req = urllib.request.Request(f"{self.base_url}/api/devices/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('device', data)

        # 3. POST /api/devices/disconnect
        req = urllib.request.Request(
            f"{self.base_url}/api/devices/disconnect",
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

    def test_f3_endpoints(self):
        # 1. Inject F3 log into server
        self.server.f3_history.append({
            'timestamp': '12:30:00.123',
            'subsystem': 'RRC',
            'severity': 'INFO',
            'file': 'modem_rrc.c',
            'line': 142,
            'text': 'RRC_STATE_IDLE -> RRC_STATE_CONNECTED',
            'opcode': 121
        })

        # 2. GET /api/f3/list
        req = urllib.request.Request(f"{self.base_url}/api/f3/list")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreaterEqual(data['count'], 1)

        # 3. GET /api/f3/history
        req = urllib.request.Request(f"{self.base_url}/api/f3/history?subsystem=RRC&limit=50")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

        # 4. GET /api/f3/export
        req = urllib.request.Request(f"{self.base_url}/api/f3/export?format=txt")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            txt_content = resp.read().decode('utf-8')
            self.assertIn('QXDM F3 Trace Log', txt_content)

    def test_terminal_endpoints(self):
        # 1. POST /api/terminal/exec (AT Command)
        req_data = json.dumps({'cmd': 'AT+CSQ'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/terminal/exec",
            data=req_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('+CSQ:', data['output'])

        # 2. POST /api/terminal/diag_raw (Qualcomm DIAG Version Opcode 0x00)
        diag_data = json.dumps({'hex': '00'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/terminal/diag_raw",
            data=diag_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('DIAG_VERNO_F', data['output'])

        # 3. GET /api/terminal/commands (Library)
        req = urllib.request.Request(f"{self.base_url}/api/terminal/commands")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreaterEqual(len(data['commands']), 4)

        # 4. POST /api/terminal/macro (Full Audit)
        macro_data = json.dumps({'macro': 'rf_scan'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/terminal/macro",
            data=macro_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreaterEqual(len(data['results']), 2)

        # 5. POST /api/terminal/macro_custom
        custom_data = json.dumps({'name': 'test_seq', 'commands': ['AT', 'AT+CPIN?']}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/terminal/macro_custom",
            data=custom_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['total_commands'], 2)

        # 6. GET /api/terminal/export
        req = urllib.request.Request(f"{self.base_url}/api/terminal/export?format=txt")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            txt_exp = resp.read().decode('utf-8')
            self.assertIn('Terminal Session Log', txt_exp)

        # 7. POST /api/terminal/clear
        req = urllib.request.Request(
            f"{self.base_url}/api/terminal/clear",
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

    def test_fuzzer_endpoints(self):
        # 1. GET /api/fuzzer/templates
        req = urllib.request.Request(f"{self.base_url}/api/fuzzer/templates")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('nr_rrc_reconfig', data['templates'])
            self.assertIn('lte_nas_smc', data['templates'])
            self.assertGreaterEqual(len(data['templates']), 5)

        # 2. POST /api/fuzzer/generate
        post_data = json.dumps({
            'template': 'nr_rrc_reconfig',
            'strategy': 'length_tamper',
            'intensity': 3
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/fuzzer/generate",
            data=post_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertIn('vector', data)
            self.assertIn('mutated_hex', data['vector'])

        # 3. POST /api/fuzzer/campaign/start
        camp_data = json.dumps({
            'template': 'lte_rrc_reconfig',
            'strategy': 'byte_boundary',
            'intensity': 2,
            'count': 5
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/fuzzer/campaign/start",
            data=camp_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['campaign_count'], 5)
            self.assertEqual(len(data['vectors']), 5)

        # 4. GET /api/fuzzer/campaign/history
        req = urllib.request.Request(f"{self.base_url}/api/fuzzer/campaign/history")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreaterEqual(data['total_generated'], 6)

        # 5. GET /api/fuzzer/export_pcap
        req = urllib.request.Request(f"{self.base_url}/api/fuzzer/export_pcap")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            pcap_bytes = resp.read()
            self.assertGreaterEqual(len(pcap_bytes), 24)
            # Verify libpcap magic header (0xa1b2c3d4)
            self.assertEqual(pcap_bytes[:4], b'\xd4\xc3\xb2\xa1')

        # 6. GET /api/fuzzer/export_json
        req = urllib.request.Request(f"{self.base_url}/api/fuzzer/export_json")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            json_data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(json_data['status'], 'ok')

        # 7. POST /api/fuzzer/clear
        req = urllib.request.Request(
            f"{self.base_url}/api/fuzzer/clear",
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

    def test_benchmark_endpoints(self):
        # 1. POST /api/benchmark/run
        bench_data = json.dumps({'count': 200, 'rate': 1000}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/benchmark/run",
            data=bench_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['packets_processed'], 200)
            self.assertIn('throughput_pkts_per_sec', data)
            self.assertIn('latency_stats_ms', data)

        # 2. GET /api/benchmark/status
        req = urllib.request.Request(f"{self.base_url}/api/benchmark/status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            status_data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(status_data['status'], 'ok')
            self.assertFalse(status_data['is_running'])

    def test_security_audit_endpoints(self):
        # 1. GET /api/security/rules (Catalog)
        req = urllib.request.Request(f"{self.base_url}/api/security/rules")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['count'], 88)
            self.assertEqual(len(data['rules']), 88)
            self.assertEqual(data['rules'][0]['rule_id'], 'TELCOSEC-VULN-001')

        # 2. POST /api/security/rules/toggle
        toggle_data = json.dumps({'rule_id': 'TELCOSEC-VULN-004', 'enabled': False}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/security/rules/toggle",
            data=toggle_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertFalse(data['enabled'])

        # 3. POST /api/security/rules/simulate
        sim_data = json.dumps({'rule_id': 'TELCOSEC-VULN-004'}).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/security/rules/simulate",
            data=sim_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')

        # 4. GET /api/audit/report?format=html (Executive HTML Dossier)
        req = urllib.request.Request(f"{self.base_url}/api/audit/report?format=html")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            html_content = resp.read().decode('utf-8')
            self.assertIn('SECURITY AUDIT REPORT', html_content)
            self.assertIn('TelcoSec.net', html_content)

        # 5. GET /api/audit/report?format=json
        req = urllib.request.Request(f"{self.base_url}/api/audit/report?format=json")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            json_report = json.loads(resp.read().decode('utf-8'))
            self.assertIn('findings', json_report)
            self.assertIn('metrics', json_report)

        # 6. GET /api/audit/report?format=markdown
        req = urllib.request.Request(f"{self.base_url}/api/audit/report?format=markdown")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            md_content = resp.read().decode('utf-8')
            self.assertIn('# TelcoSec AirTap Telecom Security Audit Report', md_content)

    def test_bts_intelligence_endpoints(self):
        # 1. Post a sample GPS point with PCI to populate tower database
        post_data = json.dumps({
            'lat': 37.774929,
            'lng': -122.419416,
            'alt': 18.5,
            'speed': 24.5,
            'heading': 45.0,
            'pci': 248,
            'rsrp': -84,
            'sinr': 18,
            'band': 'n78',
            'rat': '5G'
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{self.base_url}/api/geo/point",
            data=post_data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)

        # 2. GET /api/geo/towers (Verifies rich BTS fields)
        req = urllib.request.Request(f"{self.base_url}/api/geo/towers")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertGreater(data['total_sites'], 0)
            bts = data['towers'][0]
            self.assertIn('site_id', bts)
            self.assertIn('cgi', bts)
            self.assertIn('dl_freq_mhz', bts)
            self.assertIn('ul_freq_mhz', bts)
            self.assertIn('bandwidth_mhz', bts)
            self.assertIn('antenna_height_m', bts)
            self.assertIn('eirp_dbm', bts)
            # This record is modeled/estimated from PCI for map display, not
            # a real per-site security check - verify it's labeled as such
            # and that fbs_verdict reflects the real session-wide auditor
            # signal rather than a fabricated per-tower "VERIFIED" claim.
            self.assertTrue(bts.get('estimated'))
            self.assertIn('fbs_verdict', bts)
            self.assertNotIn('VERIFIED', bts['fbs_verdict'])
            self.assertIn('security', bts)

        # 3. GET /api/geo/bts_details
        site_id = bts['site_id']
        req = urllib.request.Request(f"{self.base_url}/api/geo/bts_details?site_id={site_id}")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['bts']['site_id'], site_id)
            self.assertEqual(data['bts']['carrier'], 'AT&T Mobility (310-410)')

    def test_deep_dissector_decoding(self):
        from src.protocol.deep_dissector import DeepDissector
        # 1. Test LTE NAS Security Mode Command Dissection
        # Security header 0x04 (Integrity and Ciphered with new EPS security context), msg_type 0x5D
        smc_payload = bytes([0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x07, 0x5D, 0x22, 0x00])
        res = DeepDissector.dissect(0xB0E2, smc_payload, rat='4g', protocol='NAS-EPS EMM')
        self.assertEqual(res['summary'], 'Security Mode Command')
        self.assertTrue(res['is_security_protected'])
        self.assertIn('128-EEA2', res['cipher_algo'])
        self.assertIn('128-EIA2', res['integrity_algo'])
        self.assertIn('Non-Access-Stratum', res['tree'])

        # 2. Test 5G NAS Registration Request
        reg_payload = bytes([0x00, 0x7E, 0x41, 0x01, 0x00])
        res_5g = DeepDissector.dissect(0xB821, reg_payload, rat='5g', protocol='5GS 5GMM')
        self.assertEqual(res_5g['summary'], '5GMM Registration Request')
        self.assertIn('5G System', res_5g['tree'])

        # 3. Test UICC APDU AUTHENTICATE
        apdu_payload = bytes([0x00, 0x88, 0x00, 0x81, 0x22])
        res_sim = DeepDissector.dissect(0x1004, apdu_payload, rat='sim', protocol='SIM APDU')
        self.assertIn('AUTHENTICATE', res_sim['summary'])
        self.assertIn('ISO/IEC 7816-4', res_sim['tree'])

        # 4. Test IMS SIP Frame
        sip_payload = b"INVITE sip:alice@ims.mnc410.mcc310.3gppnetwork.org SIP/2.0\r\nFrom: <sip:bob@ims>\r\nTo: <sip:alice@ims>\r\nCall-ID: abc123xyz\r\n\r\n"
        res_sip = DeepDissector.dissect(0xB0C2, sip_payload, rat='ims', protocol='IMS SIP')
        self.assertIn('SIP Request: INVITE', res_sip['summary'])
        self.assertIn('Call-ID', res_sip['tree'])

if __name__ == '__main__':
    unittest.main()


