#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
from struct import pack
import tempfile
import json
import os

from src.protocol.log_types import (
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_LTE_CALEA_TRACE_LOG_C,
    LOG_NR_CALEA_TRACE_LOG_C,
    LOG_GSM_CELL_BROADCAST_C,
    LOG_LTE_RRC_ETWS_CMAS_LOG_C,
    LOG_SIM_APDU_LOG_C,
    LOG_LTE_IMS_SIP_MSG_C,
    LOG_NR_IMS_SIP_MSG_C,
)
from src.modules.sec_audit import SecurityAuditor, SecurityAlert


class TestSecurityAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = SecurityAuditor(diag_input=None)

    def test_alert_object_structure(self):
        alert = SecurityAlert(
            severity='CRITICAL',
            category='CIPHERING',
            rat='4G',
            title='Null Ciphering Test',
            description='Testing alert data structure',
            rule_id='TELCOSEC-VULN-003',
            raw_data=b'\x01\x02\x03\x04',
            timestamp=1600000000.0
        )
        d = alert.to_dict()
        self.assertEqual(d['severity'], 'CRITICAL')
        self.assertEqual(d['category'], 'CIPHERING')
        self.assertEqual(d['rat'], '4G')
        self.assertEqual(d['rule_id'], 'TELCOSEC-VULN-003')
        self.assertEqual(d['raw_hex'], '01020304')
        self.assertIn('TELCOSEC-VULN-003', alert.format_terminal())

    def test_lte_nas_security_mode_command_null_ciphering(self):
        hdr = pack('<BBBB', 1, 0, 0, 0)
        nas_pdu = bytes([0x07, 0x5d, 0x01, 0x00])
        log_payload = hdr + nas_pdu

        self.auditor.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'CIPHERING']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-003')
        self.assertIn('EEA0', alerts[0].title)

    def test_lte_nas_security_mode_command_null_integrity(self):
        hdr = pack('<BBBB', 1, 0, 0, 0)
        nas_pdu = bytes([0x07, 0x5d, 0x20, 0x00])
        log_payload = hdr + nas_pdu

        self.auditor.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'INTEGRITY']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-005')
        self.assertIn('EIA0', alerts[0].title)

    def test_lte_nas_cleartext_imsi_identity_request(self):
        hdr = pack('<BBBB', 1, 0, 0, 0)
        nas_pdu = bytes([0x07, 0x55, 0x01])
        log_payload = hdr + nas_pdu

        self.auditor.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'IDENTITY']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-006')
        self.assertIn('IMSI', alerts[0].title)

    def test_lte_nas_attach_reject_forced_downgrade(self):
        hdr = pack('<BBBB', 1, 0, 0, 0)
        nas_pdu = bytes([0x07, 0x44, 0x07])
        log_payload = hdr + nas_pdu

        self.auditor.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'DOWNGRADE']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-007')

    def test_5g_nas_security_mode_command_nea0_nia0(self):
        hdr = pack('<BBBB', 1, 0, 0, 0)
        nas_pdu = bytes([0x7E, 0x00, 0x5D, 0x00])
        log_payload = hdr + nas_pdu

        self.auditor.on_log(LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)

        c_alerts = [a for a in self.auditor.alerts if a.category == 'CIPHERING' and a.rat == '5G']
        i_alerts = [a for a in self.auditor.alerts if a.category == 'INTEGRITY' and a.rat == '5G']
        self.assertEqual(len(c_alerts), 1)
        self.assertEqual(len(i_alerts), 1)
        self.assertEqual(c_alerts[0].rule_id, 'TELCOSEC-VULN-004')
        self.assertEqual(i_alerts[0].rule_id, 'TELCOSEC-VULN-005')

    def test_2g_gsm_ciphering_mode_command_a5_0(self):
        payload = bytes([0x06, 0x35, 0x00, 0x00])
        self.auditor.on_log(LOG_GSM_RR_SIGNALING_MESSAGE_C, payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'CIPHERING' and a.rat == '2G']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-001')

    def test_sim_apdu_authenticate_aka(self):
        # Header (4B) + APDU [CLA=0x00, INS=0x88 (AUTHENTICATE), P1=0x00, P2=0x81]
        payload = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x88, 0x00, 0x81, 0x22])
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-020']
        self.assertEqual(len(alerts), 1)
        self.assertIn('AUTHENTICATE', alerts[0].title)

    def test_sim_apdu_verify_pin(self):
        # Header (4B) + APDU [CLA=0x00, INS=0x20 (VERIFY PIN), P1=0x00, P2=0x01]
        payload = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x20, 0x00, 0x01, 0x08])
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-016']
        self.assertEqual(len(alerts), 1)
        self.assertIn('VERIFY PIN', alerts[0].title)

    def test_stk_simjacker_send_sms(self):
        # Header (4B) + STK TLV [Tag=0xD0, Len=0x10, CmdDetailsTag=0x81, CmdDetailsLen=0x03, Num=1, CmdType=0x13 (SEND SMS)]
        stk_tlv = bytes([0xD0, 0x10, 0x81, 0x03, 0x01, 0x13, 0x00])
        payload = bytes([0x00, 0x00, 0x00, 0x07]) + stk_tlv
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-009']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertIn('SIMjacker', alerts[0].title)

    def test_stk_stealth_location_harvesting(self):
        # STK TLV [Tag=0xD0, Len=0x10, CmdDetailsTag=0x81, CmdDetailsLen=0x03, Num=1, CmdType=0x26 (PROVIDE LOCAL INFO)]
        stk_tlv = bytes([0xD0, 0x10, 0x81, 0x03, 0x01, 0x26, 0x00])
        payload = bytes([0x00, 0x00, 0x00, 0x07]) + stk_tlv
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-017']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('PROVIDE LOCAL INFORMATION', alerts[0].title)

    def test_silent_sms_type0_probe(self):
        pdu = bytes([0x04, 0x0B, 0x91, 0x12, 0x34, 0x56, 0x78, 0x90, 0x40, 0x00])
        self.auditor.audit_sms_tp_pdu(pdu, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.category == 'SILENT_SMS']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].rule_id, 'TELCOSEC-VULN-008')

    def test_ims_sip_caller_id_spoofing(self):
        sip_msg = (
            b"\x00\x00\x00\x00"
            b"INVITE sip:+1987654321@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
            b"From: \"Bank Support\" <sip:+1800123456@ims.mnc001.mcc001.3gppnetwork.org>;tag=12345\r\n"
            b"P-Asserted-Identity: <sip:+1555000111@ims.mnc001.mcc001.3gppnetwork.org>\r\n"
            b"To: <sip:+1987654321@ims.mnc001.mcc001.3gppnetwork.org>\r\n"
            b"\r\n"
        )
        self.auditor.on_log(LOG_LTE_IMS_SIP_MSG_C, sip_msg, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-BADPRAC-004']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('Caller ID', alerts[0].title)

    def test_ims_sip_unencrypted_rtp_stream(self):
        sip_msg = (
            b"\x00\x00\x00\x00"
            b"SIP/2.0 200 OK\r\n"
            b"Content-Type: application/sdp\r\n"
            b"\r\n"
            b"v=0\r\n"
            b"m=audio 49170 RTP/AVP 104\r\n"
            b"a=rtpmap:104 AMR-WB/16000\r\n"
        )
        self.auditor.on_log(LOG_LTE_IMS_SIP_MSG_C, sip_msg, timestamp=1600000000.0)

        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-BADPRAC-003']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('Unencrypted VoLTE', alerts[0].title)

    def test_fbs_sib_security_audit(self):
        from src.modules.decoded_sibs_dump import audit_decoded_sib_security
        
        # Test SIB7 forced 2G downgrade
        alerts = audit_decoded_sib_security('LTE_SystemInformationBlockType7', {'geran_freq': 123})
        self.assertTrue(any('TELCOSEC-BADPRAC-002' in a for a in alerts))

        # Test permissive q-RxLevMin
        alerts = audit_decoded_sib_security('LTE_SystemInformationBlockType1', {'q_rxlevmin': -70}) # -70 * 2 = -140 dBm
        self.assertTrue(any('TELCOSEC-BADPRAC-007' in a for a in alerts))

        # Test 2G CRO inflation
        alerts = audit_decoded_sib_security('GSM_SI3', {'cro': 15}) # 15 * 2 = 30 dB
        self.assertTrue(any('TELCOSEC-BADPRAC-001' in a for a in alerts))

    def test_json_export_and_summary(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            auditor = SecurityAuditor(diag_input=None, audit_log_path=temp_path)
            auditor.record_alert('CRITICAL', 'CIPHERING', '4G', 'Test Alert', 'Test Desc', rule_id='TELCOSEC-VULN-003')
            auditor.on_dispose()

            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.assertEqual(data['total_alerts'], 1)
            self.assertEqual(data['alerts'][0]['rule_id'], 'TELCOSEC-VULN-003')
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # =========================================================================
    # New rule tests (VULN-010 through VULN-023)
    # =========================================================================

    def test_3g_srns_relocation_without_reauth(self):
        """VULN-010: SRNS relocation byte 0x49 triggers re-auth warning."""
        # 0x49 byte present in a short 3G signaling payload
        payload = bytes([0x06, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.auditor.on_log(WCDMA_SIGNALLING_MESSAGE, payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-010']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertEqual(alerts[0].category, 'AUTHENTICATION')

    def test_lte_bearer_modification_qos_downgrade(self):
        """VULN-011: Bearer QoS downgrade (QCI 1 -> 9 and MBR throttle) triggers HIGH alert."""
        self.auditor.audit_lte_bearer_modification(
            qci_before=1, qci_after=9, mbr_dl_before=50000, mbr_dl_after=1000,
            timestamp=1600000000.0
        )
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-011']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertEqual(alerts[0].category, 'QOS_MANIPULATION')
        self.assertIn('QCI 1', alerts[0].description)

    def test_lte_bearer_modification_no_downgrade_no_alert(self):
        """VULN-011: Bearer upgrade (QCI 9 -> 1) should NOT fire an alert."""
        self.auditor.audit_lte_bearer_modification(
            qci_before=9, qci_after=1, mbr_dl_before=1000, mbr_dl_after=50000,
            timestamp=1600000001.0
        )
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-011']
        self.assertEqual(len(alerts), 0)

    def test_lte_guti_reallocation_suppressed(self):
        """VULN-012: Attach Accept without GUTI IEI 0x50 triggers MEDIUM IDENTITY alert."""
        hdr = pack('<BBBB', 1, 0, 0, 0)
        # 0x07 = EPD, 0x42 = Attach Accept (inbound), no 0x50 IEI following
        nas_pdu = bytes([0x07, 0x42, 0x00, 0x02, 0x00, 0xE0, 0x00])
        log_payload = hdr + nas_pdu
        self.auditor.on_log(LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, log_payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-012' and a.rat == '4G']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'MEDIUM')
        self.assertIn('GUTI', alerts[0].title)

    def test_5g_amf_config_update_without_reregistration(self):
        """VULN-013: AMF Config Update Command (0x54) after SMC without registration fires HIGH."""
        hdr = pack('<BBBB', 1, 0, 0, 0)
        # First: send a 5G SMC (0x5d) to increment smc_count
        smc_pdu = bytes([0x7E, 0x00, 0x5D, 0x00])
        self.auditor.on_log(LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, hdr + smc_pdu, timestamp=1600000000.0)
        # Then: send Config Update Command without any registration in between
        cfg_pdu = bytes([0x7E, 0x00, 0x54, 0x00])
        self.auditor.on_log(LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, hdr + cfg_pdu, timestamp=1600000010.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-013']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_stk_wib_open_channel_bip(self):
        """VULN-015: STK OPEN CHANNEL (BIP, cmd_type=0x40) triggers HIGH WIBjacker alert."""
        stk_tlv = bytes([0xD0, 0x10, 0x81, 0x03, 0x01, 0x40, 0x00])
        payload = bytes([0x00, 0x00, 0x00, 0x07]) + stk_tlv
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-015']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('WIBjacker', alerts[0].title)

    def test_usim_ef_imsi_read_binary(self):
        """VULN-018: READ BINARY (INS=0xB0) on EF_IMSI (SFI=0x07) triggers HIGH EF exfil alert."""
        # Header (4B) + APDU [CLA=0x00, INS=0xB0, P1=0x07 (SFI=EF_IMSI set bit), P2=0x00]
        payload = bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0xB0, 0x07, 0x00, 0x09])
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-018']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('EF_IMSI', alerts[0].title)

    def test_stk_set_up_call_unauthorized(self):
        """VULN-019: STK SET UP CALL (cmd_type=0x10) triggers CRITICAL unauthorized call alert."""
        stk_tlv = bytes([0xD0, 0x10, 0x81, 0x03, 0x01, 0x10, 0x00])
        payload = bytes([0x00, 0x00, 0x00, 0x07]) + stk_tlv
        self.auditor.on_log(LOG_SIM_APDU_LOG_C, payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-019']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertIn('SET UP CALL', alerts[0].title)

    def test_5g_interworking_bidding_down(self):
        """VULN-022: 5G Registration Accept with IEI 0x29 (interworking) triggers HIGH downgrade."""
        hdr = pack('<BBBB', 1, 0, 0, 0)
        # 0x42 = Registration Accept, 0x77 ABSENT (no GUTI), 0x29 present (interworking)
        nas_pdu = bytes([0x7E, 0x00, 0x42, 0x29, 0x01, 0x00])
        self.auditor.on_log(LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C, hdr + nas_pdu, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-022']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertEqual(alerts[0].category, 'DOWNGRADE')

    def test_lte_rrc_fbs_no_neighbor_cells(self):
        """VULN-023: Small LTE RRC payload without SIB4/SIB5 triggers FBS isolation alert."""
        from src.protocol.log_types import LOG_LTE_RRC_OTA_MSG_LOG_C
        # Short SIB payload: 4B header + 20B of RRC data, no 0x04/0x05 byte in first 20 bytes
        rrc_payload = bytes([0x01, 0x00, 0x00, 0x00]) + bytes([0x01, 0x02, 0x06, 0x08, 0x0A] * 4)
        self.auditor.on_log(LOG_LTE_RRC_OTA_MSG_LOG_C, rrc_payload, timestamp=1600000000.0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-023' and a.rat == '4G']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'MEDIUM')
        self.assertEqual(alerts[0].category, 'FBS_HEURISTIC')

    def test_deduplication_suppresses_rapid_repeated_alerts(self):
        """Record_alert deduplication: same rule within cooldown window fires only once."""
        for _ in range(5):
            self.auditor.record_alert(
                'HIGH', 'CIPHERING', '4G', 'Repeat Alert', 'Duplicate test',
                rule_id='TELCOSEC-TEST-DUP', timestamp=1600000000.0
            )
        dup_alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-TEST-DUP']
        self.assertEqual(len(dup_alerts), 1, 'Deduplication should suppress repeat alerts within cooldown')

    def test_deduplication_allows_alerts_after_cooldown(self):
        """Record_alert deduplication: same rule after cooldown period fires again."""
        self.auditor.record_alert(
            'HIGH', 'CIPHERING', '4G', 'First Alert', 'First',
            rule_id='TELCOSEC-TEST-COOL', timestamp=1600000000.0
        )
        # Second call well outside the 5s cooldown window
        self.auditor.record_alert(
            'HIGH', 'CIPHERING', '4G', 'Second Alert', 'Second',
            rule_id='TELCOSEC-TEST-COOL', timestamp=1600000010.0
        )
        cool_alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-TEST-COOL']
        self.assertEqual(len(cool_alerts), 2, 'Second alert after cooldown should be recorded')

    def test_full_88_rules_catalog(self):
        """Verify that get_all_rules_catalog returns exactly 88 rules."""
        catalog = self.auditor.get_all_rules_catalog()
        self.assertEqual(len(catalog), 88)
        self.assertEqual(catalog[0]['rule_id'], 'TELCOSEC-VULN-001')
        self.assertEqual(catalog[80]['rule_id'], 'TELCOSEC-VULN-081')
        self.assertEqual(catalog[87]['rule_id'], 'TELCOSEC-VULN-088')

    def test_broadpwn_wifi_heap_overflow(self):
        """VULN-081: Broadpwn Wi-Fi SoC heap overflow triggers critical alert."""
        self.auditor.audit_broadpwn_wifi_frame(wlc_event_code=100, payload_len=1200)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-081']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertEqual(alerts[0].category, 'WIFI_SECURITY')

    def test_sweyntooth_ble_zero_length(self):
        """VULN-082: SweynTooth BLE link-layer zero-length packet triggers alert."""
        self.auditor.audit_bluetooth_sweyntooth_packet(llid=0x01, length=0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-082']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_braktooth_bluetooth_lmp(self):
        """VULN-083: BrakTooth Bluetooth LMP malformed control frame."""
        self.auditor.audit_bluetooth_braktooth_lmp(opcode=39, payload_len=0)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-083']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_knob_bluetooth_entropy(self):
        """VULN-084: KNOB attack low entropy encryption negotiation."""
        self.auditor.audit_bluetooth_knob_entropy(key_entropy_bytes=4)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-084']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_bluetooth_mesh_unencrypted_provisioning(self):
        """VULN-085: Bluetooth Mesh unencrypted provisioning data."""
        self.auditor.audit_bluetooth_mesh_provisioning(is_encrypted=False, pdu_type='PROV_DATA')
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-085']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_coex_interference(self):
        """VULN-086: Cellular-Wi-Fi CoEx starvation alert."""
        self.auditor.audit_coex_interference(rssi_drop_db=32.0, collision_rate=0.75)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-086']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'MEDIUM')

    def test_vowifi_ikev2_null_sa(self):
        """VULN-087: VoWiFi IPsec IKEv2 weak cipher / DH group alert."""
        self.auditor.audit_vowifi_ikev2_sa(encryption_algo='ENCR_NULL', dh_group=2)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-087']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_baseband_dma_escape(self):
        """VULN-088: Cellular baseband DMA memory escape alert."""
        self.auditor.audit_baseband_dma_escape(event_type='DMA_CORRUPT', dma_address=0x89000000)
        alerts = [a for a in self.auditor.alerts if a.rule_id == 'TELCOSEC-VULN-088']
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')


if __name__ == '__main__':
    unittest.main()
