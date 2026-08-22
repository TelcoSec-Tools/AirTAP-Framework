#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    AirTap - Unit Tests for APN & 5G DNN Security Auditor
    Copyright (C) TelcoSec.net
"""

import unittest
from src.modules.apn_sec_audit import ApnSecurityAuditor


class TestApnSecurityAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor = ApnSecurityAuditor()

    def test_valid_carrier_apn_clean(self):
        res = self.auditor.audit_apn(
            apn_name="internet.mnc001.mcc001.gprs",
            pdn_type="IPv4v6",
            restriction_level=0
        )
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["network_id"], "internet")
        self.assertEqual(res["mcc"], "001")
        self.assertEqual(res["mnc"], "001")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(len(res["findings"]), 0)

    def test_ims_apn_level_zero_violation(self):
        res = self.auditor.audit_apn(
            apn_name="ims.mnc020.mcc310.gprs",
            pdn_type="IPv4v6",
            restriction_level=0 # Violation: Level 0 on IMS APN
        )
        self.assertEqual(res["profile_category"], "IMS_VOLTE")
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-008" for f in res["findings"]))

    def test_ims_apn_ipv4_only_violation(self):
        res = self.auditor.audit_apn(
            apn_name="ims.mnc020.mcc310.gprs",
            pdn_type="IPv4", # Violation: GSMA IR.92 requires IPv6/IPv4v6
            restriction_level=4
        )
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-007" for f in res["findings"]))

    def test_empty_apn_critical(self):
        res = self.auditor.audit_apn(apn_name="")
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-001" for f in res["findings"]))

    def test_malformed_consecutive_dots(self):
        res = self.auditor.audit_apn(apn_name="my..apn")
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-003" for f in res["findings"]))

    def test_static_proxy_mitm_detection(self):
        res = self.auditor.audit_apn(
            apn_name="custom.internet",
            proxy_host="192.168.1.50",
            proxy_port=8080
        )
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-010" for f in res["findings"]))

    def test_5g_emergency_slice_mismatch(self):
        res = self.auditor.audit_apn(
            apn_name="sos",
            sst=1 # eMBB instead of URLLC SST 2
        )
        self.assertTrue(any(f["rule_id"] == "TELCOSEC-APN-009" for f in res["findings"]))

    def test_cli_report_formatting(self):
        res = self.auditor.audit_apn(apn_name="ims", restriction_level=0)
        report = self.auditor.format_cli_report(res)
        self.assertIn("AirTap - APN & 5G Data Network Name Security Auditor", report)
        self.assertIn("TELCOSEC-APN-008", report)
        self.assertIn("https://app.telcosec.net", report)


if __name__ == '__main__':
    unittest.main()
