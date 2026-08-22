#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Wireshark Lua Dissectors Test Suite
    Verifies all TelcoSec cellular dissectors, framing, and plugin installer.
"""

import os
import unittest
import tempfile
import shutil

from src.modules.wireshark_plugin.install_plugins import (
    get_wireshark_plugin_dir,
    get_plugin_source_dir,
    list_dissectors,
    install
)


class TestWiresharkPlugins(unittest.TestCase):

    def setUp(self):
        self.plugin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "modules", "wireshark_plugin")

    def test_dissector_files_exist(self):
        expected_plugins = [
            "telcosec_vuln_audit_engine.lua",
            "gsmtap_sec_analyzer.lua",
            "qc_lte_nas.lua",
            "qc_lte_rrc.lua",
            "qc_5g_nr_nas.lua",
            "qc_5g_nr_rrc.lua",
            "uicc_apdu_sec.lua",
            "lea_intercept_sec.lua",
            "etsi_li_ps_pdu.lua",
            "shannon_5g_nr.lua",
            "shannon_lte.lua",
            "shannon_gsm_wcdma.lua",
            "shannon_baseband_crash.lua",
            "mtk_mobilelog_framing.lua",
            "gsm_sms_cbs_sec.lua",
            "lpp_positioning_sec.lua",
            "s1ap_sec.lua",
            "x2ap_sec.lua",
            "x2ap_endc_sec.lua",
            "gtp_u_v1_sec.lua"
        ]

        for plugin in expected_plugins:
            full_path = os.path.join(self.plugin_dir, plugin)
            self.assertTrue(os.path.exists(full_path), f"Plugin file missing: {plugin}")
            self.assertGreater(os.path.getsize(full_path), 50, f"Plugin file is empty or too small: {plugin}")

    def test_dissector_lua_structure(self):
        lua_files = [f for f in os.listdir(self.plugin_dir) if f.endswith('.lua')]
        self.assertGreaterEqual(len(lua_files), 20)

        for fname in lua_files:
            full_path = os.path.join(self.plugin_dir, fname)
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            if fname == "telcosec_vuln_audit_engine.lua":
                self.assertIn("TELCOSEC-VULN-001", content)
            else:
                self.assertTrue("Proto" in content or "DissectorTable" in content, f"{fname} missing Proto definition")
                self.assertTrue("dissector" in content.lower(), f"{fname} missing dissector function")

    def test_plugin_installer_path_detection(self):
        path = get_wireshark_plugin_dir()
        self.assertIsInstance(path, str)
        self.assertIn("plugins", path.lower())

    def test_plugin_installer_execution(self):
        temp_target = tempfile.mkdtemp(prefix="airtap_ws_test_")
        try:
            res = install(dest_dir=temp_target)
            self.assertEqual(res["status"], "ok")
            self.assertGreaterEqual(res["total_dissectors"], 20)

            installed = [f for f in os.listdir(temp_target) if f.endswith(".lua")]
            self.assertEqual(len(installed), res["total_dissectors"])
        finally:
            shutil.rmtree(temp_target, ignore_errors=True)

    def test_plugin_installer_dry_run(self):
        temp_target = tempfile.mkdtemp(prefix="airtap_ws_test_dry_")
        try:
            res = install(dest_dir=temp_target, dry_run=True)
            self.assertEqual(res["status"], "ok")
            self.assertTrue(res["dry_run"])
            # In dry-run, no files should be created in the directory
            installed = [f for f in os.listdir(temp_target) if f.endswith(".lua")]
            self.assertEqual(len(installed), 0)
        finally:
            shutil.rmtree(temp_target, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
