#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - AT Terminal & Protocol Fuzzer Unit Test Suite
    Tests command execution, macro dispatch, URC callbacks, and 3GPP mutation strategies.
"""

import unittest
from src.modules.at_terminal import AtTerminalEngine, PREDEFINED_AT_COMMANDS
from src.modules.protocol_fuzzer import ProtocolFuzzerEngine, SIGNALING_TEMPLATES


class TestTerminalAndFuzzer(unittest.TestCase):

    def setUp(self):
        self.urcs_received = []
        self.term = AtTerminalEngine(urc_callback=lambda u: self.urcs_received.append(u))
        self.fuzzer = ProtocolFuzzerEngine()

    def test_at_terminal_commands_list(self):
        cmds = self.term.get_predefined_commands()
        self.assertIsInstance(cmds, list)
        self.assertGreaterEqual(len(cmds), 3)
        cat_names = [c["category"] for c in cmds]
        self.assertIn("Radio & Serving Network", cat_names)
        self.assertIn("SIM & Smart Card Security", cat_names)

    def test_at_terminal_execution_csq(self):
        res = self.term.execute_command("AT+CSQ")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["cmd"], "AT+CSQ")
        self.assertIn("+CSQ:", res["output"])
        self.assertGreaterEqual(len(self.term.get_history()), 1)

    def test_at_terminal_execution_cops(self):
        res = self.term.execute_command("AT+COPS=?")
        self.assertEqual(res["status"], "ok")
        self.assertIn("+COPS:", res["output"])

    def test_at_terminal_macro_full_audit(self):
        res = self.term.execute_macro("full_audit")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["macro"], "full_audit")
        self.assertGreater(len(res["results"]), 5)

    def test_protocol_fuzzer_templates(self):
        tmpls = self.fuzzer.get_templates()
        self.assertIn("lte_nas_smc", tmpls)
        self.assertIn("lte_rrc_reconfig", tmpls)
        self.assertIn("nr_rrc_reconfig", tmpls)

    def test_protocol_fuzzer_byte_boundary(self):
        res = self.fuzzer.generate_mutated_vector("lte_nas_smc", "byte_boundary", intensity=3)
        self.assertEqual(res["template"], "lte_nas_smc")
        self.assertEqual(res["strategy"], "byte_boundary")
        self.assertEqual(res["original_len"], res["mutated_len"])
        self.assertTrue(len(res["mutated_hex"]) > 0)

    def test_protocol_fuzzer_length_tamper(self):
        res = self.fuzzer.generate_mutated_vector("lte_rrc_reconfig", "length_tamper")
        self.assertEqual(res["strategy"], "length_tamper")
        self.assertIn("length field mismatch", res["description"])

    def test_protocol_fuzzer_truncation(self):
        res = self.fuzzer.generate_mutated_vector("nr_rrc_reconfig", "truncation")
        self.assertLess(res["mutated_len"], res["original_len"])

    def test_protocol_fuzzer_ie_injection(self):
        res = self.fuzzer.generate_mutated_vector("lte_sib1", "ie_injection", intensity=2)
        self.assertGreater(res["mutated_len"], res["original_len"])


if __name__ == '__main__':
    unittest.main()
