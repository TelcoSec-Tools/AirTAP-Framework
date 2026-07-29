#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

from unittest import TestCase
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.protocol.messages import DIAG_VERNO_F, DIAG_LOG_F, DIAG_BAD_CMD_F, get_message_name, message_id_to_name

class MessageTests(TestCase):

    def test_message_id_mapping(self):
        self.assertIn(DIAG_VERNO_F, message_id_to_name)
        self.assertEqual(message_id_to_name[DIAG_VERNO_F], 'DIAG_VERNO_F')
        self.assertEqual(message_id_to_name[DIAG_LOG_F], 'DIAG_LOG_F')
        self.assertEqual(message_id_to_name[DIAG_BAD_CMD_F], 'DIAG_BAD_CMD_F')

    def test_get_message_name_known_and_unknown(self):
        self.assertEqual(get_message_name(DIAG_VERNO_F), 'DIAG_VERNO_F')
        # Unknown opcode should return string representation
        self.assertEqual(get_message_name(99999), '99999')
