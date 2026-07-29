#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

from unittest import TestCase
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.inputs._hdlc_mixin import HdlcMixin

class HdlcTests(TestCase, HdlcMixin):
    
    def test_hdlc_encapsulate_and_decapsulate(self):
        payload = b'\x00\x01\x02\x03\x04\x05'
        encapsulated = self.hdlc_encapsulate(payload)
        
        # Check trailer byte
        self.assertTrue(encapsulated.endswith(self.TRAILER_CHAR))
        
        decapsulated = self.hdlc_decapsulate(encapsulated)
        self.assertEqual(payload, decapsulated)

    def test_hdlc_escaping(self):
        # Payload containing bytes that require HDLC escaping (0x7d and 0x7e)
        payload = b'\x13\x7d\x7e\x00'
        encapsulated = self.hdlc_encapsulate(payload)
        
        decapsulated = self.hdlc_decapsulate(encapsulated)
        self.assertEqual(payload, decapsulated)

    def test_hdlc_invalid_crc(self):
        payload = b'\x00\x01\x02'
        encapsulated = self.hdlc_encapsulate(payload)
        
        # Corrupt one byte before trailer
        corrupted = encapsulated[:-3] + b'\xff' + encapsulated[-2:]
        with self.assertRaises(HdlcMixin.InvalidFrameError):
            self.hdlc_decapsulate(corrupted)

    def test_hdlc_short_frame(self):
        with self.assertRaises(HdlcMixin.InvalidFrameError):
            self.hdlc_decapsulate(b'\x7e')
