#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from os.path import exists
import re

class DmcParser:
    """
    Parses Qualcomm QXDM Item Configuration (.dmc / .cfg) files to extract
    log codes, event IDs, and message subsystem masks.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.log_codes = set()
        self.event_ids = set()
        self.message_ssids = set()

    def parse(self):
        if not exists(self.file_path):
            raise FileNotFoundError(f"DMC file not found: {self.file_path}")

        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue

            # 1. Match LOG_CODE / LOG_PACKET / LOG 0xXXXX
            log_match = re.search(r'(?:LOG_CODE|LOG_PACKET|LOG|0x[0-9a-fA-F]+)', line, re.IGNORECASE)
            hex_matches = re.findall(r'0x[0-9a-fA-F]+', line)
            for h in hex_matches:
                try:
                    val = int(h, 16)
                    if 0x1000 <= val <= 0xFFFF: # Standard Qualcomm 16-bit log codes
                        self.log_codes.add(val)
                except ValueError:
                    pass

            # 2. Match EVENT_ID / EVENT XXXX
            if 'EVENT' in line.upper():
                digits = re.findall(r'\b\d+\b', line)
                for d in digits:
                    try:
                        self.event_ids.add(int(d, 10))
                    except ValueError:
                        pass

            # 3. Match MESSAGE / SSID XXXX
            if 'MSG' in line.upper() or 'SSID' in line.upper():
                digits = re.findall(r'\b\d+\b', line)
                for d in digits:
                    try:
                        self.message_ssids.add(int(d, 10))
                    except ValueError:
                        pass

        return {
            'log_codes': sorted(list(self.log_codes)),
            'event_ids': sorted(list(self.event_ids)),
            'message_ssids': sorted(list(self.message_ssids)),
        }
