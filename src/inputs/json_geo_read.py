#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from base64 import b64decode
from struct import unpack
from json import loads
from time import time
import gzip

from ._base_input import BaseInput

"""
    This class implements reading JSON files produced with the json_geo_dump.py
    module.
"""

class JsonGeoReader(BaseInput):
    
    def __init__(self, json_file):
        
        self.json_file = json_file
        
        super().__init__()
    
    def read_loop(self):
        for line in self.json_file:
            if not line or not line.strip():
                continue
            
            try:
                row = loads(line)
            except Exception:
                continue
            
            if 'lat' in row and 'lng' in row:
                self.latitude = row['lat']
                self.longitude = row['lng']

            if 'log_frame' in row:
                log_type, log_frame, timestamp = row['log_type'], b64decode(row['log_frame']), row.get('timestamp', 0)
                self.dispatch_diag_log(log_type, log_frame[12:], log_frame[:12], timestamp)

    
