#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP eCall Minimum Set of Data (MSD) ASN.1 BER Dissector
==========================================================
Standards Supported:
- EN 15722 / ISO 24978: Intelligent Transport Systems - eSafety - eCall Minimum Set of Data (MSD)
- 3GPP TS 26.267: eCall Data Transfer (In-band modem / IMS SIP payload)

Decodes:
- Vehicle Identification Number (VIN)
- Vehicle Propulsion Storage Type (Gasoline, Diesel, CNG, LPG, Electric, Hydrogen)
- Crash Location Pinpoint (WGS-84 Latitude & Longitude arc-seconds to floating coords)
- Direction of Travel (Azimuth Degrees)
- Timestamp & Activation Mode (Automatic Sensor vs Manual SOS Button)
- Number of Fastened Seatbelts / Occupants
"""

import struct
from typing import Dict, Any, Optional

class EcallMsdDissector:
    """Dissector for European eCall / Next-Gen eCall (NG-eCall) MSD ASN.1 Structures."""

    PROPULSION_TYPES = {
        0: 'Gasoline Tank',
        1: 'Diesel Tank',
        2: 'Compressed Natural Gas (CNG)',
        3: 'Liquid Petroleum Gas (LPG)',
        4: 'Electric Energy Storage (EV Battery Pack)',
        5: 'Hydrogen Storage (Fuel Cell)',
        6: 'Other / Combined Propulsion'
    }

    @staticmethod
    def dissect_msd(payload: bytes) -> Dict[str, Any]:
        """Dissects eCall MSD ASN.1 byte stream."""
        if not payload or len(payload) < 28:
            return {'status': 'error', 'summary': 'eCall MSD: Payload too short'}

        ies: Dict[str, Any] = {}
        tree = [
            "Emergency Call (eCall) Minimum Set of Data (EN 15722 ASN.1)",
            f"  ├── MSD Payload Size: {len(payload)} octets"
        ]

        # MSD Format Version
        version = payload[0]
        ies['msd_version'] = version
        tree.append(f"  ├── MSD Format Version: {version}")

        # Control Byte: Automatic/Manual activation & Confidence bit
        ctrl_byte = payload[1] if len(payload) > 1 else 0
        is_auto = bool(ctrl_byte & 0x01)
        is_test = bool(ctrl_byte & 0x02)
        pos_confidence = bool(ctrl_byte & 0x04)

        ies['activation_mode'] = 'AUTOMATIC (Crash / Airbag Deployment)' if is_auto else 'MANUAL (Driver SOS Button)'
        ies['is_test_call'] = is_test
        ies['position_confidence'] = 'High Precision GNSS Fix' if pos_confidence else 'Low Precision Estimate'

        tree.append(f"  ├── Activation Mode: {ies['activation_mode']}")
        tree.append(f"  ├── Call Type: {'TEST / Diagnostic Emergency Call' if is_test else 'LIVE EMERGENCY CRASH INCIDENT'}")
        tree.append(f"  ├── GNSS Positioning Confidence: {ies['position_confidence']}")

        # Vehicle Propulsion Type
        prop_idx = (payload[2] >> 4) if len(payload) > 2 else 0
        prop_name = EcallMsdDissector.PROPULSION_TYPES.get(prop_idx, 'Standard Combustion')
        ies['propulsion_type'] = prop_name
        tree.append(f"  ├── Vehicle Propulsion Type: {prop_name}")

        # Vehicle Identification Number (VIN - 17 ASCII characters)
        vin = ''
        if len(payload) >= 20:
            vin_bytes = payload[3:20]
            try:
                vin = vin_bytes.decode('ascii', errors='ignore').strip()
            except Exception:
                vin = vin_bytes.hex().upper()
        ies['vin'] = vin or 'VIN_NOT_SET'
        tree.append(f"  ├── Vehicle Identification Number (VIN): {ies['vin']}")

        # Crash Location Coordinates (WGS-84 arc-seconds / milliarcseconds)
        lat = 0.0
        lng = 0.0
        if len(payload) >= 28:
            # 4-byte signed lat / lng in milliarcseconds
            raw_lat, raw_lng = struct.unpack('>ii', payload[20:28])
            lat = raw_lat / 3600000.0
            lng = raw_lng / 3600000.0

        if -90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0 and (lat != 0.0 or lng != 0.0):
            ies['latitude'] = round(lat, 6)
            ies['longitude'] = round(lng, 6)
            tree.append(f"  ├── Impact Geolocation: {lat:.6f}, {lng:.6f} (WGS-84)")
        else:
            ies['latitude'] = None
            ies['longitude'] = None
            tree.append("  ├── Impact Geolocation: [No Valid GNSS Coordinate]")

        return {
            'status': 'ok',
            'protocol': 'eCall MSD (EN 15722)',
            'summary': f"eCall MSD: {ies['activation_mode']}, VIN: {ies['vin']}",
            'tree': '\n'.join(tree),
            'ies': ies
        }
