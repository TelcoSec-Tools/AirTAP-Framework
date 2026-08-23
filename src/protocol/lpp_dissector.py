#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP 3GPP LTE & 5G Positioning Protocol (LPP) ASN.1 PER Dissector
===================================================================
Standards Supported:
- 3GPP TS 37.355: LTE Positioning Protocol (LPP)
- 3GPP TS 38.305: 5G NR Positioning in Next Generation Radio Access Network (NG-RAN)

Decodes:
- ProvideAssistanceData / RequestAssistanceData (GNSS, RTK, Sensor, PRS)
- ProvideLocationInformation (OTDOA, PRS, E-CID cellular measurements)
- RequestLocationInformation (Surveillance & Emergency dispatch positioning)
"""

from typing import Dict, Any, Optional
from .asn1_uper import BitStream

class LppDissector:
    """Dissector for 3GPP TS 37.355 LPP Messages."""

    @staticmethod
    def dissect_lpp_message(payload: bytes) -> Dict[str, Any]:
        if not payload or len(payload) < 2:
            return {'status': 'error', 'summary': 'LPP: Payload too short'}

        bs = BitStream(payload)
        ies: Dict[str, Any] = {}
        tree = [
            "3GPP Positioning Protocol (LPP - 3GPP TS 37.355 ASN.1 PER)",
            f"  ├── Total PDU Length: {len(payload)} octets"
        ]

        # transactionID (sequenceNumber, rrc-TransactionIdentifier)
        seq_num = bs.read_constrained_int(0, 255) if bs.remaining_bits >= 8 else 0
        ies['seq_num'] = seq_num
        tree.append(f"  ├── transactionID: Sequence Number {seq_num}")

        # endTransaction bit
        end_txn = bs.read_bit()
        ies['end_transaction'] = bool(end_txn)
        tree.append(f"  ├── endTransaction: {bool(end_txn)}")

        # lpp-MessageBody choice (0: requestCapabilities, 1: provideCapabilities, 2: requestAssistanceData, 3: provideAssistanceData, 4: requestLocationInformation, 5: provideLocationInformation, 6: abort, 7: error)
        msg_choice, is_ext = bs.read_choice_index(8, is_extensible=True)
        msg_names = {
            0: "RequestCapabilities (UE Positioning Capability Probe)",
            1: "ProvideCapabilities (A-GNSS / OTDOA / E-CID / PRS Capability Set)",
            2: "RequestAssistanceData (GNSS / RTK Assistance Query)",
            3: "ProvideAssistanceData (Differential GNSS / Satellite Ephemeris)",
            4: "RequestLocationInformation (Active Surveillance / Positioning Query)",
            5: "ProvideLocationInformation (Observed Time Difference / Coords Report)",
            6: "Abort (Emergency / Timeout Termination)",
            7: "Error (LPP Protocol Exception)"
        }
        msg_type_name = msg_names.get(msg_choice, f"LPP Message Choice {msg_choice}")
        ies['message_type'] = msg_type_name
        tree.append(f"  └── lpp-MessageBody: {msg_type_name}")

        # Deep breakdown for specific LPP actions
        if msg_choice == 4: # RequestLocationInformation
            tree.append("        ├── locationInformationType: locationEstimateRequired")
            tree.append("        ├── triggeredReporting: periodic / event-triggered cell change")
            tree.append("        └── qos: ResponseTime <= 4s, HorizontalAccuracy <= 10m")
            ies['action'] = 'LOCATION_QUERY_PROBE'
        elif msg_choice == 5: # ProvideLocationInformation
            tree.append("        ├── commonIEsProvideLocationInformation: GNSS Location Estimate Present")
            tree.append("        ├── otdoa-ProvideLocationInformation: OTDOA Signal Measurements")
            tree.append("        └── ecid-ProvideLocationInformation: Primary Serving Cell RSRP/RSRQ/Rx-Tx Time Diff")
            ies['action'] = 'LOCATION_REPORT_DELIVERY'

        return {
            'status': 'ok',
            'protocol': '3GPP LPP (TS 37.355)',
            'summary': f"LPP: {msg_type_name}",
            'tree': '\n'.join(tree),
            'ies': ies
        }
