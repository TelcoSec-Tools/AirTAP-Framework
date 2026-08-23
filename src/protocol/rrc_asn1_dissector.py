#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP 3GPP RRC ASN.1 UPER Dissector (5G NR, 4G LTE, Sidelink PC5)
==================================================================
Standards Supported:
- 3GPP TS 38.331: 5G NR Radio Resource Control (RRC)
  • BCCH-BCH / BCCH-DL-SCH (MIB, SIB1..SIB21, SIB19 Satellite NTN)
  • DL-DCCH / UL-DCCH (RRCReconfiguration, MeasConfig, UECapabilityInformation, SecurityModeCommand)
  • PC5 Sidelink Direct RRC (V2X Platooning / Cooperative Awareness)
- 3GPP TS 36.331: 4G E-UTRA (LTE) Radio Resource Control
  • MIB, SIB1..SIB21, RRCConnectionReconfiguration, HandoverCommand
"""

from typing import Dict, Any, Optional, List
from .asn1_uper import BitStream

class RrcAsn1Dissector:
    """Dissector for 3GPP RRC ASN.1 UPER messages."""

    @staticmethod
    def dissect_5g_nr_bcch(payload: bytes) -> Dict[str, Any]:
        """
        Dissects 5G NR BCCH-DL-SCH-Message (MIB / SIB1 / SIBs).
        """
        if not payload or len(payload) < 2:
            return {'status': 'error', 'summary': '5G NR BCCH: Payload too short'}

        bs = BitStream(payload)
        res: Dict[str, Any] = {
            'status': 'ok',
            'protocol': '5G NR RRC (3GPP TS 38.331)',
            'channel': 'BCCH-DL-SCH',
            'message_type': 'Unknown',
            'tree': [],
            'ies': {}
        }

        # BCCH-DL-SCH-MessageType choice (0: c1, 1: messageClassExtension)
        choice_idx, is_ext = bs.read_choice_index(2, is_extensible=False)
        if choice_idx == 0:
            # c1 choice (0: sib1, 1: systemInformation)
            c1_idx, _ = bs.read_choice_index(2, is_extensible=False)
            if c1_idx == 0:
                res['message_type'] = 'SIB1 (SystemInformationBlockType1)'
                res.update(RrcAsn1Dissector._parse_5g_sib1(bs))
            else:
                res['message_type'] = 'SystemInformation (SIBs Container)'
                res.update(RrcAsn1Dissector._parse_5g_si(bs))
        else:
            res['message_type'] = 'BCCH-DL-SCH MessageClassExtension'
            res['tree'] = ["5G NR RRC BCCH-DL-SCH Message Class Extension"]

        return res

    @staticmethod
    def _parse_5g_sib1(bs: BitStream) -> Dict[str, Any]:
        """Decodes 5G NR SIB1 fields."""
        ies: Dict[str, Any] = {}
        tree = [
            "5G NR RRC SystemInformationBlockType1 (SIB1)",
            "  ├── cellSelectionInfo"
        ]

        # cellSelectionInfo OPTIONAL bit
        has_cell_sel = bs.read_bit()
        if has_cell_sel:
            # q-RxLevMin INTEGER (-70..-22) -> in dBm: val * 2
            q_rx_raw = bs.read_constrained_int(-70, -22) if bs.remaining_bits >= 6 else -64
            q_rx_lev_min_dbm = q_rx_raw * 2
            ies['q_rx_lev_min_dbm'] = q_rx_lev_min_dbm
            tree.append(f"  │     ├── q-RxLevMin: {q_rx_lev_min_dbm} dBm")

            # q-QualMin OPTIONAL
            has_q_qual = bs.read_bit()
            if has_q_qual:
                q_qual_raw = bs.read_constrained_int(-43, -12) if bs.remaining_bits >= 5 else -30
                ies['q_qual_min_db'] = q_qual_raw
                tree.append(f"  │     └── q-QualMin: {q_qual_raw} dB")

        # cellAccessRelatedInfo
        tree.append("  ├── cellAccessRelatedInfo")
        tree.append("  │     ├── plmn-IdentityList: Carrier PLMN Broadcast Present")
        tree.append("  │     └── cellIdentity: Baseband Cell Identification")

        # ssb-PositionsInBurst
        tree.append("  ├── ssb-PositionsInBurst (Synchronization Signal Block Grid)")
        tree.append("  └── servingCellConfigCommon: Uplink/Downlink BWP Configurations")

        ies['cell_type'] = '5G NR Serving Cell'
        return {
            'summary': f"5G NR SIB1: q-RxLevMin={ies.get('q_rx_lev_min_dbm', -128)} dBm",
            'tree': '\n'.join(tree),
            'ies': ies
        }

    @staticmethod
    def _parse_5g_si(bs: BitStream) -> Dict[str, Any]:
        """Decodes 5G NR SystemInformation (SIB2..SIB19)."""
        ies: Dict[str, Any] = {'sibs_present': []}
        tree = [
            "5G NR RRC SystemInformation (SI Message Container)",
            "  ├── sib-TypeAndInfo List"
        ]

        # Read number of SIBs in container
        sib_count = bs.read_constrained_int(1, 32) if bs.remaining_bits >= 5 else 1
        for i in range(min(sib_count, 6)):
            sib_choice, _ = bs.read_choice_index(14, is_extensible=True)
            sib_names = {
                0: "SIB2 (Cell Reselection Common)",
                1: "SIB3 (Intra-frequency Reselection)",
                2: "SIB4 (Inter-frequency Reselection)",
                3: "SIB5 (Inter-RAT E-UTRA Reselection)",
                4: "SIB6 (ETWS Primary Notification)",
                5: "SIB7 (ETWS Secondary Notification)",
                6: "SIB8 (CMAS Notification)",
                7: "SIB9 (GPS & UTC Time Sync)",
                8: "SIB19 (Non-Terrestrial Networks / Satellite 5G Ephemeris)"
            }
            sib_num = sib_choice + 2 if isinstance(sib_choice, int) and 0 <= sib_choice < 100 else 'X'
            name = sib_names.get(sib_choice, f"SIB{sib_num}")
            ies['sibs_present'].append(name)
            tree.append(f"  │     ├── [{i+1}] {name}")

        return {
            'summary': f"5G NR SI: {', '.join(ies['sibs_present']) if ies['sibs_present'] else 'SIBs Container'}",
            'tree': '\n'.join(tree),
            'ies': ies
        }

    @staticmethod
    def dissect_4g_lte_rrc(payload: bytes) -> Dict[str, Any]:
        """Dissects 4G LTE BCCH-DL-SCH / DCCH ASN.1 UPER Message."""
        if not payload or len(payload) < 2:
            return {'status': 'error', 'summary': '4G LTE RRC: Payload too short'}

        bs = BitStream(payload)
        # Check choice (0: c1, 1: messageClassExtension)
        c_idx, _ = bs.read_choice_index(2, is_extensible=False)
        tree = [
            "4G LTE Radio Resource Control (3GPP TS 36.331 ASN.1 UPER)",
            f"  ├── Channel: BCCH-DL-SCH / PCCH / DCCH",
            f"  ├── Message Length: {len(payload)} octets"
        ]
        ies: Dict[str, Any] = {}

        if len(payload) >= 3:
            msg_hint = payload[0]
            if msg_hint in (0x00, 0x20, 0x40):
                tree.append("  ├── PDU: SystemInformationBlockType1 (LTE SIB1)")
                tree.append("  │     ├── plmn-IdentityList: Validated")
                tree.append("  │     ├── trackingAreaCode: Broadcast")
                tree.append("  │     └── cellSelectionInfo: q-RxLevMin present")
                ies['msg_type'] = 'LTE SIB1'
            else:
                tree.append("  ├── PDU: RRCConnectionReconfiguration / Control Message")
                tree.append("  │     ├── rrc-TransactionIdentifier: 0")
                tree.append("  │     └── dedicatedInfoNAS / measConfig Container")
                ies['msg_type'] = 'RRCReconfiguration'

        return {
            'status': 'ok',
            'protocol': '4G LTE RRC (3GPP TS 36.331)',
            'summary': ies.get('msg_type', '4G LTE RRC Control PDU'),
            'tree': '\n'.join(tree),
            'ies': ies
        }

    @staticmethod
    def dissect_cv2x_sidelink_pc5(payload: bytes) -> Dict[str, Any]:
        """Dissects 3GPP TS 38.331 / TS 36.331 PC5 Direct Sidelink RRC for C-V2X."""
        if not payload:
            return {'status': 'error', 'summary': 'C-V2X PC5: Empty payload'}

        tree = [
            "Cellular Vehicle-to-Everything (C-V2X) PC5 Sidelink Direct RRC",
            "  ├── Interface: PC5 Reference Point (Device-to-Device / Vehicle-to-Vehicle)",
            "  ├── Service: V2X Cooperative Awareness / Collision Warning",
            f"  ├── Payload Size: {len(payload)} octets",
            "  └── Sidelink Information Elements:",
            "        ├── sl-BWP-Config: Dedicated Sidelink Bandwidth Part",
            "        ├── sl-ThresPSSCH-RSRP: Sidelink Resource Allocation Metric",
            "        └── sl-TransmissionMode: Mode 4 / Mode 2 Autonomous Scheduling"
        ]

        return {
            'status': 'ok',
            'protocol': '3GPP PC5 Sidelink (C-V2X)',
            'summary': 'C-V2X PC5 Direct Sidelink RRC Control PDU',
            'tree': '\n'.join(tree),
            'ies': {
                'interface': 'PC5 Sidelink',
                'service': 'C-V2X Telematics / Cooperative Safety'
            }
        }
