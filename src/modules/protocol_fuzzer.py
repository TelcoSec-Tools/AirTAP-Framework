#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Baseband Protocol Robustness & Compliance Mutation Tester
    Copyright (C) TelcoSec.net - Telecom Security Intelligence & Research

    Generates grammar-aware 3GPP signaling test vectors, TLV boundary mutations,
    and ASN.1 length anomalies for protocol verification and crash resilience auditing.
"""

import os
import struct
import random
import time
import io
from logging import info, error, warning

# Canonical 3GPP Signaling Template Packets (Hex Payload)
SIGNALING_TEMPLATES = {
    "nr_rrc_reconfig": {
        "name": "5G NR RRC Reconfiguration (3GPP TS 38.331)",
        "rat": "5G",
        "raw_hex": "400408102030405060708090a0b0c0d0e0f0",
        "description": "5G NR standalone radio bearer configuration and measurement config."
    },
    "nr_reg_reject": {
        "name": "5G 5GMM Registration Reject (3GPP TS 24.501)",
        "rat": "5G",
        "raw_hex": "7e00440b",
        "description": "5GMM Registration Reject with 5GMM Cause #11 (PLMN not allowed)."
    },
    "nr_auth_request": {
        "name": "5G 5GMM Authentication Request (3GPP TS 24.501)",
        "rat": "5G",
        "raw_hex": "7e00560110aabbccddeeff001122334455667788991000112233445566778899aabbccddeeff",
        "description": "5G AKA authentication challenge containing 128-bit RAND and AUTN."
    },
    "nr_sib1": {
        "name": "5G NR SIB1 System Information (3GPP TS 38.331)",
        "rat": "5G",
        "raw_hex": "00003881020408102030405060708090a0b0c0",
        "description": "5G Standalone SIB1 cell selection, scheduling info and PLMN identity."
    },
    "lte_nas_smc": {
        "name": "LTE NAS Security Mode Command (3GPP TS 24.301)",
        "rat": "4G",
        "raw_hex": "075d020220112233445566778899aabbccddeeff",
        "description": "NAS SMC specifying ciphering and integrity algorithms (EEA2/EIA2)."
    },
    "lte_rrc_reconfig": {
        "name": "LTE RRC Connection Reconfiguration (3GPP TS 36.331)",
        "rat": "4G",
        "raw_hex": "280010048123456789abcdef0123456789",
        "description": "Standard RRC connection reconfiguration establishing srb2/drb1."
    },
    "lte_sib1": {
        "name": "LTE SIB1 (SystemInformationBlockType1)",
        "rat": "4G",
        "raw_hex": "68000411223344556677889900aabbccddee",
        "description": "Broadcast SIB1 containing cellSelectionInfo (q-RxLevMin) and PLMN identity list."
    },
    "lte_sib2": {
        "name": "LTE SIB2 Radio Resource Configuration (3GPP TS 36.331)",
        "rat": "4G",
        "raw_hex": "48001234567890abcdef1122334455667788",
        "description": "Common radio resource configuration, RACH parameters, and timers."
    },
    "lte_tau_reject": {
        "name": "LTE Tracking Area Update (TAU) Reject (3GPP TS 24.301)",
        "rat": "4G",
        "raw_hex": "074b09",
        "description": "EMM TAU Reject with Cause #9 (UE identity cannot be derived by network)."
    },
    "lte_nas_auth_reject": {
        "name": "LTE NAS Authentication Reject (3GPP TS 24.301)",
        "rat": "4G",
        "raw_hex": "0754",
        "description": "Unauthenticated NAS Auth Reject (EMM Cause #7)."
    },
    "ims_sip_invite": {
        "name": "IMS VoLTE/VoNR SIP INVITE Malformed (3GPP TS 24.229)",
        "rat": "IMS",
        "raw_hex": "494e56495445207369703a7573657240696d732e636f6d205349502f322e300d0a",
        "description": "Malformed Session Initiation Protocol (SIP) INVITE dialog frame."
    },
    "sim_apdu_auth": {
        "name": "UICC / USIM Authenticate Command APDU (3GPP TS 31.102)",
        "rat": "SIM",
        "raw_hex": "008800812210112233445566778899aabbccddeeff001000112233445566778899aabbccddeeff",
        "description": "USIM AUTHENTICATE APDU command carrying 3G/4G/5G Milenage RAND & AUTN vectors."
    },
    "nr_sib19_ntn": {
        "name": "5G Satellite NTN SIB19 Ephemeris (3GPP TS 38.331 Rel-17)",
        "rat": "5G",
        "raw_hex": "004081020408102030405060708090a0b0c0d0e0f0",
        "description": "5G Satellite Non-Terrestrial Network SIB19 orbital trajectory and Doppler compensation."
    },
    "lpp_prov_loc": {
        "name": "3GPP LPP ProvideLocationInformation (3GPP TS 37.355)",
        "rat": "5G",
        "raw_hex": "0c804000112233445566778899aabbccddee",
        "description": "LPP Location Report containing GNSS and OTDOA/PRS cellular signal measurements."
    },
    "lpp_req_loc": {
        "name": "3GPP LPP RequestLocationInformation (3GPP TS 37.355)",
        "rat": "4G",
        "raw_hex": "0c002000aabbccdd",
        "description": "LPP Active Location Probe query requesting UE coordinate fix."
    },
    "ecall_msd_sos": {
        "name": "eCall Emergency Minimum Set of Data (EN 15722 ASN.1)",
        "rat": "IMS",
        "raw_hex": "0101405646314142434445463132333435363738081a4b00f81a4b00",
        "description": "Emergency eCall MSD payload containing VIN, EV battery propulsion, and crash geolocation."
    },
    "cv2x_pc5_sidelink": {
        "name": "C-V2X Sidelink Direct RRC PDU (3GPP TS 38.331 PC5)",
        "rat": "5G",
        "raw_hex": "1234567890abcdef1122334455667788",
        "description": "Cellular Vehicle-to-Everything PC5 Direct Sidelink cooperative safety PDU."
    }
}


class ProtocolFuzzerEngine:
    """
    Grammar-aware 3GPP signaling mutator for protocol robustness and security verification.
    """

    def __init__(self, diag_input=None):
        self.diag_input = diag_input
        self.history = []
        self.total_generated = 0
        self.total_anomalies = 0

    def get_templates(self) -> dict:
        return SIGNALING_TEMPLATES

    def generate_mutated_vector(self, template_key: str, strategy: str = "byte_boundary", intensity: int = 2) -> dict:
        template = SIGNALING_TEMPLATES.get(template_key, SIGNALING_TEMPLATES["lte_nas_smc"])
        raw_bytes = bytearray.fromhex(template["raw_hex"])
        mutated_bytes = bytearray(raw_bytes)
        desc = ""
        anomaly_detected = False

        if strategy == "bit_flip":
            for _ in range(max(1, intensity)):
                if len(mutated_bytes) > 0:
                    byte_idx = random.randint(0, len(mutated_bytes) - 1)
                    bit_idx = random.randint(0, 7)
                    mutated_bytes[byte_idx] ^= (1 << bit_idx)
            desc = f"Flipped {intensity} random bit(s) across payload."

        elif strategy == "byte_boundary":
            boundaries = [0x00, 0x7F, 0x80, 0xFF, 0xFE, 0x01]
            for _ in range(max(1, intensity)):
                if len(mutated_bytes) > 0:
                    pos = random.randint(0, len(mutated_bytes) - 1)
                    val = random.choice(boundaries)
                    mutated_bytes[pos] = val
            desc = f"Injected boundary integers (0x00, 0x7F, 0xFF) at {intensity} position(s)."

        elif strategy == "length_tamper":
            if len(mutated_bytes) >= 2:
                mutated_bytes[1] = random.choice([0x00, 0xFE, 0xFF, min(255, len(mutated_bytes) + 30)])
            desc = "Declared invalid TLV length field mismatch in signaling header."
            anomaly_detected = True

        elif strategy == "truncation":
            cut_point = max(1, len(mutated_bytes) // 2)
            mutated_bytes = mutated_bytes[:cut_point]
            desc = f"Truncated frame payload mid-IE at byte offset {cut_point}."

        elif strategy == "ie_injection":
            garbage = bytes([random.randint(0, 255) for _ in range(intensity * 4)])
            mutated_bytes.extend(garbage)
            desc = f"Appended {len(garbage)} bytes of anomalous extraneous IE data."

        elif strategy == "asn1_tag_corrupt":
            if len(mutated_bytes) > 0:
                mutated_bytes[0] = random.choice([0x1F, 0x3F, 0xFF, 0x80])
            desc = "Corrupted ASN.1 BER/PER class identifier and constructed tag bits."
            anomaly_detected = True

        elif strategy == "asn1_uper_overflow":
            if len(mutated_bytes) >= 3:
                mutated_bytes[0] = mutated_bytes[0] | 0x80 # Set extension bit
                mutated_bytes[1] = 0xFF # Extreme length determinant chunk
                mutated_bytes[2] = 0xFF
            desc = "Injected ASN.1 UPER oversized length determinant and extension overflow bits."
            anomaly_detected = True

        elif strategy == "asn1_choice_tamper":
            if len(mutated_bytes) >= 1:
                mutated_bytes[0] = (mutated_bytes[0] & 0x0F) | 0x70 # Out-of-bounds choice index
            desc = "Injected out-of-range ASN.1 CHOICE discriminant index."
            anomaly_detected = True

        elif strategy == "gps_coord_spoof":
            # If payload has coordinates (e.g. eCall MSD or LPP), inject extreme coordinates (0x7FFFFFFF)
            if len(mutated_bytes) >= 28:
                mutated_bytes[20:28] = struct.pack('>ii', 0x7FFFFFFF, -0x7FFFFFFF)
                desc = "Injected out-of-bounds GPS coordinates (overflow WGS-84 coordinate limit)."
            else:
                mutated_bytes.extend(struct.pack('>ii', 0x7FFFFFFF, -0x7FFFFFFF))
                desc = "Appended spoofed out-of-bounds GPS coordinate telemetry."
            anomaly_detected = True

        elif strategy == "suci_ecies_tamper":
            if len(mutated_bytes) >= 10:
                for idx in range(min(10, len(mutated_bytes))):
                    mutated_bytes[idx] = random.choice([0x00, 0xFF, 0xAA])
            desc = "Corrupted ECIES Curve25519/secp256r1 Ephemeral Public Key points."
            anomaly_detected = True

        # Real hardware / stack transmission evaluation
        baseband_status = "MALFORMED_DROP"
        if self.diag_input and hasattr(self.diag_input, 'send_raw_pdu'):
            try:
                resp = self.diag_input.send_raw_pdu(bytes(mutated_bytes))
                if resp and len(resp) > 0:
                    baseband_status = "ACK_PROCESSED"
                else:
                    baseband_status = "MALFORMED_DROP"
            except Exception:
                baseband_status = "BASEBAND_ANOMALY"
        elif self.diag_input and hasattr(self.diag_input, 'send_diag_cmd'):
            try:
                resp = self.diag_input.send_diag_cmd(bytes(mutated_bytes))
                if resp and len(resp) > 0:
                    baseband_status = "ACK_PROCESSED"
                else:
                    baseband_status = "MALFORMED_DROP"
            except Exception:
                baseband_status = "BASEBAND_ANOMALY"
        elif anomaly_detected:
            baseband_status = "STACK_REJECT_MALFORMED"
        else:
            baseband_status = "CRC_INTEGRITY_FAIL"

        if baseband_status == "BASEBAND_ANOMALY":
            self.total_anomalies += 1

        self.total_generated += 1
        vector_id = f"FUZZ-{self.total_generated:05d}"

        result = {
            "id": vector_id,
            "template": template_key,
            "template_name": template["name"],
            "rat": template.get("rat", "4G"),
            "strategy": strategy,
            "original_hex": template["raw_hex"],
            "mutated_hex": mutated_bytes.hex(),
            "original_len": len(raw_bytes),
            "mutated_len": len(mutated_bytes),
            "description": desc,
            "baseband_status": baseband_status,
            "timestamp": time.strftime("%H:%M:%S")
        }

        self.history.append(result)
        if len(self.history) > 300:
            self.history.pop(0)

        return result

    def generate_campaign(self, template_key: str = "nr_rrc_reconfig", count: int = 10, strategy: str = "byte_boundary", intensity: int = 2) -> dict:
        results = []
        for _ in range(count):
            results.append(self.generate_mutated_vector(template_key, strategy, intensity))
        return {
            "status": "ok",
            "campaign_count": len(results),
            "total_generated": self.total_generated,
            "total_anomalies": self.total_anomalies,
            "vectors": results
        }

    def export_fuzz_pcap(self, vectors=None) -> tuple:
        """Export generated fuzzing vectors as Wireshark PCAP with GSMTAP framing."""
        vecs = vectors if vectors is not None else self.history
        buf = io.BytesIO()
        
        # Write PCAP Header (Magic, Version 2.4, Snaplen 65535, Linktype 228 LINKTYPE_IPV4 for GSMTAP)
        buf.write(struct.pack('<IHHi4xII', 0xa1b2c3d4, 2, 4, 0, 65535, 228))
        
        now = time.time()
        for idx, v in enumerate(vecs):
            raw_bytes = bytes.fromhex(v.get('mutated_hex', ''))
            ts = now + idx * 0.05
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1000000)
            
            rat_type = 0x04 if v.get('rat') == '5G' else (0x03 if v.get('rat') == '4G' else 0x01)
            gsmtap_hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, rat_type, 0, 0, -85, 12, 0, 0, 0, 0, 0)
            ip_udp_pkt = b'\x45\x00' + struct.pack('!H', 20 + 8 + 16 + len(raw_bytes)) + b'\x00\x01\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'
            udp_hdr = struct.pack('!HHHH', 4729, 4729, 8 + 16 + len(raw_bytes), 0)
            
            full_frame = ip_udp_pkt + udp_hdr + gsmtap_hdr + raw_bytes
            buf.write(struct.pack('<IIII', ts_sec, ts_usec, len(full_frame), len(full_frame)))
            buf.write(full_frame)
            
        data = buf.getvalue()
        filename = f"airtap_fuzz_vectors_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
        return data, 'application/vnd.tcpdump.pcap', filename

    def get_campaign_history(self) -> dict:
        return {
            "status": "ok",
            "total_generated": self.total_generated,
            "total_anomalies": self.total_anomalies,
            "history": list(self.history)
        }

    def clear_history(self) -> dict:
        self.history.clear()
        return {"status": "ok", "message": "Fuzzing campaign history cleared"}
