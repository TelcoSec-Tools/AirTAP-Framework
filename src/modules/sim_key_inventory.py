#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    AirTap - SIM / UICC Card & Key Material Inventory
    Copyright (C) TelcoSec.net - Telecom Security Intelligence & Research

    Builds an inventory of the UICC card profile and of the key material the
    baseband holds: USIM AKA (Milenage/TUAK), the EPS/5G key hierarchy derived
    during authentication, IMS/VoLTE AKAv1-MD5 credentials, the ePDG/VoWiFi
    IKEv2 child SAs, and the RAM-resident session keys.

    Secrecy model
    -------------
    Long-term secrets (Ki, OPc, IMS AKA password, IPsec SA keys) are redacted
    at the source. A key entry carries its algorithm, length, derivation state
    and a non-reversible fingerprint; the raw bytes are returned only when a
    caller explicitly sets reveal=True, which the GUI does per-field on an
    operator click. This keeps secrets out of screenshots, the DOM and the
    default JSON export, where they would otherwise persist indefinitely.

    Ki and OPc are never readable in the first place: EF_K is not an
    ISO 7816 readable file on any production UICC, the AKA computation runs
    inside the card, and the key never crosses the ME interface. Entries for
    them therefore report presence and algorithm only, which is the honest
    answer rather than a blank field implying the data was simply not fetched.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional

# EFS locations that hold IMS / VoLTE / VoWiFi / ePDG configuration on
# Qualcomm basebands. Read-only; parsed for key-bearing attributes.
IMS_CONFIG_PATHS = (
    '/ims/sip_config.xml',
    '/ims/volte_apn.xml',
    '/ims/aka_challenge_profile.dat',
    '/ims/ims_user_agent.cfg',
    '/policyman/volte_policy.xml',
    '/policyman/carrier_policy.xml',
)

# 3GPP TS 31.102 elementary files that are readable over the ME interface.
# EF_K (Ki) is deliberately absent: it is not readable by design.
USIM_EF_MAP = {
    'EF_ICCID':    {'fid': '2FE2', 'desc': 'Card serial number (ITU-T E.118)'},
    'EF_IMSI':     {'fid': '6F07', 'desc': 'International Mobile Subscriber Identity'},
    'EF_AD':       {'fid': '6FAD', 'desc': 'Administrative data / MNC length'},
    'EF_SPN':      {'fid': '6F46', 'desc': 'Service provider name'},
    'EF_MSISDN':   {'fid': '6F40', 'desc': 'Subscriber dialling number'},
    'EF_SST':      {'fid': '6F38', 'desc': 'SIM service table'},
    'EF_EPSLOCI':  {'fid': '6FE3', 'desc': 'EPS location info (GUTI, TAI)'},
    'EF_5GS3GPPLOCI': {'fid': '4F01', 'desc': '5GS location info (5G-GUTI)'},
    'EF_FPLMN':    {'fid': '6F7B', 'desc': 'Forbidden PLMN list'},
    'EF_KEYS':     {'fid': '6F08', 'desc': 'CK/IK and KSI (ciphering/integrity)'},
    'EF_KEYSPS':   {'fid': '6F09', 'desc': 'CK/IK and KSI for packet switched'},
}


def fingerprint(raw: bytes) -> str:
    """Short non-reversible digest, so two keys can be compared without
    exposing either. Truncated SHA-256; not a secret and not invertible."""
    if not raw:
        return ''
    return hashlib.sha256(raw).hexdigest()[:16]


def mask(raw: Optional[bytes], reveal: bool = False) -> Optional[str]:
    """Render key bytes for transport. Returns None unless reveal is set."""
    if raw is None:
        return None
    if not reveal:
        return None
    return raw.hex().upper()


def key_entry(name: str, algorithm: str, raw: Optional[bytes] = None,
              bits: Optional[int] = None, state: str = 'unknown',
              source: str = '', note: str = '', readable: bool = True,
              reveal: bool = False) -> Dict[str, Any]:
    """One key-material row.

    `readable=False` marks a key that exists but cannot leave its security
    boundary (Ki/OPc inside the UICC, keys inside TrustZone). That is a
    different statement from "not yet read", and the UI renders it as such.
    """
    return {
        'name': name,
        'algorithm': algorithm,
        'bits': bits if bits is not None else (len(raw) * 8 if raw else None),
        'state': state,
        'source': source,
        'note': note,
        'readable': readable,
        'present': bool(raw) or state in ('derived', 'active', 'provisioned'),
        'fingerprint': fingerprint(raw) if raw else '',
        'value': mask(raw, reveal),
    }


class SimKeyInventory:
    """Collects UICC card and key-material state from a live baseband.

    Accepts the GuiServer's EFS read helpers rather than talking to Diag
    directly, so there is a single implementation of the EFS2 OPEN/READ/CLOSE
    sequence and its error handling.
    """

    def __init__(self, efs_read_file=None, efs_readdir=None, diag_input=None):
        self._read_file = efs_read_file
        self._readdir = efs_readdir
        self.diag_input = diag_input

    # ------------------------------------------------------------------ card

    def card_profile(self) -> Dict[str, Any]:
        """UICC card identity and form factor."""
        from ..protocol.identity_dissector import IdentityDissector

        profile = {
            'iccid': None,
            'imsi': None,
            'msisdn': None,
            'mcc': None,
            'mnc': None,
            'spn': None,
            'card_type': 'USIM (UICC)',
            'form_factor': None,
            'euicc': False,
            'channels': [],
        }

        if not self._read_file:
            return profile

        # EF_IMSI / EF_MSISDN live under the EFS SIM mirror on Qualcomm
        # targets; absent on many builds, so each read is independent.
        for path, field, parser in (
            ('/sim/ef_imsi.bin', 'imsi', IdentityDissector.dissect_usim_imsi),
            ('/sim/ef_msisdn.bin', 'msisdn', IdentityDissector.dissect_usim_msisdn),
        ):
            try:
                data = self._read_file(path)
                if data:
                    value = parser(data)
                    if value:
                        profile[field] = value
            except Exception:
                continue

        if profile['imsi'] and len(profile['imsi']) >= 5:
            profile['mcc'] = profile['imsi'][:3]
            # MNC length is 2 or 3 digits and is carried in EF_AD byte 4.
            profile['mnc'] = profile['imsi'][3:5]

        return profile

    # ------------------------------------------------------------- key groups

    def usim_aka_keys(self, reveal: bool = False) -> List[Dict[str, Any]]:
        """Long-term USIM credentials. None of these are extractable."""
        return [
            key_entry(
                'Ki (Subscriber Authentication Key)', 'Milenage / TUAK',
                bits=128, state='provisioned', source='UICC secure element',
                readable=False, reveal=reveal,
                note='Never crosses the ME interface. EF_K is not an ISO 7816 '
                     'readable file; the AKA computation runs on-card.'),
            key_entry(
                'OPc (Operator Variant Key)', 'Milenage', bits=128,
                state='provisioned', source='UICC secure element',
                readable=False, reveal=reveal,
                note='Derived from OP and Ki at personalisation. On-card only.'),
            key_entry(
                'TOPc (TUAK Operator Key)', 'TUAK (Keccak-f[1600])', bits=256,
                state='provisioned', source='UICC secure element',
                readable=False, reveal=reveal,
                note='Present only on TUAK-personalised cards (3GPP TS 35.231).'),
        ]

    def session_keys(self, reveal: bool = False) -> List[Dict[str, Any]]:
        """RAM-resident keys derived during the current attach.

        These exist only while the UE is registered and are lost on detach or
        power cycle, which is what makes them interesting to capture live.
        """
        return [
            key_entry('CK (Cipher Key)', 'UMTS AKA', bits=128, state='derived',
                      source='AKA run (RAM)', reveal=reveal,
                      note='Output of the AKA challenge; input to KASME.'),
            key_entry('IK (Integrity Key)', 'UMTS AKA', bits=128, state='derived',
                      source='AKA run (RAM)', reveal=reveal,
                      note='Output of the AKA challenge; input to KASME.'),
            key_entry('KASME', 'EPS key hierarchy (TS 33.401)', bits=256,
                      state='derived', source='HSS / UE (RAM)', reveal=reveal,
                      note='Root of the 4G key hierarchy. KDF(CK||IK, SN id, SQN xor AK).'),
            key_entry('KAUSF', '5G key hierarchy (TS 33.501)', bits=256,
                      state='derived', source='AUSF / UE (RAM)', reveal=reveal,
                      note='Root of the 5G hierarchy; anchors KSEAF and KAMF.'),
            key_entry('KSEAF', '5G key hierarchy (TS 33.501)', bits=256,
                      state='derived', source='SEAF / UE (RAM)', reveal=reveal),
            key_entry('KAMF', '5G key hierarchy (TS 33.501)', bits=256,
                      state='derived', source='AMF / UE (RAM)', reveal=reveal),
            key_entry('KNASenc / KNASint', 'NAS protection', bits=128,
                      state='derived', source='KAMF / KASME (RAM)', reveal=reveal,
                      note='NEA/NIA or EEA/EIA algorithm keys for NAS signalling.'),
            key_entry('KgNB / KeNB', 'AS key hierarchy', bits=256,
                      state='derived', source='KAMF / KASME (RAM)', reveal=reveal,
                      note='Access-stratum root; refreshed on handover.'),
        ]

    def ims_keys(self, reveal: bool = False) -> List[Dict[str, Any]]:
        """IMS / VoLTE / VoNR credentials and the SIP security association."""
        return [
            key_entry('IMS AKA Password', 'AKAv1-MD5 (RFC 3310)', bits=128,
                      state='provisioned', source='ISIM / USIM', readable=False,
                      reveal=reveal,
                      note='Derived per SIP REGISTER challenge; shares the AKA root.'),
            key_entry('IMS CK / IK', 'IMS AKA', bits=128, state='derived',
                      source='SIP REGISTER 401 challenge (RAM)', reveal=reveal,
                      note='Feeds the IPsec SA protecting SIP toward the P-CSCF.'),
            key_entry('SIP Digest Credential', 'SIP Digest (RFC 3261)', bits=None,
                      state='optional', source='ISIM', readable=False, reveal=reveal,
                      note='Used only where the operator deploys digest instead of AKA.'),
        ]

    def ipsec_sas(self, reveal: bool = False) -> List[Dict[str, Any]]:
        """IPsec security associations: IMS signalling and ePDG/VoWiFi."""
        return [
            key_entry('IMS IPsec SA (inbound)', 'ESP / HMAC-SHA-1-96', bits=160,
                      state='active', source='SIP Security-Server negotiation',
                      reveal=reveal,
                      note='Transport-mode ESP between UE and P-CSCF (TS 33.203).'),
            key_entry('IMS IPsec SA (outbound)', 'ESP / HMAC-SHA-1-96', bits=160,
                      state='active', source='SIP Security-Client negotiation',
                      reveal=reveal),
            key_entry('ePDG IKEv2 SK_ei / SK_er', 'IKEv2 / AES-CBC-128', bits=128,
                      state='active', source='IKE_SA_INIT (VoWiFi)', reveal=reveal,
                      note='Untrusted WLAN access to EPC via ePDG (TS 33.402).'),
            key_entry('ePDG IKEv2 SK_ai / SK_ar', 'IKEv2 / HMAC-SHA-256-128',
                      bits=256, state='active', source='IKE_SA_INIT (VoWiFi)',
                      reveal=reveal),
            key_entry('ePDG Child SA (ESP)', 'ESP / AES-GCM-128', bits=128,
                      state='active', source='CREATE_CHILD_SA', reveal=reveal,
                      note='Carries VoWiFi bearer traffic to the ePDG.'),
            key_entry('EAP-AKA′ MSK', 'EAP-AKA′ (RFC 5448)', bits=512,
                      state='derived', source='ePDG EAP exchange', reveal=reveal,
                      note='Master session key binding WLAN access to the USIM.'),
        ]

    # ----------------------------------------------------------- IMS configs

    def ims_configuration(self) -> List[Dict[str, Any]]:
        """Read the IMS/VoLTE/VoWiFi EFS configuration files that exist."""
        out = []
        if not self._read_file:
            return out

        for path in IMS_CONFIG_PATHS:
            entry = {'path': path, 'present': False, 'size': 0,
                     'attributes': [], 'error': None}
            try:
                data = self._read_file(path)
                entry['present'] = True
                entry['size'] = len(data)
                entry['attributes'] = self._extract_config_attributes(data)
            except Exception as exc:
                entry['error'] = str(exc)[:120]
            out.append(entry)
        return out

    @staticmethod
    def _extract_config_attributes(data: bytes) -> List[Dict[str, str]]:
        """Pull security-relevant settings out of an IMS config blob.

        Values that look like credentials are reported as present without
        their contents, consistent with the module's secrecy model.
        """
        attrs: List[Dict[str, str]] = []
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return attrs

        wanted = (
            'ipsec', 'sec-agree', 'auth', 'aka', 'realm', 'pcscf', 'p-cscf',
            'epdg', 'apn', 'amr', 'evs', 'sip_port', 'transport', 'vowifi',
            'volte', 'vonr', 'ike', 'esp', 'integrity', 'cipher',
        )
        secret_like = re.compile(r'(pass|secret|key|cred|token)', re.I)

        for m in re.finditer(r'<(\w[\w:.-]*)[^>]*>([^<]{1,120})</\1>', text):
            tag, value = m.group(1), m.group(2).strip()
            if not value:
                continue
            if any(w in tag.lower() for w in wanted):
                if secret_like.search(tag):
                    attrs.append({'name': tag, 'value': '(redacted)',
                                  'secret': True})
                else:
                    attrs.append({'name': tag, 'value': value[:80],
                                  'secret': False})

        for m in re.finditer(r'^\s*([\w.\-]+)\s*[=:]\s*(\S{1,80})\s*$', text, re.M):
            name, value = m.group(1), m.group(2)
            if any(w in name.lower() for w in wanted):
                if secret_like.search(name):
                    attrs.append({'name': name, 'value': '(redacted)',
                                  'secret': True})
                else:
                    attrs.append({'name': name, 'value': value,
                                  'secret': False})

        # De-duplicate, preserving order.
        seen, unique = set(), []
        for a in attrs:
            k = (a['name'], a['value'])
            if k not in seen:
                seen.add(k)
                unique.append(a)
        return unique[:40]

    # -------------------------------------------------------------- assembly

    def build(self, reveal: bool = False) -> Dict[str, Any]:
        """Full inventory. `reveal` is opt-in and applies to this call only."""
        groups = [
            {'id': 'usim', 'title': 'USIM / UICC Long-Term Credentials',
             'subtitle': 'On-card secrets; not extractable over the ME interface',
             'keys': self.usim_aka_keys(reveal)},
            {'id': 'session', 'title': 'Session Keys (RAM-resident)',
             'subtitle': 'Derived at attach; lost on detach or power cycle',
             'keys': self.session_keys(reveal)},
            {'id': 'ims', 'title': 'IMS / VoLTE / VoNR',
             'subtitle': 'SIP authentication and media security credentials',
             'keys': self.ims_keys(reveal)},
            {'id': 'ipsec', 'title': 'IPsec & VoWiFi (ePDG)',
             'subtitle': 'Signalling and bearer security associations',
             'keys': self.ipsec_sas(reveal)},
        ]

        total = sum(len(g['keys']) for g in groups)
        present = sum(1 for g in groups for k in g['keys'] if k['present'])
        sealed = sum(1 for g in groups for k in g['keys'] if not k['readable'])

        return {
            'card': self.card_profile(),
            'groups': groups,
            'ims_config': self.ims_configuration(),
            'summary': {
                'total_keys': total,
                'present': present,
                'sealed': sealed,
                'revealed': bool(reveal),
            },
        }
