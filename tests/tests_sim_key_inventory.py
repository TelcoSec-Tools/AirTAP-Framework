#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - SIM / UICC Card & Key Material Inventory Test Suite

    Covers the inventory builder and its two API endpoints, with emphasis on
    the secrecy model: a regression that leaks key bytes into a default
    response or an export is silent and permanent, since the artefact outlives
    the session that produced it.
"""

import json
import unittest
import urllib.request

from src.modules.sim_key_inventory import (
    SimKeyInventory,
    USIM_EF_MAP,
    fingerprint,
    key_entry,
    mask,
)


class TestKeyEntryRedaction(unittest.TestCase):
    """Key bytes must never appear unless explicitly revealed."""

    SECRET = bytes(range(16))

    def test_value_hidden_by_default(self):
        entry = key_entry('K', 'Milenage', raw=self.SECRET)
        self.assertIsNone(entry['value'],
                          'key bytes present in a non-revealed entry')

    def test_value_present_when_revealed(self):
        entry = key_entry('K', 'Milenage', raw=self.SECRET, reveal=True)
        self.assertEqual(entry['value'], self.SECRET.hex().upper())

    def test_mask_returns_none_without_reveal(self):
        self.assertIsNone(mask(self.SECRET))
        self.assertIsNone(mask(None, reveal=True))

    def test_fingerprint_is_not_reversible(self):
        fp = fingerprint(self.SECRET)
        self.assertEqual(len(fp), 16)
        self.assertNotIn(self.SECRET.hex(), fp)
        # Same input -> same fingerprint; different input -> different.
        self.assertEqual(fp, fingerprint(self.SECRET))
        self.assertNotEqual(fp, fingerprint(self.SECRET + b'\x01'))

    def test_bits_inferred_from_raw_length(self):
        self.assertEqual(key_entry('K', 'X', raw=self.SECRET)['bits'], 128)

    def test_explicit_bits_win_over_inference(self):
        entry = key_entry('K', 'X', raw=self.SECRET, bits=256)
        self.assertEqual(entry['bits'], 256)


class TestInventoryStructure(unittest.TestCase):

    def setUp(self):
        self.inv = SimKeyInventory()
        self.data = self.inv.build()

    def test_all_groups_present(self):
        ids = {g['id'] for g in self.data['groups']}
        self.assertEqual(ids, {'usim', 'session', 'ims', 'ipsec'})

    def test_every_key_has_required_fields(self):
        required = {'name', 'algorithm', 'state', 'readable', 'present',
                    'value', 'fingerprint'}
        for group in self.data['groups']:
            for k in group['keys']:
                missing = required - set(k)
                self.assertEqual(missing, set(),
                                 '%s missing %s' % (k.get('name'), missing))

    def test_summary_counts_match_groups(self):
        keys = [k for g in self.data['groups'] for k in g['keys']]
        self.assertEqual(self.data['summary']['total_keys'], len(keys))
        self.assertEqual(self.data['summary']['sealed'],
                         sum(1 for k in keys if not k['readable']))

    def test_long_term_credentials_are_sealed(self):
        """Ki/OPc/TOPc never leave the UICC, so they must be marked sealed.

        Reporting them as merely "not read" would imply a later read could
        succeed, which is false: the AKA computation runs on-card and EF_K is
        not an ISO 7816 readable file.
        """
        usim = next(g for g in self.data['groups'] if g['id'] == 'usim')
        for k in usim['keys']:
            self.assertFalse(k['readable'],
                             '%s must be marked non-extractable' % k['name'])
            self.assertIsNone(k['value'])

    def test_sealed_keys_stay_sealed_when_revealed(self):
        """reveal=True must not expose on-card secrets."""
        revealed = SimKeyInventory().build(reveal=True)
        for group in revealed['groups']:
            for k in group['keys']:
                if not k['readable']:
                    self.assertIsNone(
                        k['value'],
                        '%s leaked bytes under reveal=True' % k['name'])

    def test_requested_key_classes_are_covered(self):
        """The tab must cover IPsec, VoLTE/IMS and VoWiFi/ePDG material."""
        names = ' '.join(k['name'] + ' ' + (k['source'] or '')
                         for g in self.data['groups'] for k in g['keys']).lower()
        for term in ('ipsec', 'ims', 'epdg', 'ikev2', 'eap-aka', 'kasme',
                     'kausf', 'ck', 'ik'):
            self.assertIn(term, names, 'no key material covering %r' % term)

    def test_build_without_device_does_not_raise(self):
        """No EFS readers supplied: card/config degrade, keys still describe."""
        self.assertIsInstance(self.data['card'], dict)
        self.assertEqual(self.data['ims_config'], [])


class TestConfigAttributeExtraction(unittest.TestCase):
    """IMS config parsing must redact credentials but keep diagnostics."""

    def test_secret_attributes_are_redacted(self):
        blob = b'<ipsec_auth_key>deadbeef</ipsec_auth_key><pcscf_addr>10.1.2.3</pcscf_addr>'
        attrs = SimKeyInventory._extract_config_attributes(blob)
        by_name = {a['name']: a for a in attrs}
        self.assertEqual(by_name['ipsec_auth_key']['value'], '(redacted)')
        self.assertTrue(by_name['ipsec_auth_key']['secret'])
        self.assertEqual(by_name['pcscf_addr']['value'], '10.1.2.3')
        self.assertFalse(by_name['pcscf_addr']['secret'])

    def test_secret_value_never_appears_in_output(self):
        blob = b'<ims_password>SUPERSECRET123</ims_password>'
        attrs = SimKeyInventory._extract_config_attributes(blob)
        self.assertNotIn('SUPERSECRET123', json.dumps(attrs))

    def test_key_value_syntax_is_parsed(self):
        blob = b'epdg_fqdn = epdg.example.net\nvolte_enabled: 1\n'
        names = {a['name'] for a in SimKeyInventory._extract_config_attributes(blob)}
        self.assertIn('epdg_fqdn', names)
        self.assertIn('volte_enabled', names)

    def test_malformed_input_does_not_raise(self):
        for blob in (b'', b'\xff\xfe\x00binary', b'<unclosed', b'=' * 400):
            self.assertIsInstance(
                SimKeyInventory._extract_config_attributes(blob), list)

    def test_duplicate_attributes_are_collapsed(self):
        blob = b'<pcscf_addr>1.1.1.1</pcscf_addr><pcscf_addr>1.1.1.1</pcscf_addr>'
        attrs = SimKeyInventory._extract_config_attributes(blob)
        self.assertEqual(len(attrs), 1)


class TestInventoryWithEfsReader(unittest.TestCase):
    """Card profile parsing against a stub EFS."""

    def test_imsi_is_decoded_from_ef(self):
        # EF_IMSI (TS 31.102 4.2.2): length byte then parity/BCD digits.
        ef_imsi = bytes([0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98])

        def reader(path):
            if path == '/sim/ef_imsi.bin':
                return ef_imsi
            raise IOError('absent')

        card = SimKeyInventory(efs_read_file=reader).card_profile()
        self.assertTrue(card['imsi'], 'EF_IMSI was not decoded')
        self.assertEqual(card['mcc'], card['imsi'][:3])

    def test_unreadable_efs_degrades_quietly(self):
        def reader(path):
            raise IOError('EFS read failed')

        card = SimKeyInventory(efs_read_file=reader).card_profile()
        self.assertIsNone(card['imsi'])

    def test_ims_config_records_unreadable_paths(self):
        def reader(path):
            raise IOError('no such file')

        items = SimKeyInventory(efs_read_file=reader).ims_configuration()
        self.assertTrue(items)
        self.assertTrue(all(not i['present'] for i in items))
        self.assertTrue(all(i['error'] for i in items))


class TestSimApiEndpoints(unittest.TestCase):
    """End-to-end over HTTP, including the reveal query parameter."""

    @classmethod
    def setUpClass(cls):
        from src.modules.gui_server import GuiServer
        # diag_input=None exercises the offline path; the constructor binds the
        # listener, while on_init() is the Diag handshake and is not called.
        cls.server = GuiServer(diag_input=None, host='127.0.0.1',
                               port=15881, auto_open=False)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.on_deinit()
        except Exception:
            pass

    def _get(self, path):
        url = 'http://127.0.0.1:%d%s' % (self.server.port, path)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def test_inventory_endpoint(self):
        data = self._get('/api/sim/inventory')
        self.assertIn(data['status'], ('ok', 'offline'))
        self.assertIn('groups', data)
        self.assertIn('summary', data)
        self.assertGreater(data['summary']['total_keys'], 0)

    def test_inventory_hides_values_by_default(self):
        data = self._get('/api/sim/inventory')
        self.assertFalse(data['summary']['revealed'])
        for g in data['groups']:
            for k in g['keys']:
                self.assertIsNone(k['value'],
                                  '%s exposed without reveal' % k['name'])

    def test_reveal_flag_is_honoured(self):
        data = self._get('/api/sim/inventory?reveal=1')
        self.assertTrue(data['summary']['revealed'])
        # Sealed keys stay sealed regardless of the flag.
        for g in data['groups']:
            for k in g['keys']:
                if not k['readable']:
                    self.assertIsNone(k['value'])

    def test_ef_endpoint_lists_known_files(self):
        data = self._get('/api/sim/efs')
        self.assertEqual(data['count'], len(USIM_EF_MAP))
        names = {f['name'] for f in data['files']}
        self.assertIn('EF_IMSI', names)
        self.assertIn('EF_ICCID', names)

    def test_ef_k_is_not_offered_as_readable(self):
        """EF_K holds Ki and is not readable; listing it would mislead."""
        data = self._get('/api/sim/efs')
        self.assertNotIn('EF_K', {f['name'] for f in data['files']})


if __name__ == '__main__':
    unittest.main()
