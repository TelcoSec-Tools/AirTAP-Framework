#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Wireshark Lua Dissector Runtime & Portability Test Suite

    Guards a failure mode that file-existence checks cannot see.

    Lua resolves globals at *call* time. A dissector referencing an absent
    library (such as the Lua 5.1 'bit' / Lua 5.2 'bit32' bitwise helpers, both
    removed in the Lua 5.3+ that Wireshark 4.x embeds) therefore loads and
    registers perfectly, then raises "attempt to index a nil value" the moment a
    packet reaches the heuristic. The dissector appears installed but silently
    decodes nothing on live traffic.

    Two layers of defence:

      * Static checks (always run, no dependencies) - every dissector using
        bitwise helpers must carry the compatibility shim, declared before first
        use, and no empty accumulator table may sit at module scope.
      * Interpreter checks (run when 'lupa' is installed, skipped otherwise) -
        compile every dissector under a real Lua 5.3+ VM and execute a sample of
        them against synthetic packet bytes through tests/lua_harness/wsstub.lua.

    'lupa' is intentionally not a project dependency; the static layer is the
    portable guarantee and the interpreter layer is a local/CI bonus.
"""

import os
import re
import unittest

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "modules", "wireshark_plugin",
)
HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lua_harness", "wsstub.lua")

# bit.band(...) / bit32.rshift(...) but not rabbit.band(...) or x.bit.band(...)
BIT_CALL = re.compile(r'(?<![\w.])bit(?:32)?\.(band|bor|bxor|bnot|lshift|rshift|tobit|tohex|arshift)')
SHIM_DECL = "local bit = bit or bit32"
SHIM_MARK = "compatibility shim (AirTap)"


def lua_files():
    return sorted(f for f in os.listdir(PLUGIN_DIR) if f.endswith(".lua"))


def read(fname):
    with open(os.path.join(PLUGIN_DIR, fname), "r", encoding="utf-8", errors="replace") as fd:
        return fd.read()


class TestLuaBitwisePortability(unittest.TestCase):
    """Static guarantees - no Lua interpreter required."""

    def test_bitwise_users_carry_shim(self):
        """Every dissector calling bit.*/bit32.* must define the fallback itself.

        Wireshark loads plugin .lua files flat and in unspecified order, and the
        plugin dir is not on package.path, so a shared helper module cannot be
        required reliably. Each file therefore carries its own shim.
        """
        missing = [f for f in lua_files()
                   if BIT_CALL.search(read(f)) and SHIM_DECL not in read(f)]
        self.assertEqual(
            missing, [],
            "These dissectors call bit.*/bit32.* with no compatibility shim and "
            "will raise \"attempt to index a nil value (global 'bit')\" on the "
            "first matching packet under Wireshark 4.x (Lua 5.3+): %s" % missing,
        )

    def test_shim_declared_before_first_use(self):
        """The shim is a `local`, so it must lexically precede every use.

        A use above the declaration silently reads the (nil) global instead of
        the shim, reintroducing the exact crash the shim exists to prevent.
        """
        offenders = []
        for fname in lua_files():
            lines = read(fname).split("\n")
            decl = next((i for i, l in enumerate(lines) if l.startswith(SHIM_DECL)), None)
            uses = [i for i, l in enumerate(lines) if BIT_CALL.search(l)]
            if not uses or decl is None:
                continue
            if min(uses) < decl:
                offenders.append("%s (use at line %d, shim at line %d)"
                                 % (fname, min(uses) + 1, decl + 1))
        self.assertEqual(offenders, [], "Shim declared after first use: %s" % offenders)

    def test_shim_provides_every_operation_used(self):
        """The shim must implement each bitwise op the file actually calls."""
        gaps = []
        for fname in lua_files():
            src = read(fname)
            if SHIM_DECL not in src:
                continue
            used = set(BIT_CALL.findall(src))
            # Operations defined inside the shim table.
            provided = set(re.findall(r'^\s*(\w+)\s*=\s*function\s*\(', src, re.M))
            for op in sorted(used - provided):
                gaps.append("%s: calls bit.%s but shim does not define it" % (fname, op))
        self.assertEqual(gaps, [], "Incomplete shim: %s" % gaps)

    def test_no_bare_bit32_calls_remain(self):
        """bit32 was removed in Lua 5.3; calls must be normalised to bit.*."""
        offenders = []
        for fname in lua_files():
            for i, line in enumerate(read(fname).split("\n"), 1):
                if SHIM_DECL in line:
                    continue  # `local bit = bit or bit32` is the intended probe
                if re.search(r'(?<![\w.])bit32\.', line):
                    offenders.append("%s:%d" % (fname, i))
        self.assertEqual(offenders, [], "Direct bit32.* calls remain: %s" % offenders)


class TestSecurityHeuristicPrecision(unittest.TestCase):
    """Guards against alert heuristics that match bytes at arbitrary offsets.

    Several dissectors hex-encoded a whole PDU and substring-searched it for a
    cipher or redirection code. That is unsound twice over: the search is
    unanchored, so it matches across byte boundaries at any nibble offset, and
    it ignores field position entirely in a bit-packed ASN.1 UPER payload. A
    one-byte pattern occurs in most arbitrary PDUs by chance, so benign frames
    raised [CRITICAL] IMSI-catcher and null-cipher alerts. In an auditing tool
    a false critical is worse than a miss: it trains the operator to ignore
    real findings.

    Detection for these belongs on UPER-decoded fields, read by post-dissectors
    (lte_radio_sec.lua, nr_radio_sec.lua, telcosec_vuln_audit_engine.lua) from
    the native Wireshark dissectors.
    """

    # Patterns of 1-2 hex bytes are chance-prone; >=3 bytes are tolerated.
    SHORT_HEX = re.compile(
        r'string\.find\(\s*(?:hex_str|hex_pdu|raw_hex|raw_bytes_str)\s*,\s*"([0-9a-fA-F]{1,4})"')

    def test_no_short_hex_substring_alerts(self):
        """No dissector may drive an alert from a 1-2 byte hex substring.

        Every such site has been replaced with either a decoded-field read or
        a positional parse, so this now applies across the whole plugin set
        rather than to a carve-out list of RATs.
        """
        offenders = []
        for fname in lua_files():
            for i, line in enumerate(read(fname).split("\n"), 1):
                m = self.SHORT_HEX.search(line)
                if m:
                    offenders.append("%s:%d (pattern %r)" % (fname, i, m.group(1)))
        self.assertEqual(
            offenders, [],
            "security alerts must come from decoded fields or a positional "
            "parse, not short hex substring scans: %s" % offenders,
        )

    def test_gea_is_read_from_the_gmm_ciphering_ie(self):
        """GPRS ciphering is selected by GMM, not by LLC XID.

        3GPP TS 44.064 XID parameter types are version, IOV, T200, N200,
        N201, mD/mU, kD/kU, Layer-3 and Reset: none carries a cipher. An
        earlier revision scanned LLC frames for "0000" and reported a forced
        GEA0, an alert that could never have been correct because the field
        is not in that layer.
        """
        gmm = read("gprs_gmm_sm_sec.lua")
        self.assertIn("0x12", gmm,
                      "GMM Authentication & Ciphering Request not handled")
        self.assertIn("GEA_ALGORITHMS", gmm,
                      "no GEA algorithm table in the GMM dissector")

        llc = read("gprs_llc_sec.lua")
        self.assertNotIn(
            'string.find(hex_str, "0000")', llc,
            "LLC substring GEA scan reintroduced; GEA is not an LLC field")

    def test_bssmap_encryption_ie_is_parsed_positionally(self):
        """TS 48.008 3.2.2.10: Encryption Information is a TLV, IEI 0x0A."""
        src = read("gsm_bssmap_sec.lua")
        self.assertIn("0x0A", src, "Encryption Information IEI not referenced")
        self.assertIn("A5_ALGORITHMS", src,
                      "no permitted-algorithms bitmask table")
        self.assertNotIn('string.find(hex_str, "0101")', src,
                         "BSSMAP substring cipher scan reintroduced")

    def test_eutra_is_not_treated_as_an_lte_downgrade(self):
        """From LTE, redirect to 'eutra' is normal mobility, not an attack.

        'utra' is a substring of 'eutra', so an unanchored test flags every
        benign LTE carrier redirect as a rogue eNodeB forcing a 3G downgrade.
        """
        src = read("lte_radio_sec.lua")
        self.assertIn(
            'not redir_lc:find("eutra"', src,
            "lte_radio_sec.lua must exclude 'eutra' when testing for a UTRA "
            "(3G) downgrade, or benign LTE redirects raise false criticals",
        )
        # The bare substring form must not come back.
        self.assertNotIn(
            'string.find(redir_str:lower(), "utra")', src,
            "unanchored 'utra' test reintroduced in lte_radio_sec.lua",
        )

    def test_map_sec_has_no_unused_full_buffer_hex(self):
        """map_sec.lua computed a whole-PDU hex string it never read."""
        src = read("map_sec.lua")
        self.assertNotIn(
            "local raw_hex = tvb:bytes():tohex()", src,
            "dead full-buffer hex conversion on the MAP hot path",
        )


class TestLuaPerPacketState(unittest.TestCase):
    """Guards the hot-path optimisation against a correctness regression."""

    def test_no_empty_accumulator_at_module_scope(self):
        """Per-packet accumulators must stay inside the dissect function.

        Dissectors build findings with `local alerts = {}` then table.insert.
        Hoisting such a table to module scope (tempting, since it looks like a
        constant) makes alerts accumulate across every packet in the capture and
        fabricates findings on unrelated frames.
        """
        offenders = []
        for fname in lua_files():
            src = read(fname)
            for i, line in enumerate(src.split("\n"), 1):
                m = re.match(r'^local (\w+) = \{\s*\}\s*$', line)
                if not m:
                    continue
                name = m.group(1)
                if re.search(r'table\.insert\(\s*%s\s*,' % re.escape(name), src):
                    offenders.append("%s:%d (%s)" % (fname, i, name))
        self.assertEqual(
            offenders, [],
            "Empty tables filled via table.insert must not be module-scope; "
            "they would leak state across packets: %s" % offenders,
        )

    def test_hoisted_tables_are_constant(self):
        """Module-scope lookup tables must be literal, capturing no state."""
        offenders = []
        for fname in lua_files():
            for i, line in enumerate(read(fname).split("\n"), 1):
                m = re.match(r'^local \w+ = (\{.+\})\s*$', line)
                if not m:
                    continue
                body = re.sub(r'"[^"]*"', '', m.group(1))
                body = re.sub(r"'[^']*'", '', body)
                # A call at module scope in a lookup table implies captured state.
                if re.search(r'\w+\s*\(', body):
                    offenders.append("%s:%d" % (fname, i))
        self.assertEqual(offenders, [], "Non-constant module-scope table: %s" % offenders)


def _lua_runtime():
    """Return a lupa LuaRuntime, or None when lupa is unavailable."""
    try:
        import lupa
    except ImportError:
        return None
    return lupa.LuaRuntime(unpack_returned_tuples=True)


@unittest.skipIf(_lua_runtime() is None, "lupa not installed (pip install lupa)")
class TestLuaInterpreter(unittest.TestCase):
    """Executes dissectors under a real Lua VM via the Wireshark API stub."""

    def _fresh(self):
        rt = _lua_runtime()
        rt.globals()["STUBPATH"] = HARNESS.replace("\\", "/")
        ws = rt.eval("(loadfile(STUBPATH))()")
        captured = ws.install(rt.globals())
        return rt, ws, captured

    def test_lua_is_53_or_newer(self):
        """Confirms the VM matches Wireshark 4.x, where bit/bit32 are absent."""
        rt, _, _ = self._fresh()
        version = rt.eval("_VERSION")
        self.assertNotIn(version, ("Lua 5.1", "Lua 5.2"), "need Lua 5.3+ to be representative")
        self.assertTrue(rt.eval("bit == nil"), "test VM unexpectedly provides 'bit'")
        self.assertTrue(rt.eval("bit32 == nil"), "test VM unexpectedly provides 'bit32'")

    def test_every_dissector_compiles(self):
        rt, _, _ = self._fresh()
        errors = []
        for fname in lua_files():
            rt.globals()["SRC"] = read(fname)
            ok = rt.eval("select(1, load(SRC, 'chunk')) ~= nil")
            if not ok:
                errors.append("%s: %s" % (fname, rt.eval("select(2, load(SRC, 'chunk'))")))
        self.assertEqual(errors, [], "Lua syntax errors: %s" % errors)

    def test_every_dissector_loads_under_stub(self):
        """Executing the file body must not fault (catches module-scope errors)."""
        errors = []
        for fname in lua_files():
            rt, _, _ = self._fresh()
            rt.globals()["SRC"] = read(fname)
            try:
                rt.execute("local f, e = load(SRC, 'chunk'); if not f then error(e, 0) end; f()")
            except Exception as exc:  # noqa: BLE001 - report any load fault
                errors.append("%s: %s" % (fname, str(exc).split("\n")[0][:160]))
        self.assertEqual(errors, [], "Dissectors failed to load: %s" % errors)

    def _dissect(self, fname, payload):
        """Load one dissector and run its dissector() over payload bytes."""
        rt, ws, captured = self._fresh()
        rt.globals()["SRC"] = read(fname)
        rt.execute("local f, e = load(SRC, 'chunk'); if not f then error(e, 0) end; f()")
        proto = captured.proto
        self.assertIsNotNone(proto, "%s registered no Proto" % fname)
        fn = proto["dissector"]
        self.assertIsNotNone(fn, "%s registered no dissector function" % fname)
        rt.globals()["D"] = fn
        rt.globals()["WS"] = ws
        rt.globals()["PKT"] = payload.decode("latin-1")
        rt.execute("D(WS.tvb(PKT), WS.pinfo(), WS.tree())")
        return ws.recorded()

    def test_gsm_mm_location_updating_reject_heuristic(self):
        """The SIM-bricking heuristic must fire on LU Reject cause #3.

        This is the regression test for the bit-shim bug: pre-fix, this payload
        raised "attempt to index a nil value (global 'bit')" on the PD check and
        produced no output at all.
        """
        # PD=5 (MM) | msg 0x04 Location Updating Reject | cause 0x03 Illegal MS
        out = self._dissect("gsm_mm_sec.lua", bytes([0x05, 0x04, 0x03]))
        self.assertIn("Location Updating Reject", out)
        self.assertIn("Illegal MS", out)
        self.assertIn("CRITICAL", out)

    def test_gsm_mm_identity_request_imsi_harvest(self):
        """Plain IMSI Identity Request must be flagged as identity harvesting."""
        # PD=5 | msg 0x18 Identity Request | id type 1 = IMSI
        out = self._dissect("gsm_mm_sec.lua", bytes([0x05, 0x18, 0x01]))
        self.assertIn("IMSI", out)
        self.assertIn("CRITICAL", out)

    def test_gsm_mm_benign_message_raises_no_alert(self):
        """A normal LU Accept must not produce a CRITICAL finding."""
        # PD=5 | msg 0x02 Location Updating Accept
        out = self._dissect("gsm_mm_sec.lua", bytes([0x05, 0x02, 0x00]))
        self.assertNotIn("CRITICAL", out)

    def test_wrong_protocol_discriminator_is_ignored(self):
        """PD != 5 is not MM and must be declined without error."""
        out = self._dissect("gsm_mm_sec.lua", bytes([0x03, 0x04, 0x03]))
        self.assertNotIn("CRITICAL", out)

    def test_bitwise_dissectors_survive_truncated_frames(self):
        """Diag/serial streams deliver partial frames; parsers must not crash.

        Every shimmed dissector is driven with 0..4-byte payloads. A raised error
        here would propagate out of the real capture loop.
        """
        shimmed = [f for f in lua_files() if SHIM_MARK in read(f)]
        self.assertGreater(len(shimmed), 0, "no shimmed dissectors found to exercise")

        failures = []
        for fname in shimmed:
            for size in range(0, 5):
                payload = bytes(range(1, size + 1))
                try:
                    self._dissect(fname, payload)
                except Exception as exc:  # noqa: BLE001 - any fault is a failure
                    msg = str(exc).split("\n")[0]
                    # Stub-imposed bounds errors are artefacts of the fixture,
                    # not dissector faults: Wireshark raises these too and
                    # catches them per-packet rather than aborting the capture.
                    if "tvb out of bounds" in msg:
                        continue
                    failures.append("%s @%dB: %s" % (fname, size, msg[:120]))
        self.assertEqual(failures, [], "Crashes on truncated input: %s" % failures)


if __name__ == "__main__":
    unittest.main()
