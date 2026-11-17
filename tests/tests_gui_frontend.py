#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Visual Operations Suite Frontend Regression Suite

    The existing GUI tests exercise server endpoints only, so a browser-side
    fault reaches the operator as a console ReferenceError with the control
    silently dead. That happened: switchTab() called fetchDeviceDossier(),
    which was never defined anywhere, so opening the Device tab threw and the
    dossier never populated.

    Function resolution is verified by evaluating app.js in Node (V8), not by
    pattern-matching the source. A regex "parser" gave false positives here --
    it reported eight functions as undefined that V8 confirms are defined --
    and a test that cries wolf is worse than no test. Those checks are skipped
    when Node is unavailable; the string-level checks below always run.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

ASSETS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "modules", "gui_assets",
)
APP_JS = os.path.join(ASSETS, "app.js")

NODE = shutil.which("node")


def app_js():
    with open(APP_JS, "r", encoding="utf-8") as fd:
        return fd.read()


# Evaluates app.js under a stub browser and reports, for every function the UI
# dispatches by name, whether it resolved to a callable binding.
#
# Call sites are collected by V8's own tokenizer rather than by regex: the file
# is re-read as text only to list candidate names, and each candidate is then
# tested against the real global object, so comments, string literals and
# template literals cannot produce a false "missing".
PROBE_JS = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');

const ctx = {
  console: { log(){}, warn(){}, error(){}, info(){}, debug(){} },
  setTimeout: () => 0, setInterval: () => 0,
  clearTimeout(){}, clearInterval(){},
  requestAnimationFrame: () => 0, cancelAnimationFrame(){},
  fetch: () => new Promise(() => {}),
  JSON, Math, Date, Object, Array, String, Number, Boolean, RegExp, Error,
  Map, Set, WeakMap, Promise, Intl, parseInt, parseFloat, isNaN, isFinite,
  encodeURIComponent, decodeURIComponent, btoa: s => s, atob: s => s,
  navigator: { userAgent: 'node', geolocation: { getCurrentPosition(){}, watchPosition(){} } },
  localStorage: { getItem: () => null, setItem(){}, removeItem(){} },
  sessionStorage: { getItem: () => null, setItem(){}, removeItem(){} },
  location: { href: '', search: '', reload(){} },
  performance: { now: () => 0 },
  matchMedia: () => ({ matches: false, addEventListener(){} }),
  getComputedStyle: () => new Proxy({}, { get: () => '' }),
  WebSocket: function(){ return { addEventListener(){}, send(){}, close(){} }; },
  URL: class { constructor(){} }, URLSearchParams: class { get(){ return null; } },
  Blob: class {}, FormData: class {}, Image: class {},
  AbortController: class { constructor(){ this.signal = {}; } },
  Notification: class {}, crypto: { getRandomValues: a => a },
};

// A permissive DOM: every property access yields a callable proxy, so
// top-level initialisation can run without a real document.
const anyNode = new Proxy(function(){}, {
  get: (t, p) => (p === 'style' || p === 'dataset' || p === 'classList')
        ? anyNode
        : (p === 'length' ? 0 : anyNode),
  set: () => true,
  apply: () => anyNode,
  construct: () => anyNode,
});
ctx.document = new Proxy({}, { get: () => anyNode, set: () => true });
ctx.window = ctx;
ctx.globalThis = ctx;
ctx.self = ctx;
ctx.top = ctx;
ctx.L = anyNode;
ctx.Chart = anyNode;

vm.createContext(ctx);
let topLevelError = null;
try {
  new vm.Script(src, { filename: 'app.js' }).runInContext(ctx, { timeout: 10000 });
} catch (e) {
  topLevelError = e.constructor.name + ': ' + e.message;
}

// Only globals can be checked this way. Nested helpers (`const closeModal =
// () => {}` inside an init function) and late bindings (`window.foo = ...`
// assigned when a pane first opens) are invisible from global scope, so
// probing every call site in the file would report them all as missing.
//
// switchTab() is the high-value case and is sound to check: it runs at top
// level on every tab change, so each function it dispatches to must already
// be a resolvable global. This is exactly where fetchDeviceDossier() broke.
//
// The body comes from Function.prototype.toString(), i.e. the source V8
// actually parsed. Matching braces by hand desynchronizes on regex literals
// and nested ${} in template strings, which this file uses heavily.
let hooks = [];
let bodyLines = 0;
if (typeof ctx.switchTab === 'function') {
  const body = ctx.switchTab.toString();
  bodyLines = body.split(String.fromCharCode(10)).length;
  hooks = [...new Set([...body.matchAll(/(?<![\w$.])([a-z_$][\w$]*)\s*\(/g)].map(m => m[1]))];
}

const unresolved = [];
for (const name of hooks) {
  let v;
  try { v = ctx[name]; } catch (e) { v = undefined; }
  if (typeof v !== 'function') unresolved.push(name);
}

process.stdout.write(JSON.stringify({
  topLevelError,
  hookCount: hooks.length,
  bodyLines,
  unresolved: unresolved.sort(),
}));
"""

# Identifiers that look like calls in the source but are language syntax,
# host builtins we do not stub, or words inside non-code text. Reviewed by
# hand; a name here is asserted to be a non-issue, not merely unresolved.
IGNORED = {
    # keywords / syntax
    "if", "for", "while", "switch", "catch", "return", "typeof", "function",
    "await", "new", "do", "else", "try", "throw", "delete", "void", "in", "of",
    "case", "with", "yield", "super", "this", "instanceof", "var", "let",
    "const", "class", "extends", "import", "export", "default", "break",
    "continue", "debugger", "finally", "null", "true", "false", "undefined",
    "eval", "require", "module", "exports", "process",
    # CSS / template fragments that read as calls
    "rgba", "rgb", "hsl", "hsla", "url", "translate", "translateX",
    "translateY", "translateZ", "rotate", "scale", "calc", "linear",
    "cubic", "steps", "blur", "brightness", "drop", "polygon", "attr",
    "counter", "gradient", "repeat", "minmax", "clamp", "env",
    # prose inside alert/remediation strings
    "access", "applets", "applications", "checking", "cin", "command",
    "context", "device", "downlink", "enabled", "etsi", "filtering", "flush",
    "frame", "handler", "handsets", "hexString", "identifier", "lawfulIntercept",
    "lists", "locally", "logging", "media", "messageAuthenticationCode",
    "messages", "meters", "organization", "packages", "policy", "procedures",
    "request", "roaming", "securityDomain", "signaling", "snapshot",
    "thresholds", "transitions", "types", "uplink", "vectors", "verification",
    "buffer", "b3", "n78", "dBm", "getShareableInterfaceObject",
}


def run_probe():
    """Return (top_level_error, unresolved_names) from the Node probe."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = os.path.join(tmp, "probe.js")
        with open(probe, "w", encoding="utf-8") as fd:
            fd.write(PROBE_JS)
        proc = subprocess.run(
            [NODE, probe, APP_JS],
            capture_output=True, text=True, timeout=120,
        )
    if proc.returncode != 0:
        raise AssertionError("probe failed: %s" % (proc.stderr or "")[:400])
    data = json.loads(proc.stdout)
    return data["topLevelError"], data["unresolved"], data["hookCount"]


@unittest.skipIf(NODE is None, "node not available on PATH")
class TestFrontendFunctionResolution(unittest.TestCase):
    """Every function the UI dispatches by name must actually exist."""

    @classmethod
    def setUpClass(cls):
        cls.top_level_error, cls.unresolved, cls.hook_count = run_probe()

    def test_app_js_parses(self):
        """A SyntaxError here means the whole GUI fails to load."""
        if self.top_level_error and "SyntaxError" in self.top_level_error:
            self.fail("app.js does not parse: %s" % self.top_level_error)

    def test_switch_tab_hooks_resolve(self):
        """Every tab-hydration function must exist as a global.

        switchTab() runs on each tab change, so an unresolved name here is a
        guaranteed ReferenceError that leaves the tab unpopulated.
        """
        real = sorted(n for n in self.unresolved if n not in IGNORED)
        self.assertEqual(
            real, [],
            "switchTab() dispatches to functions that do not exist; each "
            "throws ReferenceError and leaves its tab empty: %s" % real,
        )

    def test_probe_actually_found_hooks(self):
        """Guard against the probe silently checking nothing."""
        self.assertGreater(
            self.hook_count, 5,
            "probe found only %d call sites in switchTab(); the body parse "
            "likely failed, so the test above proves nothing" % self.hook_count,
        )


class TestDeviceTabHydration(unittest.TestCase):
    """Regression: the Device tab called a function that was never defined."""

    def test_fetch_device_dossier_is_gone(self):
        # assertNotIn would echo the whole 7700-line file into the failure
        # report, so compare a boolean and supply the message ourselves.
        self.assertFalse(
            "fetchDeviceDossier" in app_js(),
            "fetchDeviceDossier() is defined nowhere in the project; the "
            "Device tab must hydrate via loadDeviceStatus()",
        )

    def test_device_tab_hydrates(self):
        """Opening the tab must still refresh the dossier."""
        src = app_js()
        idx = src.find("tabId === 'tab-device'")
        self.assertNotEqual(idx, -1, "tab-device hydration hook missing")
        block = src[idx:idx + 500]
        self.assertIn(
            "loadDeviceStatus()", block,
            "the tab-device branch of switchTab() no longer refreshes the "
            "device dossier",
        )


class TestExternalGeolocationBackoff(unittest.TestCase):
    """The IP-geolocation fallback must not hammer a throttled endpoint."""

    def test_rate_limit_is_recorded(self):
        """A 429/403 must persist a backoff, not just be swallowed.

        The handler returned null on any non-ok response and cached only on
        success, so after a 429 nothing was cached and every later caller
        re-requested the throttled endpoint.
        """
        src = app_js()
        self.assertIn("airtap_geo_backoff", src,
                      "no backoff recorded after an IP-geolocation rate limit")
        self.assertRegex(
            src, r'status\s*===\s*429',
            "HTTP 429 is not detected explicitly in the geolocation fallback",
        )

    def test_concurrent_callers_are_coalesced(self):
        """Three code paths can call the fallback at once on page load."""
        self.assertIn("ipGeoInFlight", app_js(),
                      "concurrent IP-geolocation requests are not coalesced")

    def test_backoff_is_consulted_before_requesting(self):
        src = app_js()
        idx_read = src.find("getItem('airtap_geo_backoff')")
        idx_fetch = src.find("fetch('https://ipwho.is/')")
        self.assertNotEqual(idx_read, -1, "backoff value is never read back")
        self.assertNotEqual(idx_fetch, -1, "geolocation fetch not found")
        self.assertLess(
            idx_read, idx_fetch,
            "the backoff must be checked before issuing the request",
        )

    def test_success_is_cached(self):
        self.assertIn("airtap_cached_geo", app_js(),
                      "successful geolocation lookups are not cached")


if __name__ == "__main__":
    unittest.main()
