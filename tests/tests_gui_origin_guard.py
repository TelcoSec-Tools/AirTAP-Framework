#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - GUI Cross-Origin Request Guard Test Suite

    The Visual Operations Suite binds to loopback and has no authentication,
    so the browser's ambient authority is the entire access-control story:
    any page the operator visits while AirTap runs can reach this server.

    Before the guard, every JSON response carried Access-Control-Allow-Origin:
    *, and no handler checked Origin, Referer or Content-Type. A hostile page
    could therefore:

      * read /api/sim/inventory, /api/efs/ls and captured signaling, because
        the wildcard made the responses readable cross-origin; and
      * POST to /api/nv/write (persistent baseband NVRAM),
        /api/terminal/diag_raw and /api/terminal/exec, because a form post of
        Content-Type: text/plain is a CORS "simple request" that browsers
        send with no preflight, and the handlers json.loads() the body without
        ever inspecting the content type.

    Both were confirmed against a live instance. These tests pin the fix and,
    just as importantly, pin that legitimate same-origin and non-browser
    access still works -- a guard that breaks the GUI would be reverted.
"""

import json
import unittest
import urllib.error
import urllib.request

PORT = 15882


def request(path, origin=None, method='GET', body=None, referer=None,
            content_type='text/plain'):
    """Issue a request and return (status, body_text)."""
    url = 'http://127.0.0.1:%d%s' % (PORT, path)
    data = body.encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if origin is not None:
        req.add_header('Origin', origin)
    if referer is not None:
        req.add_header('Referer', referer)
    if data is not None:
        req.add_header('Content-Type', content_type)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace'), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace'), dict(exc.headers)


class TestCrossOriginGuard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from src.modules.gui_server import GuiServer
        cls.server = GuiServer(diag_input=None, host='127.0.0.1', port=PORT,
                               auto_open=False)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.on_deinit()
        except Exception:
            pass

    # ------------------------------------------------------------- rejected

    def test_cross_origin_read_is_rejected(self):
        """A hostile page must not read subscriber or capture data."""
        for path in ('/api/sim/inventory', '/api/efs/ls?path=/', '/api/status',
                     '/api/identities/list'):
            status, _, _ = request(path, origin='https://evil.example')
            self.assertEqual(status, 403, '%s readable cross-origin' % path)

    def test_cross_origin_state_change_is_rejected(self):
        """The damaging POSTs must not be reachable from another site.

        text/plain is used deliberately: it is a CORS simple request, so a
        browser sends it with no preflight, and the handlers parse the body
        as JSON regardless of the declared content type.
        """
        cases = [
            ('/api/nv/write', '{"id":0,"data":"00"}'),
            ('/api/terminal/exec', '{"command":"ATI"}'),
            ('/api/terminal/diag_raw', '{"hex":"7e0000"}'),
            ('/api/devices/connect', '{"type":"adb","id":"x"}'),
        ]
        for path, body in cases:
            status, _, _ = request(path, origin='https://evil.example',
                                   method='POST', body=body)
            self.assertEqual(status, 403,
                             '%s accepted a cross-origin state change' % path)

    def test_loopback_lookalike_hostnames_are_rejected(self):
        """A hostname merely starting with the loopback IP is not loopback."""
        for origin in ('http://127.0.0.1.evil.com',
                       'http://localhost.evil.com',
                       'https://evil.com/?127.0.0.1'):
            status, _, _ = request('/api/status', origin=origin)
            self.assertEqual(status, 403, '%s was accepted' % origin)

    def test_other_local_port_is_rejected(self):
        """Another service on loopback is still a different origin."""
        status, _, _ = request('/api/status', origin='http://127.0.0.1:9999')
        self.assertEqual(status, 403)

    def test_null_origin_is_rejected(self):
        """Sandboxed iframes and some redirects send Origin: null."""
        status, _, _ = request('/api/status', origin='null')
        self.assertEqual(status, 403)

    def test_cross_origin_referer_is_rejected(self):
        """Referer is the fallback when Origin is absent."""
        status, _, _ = request('/api/status', referer='https://evil.example/x')
        self.assertEqual(status, 403)

    # ------------------------------------------------------------- permitted

    def test_same_origin_is_allowed(self):
        for origin in ('http://127.0.0.1:%d' % PORT,
                       'http://localhost:%d' % PORT):
            status, _, _ = request('/api/status', origin=origin)
            self.assertEqual(status, 200, '%s was blocked' % origin)

    def test_same_origin_post_is_allowed(self):
        status, _, _ = request('/api/terminal/exec',
                               origin='http://127.0.0.1:%d' % PORT,
                               method='POST', body='{"command":"ATI"}',
                               content_type='application/json')
        self.assertEqual(status, 200)

    def test_request_without_origin_is_allowed(self):
        """curl, scripts and direct navigation carry no ambient credentials."""
        status, _, _ = request('/api/status')
        self.assertEqual(status, 200)

    def test_same_origin_referer_is_allowed(self):
        status, _, _ = request('/api/status',
                               referer='http://127.0.0.1:%d/index.html' % PORT)
        self.assertEqual(status, 200)

    def test_index_is_served_to_direct_navigation(self):
        status, body, _ = request('/')
        self.assertEqual(status, 200)
        self.assertIn('AirTap', body)

    # --------------------------------------------------------------- headers

    def test_no_wildcard_cors_header(self):
        """A wildcard would make every response readable by any website."""
        _, _, headers = request('/api/status')
        acao = headers.get('Access-Control-Allow-Origin')
        self.assertIsNone(
            acao,
            'Access-Control-Allow-Origin: %r re-exposes the API to any site' % acao)

    def test_nosniff_header_present(self):
        _, _, headers = request('/api/status')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')

    def test_rejection_body_is_json(self):
        """The GUI's fetch handlers expect JSON even on failure."""
        status, body, _ = request('/api/status', origin='https://evil.example')
        self.assertEqual(status, 403)
        payload = json.loads(body)
        self.assertEqual(payload['status'], 'error')
        self.assertIn('Cross-origin', payload['error'])


if __name__ == '__main__':
    unittest.main()
