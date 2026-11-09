"""Panel access control: IP allowlist and domain-only mode.

Both are global settings rendered as checkboxes on the settings page and
enforced by a middleware that runs before auth, templates and static files.
Loopback always stays reachable so an admin can recover over an SSH tunnel;
the managed fleet hosts are allowed implicitly.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class IpMatchingTests(unittest.TestCase):
    def test_single_address_matches_itself_only(self):
        self.assertTrue(panel._ip_allowed('203.0.113.7', ['203.0.113.7']))
        self.assertFalse(panel._ip_allowed('203.0.113.8', ['203.0.113.7']))

    def test_cidr_matches_the_whole_range(self):
        self.assertTrue(panel._ip_allowed('203.0.113.200', ['203.0.113.0/24']))
        self.assertFalse(panel._ip_allowed('203.0.114.1', ['203.0.113.0/24']))

    def test_families_do_not_cross(self):
        self.assertFalse(panel._ip_allowed('2001:db8::1', ['203.0.113.0/24']))
        self.assertTrue(panel._ip_allowed('2001:db8::1', ['2001:db8::/32']))

    def test_garbage_is_ignored_not_raised(self):
        self.assertFalse(panel._ip_allowed('203.0.113.7', ['not-an-ip', '']))
        self.assertFalse(panel._ip_allowed('garbage', ['203.0.113.0/24']))

    def test_loopback_detection(self):
        self.assertTrue(panel._is_loopback_ip('127.0.0.1'))
        self.assertTrue(panel._is_loopback_ip('::1'))
        self.assertFalse(panel._is_loopback_ip('203.0.113.7'))


class HostHeaderTests(unittest.TestCase):
    def test_strips_port(self):
        self.assertEqual(panel._host_header_name('panel.example.com:5000'), 'panel.example.com')

    def test_bracketed_ipv6_keeps_the_address(self):
        self.assertEqual(panel._host_header_name('[2001:db8::1]:5000'), '2001:db8::1')

    def test_empty_is_empty(self):
        self.assertEqual(panel._host_header_name(''), '')


class AccessMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [{'host': '198.51.100.5', 'name': 'fleet'}],
                       'users': [], 'user_connections': []}, f)
        self._access = dict(panel._PANEL_ACCESS)

    def tearDown(self):
        panel._PANEL_ACCESS.clear()
        panel._PANEL_ACCESS.update(self._access)
        panel.DATA_FILE = self._data_file
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _client(self, **access):
        """Enter the client (the startup event refreshes the access cache from
        data.json), then apply the scenario on top of the fresh cache."""
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        if access:
            panel._PANEL_ACCESS.update(access)
        return client

    def test_disabled_lets_everyone_through(self):
        self.assertEqual(self._client(ip_allowlist_enabled=False,
                                      domain_only=False).get('/login').status_code, 200)

    def test_enabled_allowlist_blocks_unknown_ip(self):
        res = self._client(ip_allowlist_enabled=True,
                           ip_allowlist=['203.0.113.7'],
                           domain_only=False).get('/login')
        self.assertEqual(res.status_code, 404)
        # A denied caller must not learn that a panel lives here.
        self.assertIn('404 Not Found', res.text)
        self.assertNotIn('panel', res.text.lower())

    def test_fleet_host_is_allowed_implicitly(self):
        client = TestClient(panel.app, client=("203.0.113.9", 50000))
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        panel._PANEL_ACCESS.update({'ip_allowlist_enabled': True,
                                    'ip_allowlist': [],
                                    'domain_only': False,
                                    'fleet_ips': ['203.0.113.9']})
        self.assertEqual(client.get('/login').status_code, 200)

    def test_unknown_ip_is_blocked_even_with_a_fleet_list(self):
        client = TestClient(panel.app, client=("203.0.113.9", 50000))
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        panel._PANEL_ACCESS.update({'ip_allowlist_enabled': True,
                                    'ip_allowlist': [],
                                    'domain_only': False,
                                    'fleet_ips': ['198.51.100.5']})
        self.assertEqual(client.get('/login').status_code, 404)

    def test_domain_only_blocks_ip_host(self):
        res = self._client(ip_allowlist_enabled=False,
                           domain_only=True,
                           allowed_domain='panel.example.com').get(
                               '/login', headers={'host': '203.0.113.7'})
        self.assertEqual(res.status_code, 404)
        self.assertIn('404 Not Found', res.text)
        self.assertNotIn('panel', res.text.lower())

    def test_domain_only_allows_the_domain(self):
        res = self._client(ip_allowlist_enabled=False,
                           domain_only=True,
                           allowed_domain='panel.example.com').get(
                               '/login', headers={'host': 'panel.example.com'})
        self.assertEqual(res.status_code, 200)

    def test_refresh_reads_settings_and_servers(self):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [{'host': '198.51.100.5'}],
                       'settings': {'panel_access': {
                           'ip_allowlist_enabled': True,
                           'ip_allowlist': ['203.0.113.0/24'],
                           'domain_only': True,
                           'allowed_domain': 'Panel.Example.com'}},
                       'users': [], 'user_connections': []}, f)
        panel._refresh_panel_access()
        self.assertTrue(panel._PANEL_ACCESS['ip_allowlist_enabled'])
        self.assertTrue(panel._PANEL_ACCESS['domain_only'])
        self.assertEqual(panel._PANEL_ACCESS['allowed_domain'], 'panel.example.com')
        self.assertIn('198.51.100.5', panel._PANEL_ACCESS['fleet_ips'])


class FrontResponseTests(unittest.TestCase):
    def test_front_body_matches_the_app_denial_body(self):
        import panel_front
        self.assertEqual(panel_front.NOT_FOUND_BODY, panel._PANEL_NOT_FOUND_BODY)

    def test_stock_response_shape(self):
        import panel_front
        raw = panel_front.not_found_response()
        self.assertTrue(raw.startswith(b'HTTP/1.1 404 Not Found\r\n'))
        self.assertIn(b'Server: nginx\r\n', raw)
        self.assertIn(b'Content-Length: ' + str(len(panel_front.NOT_FOUND_BODY)).encode(), raw)
        self.assertTrue(raw.endswith(panel_front.NOT_FOUND_BODY))

    def test_tls_detection(self):
        import panel_front
        self.assertTrue(panel_front._looks_like_tls(b'\x16\x03\x01\x02\x00'))
        self.assertFalse(panel_front._looks_like_tls(b'GET / HTTP/1.1\r\n'))
        self.assertFalse(panel_front._looks_like_tls(b''))

    def test_plain_http_gets_the_stock_404_over_a_live_socket(self):
        import socket
        import threading
        import time
        import panel_front
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        threading.Thread(
            target=panel_front.serve,
            kwargs={'host': '127.0.0.1', 'port': port, 'backend': ('127.0.0.1', 1)},
            daemon=True).start()
        sock = None
        for _ in range(100):
            try:
                sock = socket.create_connection(('127.0.0.1', port), timeout=1)
                break
            except OSError:
                time.sleep(0.05)
        self.assertIsNotNone(sock, 'front did not start')
        sock.sendall(b'GET / HTTP/1.1\r\nHost: example\r\n\r\n')
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        self.assertTrue(data.startswith(b'HTTP/1.1 404 Not Found'), data[:80])
        self.assertIn(b'Server: nginx', data)
        self.assertNotIn(b'panel', data.lower())


if __name__ == '__main__':
    unittest.main()
