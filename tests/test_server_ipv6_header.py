"""The server page header shows the box's global IPv6 addresses when it has any.

The /stats endpoint collects them with `ip -6 addr show scope global` (ULA and
link-local stay excluded), and the page renders a second mono line under
`host:port • user` only when the list is non-empty.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


def server_with():
    return {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22, 'username': 'root',
            'password': 'x', 'private_key': '', 'server_info': {}, 'uid': 'srv-uid',
            'protocols': {}}


class ServerStatsIpv6Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [server_with()], 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)
        return client

    def _ssh_returning(self, ipv6_output):
        ssh = mock.Mock()

        def run_command(cmd, *args, **kwargs):
            if 'ip -6 addr' in cmd:
                # the remote awk filters ULA (fd00::/8) and transit /126
                # prefixes, and strips /prefix
                kept = []
                for line in ipv6_output.splitlines():
                    addr, _, plen = line.partition('/')
                    if addr.startswith('fd') or (plen and int(plen) > 64):
                        continue
                    kept.append(addr)
                return '\n'.join(kept) + ('\n' if kept else ''), '', 0
            return '0', '', 0

        ssh.run_command.side_effect = run_command
        return ssh

    def test_global_addresses_come_back_as_a_list(self):
        out = ('2a01:f500:aaa0:2800::a/56\n2a0c:5d00:3001::afc5:c09a/48\n'
               'fd00:42::1/64\n2a01:f500:aaaa:fe00::1:2002/126\n')
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', return_value=self._ssh_returning(out)):
            res = client.post('/api/servers/0/stats')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['ipv6'], ['2a01:f500:aaa0:2800::a', '2a0c:5d00:3001::afc5:c09a'])

    def test_no_global_address_means_an_empty_list(self):
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', return_value=self._ssh_returning('')):
            res = client.post('/api/servers/0/stats')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['ipv6'], [])

    def test_page_has_the_header_line_and_renders_it_only_with_data(self):
        page = open(os.path.join(os.path.dirname(panel.__file__),
                                 'templates', 'server.html'), encoding='utf-8').read()
        self.assertIn('id="serverIpv6"', page)
        self.assertIn("Array.isArray(stats.ipv6)", page)
        self.assertIn("ipv6.join(' • ')", page)
        self.assertIn("ipv6El.style.display = 'none'", page)


if __name__ == '__main__':
    unittest.main()
