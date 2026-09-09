import json
import os
import re
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

import app as panel


def seed_servers():
    return [
        {'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22, 'username': 'root', 'password': 'x',
         'private_key': '', 'server_info': {}, 'uid': 'entry-uid',
         'protocols': {'awg2': {'installed': True, 'port': '55424', 'awg_params': {}, 'base_protocol': 'awg2',
                                'instance': 1, 'display_name': 'AmneziaWG 2.0', 'container_name': 'amnezia-awg2',
                                'exit_link': {'exit_uid': 'exit-uid', 'exit_name': 'Berlin-1', 'transit_ip': '10.9.0.7',
                                              'exit_public_key': 'k', 'endpoint_host': '203.0.113.5',
                                              'endpoint_port': '55520', 'obfuscation': False, 'dns_via_exit': False,
                                              'linked_at': 't', 'stale': None}}}},
        {'name': 'Berlin-1', 'host': '203.0.113.5', 'ssh_port': 22, 'username': 'root', 'password': 'x',
         'private_key': '', 'server_info': {}, 'uid': 'exit-uid',
         'protocols': {'exit': {'installed': True, 'port': '55520', 'awg_params': {}, 'subnet': '10.9.0.0/24',
                                'public_key': 'EXITPUB', 'obfuscation': False, 'base_protocol': 'exit',
                                'instance': 1, 'display_name': 'Exit Node', 'container_name': 'amnezia-exit'}}},
    ]


class ServerPageRenderTests(unittest.TestCase):
    """Render the real server page through the app (startup creates the
    default admin, the session comes from a real login) and make sure the
    exit-node markup, scripts and translations come out of Jinja intact."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': seed_servers(), 'users': [], 'user_connections': []}, f)
        # keep the background SSH monitor out of the test
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def render(self, client, path, lang='en'):
        client.cookies.set('lang', lang)
        response = client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return response.text

    def test_server_pages_render_with_exit_node_ui(self):
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)

            for sid in (0, 1):
                page = self.render(client, f'/server/{sid}')
                for marker in ('id="proto-exit"', 'id="exitLinkModal"', 'id="exitPeersModal"', 'id="exitOptions"',
                               "proto: 'exit'", 'function openExitLinkModal', 'function showExitPeers'):
                    self.assertTrue(marker in page, f'/server/{sid} lacks {marker}')
                # a missing translation renders as the raw key
                self.assertEqual(re.findall(r'>\s*exit_[a-z0-9_]+\s*<', page), [], f'/server/{sid} leaks raw keys')
                self.assertTrue('Exit node: a transit endpoint' in page, f'/server/{sid} lacks the English description')

            page = self.render(client, '/server/0', lang='ru')
            self.assertTrue('Выходная нода' in page, 'ru page lacks the Russian card text')
            i18n = json.loads(re.search(r'window\.I18N = (\{.*?\});', page).group(1))
            self.assertEqual(i18n['exit_link_saved'], 'Выходная нода привязана')
            self.assertTrue('dataset.serverUid = "entry-uid"' in page, 'own server uid not stamped on the page')

            exits = client.get('/api/exit-nodes').json()
            self.assertEqual([n['uid'] for n in exits['exit_nodes']], ['exit-uid'])


if __name__ == '__main__':
    unittest.main()
