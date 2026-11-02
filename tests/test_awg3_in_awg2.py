import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers.awg_manager import AWGManager
from tests.test_awg_config_cache import CONFIG_PATH, SERVER_CONFIG, FakeSSH


# What the official Amnezia client leaves in amnezia-awg2 when it installs
# AWG 3.x: the same container name, only the 3.x keys in the config.
AWG3_SERVER_CONFIG = SERVER_CONFIG.replace(
    'H4 = 2528465083\n',
    'H4 = 2528465083\nHeaderProtectionKey = HPKEY\nContentPaddingAddition = 16\n',
)


def status_for(config):
    manager = AWGManager(FakeSSH({CONFIG_PATH: config}))
    with mock.patch.object(manager, 'check_protocol_installed', return_value=True), \
            mock.patch.object(manager, 'check_container_running', return_value=True):
        return manager.get_server_status('awg2')


class HeaderProtectionStatusTests(unittest.TestCase):
    def test_minor_version_requires_31_parameters(self):
        self.assertEqual(status_for(AWG3_SERVER_CONFIG)['protocol_version'], '3.x')
        self.assertEqual(status_for(SERVER_CONFIG)['protocol_version'], '2.0')
        for key in ('RandomTrailers', 'DisableCookies'):
            for value in ('on', 'off'):
                with self.subTest(key=key, value=value):
                    config = AWG3_SERVER_CONFIG.replace('[Peer]', f'{key} = {value}\n\n[Peer]', 1)
                    self.assertEqual(status_for(config)['protocol_version'], '3.1')

    def test_awg3_config_in_awg2_container_is_flagged(self):
        self.assertTrue(status_for(AWG3_SERVER_CONFIG)['header_protection'])

    def test_plain_awg2_config_is_not_flagged(self):
        self.assertFalse(status_for(SERVER_CONFIG)['header_protection'])


class NamingTests(unittest.TestCase):
    def test_31_names_use_detected_version_not_container_name(self):
        self.assertEqual(panel.protocol_display_name('awg2', True, '3.1'), 'AmneziaWG 3.1 (amnezia-awg2)')
        self.assertEqual(panel.protocol_display_name('awg2__2', True, '3.1'), 'AmneziaWG 3.1 (amnezia-awg2) #2')
        self.assertEqual(panel.protocol_short_name('awg2', True, '3.1'), 'AWG3.1')
        self.assertEqual(panel.protocol_short_name('awg2__2', True, '3.1'), 'AWG3.1#2')
        server = {'name': 'node', 'protocols': {'awg2': {'header_protection': True, 'protocol_version': '3.1'}}}
        self.assertEqual(panel.connection_display_name(server, 'awg2'), 'node AWG3.1')

    def test_display_name(self):
        self.assertEqual(panel.protocol_display_name('awg2'), 'AmneziaWG 2.0')
        self.assertEqual(panel.protocol_display_name('awg2', True), 'AmneziaWG 3.x (amnezia-awg2)')
        self.assertEqual(panel.protocol_display_name('awg2__2', True), 'AmneziaWG 3.x (amnezia-awg2) #2')
        # the flag only means something for the amnezia-awg2 container
        self.assertEqual(panel.protocol_display_name('awg3', True), 'AmneziaWG 3.1')
        self.assertEqual(panel.protocol_display_name('awg', True), 'AmneziaWG')

    def test_short_name_and_connection_name(self):
        self.assertEqual(panel.protocol_short_name('awg2'), 'AWG2')
        self.assertEqual(panel.protocol_short_name('awg2', True), 'AWG3')
        server = {'name': 'nl-01', 'protocols': {'awg2': {'header_protection': True}}}
        self.assertEqual(panel.connection_display_name(server, 'awg2'), 'nl-01 AWG3')
        server['protocols']['awg2']['header_protection'] = False
        self.assertEqual(panel.connection_display_name(server, 'awg2'), 'nl-01 AWG2')


def seed_servers(header_protection):
    return [{
        'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22, 'username': 'root', 'password': 'x',
        'private_key': '', 'server_info': {}, 'uid': 'entry-uid',
        'protocols': {'awg2': {'installed': True, 'port': '55424', 'awg_params': {}, 'base_protocol': 'awg2',
                               'instance': 1, 'display_name': 'AmneziaWG 2.0', 'container_name': 'amnezia-awg2',
                               'header_protection': header_protection}},
    }]


class FakeCheckManager:
    def __init__(self, header_protection, protocol_version=None):
        self.header_protection = header_protection
        self.protocol_version = protocol_version

    def check_docker_installed(self):
        return True

    def get_server_status(self, protocol_type):
        if protocol_type != 'awg2':
            return {'container_exists': False, 'container_running': False, 'protocol': protocol_type}
        result = {'container_exists': True, 'container_running': True, 'protocol': protocol_type,
                'port': '55424', 'awg_params': {}, 'clients_count': 0,
                'header_protection': self.header_protection}
        if self.protocol_version is not None:
            result['protocol_version'] = self.protocol_version
        return result


class ServerPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self, header_protection):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': seed_servers(header_protection), 'users': [], 'user_connections': []}, f)

    def login(self, client):
        login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)

    def test_page_names_awg3_card(self):
        self.seed(True)
        with TestClient(panel.app) as client:
            self.login(client)
            page = client.get('/server/0').text
        self.assertIn('<div class="protocol-name">AmneziaWG 3.x (amnezia-awg2)</div>', page)
        self.assertIn('"awg2": true,', page)

    def test_page_keeps_awg2_card_name(self):
        self.seed(False)
        with TestClient(panel.app) as client:
            self.login(client)
            page = client.get('/server/0').text
        self.assertIn('<div class="protocol-name">AmneziaWG 2.0</div>', page)
        self.assertNotIn('"awg2": true,', page)

    def check(self, header_protection, protocol_version=None):
        ssh = mock.Mock()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=FakeCheckManager(header_protection, protocol_version)):
            with TestClient(panel.app) as client:
                self.login(client)
                response = client.post('/api/servers/0/check')
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['protocols']['awg2'], panel.load_data()['servers'][0]['protocols']['awg2']

    def test_minor_version_refreshes_even_when_header_protection_is_unchanged(self):
        self.seed(True)
        live, saved = self.check(True, '3.1')
        self.assertEqual(live['display_name'], 'AmneziaWG 3.1 (amnezia-awg2)')
        self.assertEqual(saved['protocol_version'], '3.1')
        self.assertEqual(saved['display_name'], live['display_name'])
        self.assertEqual(saved['container_name'], 'amnezia-awg2')
        with TestClient(panel.app) as client:
            self.login(client)
            page = client.get('/server/0').text
            self.assertIn('<div class="protocol-name">AmneziaWG 3.1 (amnezia-awg2)</div>', page)
            self.assertIn('"awg2": "3.1",', page)
            self.assertIn('AWG3.1', client.get('/').text)
        live, saved = self.check(True, '3.x')
        self.assertEqual(live['display_name'], 'AmneziaWG 3.x (amnezia-awg2)')
        self.assertEqual(saved['protocol_version'], '3.x')

    def test_check_persists_detection_both_ways(self):
        self.seed(False)
        live, saved = self.check(True)
        self.assertEqual(live['display_name'], 'AmneziaWG 3.x (amnezia-awg2)')
        self.assertTrue(saved['header_protection'])
        self.assertEqual(saved['display_name'], 'AmneziaWG 3.x (amnezia-awg2)')
        self.assertEqual(saved['container_name'], 'amnezia-awg2')

        live, saved = self.check(False)
        self.assertEqual(live['display_name'], 'AmneziaWG 2.0')
        self.assertFalse(saved['header_protection'])
        self.assertEqual(saved['display_name'], 'AmneziaWG 2.0')


if __name__ == '__main__':
    unittest.main()
