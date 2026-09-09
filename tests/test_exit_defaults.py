import json
import os
import re
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

import app as panel
from app import should_link_default_exit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def seed_servers():
    return [
        {'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22, 'username': 'root', 'password': 'x',
         'private_key': '', 'server_info': {}, 'uid': 'entry-uid',
         'protocols': {'awg2': {'installed': True, 'port': '55424'}}},
        {'name': 'Berlin-1', 'host': '203.0.113.5', 'ssh_port': 22, 'username': 'root', 'password': 'x',
         'private_key': '', 'server_info': {}, 'uid': 'exit-uid',
         'protocols': {'exit': {'installed': True, 'port': '55520', 'subnet': '10.9.0.0/24'}}},
    ]


SETTINGS_PAYLOAD = {
    'appearance': {'title': 'Amnezia', 'logo': '❤️', 'subtitle': 'Web Panel'},
    'sync': {},
    'captcha': {'enabled': False},
    'telegram': {'token': '', 'enabled': False},
    'ssl': {'enabled': False},
}


class AutoLinkDecisionTests(unittest.TestCase):
    """Which installs join the default exit node."""

    def decide(self, **kw):
        args = dict(default_uid='exit-uid', server_uid='entry-uid', is_awg=True,
                    reinstall=False, previous_link=None)
        args.update(kw)
        return should_link_default_exit(args['default_uid'], args['server_uid'], args['is_awg'],
                                        args['reinstall'], args['previous_link'])

    def test_a_newly_added_awg_instance_joins(self):
        self.assertTrue(self.decide())

    def test_reinstalling_an_unlinked_instance_stays_unlinked(self):
        # the instance was deliberately left (or set) unlinked - a reinstall
        # must not route its clients through the default exit behind our back
        self.assertFalse(self.decide(reinstall=True))

    def test_an_instance_with_its_own_link_is_left_to_the_relink_path(self):
        self.assertFalse(self.decide(reinstall=True, previous_link={'exit_uid': 'other'}))
        self.assertFalse(self.decide(previous_link={'exit_uid': 'other'}))

    def test_no_default_no_self_link_no_other_protocols(self):
        self.assertFalse(self.decide(default_uid=''))
        self.assertFalse(self.decide(server_uid='exit-uid'))   # the exit's own server
        self.assertFalse(self.decide(is_awg=False))


class DefaultExitNodeSettingsTests(unittest.TestCase):
    """The default exit node is stored in settings and only ever points at an
    exit node that is actually installed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': seed_servers(), 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def save(self, client, uid):
        response = client.post('/api/settings/save', json=dict(SETTINGS_PAYLOAD,
                                                               exit_nodes={'default_exit_uid': uid}))
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_default_is_kept_only_while_the_node_exists(self):
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)

            # a real exit node is stored as given
            self.assertEqual(self.save(client, ' exit-uid ')['warnings'], [])
            self.assertEqual(panel.load_data()['settings']['exit_nodes']['default_exit_uid'], 'exit-uid')

            # a uid that names no installed exit node is dropped, with a warning
            saved = self.save(client, 'gone-uid')
            self.assertEqual(saved['warnings'], ['exit_default_cleared'])
            self.assertEqual(panel.load_data()['settings']['exit_nodes']['default_exit_uid'], '')

            # so is a server that has no exit installed
            self.assertEqual(self.save(client, 'entry-uid')['warnings'], ['exit_default_cleared'])

            # empty means "no default" and is not a warning
            self.assertEqual(self.save(client, '')['warnings'], [])

    def test_settings_default_is_present_for_old_data_files(self):
        self.assertEqual(panel.load_data()['settings']['exit_nodes'], {'default_exit_uid': ''})

    def test_settings_page_renders_the_exit_card(self):
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)
            page = client.get('/settings')
            self.assertEqual(page.status_code, 200, page.text)
            for marker in ('id="exitDefaultNode"', 'loadExitNodes()', 'Default exit node'):
                self.assertIn(marker, page.text, f'/settings lacks {marker}')
            # the stored uid reaches the page as JSON, not as raw interpolation
            self.assertIn('const current = ""', page.text)

    def test_settings_page_wiring(self):
        with open(os.path.join(ROOT, 'templates', 'settings.html'), encoding='utf-8') as f:
            page = f.read()
        self.assertIn('id="exitDefaultNode"', page)
        self.assertRegex(page, r"async function loadExitNodes\(")
        self.assertIn("const exit_nodes = { default_exit_uid:", page)
        self.assertIn('self_service, exit_nodes })', page)
        # the saved uid comes from the server, so it is not interpolated raw
        self.assertIn("| tojson }};", page[page.index('async function loadExitNodes'):][:600])


if __name__ == '__main__':
    unittest.main()
