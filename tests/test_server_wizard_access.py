"""Focused regression tests for the add-server wizard and its access policy.

The wizard is administrator-only: support users keep their existing
read/operate access to server pages, but may not open the wizard or create a
new inventory entry.  These tests render the real routes through the app with
an isolated DATA_FILE; they never touch the panel's production data or SSH.
"""
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app as panel

ROOT = Path(__file__).resolve().parents[1]
WIZARD_TEMPLATE = ROOT / 'templates' / 'server_new.html'
LANGUAGES = ('en', 'ru', 'fr', 'fa', 'zh')


class ServerWizardAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)

        # Keep the background connection monitor out of this isolated run.
        self._monitor_started = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._monitor_started)

        users = [
            {'id': 'admin-id', 'username': 'admin', 'password_hash': panel.hash_password('admin'),
             'role': 'admin', 'enabled': True},
            {'id': 'support-id', 'username': 'support', 'password_hash': panel.hash_password('support'),
             'role': 'support', 'enabled': True},
        ]
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [], 'users': users, 'user_connections': []}, f)

    def login(self, client, username):
        response = client.post('/api/auth/login',
                               json={'username': username, 'password': username})
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_admin_sees_the_wizard_template(self):
        self.assertTrue(WIZARD_TEMPLATE.is_file(),
                        'the wizard template templates/server_new.html is missing')
        rendered = []

        def record_template(name, *args, **kwargs):
            rendered.append(name)
            return original_template(name, *args, **kwargs)

        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            original_template = panel.templates.TemplateResponse
            with mock.patch.object(panel.templates, 'TemplateResponse',
                                   side_effect=record_template):
                response = client.get('/servers/new', follow_redirects=False)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('text/html', response.headers.get('content-type', ''))
        self.assertIn('server_new.html', rendered,
                      'GET /servers/new did not render server_new.html')
        self.assertTrue(response.text.strip(), 'the wizard rendered an empty page')

    def test_support_cannot_open_the_wizard(self):
        with TestClient(panel.app) as client:
            self.login(client, 'support')
            response = client.get('/servers/new', follow_redirects=False)

        self.assertNotEqual(response.status_code, 200,
                            'support must not receive the add-server wizard')
        if 300 <= response.status_code < 400:
            location = response.headers.get('location', '')
            path = location.split('?', 1)[0]
            self.assertNotEqual(path, '/servers/new')
        else:
            self.assertIn(response.status_code, (401, 403))

    def test_support_cannot_create_a_server(self):
        with TestClient(panel.app) as client:
            self.login(client, 'support')
            with mock.patch.object(panel, 'SSHManager') as ssh:
                response = client.post('/api/servers/add', json={
                    'name': 'synthetic',
                    'host': '192.0.2.10',
                    'ssh_port': 22,
                    'username': 'root',
                    'password': 'synthetic',
                })
        self.assertEqual(response.status_code, 403,
                         'POST /api/servers/add must stay administrator-only')
        ssh.assert_not_called()

    def test_anonymous_is_sent_to_login(self):
        with TestClient(panel.app) as client:
            response = client.get('/servers/new', follow_redirects=False)
        self.assertIn(response.status_code, (302, 307))
        self.assertIn('/login', response.headers.get('location', ''))


class ServerWizardTranslationTests(unittest.TestCase):
    """Keys used by the new template must exist in every shipped locale.

    The key list is taken from the template, not from a hard-coded wording, so
    translators remain free to choose the actual text.
    """

    def setUp(self):
        if not WIZARD_TEMPLATE.is_file():
            self.skipTest('templates/server_new.html is not implemented yet')
        self.source = WIZARD_TEMPLATE.read_text(encoding='utf-8')

    def test_wizard_translation_keys_exist_in_every_locale(self):
        # Only literals passed directly to _(); dynamic keys such as
        # _('ssh_trust_' + state) are not translation entries of their own.
        keys = set(re.findall(r"""_\s*\(\s*['"]([A-Za-z0-9_]+)['"]\s*\)""", self.source))
        self.assertTrue(keys, 'the wizard template references no static translation keys')
        for lang in LANGUAGES:
            with self.subTest(lang=lang):
                values = json.loads((ROOT / 'translations' / f'{lang}.json')
                                    .read_text(encoding='utf-8'))
                missing = sorted(key for key in keys if key not in values)
                self.assertEqual(missing, [], f'{lang}.json is missing: {missing}')
                empty = sorted(key for key in keys if not str(values[key]).strip())
                self.assertEqual(empty, [], f'{lang}.json has empty values: {empty}')


if __name__ == '__main__':
    unittest.main()
