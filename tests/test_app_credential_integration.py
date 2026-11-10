"""Application seams for encrypted SSH credentials and portable exports."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


PASSWORD = 'APP-SEAM-SYNTHETIC-SSH-PASSWORD'
PRIVATE_KEY = '-----BEGIN SYNTHETIC KEY-----\nAPP-SEAM-SECRET\n-----END SYNTHETIC KEY-----'


class AppCredentialIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = Path(self.tmp) / 'data.json'
        self.key = Path(self.tmp) / 'data.json.credential.key'
        self.old_data_file = panel.DATA_FILE
        self.old_data_lock = panel.DATA_LOCK
        panel.DATA_FILE = str(self.path)
        panel.DATA_LOCK = asyncio.Lock()
        self.addCleanup(setattr, panel, 'DATA_FILE', self.old_data_file)
        self.addCleanup(setattr, panel, 'DATA_LOCK', self.old_data_lock)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self.old_data_file)

    def legacy(self):
        return {
            'servers': [{
                'uid': 'server-a', 'name': 'fixture', 'host': '192.0.2.10',
                'ssh_port': 22, 'username': 'root', 'password': PASSWORD,
                'private_key': PRIVATE_KEY, 'protocols': {},
            }],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin-password'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [], 'settings': {},
        }

    def write_raw(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')

    def test_load_data_migrates_legacy_plaintext_atomically_and_ssh_still_resolves(self):
        self.write_raw(self.legacy())
        data = panel.load_data()
        raw = self.path.read_text(encoding='utf-8')
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn('APP-SEAM-SECRET', raw)
        self.assertNotIn('password', data['servers'][0])
        self.assertNotIn('private_key', data['servers'][0])
        self.assertIn('ssh_credentials', data['servers'][0])

        with mock.patch.object(panel, 'SSHManager') as manager:
            panel._ssh_manager_for(data['servers'][0], data)
        kwargs = manager.call_args.kwargs
        self.assertEqual(kwargs['password'], PASSWORD)
        self.assertEqual(kwargs['private_key'], PRIVATE_KEY)

    def test_save_data_never_writes_new_plaintext_credentials(self):
        data = self.legacy()
        panel.save_data(data)
        raw = self.path.read_text(encoding='utf-8')
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn('APP-SEAM-SECRET', raw)
        stored = json.loads(raw)
        self.assertIn('ssh_credentials', stored['servers'][0])

    def test_legacy_download_is_disabled_and_private(self):
        self.write_raw(self.legacy())
        panel.load_data()
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={
                'username': 'admin', 'password': 'admin-password'
            })
            self.assertEqual(login.status_code, 200, login.text)
            response = client.get('/api/settings/backup/download')
        self.assertEqual(response.status_code, 410)
        self.assertIn('no-store', response.headers.get('cache-control', ''))
        self.assertNotIn(PASSWORD, response.text)
        self.assertNotIn('APP-SEAM-SECRET', response.text)

    def test_restore_old_plaintext_json_persists_only_encrypted_credentials(self):
        current = self.legacy()
        self.write_raw(current)
        panel.load_data()
        portable = self.legacy()
        portable['settings'] = {'appearance': {'title': 'Restored'}}
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={
                'username': 'admin', 'password': 'admin-password'
            })
            self.assertEqual(login.status_code, 200, login.text)
            page = client.get('/settings')
            self.assertEqual(page.status_code, 200)
            csrf = client.cookies.get('session')
            self.assertTrue(csrf)
            response = client.post(
                '/api/settings/backup/restore',
                headers={'Origin': 'http://testserver', 'Sec-Fetch-Site': 'same-origin'},
                files={'file': ('data.json', json.dumps(portable).encode(), 'application/json')},
            )
        self.assertEqual(response.status_code, 200, response.text)
        raw = self.path.read_text(encoding='utf-8')
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn('APP-SEAM-SECRET', raw)
        server = json.loads(raw)['servers'][0]
        self.assertIn('ssh_credentials', server)
        self.assertNotIn('password', server)
        self.assertNotIn('private_key', server)


if __name__ == '__main__':
    unittest.main()
