"""Support must not download or restore the panel backup; admin still can.

These tests use the real HTTP routes and real session login.  Every request is
served with an isolated temporary DATA_FILE, so no production data is read and
no SSH connection is ever opened.  The restore test uses the ordinary online
restore flow (recovery snapshot + atomic commit), not the offline disaster
recovery script.
"""
import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class SupportBackupAdminAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)

        # The lifecycle fence is configured at import time against the real
        # data path.  Repoint it at the temporary tree so a deployment fence
        # cannot influence this test, then restore the original configuration.
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self._data_file)

        # Keep the background connection monitor away from synthetic inventory.
        self._conn_monitor_started = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started',
                        self._conn_monitor_started)

        self.admin = {
            'id': 'admin-id',
            'username': 'admin',
            'password_hash': panel.hash_password('admin'),
            'role': 'admin',
            'enabled': True,
        }
        self.support = {
            'id': 'support-id',
            'username': 'support',
            'password_hash': panel.hash_password('support'),
            'role': 'support',
            'enabled': True,
        }
        self.write_data({
            'servers': [],
            'users': [self.admin, self.support],
            'user_connections': [],
            'private_marker': 'support-must-not-receive-this',
        })

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as destination:
            json.dump(data, destination)

    def read_data_bytes(self):
        with open(panel.DATA_FILE, 'rb') as source:
            return source.read()

    def login(self, client, username):
        response = client.post('/api/auth/login',
                               json={'username': username, 'password': username})
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def valid_backup(self):
        """A structurally valid online restore fixture; no SSH or real keys."""
        return {
            'servers': [{
                'uid': 'fixture-node',
                'name': 'fixture',
                'host': '192.0.2.10',
                'ssh_port': 22,
                'username': 'root',
                'protocols': {},
            }],
            'users': [dict(self.admin)],
            'user_connections': [],
            'restore_marker': 'synthetic-backup-restored',
        }

    def restore(self, client, backup, headers=None):
        return client.post(
            '/api/settings/backup/restore',
            headers=headers,
            files={'file': ('data.json', json.dumps(backup).encode('utf-8'),
                            'application/json')},
        )

    def add_api_token(self, user_id, raw_token):
        """Store a token exactly as the panel does: only its SHA-256 digest."""
        now = datetime.now().isoformat()
        data = json.loads(self.read_data_bytes())
        data.setdefault('api_tokens', []).append({
            'id': 'support-backup-token',
            'name': 'support-backup-regression',
            'token_hash': hashlib.sha256(raw_token.encode('utf-8')).hexdigest(),
            'token_prefix': raw_token[:len(panel.API_TOKEN_PREFIX) + 4],
            'user_id': user_id,
            'created_at': now,
            # Recent use suppresses the best-effort last_used_at rewrite, so
            # any DATA_FILE change observed below is caused by backup handling.
            'last_used_at': now,
        })
        self.write_data(data)

    def test_support_cannot_download_data_backup(self):
        with TestClient(panel.app) as client:
            self.login(client, 'support')
            before = self.read_data_bytes()
            response = client.get('/api/settings/backup/download')

        self.assertEqual(response.status_code, 403, response.text)
        # The response is a denial, not the data file (which contains secrets).
        self.assertNotIn('support-must-not-receive-this', response.text)
        self.assertNotIn(self.admin['password_hash'], response.text)
        self.assertEqual(self.read_data_bytes(), before,
                         'a denied download must not rewrite data.json')

    def test_support_cannot_restore_backup_or_write_data(self):
        backup = self.valid_backup()
        with TestClient(panel.app) as client:
            self.login(client, 'support')
            before = self.read_data_bytes()
            with mock.patch.object(panel, 'validate_backup') as validate, \
                 mock.patch.object(panel, 'RecoveryStore') as store:
                response = self.restore(client, backup)
            validate.assert_not_called()
            store.assert_not_called()

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn('synthetic-backup-restored', response.text)
        self.assertEqual(self.read_data_bytes(), before,
                         'a denied restore must not rewrite data.json')
        self.assertFalse(Path(panel.DATA_FILE + '.recovery').exists(),
                         'a denied restore must not create a recovery journal')

    def test_support_bearer_token_cannot_download_or_restore_backup(self):
        raw_token = 'awp_support-backup-regression-token'
        self.add_api_token('support-id', raw_token)
        headers = {'Authorization': 'Bearer ' + raw_token}
        backup = self.valid_backup()

        with TestClient(panel.app) as client:
            self.assertIsNone(client.cookies.get('session'))
            # Positive control: the token is real and accepted for ordinary
            # support access, so the 403s below are endpoint policy, not a
            # malformed or unknown token.
            settings = client.get('/api/settings', headers=headers)
            self.assertEqual(settings.status_code, 200, settings.text)

            before = self.read_data_bytes()
            with mock.patch.object(panel, 'validate_backup') as validate, \
                 mock.patch.object(panel, 'RecoveryStore') as store:
                download = client.get('/api/settings/backup/download',
                                      headers=headers)
                restore = self.restore(client, backup, headers=headers)
            self.assertIsNone(client.cookies.get('session'))
            validate.assert_not_called()
            store.assert_not_called()

        self.assertEqual(download.status_code, 403, download.text)
        self.assertEqual(restore.status_code, 403, restore.text)
        self.assertNotIn('support-must-not-receive-this', download.text)
        self.assertNotIn(self.admin['password_hash'], download.text)
        self.assertNotIn('synthetic-backup-restored', restore.text)
        self.assertEqual(self.read_data_bytes(), before,
                         'support Bearer access must not rewrite data.json')
        self.assertFalse(Path(panel.DATA_FILE + '.recovery').exists(),
                         'support Bearer restore must not create a recovery journal')

    def test_admin_can_download_data_backup(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            before = self.read_data_bytes()
            response = client.get('/api/settings/backup/download')

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('application/json', response.headers.get('content-type', ''))
        downloaded = response.json()
        self.assertEqual([user['username'] for user in downloaded['users']],
                         ['admin', 'support'])
        self.assertEqual(downloaded['private_marker'],
                         'support-must-not-receive-this')
        self.assertEqual(self.read_data_bytes(), before,
                         'the download endpoint must not rewrite data.json')

    def test_admin_can_restore_valid_backup(self):
        backup = self.valid_backup()
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            before = self.read_data_bytes()
            with mock.patch.object(panel, 'get_ssh',
                                   side_effect=AssertionError('SSH is forbidden in tests')):
                response = self.restore(client, backup)

        self.assertEqual(response.status_code, 200, response.text)
        # This is the response the settings page expects (no operation_id sent).
        self.assertEqual(response.json(), {'status': 'success'})
        self.assertNotIn('before_base64', response.text)
        self.assertNotIn('synthetic-backup-restored', response.text)
        self.assertNotIn(self.admin['password_hash'], response.text)

        restored = json.loads(self.read_data_bytes())
        self.assertEqual(restored['restore_marker'], 'synthetic-backup-restored')
        self.assertEqual([user['id'] for user in restored['users']], ['admin-id'])
        self.assertEqual(restored['servers'][0]['uid'], 'fixture-node')

        # The online restore is journaled before its atomic commit.  The
        # snapshot is owner-only local state and must contain the pre-request
        # bytes; the HTTP response above must not expose it.
        records = list((Path(panel.DATA_FILE + '.recovery')).glob('*.json'))
        self.assertEqual(len(records), 1, records)
        record = json.loads(records[0].read_bytes())
        self.assertEqual(record['phase'], 'committed')
        self.assertEqual(record['actor'], 'admin-id')
        self.assertEqual(record['kind'], 'ordinary_restore')
        self.assertEqual(base64.b64decode(record['before_base64']), before)


if __name__ == '__main__':
    unittest.main()
