"""POST /api/users/{id}/toggle through the real app, without patching panel globals.

Other toggle tests inject ``_USER_STATE_TASKS`` into an extracted namespace or
patch it with ``create=True``, which hid that the module-level definition was
lost in a merge: every real toggle answered 500 after saving the intent.
The data file is a temporary synthetic one and the toggled user has no
connections, so no SSH connection is opened.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class UserToggleHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self._data_file)

        self._conn_monitor_started = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started',
                        self._conn_monitor_started)

        users = [
            {'id': 'admin-id', 'username': 'admin', 'role': 'admin', 'enabled': True,
             'password_hash': panel.hash_password('admin')},
            {'id': 'target-id', 'username': 'target', 'role': 'user', 'enabled': True,
             'password_hash': panel.hash_password('target')},
        ]
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as destination:
            json.dump({'servers': [], 'users': users, 'user_connections': []}, destination)

    def target(self):
        with open(panel.DATA_FILE, encoding='utf-8') as source:
            return next(u for u in json.load(source)['users'] if u['id'] == 'target-id')

    def test_admin_session_can_disable_and_enable_user(self):
        with mock.patch.object(panel, 'get_ssh',
                               side_effect=AssertionError('SSH is forbidden in tests')), \
             TestClient(panel.app) as client:
            login = client.post('/api/auth/login',
                                json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)

            disabled = client.post('/api/users/target-id/toggle', json={'enabled': False})
            self.assertEqual(disabled.status_code, 200, disabled.text)
            self.assertEqual(disabled.json(), {'status': 'success', 'enabled': False})
            self.assertFalse(self.target()['enabled'])
            self.assertFalse(self.target()['access_sync_pending'])

            enabled = client.post('/api/users/target-id/toggle', json={'enabled': True})
            self.assertEqual(enabled.status_code, 200, enabled.text)
            self.assertEqual(enabled.json(), {'status': 'success', 'enabled': True})
            self.assertTrue(self.target()['enabled'])


if __name__ == '__main__':
    unittest.main()
