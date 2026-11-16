"""First-run administrator setup regressions; synthetic state only."""
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class InitialAdminBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = Path(self.tmp) / 'data.json'
        self.old_data_file = panel.DATA_FILE
        panel.DATA_FILE = str(self.path)
        self.addCleanup(setattr, panel, 'DATA_FILE', self.old_data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self.old_data_file)
        self.old_data_lock = panel.DATA_LOCK
        panel.DATA_LOCK = asyncio.Lock()
        self.addCleanup(setattr, panel, 'DATA_LOCK', self.old_data_lock)
        self.write({'servers': [], 'users': [], 'user_connections': [], 'settings': {}})

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')

    def read(self):
        return json.loads(self.path.read_text(encoding='utf-8'))

    def test_startup_does_not_create_fixed_default_credentials(self):
        old_lease = panel._panel_lease
        panel._panel_lease = None
        self.addCleanup(setattr, panel, '_panel_lease', old_lease)
        created_tasks = []

        def capture(coro):
            created_tasks.append(coro)
            coro.close()
            return mock.Mock()

        with mock.patch.object(panel, 'PanelLease') as lease, \
             mock.patch.object(panel, '_start_conn_monitor'), \
             mock.patch.object(panel, '_start_duckdns_monitor'), \
             mock.patch.object(panel, '_op_store') as op_store, \
             mock.patch.object(panel.asyncio, 'create_task', side_effect=capture):
            lease.return_value.acquire.return_value = lease.return_value
            asyncio.run(panel.startup())

        self.assertEqual(self.read()['users'], [])
        serialized = self.path.read_text(encoding='utf-8')
        self.assertNotIn('admin / admin', serialized)
        self.assertGreaterEqual(len(created_tasks), 5)
        op_store.return_value.mark_interrupted.assert_called_once_with()

    def test_login_page_switches_between_setup_and_login(self):
        with TestClient(panel.app) as client:
            setup = client.get('/login')
            self.assertEqual(setup.status_code, 200)
            self.assertIn('id="setupForm"', setup.text)
            self.assertNotIn('id="loginForm"', setup.text)

            data = self.read()
            data['users'] = [{'id': 'existing', 'username': 'existing',
                              'password_hash': panel.hash_password('existing-password'),
                              'role': 'admin', 'enabled': True}]
            self.write(data)
            login = client.get('/login')
            self.assertEqual(login.status_code, 200)
            self.assertIn('id="loginForm"', login.text)
            self.assertNotIn('id="setupForm"', login.text)

    def test_first_setup_creates_one_admin_and_logs_in(self):
        with TestClient(panel.app) as client:
            response = client.post('/api/auth/setup', json={
                'username': ' first-admin ',
                'password': 'correct horse battery staple',
                'password_confirm': 'correct horse battery staple',
            })
            self.assertEqual(response.status_code, 201, response.text)
            self.assertEqual(response.json()['role'], 'admin')
            home = client.get('/', follow_redirects=False)
            self.assertEqual(home.status_code, 200)

        users = self.read()['users']
        self.assertEqual(len(users), 1)
        admin = users[0]
        self.assertEqual(admin['username'], 'first-admin')
        self.assertEqual(admin['role'], 'admin')
        self.assertTrue(admin['enabled'])
        self.assertNotIn('password', admin)
        self.assertTrue(panel.verify_password('correct horse battery staple', admin['password_hash']))
        for key in ('traffic_used', 'traffic_total', 'traffic_limit',
                    'traffic_reset_strategy', 'last_reset_at', 'expiration_date',
                    'share_enabled', 'share_token', 'share_password_hash', 'created_at'):
            self.assertIn(key, admin)

    def test_setup_validates_password_and_is_closed_after_any_user_exists(self):
        with TestClient(panel.app) as client:
            short = client.post('/api/auth/setup', json={
                'username': 'owner', 'password': 'too-short',
                'password_confirm': 'too-short',
            })
            self.assertEqual(short.status_code, 400)
            mismatch = client.post('/api/auth/setup', json={
                'username': 'owner', 'password': 'a-secure-password',
                'password_confirm': 'different-password',
            })
            self.assertEqual(mismatch.status_code, 400)
            self.assertEqual(self.read()['users'], [])

            data = self.read()
            data['users'] = [{'id': 'record-only', 'username': 'external',
                              'password_hash': None, 'role': 'none', 'enabled': False}]
            self.write(data)
            closed = client.post('/api/auth/setup', json={
                'username': 'attacker', 'password': 'a-secure-password',
                'password_confirm': 'a-secure-password',
            })
            self.assertEqual(closed.status_code, 409)
            self.assertEqual([u['id'] for u in self.read()['users']], ['record-only'])

    @unittest.skipUnless(shutil.which('node'), 'node is not installed')
    def test_rendered_setup_and_login_scripts_are_valid_javascript(self):
        with TestClient(panel.app) as client:
            pages = [client.get('/login').text]
            data = self.read()
            data['users'] = [{'id': 'existing', 'username': 'existing',
                              'password_hash': panel.hash_password('existing-password'),
                              'role': 'admin', 'enabled': True}]
            self.write(data)
            pages.append(client.get('/login').text)
        for html in pages:
            scripts = '\n'.join(re.findall(r'<script(?:[^>]*)>(.*?)</script>', html, re.S))
            with tempfile.NamedTemporaryFile('w', suffix='.js', encoding='utf-8', delete=False) as handle:
                handle.write(scripts)
                name = handle.name
            try:
                result = subprocess.run(['node', '--check', name], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                os.unlink(name)

    def test_parallel_setup_has_exactly_one_winner(self):
        barrier = __import__('threading').Barrier(2)
        original_hash = panel.hash_password

        def synchronized_hash(password):
            barrier.wait(timeout=5)
            return original_hash(password)

        async def submit(name):
            from httpx import ASGITransport, AsyncClient
            async with AsyncClient(transport=ASGITransport(app=panel.app),
                                   base_url='http://testserver') as client:
                return await client.post('/api/auth/setup', json={
                    'username': name,
                    'password': 'a-secure-password',
                    'password_confirm': 'a-secure-password',
                })

        async def race():
            return await asyncio.gather(submit('one'), submit('two'))

        with mock.patch.object(panel, 'hash_password', side_effect=synchronized_hash):
            first, second = asyncio.run(race())

        self.assertEqual(sorted([first.status_code, second.status_code]), [201, 409])
        self.assertEqual(len(self.read()['users']), 1)

    def test_setup_rejects_cross_origin_request_without_writing(self):
        before = self.path.read_bytes()
        with TestClient(panel.app) as client:
            response = client.post('/api/auth/setup', headers={
                'Origin': 'https://evil.example', 'Sec-Fetch-Site': 'cross-site'
            }, json={
                'username': 'owner', 'password': 'a-secure-password',
                'password_confirm': 'a-secure-password',
            })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
