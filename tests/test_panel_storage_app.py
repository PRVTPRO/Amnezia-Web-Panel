"""app.py wiring of the optional S3 storage backend (panel_storage).

The status route and the settings card expose bucket, endpoint and lease owner,
so they follow the backup policy: admin only (session or API token), private
cache headers, nothing for support. In the default local mode the card is not
rendered and the lifecycle hooks do nothing. The S3 status itself is patched:
these tests never talk to S3 and never call bootstrap().
"""
import ast
import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient
from markupsafe import escape

import app as panel
import panel_storage


ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = 'awp_storage-status-admin-token'
SUPPORT_TOKEN = 'awp_storage-status-support-token'
BUCKET = 'panel-state-bucket-fixture'
S3_STATUS = {
    'backend': 's3', 'bucket': BUCKET, 'prefix': 'amnezia-panel/',
    'endpoint': 'https://s3.example.test', 'region': 'us-east-1',
    'fencing': 'enforced', 'generation': 42, 'files': 7, 'bytes': 123456,
    'last_commit_at': '2026-11-16T10:00:00Z', 'last_error': 'AccessDenied (403)',
    'last_error_at': '2026-11-16T10:05:00Z', 'fenced': False, 'pending': False,
    'lease_owner': 'panel-0-1-abcdef01',
}


def text(key):
    """The English string as Jinja renders it into the page."""
    return str(escape(panel._t(key, 'en')))


def local_env():
    """Run with PANEL_STORAGE unset, whatever the developer's shell has."""
    patcher = mock.patch.dict(os.environ)
    patcher.start()
    os.environ.pop('PANEL_STORAGE', None)
    return patcher


class PanelFixture(unittest.TestCase):
    """Synthetic DATA_FILE with admin/support/user, as in test_api_token_admin_routes."""

    def setUp(self):
        self.addCleanup(local_env().stop)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

        old_data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', old_data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, old_data_file)

        monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', monitor)

        ssh = mock.patch.object(panel, 'get_ssh',
                                side_effect=AssertionError('SSH is forbidden in tests'))
        ssh.start()
        self.addCleanup(ssh.stop)

        def user(uid, role):
            return {'id': uid + '-id', 'username': uid, 'role': role, 'enabled': True,
                    'password_hash': panel.hash_password(uid)}

        now = datetime.now().isoformat()

        def token(raw, owner):
            # A recent last_used_at keeps _touch_api_token from rewriting the file.
            return {'id': owner + '-token', 'name': owner, 'user_id': owner + '-id',
                    'token_hash': hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                    'token_prefix': raw[:len(panel.API_TOKEN_PREFIX) + 4],
                    'created_at': now, 'last_used_at': now}

        with open(panel.DATA_FILE, 'w', encoding='utf-8') as destination:
            json.dump({
                'servers': [],
                'users': [user('admin', 'admin'), user('support', 'support'),
                          user('alice', 'user')],
                'user_connections': [],
                'api_tokens': [token(ADMIN_TOKEN, 'admin'), token(SUPPORT_TOKEN, 'support')],
            }, destination)

    @staticmethod
    def bearer(raw):
        return {'Authorization': 'Bearer ' + raw}

    def login(self, client, username):
        client.cookies.clear()
        response = client.post('/api/auth/login',
                               json={'username': username, 'password': username})
        self.assertEqual(response.status_code, 200, response.text)

    def s3_status(self, **changes):
        status = dict(S3_STATUS, **changes)
        patcher = mock.patch.object(panel.panel_storage, 'status', return_value=status)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def assert_private(self, response):
        for name, value in panel.PRIVATE_HEADERS.items():
            self.assertEqual(response.headers.get(name), value, name)


class StorageStatusRouteTests(PanelFixture):
    def test_anonymous_and_support_are_denied_without_leak(self):
        status = self.s3_status()
        with TestClient(panel.app) as client:
            anonymous = client.get('/api/settings/storage')
            denied = [client.get('/api/settings/storage', headers=self.bearer(raw))
                      for raw in ('awp_not-a-stored-token', SUPPORT_TOKEN)]
            self.login(client, 'support')
            denied.append(client.get('/api/settings/storage'))
            self.login(client, 'alice')
            denied.append(client.get('/api/settings/storage'))
        # The route answers 403; the panel's middleware turns a cookie-less browser
        # denial into 401 "Session expired" and keeps the private headers.
        self.assertEqual(anonymous.status_code, 401, anonymous.text)
        self.assertEqual(anonymous.json(), {'error': 'Session expired'})
        self.assert_private(anonymous)
        self.assertEqual([r.status_code for r in denied], [403, 403, 403, 403],
                         [r.text for r in denied])
        for response in denied:
            self.assertEqual(response.json(), {'error': 'Forbidden'})
            self.assert_private(response)
        for response in [anonymous, *denied]:
            self.assertNotIn(BUCKET, response.text)
        status.assert_not_called()

    def test_admin_session_and_token_get_the_status(self):
        self.s3_status()
        with TestClient(panel.app) as client:
            by_token = client.get('/api/settings/storage', headers=self.bearer(ADMIN_TOKEN))
            self.assertIsNone(client.cookies.get('session'))
            self.login(client, 'admin')
            by_session = client.get('/api/settings/storage')
        for response in (by_token, by_session):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json(), S3_STATUS)
            self.assert_private(response)

    def test_local_backend_reports_local(self):
        with TestClient(panel.app) as client:
            response = client.get('/api/settings/storage', headers=self.bearer(ADMIN_TOKEN))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['backend'], 'local')
        self.assertEqual(response.json(), panel_storage.status())
        self.assert_private(response)


class SettingsStorageCardTests(PanelFixture):
    def settings_page(self, username):
        with TestClient(panel.app) as client:
            self.login(client, username)
            response = client.get('/settings')
        self.assertEqual(response.status_code, 200, response.text[:200])
        return response.text

    def test_admin_sees_the_card_in_s3_mode(self):
        self.s3_status()
        html = self.settings_page('admin')
        self.assertIn('id="settings-storage"', html)
        self.assertIn('href="#settings-storage"', html)
        # Placed right after the backup card.
        self.assertLess(html.index('id="settings-backup"'), html.index('id="settings-storage"'))
        self.assertLess(html.index('id="settings-storage"'), html.index('id="settings-tokens"'))
        card = html.split('id="settings-storage"', 1)[1].split('id="settings-tokens"', 1)[0]
        for value in (BUCKET, 'amnezia-panel/', 'https://s3.example.test', 'us-east-1',
                      '42', '2026-11-16 10:00:00 UTC', 'AccessDenied (403)',
                      text('storage_fencing_enforced'), text('storage_env_hint')):
            self.assertIn(value, card)
        self.assertIn('badge-danger', card)
        self.assertNotIn(text('storage_fenced_warning'), card)
        self.assertNotIn(text('storage_unfenced_hint'), card)
        # Read-only: nothing on the card can change the configuration.
        for control in ('<input', '<select', '<button', '<form'):
            self.assertNotIn(control, card)

    def test_fenced_and_unfenced_states_are_flagged(self):
        self.s3_status(fenced=True, fencing='unfenced', last_error=None, last_error_at=None,
                       generation=None, last_commit_at=None, prefix='')
        html = self.settings_page('admin')
        card = html.split('id="settings-storage"', 1)[1].split('id="settings-tokens"', 1)[0]
        for value in (text('storage_fenced_warning'), text('storage_unfenced_hint'),
                      text('storage_fencing_unfenced'), text('storage_no_error'),
                      text('storage_never'), text('storage_prefix_root')):
            self.assertIn(value, card)
        self.assertNotIn('badge-danger', card)

    def test_support_never_gets_the_card(self):
        status = self.s3_status()
        html = self.settings_page('support')
        self.assertNotIn('id="settings-storage"', html)
        self.assertNotIn('href="#settings-storage"', html)
        self.assertNotIn(BUCKET, html)
        # The handler does not even fetch the status for support.
        status.assert_not_called()
        # Positive control: support does see the rest of the settings page.
        self.assertIn('id="settings-backup"', html)

    def test_local_backend_has_no_card(self):
        html = self.settings_page('admin')
        self.assertIn('id="settings-backup"', html)
        self.assertNotIn('id="settings-storage"', html)
        self.assertNotIn('href="#settings-storage"', html)


class StorageHookTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(local_env().stop)

    def test_startup_and_shutdown_hooks_are_noops_in_local_mode(self):
        before = panel_storage._S.thread
        with mock.patch.object(panel_storage, '_sync_loop') as sync_loop, \
             mock.patch.object(panel_storage, '_final_flush_locked') as flush:
            asyncio.run(panel.start_panel_storage())
            asyncio.run(panel.stop_panel_storage())
        self.assertIs(panel_storage._S.thread, before)
        sync_loop.assert_not_called()
        flush.assert_not_called()
        self.assertEqual(panel_storage.uvicorn_overrides(), {})

    def test_startup_hook_refuses_s3_mode_without_bootstrap(self):
        # `uvicorn app:app` or --workers skip __main__ and therefore bootstrap().
        panel_storage._reset()
        self.addCleanup(panel_storage._reset)
        os.environ['PANEL_STORAGE'] = 's3'
        with self.assertRaises(panel_storage.StorageError):
            asyncio.run(panel.start_panel_storage())
        self.assertIsNone(panel_storage._S.thread)
        asyncio.run(panel.stop_panel_storage())  # never raises

    def test_shutdown_hook_awaits_stop_async_without_the_default_executor(self):
        # The default executor is shared with every SSH call; a queued stop() could
        # start only after the pod's grace period.
        with mock.patch.object(panel_storage, 'stop_async', mock.AsyncMock()) as stop_async, \
             mock.patch.object(panel_storage, 'stop', side_effect=AssertionError('blocking stop() in the hook')), \
             mock.patch('asyncio.to_thread', side_effect=AssertionError('the shared executor')):
            asyncio.run(panel.stop_panel_storage())
        stop_async.assert_awaited_once_with()

    def test_hooks_run_after_the_panel_startup(self):
        startup = panel.app.router.on_startup
        self.assertIn(panel.start_panel_storage, startup)
        # The sync thread must start after PanelLease and the startup migrations.
        self.assertLess(startup.index(panel.startup), startup.index(panel.start_panel_storage))
        self.assertIn(panel.stop_panel_storage, panel.app.router.on_shutdown)


class MainBlockTests(unittest.TestCase):
    @staticmethod
    def main_block():
        source = (ROOT / 'app.py').read_text(encoding='utf-8')
        return next(node for node in ast.parse(source).body
                    if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "__name__ == '__main__'")

    def test_bootstrap_runs_before_anything_reads_state(self):
        body = self.main_block().body
        self.assertEqual(
            ast.unparse(body[0]),
            'panel_storage.bootstrap(DATA_FILE, app_dir=application_path, '
            'panel_version=CURRENT_VERSION)')
        first_read = next(index for index, node in enumerate(body)
                          if any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                                 and call.func.id == 'load_data' for call in ast.walk(node)))
        self.assertEqual(first_read, 1)
        self.assertEqual(ast.unparse(body[1]), 'data = load_data()')

    def test_uvicorn_overrides_extend_the_kwargs_before_launch(self):
        body = self.main_block().body
        lines = [ast.unparse(node) for node in body]
        update = lines.index('uvicorn_kwargs.update(panel_storage.uvicorn_overrides())')
        assigned = next(index for index, node in enumerate(body)
                        if isinstance(node, ast.Assign)
                        and ast.unparse(node.targets[0]) == 'uvicorn_kwargs')
        launch = next(index for index, node in enumerate(body)
                      if 'uvicorn.run(' in ast.unparse(node))
        self.assertEqual(update, assigned + 1)
        self.assertLess(update, launch)
        front = next(node for node in body if isinstance(node, ast.Assign)
                     and ast.unparse(node.targets[0]) == 'front_enabled')
        setup = ast.Module(body=[front, body[assigned], body[update]], type_ignores=[])
        code = compile(ast.fix_missing_locations(setup), str(ROOT / 'app.py'), 'exec')
        stub = SimpleNamespace(uvicorn_overrides=lambda: {'timeout_graceful_shutdown': 20})
        namespace = {'__builtins__': {}, 'app': object(), 'ssl_conf': {},
                     'internal_port': 5001, 'panel_bind_host': lambda ssl: '127.0.0.1',
                     'os': SimpleNamespace(environ={}), 'panel_storage': stub}
        exec(code, namespace)
        self.assertEqual(namespace['uvicorn_kwargs']['timeout_graceful_shutdown'], 20)
        self.assertEqual(namespace['uvicorn_kwargs']['port'], 5001)
        self.assertFalse(namespace['uvicorn_kwargs']['server_header'])


if __name__ == '__main__':
    unittest.main()
