"""Admin API tokens work on every admin endpoint, with the owner's role.

README promises that ``Authorization: Bearer <token>`` is accepted wherever an
admin session is.  Five handlers predated tokens and checked the session only
(users add/delete/toggle, a user's connection list and connection config
export), and orphan recovery crashed on the missing session after its token
gate.  These tests drive the real routes with stored tokens and real session
logins against a temporary synthetic DATA_FILE; SSH is never opened.
"""
import ast
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

import app as panel


ADMIN_TOKEN = 'awp_admin-route-regression-token'
SUPPORT_TOKEN = 'awp_support-route-regression-token'


class ApiTokenAdminRouteTests(unittest.TestCase):
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

        ssh = mock.patch.object(panel, 'get_ssh',
                                side_effect=AssertionError('SSH is forbidden in tests'))
        ssh.start()
        self.addCleanup(ssh.stop)

        def user(uid, role):
            return {'id': uid + '-id', 'username': uid, 'role': role, 'enabled': True,
                    'password_hash': panel.hash_password(uid)}

        now = datetime.now().isoformat()

        def token(raw, owner):
            # Stored exactly as the panel stores it; a recent last_used_at keeps
            # _touch_api_token from rewriting the file during the request.
            return {'id': owner + '-token', 'name': owner, 'user_id': owner + '-id',
                    'token_hash': hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                    'token_prefix': raw[:len(panel.API_TOKEN_PREFIX) + 4],
                    'created_at': now, 'last_used_at': now}

        self.write_data({
            'servers': [{'uid': 'node-1', 'name': 'node', 'host': '192.0.2.10',
                         'ssh_port': 22, 'username': 'root',
                         'protocols': {'awg2': {'port': '55424'}}}],
            'users': [user('admin', 'admin'), user('support', 'support'),
                      user('alice', 'user'), user('bob', 'user')],
            'user_connections': [{'id': 'alice-conn', 'user_id': 'alice-id', 'server_id': 0,
                                  'protocol': 'awg2', 'client_id': 'alice-key',
                                  'name': 'alice-1'}],
            'api_tokens': [token(ADMIN_TOKEN, 'admin'), token(SUPPORT_TOKEN, 'support')],
        })

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as destination:
            json.dump(data, destination)

    def data(self):
        with open(panel.DATA_FILE, encoding='utf-8') as source:
            return json.load(source)

    def usernames(self):
        return {u['username'] for u in self.data()['users']}

    @staticmethod
    def bearer(raw):
        return {'Authorization': 'Bearer ' + raw}

    def login(self, client, username):
        response = client.post('/api/auth/login',
                               json={'username': username, 'password': username})
        self.assertEqual(response.status_code, 200, response.text)

    def fake_config_backend(self):
        """Stand-ins for the SSH/manager calls of the config export."""
        ssh = SimpleNamespace(connect=lambda: None, disconnect=lambda: None)
        return (mock.patch.object(panel, 'get_ssh', return_value=ssh),
                mock.patch.object(panel, 'get_protocol_manager', return_value=object()),
                mock.patch.object(panel, '_manager_call', return_value='[Interface]\n'),
                mock.patch.object(panel, 'config_payloads', return_value={}))

    # --- admin-only user management -------------------------------------

    def test_admin_token_can_add_user(self):
        with TestClient(panel.app) as client:
            response = client.post('/api/users/add', headers=self.bearer(ADMIN_TOKEN),
                                   json={'username': 'carol', 'role': 'none'})
            self.assertIsNone(client.cookies.get('session'))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('carol', self.usernames())

    def test_admin_token_can_delete_user_but_not_its_owner(self):
        with TestClient(panel.app) as client:
            deleted = client.post('/api/users/bob-id/delete', headers=self.bearer(ADMIN_TOKEN))
            own = client.post('/api/users/admin-id/delete', headers=self.bearer(ADMIN_TOKEN))
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertNotIn('bob', self.usernames())
        # The self-delete guard applies to the token owner as well.
        self.assertEqual(own.status_code, 400, own.text)
        self.assertIn('admin', self.usernames())

    def test_admin_token_can_toggle_user(self):
        with TestClient(panel.app) as client:
            response = client.post('/api/users/bob-id/toggle', headers=self.bearer(ADMIN_TOKEN),
                                   json={'enabled': False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {'status': 'success', 'enabled': False})
        bob = next(u for u in self.data()['users'] if u['id'] == 'bob-id')
        self.assertFalse(bob['enabled'])

    def test_support_token_still_cannot_manage_users(self):
        with TestClient(panel.app) as client:
            headers = self.bearer(SUPPORT_TOKEN)
            # Positive control: the support token itself is valid.
            control = client.get('/api/users', headers=headers)
            self.assertEqual(control.status_code, 200, control.text)
            before = self.data()  # after startup migrations
            responses = [
                client.post('/api/users/add', headers=headers, json={'username': 'carol'}),
                client.post('/api/users/bob-id/delete', headers=headers),
                client.post('/api/users/bob-id/toggle', headers=headers, json={'enabled': False}),
            ]
        self.assertEqual([r.status_code for r in responses], [403, 403, 403],
                         [r.text for r in responses])
        self.assertEqual(self.data()['users'], before['users'])

    def test_unknown_or_missing_token_is_rejected(self):
        with TestClient(panel.app) as client:
            for headers in ({}, self.bearer('awp_not-a-stored-token')):
                with self.subTest(headers=headers):
                    responses = [
                        client.post('/api/users/add', headers=headers, json={'username': 'x'}),
                        client.post('/api/users/bob-id/delete', headers=headers),
                        client.post('/api/users/bob-id/toggle', headers=headers,
                                    json={'enabled': False}),
                        client.get('/api/users/alice-id/connections', headers=headers),
                        client.post('/api/servers/0/connections/config', headers=headers,
                                    json={'protocol': 'awg2', 'client_id': 'alice-key'}),
                    ]
                    self.assertEqual({r.status_code for r in responses}, {403},
                                     [r.text for r in responses])
        self.assertEqual(self.usernames(), {'admin', 'support', 'alice', 'bob'})

    def test_admin_session_still_manages_users(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            added = client.post('/api/users/add', json={'username': 'carol', 'role': 'none'})
            self.assertEqual(added.status_code, 200, added.text)
            toggled = client.post(f"/api/users/{added.json()['user_id']}/toggle",
                                  json={'enabled': False})
        self.assertEqual(toggled.status_code, 200, toggled.text)

    # --- connection list and config export (owner or admin/support) -----

    def test_admin_and_support_tokens_can_list_any_users_connections(self):
        with TestClient(panel.app) as client:
            for raw in (ADMIN_TOKEN, SUPPORT_TOKEN):
                with self.subTest(token=raw):
                    response = client.get('/api/users/alice-id/connections',
                                          headers=self.bearer(raw))
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual([c['id'] for c in response.json()['connections']],
                                     ['alice-conn'])

    def test_regular_session_still_sees_only_own_connections(self):
        with TestClient(panel.app) as client:
            self.login(client, 'bob')
            own = client.get('/api/users/bob-id/connections')
            other = client.get('/api/users/alice-id/connections')
        self.assertEqual(own.status_code, 200, own.text)
        self.assertEqual(other.status_code, 403, other.text)

    def test_admin_and_support_tokens_can_export_connection_config(self):
        body = {'protocol': 'awg2', 'client_id': 'alice-key'}
        patches = self.fake_config_backend()
        with patches[0], patches[1], patches[2] as manager_call, patches[3], \
             TestClient(panel.app) as client:
            for raw in (ADMIN_TOKEN, SUPPORT_TOKEN):
                with self.subTest(token=raw):
                    response = client.post('/api/servers/0/connections/config',
                                           headers=self.bearer(raw), json=body)
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()['config'], '[Interface]\n')
        self.assertEqual(manager_call.call_count, 2)

    def test_regular_session_still_cannot_export_foreign_config(self):
        patches = self.fake_config_backend()
        with patches[0], patches[1], patches[2] as manager_call, patches[3], \
             TestClient(panel.app) as client:
            self.login(client, 'bob')
            response = client.post('/api/servers/0/connections/config',
                                   json={'protocol': 'awg2', 'client_id': 'alice-key'})
        self.assertEqual(response.status_code, 403, response.text)
        manager_call.assert_not_called()

    # --- audit actor for token callers ----------------------------------

    def test_orphan_recovery_with_token_records_token_owner(self):
        store = mock.Mock()
        store.replay.return_value = {'status': 'replayed'}
        body = {'operation_id': 'op-1', 'connection_id': 'alice-conn',
                'expected_digest': 'x', 'expected_peer_digest': 'y', 'mode': 'repair',
                'target_user_id': 'alice-id',
                'confirmation': 'RESTORE OWNERSHIP; USAGE IS UNVERIFIED'}
        with mock.patch.object(panel, 'RecoveryStore', return_value=store), \
             TestClient(panel.app) as client:
            response = client.post('/api/recovery/orphans', headers=self.bearer(ADMIN_TOKEN),
                                   json=body)
            unconfirmed = client.post('/api/recovery/orphans', headers=self.bearer(ADMIN_TOKEN),
                                      json=dict(body, confirmation='wrong'))
        # Previously a token caller crashed on the missing session: 503 every time.
        self.assertEqual(response.status_code, 200, response.text)
        # The token owner, not the 'admin' fallback used when no caller is known.
        self.assertEqual(store.replay.call_args.args[1], 'admin-id')
        self.assertEqual(unconfirmed.status_code, 409, unconfirmed.text)
        self.assertEqual(unconfirmed.json()['error'], 'explicit_confirmation_required')

    def test_actor_id_prefers_authorized_caller(self):
        no_session = SimpleNamespace(session={}, headers={})
        self.assertEqual(panel._actor_id(no_session, {'id': 'token-owner', 'role': 'admin'}),
                         'token-owner')
        # Tests and sentinels may authorize with a bare truthy value.
        self.assertEqual(panel._actor_id(no_session, True), 'admin')
        with mock.patch.object(panel, 'get_current_user', return_value={'id': 'session-id'}):
            self.assertEqual(panel._actor_id(no_session, True), 'session-id')


class TokenAwareGateGuardTests(unittest.TestCase):
    """Every admin JSON route must authorize through a token-aware helper."""

    TOKEN_AWARE = {'_check_admin', '_backup_admin', '_ssh_trust_admin', '_request_user'}
    # Session-only by design: login/captcha, a user's own data, password-shared links.
    SESSION_ONLY_PREFIXES = ('/api/auth/', '/api/my/', '/api/share/')
    # These read the session only to tell Bearer callers apart; both handle None.
    DIRECT_SESSION_READS = {'api_backup_archive', 'api_backup_restore'}

    def routes(self):
        tree = ast.parse(Path(panel.__file__).read_text(encoding='utf-8'))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Attribute)
                        and isinstance(decorator.func.value, ast.Name)
                        and decorator.func.value.id == 'app'
                        and decorator.args and isinstance(decorator.args[0], ast.Constant)):
                    path = decorator.args[0].value
                    if path.startswith('/api/') and not path.startswith(self.SESSION_ONLY_PREFIXES):
                        calls = {call.func.id for call in ast.walk(node)
                                 if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
                        yield path, node.name, calls

    def test_admin_routes_use_token_aware_authorization(self):
        routes = list(self.routes())
        self.assertGreater(len(routes), 100)
        missing = sorted(f'{path} ({name})' for path, name, calls in routes
                         if not calls & self.TOKEN_AWARE)
        self.assertEqual(missing, [], 'these routes reject API tokens')

    def test_admin_routes_do_not_read_session_identity_directly(self):
        direct = sorted(f'{path} ({name})' for path, name, calls in self.routes()
                        if 'get_current_user' in calls and name not in self.DIRECT_SESSION_READS)
        self.assertEqual(direct, [], 'use _request_user/_actor_id: Bearer requests have no session')


if __name__ == '__main__':
    unittest.main()
