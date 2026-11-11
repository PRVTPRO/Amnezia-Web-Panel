"""Non-secret inventory and UID-bound integration requests; no real SSH/state."""
import asyncio
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as panel
from integration_inventory import integration_inventory


def fixture():
    return {'servers': [{'uid': 'node-a', 'name': 'A', 'host': '192.0.2.1',
                         'username': 'admin', 'password': 'SECRET_CANARY',
                         'protocols': {'awg3__2': {'installed': True},
                                       'telemt': {'installed': True, 'secret': 'SECRET_CANARY'}}}],
            'users': [{'id': 'owner', 'password_hash': 'SECRET_CANARY',
                       'share_token': 'SECRET_CANARY'}],
            'user_connections': [{'id': 'connection', 'user_id': 'owner',
                                  'server_id': 0, 'protocol': 'awg3__2',
                                  'client_id': 'public-key', 'name': 'Device',
                                  'config': 'SECRET_CANARY'}],
            'api_tokens': [{'token': 'SECRET_CANARY'}]}


class IntegrationInventoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_whitelist_is_complete_and_does_not_mutate(self):
        data = fixture()
        before = copy.deepcopy(data)
        result = integration_inventory(data, panel.protocol_base)
        self.assertNotIn('SECRET_CANARY', json.dumps(result))
        self.assertEqual(result['servers'][0]['uid'], 'node-a')
        self.assertEqual(result['servers'][0]['protocols']['awg3__2']['base_protocol'], 'awg3')
        self.assertEqual(result['users'], [{'id': 'owner'}])
        self.assertTrue(result['complete'])
        self.assertEqual(data, before)

    async def test_invalid_or_ambiguous_identity_fails_closed(self):
        for mutate in (lambda d: d['servers'][0].pop('uid'),
                       lambda d: d['servers'].append(copy.deepcopy(d['servers'][0])),
                       lambda d: d['user_connections'].append(copy.deepcopy(d['user_connections'][0])),
                       lambda d: d['users'].clear(),
                       lambda d: d['servers'][0]['protocols']['awg3__2'].update(installed='true')):
            data = fixture()
            mutate(data)
            with self.assertRaises((ValueError, TypeError)):
                integration_inventory(data, panel.protocol_base)

    async def test_route_authorization_private_headers_and_no_remote_calls(self):
        for allowed in (False, True):
            with patch.object(panel, '_check_admin', return_value=allowed), \
                 patch.object(panel, 'load_data', return_value=fixture()) as load, \
                 patch.object(panel, 'get_ssh') as ssh, \
                 patch.object(panel, 'save_data') as save, \
                 patch.object(panel, 'DATA_LOCK', asyncio.Lock()):
                result = await panel.api_integration_inventory(SimpleNamespace())
                self.assertEqual(result.status_code, 200 if allowed else 403)
                self.assertIn('no-store', result.headers['cache-control'])
                self.assertNotIn(b'SECRET_CANARY', result.body)
                self.assertEqual(load.call_count, 1 if allowed else 0)
                ssh.assert_not_called()
                save.assert_not_called()

    async def test_route_rejects_partial_state_and_recovers(self):
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'load_data', side_effect=[{}, fixture()]), \
             patch.object(panel, 'DATA_LOCK', asyncio.Lock()):
            self.assertEqual((await panel.api_integration_inventory(SimpleNamespace())).status_code, 503)
            self.assertEqual((await panel.api_integration_inventory(SimpleNamespace())).status_code, 200)

    async def test_server_uid_is_forwarded_only_when_supplied(self):
        class Service:
            async def create(self, *args, **kwargs):
                self.options = kwargs
                raise panel.PeerCreateError('synthetic stop before SSH', 409)
        service = Service()
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'peer_creates', service):
            for uid in (None, '', 'node-a'):
                req = panel.AddUserConnectionRequest(server_id=0, protocol='awg3', server_uid=uid)
                result = await panel.api_add_user_connection(SimpleNamespace(), 'owner', req)
                self.assertEqual(result.status_code, 409)
                self.assertEqual(service.options, {} if uid is None else {'expected_server_uid': uid})


class ConfigIdentityTests(unittest.TestCase):
    def read(self, uid='node-a', after=None, fail=False):
        data = fixture()
        server = data['servers'][0]
        server['port'] = 12345
        request = SimpleNamespace()
        ssh = Mock()
        manager = Mock()
        with patch.object(panel, '_request_user', return_value={'id': 'owner', 'role': 'user'}), \
             patch.object(panel, 'load_data', side_effect=[data, after or data]), \
             patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint', return_value=('192.0.2.1', None)), \
             patch.object(panel, '_manager_call', side_effect=RuntimeError('synthetic') if fail else None,
                          return_value='synthetic config'), \
             patch.object(panel, 'config_payloads', return_value={}), \
             patch.object(panel, 'save_data') as save:
            result = panel.api_get_connection_config(request, 0, panel.ConnectionActionRequest(
                server_uid=uid, protocol='awg3__2', client_id='public-key'))
            save.assert_not_called()
        return result, ssh

    def test_config_read_is_read_only_and_uid_bound(self):
        result, ssh = self.read()
        self.assertEqual(result['config'], 'synthetic config')
        ssh.disconnect.assert_called_once()

    def test_uid_mismatch_prevents_ssh_including_empty_uid(self):
        for uid in ('', 'different-node'):
            result, ssh = self.read(uid)
            self.assertEqual(result.status_code, 409)
            ssh.connect.assert_not_called()

    def test_endpoint_change_during_read_discards_config(self):
        after = fixture()
        after['servers'][0]['host'] = '192.0.2.2'
        result, ssh = self.read(after=after)
        self.assertEqual(result.status_code, 409)
        self.assertNotIn(b'synthetic config', result.body)
        ssh.disconnect.assert_called_once()

    def test_exception_releases_ssh(self):
        result, ssh = self.read(fail=True)
        self.assertEqual(result.status_code, 500)
        ssh.disconnect.assert_called_once()

    def test_foreign_connection_denied_before_ssh(self):
        with patch.object(panel, '_request_user', return_value={'id': 'stranger', 'role': 'user'}), \
             patch.object(panel, 'load_data', return_value=fixture()), \
             patch.object(panel, 'get_ssh') as ssh:
            result = panel.api_get_connection_config(SimpleNamespace(), 0,
                panel.ConnectionActionRequest(server_uid='node-a', protocol='awg3__2', client_id='public-key'))
            self.assertEqual(result.status_code, 403)
            ssh.assert_not_called()


class InventoryHTTPTests(unittest.TestCase):
    """Use real session/Bearer authorization and middleware, synthetic storage."""

    def setUp(self):
        import hashlib
        from datetime import datetime
        from fastapi.testclient import TestClient

        self.data = fixture()
        password = panel.hash_password('synthetic-inventory-password')
        self.data['users'] = [
            {'id': uid, 'username': uid, 'password_hash': password,
             'role': role, 'enabled': True}
            for uid, role in [('owner', 'user'), ('admin', 'admin'),
                              ('support', 'support'), ('other', 'user')]]
        now = datetime.now().isoformat()
        self.token = panel.API_TOKEN_PREFIX + 'synthetic-inventory-token'
        self.data['api_tokens'] = [{
            'id': 'token', 'user_id': 'admin', 'name': 'Synthetic',
            'token_hash': hashlib.sha256(self.token.encode()).hexdigest(),
            'created_at': now, 'last_used_at': now}]
        self.stack = __import__('contextlib').ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(panel, 'load_data',
                                             side_effect=lambda: copy.deepcopy(self.data)))
        self.save = self.stack.enter_context(patch.object(panel, 'save_data'))
        self.ssh = self.stack.enter_context(patch.object(panel, 'get_ssh'))
        self.stack.enter_context(patch.object(panel, 'DATA_LOCK', asyncio.Lock()))
        self.client = TestClient(panel.app)
        self.addCleanup(self.client.close)

    def login(self, username):
        result = self.client.post('/api/auth/login', json={
            'username': username, 'password': 'synthetic-inventory-password'})
        self.assertEqual(result.status_code, 200)
        self.save.reset_mock()

    def check_private(self, response, status):
        self.assertEqual(response.status_code, status, response.text)
        self.assertIn('no-store', response.headers['cache-control'])
        self.assertNotIn('SECRET_CANARY', response.text)
        self.assertNotIn('password_hash', response.text)
        self.assertNotIn('token_hash', response.text)
        self.ssh.assert_not_called()
        self.save.assert_not_called()

    def test_anonymous_and_invalid_bearer_preserve_auth_contract(self):
        self.check_private(self.client.get('/api/integration/inventory'), 401)
        self.check_private(self.client.get('/api/integration/inventory', headers={
            'Authorization': 'Bearer invalid-synthetic-token'}), 403)

    def test_plain_user_session_cannot_read_other_owners(self):
        self.login('owner')
        self.check_private(self.client.get('/api/integration/inventory'), 403)

    def test_admin_and_support_sessions_receive_only_projection(self):
        for role in ('admin', 'support'):
            with self.subTest(role=role):
                self.client.cookies.clear()
                self.login(role)
                before = copy.deepcopy(self.data)
                response = self.client.get('/api/integration/inventory')
                self.check_private(response, 200)
                self.assertEqual(response.json(), integration_inventory(
                    self.data, panel.protocol_base))
                self.assertEqual(self.data, before)

    def test_bearer_inherits_current_owner_role_and_enabled_state(self):
        headers = {'Authorization': 'Bearer ' + self.token}
        self.check_private(self.client.get('/api/integration/inventory', headers=headers), 200)
        admin = next(u for u in self.data['users'] if u['id'] == 'admin')
        admin['enabled'] = False
        self.check_private(self.client.get('/api/integration/inventory', headers=headers), 403)
        admin.update(enabled=True, role='user')
        self.check_private(self.client.get('/api/integration/inventory', headers=headers), 403)

    def test_incomplete_metadata_fails_closed_then_recovers(self):
        self.login('admin')
        before = copy.deepcopy(self.data)
        self.data['servers'][0].pop('uid')
        self.check_private(self.client.get('/api/integration/inventory'), 503)
        self.data = before
        self.check_private(self.client.get('/api/integration/inventory'), 200)
