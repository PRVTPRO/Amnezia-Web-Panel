"""Security and HTTP-contract tests for the IPv6 endpoints.

These tests pin the protection rules of design/server-ipv6-spec.md:
cross-origin writes are refused, a Bearer admin token passes while support
may only read, the status response never echoes secrets, the status cache
turns two polls into one manager call, and every blocked_reason reported by
set_instance_ipv6 maps to its documented HTTP status.

Nothing here touches a real host: SSH is mocked and the manager is a Mock.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


CROSS_SITE = {'Origin': 'https://evil.test', 'Sec-Fetch-Site': 'cross-site'}

# Reasons from AWGManager.set_instance_ipv6 and the status each documents.
DOCUMENTED_REASONS = {
    'peers': 409,
    'exit_link': 409,
    'server_off': 409,
    'docker_off': 409,
    'needs_recreate': 409,
    'state_unreadable': 409,
    'ipv6_pool_exhausted': 409,
    'peers_appeared': 409,
}


def base_server(**extra):
    server = {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
              'username': 'root', 'password': 'x', 'private_key': '',
              'server_info': {}, 'uid': 'srv-uid', 'protocols': {}}
    server.update(extra)
    return server


def ipv6_state(**extra):
    """A ready instance state, as AWGManager would report it."""
    state = {'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
             'container': 'c', 'needs_recreate': False,
             'can_enable': True, 'can_disable': True}
    state.update(extra)
    return state


def status_payload():
    """A fresh /ip-status payload, as AWGManager.get_ip_status would return."""
    return {
        'state': 'ok', 'error': None,
        'host': {'ipv4': '', 'ipv6': '2a0a:9300:1:5::1',
                 'ipv4_state': 'in_use', 'ipv6_state': 'in_use',
                 'ipv6_default_route': True},
        'docker': {'installed': True, 'ipv6_enabled': True,
                   'bridge_ipv6': True, 'daemon_json_present': True,
                   'restart_required': False, 'ip6tables_ok': True},
        'instances': [{'proto': 'awg3', 'peers': 3, 'peers_v6': 1,
                       'ipv6_enabled': True, 'subnet_v4': '10.8.1.1',
                       'subnet_v6': 'fd42:8:1::1', 'blocked_reason': 'peers',
                       'can_enable': False, 'can_disable': False,
                       'container_running': True}],
    }


class Ipv6ContractBase(unittest.TestCase):
    server_extra = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self._data_file)
        self._monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._monitor)
        self.write_data({
            'servers': [base_server(**self.server_extra)],
            'users': [
                {'id': 'admin-id', 'username': 'admin',
                 'password_hash': panel.hash_password('admin'),
                 'role': 'admin', 'enabled': True},
                {'id': 'support-id', 'username': 'support',
                 'password_hash': panel.hash_password('support'),
                 'role': 'support', 'enabled': True},
            ],
            'user_connections': [],
        })
        # No test may open a real SSH connection to the synthetic server.
        ssh_patch = mock.patch.object(panel, 'get_ssh', return_value=mock.Mock())
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)
        # The status cache is process-wide: never leak one test into another.
        panel._invalidate_ip_status()
        self.addCleanup(panel._invalidate_ip_status)

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def read_data(self):
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            return json.load(f)

    def client(self, username, password):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': username, 'password': password})
        self.assertEqual(res.status_code, 200, res.text)
        return client

    def admin(self):
        return self.client('admin', 'admin')

    def support(self):
        return self.client('support', 'support')

    def admin_token(self):
        """Plant a bearer token owned by the admin user; return its raw value."""
        raw = panel._generate_api_token()
        data = self.read_data()
        data.setdefault('api_tokens', []).append({
            'id': 'tok-contract', 'name': 'contract',
            'token_hash': panel._hash_api_token(raw),
            'token_prefix': raw[:len(panel.API_TOKEN_PREFIX) + 4],
            'user_id': 'admin-id', 'created_at': '2026-01-01T00:00:00',
            'last_used_at': None,
        })
        self.write_data(data)
        return raw

    def bearer(self, token):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        client.headers.update({'Authorization': f'Bearer {token}'})
        return client

    def admin_client_for(self, token):
        return self.bearer(token)


class CrossOriginWriteTests(Ipv6ContractBase):
    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_cross_site_preference_write_is_403(self):
        res = self.admin().post('/api/servers/0/ipv6', json={'enabled': True},
                                headers=CROSS_SITE)
        self.assertEqual(res.status_code, 403, res.text)
        self.assertNotIn('ipv6_new_instances', self.read_data()['servers'][0])

    def test_cross_site_docker_apply_is_403(self):
        res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                json={'confirm': 'yes'}, headers=CROSS_SITE)
        self.assertEqual(res.status_code, 403, res.text)

    def test_cross_site_instance_toggle_is_403(self):
        res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                json={'enabled': True}, headers=CROSS_SITE)
        self.assertEqual(res.status_code, 403, res.text)


class BearerTokenTests(Ipv6ContractBase):
    def test_bearer_admin_reads_status(self):
        token = self.admin_token()
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = status_payload()
            res = self.bearer(token).get('/api/servers/0/ip-status')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(res.json()['can_write'])

    def test_bearer_admin_writes_preference(self):
        token = self.admin_token()
        res = self.bearer(token).post('/api/servers/0/ipv6',
                                      json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(res.json()['changed'])
        self.assertIs(self.read_data()['servers'][0]['ipv6_new_instances'], True)


class SupportRoleTests(Ipv6ContractBase):
    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_support_reads_status_without_write(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = status_payload()
            res = self.support().get('/api/servers/0/ip-status')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertFalse(res.json()['can_write'])

    def test_support_cannot_write_preference(self):
        res = self.support().post('/api/servers/0/ipv6', json={'enabled': True})
        self.assertEqual(res.status_code, 403, res.text)
        self.assertNotIn('ipv6_new_instances', self.read_data()['servers'][0])

    def test_support_cannot_apply_docker_ipv6(self):
        res = self.support().post('/api/servers/0/docker/ipv6/apply',
                                  json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 403, res.text)

    def test_support_cannot_toggle_instance(self):
        res = self.support().post('/api/servers/0/protocol/awg3/ipv6',
                                  json={'enabled': True})
        self.assertEqual(res.status_code, 403, res.text)


class SecretLeakTests(Ipv6ContractBase):
    def test_status_never_echoes_secrets(self):
        self.write_data({
            'servers': [base_server(password='LEAK-server-password',
                                    private_key='LEAK-private-key',
                                    protocols={'awg3': {'installed': True}})],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [],
        })
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = status_payload()
            res = self.admin().get('/api/servers/0/ip-status')
        self.assertEqual(res.status_code, 200, res.text)
        text = res.text
        self.assertNotIn('PrivateKey', text)
        self.assertNotIn('PresharedKey', text)
        self.assertNotIn('LEAK-server-password', text)
        self.assertNotIn('LEAK-private-key', text)


class StatusCacheTests(Ipv6ContractBase):
    def test_two_polls_hit_manager_once(self):
        client = self.admin()
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = status_payload()
            first = client.get('/api/servers/0/ip-status')
            second = client.get('/api/servers/0/ip-status')
            calls = manager_cls.return_value.get_ip_status.call_count
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json()['state'], 'ok')
        self.assertEqual(calls, 1)


class BlockedReasonMappingTests(Ipv6ContractBase):
    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_each_blocked_reason_maps_to_its_status(self):
        client = self.admin()
        for reason, expected in DOCUMENTED_REASONS.items():
            with self.subTest(reason=reason):
                with mock.patch.object(panel, 'AWGManager') as manager_cls:
                    manager = manager_cls.return_value
                    manager.get_instance_ipv6_state.return_value = \
                        ipv6_state(blocked_reason=reason)
                    manager.set_instance_ipv6.side_effect = RuntimeError(reason)
                    res = client.post('/api/servers/0/protocol/awg3/ipv6',
                                      json={'enabled': False})
                self.assertEqual(res.status_code, expected, res.text)
                self.assertEqual(res.json()['code'], reason)


if __name__ == '__main__':
    unittest.main()
