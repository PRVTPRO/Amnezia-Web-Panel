"""Tests for the compact enrollment flow's connection-test endpoint.

`POST /api/servers/test` must pin an unknown host key (TOFU), refuse a changed
key until it is explicitly confirmed, test authentication without saving the
server, and stay administrator-only.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import paramiko
from fastapi.testclient import TestClient

import app as panel


class PanelTestBase:
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)

        self._monitor_started = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._monitor_started)

        users = [
            {'id': 'admin-id', 'username': 'admin',
             'password_hash': panel.hash_password('admin'),
             'role': 'admin', 'enabled': True},
            {'id': 'support-id', 'username': 'support',
             'password_hash': panel.hash_password('support'),
             'role': 'support', 'enabled': True},
        ]
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [], 'users': users, 'user_connections': []}, f)

    def login(self, client, username):
        response = client.post('/api/auth/login',
                               json={'username': username, 'password': username})
        self.assertEqual(response.status_code, 200, response.text)

    def payload(self):
        return {
            'name': 'synthetic',
            'host': '192.0.2.10',
            'ssh_port': 2222,
            'username': 'root',
            'password': 'synthetic-password',
        }

    def inspection(self, status):
        result = {
            'host': '192.0.2.10', 'port': 2222,
            'algorithm': 'ssh-ed25519',
            'fingerprint': 'SHA256:synthetic',
            'old_fingerprints': [], 'status': status,
        }
        if status != 'trusted':
            result['token'] = 'synthetic-token'
        if status == 'changed':
            result['old_fingerprints'] = [
                {'algorithm': 'ssh-ed25519', 'fingerprint': 'SHA256:old'}]
        return result

    def fake_ssh(self):
        ssh = mock.MagicMock()
        ssh.test_connection.return_value = {'hostname': 'synthetic'}
        return ssh


class ServerTestEndpointTests(PanelTestBase, unittest.TestCase):
    def test_unknown_key_is_pinned_then_credentials_are_tested(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            ssh = self.fake_ssh()
            with mock.patch.object(panel.ssh_trust, 'inspect',
                                   return_value=self.inspection('unknown')) as inspect, \
                    mock.patch.object(panel.ssh_trust, 'enroll') as enroll, \
                    mock.patch.object(panel, 'SSHManager', return_value=ssh) as manager:
                response = client.post('/api/servers/test', json=self.payload())

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body['status'], 'success')
        self.assertEqual(body['host_key']['status'], 'pinned')
        inspect.assert_called_once()
        enroll.assert_called_once()
        manager.assert_called_once_with('192.0.2.10', 2222, 'root',
                                        'synthetic-password', '')
        ssh.connect.assert_called_once()
        ssh.disconnect.assert_called_once()
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            self.assertEqual(json.load(f)['servers'], [],
                             'the test endpoint must never save a server')

    def test_changed_key_blocks_before_authentication(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            with mock.patch.object(panel.ssh_trust, 'inspect',
                                   return_value=self.inspection('changed')) as inspect, \
                    mock.patch.object(panel.ssh_trust, 'enroll') as enroll, \
                    mock.patch.object(panel, 'SSHManager') as manager:
                response = client.post('/api/servers/test', json=self.payload())

        self.assertEqual(response.status_code, 409, response.text)
        body = response.json()
        self.assertEqual(body['error_code'], 'host_key_changed')
        self.assertEqual(body['host_key']['status'], 'changed')
        self.assertEqual(body['host_key']['token'], 'synthetic-token')
        inspect.assert_called_once()
        enroll.assert_not_called()
        manager.assert_not_called()

    def test_trusted_key_skips_pinning_and_tests_authentication(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            ssh = self.fake_ssh()
            with mock.patch.object(panel.ssh_trust, 'inspect',
                                   return_value=self.inspection('trusted')), \
                    mock.patch.object(panel.ssh_trust, 'enroll') as enroll, \
                    mock.patch.object(panel, 'SSHManager', return_value=ssh):
                response = client.post('/api/servers/test', json=self.payload())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['host_key']['status'], 'trusted')
        enroll.assert_not_called()
        ssh.connect.assert_called_once()

    def test_authentication_failure_is_classified(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            ssh = self.fake_ssh()
            ssh.connect.side_effect = paramiko.AuthenticationException('denied')
            with mock.patch.object(panel.ssh_trust, 'inspect',
                                   return_value=self.inspection('trusted')), \
                    mock.patch.object(panel, 'SSHManager', return_value=ssh):
                response = client.post('/api/servers/test', json=self.payload())

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['error_code'], 'authentication_failed')

    def test_support_cannot_test_a_connection(self):
        with TestClient(panel.app) as client:
            self.login(client, 'support')
            with mock.patch.object(panel.ssh_trust, 'inspect') as inspect, \
                    mock.patch.object(panel, 'SSHManager') as manager:
                response = client.post('/api/servers/test', json=self.payload())

        self.assertEqual(response.status_code, 403, response.text)
        inspect.assert_not_called()
        manager.assert_not_called()

    def test_missing_credentials_are_rejected_before_any_ssh(self):
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            body = self.payload()
            body['password'] = ''
            with mock.patch.object(panel.ssh_trust, 'inspect') as inspect, \
                    mock.patch.object(panel, 'SSHManager') as manager:
                response = client.post('/api/servers/test', json=body)

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['error_code'], 'validation_error')
        inspect.assert_not_called()
        manager.assert_not_called()


class ServerPingTrustTests(PanelTestBase, unittest.TestCase):
    """The card warning icon needs a live changed/unknown/trusted signal."""

    def setUp(self):
        super().setUp()
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            data = json.load(f)
        data['servers'] = [{
            'uid': 'server-uid', 'name': 'synthetic', 'host': '192.0.2.10',
            'ssh_port': 2222, 'username': 'root', 'password': 'synthetic',
            'private_key': '', 'protocols': {},
        }]
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def test_ping_returns_live_host_key_state_and_details(self):
        writer = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()
        reader = mock.MagicMock()
        with TestClient(panel.app) as client:
            self.login(client, 'admin')
            with mock.patch.object(panel.asyncio, 'open_connection',
                                   new=mock.AsyncMock(return_value=(reader, writer))), \
                    mock.patch.object(panel.ssh_trust, 'inspect',
                                      return_value=self.inspection('changed')):
                response = client.get('/api/servers/0/ping')

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['alive'])
        self.assertEqual(body['ssh_trust'], 'changed')
        self.assertEqual(body['ssh_trust_detail']['token'], 'synthetic-token')
        self.assertFalse(body['ssh_verified'])


if __name__ == '__main__':
    unittest.main()
