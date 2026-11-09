"""SSH jump-host settings and transport routing regressions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import paramiko
from fastapi.testclient import TestClient

import app as panel
from managers.ssh_manager import SSHManager


ROOT = Path(__file__).resolve().parents[1]


def server(uid, host):
    return {
        'uid': uid, 'name': uid, 'host': host, 'ssh_port': 22,
        'username': 'root', 'password': 'secret', 'private_key': '',
        'protocols': {},
    }


class JumpTransportTests(unittest.TestCase):
    def test_target_connects_through_jump_transport(self):
        jump = SSHManager('jump.example', 22, 'jump', password='jump-secret')
        jump.client = mock.Mock()
        jump_transport = mock.Mock()
        jump_transport.is_active.return_value = True
        jump.client.get_transport.return_value = jump_transport
        channel = object()
        jump_transport.open_channel.return_value = channel

        target = SSHManager('target.example', 2222, 'root', password='target-secret',
                            jump_manager=jump)
        target_client = mock.Mock()
        with mock.patch.object(paramiko, 'SSHClient', return_value=target_client):
            target._connect_once()

        jump.ensure_connected = mock.Mock()
        jump_transport.open_channel.assert_called_once_with(
            'direct-tcpip', ('target.example', 2222), ('127.0.0.1', 0))
        self.assertIs(target_client.connect.call_args.kwargs['sock'], channel)
        self.assertEqual(target_client.connect.call_args.kwargs['hostname'], 'target.example')

    def test_jump_connect_failure_prevents_target_authentication(self):
        jump = mock.Mock()
        jump.ensure_connected.side_effect = OSError('jump unavailable')
        target = SSHManager('target.example', 22, 'root', password='target-secret',
                            jump_manager=jump)
        target_client = mock.Mock()
        with mock.patch.object(paramiko, 'SSHClient', return_value=target_client), \
             self.assertRaisesRegex(OSError, 'jump unavailable'):
            target._connect_once()
        target_client.connect.assert_not_called()

    def test_host_key_probe_uses_jump_channel_without_target_authentication(self):
        jump = mock.Mock()
        transport = mock.Mock()
        transport.is_active.return_value = True
        channel = mock.MagicMock()
        transport.open_channel.return_value = channel
        jump.client.get_transport.return_value = transport
        target_transport = mock.Mock()
        target_transport.get_remote_server_key.return_value = mock.sentinel.key
        with mock.patch.object(paramiko, 'Transport', return_value=target_transport):
            key = panel.ssh_trust.probe('target.example', 22, jump)
        self.assertIs(key, mock.sentinel.key)
        transport.open_channel.assert_called_once_with(
            'direct-tcpip', ('target.example', 22), ('127.0.0.1', 0))
        target_transport.start_client.assert_called_once_with(timeout=10)


class JumpSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'data.json'
        self.data = {
            'servers': [server('jump', 'jump.example'), server('target', 'target.example')],
            'users': [{'id': 'admin', 'username': 'admin', 'role': 'admin', 'enabled': True,
                       'password_hash': panel.hash_password('admin')}],
            'user_connections': [],
            'settings': {},
        }
        self.path.write_text(json.dumps(self.data), encoding='utf-8')
        self.old_data_file = panel.DATA_FILE
        panel.DATA_FILE = str(self.path)
        self.addCleanup(setattr, panel, 'DATA_FILE', self.old_data_file)
        self.old_monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self.old_monitor)
        panel._SSH_POOL.clear()
        self.addCleanup(panel._SSH_POOL.clear)

    def login(self, client):
        result = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(result.status_code, 200, result.text)

    def payload(self, jump_host_uid=''):
        return {
            'appearance': {}, 'sync': {}, 'captcha': {}, 'telegram': {},
            'ssl': {}, 'mail': {}, 'auto_backup': {}, 'self_service': {},
            'exit_nodes': {}, 'ssh_jump': {'jump_host_uid': jump_host_uid},
        }

    def test_default_is_off_and_legacy_data_migrates_twice(self):
        first = panel.load_data()
        second = panel.load_data()
        expected = {'jump_host_uid': ''}
        self.assertEqual(first['settings']['ssh_jump'], expected)
        self.assertEqual(second['settings']['ssh_jump'], expected)

    def test_settings_round_trip_accepts_existing_uid_and_rejects_missing_uid(self):
        with TestClient(panel.app) as client:
            self.login(client)
            saved = client.post('/api/settings/save', json=self.payload('jump'))
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(panel.load_data()['settings']['ssh_jump'], {'jump_host_uid': 'jump'})
            rejected = client.post('/api/settings/save', json=self.payload('missing'))
            self.assertEqual(rejected.status_code, 400, rejected.text)
            self.assertEqual(panel.load_data()['settings']['ssh_jump'], {'jump_host_uid': 'jump'})

    def test_get_ssh_uses_selected_jump_but_never_routes_jump_through_itself(self):
        data = panel.load_data()
        data['settings']['ssh_jump'] = {'jump_host_uid': 'jump'}
        panel.save_data(data)
        with mock.patch.object(SSHManager, 'ensure_connected'):
            target = panel.get_ssh(data['servers'][1])
            selected_jump = panel.get_ssh(data['servers'][0])
        self.assertIsNotNone(target.jump_manager)
        self.assertEqual(target.jump_manager.host, 'jump.example')
        self.assertIsNone(selected_jump.jump_manager)

    def test_pool_identity_changes_when_jump_setting_changes(self):
        data = panel.load_data()
        with mock.patch.object(SSHManager, 'ensure_connected'):
            direct = panel.get_ssh(data['servers'][1])
            data['settings']['ssh_jump'] = {'jump_host_uid': 'jump'}
            panel.save_data(data)
            jumped = panel.get_ssh(data['servers'][1])
        self.assertIsNot(direct, jumped)

    def test_ad_hoc_manager_resolves_jump_for_telegram_and_connection_services(self):
        data = panel.load_data()
        data['settings']['ssh_jump'] = {'jump_host_uid': 'jump'}
        panel.save_data(data)
        target = SSHManager('target.example', 22, 'root', password='target-secret')
        self.assertIsNotNone(target.jump_manager)
        self.assertEqual(target.jump_manager.host, 'jump.example')
        selected_jump = SSHManager('jump.example', 22, 'root', password='jump-secret')
        self.assertIsNone(selected_jump.jump_manager)

    def test_new_unmanaged_server_stays_direct_during_enrollment(self):
        data = panel.load_data()
        data['settings']['ssh_jump'] = {'jump_host_uid': 'jump'}
        panel.save_data(data)
        new_server = SSHManager('new.example', 22, 'root', password='new-secret')
        self.assertIsNone(new_server.jump_manager)
        self.assertIsNone(panel._resolve_ssh_trust_jump(
            {'host': 'new.example', 'ssh_port': 22, 'username': 'root'}))

    def test_settings_page_renders_off_and_existing_servers_and_submits_uid(self):
        template = (ROOT / 'templates' / 'settings.html').read_text(encoding='utf-8')
        self.assertIn('id="ssh_jump_host_uid"', template)
        self.assertIn("value=\"\"", template)
        self.assertIn("for s in servers", template)
        self.assertIn("jump_host_uid: document.getElementById('ssh_jump_host_uid').value", template)
        self.assertIn('ssh_jump, exit_nodes', template)


if __name__ == '__main__':
    unittest.main()
