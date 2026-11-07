"""Install-time IPv6 gate for POST /api/servers/{id}/install.

The tri-state server preference (True/False/None) decides the
``ipv6_preference`` passed to the AWG manager. Docker bridge IPv6 must be
enabled before an explicit "on" is allowed. An instance that will join the
default exit node is forced IPv4-only. The ``AWG_IPV6`` environment variable
is reported through /ip-status but does not change what the API passes.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


def base_server(**extra):
    server = {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
              'username': 'root', 'password': 'x', 'private_key': '',
              'server_info': {}, 'uid': 'srv-uid', 'protocols': {}}
    server.update(extra)
    return server


class InstallGateBase(unittest.TestCase):
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
        # No test may open a real SSH connection to the synthetic server.
        ssh_patch = mock.patch.object(panel, 'get_ssh', return_value=mock.Mock())
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)
        panel._invalidate_ip_status()
        self.addCleanup(panel._invalidate_ip_status)

    def write_server(self, server=None, settings=None):
        data = {'servers': [server or base_server()],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': []}
        if settings is not None:
            data['settings'] = settings
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def admin(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        return client

    def _patches(self, docker_on):
        """Patch the install dependencies and return (patches, manager)."""
        ssh = mock.Mock()
        manager = mock.Mock()
        manager._docker_ipv6_info.return_value = {'ipv6_enabled': docker_on,
                                                  'installed': True}
        manager.install_protocol.return_value = {
            'status': 'success', 'awg_params': {}, 'mtu': 1376, 'dns': ''}
        patches = [
            mock.patch.object(panel, 'get_ssh', return_value=ssh),
            mock.patch.object(panel, 'get_used_ports', return_value={}),
            mock.patch.object(panel, 'ensure_docker_installed', return_value=''),
            mock.patch.object(panel, 'get_protocol_manager', return_value=manager),
            mock.patch.object(panel.exit_link_svc, 'link',
                              new=mock.AsyncMock(side_effect=RuntimeError('skip'))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return manager

    def install(self, client, protocol='awg3'):
        return client.post('/api/servers/0/install', json={'protocol': protocol})


class InstallGateTests(InstallGateBase):
    def test_preference_true_docker_off_is_409_and_skips_install(self):
        self.write_server(base_server(ipv6_new_instances=True))
        manager = self._patches(docker_on=False)
        res = self.install(self.admin())
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'docker_pending')
        self.assertFalse(manager.install_protocol.called)

    def test_preference_true_docker_on_passes_true(self):
        self.write_server(base_server(ipv6_new_instances=True))
        manager = self._patches(docker_on=True)
        res = self.install(self.admin())
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], True)

    def test_preference_false_passes_false(self):
        self.write_server(base_server(ipv6_new_instances=False))
        manager = self._patches(docker_on=True)
        res = self.install(self.admin())
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)

    def test_preference_none_without_default_exit_passes_none(self):
        self.write_server(base_server())
        manager = self._patches(docker_on=True)
        res = self.install(self.admin())
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIsNone(kwargs['ipv6_preference'])

    def test_preference_none_with_default_exit_forces_false_and_logs(self):
        self.write_server(
            base_server(),
            settings={'exit_nodes': {'default_exit_uid': 'exit-uid'}})
        manager = self._patches(docker_on=True)
        res = self.install(self.admin())
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)
        log = res.json().get('log') or []
        self.assertTrue(any('IPv6' in str(line) for line in log),
                        f'no IPv6 line in install log: {log}')

    def test_env_override_does_not_change_api_and_is_reported(self):
        self.write_server(base_server(ipv6_new_instances=True))
        with mock.patch.dict('os.environ', {'AWG_IPV6': 'off'}):
            manager = self._patches(docker_on=True)
            res = self.install(self.admin())
            self.assertEqual(res.status_code, 200, res.text)
            kwargs = manager.install_protocol.call_args.kwargs
            self.assertIs(kwargs['ipv6_preference'], False)
            status = {'state': 'ok', 'error': None,
                      'host': {}, 'docker': {}, 'instances': []}
            with mock.patch.object(panel, 'AWGManager') as manager_cls:
                manager_cls.return_value.get_ip_status.return_value = status
                ip_status = self.admin().get('/api/servers/0/ip-status')
        self.assertEqual(ip_status.status_code, 200, ip_status.text)
        self.assertEqual(ip_status.json()['preference']['env_override'], 'off')


if __name__ == '__main__':
    unittest.main()
