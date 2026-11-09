"""HTTP contract of the IPv6 endpoints.

Covers permissions (support reads, admin writes), the tri-state server
preference, HTTP status mapping for blocked_reason and the install gates:
an explicit "on" needs Docker IPv6, an auto-linked instance stays IPv4-only.
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


def ipv6_state(**extra):
    """A ready instance state, as AWGManager would report it."""
    state = {'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
             'container': 'c', 'needs_recreate': False,
             'can_enable': True, 'can_disable': True}
    state.update(extra)
    return state


class Ipv6ApiBase(unittest.TestCase):
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

    def wait_op(self, op_id, timeout=5.0):
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            operation = panel._op_store().get(op_id)
            if operation and operation.get('state') != 'running':
                return operation
            time.sleep(0.02)
        self.fail(f'operation {op_id} did not finish')

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


class PreferenceTests(Ipv6ApiBase):
    def test_admin_sets_true_and_false(self):
        client = self.admin()
        res = client.post('/api/servers/0/ipv6', json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(res.json()['changed'])
        self.assertIs(res.json()['preference']['new_instances'], True)
        self.assertIs(self.read_data()['servers'][0]['ipv6_new_instances'], True)

        res = client.post('/api/servers/0/ipv6', json={'enabled': False})
        self.assertIs(res.json()['preference']['new_instances'], False)

    def test_null_restores_auto_and_removes_the_key(self):
        client = self.admin()
        client.post('/api/servers/0/ipv6', json={'enabled': True})
        res = client.post('/api/servers/0/ipv6', json={'enabled': None})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIsNone(res.json()['preference']['new_instances'])
        self.assertNotIn('ipv6_new_instances', self.read_data()['servers'][0])

    def test_repeated_request_is_a_no_op(self):
        client = self.admin()
        client.post('/api/servers/0/ipv6', json={'enabled': True})
        res = client.post('/api/servers/0/ipv6', json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertFalse(res.json()['changed'])

    def test_wrong_type_is_400_bad_request(self):
        res = self.admin().post('/api/servers/0/ipv6', json={'enabled': 'yes'})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 'bad_request')

    def test_env_override_is_reported(self):
        with mock.patch.dict('os.environ', {'AWG_IPV6': 'off'}):
            res = self.admin().post('/api/servers/0/ipv6', json={'enabled': True})
        self.assertEqual(res.json()['preference']['env_override'], 'off')

    def test_support_cannot_write(self):
        res = self.support().post('/api/servers/0/ipv6', json={'enabled': True})
        self.assertEqual(res.status_code, 403)
        self.assertNotIn('ipv6_new_instances', self.read_data()['servers'][0])

    def test_unknown_server_is_404(self):
        res = self.admin().post('/api/servers/9/ipv6', json={'enabled': True})
        self.assertEqual(res.status_code, 404)


class IpStatusTests(Ipv6ApiBase):
    def _status(self, can_write):
        return {'state': 'ok', 'error': None,
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
                               'container_running': True}]}

    def test_admin_gets_status_and_can_write(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = self._status(True)
            res = self.admin().get('/api/servers/0/ip-status')
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertTrue(body['can_write'])
        self.assertEqual(body['host']['ipv6_state'], 'in_use')
        self.assertEqual(body['instances'][0]['peers_v6'], 1)

    def test_support_reads_but_cannot_write(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = self._status(False)
            res = self.support().get('/api/servers/0/ip-status')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertFalse(res.json()['can_write'])

    def test_preference_is_included(self):
        self.write_data({'servers': [base_server(ipv6_new_instances=False)],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = self._status(True)
            res = self.admin().get('/api/servers/0/ip-status')
        self.assertIs(res.json()['preference']['new_instances'], False)


class DockerApplyTests(Ipv6ApiBase):
    def test_confirm_is_required(self):
        res = self.admin().post('/api/servers/0/docker/ipv6/apply', json={})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 'confirm_required')

    def test_support_cannot_apply(self):
        res = self.support().post('/api/servers/0/docker/ipv6/apply',
                                  json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 403)

    def test_bridge_failure_is_reported_on_the_operation(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.enable_docker_ipv6.side_effect = \
                RuntimeError('docker_bridge_ipv6_missing')
            res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                    json={'confirm': 'yes'})
            self.assertEqual(res.status_code, 202, res.text)
            operation = self.wait_op(res.json()['op_id'])
        self.assertEqual(operation['state'], 'failed')
        self.assertEqual(operation['reason'], 'docker_bridge_ipv6_missing')

    def test_invalid_daemon_json_is_reported_on_the_operation(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.enable_docker_ipv6.side_effect = \
                RuntimeError('daemon_json_invalid')
            res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                    json={'confirm': 'restart-docker'})
            self.assertEqual(res.status_code, 202, res.text)
            operation = self.wait_op(res.json()['op_id'])
        self.assertEqual(operation['reason'], 'daemon_json_invalid')

    def test_success_finishes_the_operation(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.enable_docker_ipv6.return_value = {
                'pending': False}
            res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                    json={'confirm': 'yes'})
            self.assertEqual(res.status_code, 202, res.text)
            operation = self.wait_op(res.json()['op_id'])
        self.assertEqual(operation['state'], 'done')

    def test_second_operation_is_busy(self):
        lock = panel._op_lock('srv-uid')
        lock.acquire()
        self.addCleanup(lock.release)
        res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 'operation_busy')

    def test_unknown_operation_is_404(self):
        res = self.admin().get('/api/servers/0/operations/does-not-exist')
        self.assertEqual(res.status_code, 404)

    def test_operation_is_pollable(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.enable_docker_ipv6.return_value = {}
            res = self.admin().post('/api/servers/0/docker/ipv6/apply',
                                    json={'confirm': 'yes'})
            op_id = res.json()['op_id']
            self.wait_op(op_id)
            polled = self.admin().get(f'/api/servers/0/operations/{op_id}')
        self.assertEqual(polled.status_code, 200)
        self.assertEqual(polled.json()['state'], 'done')


class InstanceToggleTests(Ipv6ApiBase):
    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_non_awg_protocol_is_400(self):
        res = self.admin().post('/api/servers/0/protocol/xray/ipv6',
                                json={'enabled': True})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 'not_awg')

    def test_missing_instance_is_404(self):
        res = self.admin().post('/api/servers/0/protocol/awg2/ipv6',
                                json={'enabled': True})
        self.assertEqual(res.status_code, 404)

    def test_peers_are_409(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.side_effect = \
                RuntimeError('peers')
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': False})
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 'peers')

    def test_support_cannot_toggle(self):
        res = self.support().post('/api/servers/0/protocol/awg3/ipv6',
                                  json={'enabled': True})
        self.assertEqual(res.status_code, 403)

    def test_unexpected_error_is_500_without_raw_text(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.side_effect = \
                RuntimeError('sed: cannot open /opt/amnezia/awg0.conf')
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': True})
        self.assertEqual(res.status_code, 500)
        self.assertEqual(res.json()['code'], 'internal_error')
        self.assertNotIn('sed:', res.json()['error'])

    def test_success_returns_instance_state(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.return_value = {
                'proto': 'awg3', 'ipv6_enabled': True, 'peers': 0}
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(res.json()['instance']['ipv6_enabled'])

    def test_rebuild_path_returns_202_and_completes(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state(needs_recreate=True, blocked_reason='needs_recreate')
            manager_cls.return_value.set_instance_ipv6.return_value = {}
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': True})
            self.assertEqual(res.status_code, 202, res.text)
            operation = self.wait_op(res.json()['op_id'])
        self.assertEqual(operation['state'], 'done')

    def test_repair_flag_is_passed_to_the_manager(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            instance = manager_cls.return_value
            instance.get_instance_ipv6_state.return_value = ipv6_state(peers=3)
            instance.set_instance_ipv6.return_value = {}
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': False, 'repair': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(instance.set_instance_ipv6.call_args.kwargs['allow_repair'])

    def test_multi_instance_name_is_accepted(self):
        self.write_data({'servers': [base_server(protocols={
            'awg3__2': {'installed': True}})],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': []})
        client = self.admin()
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.return_value = {}
            res = client.post('/api/servers/0/protocol/awg3__2/ipv6',
                              json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)

    def test_legacy_protocol_is_rejected(self):
        self.write_data({'servers': [base_server(protocols={
            'awg_legacy': {'installed': True}})],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': []})
        res = self.admin().post('/api/servers/0/protocol/awg_legacy/ipv6',
                                json={'enabled': True})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 'not_awg')


class InstallGatingTests(Ipv6ApiBase):
    def _patches(self, docker_on, install_result=None):
        ssh = mock.Mock()
        manager = mock.Mock()
        manager._docker_ipv6_info.return_value = {'ipv6_enabled': docker_on,
                                                  'installed': True}
        manager.install_protocol.return_value = install_result or {
            'status': 'success', 'awg_params': {}, 'mtu': 1376, 'dns': ''}
        return [
            mock.patch.object(panel, 'get_ssh', return_value=ssh),
            mock.patch.object(panel, 'get_used_ports', return_value={}),
            mock.patch.object(panel, 'ensure_docker_installed', return_value=''),
            mock.patch.object(panel, 'get_protocol_manager', return_value=manager),
            mock.patch.object(panel.exit_link_svc, 'link',
                              new=mock.AsyncMock(side_effect=RuntimeError('skip'))),
        ], manager

    def test_explicit_on_without_docker_is_409(self):
        self.write_data({'servers': [base_server(ipv6_new_instances=True)],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})
        patches, _manager = self._patches(docker_on=False)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        res = self.admin().post('/api/servers/0/install', json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'docker_pending')

    def test_explicit_off_forces_ipv4_only(self):
        self.write_data({'servers': [base_server(ipv6_new_instances=False)],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})
        patches, manager = self._patches(docker_on=True)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        res = self.admin().post('/api/servers/0/install', json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)

    def test_auto_linked_instance_forces_ipv4_only(self):
        data = {'servers': [base_server()],
                'settings': {'exit_nodes': {'default_exit_uid': 'exit-uid'}},
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': []}
        self.write_data(data)
        patches, manager = self._patches(docker_on=True)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        res = self.admin().post('/api/servers/0/install', json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)


if __name__ == '__main__':
    unittest.main()

