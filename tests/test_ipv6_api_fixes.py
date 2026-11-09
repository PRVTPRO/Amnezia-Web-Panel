"""Focused regression tests for the HTTP-layer defects B1-B11.

Each test pins one confirmed defect from the review of the IPv6 API:
bad-body status mapping, op-lock release, instance-name validation,
precondition ordering, cache invalidation and TTL, lifecycle serialization,
error text leaks, reinstall inheritance and the Docker install gate.

No real host is touched: SSH and every manager are Mocks.
"""
import asyncio
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import httpx
from fastapi.testclient import TestClient

import app as panel
import peer_lifecycle_lock


def base_server(**extra):
    server = {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
              'username': 'root', 'password': 'x', 'private_key': '',
              'server_info': {}, 'uid': 'srv-uid', 'protocols': {}}
    server.update(extra)
    return server


def ipv6_state(**extra):
    state = {'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
             'container': 'c', 'needs_recreate': False,
             'can_enable': True, 'can_disable': True}
    state.update(extra)
    return state


def status_payload(state='ok', error=None):
    return {'state': state, 'error': error,
            'host': {'ipv4': '', 'ipv6': '2a0a:9300:1:5::1',
                     'ipv4_state': 'in_use', 'ipv6_state': 'in_use',
                     'ipv6_default_route': True},
            'docker': {'installed': True, 'ipv6_enabled': True,
                       'bridge_ipv6': True, 'daemon_json_present': True,
                       'restart_required': False, 'ip6tables_ok': True},
            'instances': []}


class Ipv6FixesBase(unittest.TestCase):
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
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [],
        })
        ssh_patch = mock.patch.object(panel, 'get_ssh', return_value=mock.Mock())
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)
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

    def admin(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        return client

class BadBodyTests(Ipv6FixesBase):
    """B1: malformed IPv6 bodies are 400 bad_request, others stay 422."""

    def test_bad_bodies_are_400_bad_request(self):
        client = self.admin()
        for name, kwargs in (
            ('no body', {'content': b''}),
            ('broken json', {'content': b'{'}),
            ('array', {'json': []}),
        ):
            with self.subTest(name=name):
                res = client.post('/api/servers/0/ipv6', **kwargs)
                self.assertEqual(res.status_code, 400, res.text)
                self.assertEqual(res.json()['code'], 'bad_request')

        res = client.post('/api/servers/0/protocol/awg3/ipv6', content=b'{')
        self.assertEqual(res.status_code, 400, res.text)
        res = client.post('/api/servers/0/docker/ipv6/apply', content=b'[')
        self.assertEqual(res.status_code, 400, res.text)

    def test_other_endpoints_keep_422(self):
        res = self.admin().post('/api/users/add', json={})
        self.assertEqual(res.status_code, 422, res.text)


class DockerApplyLockTests(Ipv6FixesBase):
    """B2: a failed store.create must not leave the op lock taken."""

    def test_create_failure_releases_the_lock(self):
        client = self.admin()
        store = panel._op_store()
        with mock.patch.object(store, 'create', side_effect=OSError('disk full')):
            res = client.post('/api/servers/0/docker/ipv6/apply',
                              json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 500, res.text)
        self.assertEqual(res.json()['code'], 'internal_error')

        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.enable_docker_ipv6.return_value = {}
            res = client.post('/api/servers/0/docker/ipv6/apply',
                              json={'confirm': 'yes'})
            self.assertEqual(res.status_code, 202, res.text)
            self.wait_op(res.json()['op_id'])


class SwitchableProtocolTests(Ipv6FixesBase):
    """B3: awg3__6 and higher are valid instances, awg_legacy is not."""

    def test_high_multi_instance_is_accepted(self):
        self.write_data({'servers': [base_server(protocols={'awg3__6': {}})],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.return_value = {}
            res = self.admin().post('/api/servers/0/protocol/awg3__6/ipv6',
                                    json={'enabled': True})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertNotEqual(res.json().get('code'), 'not_awg')

    def test_legacy_is_still_not_awg(self):
        self.write_data({'servers': [base_server(protocols={'awg_legacy': {}})],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})
        res = self.admin().post('/api/servers/0/protocol/awg_legacy/ipv6',
                                json={'enabled': True})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 'not_awg')


class InstancePreconditionTests(Ipv6FixesBase):
    """B4: a blocked enable is 409 before any 202 operation starts."""

    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_peers_with_needs_recreate_is_409_and_starts_no_operation(self):
        client = self.admin()
        with mock.patch.object(panel, 'AWGManager') as manager_cls, \
                mock.patch.object(panel, '_op_store') as store:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state(peers=3, needs_recreate=True, blocked_reason='peers')
            res = client.post('/api/servers/0/protocol/awg3/ipv6',
                              json={'enabled': True})
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'peers')
        store.assert_not_called()

    def test_needs_recreate_alone_still_returns_202(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state(needs_recreate=True, blocked_reason='needs_recreate')
            manager_cls.return_value.set_instance_ipv6.return_value = {}
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': True})
            self.assertEqual(res.status_code, 202, res.text)
            self.wait_op(res.json()['op_id'])

class CacheInvalidationTests(Ipv6FixesBase):
    """B5: every IPv6-relevant mutation drops the /ip-status entry."""

    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def _assert_invalidated(self, mutate):
        panel._invalidate_ip_status()
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_ip_status.return_value = status_payload()
            client = self.admin()
            first = client.get('/api/servers/0/ip-status')
            self.assertEqual(first.status_code, 200, first.text)
            mutate(client)
            second = client.get('/api/servers/0/ip-status')
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(manager_cls.return_value.get_ip_status.call_count, 2)

    def _container_toggle(self, client):
        ssh = mock.Mock()
        ssh.run_sudo_command.return_value = ('false', '', '')
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.post('/api/servers/0/container/toggle',
                              json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)

    def test_container_toggle(self):
        self._assert_invalidated(self._container_toggle)

    def test_exit_link(self):
        def mutate(client):
            with mock.patch.object(panel.exit_link_svc, 'link',
                                   new=mock.AsyncMock(return_value={})):
                res = client.post('/api/servers/0/exit-link',
                                  json={'protocol': 'awg3', 'exit_uid': 'e'})
            self.assertEqual(res.status_code, 200, res.text)
        self._assert_invalidated(mutate)

    def test_exit_unlink(self):
        def mutate(client):
            with mock.patch.object(panel.exit_link_svc, 'unlink',
                                   new=mock.AsyncMock(return_value={})):
                res = client.post('/api/servers/0/exit-link/remove',
                                  json={'protocol': 'awg3'})
            self.assertEqual(res.status_code, 200, res.text)
        self._assert_invalidated(mutate)

    def test_exit_relink(self):
        def mutate(client):
            with mock.patch.object(panel.exit_link_svc, 'relink_entry',
                                   new=mock.AsyncMock(return_value={})):
                res = client.post('/api/servers/0/exit-link/relink',
                                  json={'protocol': 'awg3'})
            self.assertEqual(res.status_code, 200, res.text)
        self._assert_invalidated(mutate)

    def test_exit_failover(self):
        def mutate(client):
            with mock.patch.object(panel.exit_link_svc, 'configure_failover',
                                   new=mock.AsyncMock(return_value={})):
                res = client.post('/api/servers/0/exit-link/failover',
                                  json={'protocol': 'awg3', 'enabled': True})
            self.assertEqual(res.status_code, 200, res.text)
        self._assert_invalidated(mutate)

    def test_connections_toggle(self):
        def mutate(client):
            manager = mock.Mock()
            with mock.patch.object(panel, 'get_protocol_manager',
                                   return_value=manager):
                res = client.post('/api/servers/0/connections/toggle',
                                  json={'protocol': 'awg3',
                                        'client_id': 'c', 'enable': True})
            self.assertEqual(res.status_code, 200, res.text)
        self._assert_invalidated(mutate)


class LifecycleDecoratorTests(Ipv6FixesBase):
    """B6: the instance switch takes the peer lifecycle interlock."""

    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_decorator_is_present(self):
        self.assertTrue(hasattr(panel.api_instance_ipv6, '__wrapped__'))

    def test_busy_lifecycle_is_reported_unchanged(self):
        async def scenario():
            lock = peer_lifecycle_lock._mutation_locks.setdefault(
                asyncio.get_running_loop(), asyncio.Lock())
            await lock.acquire()
            try:
                transport = httpx.ASGITransport(app=panel.app)
                async with httpx.AsyncClient(
                        transport=transport, base_url='http://testserver') as c:
                    return await c.post('/api/servers/0/protocol/awg3/ipv6',
                                        json={'enabled': True})
            finally:
                lock.release()

        with mock.patch.object(panel, '_require_admin_strict',
                               return_value={'id': 'admin-id', 'role': 'admin'}), \
                mock.patch.object(peer_lifecycle_lock, 'QUEUE_WAIT_SECONDS', 0):
            res = asyncio.run(scenario())
        self.assertEqual(res.status_code, 503, res.text)
        self.assertEqual(res.json()['code'], 'peer_lifecycle_busy')

class ErrorLeakTests(Ipv6FixesBase):
    """B7: unexpected errors are internal_error and never echo str(e)."""

    server_extra = {'protocols': {'awg3': {'installed': True}}}

    def test_instance_error_does_not_echo_the_message(self):
        with mock.patch.object(panel, 'AWGManager') as manager_cls:
            manager_cls.return_value.get_instance_ipv6_state.return_value = \
                ipv6_state()
            manager_cls.return_value.set_instance_ipv6.side_effect = \
                ValueError('PrivateKey = LEAK')
            res = self.admin().post('/api/servers/0/protocol/awg3/ipv6',
                                    json={'enabled': True})
        self.assertEqual(res.status_code, 500, res.text)
        self.assertEqual(res.json()['code'], 'internal_error')
        self.assertNotIn('LEAK', res.text)

    def test_preference_error_does_not_echo_the_message(self):
        client = self.admin()
        with mock.patch.object(panel, 'save_data',
                               side_effect=ValueError('PrivateKey = LEAK')):
            res = client.post('/api/servers/0/ipv6',
                              json={'enabled': True})
        self.assertEqual(res.status_code, 500, res.text)
        self.assertEqual(res.json()['code'], 'internal_error')
        self.assertNotIn('LEAK', res.text)


class ReinstallInheritsIpv4Tests(Ipv6FixesBase):
    """B8: a reinstall of an exit-linked instance stays IPv4-only."""

    def test_previous_link_forces_ipv4_only(self):
        self.write_data({
            'servers': [base_server(
                ipv6_new_instances=True,
                protocols={'awg3': {'installed': True,
                                    'exit_link': {'exit_uid': 'exit-uid',
                                                  'exit_name': 'E'}}})],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [],
        })
        manager = mock.Mock()
        manager._docker_ipv6_info.return_value = {'ipv6_enabled': True,
                                                  'installed': True}
        manager.install_protocol.return_value = {
            'status': 'success', 'awg_params': {}, 'mtu': 1376, 'dns': ''}
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'ensure_docker_installed',
                                  return_value=''), \
                mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=manager), \
                mock.patch.object(panel.exit_link_svc, 'relink_entry',
                                  new=mock.AsyncMock(return_value={})):
            res = self.admin().post('/api/servers/0/install',
                                    json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)
        log = res.json().get('log') or []
        self.assertTrue(any('IPv6' in str(line) for line in log), log)


class DockerInstallGateTests(Ipv6FixesBase):
    """B9: Docker apply is refused while an install is running."""

    def test_running_install_is_operation_busy(self):
        client = self.admin()
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        self.addCleanup(panel._INSTALL_OPS.pop, op['id'], None)
        self.addCleanup(panel._INSTALL_ACTIVE.pop, (0, 'protocol'), None)
        with mock.patch.object(panel, '_op_store') as store:
            res = client.post('/api/servers/0/docker/ipv6/apply',
                              json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'operation_busy')
        store.assert_not_called()

    def test_starting_install_is_operation_busy(self):
        client = self.admin()
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        op['state'] = 'starting'
        self.addCleanup(panel._INSTALL_OPS.pop, op['id'], None)
        self.addCleanup(panel._INSTALL_ACTIVE.pop, (0, 'protocol'), None)
        res = client.post('/api/servers/0/docker/ipv6/apply',
                          json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 409, res.text)


class Ip6HostHeaderTests(Ipv6FixesBase):
    """B10: an IPv6 literal Host header is parsed, not rejected."""

    def test_bracketed_ipv6_host_is_allowed(self):
        res = self.admin().post('/api/servers/0/ipv6',
                                json={'enabled': True},
                                headers={'Host': '[::1]:5000'})
        self.assertEqual(res.status_code, 200, res.text)


class StatusCacheTtlTests(unittest.TestCase):
    """B11: healthy payloads live 20 s, degraded ones only 3 s."""

    def setUp(self):
        panel._IP_STATUS_CACHE.clear()
        self.addCleanup(panel._IP_STATUS_CACHE.clear)

    def test_ok_payload_lives_twenty_seconds(self):
        payload = status_payload()
        with mock.patch.object(panel.time, 'time', return_value=100.0):
            panel._ip_status_cache_put('srv-uid', payload)
        with mock.patch.object(panel.time, 'time', return_value=119.0):
            self.assertIs(panel._ip_status_cache_get('srv-uid'), payload)
        with mock.patch.object(panel.time, 'time', return_value=121.0):
            self.assertIsNone(panel._ip_status_cache_get('srv-uid'))

    def test_degraded_payload_lives_three_seconds(self):
        payload = status_payload(state='degraded', error='ssh_failed')
        with mock.patch.object(panel.time, 'time', return_value=100.0):
            panel._ip_status_cache_put('srv-uid', payload)
        with mock.patch.object(panel.time, 'time', return_value=102.0):
            self.assertIs(panel._ip_status_cache_get('srv-uid'), payload)
        with mock.patch.object(panel.time, 'time', return_value=104.0):
            self.assertIsNone(panel._ip_status_cache_get('srv-uid'))


if __name__ == '__main__':
    unittest.main()



