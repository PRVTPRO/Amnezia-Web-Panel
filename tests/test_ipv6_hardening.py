"""Regression tests for the IPv6 hardening fixes.

Every test pins one fix: a failed worker start releases the op lock and
answers 500, AWG_IPV6=off wins over the server preference and skips the
Docker gate, a failed rollback is reported as recreate_rollback_failed,
the rebuilt run command carries env/entrypoint/cmd/labels and drops -p for
host networking, DNS values must be IP addresses, a stopped container
cannot be disabled, and escapeHtml escapes both quote characters.

No SSH is opened and the panel uses a temporary data file.
"""
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers.awg_manager import AWGManager

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / 'templates' / 'server.html'


def base_server(**extra):
    server = {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
              'username': 'root', 'password': 'x', 'private_key': '',
              'server_info': {}, 'uid': 'srv-uid', 'protocols': {}}
    server.update(extra)
    return server


class RunCmdFromInspectHardeningTests(unittest.TestCase):
    def test_runtime_config_is_carried_over(self):
        info = {
            'HostConfig': {
                'NetworkMode': 'bridge',
                'PortBindings': {
                    '55424/udp': [{'HostIp': '', 'HostPort': '55424'}]},
            },
            'Config': {
                'Env': ['PATH=/usr/bin', 'MSG=two words', 'PATH=/dup'],
                'Entrypoint': ['/entry.sh', 'ignored-arg'],
                'Cmd': ['serve', '--flag', 'two words'],
                'Labels': {'panel.role': 'awg server'},
            },
        }
        cmd = AWGManager._run_cmd_from_inspect(info, 'amnezia-awg', 'img')
        self.assertIn("-e PATH=/usr/bin", cmd)
        self.assertIn("-e MSG='two words'", cmd)
        # A repeated key must not be emitted twice.
        self.assertEqual(cmd.count('PATH='), 1)
        self.assertIn('--entrypoint /entry.sh', cmd)
        self.assertIn('--label panel.role=', cmd)
        # Docker replaces the whole Entrypoint with --entrypoint, so the rest
        # of an exec-form Entrypoint list is prepended to Cmd. Both come after
        # the image, quoted as separate arguments.
        self.assertTrue(
            cmd.endswith("img ignored-arg serve --flag 'two words'"), cmd)

    def test_ports_are_skipped_for_host_and_container_networks(self):
        info = {
            'HostConfig': {
                'NetworkMode': 'host',
                'PortBindings': {
                    '55424/udp': [{'HostIp': '', 'HostPort': '55424'}]},
            },
        }
        self.assertNotIn(' -p ', AWGManager._run_cmd_from_inspect(
            info, 'amnezia-awg', 'img'))
        info['HostConfig']['NetworkMode'] = 'container:other'
        self.assertNotIn(' -p ', AWGManager._run_cmd_from_inspect(
            info, 'amnezia-awg', 'img'))
        info['HostConfig']['NetworkMode'] = 'bridge'
        self.assertIn('-p 55424:55424/udp', AWGManager._run_cmd_from_inspect(
            info, 'amnezia-awg', 'img'))


class ValidateDnsValueTests(unittest.TestCase):
    def setUp(self):
        self.manager = AWGManager(mock.Mock())

    def test_valid_addresses_pass(self):
        self.assertEqual(self.manager._validate_dns_value('9.9.9.9'),
                         '9.9.9.9')
        self.assertEqual(self.manager._validate_dns_value('2001:db8::53'),
                         '2001:db8::53')
        self.assertEqual(self.manager._validate_dns_value('1.1.1.1, 2001:db8::53'),
                         '1.1.1.1, 2001:db8::53')

    def test_empty_value_clears_the_setting(self):
        self.assertEqual(self.manager._validate_dns_value(''), '')
        self.assertIsNone(self.manager._validate_dns_value(None))

    def test_non_address_is_bad_request(self):
        for bad in ('example.com', '<script>', '1.1.1.1; rm -rf /'):
            with self.subTest(value=bad):
                with self.assertRaises(RuntimeError) as ctx:
                    self.manager._validate_dns_value(bad)
                self.assertEqual(str(ctx.exception), 'bad_request')


class StoppedContainerStateTests(unittest.TestCase):
    def test_stopped_container_cannot_be_disabled(self):
        manager = AWGManager(mock.Mock())
        manager.ssh.run_sudo_command.return_value = ('', '', 0)
        manager._docker_ipv6_info = mock.Mock(
            return_value={'ipv6_enabled': True})
        manager._get_subnet_ipv6_ip = mock.Mock(return_value='fd42:8:1::1')
        manager._peers_state = mock.Mock(return_value=(0, 0, True))
        manager._container_state = mock.Mock(return_value=(False, 'awg3'))
        manager._get_subnet_ip = mock.Mock(return_value='10.8.1.1')
        manager.exit_link_info = mock.Mock(return_value=None)
        state = manager.get_instance_ipv6_state('awg3')
        self.assertFalse(state['can_disable'])
        self.assertEqual(state['blocked_reason'], 'server_off')


class RecreateRollbackFailureTests(unittest.TestCase):
    def test_failed_restore_is_reported_as_recreate_rollback_failed(self):
        ssh = mock.Mock()

        def sudo(command, *args, **kwargs):
            if command.startswith('docker run -d'):
                return '', 'run failed', 1
            if command == 'docker rename amnezia-awg3-ipv6bak amnezia-awg3':
                return '', 'rename failed', 1
            return '', '', 0

        ssh.run_sudo_command.side_effect = sudo
        manager = AWGManager(ssh)
        manager._resolve_config_path = mock.Mock(
            return_value='/opt/amnezia/awg0.conf')
        manager._get_server_config = mock.Mock(
            return_value='[Interface]\nAddress = 10.8.1.1/24\n'
                         'ListenPort = 55424\n')
        manager._container_run_image = mock.Mock(return_value='amnezia-awg3')
        manager._inspect_container = mock.Mock(return_value=None)
        manager._docker_run_cmd = mock.Mock(return_value='docker run -d fake')
        manager._invalidate_config_cache = mock.Mock()
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg3')
        self.assertEqual(str(ctx.exception), 'recreate_rollback_failed')


class ApiTestBase(unittest.TestCase):
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
            ],
            'user_connections': [],
        })
        ssh_patch = mock.patch.object(panel, 'get_ssh', return_value=mock.Mock())
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)
        panel._invalidate_ip_status()
        self.addCleanup(panel._invalidate_ip_status)

    def write_data(self, data):
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


class DockerWorkerStartFailureTests(ApiTestBase):
    def test_worker_start_failure_returns_500_and_releases_lock(self):
        client = self.admin()
        lock = panel._op_lock('srv-uid')
        with mock.patch.object(panel.threading, 'Thread') as thread_cls:
            thread_cls.return_value.start.side_effect = RuntimeError('boom')
            res = client.post('/api/servers/0/docker/ipv6/apply',
                              json={'confirm': 'yes'})
        self.assertEqual(res.status_code, 500, res.text)
        self.assertEqual(res.json()['code'], 'internal_error')
        operations = list(panel._op_store()._read().values())
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]['state'], 'failed')
        self.assertEqual(operations[0]['reason'], 'internal_error')
        # The worker never ran, so the handler itself must free the op lock.
        self.assertTrue(lock.acquire(blocking=False))
        lock.release()


class InstallEnvOverrideTests(ApiTestBase):
    def test_env_off_forces_ipv4_and_skips_the_docker_gate(self):
        self.write_data({
            'servers': [base_server(ipv6_new_instances=True)],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [],
        })
        ssh = mock.Mock()
        manager = mock.Mock()
        manager._docker_ipv6_info.return_value = {'ipv6_enabled': False,
                                                  'installed': True}
        manager.install_protocol.return_value = {
            'status': 'success', 'awg_params': {}, 'mtu': 1376, 'dns': ''}
        patches = [
            mock.patch.object(panel, 'get_ssh', return_value=ssh),
            mock.patch.object(panel, 'get_used_ports', return_value={}),
            mock.patch.object(panel, 'ensure_docker_installed', return_value=''),
            mock.patch.object(panel, 'get_protocol_manager', return_value=manager),
            mock.patch.dict('os.environ', {'AWG_IPV6': 'off'}),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        res = self.admin().post('/api/servers/0/install',
                                json={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertIs(kwargs['ipv6_preference'], False)
        manager._docker_ipv6_info.assert_not_called()


def load_escape_html():
    """Rebuild escapeHtml's real replacements from templates/server.html."""
    source = SERVER_TEMPLATE.read_text(encoding='utf-8')
    start = source.index('function escapeHtml(str) {')
    end = source.index('\n    }', start)
    body = source[start:end]
    pairs = re.findall(r"\.replace\(/(.+?)/g, '([^']*)'\)", body)
    if not pairs:
        raise AssertionError('escapeHtml has no replacements:\n' + body)

    def escape(value):
        text = '' if value is None else str(value)
        for pattern, replacement in pairs:
            text = re.sub(pattern, replacement, text)
        return text
    return escape


class EscapeHtmlTests(unittest.TestCase):
    def test_quotes_and_script_tags_are_escaped(self):
        escape = load_escape_html()
        value = 'He said "hi" & <script>alert(\'x\')</script>'
        self.assertEqual(
            escape(value),
            'He said &quot;hi&quot; &amp; &lt;script&gt;'
            'alert(&#39;x&#39;)&lt;/script&gt;')
        self.assertNotIn('<script>', escape(value))
        self.assertNotIn('"', escape(value))
        self.assertNotIn("'", escape(value))
