"""Адресный fence жизненного цикла (#341).

Неизвестный SSH-исход на сервере A не должен выключать здоровые серверы B/C:
маркер хранит идентичность сервера и операции, SSH-слой передаёт свою
идентичность в проверку, а legacy-маркер без идентичности остаётся глобальным.
"""
import asyncio
import copy
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import app as panel
import peer_lifecycle_lock as lifecycle
from managers.ssh_manager import SSHManager

SCOPE_A = {'server_uid': 'node-a', 'host': '192.0.2.1', 'ssh_port': 22,
           'username': 'root'}
SCOPE_B = {'server_uid': 'node-b', 'host': '192.0.2.2', 'ssh_port': 22,
           'username': 'root'}


def _write_marker(path, payload):
    path.write_text(json.dumps(payload), encoding='utf-8')


class FenceScopeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data_file = os.path.join(self.tmp, 'data.json')
        self.previous_path = lifecycle._fence_path
        lifecycle.configure(self.data_file)
        self.addCleanup(setattr, lifecycle, '_fence_path', self.previous_path)
        self.addCleanup(setattr, lifecycle, '_fenced', False)
        self.addCleanup(setattr, lifecycle, '_fenced_scope', None)
        self.addCleanup(lifecycle.configure_resolvers, lifecycle._identity_resolver,
                        lifecycle._dependency_resolver)
        self.marker = Path(self.data_file + '.lifecycle-uncertain.json')

    def note_while_active(self, scope):
        """Отметить неизвестность так, как это делает SSH-слой."""
        token = lifecycle._active.set(True)
        try:
            lifecycle.note_ssh_uncertainty(scope)
        finally:
            lifecycle._active.reset(token)


class ScopeRecordingTests(FenceScopeTestCase):
    def test_incident_records_identity_and_operation(self):
        lifecycle.configure_resolvers(lambda server_id: SCOPE_A, None)

        async def scenario():
            @lifecycle.serialize_peer_lifecycle
            async def mutate(server_id):
                lifecycle.note_ssh_uncertainty(SCOPE_A)

            await mutate(0)

        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            asyncio.run(scenario())
        marker = json.loads(self.marker.read_text(encoding='utf-8'))
        self.assertEqual(marker['version'], 2)
        self.assertEqual(marker['reason'], 'ssh_result_unknown')
        self.assertEqual(marker['scope'], SCOPE_A)
        self.assertEqual(marker['operation'], {'kind': 'lifecycle',
                                               'label': 'mutate'})
        # Никаких секретов и сырых команд в маркере.
        raw = self.marker.read_text(encoding='utf-8')
        self.assertNotIn('password', raw)
        self.assertNotIn('sudo', raw)

    def test_second_incident_on_another_server_widens_to_global(self):
        self.marker.write_text(json.dumps({'version': 2, 'created_at': int(time.time()),
                                           'reason': 'ssh_result_unknown',
                                           'scope': SCOPE_A}), encoding='utf-8')

        self.note_while_active(SCOPE_B)
        self.assertIsNone(lifecycle.fence_scope()[1])

    def test_global_marker_is_never_narrowed(self):
        self.marker.write_text(json.dumps({'version': 1, 'created_at': int(time.time()),
                                           'reason': 'ssh_result_unknown'}),
                               encoding='utf-8')

        self.note_while_active(SCOPE_A)
        self.assertIsNone(lifecycle.fence_scope()[1])


class ScopedCheckTests(FenceScopeTestCase):
    def _fence(self, scope=None, version=2):
        payload = {'version': version, 'created_at': int(time.time()),
                   'reason': 'ssh_result_unknown'}
        if scope is not None:
            payload['scope'] = scope
        _write_marker(self.marker, payload)

    def test_affected_server_is_blocked(self):
        self._fence(SCOPE_A)
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(SCOPE_A)

    def test_unrelated_server_passes(self):
        self._fence(SCOPE_A)
        lifecycle.check_remote_fence(SCOPE_B)

    def test_unknown_target_stays_conservative(self):
        self._fence(SCOPE_A)
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(None)

    def test_legacy_marker_blocks_everyone(self):
        self._fence(None, version=1)
        for identity in (SCOPE_A, SCOPE_B, None):
            with self.assertRaises(lifecycle.PeerLifecycleUncertain):
                lifecycle.check_remote_fence(identity)

    def test_unreadable_marker_blocks_everyone(self):
        self.marker.write_text('{oops', encoding='utf-8')
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(SCOPE_B)

    def test_matching_falls_back_to_connection_coordinates_without_uid(self):
        self._fence(SCOPE_A)
        # У цели нет uid — сравниваем координаты соединения.
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(dict(SCOPE_A, server_uid=None))
        # Другой uid при тех же координатах — тот же сервер (переименован uid).
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(dict(SCOPE_A, server_uid='other-uid'))
        # Другой хост — независимый сервер.
        lifecycle.check_remote_fence({'server_uid': None, 'host': '192.0.2.9',
                                      'ssh_port': 22, 'username': 'root'})

    def test_exit_link_dependency_blocks_both_sides(self):
        self._fence(SCOPE_A)
        lifecycle.configure_resolvers(None, lambda uid: ('node-b',) if uid == 'node-a' else ())
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(SCOPE_B)

    def test_broken_dependency_resolver_fails_closed(self):
        self._fence(SCOPE_A)

        def broken(uid):
            raise RuntimeError('inventory unreadable')

        lifecycle.configure_resolvers(None, broken)
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            lifecycle.check_remote_fence(SCOPE_B)


class _Stream:
    def __init__(self):
        self.channel = mock.Mock()
        self.channel.recv_exit_status.return_value = 0

    def read(self):
        return b'ok'

    def write(self, data):
        pass

    def flush(self):
        pass


class _FakeClient:
    def __init__(self):
        self.commands = []
        self.opened_sftp = 0

    def get_transport(self):
        return mock.Mock(is_active=mock.Mock(return_value=True))

    def close(self):
        pass

    def exec_command(self, command, timeout=60):
        self.commands.append(command)
        return _Stream(), _Stream(), _Stream()

    def open_sftp(self):
        self.opened_sftp += 1
        sftp = mock.MagicMock()
        sftp.file.return_value.__enter__.return_value.read.return_value = b'payload'
        return sftp


class SshGateTests(FenceScopeTestCase):
    def _manager(self, scope):
        ssh = SSHManager('192.0.2.1', 22, 'root', 'x', '', server_scope=scope)
        ssh.client = _FakeClient()
        ssh.ensure_connected = lambda: True
        return ssh

    def _fence_a(self):
        _write_marker(self.marker, {'version': 2, 'created_at': int(time.time()),
                                    'reason': 'ssh_result_unknown', 'scope': SCOPE_A})

    def test_commands_on_the_affected_server_are_refused_before_ssh(self):
        self._fence_a()
        ssh = self._manager(SCOPE_A)
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            ssh.run_command('docker ps')
        self.assertEqual(ssh.client.commands, [])

    def test_commands_on_other_servers_run(self):
        self._fence_a()
        ssh = self._manager(SCOPE_B)
        self.assertEqual(ssh.run_command('docker ps')[0], 'ok')
        self.assertEqual(ssh.client.commands, ['docker ps'])

    def test_sftp_writes_are_gated_too(self):
        self._fence_a()
        blocked = self._manager(SCOPE_A)
        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            blocked.upload_file('x', '/tmp/x')
        self.assertEqual(blocked.client.opened_sftp, 0)
        allowed = self._manager(SCOPE_B)
        allowed.upload_file('x', '/tmp/x')
        self.assertEqual(allowed.client.opened_sftp, 1)

    def test_sftp_reads_and_file_checks_are_gated(self):
        self._fence_a()
        ssh = self._manager(SCOPE_A)
        for call in (lambda: ssh.download_file('/tmp/x'),
                     lambda: ssh.file_exists('/tmp/x')):
            with self.assertRaises(lifecycle.PeerLifecycleUncertain):
                call()
        self.assertEqual(ssh.client.opened_sftp, 0)


class DeleteAdmissionTests(FenceScopeTestCase):
    """Регрессия из #341: локальное удаление несвязанного сервера проходит."""

    def setUp(self):
        super().setUp()
        self.data = {'servers': [
            {'uid': 'node-a', 'name': 'a', 'host': '192.0.2.1', 'ssh_port': 22,
             'username': 'root', 'protocols': {}},
            {'uid': 'node-b', 'name': 'b', 'host': '192.0.2.2', 'ssh_port': 22,
             'username': 'root', 'protocols': {}},
        ], 'users': [{'id': 'admin', 'username': 'admin', 'role': 'admin',
                      'enabled': True, 'traffic_used': 0, 'traffic_total': 0}],
           'user_connections': []}
        self.saved = []
        self.stack = []
        self.addCleanup(lambda: [p.stop() for p in reversed(self.stack)])
        self.patch('DATA_FILE', self.data_file)
        self.patch('load_data', lambda: copy.deepcopy(self.data))
        self.patch('save_data', mock.Mock(side_effect=lambda value: self.saved.append(
            copy.deepcopy(value))))
        self.patch('_check_admin', lambda request: True)
        self.patch('get_current_user', lambda request: {'id': 'admin', 'role': 'admin'})
        self.commits = []

        def commit(data_file, operation_id, actor, kind, intent, before, after):
            self.commits.append(copy.deepcopy(after))
            return {'status': 'success'}

        self.patch('commit_finalize', mock.Mock(side_effect=commit))
        self.patch('_finish_locked_worker', mock.AsyncMock())
        self.patch('drop_ssh', mock.Mock())
        self.request = SimpleNamespace(cookies={}, headers={})

    def patch(self, name, value):
        patcher = mock.patch.object(panel, name, value)
        self.stack.append(patcher)
        patcher.start()

    def _fence_a(self):
        _write_marker(self.marker, {'version': 2, 'created_at': int(time.time()),
                                    'reason': 'ssh_result_unknown', 'scope': SCOPE_A})

    def test_panel_only_removal_of_a_healthy_server_is_allowed(self):
        self._fence_a()

        async def scenario():
            return await panel.api_delete_server(
                self.request, 1, server_uid='node-b', panel_only=True)

        result = asyncio.run(scenario())
        self.assertEqual(result['status'], 'success')
        self.assertEqual([server['uid'] for server in self.commits[-1]['servers']],
                         ['node-a'])

    def test_panel_only_removal_of_the_affected_server_is_refused(self):
        self._fence_a()

        async def scenario():
            return await panel.api_delete_server(
                self.request, 0, server_uid='node-a', panel_only=True)

        with self.assertRaises(lifecycle.PeerLifecycleUncertain):
            asyncio.run(scenario())
        self.assertEqual(self.commits, [])


if __name__ == '__main__':
    unittest.main()
