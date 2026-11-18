"""Lifecycle fence: честная подача состояния и отказ не латчить fence.

Регрессии из #341: `/check`, `/smartroute/status` и `/awg-plugin/status`
перехватывали `PeerLifecycleUncertain` общим `except Exception` и отдавали
generic 500, хотя в приложении зарегистрированы штатные обработчики (503 с
машинным кодом). Кроме того, отказ сервера стартовать операцию (busy/backoff)
латчил долговременный fence, хотя ничего не выполнялось.
"""
import asyncio
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
import peer_lifecycle_lock as lifecycle



class FencePresentationBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data_file = os.path.join(self.tmp, 'data.json')
        previous_data = panel.DATA_FILE
        panel.DATA_FILE = self.data_file
        self.addCleanup(setattr, panel, 'DATA_FILE', previous_data)
        lifecycle.configure(self.data_file)
        self.addCleanup(lifecycle.configure, previous_data)
        self.addCleanup(setattr, lifecycle, '_fenced', False)
        self.marker = Path(self.data_file + '.lifecycle-uncertain.json')
        self.write_data()

    def write_data(self, extra=None):
        server = {'name': 'B', 'host': '198.51.100.2', 'ssh_port': 22,
                  'username': 'root', 'password': 'x', 'private_key': '',
                  'server_info': {}, 'uid': 'uid-B', 'protocols': {}}
        if extra:
            server.update(extra)
        data = {'servers': [server],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': []}
        with open(self.data_file, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)

    def admin_client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        response = client.post('/api/auth/login',
                               json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)
        return client


class StructuredFenceResponseTests(FencePresentationBase):
    def test_check_returns_503_instead_of_generic_500(self):
        client = self.admin_client()

        def fenced(*args, **kwargs):
            raise lifecycle.PeerLifecycleUncertain('peer_lifecycle_uncertain')

        with mock.patch.object(panel, 'get_ssh', side_effect=fenced):
            response = client.post('/api/servers/0/check')
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()['code'], 'peer_lifecycle_uncertain')

    def test_smartroute_status_returns_503_instead_of_generic_500(self):
        client = self.admin_client()
        with mock.patch.object(panel.smartroute_svc, 'status',
                               new=mock.AsyncMock(side_effect=lifecycle.PeerLifecycleUncertain(
                                   'peer_lifecycle_uncertain'))):
            response = client.get('/api/servers/0/smartroute/status')
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()['code'], 'peer_lifecycle_uncertain')

    def test_awg_plugin_status_returns_503_instead_of_generic_500(self):
        client = self.admin_client()

        def fenced(server_id):
            raise lifecycle.PeerLifecycleUncertain('peer_lifecycle_uncertain')

        with mock.patch.object(panel, '_awg_plugin_updater', side_effect=fenced):
            response = client.get('/api/servers/0/awg-plugin/status')
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()['code'], 'peer_lifecycle_uncertain')

    def test_busy_is_reported_as_busy_not_as_uncertain(self):
        client = self.admin_client()
        with mock.patch.object(panel.smartroute_svc, 'status',
                               new=mock.AsyncMock(side_effect=lifecycle.PeerLifecycleBusy(
                                   'peer_lifecycle_busy'))):
            response = client.get('/api/servers/0/smartroute/status')
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()['code'], 'peer_lifecycle_busy')


class DiagnosticsTests(FencePresentationBase):
    def test_legacy_marker_reports_reason_and_time_without_scope(self):
        created = int(time.time()) - 120
        self.marker.write_text(json.dumps({'version': 1, 'created_at': created,
                                           'reason': 'ssh_result_unknown'}),
                               encoding='utf-8')
        state = lifecycle.diagnostics()
        self.assertTrue(state['blocked'])
        self.assertEqual(state['reason'], 'ssh_result_unknown')
        self.assertEqual(state['created_at'], created)
        self.assertGreaterEqual(state['age_seconds'], 115)
        # Legacy-маркер не знает сервера: угадывать нельзя, значит глобально.
        self.assertIsNone(state['scope'])
        self.assertIsNone(state['operation'])

    def test_unreadable_marker_still_blocks_and_says_so(self):
        self.marker.write_text('{not json', encoding='utf-8')
        state = lifecycle.diagnostics()
        self.assertTrue(state['blocked'])
        self.assertEqual(state['reason'], 'marker_unreadable')

    def test_no_marker_means_not_blocked(self):
        state = lifecycle.diagnostics()
        self.assertFalse(state['blocked'])
        self.assertNotIn('reason', state)

    def test_recovery_status_endpoint_exposes_the_same_details(self):
        self.marker.write_text(json.dumps({'version': 1, 'created_at': int(time.time()),
                                           'reason': 'ssh_result_unknown'}),
                               encoding='utf-8')
        response = self.admin_client().get('/api/recovery/status')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['blocked'])
        self.assertEqual(body['reason'], 'ssh_result_unknown')


class RetryUnderInterlockTests(unittest.TestCase):
    """Повтор команды с неизвестным исходом запрещён внутри интерлока."""

    class _FakeStream:
        channel = mock.Mock()

    class _DeadTransport:
        def __init__(self, calls):
            self.calls = calls

        def get_transport(self):
            return mock.Mock(is_active=mock.Mock(return_value=True))

        def close(self):
            pass

        def exec_command(self, command, timeout=60):
            self.calls.append(command)
            raise EOFError('transport closed')

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data_file = os.path.join(self.tmp, 'data.json')
        previous = lifecycle._fence_path
        lifecycle.configure(self.data_file)
        self.addCleanup(setattr, lifecycle, '_fence_path', previous)
        self.addCleanup(setattr, lifecycle, '_fenced', False)
        self.marker = Path(self.data_file + '.lifecycle-uncertain.json')

    def _manager(self, calls):
        from managers.ssh_manager import SSHManager
        ssh = SSHManager('198.51.100.7', 22, 'root', 'x', '')
        ssh.client = self._DeadTransport(calls)
        ssh.ensure_connected = lambda: True
        ssh.connect = mock.Mock(return_value=True)
        return ssh

    def test_plain_read_still_retries_once(self):
        calls = []
        ssh = self._manager(calls)
        out, err, code = ssh.run_command('docker ps', timeout=1)
        self.assertEqual(calls, ['docker ps', 'docker ps'])
        self.assertEqual(code, -1)
        self.assertTrue(ssh.connect.called)
        self.assertFalse(self.marker.exists())

    def test_lifecycle_mutation_is_not_replayed(self):
        calls = []

        async def scenario():
            @lifecycle.serialize_peer_lifecycle
            def mutate():
                return self._manager(calls).run_command('docker rm -f x', timeout=1)

            with self.assertRaises(lifecycle.PeerLifecycleUncertain):
                await mutate()

        asyncio.run(scenario())
        # Одна попытка: повторять мутацию с неизвестным исходом нельзя.
        self.assertEqual(calls, ['docker rm -f x'])
        self.assertTrue(self.marker.exists())

    def test_lifecycle_active_flag_marks_admission(self):
        async def scenario():
            self.assertFalse(lifecycle.lifecycle_active())

            @lifecycle.serialize_peer_lifecycle
            async def probe():
                self.assertTrue(lifecycle.lifecycle_active())
                return 'ok'

            self.assertEqual(await probe(), 'ok')
            self.assertFalse(lifecycle.lifecycle_active())

        asyncio.run(scenario())

    def test_lost_reply_still_fences(self):
        async def scenario():
            @lifecycle.serialize_peer_lifecycle
            async def lost():
                raise TimeoutError('reply lost')

            with self.assertRaises(lifecycle.PeerLifecycleUncertain):
                await lost()
            self.assertTrue(self.marker.exists())
            with self.assertRaises(lifecycle.PeerLifecycleUncertain):
                await lost()

        asyncio.run(scenario())


if __name__ == '__main__':
    unittest.main()
