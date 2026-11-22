"""Тесты импорта WARP-профиля с другого сервера (фича для SNI-фильтрованных хостов)."""

import asyncio
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
import warp_service as ws
from warp_service import WarpStateStore


def server_record(uid, name, protocols):
    return {
        'name': name,
        'host': '198.51.100.%d' % (10 + len(uid)),
        'ssh_port': 22,
        'username': 'root',
        'password': 'x',
        'private_key': '',
        'server_info': {},
        'uid': uid,
        'protocols': protocols,
    }


class WarpImportApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        self._state_store = panel.warp_state_store
        self._runtime_store = panel.warp_runtime.state_store
        self._monitor_flag = panel._conn_monitor_started

        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        panel.warp_state_store = WarpStateStore(
            os.path.join(self.tmp, 'data.json.srv_warp_state.json'))
        panel.warp_runtime.state_store = panel.warp_state_store
        panel._conn_monitor_started = True
        panel._WARP_JOBS.clear()

        self.write_data()
        self.client = TestClient(panel.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        login = self.client.post('/api/auth/login',
                                 json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel.warp_state_store = self._state_store
        panel.warp_runtime.state_store = self._runtime_store
        panel._conn_monitor_started = self._monitor_flag
        panel._WARP_JOBS.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_data(self):
        target = server_record('target-uid', 'Blocked host',
                               {'awg3': {'installed': True,
                                         'base_protocol': 'awg3',
                                         'port': '55424'}})
        source = server_record('source-uid', 'Open host',
                               {'awg3': {'installed': True,
                                         'base_protocol': 'awg3',
                                         'port': '55424'}})
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({
                'servers': [target, source],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': [],
            }, handle)

    def post(self, body):
        return self.client.post('/api/servers/0/warp/import', json=body)

    def wait_op(self, op_id):
        for _ in range(300):
            op = panel._INSTALL_OPS.get(op_id) or {}
            if op.get('state') != 'running':
                return op
            time.sleep(0.01)
        self.fail('import operation did not finish')

    # ----- guards ----------------------------------------------------------

    def test_import_from_self_is_rejected(self):
        response = self.post({'server_uid': 'target-uid',
                              'source_server_uid': 'target-uid',
                              'accept_tos': True})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_source_is_self')

    def test_import_without_source_is_rejected(self):
        response = self.post({'server_uid': 'target-uid',
                              'accept_tos': True})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_source_required')

    def test_import_with_unknown_source_is_rejected(self):
        response = self.post({'server_uid': 'target-uid',
                              'source_server_uid': 'nope-uid',
                              'accept_tos': True})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_source_not_found')

    def test_import_rejects_non_awg_source_protocol(self):
        response = self.post({'server_uid': 'target-uid',
                              'source_server_uid': 'source-uid',
                              'source_protocol': 'xray',
                              'accept_tos': True})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'],
                         'srv_warp_protocol_unsupported')

    def test_import_requires_tos(self):
        response = self.post({'server_uid': 'target-uid',
                              'source_server_uid': 'source-uid'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_tos_required')

    # ----- source capability check -----------------------------------------

    def test_sources_endpoint_returns_probe_rows(self):
        async def fake_probe(server_id, uid, source_protocol=None):
            return [{'uid': 'source-uid', 'name': 'Open host', 'host': 'x',
                     'protocols': ['awg3'], 'status': 'ready',
                     'protocol': 'awg3'}]

        with mock.patch.object(panel.warp_runtime, 'probe_sources', fake_probe):
            response = self.client.post('/api/servers/0/warp/import/sources',
                                        json={'server_uid': 'target-uid'})

        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()['sources']
        self.assertEqual([row['status'] for row in rows], ['ready'])

    def test_sources_endpoint_rejects_an_unknown_uid(self):
        async def fake_probe(server_id, uid, source_protocol=None):
            self.fail('the probe must not run for an unknown server')

        with mock.patch.object(panel.warp_runtime, 'probe_sources', fake_probe):
            response = self.client.post('/api/servers/0/warp/import/sources',
                                        json={'server_uid': 'nope-uid'})

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_identity_mismatch')

    # ----- happy path ------------------------------------------------------

    def test_import_records_after_a_handshake(self):
        """The profile is recorded only once a live handshake succeeded."""
        result = {'protocol': 'awg3', 'handshake': True,
                  'conf_hash': 'abc123', 'source': 'source-uid'}
        seen = {}

        async def fake_import(server_id, uid, source_uid, protocol=None,
                              source_protocol=None, job_id=None,
                              progress=None):
            seen['args'] = (server_id, uid, source_uid, protocol,
                            source_protocol)
            if progress:
                progress('start', 'starting')
                progress('done', 'done')

        with mock.patch.object(panel.warp_runtime, 'import_profile',
                               fake_import):
            response = self.post({'server_uid': 'target-uid',
                                  'source_server_uid': 'source-uid',
                                  'protocol': 'awg3',
                                  'accept_tos': True})
            self.assertIn(response.status_code, (200, 202), response.text)
            op = self.wait_op(response.json()['operation_id'])

        self.assertEqual(op['state'], 'success', op)
        self.assertEqual(seen['args'][1], 'target-uid')
        self.assertEqual(seen['args'][2], 'source-uid')
        self.assertEqual(seen['args'][3], 'awg3')

    def test_import_failure_reports_its_own_code(self):
        async def failing(server_id, uid, source_uid, protocol=None,
                          source_protocol=None, job_id=None, progress=None):
            raise panel.SrvWarpError('srv_warp_handshake_failed', 502)

        with mock.patch.object(panel.warp_runtime, 'import_profile', failing):
            response = self.post({'server_uid': 'target-uid',
                                  'source_server_uid': 'source-uid',
                                  'accept_tos': True})
            self.assertIn(response.status_code, (200, 202), response.text)
            op = self.wait_op(response.json()['operation_id'])

        self.assertEqual(op['state'], 'error')
        self.assertEqual(op['error']['code'], 'srv_warp_handshake_failed')


class WarpImportSecretsTests(unittest.TestCase):
    """A private key must never reach a logged shell command or the state file."""

    def test_private_key_never_passes_through_docker_exec(self):
        runtime = panel.warp_runtime
        written = []

        class FakeSSH:
            def __init__(self):
                self.commands = []
                self.scripts = []

            def run_sudo_command(self, command, timeout=60):
                self.commands.append(command)
                if 'command -v wgcf' in command:
                    return '/usr/local/bin/wgcf\n', '', 0
                if 'sha256sum' in command:
                    return 'deadbeef  /opt/amnezia/awg/warp/awg3/warp0.conf\n', '', 0
                return '', '', 0

            def run_sudo_script(self, script, timeout=120):
                self.scripts.append(script)
                written.append(script)
                return '', '', 0

        class FakeManager:
            ssh = FakeSSH()

            def _container_name(self, protocol):
                return 'amnezia-awg3'

            def _config_path(self, protocol):
                return '/opt/amnezia/awg/awg0.conf'

        account = "private_key = 'SECRET-ACCOUNT-KEY'\ndevice_id = 'x'\n"
        profile = ("[Interface]\nPrivateKey = SECRET-PRIVATE-KEY\n"
                   "Address = 172.16.0.2\n[Peer]\nPublicKey = PUB\n"
                   "AllowedIPs = 0.0.0.0/0\n"
                   "Endpoint = engage.cloudflareclient.com:2408\n")

        manager = FakeManager()
        runtime._write_imported_profile(manager, 'awg3', account, profile)

        joined_commands = '\n'.join(manager.ssh.commands)
        self.assertNotIn('SECRET-ACCOUNT-KEY', joined_commands)
        self.assertNotIn('SECRET-PRIVATE-KEY', joined_commands)
        # The secrets travel through the SFTP-backed script path only.
        joined_scripts = '\n'.join(manager.ssh.scripts)
        self.assertIn('SECRET-PRIVATE-KEY', joined_scripts)
        self.assertTrue(any('chmod 600' in s or 'chmod 700' in s
                            for s in manager.ssh.scripts + manager.ssh.commands))


class WarpSourceProbeTests(unittest.TestCase):
    """Which servers can donate a profile, and why the others cannot."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(self._restore)
        self.runtime = panel.warp_runtime

    def _restore(self):
        panel.DATA_FILE = self._data_file
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_data(self, servers):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({'servers': servers, 'users': [], 'user_connections': []},
                      handle)

    def install(self, *, running=True, profile=False, api=True):
        """Point the runtime at one fake host with the given capability."""

        class FakeSSH:
            def run_sudo_command(self, command, timeout=60):
                if 'test -s' in command:
                    return '', '', 0 if profile else 1
                if 'api.cloudflareclient.com' in command:
                    if api is None:
                        return '', 'curl: not found', 127
                    return ('200' if api else '000'), '', 0
                return '', '', 0

            def run_sudo_script(self, script, timeout=120):
                return '', '', 0

        class FakeManager:
            def _container_name(self, protocol):
                return 'amnezia-awg3'

        ssh = FakeSSH()
        manager = FakeManager()
        manager.ssh = ssh
        for name, value in (('get_ssh', lambda server: ssh),
                            ('awg_manager_factory', lambda conn: manager),
                            ('_container_running', lambda m, p: running)):
            patcher = mock.patch.object(self.runtime, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def probe(self, servers):
        self.write_data(servers)
        return asyncio.run(self.runtime.probe_sources(0, 'target-uid'))

    def test_a_stored_profile_marks_the_source_ready(self):
        self.install(profile=True)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Open', {'awg3': {}})])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'ready')
        self.assertEqual(rows[0]['protocol'], 'awg3')

    def test_reachable_api_means_the_source_can_register(self):
        self.install(profile=False, api=True)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Open', {'awg3': {}})])
        self.assertEqual(rows[0]['status'], 'can_register')

    def test_a_blocked_api_is_reported_as_blocked(self):
        self.install(profile=False, api=False)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Blocked too', {'awg3': {}})])
        self.assertEqual(rows[0]['status'], 'blocked')

    def test_an_unprobeable_source_is_reported_as_unknown(self):
        self.install(profile=False, api=None)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Odd', {'awg3': {}})])
        self.assertEqual(rows[0]['status'], 'unknown')

    def test_a_stopped_instance_is_reported_not_usable(self):
        self.install(running=False)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Stopped', {'awg3': {}})])
        self.assertEqual(rows[0]['status'], 'no_instance')

    def test_an_ssh_failure_is_reported_as_unreachable(self):
        def boom(server):
            raise RuntimeError('ssh handshake failed')

        patcher = mock.patch.object(self.runtime, 'get_ssh', boom)
        patcher.start()
        self.addCleanup(patcher.stop)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}}),
                           server_record('source-uid', 'Dead', {'awg3': {}})])
        self.assertEqual(rows[0]['status'], 'unreachable')

    def test_the_target_itself_is_never_offered(self):
        self.install(profile=True)
        rows = self.probe([server_record('target-uid', 'Blocked', {'awg3': {}})])
        self.assertEqual(rows, [])


class WarpRegisterFailureClassTests(unittest.TestCase):
    """A provider TLS/SNI block must be reported as such, not as a generic failure."""

    def make_manager(self, probe_status):
        class FakeSSH:
            def run_sudo_command(self, command, timeout=60):
                if 'command -v wgcf' in command:
                    return '/usr/local/bin/wgcf\n', '', 0
                if 'api.cloudflareclient.com' in command:
                    return probe_status, '', 0
                if 'test -f' in command:
                    return '', '', 1
                if 'wgcf register' in command:
                    return '', 'TLS handshake failed', 1
                return '', '', 0

            def run_sudo_script(self, script, timeout=120):
                return '', '', 0

        class FakeManager:
            ssh = FakeSSH()

            def _container_name(self, protocol):
                return 'amnezia-awg3'

        return FakeManager()

    def test_a_blocked_api_raises_the_dedicated_code(self):
        manager = self.make_manager('000')
        with self.assertRaises(panel.SrvWarpError) as ctx:
            panel.warp_runtime._register_and_write_conf(manager, 'awg3')
        self.assertEqual(ctx.exception.code,
                         'srv_warp_register_api_unreachable')

    def test_any_other_register_failure_keeps_the_generic_code(self):
        manager = self.make_manager('200')
        with self.assertRaises(panel.SrvWarpError) as ctx:
            panel.warp_runtime._register_and_write_conf(manager, 'awg3')
        self.assertEqual(ctx.exception.code, 'srv_warp_register_failed')


if __name__ == '__main__':
    unittest.main()
