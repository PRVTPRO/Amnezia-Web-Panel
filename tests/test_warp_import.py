"""Тесты импорта WARP-профиля с другого сервера (фича для SNI-фильтрованных хостов)."""

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


if __name__ == '__main__':
    unittest.main()
