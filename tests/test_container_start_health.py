"""Regressions for the container start path.

A `docker cp` keeps the mode of the source file. When the panel wrote
start.sh from a 0644 host temp file and then failed to `docker exec chmod`
(the container was down), the entrypoint died with 'Permission denied' and
Docker restarted it forever, while the API answered 200 'started'.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
import peer_lifecycle_lock
from managers.awg_manager import (AWGManager, ensure_start_script_executable,
                                  start_script_mode)


class RecordingSSH:
    start_script_mode = 0o755

    def __init__(self):
        self.uploads = {}
        self.commands = []

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'amnezia-start-mode-' in command and command.startswith('docker cp'):
            return '', '', 0 if self.start_script_mode is not None else 1
        if command.startswith('stat -c %a '):
            return f'{self.start_script_mode:o}\n', '', 0
        return '', '', 0

    resolved_config_path = ''


class StartScriptDeliveryTests(unittest.TestCase):
    def test_write_sets_executable_before_copy_and_never_uses_docker_exec(self):
        ssh = RecordingSSH()
        manager = AWGManager(ssh)

        manager._write_start_script('awg2')

        self.assertEqual(ssh.uploads['/tmp/_amnz_start.sh'],
                         manager._render_start_script('awg2'))
        self.assertEqual(ssh.commands[:3], [
            'chmod 755 /tmp/_amnz_start.sh',
            'docker cp /tmp/_amnz_start.sh amnezia-awg2:/opt/amnezia/start.sh',
            'rm -f /tmp/_amnz_start.sh',
        ])
        self.assertTrue(ssh.commands[3].startswith(
            'docker cp amnezia-awg2:/opt/amnezia/start.sh '
            '/tmp/amnezia-start-mode-'))
        self.assertTrue(ssh.commands[4].startswith(
            'stat -c %a /tmp/amnezia-start-mode-'))
        self.assertTrue(ssh.commands[5].startswith(
            'rm -f /tmp/amnezia-start-mode-'))
        self.assertFalse([c for c in ssh.commands if 'docker exec' in c])

    def test_write_fails_loudly_when_the_copy_stays_non_executable(self):
        ssh = RecordingSSH()
        ssh.start_script_mode = 0o644
        with self.assertRaises(RuntimeError) as ctx:
            AWGManager(ssh)._write_start_script('awg2')
        self.assertIn('not executable', str(ctx.exception))
        self.assertIn('644', str(ctx.exception))

    def test_mode_is_read_through_the_host_copy(self):
        ssh = RecordingSSH()
        ssh.start_script_mode = 0o755
        self.assertTrue(start_script_mode(ssh, 'amnezia-awg3') & 0o111)

    def test_repair_restores_the_executable_bit_without_docker_exec(self):
        ssh = RecordingSSH()
        ssh.start_script_mode = 0o644
        calls = []
        real = ssh.run_sudo_command

        def run(command, timeout=60):
            if command.startswith('stat -c %a '):
                ssh.start_script_mode = 0o755
            calls.append(command)
            return real(command, timeout=timeout)

        ssh.run_sudo_command = run
        ok, detail = ensure_start_script_executable(ssh, 'amnezia-awg3')
        self.assertTrue(ok, detail)
        self.assertIn('755', detail)
        self.assertTrue(any(c.startswith('chmod 755 /tmp/amnezia-start-fix-')
                            for c in calls))
        self.assertFalse([c for c in calls if 'docker exec' in c])


class FakeSSH:
    """Answers the toggle inspect/start/log sequence from a script."""

    def __init__(self, states, logs='', running='false'):
        self.states = list(states)
        self.logs = logs
        self.running = running
        self.commands = []
        self.connected = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def docker_ps_invalidate(self):
        pass

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if '.State.Running' in command:
            return self.running + '\n', '', 0
        if 'docker inspect -f' in command:
            value = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return value + '\n', '', 0
        if command.startswith('docker logs'):
            return self.logs, '', 0
        if command.startswith('stat -c %a '):
            return '755\n', '', 0
        return '', '', 0


class ContainerToggleTests(unittest.TestCase):
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
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'servers': [{'name': 'srv', 'host': '198.51.100.1',
                             'ssh_port': 22, 'username': 'root',
                             'password': 'x', 'private_key': '',
                             'server_info': {}, 'uid': 'srv-uid',
                             'protocols': {}}],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': [],
            }, f)
        panel._invalidate_ip_status()
        self.addCleanup(panel._invalidate_ip_status)

    def toggle(self, ssh):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            return client.post('/api/servers/0/container/toggle',
                               json={'protocol': 'awg3'})

    def test_start_waits_for_a_real_running_state(self):
        ssh = FakeSSH(['running', 'running'])
        res = self.toggle(ssh)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['action'], 'started')

    def test_restart_loop_with_permission_denied_is_repaired_and_retried(self):
        ssh = FakeSSH(['restarting', 'running', 'running'],
                      logs='[dumb-init] /opt/amnezia/start.sh: Permission denied\n')
        res = self.toggle(ssh)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['action'], 'started')
        self.assertEqual(
            len([c for c in ssh.commands if c.startswith('docker start')]), 2)
        self.assertTrue(any('amnezia-start-fix-' in c for c in ssh.commands))

    def test_start_reports_failure_instead_of_success(self):
        ssh = FakeSSH(['restarting'], logs='some other failure\n')
        res = self.toggle(ssh)
        self.assertEqual(res.status_code, 500, res.text)
        body = res.json()
        self.assertEqual(body['error'], 'container_failed_to_start')
        self.assertEqual(body['state'], 'restarting')
        self.assertIn('some other failure', body['log'])

    def test_start_on_a_restart_loop_never_runs_docker_stop(self):
        """The UI shows 'Старт' for a restarting container (docker ps: no
        'Up'), while .State.Running is true: the click used to stop it."""
        ssh = FakeSSH(['restarting'], logs='', running='true true')
        res = self.toggle(ssh)
        self.assertEqual(res.status_code, 500, res.text)
        self.assertFalse([c for c in ssh.commands if c.startswith('docker stop')])
        self.assertTrue([c for c in ssh.commands if c.startswith('docker start')])
