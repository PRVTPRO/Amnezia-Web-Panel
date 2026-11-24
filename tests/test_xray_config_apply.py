"""Xray config apply: nothing the core cannot build is persisted, nothing
secret is left behind, and a core that does not come back gets its
previous configuration restored."""
import json
import unittest
from unittest import mock
from unittest.mock import Mock

from managers.xray_manager import (
    CONFIG_MODE, PRIVILEGES, START_STABLE, XrayConfigRejected, XrayManager,
    _core_verdict)

CONFIG = '/opt/amnezia/xray/server.json'
OLD = json.dumps({'tag': 'old'})
NEW = json.dumps({'tag': 'new'}, indent=2)
MOUNTS = "docker inspect -f '{{range .Mounts}}{{.Destination}}{{println}}{{end}}'"
STATE = "docker inspect -f '{{.State.Status}} {{.RestartCount}}'"
PROOF = 'Failed to start: main: failed to add address 2606:4700::1/128 to wg0'


class FakeHost:
    """A tiny host: files with modes, docker state and the core's verdict,
    all scripted through the commands the manager issues."""

    def __init__(self, previous=OLD, mounted=True, verdict=('', '', 0), states=None,
                 logs=''):
        self.files, self.modes = {}, {}
        if previous is not None:
            self.files[CONFIG] = previous
            self.modes[CONFIG] = 0o644
        self.uploads = []
        self.mounted = mounted
        # (stdout, stderr, code) of `xray run -test`
        self.verdict = verdict
        # (status, restart count) per state query; the last one repeats.
        # None when docker reports nothing at all.
        self.states = [('running', 0)] if states is None else list(states)
        self.logs = logs
        self.commands = []
        self.container_copies = []

    def upload_file_sudo(self, content, remote_path, mode=None):
        self.uploads.append((remote_path, mode))
        self.files[remote_path] = content
        self.modes[remote_path] = 0o644 if mode is None else mode
        return True

    def run_sudo_command(self, command, **kwargs):
        self.commands.append(command)
        if command.startswith('docker run --rm '):
            return self.verdict
        if command.startswith(MOUNTS):
            return ('/opt/amnezia/xray\n' if self.mounted else '', '', 0)
        if command.startswith(STATE):
            if not self.states:
                return ('', '', 1)
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return (f'{state[0]} {state[1]}\n', '', 0)
        if command.startswith('docker logs'):
            return (self.logs, '', 0)
        if command.startswith('cat '):
            path = command.split()[1]
            return (self.files.get(path, ''), '', 0 if path in self.files else 1)
        if command.startswith('mv -f -- '):
            source, target = command.split()[-2:]
            if source in self.files:
                self.files[target] = self.files.pop(source)
                self.modes[target] = self.modes.pop(source)
            return ('', '', 0)
        if command.startswith('rm -f -- '):
            self.files.pop(command.split()[-1], None)
            self.modes.pop(command.split()[-1], None)
            return ('', '', 0)
        if command.startswith('docker cp -- '):
            self.container_copies.append(command)
            return ('', '', 0)
        return ('', '', 0)


def manager_for(host):
    manager = XrayManager(host)
    manager._get_server_json = lambda: json.loads(host.files.get(CONFIG) or 'null')
    return manager


class CoreVerdictTests(unittest.TestCase):
    def test_the_failed_to_start_line_is_the_verdict(self):
        text = ('Xray 26.11.9\n[Info] infra/conf/serial: Reading config: x\n'
                + PROOF + ': invalid argument\n')
        self.assertEqual(_core_verdict(text), PROOF + ': invalid argument')

    def test_any_other_last_line_will_do(self):
        self.assertEqual(_core_verdict('a\nb\n'), 'b')
        self.assertEqual(_core_verdict(''), 'no error output')
        self.assertEqual(_core_verdict(None), 'no error output')


class WriteTests(unittest.TestCase):
    def test_the_candidate_is_proven_before_it_replaces_the_live_file(self):
        host = FakeHost()
        manager_for(host)._write_server_json(json.loads(NEW), restart=False)

        prove = next(i for i, c in enumerate(host.commands) if 'xray run -test' in c)
        commit = next(i for i, c in enumerate(host.commands) if c.startswith('mv -f -- '))
        self.assertLess(prove, commit)
        self.assertEqual(host.files, {CONFIG: NEW})

    def test_the_proof_runs_in_a_throwaway_container_like_the_live_one(self):
        host = FakeHost()
        manager_for(host)._write_server_json(json.loads(NEW), restart=False)

        stage, mode = host.uploads[0]
        # beside the live file, never under /tmp
        self.assertTrue(stage.startswith('/opt/amnezia/xray/.server.json.'))
        self.assertEqual(mode, CONFIG_MODE)
        prove = next(c for c in host.commands if 'xray run -test' in c)
        self.assertTrue(prove.startswith(f'docker run --rm {PRIVILEGES} '), prove)
        self.assertIn('-v /opt/amnezia/xray:/opt/amnezia/xray:ro ', prove)
        self.assertIn(f'-v {stage}:/tmp/.server.json.candidate:ro ', prove)
        self.assertIn('--entrypoint="" amneziavpn/amnezia-xray ', prove)
        self.assertTrue(prove.endswith('/usr/bin/xray run -test -c /tmp/.server.json.candidate'))

    def test_nothing_is_left_behind_and_the_live_file_is_root_only(self):
        host = FakeHost()
        manager_for(host)._write_server_json(json.loads(NEW), restart=False)

        self.assertEqual(list(host.files), [CONFIG])
        self.assertEqual(host.modes, {CONFIG: CONFIG_MODE})
        self.assertFalse(any(c.startswith('rm -f') for c in host.commands))
        self.assertFalse(any('/tmp/_xray' in c for c in host.commands))

    def test_a_hot_write_neither_stops_nor_starts_the_container(self):
        host = FakeHost()
        manager_for(host)._write_server_json(json.loads(NEW), restart=False)
        self.assertFalse(any(c.startswith(('docker stop', 'docker start')) for c in host.commands))

    def test_a_container_with_its_own_copy_gets_the_file_copied_in(self):
        host = FakeHost(mounted=False)
        manager_for(host)._write_server_json(json.loads(NEW), restart=False)
        self.assertEqual(host.container_copies,
                         [f'docker cp -- {host.uploads[0][0]} amnezia-xray:{CONFIG}'])
        self.assertEqual(host.files, {CONFIG: NEW})

    def test_a_rejected_config_leaves_the_live_file_untouched(self):
        # the core reports a build failure on stdout with its own exit code
        # and keeps its incidental log on stderr
        host = FakeHost(verdict=('Xray 26.11.9\n' + PROOF + ': invalid argument\n',
                                 '[Info] infra/conf/serial: Reading config: x\n'
                                 '[Warning] core: an incidental warning\n', 23))
        with self.assertRaises(XrayConfigRejected) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)

        self.assertEqual(host.files, {CONFIG: OLD})
        self.assertEqual(host.modes[CONFIG], 0o644)
        self.assertIn(PROOF + ': invalid argument', str(ctx.exception))
        self.assertNotIn('Reading config', str(ctx.exception))
        self.assertNotIn('incidental warning', str(ctx.exception))
        self.assertFalse(any(c.startswith(('docker stop', 'docker start')) for c in host.commands))


class RestartTests(unittest.TestCase):
    def test_the_core_must_be_seen_stable_after_the_start(self):
        host = FakeHost(states=[('running', 0), ('exited', 0), ('running', 0), ('running', 0)])
        manager_for(host)._write_server_json(json.loads(NEW), restart=True)

        stop = host.commands.index('docker stop amnezia-xray')
        start = host.commands.index('docker start amnezia-xray')
        self.assertLess(stop, start)
        self.assertEqual(host.commands.count('sleep 1'), START_STABLE)
        self.assertEqual(host.files, {CONFIG: NEW})

    def test_a_restarting_container_after_the_start_is_a_failure(self):
        # caught by the status itself, before the counter has moved
        host = FakeHost(states=[('running', 0), ('exited', 0), ('restarting', 0),
                                ('exited', 0), ('running', 0), ('running', 0)],
                        logs='Started\n' + PROOF + '\n')
        with self.assertRaises(RuntimeError) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)
        self.assertEqual(host.files, {CONFIG: OLD})
        self.assertIn('previous configuration was restored', str(ctx.exception))
        self.assertIn(PROOF, str(ctx.exception))

    def test_a_crash_loop_gets_the_previous_config_back(self):
        # the counter moves on the first poll; the restored core then holds
        host = FakeHost(states=[('running', 0), ('exited', 0), ('running', 1),
                                ('exited', 1), ('running', 1), ('running', 1)],
                        logs='Started\n' + PROOF + '\n')
        with self.assertRaises(RuntimeError) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)

        self.assertEqual(host.files, {CONFIG: OLD})
        self.assertEqual(host.modes[CONFIG], CONFIG_MODE)
        self.assertIn('previous configuration was restored', str(ctx.exception))
        self.assertIn(PROOF, str(ctx.exception))
        self.assertEqual(sum(c.startswith('docker start ') for c in host.commands), 2)
        self.assertEqual(host.commands.count('sleep 1'), 3)

    def test_nothing_is_restored_over_a_config_that_was_being_fixed(self):
        # the instance crash-looped before the write: the config being
        # replaced is the broken one
        host = FakeHost(states=[('restarting', 7), ('exited', 7), ('restarting', 8)])
        with self.assertRaises(RuntimeError) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)

        self.assertEqual(host.files, {CONFIG: NEW})
        self.assertNotIn('restored', str(ctx.exception))
        self.assertEqual(sum(c.startswith('docker start ') for c in host.commands), 1)

    def test_a_restore_that_fails_too_says_so(self):
        host = FakeHost(states=[('running', 0), ('exited', 0), ('running', 1),
                                ('exited', 1), ('restarting', 2)])
        with self.assertRaises(RuntimeError) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)
        self.assertEqual(host.files, {CONFIG: OLD})
        self.assertIn('neither the new nor the previous', str(ctx.exception))

    def test_a_container_that_will_not_stop_is_reported_before_any_start(self):
        host = FakeHost(states=[('running', 0), ('running', 0)])
        with self.assertRaises(RuntimeError) as ctx:
            manager_for(host)._write_server_json(json.loads(NEW), restart=True)
        self.assertIn('takes effect at the next start', str(ctx.exception))
        self.assertFalse(any(c.startswith('docker start ') for c in host.commands))
        self.assertEqual(host.files, {CONFIG: NEW})

    def test_without_a_state_to_verify_against_the_write_is_not_blocked(self):
        host = FakeHost()
        host.states = []
        manager_for(host)._write_server_json(json.loads(NEW), restart=True)
        self.assertEqual(host.files, {CONFIG: NEW})
        self.assertEqual(sum(c.startswith('docker start ') for c in host.commands), 1)


class ClientChangeTests(unittest.TestCase):
    KEPT = {'id': 'kept', 'email': 'kept'}
    GONE = {'id': 'gone', 'email': 'gone'}

    def setUp(self):
        self.config = {'inbounds': [{'protocol': 'vless', 'tag': 'proxy', 'port': 443,
                                     'settings': {'clients': [dict(self.KEPT), dict(self.GONE)],
                                                  'decryption': 'none'}}]}
        self.manager = XrayManager(Mock())
        self.manager._get_server_json = lambda: self.config
        self.manager._upgrade_config_for_stats = lambda *args, **kwargs: None
        self.manager._xray_api_add_user = Mock(return_value=True)
        self.manager._xray_api_remove_user = Mock(return_value=True)
        self.manager._write_server_json = Mock(
            side_effect=XrayConfigRejected('Xray rejected the configuration: nope'))

    def test_an_added_client_is_taken_back_live(self):
        with self.assertRaises(XrayConfigRejected):
            self.manager.add_client('xray', 'Phone', '203.0.113.9', 443)
        added = self.manager._xray_api_add_user.call_args[0][1]
        self.manager._xray_api_remove_user.assert_called_once_with(mock.ANY, added['id'])

    def test_a_removed_client_is_put_back_live(self):
        with self.assertRaises(XrayConfigRejected):
            self.manager.remove_client('xray', 'gone')
        self.manager._xray_api_add_user.assert_called_once_with(mock.ANY, self.GONE)

    def test_a_disabled_client_is_put_back_live(self):
        with self.assertRaises(XrayConfigRejected):
            self.manager.toggle_client('xray', 'gone', False)
        self.manager._xray_api_remove_user.assert_called_once_with(mock.ANY, 'gone')
        self.manager._xray_api_add_user.assert_called_once_with(mock.ANY, self.GONE)

    def test_an_enabled_client_is_taken_back_live(self):
        with self.assertRaises(XrayConfigRejected):
            self.manager.toggle_client('xray', 'fresh', True)
        added = self.manager._xray_api_add_user.call_args[0][1]
        self.assertEqual(added['id'], 'fresh')
        self.manager._xray_api_remove_user.assert_called_once_with(mock.ANY, 'fresh')

    def test_a_successful_write_touches_the_live_core_once(self):
        self.manager._write_server_json = Mock()
        self.manager._get_clients_table = lambda strict=True: []
        self.manager._save_clients_table = lambda table: None
        self.manager.get_client_config = lambda *args, **kwargs: 'vless://example'
        self.manager.add_client('xray', 'Phone', '203.0.113.9', 443)
        self.assertEqual(self.manager._xray_api_add_user.call_count, 1)
        self.manager._xray_api_remove_user.assert_not_called()
        self.manager._write_server_json.assert_called_once_with(mock.ANY, restart=False)


class ReadTests(unittest.TestCase):
    def test_a_read_survives_an_upgrade_that_cannot_be_persisted(self):
        manager = XrayManager(Mock())
        manager._get_server_json = lambda: {'inbounds': []}
        manager._upgrade_config_for_stats = Mock(
            side_effect=XrayConfigRejected('Xray rejected the configuration: nope'))
        manager._get_clients_table = lambda strict=True: []
        manager._get_default_xray_uuid = lambda: ''
        manager._query_xray_stats = lambda: {}
        self.assertEqual(manager.get_clients('xray'), [])


class InstallTests(unittest.TestCase):
    def _install(self, verdict=('', '', 0)):
        uploads, commands = [], []
        manager = XrayManager(Mock())
        manager.check_docker_installed = lambda: True
        manager.check_protocol_installed = lambda: False
        manager._config_dir = lambda: '/opt/amnezia/xray'
        manager.ssh.run_command = lambda *args, **kwargs: ('', '', 0)
        manager.ssh.upload_file_sudo = lambda content, path, mode=None: uploads.append((path, mode))
        manager.ssh.run_sudo_command = lambda command, **kwargs: (
            commands.append(command), verdict if 'xray run -test' in command else ('', '', 0))[1]
        return manager, uploads, commands

    def test_secrets_land_root_only_and_the_config_is_proven_before_the_start(self):
        manager, uploads, commands = self._install()
        manager.install_protocol(port=443)
        modes = dict(uploads)

        self.assertEqual(modes['/opt/amnezia/xray/server.json'], CONFIG_MODE)
        self.assertEqual(modes['/opt/amnezia/xray/xray_private.key'], CONFIG_MODE)
        self.assertEqual(modes['/opt/amnezia/xray/xray_public.key'], None)
        prove = next(i for i, c in enumerate(commands) if 'xray run -test' in c)
        start = next(i for i, c in enumerate(commands) if c.startswith('docker run -d'))
        self.assertLess(prove, start)

    def test_an_install_never_starts_a_container_on_a_config_the_core_refuses(self):
        manager, _, commands = self._install(
            verdict=(PROOF + ': invalid argument\n', '', 23))
        with self.assertRaises(XrayConfigRejected) as ctx:
            manager.install_protocol(port=443)
        self.assertIn(PROOF, str(ctx.exception))
        self.assertFalse(any(c.startswith('docker run -d') for c in commands))


if __name__ == '__main__':
    unittest.main()
