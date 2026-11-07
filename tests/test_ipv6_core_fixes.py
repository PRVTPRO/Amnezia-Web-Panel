"""Focused regression tests for the IPv6 core defects A1-A9.

No SSH and no network: every remote read is served by a scripted fake. Each
test pins one defect from the review so a regression is caught by name.
"""
import asyncio
import hashlib
import json
import os
import unittest
from unittest import mock

from managers.awg_manager import AWGManager

CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'
AWG_DIR = '/opt/amnezia/awg'
CONTAINER = 'amnezia-awg'
BACKUP = 'amnezia-awg-ipv6bak'
IMAGE = 'amnezia/amneziawg:latest'

SERVER_CONFIG = (
    '[Interface]\n'
    'PrivateKey = SERVERPRIVATEKEY\n'
    'Address = 10.8.1.1/24\n'
    'ListenPort = 55424\n'
    '[Peer]\n'
    'PublicKey = PEER_A\n'
    'AllowedIPs = 10.8.1.2/32\n'
)


class FakeSSH:
    """run_sudo_command driven by a callable."""

    def __init__(self, handler):
        self.handler = handler
        self.commands = []

    def run_sudo_command(self, command, *args, **kwargs):
        self.commands.append(command)
        return self.handler(command)


class A1EntrypointTests(unittest.TestCase):
    def test_entrypoint_list_tail_is_kept_after_the_image(self):
        info = {
            'HostConfig': {'RestartPolicy': {'Name': 'always'}},
            'Config': {
                'Image': IMAGE,
                'Entrypoint': ['dumb-init', '/opt/amnezia/start.sh'],
                'Cmd': [],
            },
        }
        cmd = AWGManager._run_cmd_from_inspect(info, CONTAINER, IMAGE)
        # Entrypoint[0] is the --entrypoint; the tail is prepended to Cmd.
        self.assertIn('--entrypoint dumb-init', cmd)
        tokens = cmd.split()
        image_at = tokens.index(IMAGE)
        self.assertEqual(tokens[image_at + 1:], ['/opt/amnezia/start.sh'])
        # The effective argv (entrypoint + args) is dumb-init start.sh.
        self.assertEqual(
            [tokens[tokens.index('--entrypoint') + 1]]
            + tokens[image_at + 1:],
            ['dumb-init', '/opt/amnezia/start.sh'])


class A2RecreateCopyTests(unittest.TestCase):
    def _manager(self):
        source_sha = hashlib.sha256(SERVER_CONFIG.encode('utf-8')).hexdigest()

        def handler(command):
            if command.startswith(
                    "docker inspect -f '{{json .NetworkSettings.Networks}}'"):
                return (json.dumps({'amnezia-dns-net': {}}), '', 0)
            if command.startswith(f'docker inspect {BACKUP}'):
                return (json.dumps([{
                    'HostConfig': {'NetworkMode': 'amnezia-dns-net'},
                    'Config': {'Entrypoint': ['dumb-init',
                                              '/opt/amnezia/start.sh'],
                               'Cmd': []},
                }]), '', 0)
            if 'sha256sum' in command:
                if 'awg0.conf' in command:
                    return (source_sha + '  /tmp/x\n', '', 0)
                if 'wireguard' in command:
                    return ('b' * 64 + '  /tmp/x\n', '', 0)
                if 'clientsTable' in command:
                    return ('c' * 64 + '  /tmp/x\n', '', 0)
                return ('d' * 64 + '  /tmp/x\n', '', 0)
            if 'python3 -c' in command:
                return ('', '', 0)
            if 'grep -c' in command:
                return ('1\n', '', 0)
            if 'ip -6 route show default' in command:
                return ('default via fe80::1 dev eth0\n', '', 0)
            return ('', '', 0)

        ssh = FakeSSH(handler)
        manager = AWGManager(ssh)
        manager._get_server_config = mock.Mock(return_value=SERVER_CONFIG)
        manager._resolve_config_path = mock.Mock(return_value=CONFIG_PATH)
        manager._container_run_image = mock.Mock(return_value=IMAGE)
        manager._wait_container_running = mock.Mock(return_value=True)
        manager._invalidate_config_cache = mock.Mock()
        return manager, ssh.commands

    def test_full_awg_directory_is_copied_and_verified(self):
        manager, commands = self._manager()
        manager._recreate_container_ipv6('awg')
        joined = '\n'.join(commands)
        self.assertIn(
            f'docker cp {BACKUP}:{AWG_DIR}/. {CONTAINER}:{AWG_DIR}/', joined)
        # Keys and clientsTable are verified, not silently lost.
        self.assertIn('wireguard_server_public_key.key', joined)
        self.assertIn('clientsTable', joined)
        # amnezia-dns-net is already attached: do not connect it twice.
        self.assertFalse(any('docker network connect' in c for c in commands))


class A3SetInstanceGateTests(unittest.TestCase):
    def _manager(self, gateway=None):
        manager = AWGManager(mock.Mock())
        manager.ssh.run_sudo_command.return_value = ('', '', 0)
        manager.get_instance_ipv6_state = mock.Mock(return_value={
            'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
            'container': 'c', 'needs_recreate': False,
            'ipv6_enabled': gateway is not None,
            'subnet_v6': gateway})
        manager._peers_state = mock.Mock(return_value=(0, 0, True))
        manager._used_subnet_indexes = mock.Mock(return_value=set())
        manager._subnet_ip = mock.Mock(return_value='7')
        manager._verify_interface_up = mock.Mock()
        manager._invalidate_config_cache = mock.Mock()
        manager._set_config_address_ipv6 = mock.Mock()
        manager._write_start_script = mock.Mock()
        return manager

    def test_env_off_blocks_enable_before_any_write(self):
        manager = self._manager()
        with mock.patch.dict(os.environ, {'AWG_IPV6': 'off'}):
            with self.assertRaises(RuntimeError) as ctx:
                manager.set_instance_ipv6('awg3', True)
        self.assertEqual(str(ctx.exception), 'env_off')
        manager._set_config_address_ipv6.assert_not_called()

    def test_start_script_failure_on_disable_restores_the_previous_gateway(self):
        manager = self._manager(gateway='fd42:8:1::1/64')
        manager._write_start_script.side_effect = RuntimeError('upload failed')
        with self.assertRaises(RuntimeError):
            manager.set_instance_ipv6('awg3', False)
        calls = [c.args[1] for c in
                 manager._set_config_address_ipv6.call_args_list]
        self.assertIn('fd42:8:1::1/64', calls)

    def test_failed_disable_restores_the_old_gateway(self):
        manager = self._manager(gateway='fd42:8:1::1/64')
        manager.ssh.run_sudo_command.return_value = ('', 'boom', 1)
        with self.assertRaises(RuntimeError) as ctx:
            manager.set_instance_ipv6('awg3', False)
        self.assertEqual(str(ctx.exception), 'server_off')
        calls = [c.args[1] for c in
                 manager._set_config_address_ipv6.call_args_list]
        self.assertEqual(calls[-1], 'fd42:8:1::1/64')


class A4StateReadTests(unittest.TestCase):
    def _manager(self, config, running=True):
        ssh = mock.Mock()
        ssh.run_sudo_command.return_value = ('0', '', 0)
        ssh.docker_container_state.return_value = (running, True)
        manager = AWGManager(ssh)
        manager._get_server_config = mock.Mock(return_value=config)
        manager._peers_state = mock.Mock(return_value=(0, 0, True))
        manager.exit_link_info = mock.Mock(return_value=None)
        manager._host_ipv6_info = mock.Mock(
            return_value={'disabled_by_sysctl': False})
        return manager

    def test_failed_config_read_is_state_unreadable(self):
        manager = self._manager(SERVER_CONFIG)
        manager._get_server_config = mock.Mock(
            side_effect=RuntimeError('ssh down'))
        state = manager.get_instance_ipv6_state(
            'awg3', docker_info={'ipv6_enabled': True})
        self.assertEqual(state['blocked_reason'], 'state_unreadable')
        self.assertIsNone(state['peers'])
        self.assertFalse(state['can_enable'])
        self.assertFalse(state['can_disable'])

    def test_docker_off_blocks_enable(self):
        manager = self._manager(SERVER_CONFIG)
        state = manager.get_instance_ipv6_state(
            'awg3', docker_info={'ipv6_enabled': False})
        self.assertEqual(state['blocked_reason'], 'docker_off')
        self.assertFalse(state['can_enable'])

    def test_gateway_with_stopped_container_cannot_be_disabled(self):
        manager = self._manager(
            '[Interface]\nAddress = 10.8.1.1/24, fd42:8:1::1/64\n',
            running=False)
        state = manager.get_instance_ipv6_state(
            'awg3', docker_info={'ipv6_enabled': True})
        self.assertEqual(state['blocked_reason'], 'server_off')
        self.assertFalse(state['can_disable'])


class A5DisabledRowTests(unittest.TestCase):
    def test_disabled_clients_table_row_is_not_a_peer(self):
        manager = AWGManager(mock.Mock())
        manager._get_clients_table = mock.Mock(return_value=[
            {'clientId': 'DISABLED', 'enabled': False}])
        manager._get_server_config = mock.Mock(return_value=SERVER_CONFIG)
        manager._parse_peers_from_config = mock.Mock(return_value={})
        peers, _v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        self.assertEqual(peers, 0)


class A6DnsSixTests(unittest.TestCase):
    def test_no_gateway_returns_empty_before_reading_the_key(self):
        manager = AWGManager(mock.Mock())
        manager._get_subnet_ipv6_ip = mock.Mock(return_value='')
        manager._read_config_key = mock.Mock(return_value='2001:db8::53')
        self.assertEqual(manager._get_dns6('awg3'), '')
        manager._read_config_key.assert_not_called()


class A7ClientConfigTests(unittest.TestCase):
    def test_stored_client_ipv6_is_dropped_on_an_ipv4_only_instance(self):
        manager = AWGManager(mock.Mock())
        manager._get_clients_table = mock.Mock(return_value=[{
            'clientId': 'C',
            'userData': {
                'clientPrivateKey': 'priv',
                'clientIp': '10.8.1.10',
                'psk': 'psk',
                'clientIpv6': 'fd42:8:1::a',
            },
        }])
        manager._get_subnet_ipv6_ip = mock.Mock(return_value='')
        manager._get_server_public_key = mock.Mock(return_value='SERVER_PUB')
        manager._get_server_psk = mock.Mock(return_value='PSK')
        manager._get_awg_params_from_config = mock.Mock(return_value={'port': '55424'})
        manager._get_dns = mock.Mock(return_value='1.1.1.1, 1.0.0.1')
        manager._get_mtu = mock.Mock(return_value='1376')
        manager._read_config_key = mock.Mock(return_value='2001:db8::53')
        config = manager.get_client_config(
            'awg3', 'C', 'vpn.example.com', 55424)
        self.assertIn('Address = 10.8.1.10/32', config)
        self.assertNotIn('fd42:8:1::a', config)
        self.assertNotIn('2001:db8::53', config)


class A8DockerWriteTests(unittest.TestCase):
    def _manager(self, ip6tables_ok=True):
        ssh = mock.Mock()
        ssh.run_sudo_command.return_value = ('{}', '', 0)
        manager = AWGManager(ssh)
        manager._host_ipv6_info = mock.Mock(
            return_value={'disabled_by_sysctl': False})
        manager._docker_ipv6_info = mock.Mock(return_value={
            'ip6tables_ok': ip6tables_ok, 'flags_conflict': False})
        scripts = []
        manager.ssh.run_sudo_script = mock.Mock(
            side_effect=lambda script, timeout=120: (
                scripts.append(script) or ('', '', 0)))
        return manager, scripts

    def test_script_sets_daemon_json_mode(self):
        manager, scripts = self._manager()
        manager.enable_docker_ipv6(restart=False)
        self.assertIn('chmod 0644 /etc/docker/daemon.json', scripts[0])

    def test_restart_without_ip6tables_is_refused_before_writing(self):
        manager, scripts = self._manager(ip6tables_ok=False)
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'ip6tables_unsupported')
        self.assertEqual(scripts, [])


class A9ExitLinkTests(unittest.TestCase):
    def _harness(self):
        from test_exit_link_service import Harness
        return Harness()

    def test_config_read_failure_is_state_unreadable(self):
        from exit_link_service import ExitLinkError
        h = self._harness()

        def boom(protocol):
            raise RuntimeError('ssh down')

        h.awg()._get_server_config = boom
        with self.assertRaises(ExitLinkError) as ctx:
            asyncio.run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'state_unreadable')

    def test_address_with_ipv6_token_is_refused(self):
        from exit_link_service import ExitLinkError
        h = self._harness()
        h.awg()._get_server_config = lambda protocol: (
            '[Interface]\nAddress = 10.8.1.1/24, fd42:8:1::1/64\n')
        with self.assertRaises(ExitLinkError) as ctx:
            asyncio.run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_link_ipv6')


class R1EntrypointWithCmdTests(unittest.TestCase):
    def test_entrypoint_tail_is_prepended_to_a_non_empty_cmd(self):
        info = {
            'HostConfig': {'RestartPolicy': {'Name': 'always'}},
            'Config': {
                'Image': IMAGE,
                'Entrypoint': ['dumb-init', '/opt/amnezia/start.sh'],
                'Cmd': ['/bin/sh', '-c', 'x'],
            },
        }
        cmd = AWGManager._run_cmd_from_inspect(info, CONTAINER, IMAGE)
        tokens = cmd.split()
        image_at = tokens.index(IMAGE)
        self.assertEqual(
            tokens[image_at + 1:],
            ['/opt/amnezia/start.sh', '/bin/sh', '-c', 'x'])


class R2HostReadableTests(unittest.TestCase):
    def test_both_failed_route_probes_make_the_host_unreadable(self):
        ssh = FakeSSH(lambda command: ('', '', 255))
        manager = AWGManager(ssh)
        host = manager._host_ipv6_info()
        self.assertIs(host['readable'], False)

    def test_dead_ssh_link_is_unknown_not_absent(self):
        ssh = FakeSSH(lambda command: ('', '', 255))
        manager = AWGManager(ssh)
        manager.get_instance_ipv6_state = mock.Mock(
            side_effect=RuntimeError('ssh down'))
        status = manager.get_ip_status(['awg3'])
        self.assertEqual(status['state'], 'unknown')
        self.assertEqual(status['error'], 'ssh_failed')
        self.assertEqual(status['host']['ipv4_state'], 'unknown')
        self.assertEqual(status['host']['ipv6_state'], 'unknown')
        # The payload keeps its shape.
        self.assertIn('docker', status)
        self.assertIn('instances', status)

    def test_empty_output_with_zero_exit_code_is_readable(self):
        ssh = FakeSSH(lambda command: ('', '', 0))
        host = AWGManager(ssh)._host_ipv6_info()
        self.assertIs(host['readable'], True)


class R3IdempotentToggleTests(unittest.TestCase):
    def _manager(self, ipv6_enabled):
        manager = AWGManager(mock.Mock())
        manager.ssh.run_sudo_command.return_value = ('', '', 0)
        manager.get_instance_ipv6_state = mock.Mock(return_value={
            'ipv6_enabled': ipv6_enabled, 'peers': 5,
            'blocked_reason': 'peers', 'exit_linked': False,
            'container': 'c', 'needs_recreate': False})
        manager._set_config_address_ipv6 = mock.Mock()
        manager._write_start_script = mock.Mock()
        return manager

    def test_repeat_enable_does_not_write_or_restart(self):
        manager = self._manager(True)
        state = manager.set_instance_ipv6('awg3', True)
        self.assertTrue(state['ipv6_enabled'])
        manager._set_config_address_ipv6.assert_not_called()
        manager._write_start_script.assert_not_called()
        manager.ssh.run_sudo_command.assert_not_called()

    def test_repeat_disable_does_not_write_or_restart(self):
        manager = self._manager(False)
        state = manager.set_instance_ipv6('awg3', False)
        self.assertFalse(state['ipv6_enabled'])
        manager._set_config_address_ipv6.assert_not_called()
        manager._write_start_script.assert_not_called()
        manager.ssh.run_sudo_command.assert_not_called()


class R4ModalGuardTests(unittest.TestCase):
    def _source(self, name):
        path = os.path.join(os.path.dirname(__file__), '..', 'templates', name)
        with open(path, encoding='utf-8') as handle:
            return handle.read()

    def test_close_modal_honours_the_ip_settings_hook(self):
        base = self._source('base.html')
        self.assertIn("id === 'ipSettingsModal'", base)
        self.assertIn('window.ipSettingsCanClose', base)
        # Backdrop click and Escape take the same guarded path.
        self.assertIn('canCloseModal(e.target.id)', base)

    def test_close_ip_settings_reuses_the_hook(self):
        server = self._source('server.html')
        self.assertIn('window.ipSettingsCanClose = function ()', server)
        self.assertIn('if (!window.ipSettingsCanClose()) return;', server)


class R5PrepareHostHonoursPreferenceTests(unittest.TestCase):
    """An explicit IPv4-only choice must not enable host-level Docker IPv6."""

    class _SSH:
        def __init__(self):
            self.script = ''

        def run_sudo_script(self, script):
            self.script = script
            return '', '', 0

    def test_prepare_host_skips_docker_ipv6_when_disallowed(self):
        ssh = self._SSH()
        AWGManager(ssh).prepare_host('awg3', allow_ipv6=False)
        self.assertIn('ALLOW_IPV6=0', ssh.script)
        self.assertIn('[ "$ALLOW_IPV6" = "1" ]', ssh.script)

    def test_prepare_host_keeps_docker_ipv6_when_allowed(self):
        ssh = self._SSH()
        AWGManager(ssh).prepare_host('awg3', allow_ipv6=True)
        self.assertIn('ALLOW_IPV6=1', ssh.script)


if __name__ == '__main__':
    unittest.main()
