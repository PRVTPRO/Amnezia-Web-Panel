"""Unit tests for the IPv6 container recreate path of AWGManager.

No SSH is opened: AWGManager is built on a Mock and every remote read is
answered by a scripted `run_sudo_command` side effect. The tests pin the
contract of `_run_cmd_from_inspect` (flags rebuilt from docker inspect data,
with the IPv6 sysctls forced) and of `_recreate_container_ipv6` (fallback to
`_docker_run_cmd`, rollback on copy failure or config mismatch, and the
backup container kept until the IPv6 route check passes).
"""
import hashlib
import json
import unittest
from unittest import mock

from managers.awg_manager import AWGManager

CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'

SERVER_CONFIG = (
    '[Interface]\n'
    'PrivateKey = SERVERPRIVATEKEY\n'
    'Address = 10.8.1.1/24\n'
    'ListenPort = 55424\n'
    '[Peer]\n'
    'PublicKey = PEER_A\n'
    'AllowedIPs = 10.8.1.2/32\n'
)

CONTAINER = 'amnezia-awg'
BACKUP = 'amnezia-awg-ipv6bak'
IMAGE = 'amnezia/amneziawg:latest'
FINAL_RM = f'docker rm -f {BACKUP} >/dev/null 2>&1'
RESTORE_RM = f'docker rm -f {CONTAINER} >/dev/null 2>&1; true'


class RunCmdFromInspectTests(unittest.TestCase):
    """The run command is rebuilt from the container's own inspect data."""

    def _inspect(self, **overrides):
        info = {
            'Privileged': True,
            'CapAdd': ['NET_ADMIN', 'SYS_MODULE'],
            'CapDrop': ['MKNOD'],
            'Binds': ['/lib/modules:/lib/modules', '/data:/data:ro'],
            'Ulimits': [{'Name': 'nofile', 'Soft': 51200, 'Hard': 51200}],
            'PortBindings': {
                '55424/udp': [{'HostIp': '', 'HostPort': '55424'}],
                '51820/udp': [{'HostIp': '0.0.0.0', 'HostPort': '51820'}],
            },
            'RestartPolicy': {'Name': 'always'},
            'Sysctls': {'net.ipv4.conf.all.src_valid_mark': '1'},
            'ExtraHosts': ['host.docker.internal:host-gateway'],
            'NetworkMode': 'amnezia-dns-net',
        }
        info.update(overrides)
        return {'HostConfig': info}

    def test_inspect_dict_emits_every_flag(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._inspect(), CONTAINER, IMAGE)
        self.assertIn('docker run -d', cmd)
        self.assertIn('--privileged', cmd)
        self.assertIn('--cap-add=NET_ADMIN', cmd)
        self.assertIn('--cap-add=SYS_MODULE', cmd)
        self.assertIn('--cap-drop=MKNOD', cmd)
        self.assertIn('-v /lib/modules:/lib/modules', cmd)
        self.assertIn('-v /data:/data:ro', cmd)
        self.assertIn('--ulimit nofile=51200:51200', cmd)
        self.assertIn('-p 55424:55424/udp', cmd)
        self.assertIn('-p 0.0.0.0:51820:51820/udp', cmd)
        self.assertIn('--restart always', cmd)
        self.assertIn('--add-host host.docker.internal:host-gateway', cmd)
        self.assertIn('--network amnezia-dns-net', cmd)
        self.assertIn('--sysctl net.ipv4.conf.all.src_valid_mark=1', cmd)
        self.assertIn('--name amnezia-awg', cmd)
        self.assertTrue(cmd.endswith('amnezia/amneziawg:latest'))

    def test_ipv6_sysctls_are_always_forced(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._inspect(), CONTAINER, IMAGE)
        self.assertIn('--sysctl net.ipv6.conf.all.disable_ipv6=0', cmd)
        self.assertIn('--sysctl net.ipv6.conf.default.disable_ipv6=0', cmd)

    def test_default_bridge_network_mode_is_omitted(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._inspect(NetworkMode='bridge'), CONTAINER, IMAGE)
        self.assertNotIn('--network', cmd)

    def test_none_or_non_dict_returns_none(self):
        self.assertIsNone(AWGManager._run_cmd_from_inspect(
            None, CONTAINER, IMAGE))
        self.assertIsNone(AWGManager._run_cmd_from_inspect(
            'not a dict', CONTAINER, IMAGE))
        self.assertIsNone(AWGManager._run_cmd_from_inspect(
            [], CONTAINER, IMAGE))


class RecreateContainerIpv6Tests(unittest.TestCase):
    """`_recreate_container_ipv6` end-to-end against a scripted Mock SSH."""

    def _manager(self, inspect_data=None, fail_cp=False, copied_sha=None,
                 route_out='default via fe80::1 dev eth0\n'):
        ssh = mock.Mock()
        ssh._awg_batch = None
        commands = []

        def sudo(command, *args, **kwargs):
            commands.append(command)
            if 'for p in /opt/amnezia/awg/' in command:
                return (CONFIG_PATH + '\n', '', 0)
            if 'docker exec -i amnezia-awg cat ' in command:
                return (SERVER_CONFIG, '', 0)
            if command.startswith("docker inspect -f '{{.Config.Image}}'"):
                return (IMAGE + '\n', '', 0)
            if command.startswith('docker inspect amnezia-awg-ipv6bak'):
                if inspect_data is None:
                    return ('', '', 1)
                return (json.dumps([inspect_data]), '', 0)
            if command.startswith('docker run -d'):
                return ('', '', 0)
            if 'docker network connect amnezia-dns-net' in command:
                return ('', '', 0)
            if command.startswith('docker cp '):
                if fail_cp:
                    return ('', 'cp: error copying', 1)
                return ('', '', 0)
            if 'sha256sum' in command:
                return (f'{copied_sha}  {CONFIG_PATH}\n', '', 0)
            if '{{.State.Status}}' in command:
                return ('running\n', '', 0)
            if 'ip -6 route show default' in command:
                return (route_out, '', 0)
            return ('', '', 0)

        ssh.run_sudo_command.side_effect = sudo
        manager = AWGManager(ssh)
        return manager, commands

    @staticmethod
    def _source_sha():
        return hashlib.sha256(SERVER_CONFIG.encode('utf-8')).hexdigest()

    def test_inspect_missing_falls_back_to_docker_run_cmd(self):
        manager, commands = self._manager(
            inspect_data=None, copied_sha=self._source_sha())
        result = manager._recreate_container_ipv6('awg')
        self.assertEqual(result, CONTAINER)
        self.assertIn('docker inspect amnezia-awg-ipv6bak 2>/dev/null', commands)
        run = next(c for c in commands if c.startswith('docker run -d'))
        self.assertIn('--sysctl="net.ipv6.conf.all.disable_ipv6=0"', run)
        self.assertIn('--sysctl="net.ipv6.conf.default.disable_ipv6=0"', run)
        self.assertIn('--privileged', run)
        self.assertIn('--name amnezia-awg', run)
        self.assertIn('-p 55424:55424/udp', run)

    def test_inspect_dict_drives_the_run_command(self):
        inspect_data = {
            'HostConfig': {
                'Privileged': True,
                'CapAdd': ['NET_ADMIN'],
                'Binds': ['/lib/modules:/lib/modules'],
                'Ulimits': [{'Name': 'nofile', 'Soft': 51200, 'Hard': 51200}],
                'PortBindings': {
                    '55424/udp': [{'HostIp': '', 'HostPort': '55424'}]},
                'RestartPolicy': {'Name': 'always'},
                'Sysctls': {'net.ipv4.conf.all.src_valid_mark': '1'},
                'ExtraHosts': ['host.docker.internal:host-gateway'],
                'NetworkMode': 'amnezia-dns-net',
            }
        }
        manager, commands = self._manager(
            inspect_data=inspect_data, copied_sha=self._source_sha())
        manager._recreate_container_ipv6('awg')
        run = next(c for c in commands if c.startswith('docker run -d'))
        self.assertIn('--privileged', run)
        self.assertIn('--cap-add=NET_ADMIN', run)
        self.assertIn('-v /lib/modules:/lib/modules', run)
        self.assertIn('--ulimit nofile=51200:51200', run)
        self.assertIn('-p 55424:55424/udp', run)
        self.assertIn('--restart always', run)
        self.assertIn('--add-host host.docker.internal:host-gateway', run)
        self.assertIn('--network amnezia-dns-net', run)
        self.assertIn('--sysctl net.ipv4.conf.all.src_valid_mark=1', run)
        self.assertIn('--sysctl net.ipv6.conf.all.disable_ipv6=0', run)
        self.assertIn('--sysctl net.ipv6.conf.default.disable_ipv6=0', run)

    def assert_restore_sequence(self, commands):
        """Rollback order: remove the new container, rename the backup back,
        then start the old container again."""
        self.assertIn(RESTORE_RM, commands)
        self.assertIn(f'docker rename {BACKUP} {CONTAINER}', commands)
        self.assertIn(f'docker start {CONTAINER}', commands)
        self.assertLess(commands.index(RESTORE_RM),
                        commands.index(f'docker rename {BACKUP} {CONTAINER}'))
        self.assertLess(
            commands.index(f'docker rename {BACKUP} {CONTAINER}'),
            commands.index(f'docker start {CONTAINER}'))

    def test_docker_cp_failure_restores_old_container(self):
        manager, commands = self._manager(fail_cp=True)
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg')
        self.assertEqual(str(ctx.exception), 'state_unreadable')
        self.assert_restore_sequence(commands)
        self.assertFalse(any(c == FINAL_RM for c in commands))
        self.assertNotIn('ip -6 route show default', ' | '.join(commands))

    def test_config_sha_mismatch_restores_old_container(self):
        manager, commands = self._manager(copied_sha='f' * 64)
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg')
        self.assertEqual(str(ctx.exception), 'state_unreadable')
        self.assert_restore_sequence(commands)
        self.assertFalse(any(c == FINAL_RM for c in commands))

    def test_success_keeps_backup_until_route_check(self):
        manager, commands = self._manager(copied_sha=self._source_sha())
        result = manager._recreate_container_ipv6('awg')
        self.assertEqual(result, CONTAINER)
        route = next(c for c in commands if 'ip -6 route show default' in c)
        self.assertIn(route, commands)
        self.assertTrue(any(c == FINAL_RM for c in commands))
        self.assertLess(commands.index(route), commands.index(FINAL_RM))
        # The old container is renamed to the backup once and never restored.
        self.assertEqual(
            commands.count(f'docker rename {CONTAINER} {BACKUP}'), 1)
        self.assertNotIn(f'docker rename {BACKUP} {CONTAINER}', commands)
        self.assertEqual(manager.ssh.docker_ps_invalidate.call_count, 1)


if __name__ == '__main__':
    unittest.main()
