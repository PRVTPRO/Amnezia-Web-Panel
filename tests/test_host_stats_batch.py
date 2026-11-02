"""Exercise framing/parsing and the actual shell command without a VPS."""
import os
import re
import shlex
import shutil
import subprocess
import unittest
from unittest import mock

import server_stats
from managers.awg_manager import AWGManager
from managers.dns_manager import DNSManager


VALUES = {'cpu': '7.26', 'ram': '250 1000', 'disk': '600 1000',
          'network': '123456 987654', 'uptime': 'up 2 days, 3 hours',
          'ipv6': '2001:db8::1\n2001:db8:1::2'}


def batch_output(command, values=None):
    marker = re.search(r'@@HOST_STATS_[0-9a-f]+@@', command)[0]
    values = VALUES if values is None else values
    return '\n'.join(marker + ':' + name + '\n' + values.get(name, '')
                     for name in server_stats.HOST_STATS_COMMANDS) + '\n' + marker + ':done\n'


class HostStatsBatchTests(unittest.TestCase):
    def ssh(self, values=None):
        ssh = mock.Mock()
        ssh.run_command.side_effect = lambda command: (batch_output(command, values), '', 0)
        return ssh

    def test_preserves_all_fields_and_multiline_ipv6(self):
        ssh = self.ssh()
        self.assertEqual(server_stats.collect_host_stats(ssh), {
            'cpu': 7.3, 'ram_used': 250, 'ram_total': 1000, 'ram_percent': 25.0,
            'disk_used': 600, 'disk_total': 1000, 'disk_percent': 60.0,
            'net_rx': 123456, 'net_tx': 987654, 'uptime': 'up 2 days, 3 hours',
            'ipv6': ['2001:db8::1', '2001:db8:1::2']})
        self.assertEqual(ssh.run_command.call_count, 1)

    def test_empty_fields_keep_existing_defaults_without_bleeding_into_next_field(self):
        result = server_stats.collect_host_stats(self.ssh({}))
        self.assertEqual(result['cpu'], 0)
        self.assertEqual(result['ram_total'], 0)
        self.assertEqual(result['net_rx'], 0)
        self.assertEqual(result['ipv6'], [])

    def test_zero_total_and_invalid_numbers(self):
        values = dict(VALUES, cpu='not-a-number', ram='50 0', disk='broken', network='broken')
        result = server_stats.collect_host_stats(self.ssh(values))
        self.assertEqual(result['ram_percent'], 0)
        self.assertEqual(result['disk_used'], 0)
        self.assertEqual(result['net_tx'], 0)

    def test_failed_or_truncated_batch_is_not_reported_as_zero_usage(self):
        for code, text in [(1, ''), (0, 'partial data')]:
            ssh = mock.Mock()
            ssh.run_command.return_value = (text, '', code)
            with self.subTest(code=code), self.assertRaises(RuntimeError):
                server_stats.collect_host_stats(ssh)

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Bash shell required')
    def test_real_shell_preserves_sections_when_commands_omit_final_newlines(self):
        class ShellSSH:
            def run_command(self, command):
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                return result.stdout, result.stderr, result.returncode
        commands = {name: 'printf %s ' + shlex.quote(value) for name, value in VALUES.items()}
        with mock.patch.dict(server_stats.HOST_STATS_COMMANDS, commands, clear=True):
            result = server_stats.collect_host_stats(ShellSSH())
        self.assertEqual(result['cpu'], 7.3)
        self.assertEqual(result['uptime'], VALUES['uptime'])
        self.assertEqual(result['ipv6'], VALUES['ipv6'].splitlines())


class DockerStatusBatchTests(unittest.TestCase):
    def test_docker_version_and_daemon_are_checked_in_one_round_trip(self):
        ssh = mock.Mock()
        for output, code, expected in [('Docker version 28\nactive', 0, True),
                                       ('Docker version 28\ninactive', 3, False),
                                       ('', 127, False)]:
            ssh.reset_mock()
            ssh.run_command.return_value = (output, '', code)
            self.assertEqual(AWGManager(ssh).check_docker_installed(), expected)
            self.assertEqual(ssh.run_command.call_count, 1)

    def test_dns_uses_snapshot_for_running_stopped_and_missing_containers(self):
        for state in [(True, True), (True, False), (False, False)]:
            ssh = mock.Mock()
            ssh.docker_container_state.return_value = state
            result = DNSManager(ssh).get_server_status()
            self.assertEqual((result['container_exists'], result['container_running']), state)
            ssh.run_sudo_command.assert_not_called()

    def test_dns_falls_back_when_snapshot_is_unavailable_or_fails(self):
        for fails in (False, True):
            ssh = mock.Mock()
            ssh.docker_container_state.return_value = None
            if fails:
                ssh.docker_container_state.side_effect = OSError('temporary failure')
            ssh.run_sudo_command.side_effect = [('Up 2 hours', '', 0), ('amnezia-dns', '', 0)]
            result = DNSManager(ssh).get_server_status()
            self.assertTrue(result['container_running'])
            self.assertTrue(result['container_exists'])
