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
from managers.ssh_manager import SSHManager


VALUES = {'cpu': '7.26', 'ram': '250 1000', 'disk': '600 1000',
          'network': '123456 987654', 'uptime': 'up 2 days, 3 hours',
          'ipv6': '2001:db8::1\n2001:db8:1::2'}


def batch_output(command, values=None):
    marker = re.search(r'@@HOST_STATS_[0-9a-f]+@@', command)[0]
    values = VALUES if values is None else values
    return '\n'.join(marker + ':' + name + '\n' + values.get(name, '') + '\n' + marker + ':end:' + name + ':0'
                     for name in server_stats.HOST_STATS_COMMANDS) + '\n' + marker + ':done\n'


class HostStatsBatchTests(unittest.TestCase):
    def ssh(self, values=None):
        ssh = mock.Mock()
        ssh.run_command.side_effect = lambda command, **kw: (batch_output(command, values), '', 0)
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

    def test_nonfinite_cpu_does_not_break_json_response(self):
        for cpu in ('NaN', 'Infinity', '-Infinity'):
            result = server_stats.collect_host_stats(self.ssh(dict(VALUES, cpu=cpu)))
            self.assertEqual(result['cpu'], 0)
            self.assertEqual(result['errors'], {'cpu': 'invalid_value'})

    def test_failed_or_truncated_batch_returns_explicit_errors(self):
        for code, text in [(-1, ''), (127, ''), (1, ''), (0, 'partial data')]:
            ssh = mock.Mock()
            ssh.run_command.return_value = (text, '', code)
            with self.subTest(code=code):
                result = server_stats.collect_host_stats(ssh)
                self.assertEqual(result['cpu'], 0)
                self.assertIn('batch', result['errors'])
                self.assertIn('cpu', result['errors'])
                self.assertEqual(ssh.run_command.call_count, 1)

    def test_partial_output_preserves_only_completed_fields(self):
        ssh = mock.Mock()
        def truncated(command, **kw):
            marker = re.search(r'@@HOST_STATS_[0-9a-f]+@@', command)[0]
            return batch_output(command).split(marker + ':disk')[0] + marker + ':disk\n12', '', -1
        ssh.run_command.side_effect = truncated
        result = server_stats.collect_host_stats(ssh)
        self.assertEqual(result['cpu'], 7.3)
        self.assertEqual(result['ram_total'], 1000)
        self.assertNotIn('cpu', result['errors'])
        self.assertIn('disk', result['errors'])

    def test_one_failed_probe_does_not_discard_other_fields(self):
        ssh = mock.Mock()
        ssh.run_command.side_effect = lambda cmd, **kw: (
            batch_output(cmd).replace(':end:ram:0', ':end:ram:1'), '', 0)
        result = server_stats.collect_host_stats(ssh)
        self.assertEqual(result['errors'], {'ram': 'probe_failed'})
        self.assertEqual(result['cpu'], 7.3)
        self.assertEqual(result['disk_total'], 1000)

    def test_transport_exception_and_timeout_are_bounded(self):
        ssh = mock.Mock()
        ssh.run_command.side_effect = TimeoutError('synthetic transport failure')
        result = server_stats.collect_host_stats(ssh)
        self.assertIn('batch', result['errors'])
        self.assertEqual(ssh.run_command.call_args.kwargs['timeout'], 30)

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Bash shell required')
    def test_real_shell_preserves_sections_when_commands_omit_final_newlines(self):
        class ShellSSH:
            def run_command(self, command, **kw):
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                return result.stdout, result.stderr, result.returncode
        commands = {name: 'printf %s ' + shlex.quote(value) for name, value in VALUES.items()}
        with mock.patch.dict(server_stats.HOST_STATS_COMMANDS, commands, clear=True):
            result = server_stats.collect_host_stats(ShellSSH())
        self.assertEqual(result['cpu'], 7.3)
        self.assertEqual(result['uptime'], VALUES['uptime'])
        self.assertEqual(result['ipv6'], VALUES['ipv6'].splitlines())

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Bash shell required')
    def test_real_shell_isolates_a_failed_field_and_sets_locale(self):
        class ShellSSH:
            def run_command(self, command, **kw):
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                return result.stdout, result.stderr, result.returncode
        commands = {name: 'printf %s ' + shlex.quote(value) for name, value in VALUES.items()}
        commands['ram'] = 'exit 1'
        commands['uptime'] = 'printf %s "$LC_ALL"'
        with mock.patch.dict(server_stats.HOST_STATS_COMMANDS, commands, clear=True):
            result = server_stats.collect_host_stats(ShellSSH())
        self.assertEqual(result['errors'], {'ram': 'probe_failed'})
        self.assertEqual(result['uptime'], 'C')
        self.assertEqual(result['cpu'], 7.3)

    @unittest.skipUnless(os.name == 'posix', 'POSIX shell required')
    def test_missing_bash_degrades_without_retrying_each_field(self):
        class NoBashSSH:
            def run_command(self, command, **kw):
                result = subprocess.run('PATH=/no-host-tools; ' + command, shell=True,
                                        capture_output=True, text=True, timeout=10)
                return result.stdout, result.stderr, result.returncode
        result = server_stats.collect_host_stats(NoBashSSH())
        self.assertIn('batch', result['errors'])
        self.assertEqual(set(result['errors']) - {'batch'}, set(server_stats.HOST_STATS_COMMANDS))


class DockerStatusBatchTests(unittest.TestCase):
    def test_failed_snapshot_is_unknown_uncached_and_can_recover(self):
        ssh = SSHManager('fixture.invalid', 22, 'root')
        ssh.run_sudo_command = mock.Mock(side_effect=[
            ('', 'denied', 1), ('amnezia-dns\trunning\n', '', 0)])
        self.assertIsNone(ssh.docker_container_state('amnezia-dns'))
        self.assertIsNone(getattr(ssh, '_docker_ps_cache', None))
        self.assertEqual(ssh.docker_container_state('amnezia-dns'), (True, True))

    def test_dns_falls_back_after_actual_nonzero_snapshot(self):
        ssh = SSHManager('fixture.invalid', 22, 'root')
        ssh.run_sudo_command = mock.Mock(side_effect=[
            ('', 'denied', 1), ('Up 2 hours', '', 0), ('amnezia-dns', '', 0)])
        result = DNSManager(ssh).get_server_status()
        self.assertTrue(result['container_exists'])
        self.assertTrue(result['container_running'])

    def test_dns_reports_failed_fallback_as_unknown(self):
        ssh = mock.Mock()
        ssh.docker_container_state.return_value = None
        ssh.run_sudo_command.return_value = ('', 'denied', 1)
        self.assertIn('error', DNSManager(ssh).get_server_status())

    def test_dns_mutations_invalidate_even_after_partial_failure(self):
        for action in ('install_protocol', 'remove_container'):
            for fails in (False, True):
                ssh = mock.Mock()
                ssh.run_command.return_value = ('Docker version 28', '', 0)
                if fails:
                    ssh.run_sudo_command.side_effect = OSError('synthetic failure')
                manager = DNSManager(ssh)
                try:
                    getattr(manager, action)()
                except OSError:
                    self.assertEqual(action, 'remove_container')
                ssh.docker_ps_invalidate.assert_called_once_with()

    def test_docker_version_and_daemon_are_checked_in_one_round_trip(self):
        ssh = mock.Mock()
        for output, code, expected in [('', 0, True),
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
