"""Regression tests for shell argument boundaries and remote staging."""
import json
import shlex
import unittest
from unittest.mock import Mock

from managers.backup_manager import BackupManager
from managers.ssh_manager import SSHManager
from managers.telemt_manager import TelemtManager


class ManagerSecurityTests(unittest.TestCase):
    def test_telemt_payload_is_literal_json(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ('{}', '', 0)
        data = {'secret': '$(touch /tmp/owned)`id`\\"\'value'}
        TelemtManager(ssh)._api_request('POST', '/v1/users', data)
        command = ssh.run_sudo_command.call_args.args[0]
        argv = shlex.split(command)
        self.assertEqual(json.loads(argv[argv.index('-d') + 1]), data)
        # POSIX single quoting must protect substitutions, not just JSON quotes.
        self.assertIn(shlex.quote(json.dumps(data)), command)

    def test_telemt_path_cannot_add_shell_or_curl_arguments(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ('{}', '', 0)
        path = '/v1/users/a; id # -o /tmp/owned'
        TelemtManager(ssh)._api_request('DELETE', path)
        command = ssh.run_sudo_command.call_args.args[0]
        argv = shlex.split(command)
        self.assertEqual(argv[-1], 'http://127.0.0.1:9091' + path)
        self.assertIn(shlex.quote(argv[-1]), command)
        self.assertIn('--globoff', argv)

    def test_backup_script_assignments_are_literal(self):
        ssh = Mock()
        ssh.run_sudo_script.return_value = ('', 'failure', 1)
        BackupManager(ssh).create_backup("telemt'; id #", "telemt'; id #")
        script = ssh.run_sudo_script.call_args.args[0]
        for name in ('protocol', 'container'):
            line = next(line for line in script.splitlines() if line.startswith(name + '='))
            self.assertEqual(shlex.split(line), [name + "=telemt'; id #"])

    def make_ssh(self):
        ssh = SSHManager('example.test', 22, 'admin', password='secret')
        ssh.ensure_connected = Mock()
        ssh.run_command = Mock(return_value=('/tmp/amnezia-private.ABC123\n', '', 0))
        ssh.run_sudo_command = Mock(return_value=('', '', 0))
        ssh.upload_file = Mock()
        return ssh

    def test_sudo_script_uses_private_allocated_directory_and_cleans_up(self):
        ssh = self.make_ssh()
        ssh.run_sudo_script('echo ok; exit 7')
        self.assertIn('mktemp -d', ssh.run_command.call_args_list[0].args[0])
        self.assertEqual(ssh.upload_file.call_args.args[1], '/tmp/amnezia-private.ABC123/script.sh')
        self.assertIn('rm -rf --', ssh.run_command.call_args_list[-1].args[0])

    def test_sudo_upload_quotes_target_and_cleans_up_on_failure(self):
        ssh = self.make_ssh()
        ssh.run_sudo_command.return_value = ('', 'denied', 1)
        target = "/etc/config'; touch /tmp/owned; #"
        with self.assertRaises(RuntimeError):
            ssh.upload_file_sudo('secret', target)
        argv = shlex.split(ssh.run_sudo_command.call_args.args[0])
        self.assertEqual(argv, ['mv', '--', '/tmp/amnezia-private.ABC123/content', target])
        self.assertIn('rm -rf --', ssh.run_command.call_args_list[-1].args[0])

    def test_staging_failure_never_uploads(self):
        ssh = self.make_ssh()
        ssh.run_command.return_value = ('', 'no space', 1)
        with self.assertRaises(RuntimeError):
            ssh.run_sudo_script('echo ok')
        ssh.upload_file.assert_not_called()

    def test_sudo_script_cleans_staging_on_upload_or_execution_exception(self):
        for method in ('upload_file', 'run_sudo_command'):
            with self.subTest(method=method):
                ssh = self.make_ssh()
                getattr(ssh, method).side_effect = TimeoutError('synthetic timeout')
                with self.assertRaises(TimeoutError):
                    ssh.run_sudo_script('first && second')
                self.assertEqual(ssh.run_command.call_args.args[0],
                                 'rm -rf -- /tmp/amnezia-private.ABC123')

    def test_sudo_script_preserves_failure_result_and_timeout(self):
        ssh = self.make_ssh()
        ssh.run_sudo_command.return_value = ('partial stdout', 'sudo denied', 1)
        self.assertEqual(ssh.run_sudo_script('first && second', timeout=17),
                         ('partial stdout', 'sudo denied', 1))
        ssh.run_sudo_command.assert_called_once_with(
            'bash /tmp/amnezia-private.ABC123/script.sh', timeout=17)

    def test_root_admin_script_is_not_filtered(self):
        ssh = self.make_ssh()
        ssh._is_root = True
        script = 'echo $(id); cat /etc/os-release | sort && true'
        ssh.run_sudo_script(script)
        ssh.run_command.assert_called_once_with(script, timeout=120)


if __name__ == '__main__':
    unittest.main()
