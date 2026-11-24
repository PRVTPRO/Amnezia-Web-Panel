"""upload_file_sudo must be able to install a file that only root can read,
without it ever being readable by others along the way."""
import unittest

from managers.ssh_manager import SSHManager

STAGING = '/tmp/amnezia-private.staging'


class UploadModeTests(unittest.TestCase):
    def _ssh(self, chmod_code=0):
        ssh = SSHManager.__new__(SSHManager)
        ssh.ensure_connected = lambda: None
        ssh._make_private_temp_dir = lambda: STAGING
        self.log = []
        ssh.upload_file = lambda content, path: self.log.append(('sftp', path)) or True

        def run_command(command, **kwargs):
            self.log.append(('run', command))
            return ('', '', chmod_code if command.startswith('chmod ') else 0)

        def run_sudo_command(command, **kwargs):
            self.log.append(('sudo', command))
            return ('', '', 0)

        ssh.run_command, ssh.run_sudo_command = run_command, run_sudo_command
        return ssh

    def _commands(self):
        return [command for kind, command in self.log]

    def test_a_restrictive_mode_is_applied_while_the_file_is_still_private(self):
        self._ssh().upload_file_sudo('{}', '/opt/amnezia/xray/server.json', mode=0o600)

        commands = self._commands()
        chmod = next(i for i, c in enumerate(commands) if c.startswith('chmod 600 '))
        move = next(i for i, c in enumerate(commands) if c.startswith('mv -- '))
        self.assertLess(chmod, move)
        self.assertTrue(commands[chmod].endswith(STAGING + '/content'))
        self.assertFalse(any('chmod 644' in c for c in commands))
        self.assertIn('rm -rf -- ' + STAGING, commands)

    def test_the_default_stays_world_readable(self):
        self._ssh().upload_file_sudo('{}', '/opt/amnezia/xray/xray_public.key')

        commands = self._commands()
        self.assertIn('chmod 644 /opt/amnezia/xray/xray_public.key', commands)
        self.assertFalse(any(c.startswith('chmod 600') for c in commands))

    def test_a_mode_that_cannot_be_set_aborts_before_the_file_is_moved(self):
        with self.assertRaises(RuntimeError):
            self._ssh(chmod_code=1).upload_file_sudo('{}', '/opt/amnezia/xray/server.json',
                                                      mode=0o600)
        commands = self._commands()
        self.assertFalse(any(c.startswith('mv -- ') for c in commands))
        self.assertIn('rm -rf -- ' + STAGING, commands)


if __name__ == '__main__':
    unittest.main()
