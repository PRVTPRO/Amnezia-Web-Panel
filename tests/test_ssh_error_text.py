"""An SSH failure must say what happened.

Paramiko raises bare `EOFError()` / `SSHException()` when the transport dies
mid-command; `str(exc)` on those is an empty string, which used to travel all
the way to the UI as "exit link apply failed: " with nothing after the colon.
"""

import unittest
from unittest import mock

from managers.awg_manager import AWGManager
from managers.ssh_manager import SSHManager


class DeadChannel:
    def settimeout(self, timeout):
        pass

    def recv_exit_status(self):
        raise EOFError()          # exactly what a dropped transport raises


class DeadStream:
    def __init__(self):
        self.channel = DeadChannel()

    def read(self):
        return b''


class ReasonTests(unittest.TestCase):
    def test_reason_falls_back_to_the_exception_type(self):
        self.assertEqual(SSHManager._reason(EOFError()), 'EOFError')
        self.assertEqual(SSHManager._reason(RuntimeError('  ')), 'RuntimeError')
        self.assertEqual(SSHManager._reason(RuntimeError('boom')), 'boom')

    def test_a_transport_dying_mid_command_is_reported(self):
        ssh = SSHManager.__new__(SSHManager)
        ssh.client = mock.Mock()
        ssh.client.exec_command.return_value = (None, DeadStream(), DeadStream())
        ssh.ensure_connected = lambda: None

        out, err, code = ssh._run_command_locked('whoami', 10, False)
        self.assertEqual((out, code), ('', -1))
        self.assertIn('SSH connection lost', err)
        self.assertIn('EOFError', err)


class ExitLinkMessageTests(unittest.TestCase):
    """The exit-link paths must not raise a message that ends at the colon."""

    class SSH:
        def __init__(self):
            self.uploads = {}

        def upload_file(self, content, path):
            self.uploads[path] = content

        def run_command(self, command, timeout=60):
            return '', '', 0

        def run_sudo_command(self, command, timeout=60):
            if 'for p in ' in command:
                return '/opt/amnezia/awg/awg0.conf\n', '', 0
            return '', '', -1        # dropped connection: no output at all

    def test_apply_and_write_report_the_exit_code(self):
        manager = AWGManager(self.SSH())
        with self.assertRaises(RuntimeError) as ctx:
            manager.exit_unlink('awg2')
        self.assertIn('SSH exit code -1', str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            manager.exit_link('awg2', {'transit_ip': '10.9.0.7', 'subnet_cidr': '24', 'exit_public_key': 'K',
                                       'psk': 'P', 'endpoint_host': '203.0.113.5', 'endpoint_port': '55520',
                                       'obfuscation': False, 'awg_params': {}})
        self.assertIn('SSH exit code -1', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
