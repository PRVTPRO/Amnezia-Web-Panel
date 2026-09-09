"""An SSH failure must say what happened.

Paramiko raises bare `EOFError()` / `SSHException()` when the transport dies
mid-command, and `str(exc)` on those is an empty string. That empty string is
what the managers interpolate into their failure messages - there are ~30
`{err}` sites across managers/ - so a dropped connection surfaced as
"Failed to configure container: " with nothing after the colon.
"""

import unittest
from unittest import mock

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


if __name__ == '__main__':
    unittest.main()
