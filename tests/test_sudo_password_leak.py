"""The sudo password must never reach the log or the remote command line.

Previously run_sudo_command/run_sudo_script wrapped every command as
`echo '<password>' | sudo -S -p '' <cmd>`, and run_command logged the first
100 chars of that string on every call -- so the panel journal held the sudo
password in clear text, and `ps` on the managed host showed it for the life
of the command. The password now travels through the channel's stdin only.
"""

import logging
import threading
import unittest
from unittest import mock

from managers.ssh_manager import SSHManager

PASSWORD = "S3cr3t Pa'ss w0rd"


class FakeChannel:
    def __init__(self):
        self.write_closed = False

    def settimeout(self, timeout):
        pass

    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        self.write_closed = True


class FakeStream:
    def __init__(self, channel=None):
        self.channel = channel or FakeChannel()

    def read(self):
        return b''


class FakeStdin(FakeStream):
    def __init__(self):
        super().__init__()
        self.written = []

    def write(self, data):
        self.written.append(data)

    def flush(self):
        pass


def make_ssh():
    ssh = SSHManager.__new__(SSHManager)
    ssh._exec_lock = threading.RLock()
    ssh._is_root = False
    ssh.password = PASSWORD
    ssh.ensure_connected = lambda: None
    ssh.upload_file = lambda content, path: None
    ssh.client = mock.Mock()
    return ssh


class SudoPasswordLeakTests(unittest.TestCase):
    def run_and_capture(self, fn):
        ssh = make_ssh()
        stdin = FakeStdin()
        channel = FakeChannel()
        ssh.client.exec_command.return_value = (
            stdin, FakeStream(channel), FakeStream(channel))

        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Handler()
        logger = logging.getLogger('managers.ssh_manager')
        logger.addHandler(handler)
        try:
            fn(ssh)
        finally:
            logger.removeHandler(handler)
        return ssh, stdin, records

    def assert_password_hidden(self, ssh, stdin, records):
        command = ssh.client.exec_command.call_args[0][0]
        self.assertNotIn(PASSWORD, command)
        self.assertTrue(all(PASSWORD not in r for r in records))
        self.assertEqual(stdin.written, [PASSWORD + '\n'])
        self.assertTrue(stdin.channel.write_closed)

    def test_sudo_command(self):
        ssh, stdin, records = self.run_and_capture(
            lambda s: s.run_sudo_command('docker ps'))
        self.assert_password_hidden(ssh, stdin, records)
        command = ssh.client.exec_command.call_args[0][0]
        self.assertEqual(command, "sudo -S -p '' docker ps")

    def test_sudo_script(self):
        ssh, stdin, records = self.run_and_capture(
            lambda s: s.run_sudo_script('echo hi'))
        self.assert_password_hidden(ssh, stdin, records)
        command = ssh.client.exec_command.call_args[0][0]
        self.assertTrue(command.startswith("sudo -S -p '' bash /tmp/"))

    def test_root_login_needs_no_stdin(self):
        ssh = make_ssh()
        ssh._is_root = True
        stdin = FakeStdin()
        channel = FakeChannel()
        ssh.client = mock.Mock()
        ssh.client.exec_command.return_value = (
            stdin, FakeStream(channel), FakeStream(channel))
        ssh.run_sudo_command('docker ps')
        command = ssh.client.exec_command.call_args[0][0]
        self.assertEqual(command, 'docker ps')
        self.assertEqual(stdin.written, [])


if __name__ == '__main__':
    unittest.main()
