"""Docker detection must survive the sudo prefix added by run_sudo_command.

run_sudo_command runs `sudo -S -p ... <command>` for a non-root user. sudo
executes the first token with execvp, and `command` is a shell builtin, so
`command -v docker` fails with `sudo: command: command not found` (rc=1).
The fix wraps the builtin in `sh -c`.
"""
import unittest

from managers.awg_manager import AWGManager

OLD_COMMAND = "command -v docker >/dev/null 2>&1 && echo yes"
SUDO_ERROR = "sudo: command: command not found"


class FakeSsh:
    """Fake SSH that reproduces the sudo failure of the old command shape."""

    def __init__(self, docker_present=True):
        self.docker_present = docker_present
        self.calls = []

    def run_sudo_command(self, command, *args, **kwargs):
        self.calls.append(command)
        text = command or ''
        if 'command -v docker' in text:
            if text.lstrip().startswith('command '):
                # Old shape: sudo tries to exec the `command` builtin.
                return 'no', SUDO_ERROR, 1
            # New shape: sh runs the builtin.
            return ('yes' if self.docker_present else 'no'), '', 0
        return '', '', 0


def make_manager(ssh):
    return AWGManager(ssh)


class DockerDetectTests(unittest.TestCase):
    def test_old_command_shape_reports_not_installed(self):
        """Pins the root cause: the raw builtin cannot run under sudo."""
        ssh = FakeSsh()
        out, err, code = ssh.run_sudo_command(OLD_COMMAND)
        self.assertEqual(code, 1)
        self.assertEqual(err, SUDO_ERROR)
        self.assertEqual(out, 'no')

    def test_sh_wrapped_command_reports_installed(self):
        ssh = FakeSsh(docker_present=True)
        manager = make_manager(ssh)
        info = manager._docker_ipv6_info()
        self.assertTrue(info['installed'])
        detect = [c for c in ssh.calls if 'command -v docker' in c]
        self.assertTrue(detect)
        self.assertTrue(detect[0].startswith(
            "sh -c 'command -v docker'"), detect[0])

    def test_missing_docker_still_reports_not_installed(self):
        ssh = FakeSsh(docker_present=False)
        manager = make_manager(ssh)
        info = manager._docker_ipv6_info()
        self.assertFalse(info['installed'])

    def test_builtin_is_never_the_first_token(self):
        ssh = FakeSsh(docker_present=True)
        manager = make_manager(ssh)
        manager._docker_ipv6_info()
        for command in ssh.calls:
            text = (command or '').strip()
            if not text:
                continue
            first = text.split()[0]
            self.assertNotEqual(first, 'command',
                                'the `command` builtin was sent as the first '
                                'token: %r' % command)
            if 'command -v docker' in text:
                self.assertTrue(text.startswith("sh -c 'command -v docker'"),
                                command)
