"""Regression tests for wrapping shell compounds in ``bash -c`` on sudo paths.

On a non-root SSH session :meth:`AwgPluginUpdater._exec` elevates single-line
commands through ``run_sudo_command``.  ``sudo`` does not run a shell, so a
compound command (``for ...; do ...; done``, ``a && b``, a pipeline) used to be
mistaken for a program name: the package-manager probe returned nothing and the
panel reported "dkms is not installed and there is no known package manager".

The fix hands the command to ``bash -c`` with a ``shlex``-quoted argument.  The
tests below assert on the *recorded* command text, never on module internals:

* compounds and simple commands are both wrapped (uniform behaviour);
* quoting preserves the original program (including single quotes);
* the package-manager probe succeeds on a non-root session;
* the OVH-shaped dependency installation (dkms missing initially) still works;
* a root session keeps its plain, unwrapped ``run_command`` path.

Everything is scripted: no real SSH, no network, no sleeps.
"""

import shlex
import unittest
from unittest.mock import patch

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
)

KVER = '6.12.113+deb13-amd64'


class RecordingFakeSSH:
    """SSH double that records ``(method, text)`` for every command."""

    def __init__(self, handler=None, *, root=False):
        self._is_root = root
        self.calls = []
        self.handler = handler or (lambda method, text: ('', '', 0))

    def _record(self, method, text):
        self.calls.append((method, text))
        return self.handler(method, text)

    def run_command(self, command, timeout=60, _retried=False, stdin_input=None):
        return self._record('command', command)

    def run_sudo_command(self, command, timeout=60):
        return self._record('sudo_command', command)

    def run_sudo_script(self, script, timeout=120):
        return self._record('sudo_script', script)

    # -- inspection helpers ---------------------------------------------------

    def find(self, needle):
        """``(method, text)`` pairs whose command contains ``needle``."""
        return [(method, text) for method, text in self.calls if needle in text]

    def methods_for(self, needle):
        return [method for method, _text in self.find(needle)]


class _Log:
    def __init__(self):
        self.entries = []

    def __call__(self, stage, message):
        self.entries.append((stage, message))

    def messages(self):
        return [message for _stage, message in self.entries]


def _wrapped(command):
    """The exact text the fixed ``_exec`` must hand to ``run_sudo_command``."""
    return 'bash -c ' + shlex.quote(command)


class ShellCompoundIsWrappedTests(unittest.TestCase):
    def test_for_loop_goes_through_one_wrapped_sudo_command(self):
        ssh = RecordingFakeSSH()
        updater = AwgPluginUpdater(ssh)
        command = 'for m in apt-get dnf; do command -v $m && echo $m; done'

        updater._exec(command)

        self.assertEqual(len(ssh.calls), 1, ssh.calls)
        method, text = ssh.calls[0]
        self.assertEqual(method, 'sudo_command')
        self.assertTrue(text.startswith('bash -c '), text)
        self.assertIn(command, text)
        # The whole compound is one argument for bash, not a sudo program name.
        self.assertEqual(shlex.split(text), ['bash', '-c', command])

    def test_simple_command_is_wrapped_too(self):
        ssh = RecordingFakeSSH()
        updater = AwgPluginUpdater(ssh)

        updater._exec('uname -r')

        self.assertEqual(ssh.calls, [('sudo_command', _wrapped('uname -r'))])
        text = ssh.calls[0][1]
        self.assertTrue(text.startswith('bash -c '), text)

    def test_single_quoted_awk_program_survives_quoting(self):
        ssh = RecordingFakeSSH()
        updater = AwgPluginUpdater(ssh)
        command = "awk '$1==\"amneziawg\"{print $3}' /proc/modules"
        program = "'$1==\"amneziawg\"{print $3}'"

        updater._exec(command)

        self.assertEqual(len(ssh.calls), 1, ssh.calls)
        method, text = ssh.calls[0]
        self.assertEqual(method, 'sudo_command')
        self.assertTrue(text.startswith('bash -c '), text)
        # The original quoted awk program is intact, character for character.
        self.assertIn(program, text)
        self.assertIn('/proc/modules', text)
        # And bash receives exactly the original command as its single script.
        self.assertEqual(shlex.split(text), ['bash', '-c', command])


class PackageManagerProbeTests(unittest.TestCase):
    @staticmethod
    def _handler(method, text):
        # Only the wrapped "for m in ..." probe may answer apt-get; this is
        # precisely the command sudo used to see as a program name.
        if 'for m in' in text:
            return ('apt-get', '', 0)
        if 'HEADERS=' in text and 'uname -r' in text:
            return (
                'KVER=%s\nHEADERS=yes\nDKMS=yes\nGCC=yes\nMAKE=yes\nGIT=yes' % KVER,
                '', 0,
            )
        if 'mokutil --sb-state' in text:
            return ('', '', 0)
        if '/proc/modules' in text:
            return ('0', '', 0)
        return ('', '', 0)

    def test_preflight_finds_apt_get_on_a_non_root_session(self):
        ssh = RecordingFakeSSH(self._handler)
        updater = AwgPluginUpdater(ssh)

        check = updater.preflight(KERNEL_MODULE)

        self.assertEqual(check['package_manager'], 'apt-get')
        self.assertNotIn(
            'no known package manager',
            ' '.join(check['blockers']),
            check['blockers'],
        )
        self.assertTrue(check['ready'], check)

        probes = ssh.find('for m in')
        self.assertEqual(len(probes), 1, ssh.calls)
        method, text = probes[0]
        self.assertEqual(method, 'sudo_command')
        self.assertTrue(text.startswith('bash -c '), text)


class DependenciesOnNonRootSessionTests(unittest.TestCase):
    def test_dkms_install_uses_sudo_script_and_recheck_sees_it(self):
        state = {'dkms': 'no'}
        dkms_answers = []

        def handler(method, text):
            if 'for m in' in text:
                return ('apt-get', '', 0)
            if 'HEADERS=' in text and 'uname -r' in text:
                dkms_answers.append(state['dkms'])
                return (
                    'KVER=%s\nHEADERS=yes\nDKMS=%s\nGCC=yes\nMAKE=yes\nGIT=yes'
                    % (KVER, state['dkms']),
                    '', 0,
                )
            if 'apt-get install' in text:
                # The real install needs root; the updater must use the script
                # path, and only that path is allowed to flip the host state.
                if method == 'sudo_script' and 'dkms' in text:
                    state['dkms'] = 'yes'
                return ('', '', 0)
            if 'mokutil --sb-state' in text:
                return ('', '', 0)
            if '/proc/modules' in text:
                return ('0', '', 0)
            return ('', '', 0)

        ssh = RecordingFakeSSH(handler)
        log = _Log()

        with patch('managers.awg_plugin_updater.time.sleep'):
            AwgPluginUpdater(ssh).ensure_dependencies(KERNEL_MODULE, log)

        installs = ssh.find('apt-get install')
        self.assertEqual(len(installs), 1, ssh.calls)
        method, command = installs[0]
        self.assertEqual(method, 'sudo_script')
        self.assertIn('dkms', command)
        self.assertFalse(command.startswith('bash -c '), command)

        self.assertEqual(dkms_answers, ['no', 'yes'], ssh.calls)
        self.assertIn('dependencies are ready', log.messages())
        self.assertFalse(any(
            'still missing' in message for message in log.messages()
        ))


class RootSessionIsUnchangedTests(unittest.TestCase):
    def test_root_exec_calls_run_command_with_raw_text(self):
        ssh = RecordingFakeSSH(root=True)
        updater = AwgPluginUpdater(ssh)
        command = 'for m in apt-get dnf; do command -v $m && echo $m; done'

        updater._exec(command)

        self.assertEqual(ssh.calls, [('command', command)])
        self.assertNotIn('bash -c', ssh.calls[0][1])
        self.assertEqual(ssh.methods_for('for m in'), ['command'])


if __name__ == '__main__':
    unittest.main()
