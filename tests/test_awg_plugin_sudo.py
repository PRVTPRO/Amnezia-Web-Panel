"""Privilege handling of the AWG plugin updater on a non-root SSH session.

Cloud images usually connect the panel as ``debian``/``ubuntu`` instead of
``root``.  ``dkms`` lives in ``/usr/sbin`` (not in that user's ``PATH``) and
installing packages needs root anyway, so the updater elevates:

* single-line probes go through ``run_sudo_command``;
* multi-line commands and build steps go through ``run_sudo_script``;
* a root session keeps using plain ``run_command`` only.

The regression at the heart of this file is the OVH case: the dependency
recheck used to run unelevated, so it still saw ``DKMS=no`` right after a
successful ``apt-get install`` and the update failed with ``preflight_failed``.

Everything is scripted: no SSH, no network, and ``time.sleep`` is patched in the
module so a codepath that sleeps cannot slow the suite.
"""

import unittest
from unittest.mock import patch

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
)
from tests.awg_plugin_fixtures import KVER, NEW, OLD

BUILD_SRC = 'ABCD1234'
INSTALL_PREFIX = 'DEBIAN_FRONTEND=noninteractive apt-get install'


class PrivilegedFakeSSH:
    """SSH double that records *how* each command was executed.

    ``calls`` holds ``(method, text)`` pairs where ``method`` is one of
    ``'command'``, ``'sudo_command'`` or ``'sudo_script'``.  The handler gets
    both values so a test can answer differently for the vulnerable plain
    ``run_command`` path and for the elevated path.
    """

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

    def methods(self):
        return [method for method, _text in self.calls]

    def find(self, needle):
        """``(method, text)`` pairs whose command contains ``needle``."""
        return [(method, text) for method, text in self.calls if needle in text]

    def methods_for(self, needle):
        return [method for method, _text in self.find(needle)]

    def texts(self, method=None):
        return [
            text for call_method, text in self.calls
            if method is None or call_method == method
        ]


class _Log:
    def __init__(self):
        self.entries = []

    def __call__(self, stage, message):
        self.entries.append((stage, message))

    def messages(self):
        return [message for _stage, message in self.entries]


def cloud_handler(*, dkms='yes', probe=None, on_install=None, secure_boot=''):
    """Scripted cloud image: preflight, installs and the kernel update path.

    ``probe(method, state)`` can override the flags reported by the preflight
    probe per execution method.  ``on_install(packages, state)`` can script a
    failing/odd package manager; by default a successful install flips the
    corresponding flags, exactly like the real host would.
    """
    state = {
        'headers': 'yes',
        'dkms': dkms,
        'gcc': 'yes',
        'make': 'yes',
        'git': 'yes',
    }

    def handler(method, command):
        # preflight probes
        if 'awk' in command and '/proc/modules' in command:
            return ('0', '', 0)
        if 'for m in apt-get' in command:
            return ('apt-get', '', 0)
        if 'mokutil --sb-state' in command:
            return (secure_boot, '', 0)
        if 'HEADERS=' in command and 'uname -r' in command:
            flags = dict(state)
            if probe is not None:
                flags = probe(method, dict(state))
            return (
                'KVER=%s\nHEADERS=%s\nDKMS=%s\nGCC=%s\nMAKE=%s\nGIT=%s'
                % (KVER, flags['headers'], flags['dkms'], flags['gcc'],
                   flags['make'], flags['git']),
                '', 0,
            )

        # one-click dependency installation
        if command.startswith(INSTALL_PREFIX):
            packages = [
                token for token in command[len(INSTALL_PREFIX):].split()
                if not token.startswith('-')
            ]
            if on_install is not None:
                answer = on_install(packages, state)
                if answer is not None:
                    return answer
            for name in packages:
                if name in ('dkms', 'gcc', 'make', 'git'):
                    state[name] = 'yes'
                elif name.startswith('linux-headers'):
                    state['headers'] = 'yes'
            return ('', '', 0)

        # kernel update path
        if command.strip() == 'uname -r':
            return (KVER, '', 0)
        if command.startswith('mkdir -p /var/lib/amnezia-plugin'):
            return (
                'ORIG=/lib/modules/%s/updates/dkms/amneziawg.ko\n'
                'BACKUP=/var/lib/amnezia-plugin/amneziawg-%s.ko' % (KVER, OLD),
                '', 0,
            )
        if 'modinfo -F version amneziawg' in command:
            return (OLD, '', 0)
        if 'modinfo -F srcversion' in command:
            return (BUILD_SRC, '', 0)
        if 'modinfo -F vermagic' in command:
            return ('%s SMP preempt mod_unload modversions' % KVER, '', 0)
        if command.startswith('cat /sys/module/amneziawg/srcversion'):
            return (BUILD_SRC, '', 0)
        if command.startswith('cat /sys/module/amneziawg/version'):
            return (NEW, '', 0)
        if 'git clone' in command:
            return ('', '', 0)
        if 'dkms add' in command or 'dkms build' in command:
            return ('', '', 0)
        if 'dkms install' in command or 'dkms remove' in command:
            return ('', '', 0)
        if 'modprobe' in command or 'depmod' in command:
            return ('', '', 0)

        # read-only probes / fallbacks
        if command.startswith('docker ps'):
            return ('', '', 0)
        if command.startswith('docker exec'):
            return ('interface: awg0', '', 0)
        return ('', '', 0)

    return handler


class RootSessionUsesNoSudoTests(unittest.TestCase):
    """A root session must not pay for (or depend on) sudo at all."""

    def test_preflight_and_versions_only_use_run_command(self):
        ssh = PrivilegedFakeSSH(cloud_handler(), root=True)
        updater = AwgPluginUpdater(ssh)

        check = updater.preflight(KERNEL_MODULE)
        versions = updater.installed_versions()

        self.assertEqual(check['package_manager'], 'apt-get')
        self.assertEqual(versions[KERNEL_MODULE], OLD)
        self.assertTrue(ssh.calls)
        self.assertEqual(set(ssh.methods()), {'command'}, ssh.calls)
        self.assertEqual(ssh.methods_for('echo KVER='), ['command'])
        self.assertEqual(ssh.methods_for('for m in apt-get'), ['command'])
        self.assertEqual(ssh.methods_for('mokutil'), ['command'])
        self.assertEqual(ssh.methods_for('/proc/modules'), ['command'])
        self.assertEqual(ssh.methods_for('modinfo -F version'), ['command'])


class NonRootProbesAreElevatedTests(unittest.TestCase):
    """Single-line probes on a normal-user session must ask for sudo."""

    def test_preflight_probes_go_through_run_sudo_command(self):
        ssh = PrivilegedFakeSSH(cloud_handler(), root=False)
        updater = AwgPluginUpdater(ssh)

        updater.preflight(KERNEL_MODULE)

        for needle in (
            'echo KVER=',
            'for m in apt-get',
            'mokutil',
            '/proc/modules',
        ):
            self.assertEqual(ssh.methods_for(needle), ['sudo_command'], needle)
        self.assertNotIn('command', ssh.methods())

    def test_installed_versions_probe_goes_through_run_sudo_command(self):
        ssh = PrivilegedFakeSSH(cloud_handler(), root=False)
        updater = AwgPluginUpdater(ssh)

        versions = updater.installed_versions()

        self.assertEqual(versions[KERNEL_MODULE], OLD)
        self.assertEqual(ssh.methods_for('modinfo -F version'), ['sudo_command'])
        self.assertNotIn('command', ssh.methods())


class MultiLineUsesScriptTests(unittest.TestCase):
    def test_exec_with_newline_uses_run_sudo_script(self):
        ssh = PrivilegedFakeSSH(
            lambda method, text: ('ok', '', 0), root=False,
        )
        updater = AwgPluginUpdater(ssh)

        out, err, code = updater._exec('line1\nline2')

        self.assertEqual((out, err, code), ('ok', '', 0))
        self.assertEqual(ssh.calls, [('sudo_script', 'line1\nline2')])
        self.assertNotIn('command', ssh.methods())
        self.assertNotIn('sudo_command', ssh.methods())


class InstallUsesSudoScriptTests(unittest.TestCase):
    def test_apt_get_install_goes_through_run_sudo_script(self):
        ssh = PrivilegedFakeSSH(cloud_handler(dkms='no'), root=False)
        log = _Log()

        with patch('managers.awg_plugin_updater.time.sleep'):
            AwgPluginUpdater(ssh).ensure_dependencies(KERNEL_MODULE, log)

        installs = ssh.find('apt-get install')
        self.assertEqual(len(installs), 1, ssh.calls)
        method, command = installs[0]
        self.assertEqual(method, 'sudo_script')
        self.assertIn('install -y -qq dkms', command)
        self.assertIn('dependencies are ready', log.messages())


class DkmsAfterSudoInstallRegressionTests(unittest.TestCase):
    """The OVH case: dkms is installed but only visible to the elevated probe."""

    @staticmethod
    def _paths_disagree(method, state):
        flags = dict(state)
        if method == 'command':
            # /usr/sbin is not in a normal user's PATH: dkms stays invisible
            # no matter what was installed, which is exactly the old bug.
            flags['dkms'] = 'no'
        return flags

    def test_update_continues_to_git_clone_after_sudo_install_of_dkms(self):
        ssh = PrivilegedFakeSSH(
            cloud_handler(dkms='no', probe=self._paths_disagree), root=False,
        )
        log = _Log()

        with patch('managers.awg_plugin_updater.time.sleep'):
            result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(result['state'], 'updated')
        self.assertIn('dependencies are ready', log.messages())
        # The elevated recheck saw the freshly installed dkms: no early abort.
        self.assertEqual(ssh.methods_for('apt-get install'), ['sudo_script'])
        clones = ssh.find('git clone')
        self.assertEqual(len(clones), 1, ssh.calls)
        self.assertEqual(clones[0][0], 'sudo_script')
        self.assertIn('dkms build amneziawg/%s' % NEW, ssh.texts())
        self.assertFalse(any(
            'still missing' in message for message in log.messages()
        ))


class HonestFailureTests(unittest.TestCase):
    def test_recheck_that_still_misses_dkms_fails_and_does_not_build(self):
        # Even the elevated probe keeps reporting the package as absent: the
        # raise is honest and nothing dangerous/costly must have run.
        ssh = PrivilegedFakeSSH(
            cloud_handler(
                dkms='no',
                probe=lambda method, state: dict(state, dkms='no'),
                on_install=lambda packages, state: ('', '', 0),
            ),
            root=False,
        )
        log = _Log()

        with patch('managers.awg_plugin_updater.time.sleep'):
            with self.assertRaises(PluginUpdateError) as ctx:
                AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        message = ctx.exception.message
        self.assertIn('missing', message)
        self.assertIn('dkms', message)
        self.assertIn('still missing after installation: dkms', message)
        self.assertEqual(ssh.find('git clone'), [])
        self.assertEqual(ssh.find('dkms add'), [])
        self.assertEqual(ssh.find('dkms build'), [])
        self.assertEqual(ssh.find('dkms install'), [])


if __name__ == '__main__':
    unittest.main()
