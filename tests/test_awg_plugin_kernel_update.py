"""Kernel-module update safety: backup, rollback, cancellation and cleanup.

These tests script the SSH fake command by command instead of relying on real
shell behaviour: every assertion is about the *sequence* of remote commands,
which is exactly what decides whether a failed update leaves a working module.
"""

import unittest

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
)
from tests.awg_plugin_fixtures import FakeSSH, OLD, NEW, KVER

ORIG = '/lib/modules/%s/updates/dkms/amneziawg.ko' % KVER
BACKUP = '/var/lib/amnezia-plugin/amneziawg-%s.ko' % OLD
CLEANUP = 'rm -rf /tmp/awg-plugin-update /tmp/awg-plugin-backup-*'


def _index(commands, needle, start=0):
    """First index of a command containing ``needle`` at or after ``start``."""
    for index in range(start, len(commands)):
        if needle in commands[index]:
            return index
    raise AssertionError('no command containing %r after index %d' % (needle, start))


def kernel_handler(*, backup=True, build=0, install=0, dry_run=0, unload=0,
                   modprobe=0, vermagic=None, sys_version=NEW):
    """Scripted answers for every command the kernel update issues.

    ``modprobe`` is the exit code of the *first* ``modprobe amneziawg``
    (the activation); the rollback's retry always succeeds so that the
    rollback phase itself can be observed.
    """
    state = {'modprobe_calls': 0}
    default_vermagic = '%s SMP preempt mod_unload modversions' % KVER

    def handler(command):
        # preflight and version detection
        if 'awk' in command and '/proc/modules' in command:
            return ('0', '', 0)
        if 'for m in apt-get' in command:
            return ('apt-get', '', 0)
        if 'apt-get install' in command:
            # One-click dependency installation: success unless a test says no.
            return ('', '', 0)
        if 'HEADERS=' in command and 'uname -r' in command:
            return (
                'KVER=%s\nHEADERS=yes\nDKMS=yes\nGCC=yes\nMAKE=yes\nGIT=yes' % KVER,
                '', 0,
            )
        if command.strip() == 'uname -r':
            return (KVER, '', 0)

        # backup: must be answered before anything can overwrite the .ko
        if command.startswith('mkdir -p /var/lib/amnezia-plugin'):
            if not backup:
                return ('', '', 0)
            return ('ORIG=%s\nBACKUP=%s' % (ORIG, BACKUP), '', 0)

        if command.startswith('cat /sys/module/amneziawg/version'):
            return (sys_version, '', 0)
        if 'modinfo -F version amneziawg' in command:
            return (OLD, '', 0)
        if 'modinfo -F vermagic' in command:
            return (default_vermagic if vermagic is None else vermagic, '', 0)

        # update steps
        if 'git clone' in command:
            return ('', '', 0)
        if 'dkms add' in command:
            return ('', '', 0)
        if 'dkms build' in command:
            return ('', '', build)
        if 'dkms install' in command:
            return ('', '', install)
        if 'modprobe -n amneziawg' in command:
            return ('', '', dry_run)
        if 'modprobe -r amneziawg' in command:
            return ('', '', unload)
        if command.strip() == 'modprobe amneziawg':
            state['modprobe_calls'] += 1
            # Only the activation (first call) can fail; the rollback retry
            # must succeed for the rollback path to be fully observable.
            return ('', '', modprobe if state['modprobe_calls'] == 1 else 0)
        if 'depmod' in command:
            return ('', '', 0)
        if 'dkms remove' in command:
            return ('', '', 0)

        # read-only probes
        if command.startswith('docker ps'):
            return ('', '', 0)
        if command.startswith('docker exec'):
            return ('interface: awg0', '', 0)
        return ('', '', 0)

    return handler


class KernelUpdateOrderingTests(unittest.TestCase):
    def test_backup_runs_before_the_build(self):
        """The loaded .ko must be copied before git clone / dkms install."""
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        backup_index = _index(ssh.commands, 'modinfo -n amneziawg')
        clone_index = _index(ssh.commands, 'git clone')
        self.assertLess(backup_index, clone_index)

        backup_command = ssh.commands[backup_index]
        self.assertIn('/var/lib/amnezia-plugin', backup_command)
        self.assertIn('amneziawg-%s.ko' % OLD, backup_command)

    def test_retry_removes_the_target_before_dkms_add(self):
        """A half-finished previous attempt must not make dkms add fail."""
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        remove_index = _index(ssh.commands, 'dkms remove amneziawg/%s --all' % NEW)
        add_index = _index(ssh.commands, 'dkms add')
        self.assertLess(remove_index, add_index)
        # It really is the retry guard: it happens before the sources exist.
        self.assertLess(remove_index, _index(ssh.commands, 'git clone'))


class KernelRollbackTests(unittest.TestCase):
    def test_rollback_uses_the_saved_file(self):
        """No rebuild when a byte copy of the old module was saved."""
        ssh = FakeSSH(kernel_handler(modprobe=1, sys_version=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'update_failed')
        commands = ssh.commands

        activate = _index(commands, 'modprobe amneziawg')
        unload = _index(commands, 'modprobe -r amneziawg')
        self.assertLess(unload, activate)

        rollback_remove = _index(
            commands, 'dkms remove amneziawg/%s --all' % NEW, activate,
        )
        copy_back = _index(commands, 'cp -a', activate)
        depmod = _index(commands, 'depmod -a', activate)
        reload = _index(commands, 'modprobe amneziawg', activate + 1)
        verify = _index(commands, 'cat /sys/module/amneziawg/version', activate)

        self.assertLess(rollback_remove, copy_back)
        self.assertLess(copy_back, depmod)
        self.assertLess(depmod, reload)
        self.assertLess(reload, verify)

        copy_command = commands[copy_back]
        self.assertIn(BACKUP, copy_command)
        self.assertIn(ORIG, copy_command)
        self.assertTrue(copy_command.rstrip().endswith(ORIG))

        # The file copy replaced the rebuild: nothing may re-run dkms build
        # for the old version.
        self.assertFalse(ssh.find('dkms build amneziawg/%s' % OLD))

    def test_rollback_falls_back_to_dkms_without_a_saved_file(self):
        ssh = FakeSSH(kernel_handler(backup=False, modprobe=1, sys_version=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % OLD))
        self.assertTrue(ssh.find('dkms install amneziawg/%s --force' % OLD))
        self.assertTrue(ssh.find('depmod -a'))

        build = _index(ssh.commands, 'dkms build amneziawg/%s' % OLD)
        install = _index(ssh.commands, 'dkms install amneziawg/%s --force' % OLD)
        self.assertLess(build, install)
        # No file copy was possible, so none is attempted (the backup script
        # itself mentions cp -a, but never the rollback path pair).
        self.assertFalse([
            command for command in ssh.commands
            if 'cp -a' in command and ORIG in command
        ])

    def test_failed_rollback_keeps_artefacts(self):
        ssh = FakeSSH(kernel_handler(modprobe=1, sys_version='9.9.99999999'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'rollback_failed')
        # Diagnostics: the build tree and the saved module must survive.
        self.assertFalse([c for c in ssh.commands if CLEANUP in c])


class KernelAbortTests(unittest.TestCase):
    def test_vermagic_mismatch_aborts_before_unload(self):
        ssh = FakeSSH(kernel_handler(vermagic='6.1.0-generic SMP preempt'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'update_failed')
        message = ctx.exception.message
        self.assertIn('6.1.0-generic', message)
        self.assertIn(KVER, message)
        self.assertTrue(ssh.find('dkms remove amneziawg/%s --all' % NEW))
        # The running (old) module was never unloaded.
        self.assertFalse(ssh.find('modprobe -r amneziawg'))


class KernelCancelTests(unittest.TestCase):
    def test_cancel_after_build_does_not_switch(self):
        ssh = FakeSSH(kernel_handler())
        seen = lambda: any('dkms build amneziawg' in c for c in ssh.commands)

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, should_cancel=seen)

        self.assertEqual(ctx.exception.code, 'cancelled')
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % NEW))
        self.assertTrue(ssh.find('dkms remove amneziawg/%s --all' % NEW))
        self.assertFalse(ssh.find('modprobe -r amneziawg'))
        self.assertFalse(ssh.find('dkms install amneziawg/%s' % NEW))

    def test_cancel_before_switch_does_not_unload(self):
        ssh = FakeSSH(kernel_handler())
        seen = lambda: any('dkms install amneziawg' in c for c in ssh.commands)

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, should_cancel=seen)

        self.assertEqual(ctx.exception.code, 'cancelled')
        self.assertTrue(ssh.find('dkms install amneziawg/%s --force' % NEW))
        # Everything was prepared, but the module switch never started.
        self.assertTrue(ssh.find('modprobe -n amneziawg'))
        self.assertFalse(ssh.find('modprobe -r amneziawg'))
        self.assertFalse(ssh.find('modprobe amneziawg'))


class KernelHappyPathTests(unittest.TestCase):
    def test_success_verifies_sys_and_keeps_the_old_dkms_version(self):
        ssh = FakeSSH(kernel_handler())
        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(result['state'], 'updated')
        self.assertEqual(result['previous'], OLD)
        self.assertEqual(result['installed'], NEW)
        self.assertTrue(ssh.find('cat /sys/module/amneziawg/version'))
        # The working DKMS version is never removed.
        self.assertFalse(ssh.find('dkms remove amneziawg/%s' % OLD))

    def test_success_ends_with_cleanup(self):
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertTrue(ssh.commands[-1].startswith(CLEANUP))
        self.assertEqual(len(ssh.find(CLEANUP)), 1)


if __name__ == '__main__':
    unittest.main()
