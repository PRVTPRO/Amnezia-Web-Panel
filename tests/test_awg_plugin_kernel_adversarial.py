"""Adversarial kernel-module update cases.

These tests deliberately exercise the awkward paths: reinstalling the version
that is already running, preflight with incomplete information, a backup that
produced nothing, and a rollback whose file copy fails.  Every assertion is
about the sequence of remote commands, because that sequence is what decides
whether a failed update leaves a working module behind.
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
                   modprobe=0, vermagic=None, sys_version=NEW,
                   headers='yes', tools='yes', git='yes', manager='apt-get',
                   cp_fail=False):
    """Scripted answers for every command the kernel update issues.

    ``modprobe`` is the exit code of the *first* ``modprobe amneziawg`` (the
    activation); the rollback retry always succeeds so the rollback phase can
    be observed.  ``manager`` is what the package-manager probe prints; an
    empty string models a host with no known package manager.
    """
    state = {'modprobe_calls': 0}
    default_vermagic = '%s SMP preempt mod_unload modversions' % KVER

    def handler(command):
        # preflight and version detection
        if 'awk' in command and '/proc/modules' in command:
            return ('0', '', 0)
        if 'for m in apt-get' in command:
            return (manager or '', '', 0)
        if 'apt-get install' in command:
            # One-click dependency installation succeeds by default.
            return ('', '', 0)
        if 'HEADERS=' in command and 'uname -r' in command:
            return (
                'KVER=%s\nHEADERS=%s\nDKMS=%s\nGCC=%s\nMAKE=%s\nGIT=%s'
                % (KVER, headers, tools, tools, tools, git),
                '', 0,
            )
        if command.strip() == 'uname -r':
            return (KVER, '', 0)

        # backup: must be answered before anything can overwrite the .ko
        if command.startswith('mkdir -p /var/lib/amnezia-plugin'):
            if not backup:
                return ('', '', 0)
            return ('ORIG=%s\nBACKUP=%s' % (ORIG, BACKUP), '', 0)

        # rollback's file copy - distinct from the backup script above
        if 'cp -a' in command and 'dirname' in command:
            return ('', '', 1 if cp_fail else 0)

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


class ReinstallRunningVersionTests(unittest.TestCase):
    def test_reinstall_of_running_version_does_not_deregister_it(self):
        """``target == installed`` must not remove the running DKMS version."""
        ssh = FakeSSH(kernel_handler(sys_version=OLD))
        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, OLD)

        self.assertEqual(result['state'], 'updated')
        self.assertEqual(result['previous'], OLD)
        self.assertEqual(result['installed'], OLD)

        add_index = _index(ssh.commands, 'dkms add')
        remove_old = 'dkms remove amneziawg/%s --all' % OLD
        before_add = [
            command for command in ssh.commands[:add_index]
            if remove_old in command
        ]
        self.assertEqual(
            before_add, [],
            'the running module was deregistered before dkms add: %r' % (before_add,),
        )


class PreflightTests(unittest.TestCase):
    def test_headers_present_and_no_package_manager_is_ready(self):
        """Minimal image: headers and tools present, no package manager."""
        ssh = FakeSSH(kernel_handler(headers='yes', tools='yes', manager=''))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)

        self.assertIs(check['package_manager'], None)
        self.assertTrue(check['ready'])
        self.assertEqual(check['blockers'], [])

    def test_headers_missing_with_package_manager_is_installable(self):
        """A known package manager turns missing headers into a one-click fix."""
        ssh = FakeSSH(kernel_handler(headers='no', manager='dnf'))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)

        self.assertTrue(check['ready'])
        self.assertEqual(check['blockers'], [])
        self.assertIn('headers', check['installable'])

    def test_headers_missing_and_no_package_manager_is_reported(self):
        ssh = FakeSSH(kernel_handler(headers='no', manager=''))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)

        self.assertFalse(check['ready'])
        self.assertTrue(
            any('no known package manager' in blocker for blocker in check['blockers']),
            'blocker does not mention the missing package manager: %r'
            % (check['blockers'],),
        )


class RollbackFailureTests(unittest.TestCase):
    def test_failed_restore_copy_is_reported_as_rollback_failed(self):
        """A failed ``cp -a <backup> <orig>`` must not be silently ignored.

        The activation fails, the rollback removes open the new DKMS version,
        but putting the saved .ko back fails.  The module is therefore not
        restored and the caller must be told with ``rollback_failed``.
        """
        ssh = FakeSSH(kernel_handler(modprobe=1, cp_fail=True, sys_version=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        copy_commands = [
            command for command in ssh.commands
            if 'cp -a' in command and 'dirname' in command
        ]
        self.assertTrue(copy_commands, 'the rollback never attempted the file copy')
        self.assertIn(BACKUP, copy_commands[0])
        self.assertIn(ORIG, copy_commands[0])

        self.assertEqual(
            ctx.exception.code, 'rollback_failed',
            'the restore copy failed but the update reported %r instead of '
            'rollback_failed' % (ctx.exception.code,),
        )


class BackupFailureTests(unittest.TestCase):
    def test_backup_without_output_falls_back_to_dkms_rebuild(self):
        """No ORIG/BACKUP must not crash; the rollback rebuilds from DKMS."""
        ssh = FakeSSH(kernel_handler(backup=False, modprobe=1, sys_version=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        # The update ran to completion (and failed at activation), rather than
        # crashing while parsing an empty backup.
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('git clone'))
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % OLD))
        self.assertTrue(ssh.find('dkms install amneziawg/%s --force' % OLD))
        build_index = _index(ssh.commands, 'dkms build amneziawg/%s' % OLD)
        install_index = _index(
            ssh.commands, 'dkms install amneziawg/%s --force' % OLD,
        )
        self.assertLess(build_index, install_index)


class CleanupAfterFailedRollbackTests(unittest.TestCase):
    def test_cleanup_is_not_skipped_after_rollback_failed(self):
        """rollback_failed must preserve the build tree and the saved module."""
        ssh = FakeSSH(kernel_handler(modprobe=1, sys_version='9.9.99999999'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'rollback_failed')
        cleanup_commands = [
            command for command in ssh.commands if CLEANUP in command
        ]
        self.assertEqual(
            cleanup_commands, [],
            'cleanup ran despite rollback_failed: %r' % (cleanup_commands,),
        )


class NeverRemoveOldVersionTests(unittest.TestCase):
    def assert_no_old_removal(self, commands):
        remove_old = 'dkms remove amneziawg/%s' % OLD
        found = [command for command in commands if remove_old in command]
        self.assertEqual(
            found, [],
            'the previously installed DKMS version was removed: %r' % (found,),
        )

    def test_success_keeps_the_old_version(self):
        ssh = FakeSSH(kernel_handler())
        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(result['state'], 'updated')
        self.assert_no_old_removal(ssh.commands)

    def test_build_failure_keeps_the_old_version(self):
        ssh = FakeSSH(kernel_handler(build=1))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assert_no_old_removal(ssh.commands)

    def test_cancel_after_build_keeps_the_old_version(self):
        ssh = FakeSSH(kernel_handler())
        should_cancel = lambda: any(
            'dkms build amneziawg' in command for command in ssh.commands
        )

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(
                KERNEL_MODULE, NEW, should_cancel=should_cancel,
            )

        self.assertEqual(ctx.exception.code, 'cancelled')
        self.assert_no_old_removal(ssh.commands)


if __name__ == '__main__':
    unittest.main()
