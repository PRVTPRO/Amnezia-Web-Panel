"""Kernel-module identity: version.h patching, srcversion and applied.json.

Upstream tag ``v3.1.20260906`` still ships ``src/version.h`` containing
``#define WIREGUARD_VERSION "3.1.20260812"``.  A module built from that tag
therefore reports the *old* version string.  The updater must patch the header,
verify the identity through ``srcversion`` (a hash of the built code) and only
then remember the tag it built in ``/var/lib/amnezia-plugin/applied.json``.

Every test scripts the SSH fake command by command: no network, no real SSH and
no sleeps.
"""

import json
import unittest

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
)
from tests.awg_plugin_fixtures import FakeSSH, OLD, NEW, KVER

ORIG = '/lib/modules/%s/updates/dkms/amneziawg.ko' % KVER
BACKUP = '/var/lib/amnezia-plugin/amneziawg-%s.ko' % OLD
APPLIED = '/var/lib/amnezia-plugin/applied.json'
BUILD_SRC = 'ABCD1234'
OTHER_SRC = 'OTHER999'


def _index(commands, needle, start=0):
    """First index of a command containing ``needle`` at or after ``start``."""
    for index in range(start, len(commands)):
        if needle in commands[index]:
            return index
    raise AssertionError('no command containing %r after index %d' % (needle, start))


def kernel_handler(*, applied='', sys_version=NEW, sys_srcversion=BUILD_SRC,
                   build_srcversion=BUILD_SRC, backup=True):
    """Scripted answers for every command a kernel update issues.

    ``applied`` is the raw content of applied.json (empty means "no record"),
    ``sys_version``/``sys_srcversion`` answer the ``/sys/module`` probes and
    ``build_srcversion`` answers ``modinfo -F srcversion`` on the new file.
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
            # One-click dependency installation always succeeds by default.
            return ('', '', 0)
        if 'HEADERS=' in command and 'uname -r' in command:
            return (
                'KVER=%s\nHEADERS=yes\nDKMS=yes\nGCC=yes\nMAKE=yes\nGIT=yes' % KVER,
                '', 0,
            )
        if command.strip() == 'uname -r':
            return (KVER, '', 0)

        # applied.json: reads return the scripted record, writes succeed.
        # Checked before the backup prefix because both share ``mkdir -p``.
        if APPLIED in command:
            if command.lstrip().startswith('cat '):
                return (applied, '', 0)
            return ('', '', 0)

        # backup: must be answered before anything can overwrite the .ko
        if command.startswith('mkdir -p /var/lib/amnezia-plugin'):
            if not backup:
                return ('', '', 0)
            return ('ORIG=%s\nBACKUP=%s' % (ORIG, BACKUP), '', 0)

        # module identity probes
        if command.startswith('cat /sys/module/amneziawg/srcversion'):
            return (sys_srcversion, '', 0)
        if command.startswith('cat /sys/module/amneziawg/version'):
            return (sys_version, '', 0)
        if 'modinfo -F version amneziawg' in command:
            return (OLD, '', 0)
        if 'modinfo -F srcversion' in command:
            return (build_srcversion, '', 0)
        if 'modinfo -F vermagic' in command:
            return (default_vermagic, '', 0)

        # update steps
        if 'git clone' in command:
            return ('', '', 0)
        if 'dkms add' in command:
            return ('', '', 0)
        if 'dkms build' in command:
            return ('', '', 0)
        if 'dkms install' in command:
            return ('', '', 0)
        if 'modprobe -n amneziawg' in command:
            return ('', '', 0)
        if 'modprobe -r amneziawg' in command:
            return ('', '', 0)
        if command.strip() == 'modprobe amneziawg':
            state['modprobe_calls'] += 1
            return ('', '', 0)
        if 'depmod' in command:
            return ('', '', 0)
        if 'dkms remove' in command:
            return ('', '', 0)

        # read-only probes / fallbacks
        if command.startswith('docker ps'):
            return ('', '', 0)
        if command.startswith('docker exec'):
            return ('interface: awg0', '', 0)
        return ('', '', 0)

    return handler


class _Log:
    def __init__(self):
        self.entries = []

    def __call__(self, stage, message):
        self.entries.append((stage, message))

    def messages(self):
        return [message for _stage, message in self.entries]


class VersionHeaderPatchTests(unittest.TestCase):
    def test_version_header_is_patched_between_clone_and_dkms_add(self):
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        clone = _index(ssh.commands, 'git clone')
        add = _index(ssh.commands, 'dkms add')
        patch = None
        for index, command in enumerate(ssh.commands):
            if ('#define WIREGUARD_VERSION' in command
                    and NEW in command
                    and '/tmp/awg-plugin-update/src' in command
                    and 'version.h' in command):
                patch = index
                break

        self.assertIsNotNone(patch, 'version.h was never patched')
        self.assertLess(clone, patch)
        self.assertLess(patch, add)


class SrcversionCaptureTests(unittest.TestCase):
    def test_srcversion_is_captured_before_unloading(self):
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        capture = _index(ssh.commands, 'modinfo -F srcversion')
        unload = _index(ssh.commands, 'modprobe -r amneziawg')
        self.assertLess(capture, unload)


class StaleVersionStringTests(unittest.TestCase):
    def test_stale_version_string_with_matching_code_is_success(self):
        ssh = FakeSSH(kernel_handler(
            sys_version=OLD, sys_srcversion=BUILD_SRC, build_srcversion=BUILD_SRC,
        ))
        log = _Log()
        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(result['state'], 'updated')
        self.assertFalse(result['rolled_back'])
        # No rollback material was touched: no depmod, no copy-back, one load.
        self.assertFalse(ssh.find('depmod -a'))
        self.assertFalse([
            command for command in ssh.commands
            if 'cp -a' in command and ORIG in command
        ])
        self.assertEqual(len(ssh.find('modprobe amneziawg')), 1)

        notes = [
            message for message in log.messages()
            if 'note' in message.lower() and OLD in message and NEW in message
        ]
        self.assertTrue(notes, 'no note about the stale version string: %r'
                        % (log.messages(),))


class IdentityMismatchTests(unittest.TestCase):
    def test_neither_version_nor_srcversion_matches_rolls_back(self):
        ssh = FakeSSH(kernel_handler(
            sys_version=OLD, sys_srcversion=OTHER_SRC, build_srcversion=BUILD_SRC,
        ))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'update_failed')
        commands = ssh.commands
        unload = _index(commands, 'modprobe -r amneziawg')
        remove = _index(commands, 'dkms remove amneziawg/%s --all' % NEW, unload)
        copy_back = _index(commands, 'cp -a', unload)
        reload = _index(commands, 'modprobe amneziawg', copy_back)

        self.assertIn(BACKUP, commands[copy_back])
        self.assertIn(ORIG, commands[copy_back])
        self.assertLess(remove, copy_back)
        self.assertLess(copy_back, reload)


class AppliedRecordTests(unittest.TestCase):
    def test_applied_json_records_target_and_srcversion(self):
        ssh = FakeSSH(kernel_handler(
            sys_version=NEW, sys_srcversion=BUILD_SRC, build_srcversion=BUILD_SRC,
        ))
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        writes = [
            command for command in ssh.commands
            if APPLIED in command and not command.lstrip().startswith('cat ')
        ]
        self.assertTrue(writes, 'applied.json was never written')
        write = writes[-1]
        self.assertIn(NEW, write)
        self.assertIn(BUILD_SRC, write)


class RecordedVersionTrustTests(unittest.TestCase):
    def test_recorded_version_is_trusted_only_when_the_hash_matches(self):
        applied = json.dumps({'version': NEW, 'srcversion': BUILD_SRC})

        matching = FakeSSH(kernel_handler(
            applied=applied, sys_version=OLD, sys_srcversion=BUILD_SRC,
        ))
        self.assertEqual(
            AwgPluginUpdater(matching).installed_versions()[KERNEL_MODULE], NEW,
        )

        stale = FakeSSH(kernel_handler(
            applied=applied, sys_version=OLD, sys_srcversion=OTHER_SRC,
        ))
        self.assertEqual(
            AwgPluginUpdater(stale).installed_versions()[KERNEL_MODULE], OLD,
        )

    def test_no_applied_json_falls_back_to_the_modinfo_value(self):
        ssh = FakeSSH(kernel_handler(applied='', sys_version=OLD))
        self.assertEqual(
            AwgPluginUpdater(ssh).installed_versions()[KERNEL_MODULE], OLD,
        )


if __name__ == '__main__':
    unittest.main()
