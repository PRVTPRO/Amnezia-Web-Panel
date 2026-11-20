"""One-click build dependencies for the AWG kernel-module update.

``preflight`` used to turn a missing compiler, DKMS or kernel headers into a
hard blocker.  It now reports what can be installed (``installable``) apart
from what is impossible (``blockers``), and ``update()`` calls
``ensure_dependencies`` before the kernel path so the operator only has to
click once.

Everything here is scripted: no SSH, no network and no real sleeps.  The apt
lock retry sleeps 15 seconds in the module, so ``time.sleep`` is patched in the
one test that exercises it.
"""

import unittest
from unittest.mock import patch

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
    TOTAL_STEPS,
    USERSPACE,
    stage_step,
)
from tests.awg_plugin_fixtures import FakeSSH, OLD, NEW, KVER

CLOUD_KVER = '6.12.113-cloud-amd64'
BUILD_SRC = 'ABCD1234'


class _Log:
    def __init__(self):
        self.entries = []

    def __call__(self, stage, message):
        self.entries.append((stage, message))

    def messages(self):
        return [message for _stage, message in self.entries]


def _apply_install(packages, state):
    """Pretend the package manager installed ``packages`` successfully."""
    for name in packages:
        if name in ('dkms', 'gcc', 'make', 'git'):
            state[name] = 'yes'
        elif name.startswith(('linux-headers', 'kernel-devel')):
            state['headers'] = 'yes'
    return ('', '', 0)


INSTALL_PREFIXES = (
    'DEBIAN_FRONTEND=noninteractive apt-get install',
    'dnf install',
    'yum install',
    'apk add',
    'pacman -S',
)


def _install_commands(commands):
    """Package-manager installs only (never ``dkms install``)."""
    return [
        command for command in commands
        if any(command.startswith(prefix) for prefix in INSTALL_PREFIXES)
    ]


def kernel_handler(*, kernel=KVER, headers='yes', dkms='yes', gcc='yes',
                   make='yes', git='yes', manager='apt-get', secure_boot='',
                   install=None, depends='', kernels_with_headers=''):
    """Scripted host state for preflight, dependency installation and update.

    Flags start as the *current* state.  A successful package install updates
    the flags, so the post-install preflight sees the fixed host, exactly like
    the real module.  ``install(packages, state)`` overrides the default
    success answer and can script failures, apt locks or header fallbacks.
    ``depends``/``kernels_with_headers`` script the hints the module reads
    when the running kernel has no headers in the repositories.
    """
    state = {
        'headers': headers, 'dkms': dkms, 'gcc': gcc,
        'make': make, 'git': git,
    }

    def handler(command):
        # preflight probes
        if 'awk' in command and '/proc/modules' in command:
            return ('0', '', 0)
        if 'for m in apt-get' in command:
            return (manager or '', '', 0)
        if 'mokutil --sb-state' in command:
            return (secure_boot, '', 0)
        if 'HEADERS=' in command and 'uname -r' in command:
            return (
                'KVER=%s\nHEADERS=%s\nDKMS=%s\nGCC=%s\nMAKE=%s\nGIT=%s'
                % (kernel, state['headers'], state['dkms'], state['gcc'],
                   state['make'], state['git']),
                '', 0,
            )
        # hints for a running kernel whose headers are gone from the pool
        if command.startswith('for d in /lib/modules'):
            return (kernels_with_headers, '', 0)
        if command.startswith('apt-cache depends'):
            return (depends, '', 0)
        if command.startswith('apt-cache search'):
            return ('', '', 0)
        if command.startswith('apt-cache show'):
            return ('Package: ' + depends, '', 0) if depends else ('', '', 0)
        if command.startswith('DEBIAN_FRONTEND=noninteractive apt-get update'):
            return ('', '', 0)

        # one-click dependency installation
        for prefix in INSTALL_PREFIXES:
            if command.startswith(prefix):
                # Drop the manager's switches: only package names remain.
                packages = [
                    token for token in command[len(prefix):].split()
                    if not token.startswith('-')
                ]
                if install is not None:
                    return install(packages, state)
                return _apply_install(packages, state)

        # kernel update path
        if command.strip() == 'uname -r':
            return (kernel, '', 0)
        if command.startswith('mkdir -p /var/lib/amnezia-plugin'):
            return (
                'ORIG=/lib/modules/%s/updates/dkms/amneziawg.ko\n'
                'BACKUP=/var/lib/amnezia-plugin/amneziawg-%s.ko' % (kernel, OLD),
                '', 0,
            )
        if 'modinfo -F version amneziawg' in command:
            return (OLD, '', 0)
        if 'modinfo -F srcversion' in command:
            return (BUILD_SRC, '', 0)
        if 'modinfo -F vermagic' in command:
            return ('%s SMP preempt mod_unload modversions' % kernel, '', 0)
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


class DependenciesHappyPathTests(unittest.TestCase):
    def test_everything_present_runs_no_install(self):
        ssh = FakeSSH(kernel_handler())
        log = _Log()

        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(result['state'], 'updated')
        self.assertEqual(_install_commands(ssh.commands), [])
        self.assertIn('all build dependencies are present', log.messages())

    def test_missing_tools_are_installed_in_one_command_and_update_continues(self):
        ssh = FakeSSH(kernel_handler(dkms='no', gcc='no'))
        log = _Log()

        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        installs = _install_commands(ssh.commands)
        self.assertEqual(len(installs), 1, installs)
        packages = installs[0].split('install -y -qq ', 1)[1].split()
        self.assertEqual(set(packages), {'dkms', 'gcc'})
        # Present tools must not be reinstalled.
        self.assertNotIn('make', packages)
        self.assertNotIn('git', packages)
        self.assertIn('missing: dkms, gcc', log.messages())
        self.assertIn('dependencies are ready', log.messages())

        # The update really continued past the dependency stage.
        self.assertEqual(result['state'], 'updated')
        self.assertTrue(ssh.find('git clone'))
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % NEW))


class AptLockRetryTests(unittest.TestCase):
    def test_apt_lock_retries_once_without_slowing_the_suite(self):
        calls = []

        def install(packages, state):
            calls.append(list(packages))
            if len(calls) == 1:
                return (
                    '',
                    'E: Could not get lock /var/lib/dpkg/lock-frontend. '
                    'It is held by process 42 (apt-get)',
                    100,
                )
            return _apply_install(packages, state)

        ssh = FakeSSH(kernel_handler(dkms='no', install=install))
        log = _Log()

        with patch('managers.awg_plugin_updater.time.sleep') as sleeper:
            result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(len(calls), 2, calls)
        sleeper.assert_any_call(15)
        self.assertIn('package manager is busy, retrying once', log.messages())
        self.assertIn('dependencies are ready', log.messages())
        self.assertEqual(result['state'], 'updated')


class HeadersFallbackTests(unittest.TestCase):
    def test_cloud_headers_fallback_after_exact_package_fails(self):
        attempts = []

        def install(packages, state):
            package = packages[0]
            attempts.append(package)
            if package == 'linux-headers-%s' % CLOUD_KVER:
                return ('', 'E: Unable to locate package ' + package, 100)
            return _apply_install(packages, state)

        ssh = FakeSSH(kernel_handler(
            kernel=CLOUD_KVER, headers='no', install=install,
        ))
        log = _Log()

        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(
            attempts,
            ['linux-headers-%s' % CLOUD_KVER, 'linux-headers-cloud-amd64'],
        )
        self.assertIn('trying linux-headers-cloud-amd64', log.messages())
        # The post-install preflight saw HEADERS=yes: the update proceeded.
        self.assertEqual(result['state'], 'updated')
        self.assertTrue(ssh.find('git clone'))

    def test_no_headers_candidate_installs_raises_preflight_failed(self):
        attempts = []

        def install(packages, state):
            attempts.append(packages[0])
            return ('', 'E: Unable to locate package ' + packages[0], 100)

        ssh = FakeSSH(kernel_handler(headers='no', install=install))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        self.assertIn('kernel headers', ctx.exception.message)
        self.assertEqual(
            attempts, ['linux-headers-%s' % KVER, 'linux-headers-amd64'],
        )
        self.assertFalse(ssh.find('git clone'))


class AptListRefreshTests(unittest.TestCase):
    def test_lists_are_refreshed_once_before_the_first_install(self):
        ssh = FakeSSH(kernel_handler(dkms='no', gcc='no'))

        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        updates = [i for i, command in enumerate(ssh.commands)
                   if command.startswith('DEBIAN_FRONTEND=noninteractive apt-get update')]
        installs = [i for i, command in enumerate(ssh.commands)
                    if command.startswith('DEBIAN_FRONTEND=noninteractive apt-get install')]
        self.assertEqual(len(updates), 1, ssh.find('apt-get update'))
        self.assertLess(updates[0], installs[0])

    def test_stale_lists_are_refreshed_and_the_install_retried(self):
        calls = []

        def install(packages, state):
            calls.append(list(packages))
            if len(calls) == 1:
                return (
                    '',
                    'E: Failed to fetch http://deb.debian.org/debian/pool/main/d/dpkg/'
                    'libdpkg-perl_1.21.22_all.deb  404  Not Found [IP: 151.101.2.132 80]\n'
                    'E: Unable to fetch some archives, maybe run apt-get update',
                    100,
                )
            return _apply_install(packages, state)

        ssh = FakeSSH(kernel_handler(dkms='no', gcc='no', install=install))
        log = _Log()

        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, log=log)

        self.assertEqual(len(calls), 2, calls)
        self.assertGreaterEqual(len(ssh.find('apt-get update')), 2)
        self.assertIn('the install failed on package metadata, refreshing the lists '
                      'and retrying once', log.messages())
        self.assertEqual(result['state'], 'updated')

    def test_plain_failure_is_not_retried_after_a_refresh(self):
        ssh = FakeSSH(kernel_handler(
            dkms='no', install=lambda packages, state: ('', 'E: Sub-process /usr/bin/dpkg returned an error code (1)', 100),
        ))

        with self.assertRaises(PluginUpdateError):
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(len(ssh.find('apt-get update')), 1)
        self.assertEqual(len(_install_commands(ssh.commands)), 1)


class OutdatedKernelTests(unittest.TestCase):
    """The running kernel is older than the one the repositories carry."""

    def _failing_headers(self, packages, state):
        return ('', 'E: Unable to locate package ' + packages[0], 100)

    def test_installed_headers_for_another_kernel_ask_for_a_reboot(self):
        ssh = FakeSSH(kernel_handler(
            headers='no', install=self._failing_headers,
            kernels_with_headers='6.1.0-56-amd64\n',
            depends='linux-headers-6.1.0-56-amd64',
        ))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        self.assertIn('6.1.0-56-amd64', ctx.exception.message)
        self.assertIn('reboot the server', ctx.exception.message)
        self.assertFalse(ssh.find('git clone'))

    def test_missing_headers_point_to_the_current_kernel(self):
        ssh = FakeSSH(kernel_handler(
            headers='no', install=self._failing_headers,
            depends='linux-headers-6.1.0-56-amd64',
        ))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        message = ctx.exception.message
        self.assertIn('carry headers only for kernel 6.1.0-56-amd64', message)
        self.assertIn('linux-image-amd64', message)
        self.assertIn('linux-headers-amd64', message)

    def test_ubuntu_flavour_gets_its_own_package_names(self):
        ssh = FakeSSH(kernel_handler(
            kernel='6.8.0-45-generic', headers='no',
            install=self._failing_headers,
            depends='linux-headers-6.8.0-46-generic',
        ))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        message = ctx.exception.message
        self.assertIn('carry headers only for kernel 6.8.0-46-generic', message)
        self.assertIn('linux-image-generic', message)
        self.assertIn('linux-headers-generic', message)
        self.assertNotIn('linux-image-amd64', message)

    def test_headers_installed_for_the_other_kernel_still_block_the_build(self):
        def install(packages, state):
            if packages[0] == 'linux-headers-%s' % KVER:
                return ('', 'E: Unable to locate package ' + packages[0], 100)
            return ('', '', 0)

        ssh = FakeSSH(kernel_handler(
            headers='no', install=install,
            kernels_with_headers='6.1.0-56-amd64\n',
        ))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        self.assertIn('still missing after installation: headers', ctx.exception.message)
        self.assertIn('reboot the server', ctx.exception.message)

    def test_no_hint_when_the_repositories_match_the_running_kernel(self):
        ssh = FakeSSH(kernel_handler(
            headers='no', install=self._failing_headers,
            depends='linux-headers-%s' % KVER,
        ))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertNotIn('reboot', ctx.exception.message)

    def test_fallback_search_stays_within_the_running_kernel_flavour(self):
        ssh = FakeSSH(kernel_handler(
            kernel='6.1.0-45-amd64', headers='no',
            install=self._failing_headers, depends='',
        ))

        with self.assertRaises(PluginUpdateError):
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        searches = [command for command in ssh.commands
                    if command.startswith('apt-cache search')]
        self.assertEqual(len(searches), 1, searches)
        # -cloud-amd64 and -rt-amd64 must not be offered for a plain kernel.
        self.assertIn('-[0-9]+-amd64$', searches[0])


class PackageManagerRefreshTests(unittest.TestCase):
    def test_dnf_metadata_is_refreshed_before_the_install(self):
        ssh = FakeSSH(kernel_handler(dkms='no', manager='dnf'))

        AwgPluginUpdater(ssh).ensure_dependencies(KERNEL_MODULE, _Log())

        refresh = [i for i, command in enumerate(ssh.commands)
                   if command == 'dnf -q makecache']
        install = [i for i, command in enumerate(ssh.commands)
                   if command.startswith('dnf install')]
        self.assertEqual(len(refresh), 1, ssh.commands)
        self.assertEqual(len(install), 1, ssh.commands)
        self.assertLess(refresh[0], install[0])

    def test_pacman_is_not_synced_without_an_upgrade(self):
        ssh = FakeSSH(kernel_handler(dkms='no', manager='pacman'))

        AwgPluginUpdater(ssh).ensure_dependencies(KERNEL_MODULE, _Log())

        # `pacman -Sy` without `-u` is a partial upgrade, not a refresh.
        self.assertFalse(ssh.find('pacman -Sy'))
        self.assertTrue(ssh.find('pacman -S --noconfirm --needed dkms'))


class SecureBootTests(unittest.TestCase):
    def test_secure_boot_is_a_blocker_and_nothing_is_installed(self):
        ssh = FakeSSH(kernel_handler(secure_boot='SecureBoot enabled'))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        self.assertIn('Secure Boot', ctx.exception.message)
        self.assertTrue(ssh.find('mokutil --sb-state'))
        self.assertEqual(_install_commands(ssh.commands), [])
        self.assertFalse(ssh.find('git clone'))
        self.assertFalse(ssh.find('dkms build'))


class InstallFailureTests(unittest.TestCase):
    def test_failed_install_stops_before_download_and_build(self):
        def install(packages, state):
            # "Unable to locate" is a stale-list symptom, so one refresh+retry
            # is expected; after that the failure is real and must stop the run.
            return ('', 'E: Unable to locate package dkms', 1)

        ssh = FakeSSH(kernel_handler(dkms='no', install=install))

        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)

        self.assertEqual(ctx.exception.code, 'preflight_failed')
        self.assertIn('cannot install dkms', ctx.exception.message)
        self.assertFalse(ssh.find('git clone'))
        self.assertFalse(ssh.find('dkms add'))
        self.assertFalse(ssh.find('dkms build'))
        self.assertFalse(ssh.find('dkms install'))
        # The failed package installation was retried once after a refresh.
        self.assertEqual(len(_install_commands(ssh.commands)), 2)


class UserspaceDependenciesTests(unittest.TestCase):
    def test_userspace_has_no_package_dependencies(self):
        def handler(command):
            if command.startswith('docker ps -a'):
                return ('amnezia-awg3\tamneziavpn/amneziawg-go:latest', '', 0)
            if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                return ('FROM amneziavpn/amneziawg-go:latest', '', 0)
            return ('', '', 0)

        ssh = FakeSSH(handler)
        log = _Log()

        check = AwgPluginUpdater(ssh).preflight(USERSPACE)
        self.assertEqual(check['installable'], [])
        self.assertEqual(check['blockers'], [])

        AwgPluginUpdater(ssh).ensure_dependencies(USERSPACE, log)

        self.assertIn('all build dependencies are present', log.messages())
        self.assertEqual(_install_commands(ssh.commands), [])
        self.assertFalse(ssh.find('for m in apt-get'))
        self.assertFalse(ssh.find('mokutil'))


class DependencyStageTests(unittest.TestCase):
    def test_kernel_stage_numbers_shifted_by_the_dependencies_stage(self):
        expected = [
            ('start', 1), ('preflight', 2), ('dependencies', 3),
            ('backup', 4), ('download', 5), ('dkms-add', 6),
            ('build', 7), ('install', 8), ('verify', 9),
            ('activate', 10), ('tunnel', 11), ('done', 12),
        ]
        self.assertEqual(TOTAL_STEPS, 12)
        for stage, step in expected:
            self.assertEqual(stage_step(KERNEL_MODULE, stage), (step, TOTAL_STEPS))

    def test_containers_are_logged_under_the_tunnel_stage(self):
        def handler(command):
            if command.startswith('docker exec'):
                return ('interface: awg0', '', 0)
            return ('', '', 0)

        log = _Log()
        AwgPluginUpdater(FakeSSH(handler))._start_awg_containers(['amnezia-awg3'], log)

        self.assertEqual({stage for stage, _message in log.entries}, {'tunnel'})
        self.assertTrue(any(
            'starting amnezia-awg3' in message for _stage, message in log.entries
        ))


if __name__ == '__main__':
    unittest.main()
