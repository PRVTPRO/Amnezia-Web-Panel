import json
import unittest
from unittest.mock import patch

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    KERNEL_MODULE,
    PluginUpdateError,
    USERSPACE,
    parse_tag,
    pick_latest,
    version_tuple,
)

OLD = '3.1.20260812'
NEW = '3.1.20260906'
GO_NEW = '3.1.20260828'


class FakeSSH:
    """Scripted SSH double: records every command, answers by handler."""

    def __init__(self, handler=None):
        self.commands = []
        self.handler = handler or (lambda command: ('', '', 0))

    def run_command(self, command, timeout=60, _retried=False, stdin_input=None):
        self.commands.append(command)
        return self.handler(command)

    def run_sudo_script(self, script, timeout=120):
        self.commands.append(script)
        return self.handler(script)

    def find(self, needle):
        return [command for command in self.commands if needle in command]


def kernel_handler(*, refs='0', headers='yes', tools='yes', git='yes', manager='apt-get',
                   clone=(0, ''), build=0, install=0, modprobe=0, unload=0,
                   dry_run=0, verify=NEW):
    state = {'modinfo_calls': 0, 'modprobe_calls': 0}

    def handler(command):
        if 'awk' in command and '/proc/modules' in command:
            return (refs, '', 0)
        if 'for m in apt-get' in command:
            return (manager or '', '', 0)
        if 'apt-get install' in command:
            # One-click dependency installation always succeeds by default.
            return ('', '', 0)
        if 'uname -r' in command and 'HEADERS=' in command:
            lines = ['KVER=6.12.113+deb13-amd64']
            lines.append('HEADERS=%s' % headers)
            lines.append('DKMS=%s' % tools)
            lines.append('GCC=%s' % tools)
            lines.append('MAKE=%s' % tools)
            lines.append('GIT=%s' % git)
            return ('\n'.join(lines), '', 0)
        # /sys reflects the module that is actually loaded; only the post-load
        # verification command starts with it, installed_versions() starts
        # with modinfo even though it falls back to /sys.
        if command.startswith('cat /sys/module/amneziawg/version'):
            return (verify, '', 0)
        if 'modinfo -F version amneziawg' in command:
            state['modinfo_calls'] += 1
            return (OLD, '', 0)
        if 'git clone' in command:
            return ('', clone[1], clone[0])
        if 'dkms add' in command:
            return ('', '', 0)
        if 'dkms build' in command:
            return ('', 'make: *** [Makefile:12: modules] Error 2' if build else '', build)
        if 'dkms install' in command:
            return ('', '', install)
        if 'modprobe -n amneziawg' in command:
            return ('', '', dry_run)
        if 'modprobe -r amneziawg' in command:
            return ('', '', unload)
        if 'modprobe amneziawg' in command:
            state['modprobe_calls'] += 1
            # Only the activation may fail; the rollback retry succeeds so the
            # rollback phase itself can be observed.
            return ('', '', modprobe if state['modprobe_calls'] == 1 else 0)
        if 'depmod' in command:
            return ('', '', 0)
        if 'dkms remove' in command:
            return ('', '', 0)
        if command.startswith('docker ps'):
            return ('', '', 0)
        if command.startswith('docker exec'):
            return ('interface: awg0', '', 0)
        return ('', '', 0)

    return handler


class TagTests(unittest.TestCase):
    def test_parse_tag(self):
        self.assertEqual(parse_tag('v3.1.20260906'), NEW)
        self.assertEqual(parse_tag('3.1.20260906'), NEW)
        self.assertIsNone(parse_tag('latest'))
        self.assertIsNone(parse_tag('v3.1.2026'))
        self.assertIsNone(parse_tag('v3.1.20260906-rc1'))

    def test_version_tuple(self):
        self.assertEqual(version_tuple(NEW), (3, 1, 20260906))
        self.assertIsNone(version_tuple('nope'))

    def test_pick_latest_orders_by_date(self):
        tags = ['v3.1.20260812', 'v3.1.20260906', 'v3.1.20260828', 'release-notes']
        self.assertEqual(pick_latest(tags), '3.1.20260906')

    def test_pick_latest_ignores_invalid(self):
        self.assertIsNone(pick_latest(['latest', 'v2.0', '']))
        self.assertIsNone(pick_latest([]))


class VersionDetectionTests(unittest.TestCase):
    def test_installed_kernel_parsed(self):
        ssh = FakeSSH(lambda command: (OLD, '', 0))
        self.assertEqual(
            AwgPluginUpdater(ssh).installed_versions()[KERNEL_MODULE], OLD,
        )

    def test_installed_kernel_absent(self):
        ssh = FakeSSH(lambda command: ('', '', 1))
        self.assertIsNone(
            AwgPluginUpdater(ssh).installed_versions()[KERNEL_MODULE],
        )

    def test_userspace_from_image_label(self):
        """The label is the fallback when the running binary prints nothing."""
        def handler(command):
            if command.startswith('docker ps -a'):
                return ('amnezia-awg3\tamneziavpn/amneziawg-go:latest', '', 0)
            if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                return ('FROM amneziavpn/amneziawg-go:latest', '', 0)
            if command.startswith('docker exec') and 'amneziawg-go --version' in command:
                return ('', '', 0)
            if 'Config.Labels' in command:
                return (GO_NEW, '', 0)
            return ('', '', 0)

        ssh = FakeSSH(handler)
        self.assertEqual(
            AwgPluginUpdater(ssh).installed_versions()[USERSPACE], GO_NEW,
        )
        self.assertTrue(ssh.find('Config.Labels'))

    def test_userspace_falls_back_to_image_tag(self):
        def handler(command):
            if command.startswith('docker ps -a'):
                return ('amnezia-awg2\tamneziavpn/amneziawg-go:%s' % OLD, '', 0)
            if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                return ('FROM amneziavpn/amneziawg-go:latest', '', 0)
            return ('', '', 0)

        ssh = FakeSSH(handler)
        self.assertEqual(
            AwgPluginUpdater(ssh).installed_versions()[USERSPACE], OLD,
        )


class StatusTests(unittest.TestCase):
    @staticmethod
    def _ssh_with_userspace():
        def handler(command):
            if command.startswith('docker ps -a'):
                return ('amnezia-awg3\tamneziavpn/amneziawg-go:latest', '', 0)
            if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                return ('FROM amneziavpn/amneziawg-go:latest', '', 0)
            return ('', '', 0)
        return FakeSSH(handler)

    def test_update_available(self):
        """Userspace is listed but status() never offers it as an update.

        The daemon reports 0.0.YYYYMMDD, which cannot be compared with the
        repository's 3.1.YYYYMMDD tags, so no "available" version is fetched
        and the component is never marked updatable.
        """
        from managers.awg_plugin_updater import _tag_cache
        _tag_cache.clear()

        def source(name):
            return ['v3.1.20260906'] if 'kernel' in name else ['v3.1.20260828']

        status = AwgPluginUpdater(
            self._ssh_with_userspace(), tag_source=source,
        ).status(installed={KERNEL_MODULE: OLD, USERSPACE: '0.0.20250522'})
        kernel = status['components'][KERNEL_MODULE]
        userspace = status['components'][USERSPACE]
        self.assertTrue(kernel['update_available'])
        self.assertTrue(userspace['applicable'])
        self.assertEqual(userspace['installed'], '0.0.20250522')
        self.assertIsNone(userspace['available'])
        self.assertFalse(userspace['update_available'])

    def test_up_to_date(self):
        status = AwgPluginUpdater(self._ssh_with_userspace()).status(
            latest={KERNEL_MODULE: NEW, USERSPACE: None},
            installed={KERNEL_MODULE: NEW, USERSPACE: '0.0.20250522'},
        )
        self.assertFalse(status['components'][KERNEL_MODULE]['update_available'])
        self.assertFalse(status['components'][USERSPACE]['update_available'])
        self.assertIsNone(status['components'][USERSPACE]['available'])

    def test_unknown_installed_is_update(self):
        status = AwgPluginUpdater(self._ssh_with_userspace()).status(
            latest={KERNEL_MODULE: NEW, USERSPACE: None},
            installed={KERNEL_MODULE: None, USERSPACE: None},
        )
        self.assertTrue(status['components'][KERNEL_MODULE]['update_available'])
        self.assertFalse(status['components'][USERSPACE]['update_available'])


class PreflightTests(unittest.TestCase):
    def test_missing_headers_with_manager_is_installable(self):
        """Headers are no longer fatal: one click installs them."""
        ssh = FakeSSH(kernel_handler(headers='no'))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)
        self.assertTrue(check['ready'])
        self.assertEqual(check['blockers'], [])
        self.assertIn('headers', check['installable'])

    def test_missing_build_tools_are_installable(self):
        """Missing dkms/gcc/make/git are installable, not blockers."""
        ssh = FakeSSH(kernel_handler(tools='no'))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)
        self.assertTrue(check['ready'])
        self.assertEqual(check['blockers'], [])
        self.assertEqual(
            set(check['installable']), {'dkms', 'gcc', 'make'},
        )

    def test_missing_tools_without_manager_blocks(self):
        ssh = FakeSSH(kernel_handler(tools='no', manager=''))
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)
        self.assertFalse(check['ready'])
        self.assertTrue(check['blockers'])

    def test_ready_when_dependencies_present(self):
        ssh = FakeSSH(kernel_handler())
        check = AwgPluginUpdater(ssh).preflight(KERNEL_MODULE)
        self.assertTrue(check['ready'])
        self.assertEqual(check['installable'], [])
        self.assertEqual(check['blockers'], [])
        self.assertFalse(check['requires_interruption'])


class KernelUpdateTests(unittest.TestCase):
    def test_success_order_and_old_kept(self):
        ssh = FakeSSH(kernel_handler())
        result = AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertEqual(result['state'], 'updated')
        self.assertEqual(result['installed'], NEW)
        self.assertEqual(result['previous'], OLD)

        clone = next(i for i, c in enumerate(ssh.commands) if 'git clone' in c)
        build = next(i for i, c in enumerate(ssh.commands) if 'dkms build' in c)
        install = next(i for i, c in enumerate(ssh.commands) if 'dkms install' in c)
        dry = next(i for i, c in enumerate(ssh.commands) if 'modprobe -n amneziawg' in c)
        unload = next(i for i, c in enumerate(ssh.commands) if 'modprobe -r amneziawg' in c)
        self.assertLess(clone, build)
        self.assertLess(build, install)
        self.assertLess(install, dry)
        self.assertLess(dry, unload)
        # The working DKMS version must survive both success and failure.
        self.assertFalse([c for c in ssh.commands if 'dkms remove amneziawg/%s' % OLD in c])

    def test_build_failure_keeps_old_module(self):
        ssh = FakeSSH(kernel_handler(build=1))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('dkms remove amneziawg/%s --all' % NEW))
        self.assertFalse(ssh.find('modprobe -r amneziawg'))
        self.assertFalse(ssh.find('dkms remove amneziawg/%s' % OLD))

    def test_dry_run_failure_keeps_running_module(self):
        ssh = FakeSSH(kernel_handler(dry_run=1))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('dkms remove amneziawg/%s --all' % NEW))
        self.assertFalse(ssh.find('modprobe -r amneziawg'))

    def test_verification_reads_the_loaded_module(self):
        ssh = FakeSSH(kernel_handler())
        AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertTrue(ssh.find('cat /sys/module/amneziawg/version'))

    def test_unload_busy_rebuilds_old_and_aborts(self):
        """dkms install of the new version overwrites the old .ko on disk, so
        an aborted switch must rebuild the old version before giving up."""
        ssh = FakeSSH(kernel_handler(unload=1))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, allow_interrupt=False)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertIn('in use', ctx.exception.message)
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % OLD))
        self.assertTrue(ssh.find('dkms install amneziawg/%s --force' % OLD))
        # The loaded old module was never touched.
        self.assertTrue(ssh.find('modprobe -r amneziawg'))
        self.assertFalse(ssh.find('dkms remove amneziawg/%s' % OLD))

    def test_rollback_rebuilds_the_old_module(self):
        ssh = FakeSSH(kernel_handler(modprobe=1, verify=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('dkms build amneziawg/%s' % OLD))
        self.assertTrue(ssh.find('dkms install amneziawg/%s --force' % OLD))
        self.assertTrue(ssh.find('depmod'))

    def test_modprobe_failure_rolls_back(self):
        ssh = FakeSSH(kernel_handler(modprobe=1, verify=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('dkms remove amneziawg/%s --all' % NEW))
        self.assertTrue(ssh.find('depmod'))
        self.assertFalse(ssh.find('dkms remove amneziawg/%s' % OLD))

    def test_requires_confirmation_changes_nothing(self):
        ssh = FakeSSH(kernel_handler(refs='2'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(KERNEL_MODULE, NEW, allow_interrupt=False)
        self.assertEqual(ctx.exception.code, 'requires_confirmation')
        self.assertFalse(ssh.find('git clone'))
        self.assertFalse(ssh.find('dkms add'))
        self.assertFalse(ssh.find('dkms build'))
        self.assertFalse(ssh.find('modprobe -r'))
        self.assertFalse(ssh.find('modprobe amneziawg'))

    def test_rejects_unsupported_target(self):
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(FakeSSH()).update(KERNEL_MODULE, 'latest')
        self.assertEqual(ctx.exception.code, 'unsupported')


class UserspaceUpdateTests(unittest.TestCase):
    def _inspect(self, name='amnezia-awg3'):
        return json.dumps([{
            'Image': 'sha256:oldimage',
            'Config': {'Image': name, 'Labels': {'org.opencontainers.image.version': OLD}},
            'HostConfig': {
                'Privileged': True,
                'CapAdd': ['NET_ADMIN', 'SYS_MODULE'],
                'Binds': ['/lib/modules:/lib/modules:rw'],
                'PortBindings': {'55424/udp': [{'HostPort': '55424'}]},
                'Sysctls': {'net.ipv4.conf.all.src_valid_mark': '1'},
                'RestartPolicy': {'Name': 'always'},
                'NetworkMode': 'default',
                'Ulimits': [{'Name': 'nofile', 'Soft': 51200, 'Hard': 51200}],
            },
        }])

    def _handler(self, *, build=0, version=GO_NEW, peers='3', peers_after='3',
                 dockerfile='yes', shape='ok', tunnel_ok=True):
        state = {'peer_calls': 0, 'builds': 0}

        def handler(command):
            if command.startswith('docker ps -a'):
                return ('amnezia-awg3\tamneziavpn/amneziawg-go:latest', '', 0)
            if 'Config.Labels' in command:
                return (version, '', 0)
            if command.startswith('docker inspect amnezia-awg3.old-'):
                return ('yes', '', 0)
            if command.startswith('docker inspect amnezia-awg3'):
                payload = json.loads(self._inspect())
                if shape == 'bad':
                    payload[0]['HostConfig']['NetworkMode'] = 'host'
                return (json.dumps(payload), '', 0)
            # _go_containers() reads the generated Dockerfile to tell the
            # amneziawg-go images apart from the legacy amnezia-wg ones.
            if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                return (
                    'FROM amneziavpn/amneziawg-go:latest' if dockerfile == 'yes' else '',
                    '', 0,
                )
            if 'test -f /opt/amnezia/' in command and 'Dockerfile' in command:
                return ('yes' if dockerfile == 'yes' else '', '', 0)
            if 'docker cp amnezia-awg3:/opt/amnezia' in command:
                return ('', '', 0)
            if "grep -c" in command and 'docker exec' in command:
                state['peer_calls'] += 1
                return ((peers if state['peer_calls'] == 1 else peers_after), '', 0)
            if 'docker exec' in command and ('awg show' in command or 'wg show' in command):
                return ('interface: awg0', '', 0) if tunnel_ok else ('', '', 1)
            if command.startswith('docker build'):
                state['builds'] += 1
                return ('', 'build failed' if build else '', build)
            if 'test -f /opt/amnezia/awg/*.conf' in command:
                return ('', '', 0)
            if command.startswith('docker run'):
                return ('container-id', '', 0)
            return ('', '', 0)

        return handler

    def test_unknown_container_shape_is_not_touched(self):
        ssh = FakeSSH(self._handler(shape='bad'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'unsupported')
        self.assertFalse(ssh.find('docker stop'))
        self.assertFalse(ssh.find('docker build'))

    def test_container_without_panel_dockerfile_is_not_touched(self):
        """Without the generated Dockerfile the container is not even detected."""
        ssh = FakeSSH(self._handler(dockerfile='no'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'not_installed')
        self.assertFalse(ssh.find('docker stop'))
        self.assertFalse(ssh.find('docker build'))
        self.assertFalse(ssh.find('docker cp'))

    def test_build_failure_touches_nothing(self):
        ssh = FakeSSH(self._handler(build=1))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertFalse(ssh.find('docker stop'))
        self.assertFalse(ssh.find('docker rename'))

    def test_registry_older_than_target_stops_before_restart(self):
        ssh = FakeSSH(self._handler(version=OLD))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'unsupported')
        self.assertFalse(ssh.find('docker stop'))

    def test_requires_confirmation_without_flag(self):
        ssh = FakeSSH(self._handler())
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW)
        self.assertEqual(ctx.exception.code, 'requires_confirmation')
        self.assertFalse(ssh.find('docker build'))

    def test_success_recreates_and_restores_configuration(self):
        ssh = FakeSSH(self._handler())
        result = AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(result['state'], 'updated')
        order = [
            next(i for i, c in enumerate(ssh.commands) if c.startswith('docker build')),
            next(i for i, c in enumerate(ssh.commands) if c.startswith('docker stop')),
            next(i for i, c in enumerate(ssh.commands) if c.startswith('docker run')),
            next(i for i, c in enumerate(ssh.commands) if c.startswith('docker cp /tmp/awg-plugin-backup')),
            next(i for i, c in enumerate(ssh.commands) if c.startswith('docker restart')),
        ]
        self.assertEqual(order, sorted(order))
        self.assertTrue(ssh.find('docker rename amnezia-awg3 amnezia-awg3.old-'))
        # The old container is only removed after the new one is verified.
        self.assertTrue(ssh.find('docker rm -f amnezia-awg3.old-'))

    def test_dropped_peers_roll_back(self):
        ssh = FakeSSH(self._handler(peers='5', peers_after='0'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('docker rm -f amnezia-awg3'))
        self.assertTrue(any(
            command.startswith('docker rename amnezia-awg3.old-')
            and command.endswith(' amnezia-awg3')
            for command in ssh.commands
        ))
        self.assertTrue(ssh.find('docker start amnezia-awg3'))

    def test_tunnel_not_coming_up_rolls_back(self):
        ssh = FakeSSH(self._handler(tunnel_ok=False))
        # The retry loop sleeps two seconds between attempts; keep it instant.
        with patch('managers.awg_plugin_updater.time.sleep'):
            with self.assertRaises(PluginUpdateError) as ctx:
                AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)
        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertIn('tunnel', ctx.exception.message)
        self.assertTrue(ssh.find('docker rm -f amnezia-awg3'))
        self.assertTrue(ssh.find('docker start amnezia-awg3'))

    def test_status_marks_unused_userspace_not_applicable(self):
        """No amneziawg-go containers: userspace is not offered at all."""
        ssh = FakeSSH(lambda command: ('', '', 0))
        asked = []

        def source(name):
            asked.append(name)
            return ['v3.1.20260906'] if 'kernel' in name else ['v3.1.20260828']

        from managers.awg_plugin_updater import _tag_cache
        _tag_cache.clear()
        status = AwgPluginUpdater(ssh, tag_source=source).status()
        userspace = status['components'][USERSPACE]
        self.assertFalse(userspace['applicable'])
        self.assertFalse(userspace['update_available'])
        self.assertNotIn('amnezia-vpn/amneziawg-go', asked)
        self.assertTrue(status['components'][KERNEL_MODULE]['applicable'])

    def test_run_command_is_rebuilt_from_inspect(self):
        command = AwgPluginUpdater._docker_run_from_inspect(
            'amnezia-awg3', json.loads(self._inspect())[0]['HostConfig'])
        self.assertIn('--privileged', command)
        self.assertIn('--cap-add=NET_ADMIN', command)
        self.assertIn('--cap-add=SYS_MODULE', command)
        self.assertIn('-p 55424:55424/udp', command)
        self.assertIn('-v /lib/modules:/lib/modules:rw', command)
        self.assertIn('--sysctl="net.ipv4.conf.all.src_valid_mark=1"', command)
        self.assertIn('--ulimit nofile=51200:51200', command)
        self.assertTrue(command.rstrip().endswith('amnezia-awg3'))


class ChangelogTests(unittest.TestCase):
    def test_unknown_installed_version_returns_empty(self):
        ssh = FakeSSH(lambda command: ('', '', 1))
        self.assertEqual(AwgPluginUpdater(ssh).changelog(KERNEL_MODULE, NEW), [])


class TagSourceTests(unittest.TestCase):
    def test_repository_slug_keeps_the_owner(self):
        """A bare repo name makes api.github.com answer 404."""
        from managers.awg_plugin_updater import _repo_slug
        self.assertEqual(
            _repo_slug('https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git'),
            'amnezia-vpn/amneziawg-linux-kernel-module',
        )
        self.assertEqual(
            _repo_slug('https://github.com/amnezia-vpn/amneziawg-go'),
            'amnezia-vpn/amneziawg-go',
        )

    def test_latest_versions_asks_for_owner_qualified_repos(self):
        asked = []

        def source(name):
            asked.append(name)
            return ['v3.1.20260906'] if 'kernel' in name else ['v3.1.20260828']

        from managers.awg_plugin_updater import _tag_cache
        _tag_cache.clear()
        latest = AwgPluginUpdater(FakeSSH(), tag_source=source).latest_versions()
        self.assertIn('amnezia-vpn/amneziawg-linux-kernel-module', asked)
        self.assertIn('amnezia-vpn/amneziawg-go', asked)
        self.assertEqual(latest[KERNEL_MODULE], '3.1.20260906')
        self.assertEqual(latest[USERSPACE], '3.1.20260828')


if __name__ == '__main__':
    unittest.main()
