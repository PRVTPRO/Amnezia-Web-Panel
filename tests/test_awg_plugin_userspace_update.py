"""Userspace (amneziawg-go) update safety.

The tests script the SSH fake command by command so every assertion is about
the *sequence* of remote commands: which version source is trusted, whether
the panel's DNS network survives the recreate, what happens on cancellation,
and which failure paths are allowed to delete the on-host backups.

``_userspace_version`` asks the running container first (the daemon prints
``amneziawg-go 0.0.YYYYMMDD``); the OCI image label is only a fallback and the
image tag is the last resort.
"""

import unittest

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    PluginUpdateError,
    USERSPACE,
)
from tests.awg_plugin_fixtures import (
    DOCKER_PS,
    FakeSSH,
    GO_NEW,
    OLD,
    container_inspect,
    inspect_json,
)

CLEANUP = 'rm -rf /tmp/awg-plugin-update /tmp/awg-plugin-backup-*'
PROBE_PREFIX = 'docker run --rm --entrypoint sh'
US_BINARY = '0.0.20250522'
US_BINARY_OUTPUT = (
    'amneziawg-go 0.0.20250522\n\n'
    'Userspace AmneziaWG daemon for linux-amd64.\n'
    'Information available at https://amnezia.org\n'
)


def _index(commands, needle, start=0):
    """First index of a command containing ``needle`` at or after ``start``."""
    for index in range(start, len(commands)):
        if needle in commands[index]:
            return index
    raise AssertionError('no command containing %r after index %d' % (needle, start))


def _ps_line(name):
    if name == 'amnezia-awg3':
        return DOCKER_PS
    return '%s\tamneziavpn/amneziawg-go:latest' % name


def userspace_handler(*, containers=None, inspect_options=None, peers_before='5',
                      peers_after=None, post_build_label=GO_NEW, probe_output=None,
                      exec_version_output=None, tunnel_ok=True, build_code=0):
    """Scripted answers for every command the userspace update issues.

    ``post_build_label`` is what the OCI version label answers after the
    image has been built (before the build it is always ``OLD``), which is
    how the tests distinguish "the label is trustworthy" from "the binary
    must be asked".  ``probe_output`` is the output of the throw-away
    ``docker run --rm --entrypoint sh`` probe.
    """
    containers = list(containers or ['amnezia-awg3'])
    inspect_options = inspect_options or {}
    peers_after = peers_before if peers_after is None else peers_after
    state = {'built': False, 'peer_calls': 0}

    def handler(command):
        if command.startswith('docker ps -a'):
            return ('\n'.join(_ps_line(name) for name in containers), '', 0)

        # The label query is used for _image_version(), _userspace_version()
        # and the post-build verification; only the suffix differs.
        if 'Config.Labels' in command:
            for name in containers:
                if name in command:
                    return ((post_build_label if state['built'] else OLD), '', 0)
            return ('', '', 0)

        if command.startswith('docker inspect ') and '.old-' in command:
            return ('yes', '', 0)
        if command.startswith('docker inspect '):
            for name in containers:
                if command.startswith('docker inspect %s' % name):
                    return (inspect_json(**inspect_options.get(name, {})), '', 0)

        # _go_containers() identifies the panel's amneziawg-go images by the
        # FROM line of their generated Dockerfile.
        if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
            return ('FROM amneziavpn/amneziawg-go:latest', '', 0)

        if 'test -f' in command and 'Dockerfile' in command:
            return ('yes', '', 0)

        # Backup copy: docker cp <name>:/opt/amnezia /tmp/awg-plugin-backup-...
        if command.startswith('docker cp ') and ':/opt/amnezia ' in command:
            return ('', '', 0)
        # Restore copy: docker cp /tmp/awg-plugin-backup-.../. <name>:/opt/...
        if command.startswith('docker cp /tmp/awg-plugin-backup'):
            return ('', '', 0)

        if command.startswith('docker exec') and 'grep -c' in command:
            state['peer_calls'] += 1
            return ((peers_before if state['peer_calls'] == 1 else peers_after), '', 0)

        if command.startswith('docker exec') and 'amneziawg-go --version' in command:
            return (exec_version_output or '', '', 0)

        if command.startswith('docker exec') and 'awg show' in command:
            return (('interface: awg0', '', 0) if tunnel_ok else ('', '', 1))

        if command.startswith('docker exec') and '*.conf' in command:
            return ('', '', 0)

        if command.startswith('docker build'):
            state['built'] = build_code == 0
            return ('', 'build failed' if build_code else '', build_code)

        if command.startswith('docker stop '):
            return ('', '', 0)
        if command.startswith('docker rename '):
            return ('', '', 0)
        if command.startswith(PROBE_PREFIX):
            return (probe_output or '', '', 0)
        if command.startswith('docker run '):
            return ('container-id', '', 0)
        if command.startswith('docker network connect '):
            return ('', '', 0)
        if command.startswith('docker restart '):
            return ('', '', 0)
        if command.startswith('docker rm ') or command.startswith('docker rmi '):
            return ('', '', 0)
        return ('', '', 0)

    return handler


class VersionSourceTests(unittest.TestCase):
    def test_version_label_is_preferred_without_a_binary_probe(self):
        """A trusting label must short-circuit the expensive image probe."""
        ssh = FakeSSH(userspace_handler())
        result = AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(result['state'], 'updated')
        self.assertEqual(result['installed'], GO_NEW)
        self.assertFalse(
            [c for c in ssh.commands if c.startswith(PROBE_PREFIX)],
            'docker run probe ran even though the OCI version label answered',
        )

    def test_binary_probe_verifies_build_when_label_is_missing(self):
        """No OCI label: the binary inside the freshly built image decides."""
        ssh = FakeSSH(userspace_handler(
            post_build_label='',
            probe_output='amneziawg-go v3.1.20260828',
        ))
        result = AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(result['state'], 'updated')
        probes = [c for c in ssh.commands if c.startswith(PROBE_PREFIX)]
        self.assertEqual(len(probes), 1)
        self.assertIn('amneziawg-go --version', probes[0])

    def test_running_container_binary_is_preferred_then_label_then_tag(self):
        """Binary first, then the OCI label, and the image tag as last resort."""
        def handler_for(*, exec_output='', label_output='', ps_line=DOCKER_PS):
            def handler(command):
                if command.startswith('docker ps -a'):
                    return (ps_line, '', 0)
                if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
                    return ('FROM amneziavpn/amneziawg-go:latest', '', 0)
                if command.startswith('docker exec') and 'amneziawg-go --version' in command:
                    return (exec_output, '', 0)
                if 'Config.Labels' in command:
                    return (label_output, '', 0)
                return ('', '', 0)
            return handler

        with self.subTest('binary wins over the label'):
            ssh = FakeSSH(handler_for(
                exec_output=US_BINARY_OUTPUT, label_output=GO_NEW,
            ))
            self.assertEqual(
                AwgPluginUpdater(ssh).installed_versions()[USERSPACE], US_BINARY,
            )
            self.assertTrue(ssh.find('amneziawg-go --version'))
            self.assertFalse(
                [c for c in ssh.commands if 'Config.Labels' in c],
                'OCI label was queried even though the running binary answered',
            )

        with self.subTest('label used when the binary is silent'):
            ssh = FakeSSH(handler_for(exec_output='', label_output=GO_NEW))
            self.assertEqual(
                AwgPluginUpdater(ssh).installed_versions()[USERSPACE], GO_NEW,
            )
            self.assertLess(
                _index(ssh.commands, 'amneziawg-go --version'),
                _index(ssh.commands, 'Config.Labels'),
                'the label must only be asked after the binary stayed silent',
            )

        with self.subTest('image tag used when both are silent'):
            ssh = FakeSSH(handler_for(
                exec_output='',
                label_output='',
                ps_line='amnezia-awg3\tamneziavpn/amneziawg-go:%s' % OLD,
            ))
            self.assertEqual(
                AwgPluginUpdater(ssh).installed_versions()[USERSPACE], OLD,
            )


class RecreateTests(unittest.TestCase):
    def test_dns_network_is_reconnected_before_the_config_restore(self):
        ssh = FakeSSH(userspace_handler(
            inspect_options={'amnezia-awg3': {'networks': {'amnezia-dns-net': {}}}},
        ))
        result = AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(result['state'], 'updated')
        run = _index(ssh.commands, 'docker run -d')
        connect = _index(ssh.commands, 'docker network connect amnezia-dns-net amnezia-awg3')
        restore = _index(ssh.commands, '. amnezia-awg3:/opt/amnezia/')
        self.assertLess(run, connect)
        self.assertLess(connect, restore)

    def test_run_command_keeps_the_udp_protocol(self):
        host = container_inspect()['HostConfig']
        command = AwgPluginUpdater._docker_run_from_inspect('amnezia-awg3', host)
        self.assertIn('-p 55424:55424/udp', command)


class CleanupTests(unittest.TestCase):
    def test_success_cleans_up_build_and_backup_artefacts(self):
        ssh = FakeSSH(userspace_handler())
        result = AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(result['state'], 'updated')
        self.assertEqual(len(ssh.find(CLEANUP)), 1)
        cleanup = _index(ssh.commands, CLEANUP)
        # Only after the new container has been verified and the old removed.
        self.assertGreater(cleanup, _index(ssh.commands, 'docker restart amnezia-awg3'))
        self.assertGreater(cleanup, _index(ssh.commands, 'docker rm -f amnezia-awg3.old-'))
        # Nothing destructive remains after the cleanup.  Re-reading the
        # installed version is allowed: it only runs read-only probes
        # (docker ps/inspect/exec and the Dockerfile head that detects the
        # amneziawg-go containers).
        for command in ssh.commands[cleanup + 1:]:
            self.assertTrue(
                command.startswith((
                    'docker ps', 'docker inspect', 'docker exec',
                    'head -1 /opt/amnezia/',
                )),
                'unexpected command after cleanup: %r' % command,
            )

    def test_rollback_still_cleans_up(self):
        ssh = FakeSSH(userspace_handler(peers_before='5', peers_after='0'))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(ctx.exception.code, 'update_failed')
        self.assertTrue(ssh.find('docker rm -f amnezia-awg3'))
        self.assertTrue([c for c in ssh.commands
                         if c.startswith('docker rename amnezia-awg3.old-')
                         and c.endswith(' amnezia-awg3')])
        self.assertTrue(ssh.find('docker start amnezia-awg3'))

        self.assertEqual(len(ssh.find(CLEANUP)), 1)
        self.assertGreater(
            _index(ssh.commands, CLEANUP),
            _index(ssh.commands, 'docker start amnezia-awg3'),
        )


class _RollbackFailedUpdater(AwgPluginUpdater):
    """Raises the code the cleanup guard keys on.

    The userspace path only reports ``rollback_failed`` when a restore command
    actually fails; this subclass exercises the real ``except`` branch in
    ``_update_userspace`` that decides whether artefacts are kept.
    """

    def _apply_container_update(self, item, version, log, should_cancel=None):
        item['switched'] = True
        item['old_name'] = 'amnezia-awg3.old-test'
        raise PluginUpdateError('update_failed', 'simulated switch failure')

    def _rollback_containers(self, prepared, log):
        return ['amnezia-awg3']


class CleanupSkipTests(unittest.TestCase):
    def test_no_cleanup_when_rollback_failed_is_reported(self):
        ssh = FakeSSH(userspace_handler())
        with self.assertRaises(PluginUpdateError) as ctx:
            _RollbackFailedUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(ctx.exception.code, 'rollback_failed')
        # The backup exists, so the absence of cleanup is a real decision.
        self.assertTrue(ssh.find('docker cp amnezia-awg3:/opt/amnezia'))
        self.assertFalse([c for c in ssh.commands if CLEANUP in c])


class CancelTests(unittest.TestCase):
    def test_cancel_between_containers_changes_nothing(self):
        ssh = FakeSSH(userspace_handler(containers=['amnezia-awg3', 'amnezia-awg2']))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(
                USERSPACE, GO_NEW, allow_interrupt=True,
                should_cancel=lambda: True,
            )

        self.assertEqual(ctx.exception.code, 'cancelled')
        self.assertFalse(ssh.find('docker stop'))
        self.assertFalse(ssh.find('docker build'))
        # Both containers were inspected and backed up before the cancel check.
        self.assertTrue(ssh.find('docker cp amnezia-awg3:/opt/amnezia'))
        self.assertTrue(ssh.find('docker cp amnezia-awg2:/opt/amnezia'))


class UnsupportedShapeTests(unittest.TestCase):
    def test_host_network_container_fails_closed(self):
        ssh = FakeSSH(userspace_handler(
            inspect_options={'amnezia-awg3': {'shape': 'bad'}},
        ))
        with self.assertRaises(PluginUpdateError) as ctx:
            AwgPluginUpdater(ssh).update(USERSPACE, GO_NEW, allow_interrupt=True)

        self.assertEqual(ctx.exception.code, 'unsupported')
        self.assertIn('network mode host', ctx.exception.message)
        self.assertFalse(ssh.find('docker build'))
        self.assertFalse(ssh.find('docker stop'))


if __name__ == '__main__':
    unittest.main()
