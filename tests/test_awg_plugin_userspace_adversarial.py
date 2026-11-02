"""Adversarial multi-container ordering for the userspace update path.

The userspace update touches several containers that share one host.  The
safety invariant is about *when* destructive commands run, not only about
which commands run:

* replacing a container must not delete its predecessor while another
  container still has to be updated (``_apply_container_update`` only
  renames/stops, ``_finalize_container_update`` deletes);
* only after *every* container was replaced and verified may the old ones be
  removed;
* any failure restores every container that was already switched, in reverse
  order, and a failure to restore one must abort the cleanup of the on-host
  backups.

Every test drives the real updater through ``FakeSSH``; the only thing that is
patched is ``time.sleep`` so the tunnel retry loop does not slow the suite
down.  No network, no real SSH, no real Docker.
"""

import json
import unittest
from unittest import mock

from managers.awg_plugin_updater import (
    AwgPluginUpdater,
    PluginUpdateError,
    USERSPACE,
)
from tests.awg_plugin_fixtures import (
    FakeSSH,
    GO_NEW,
    OLD,
    inspect_json,
)

CLEANUP = 'rm -rf /tmp/awg-plugin-update /tmp/awg-plugin-backup-*'
PORTS = {'amnezia-awg3': 55424, 'amnezia-awg2': 55425}
CONTAINERS = ('amnezia-awg3', 'amnezia-awg2')


def _index(commands, needle, start=0):
    """First index of a command containing ``needle`` at or after ``start``."""
    for index in range(start, len(commands)):
        if needle in commands[index]:
            return index
    raise AssertionError('no command containing %r after index %d' % (needle, start))


def _indexes(commands, needle):
    return [index for index, command in enumerate(commands) if needle in command]


def _rename_backs(commands, name):
    """Rollback renames: ``docker rename <name>.old-... <name>``."""
    return [
        command for command in commands
        if command.startswith('docker rename %s.old-' % name)
        and command.endswith(' %s' % name)
    ]


def _inspect_payload(port, networks=None):
    """``docker inspect <name>`` output with a container-specific UDP port."""
    payload = json.loads(inspect_json(networks=networks))[0]
    payload['HostConfig']['PortBindings'] = {
        '%d/udp' % port: [{'HostPort': str(port)}],
    }
    return json.dumps([payload])


def userspace_handler(*, containers=CONTAINERS, ports=PORTS, networks=None,
                      tunnel_fail=(), old_missing=(), peers=5,
                      post_build_label=GO_NEW):
    """Scripted answers for a multi-container userspace update.

    ``tunnel_fail`` names containers whose ``awg show`` never reports an
    interface, ``old_missing`` names containers whose ``<name>.old-*``
    predecessor no longer exists, and ``networks`` maps a container to the
    extra Docker networks its inspect output reports.
    """
    containers = list(containers)
    ports = dict(ports)
    networks = networks or {}
    tunnel_fail = set(tunnel_fail)
    old_missing = tuple(old_missing)
    state = {'built': False}

    def handler(command):
        # Container inventory.
        if command.startswith('docker ps -a'):
            return (
                '\n'.join(
                    '%s\tamneziavpn/amneziawg-go:latest' % name
                    for name in containers
                ),
                '', 0,
            )

        # Version label of an image/container: OLD until a build happened.
        if 'Config.Labels' in command:
            for name in containers:
                if name in command:
                    return ((post_build_label if state['built'] else OLD), '', 0)
            return ('', '', 0)

        # Existence probe used by the rollback.  Must be answered before the
        # plain inspect branch, because the name contains a real container.
        if command.startswith('docker inspect ') and '.old-' in command:
            if any(name in command for name in old_missing):
                return ('', '', 0)
            return ('yes', '', 0)

        if command.startswith('docker inspect '):
            for name in containers:
                if command.startswith('docker inspect %s' % name):
                    return (
                        _inspect_payload(ports[name], networks.get(name)),
                        '', 0,
                    )
            return ('', '', 0)

        # _go_containers() identifies the panel's amneziawg-go images by the
        # FROM line of their generated Dockerfile.  Must be answered before the
        # plain `test -f ... Dockerfile` branch below.
        if command.startswith('head -1 /opt/amnezia/') and '/Dockerfile' in command:
            return ('FROM amneziavpn/amneziawg-go:latest', '', 0)

        # Panel-created containers have their Dockerfile next to the config.
        if 'test -f' in command and 'Dockerfile' in command:
            return ('yes', '', 0)

        # Backup: docker cp <name>:/opt/amnezia /tmp/awg-plugin-backup-...
        if command.startswith('docker cp ') and ':/opt/amnezia ' in command:
            return ('', '', 0)
        # Restore: docker cp /tmp/awg-plugin-backup-.../. <name>:/opt/...
        if command.startswith('docker cp /tmp/awg-plugin-backup'):
            return ('', '', 0)

        if command.startswith('docker exec') and 'grep -c' in command:
            return (str(peers), '', 0)

        if command.startswith('docker exec') and '*.conf' in command:
            return ('', '', 0)

        if command.startswith('docker exec') and 'awg show' in command:
            for name in containers:
                if name in command and name in tunnel_fail:
                    return ('', '', 1)
            return ('interface: awg0', '', 0)

        if command.startswith('docker build'):
            state['built'] = True
            return ('', '', 0)

        if command.startswith('docker stop '):
            return ('', '', 0)
        if command.startswith('docker rename '):
            return ('', '', 0)
        if command.startswith('docker run --rm '):
            return ('', '', 0)
        if command.startswith('docker run '):
            return ('new-container-id', '', 0)
        if command.startswith('docker network connect '):
            return ('', '', 0)
        if command.startswith('docker restart '):
            return ('', '', 0)
        if command.startswith('docker rm ') or command.startswith('docker rmi '):
            return ('', '', 0)
        return ('', '', 0)

    return handler


class _UserspaceAdversarialTest(unittest.TestCase):
    def setUp(self):
        # The tunnel retry loop sleeps between attempts.  Keep the suite fast
        # without weakening the retry logic itself.
        sleeper = mock.patch(
            'managers.awg_plugin_updater.time.sleep', lambda *_: None,
        )
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def update(self, ssh, **kwargs):
        return AwgPluginUpdater(ssh).update(
            USERSPACE, GO_NEW, allow_interrupt=True, **kwargs
        )


class SecondContainerFailureTests(_UserspaceAdversarialTest):
    def test_second_container_failure_restores_both_and_never_finalizes(self):
        """A late failure must undo the healthy first container as well."""
        ssh = FakeSSH(userspace_handler(tunnel_fail=('amnezia-awg2',)))
        with self.assertRaises(PluginUpdateError) as ctx:
            self.update(ssh)

        self.assertEqual(ctx.exception.code, 'update_failed')

        # The container that failed its tunnel check is restored.
        self.assertIn('docker rm -f amnezia-awg2', ssh.commands)
        self.assertTrue(_rename_backs(ssh.commands, 'amnezia-awg2'))
        self.assertIn('docker start amnezia-awg2', ssh.commands)

        # The first container was healthy, but it is still rolled back.
        self.assertIn('docker rm -f amnezia-awg3', ssh.commands)
        self.assertTrue(_rename_backs(ssh.commands, 'amnezia-awg3'))
        self.assertIn('docker start amnezia-awg3', ssh.commands)

        # Finalize deletes "<name>.old-...".  It must never run, otherwise the
        # predecessor needed by the rollback above would be gone.
        self.assertFalse([
            command for command in ssh.commands
            if command.startswith('docker rm -f amnezia-awg3.old-')
        ])
        self.assertFalse([
            command for command in ssh.commands
            if command.startswith('docker rmi ')
        ])


class AllSucceedTests(_UserspaceAdversarialTest):
    def test_old_containers_are_removed_only_after_every_verification(self):
        ssh = FakeSSH(userspace_handler())
        result = self.update(ssh)
        self.assertEqual(result['state'], 'updated')

        # The tunnel check of the second container is the last verification
        # before anything may be deleted.
        second_verify = max(
            index for index in _indexes(ssh.commands, 'awg show')
            if 'amnezia-awg2' in ssh.commands[index]
        )

        first_old = _index(ssh.commands, 'docker rm -f amnezia-awg3.old-')
        second_old = _index(ssh.commands, 'docker rm -f amnezia-awg2.old-')

        self.assertGreater(first_old, second_verify)
        self.assertGreater(second_old, second_verify)
        # The artefacts are only removed after both predecessors are gone.
        cleanup = _index(ssh.commands, CLEANUP)
        self.assertGreater(cleanup, first_old)
        self.assertGreater(cleanup, second_old)


class MissingOldContainerTests(_UserspaceAdversarialTest):
    def test_missing_old_container_reports_rollback_failed_and_keeps_backups(self):
        ssh = FakeSSH(userspace_handler(
            tunnel_fail=('amnezia-awg2',),
            old_missing=('amnezia-awg3',),
        ))
        with self.assertRaises(PluginUpdateError) as ctx:
            self.update(ssh)

        self.assertEqual(ctx.exception.code, 'rollback_failed')
        self.assertIn('amnezia-awg3', ctx.exception.message)
        self.assertTrue(ssh.find('docker inspect amnezia-awg3.old-'))
        # The other container could still be restored.
        self.assertTrue(_rename_backs(ssh.commands, 'amnezia-awg2'))
        self.assertIn('docker start amnezia-awg2', ssh.commands)
        # A failed rollback means the on-host backup must be kept for an
        # operator, so the /tmp cleanup must not run at all.
        self.assertFalse([
            command for command in ssh.commands if CLEANUP in command
        ])


class CancelTests(_UserspaceAdversarialTest):
    def test_cancel_after_build_leaves_the_container_untouched(self):
        ssh = FakeSSH(userspace_handler(
            containers=['amnezia-awg3'], ports=PORTS,
        ))

        def should_cancel():
            return any(command.startswith('docker build')
                       for command in ssh.commands)

        with self.assertRaises(PluginUpdateError) as ctx:
            self.update(ssh, should_cancel=should_cancel)

        self.assertEqual(ctx.exception.code, 'cancelled')
        # The image was built, but the service was never stopped or replaced.
        self.assertTrue([command for command in ssh.commands
                         if command.startswith('docker build')])
        self.assertFalse([command for command in ssh.commands
                          if command.startswith('docker stop')])
        self.assertFalse([command for command in ssh.commands
                          if command.startswith('docker rename')])
        self.assertFalse([command for command in ssh.commands
                          if command.startswith('docker run -d')])
        self.assertFalse([command for command in ssh.commands
                          if command.startswith('docker rm ')])

    def test_cancel_between_containers_restores_the_first_and_keeps_its_old(self):
        ssh = FakeSSH(userspace_handler())

        def should_cancel():
            # The first container is switched by the time it is restarted.
            return any(command.startswith('docker restart amnezia-awg3')
                       for command in ssh.commands)

        with self.assertRaises(PluginUpdateError) as ctx:
            self.update(ssh, should_cancel=should_cancel)

        self.assertEqual(ctx.exception.code, 'cancelled')
        # The already-switched container is put back.
        self.assertIn('docker rm -f amnezia-awg3', ssh.commands)
        self.assertTrue(_rename_backs(ssh.commands, 'amnezia-awg3'))
        self.assertIn('docker start amnezia-awg3', ssh.commands)
        # The second container was never touched.
        self.assertFalse([command for command in ssh.commands
                          if command.startswith('docker stop amnezia-awg2')])
        # And the predecessor of the first was not finalized.
        self.assertFalse([
            command for command in ssh.commands
            if command.startswith('docker rm -f amnezia-awg3.old-')
        ])


class NetworkTests(_UserspaceAdversarialTest):
    def test_all_extra_networks_are_reconnected_before_the_config_restore(self):
        extra = {'amnezia-dns-net': {}, 'another-net': {}}
        ssh = FakeSSH(userspace_handler(
            networks={name: dict(extra) for name in CONTAINERS},
        ))
        result = self.update(ssh)
        self.assertEqual(result['state'], 'updated')

        for name in CONTAINERS:
            run = _index(ssh.commands, '--name %s' % name)
            restore = _index(ssh.commands, '. %s:/opt/amnezia/' % name)
            dns = _index(
                ssh.commands, 'docker network connect amnezia-dns-net %s' % name,
            )
            other = _index(
                ssh.commands, 'docker network connect another-net %s' % name,
            )
            self.assertLess(run, dns)
            self.assertLess(run, other)
            self.assertLess(dns, restore)
            self.assertLess(other, restore)


class PortTests(_UserspaceAdversarialTest):
    def test_run_commands_keep_udp_and_per_container_host_ports(self):
        ssh = FakeSSH(userspace_handler())
        result = self.update(ssh)
        self.assertEqual(result['state'], 'updated')

        runs = {}
        for command in ssh.commands:
            if not command.startswith('docker run -d'):
                continue
            for name in CONTAINERS:
                if '--name %s' % name in command:
                    runs[name] = command

        self.assertEqual(set(runs), set(CONTAINERS))
        self.assertIn('-p 55424:55424/udp', runs['amnezia-awg3'])
        self.assertIn('-p 55425:55425/udp', runs['amnezia-awg2'])
        # A missing protocol suffix would silently produce TCP port bindings.
        self.assertNotIn(':55424/tcp', runs['amnezia-awg3'])
        self.assertNotIn(':55425/tcp', runs['amnezia-awg2'])


if __name__ == '__main__':
    unittest.main()
