"""Regression guards for the two exit-link losses after a kernel rollout.

1. ``AWGManager._sync_server_config()`` ran ``awg syncconf <iface>`` without
   checking that the interface still exists. A kernel-module reload (DKMS
   update) removes every amneziawg interface while the container keeps
   running, so the sync died with "No such device" and every entry node lost
   its exit handshake. The container command now fixes the config mode (600),
   re-creates the interface from the on-disk config when it is missing, and
   only then applies the config.

2. ``ExitManager._configure_exit_container()`` rewrote ``transit0.conf`` with
   the ``[Interface]`` section only. The ``[Peer]`` sections live nowhere else
   (``peersTable`` has no PSKs), so a reinstall or a settings change silently
   dropped every entry node: the exit kept listening, the entries kept sending,
   and no handshake ever completed. The rewrite now carries the existing
   ``[Peer]`` sections over.

Both checks are offline: the SSH managers are local recorders.
"""
import ipaddress
import re
import unittest

from managers.awg_manager import AWGManager
from managers.exit_manager import ExitManager


class RecordingSSH:
    """Minimal SSH double: records sudo commands, never touches the network."""

    def __init__(self):
        self.commands = []

    def upload_file(self, content, remote_path):
        raise AssertionError('this operation must not upload files')

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        # _resolve_config_path asks the container which candidate exists; the
        # first candidate is the one this protocol expects.
        if 'for p in ' in command:
            candidates = command.split('for p in ', 1)[1].split(';', 1)[0]
            return candidates.split()[0] + '\n', '', 0
        return '', '', 0


class SyncServerConfigGuardTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = AWGManager(self.ssh)
        # Names come from the real helpers (no SSH involved).
        self.container = self.manager._container_name('awg3')
        self.config = self.manager._config_path('awg3')
        self.iface = self.manager._interface_name('awg3', self.config)
        self.quick = self.manager._quick_binary('awg3')
        self.wg = self.manager._wg_binary('awg3')

    def sync(self):
        self.manager._sync_server_config('awg3')
        return next(c for c in self.ssh.commands if 'syncconf' in c)

    def test_command_heals_a_missing_interface_before_syncing(self):
        cmd = self.sync()
        self.assertTrue(
            cmd.startswith('docker exec -i %s bash -c ' % self.container), cmd
        )
        self.assertIn('chmod 600 %s' % self.config, cmd)
        self.assertIn('ip link show %s' % self.iface, cmd)
        self.assertIn('%s up %s' % (self.quick, self.config), cmd)
        self.assertIn('%s syncconf %s' % (self.wg, self.iface), cmd)
        self.assertIn('%s strip %s' % (self.quick, self.config), cmd)
        # Order matters: perms, existence check, heal, then apply.
        self.assertLess(cmd.index('chmod 600'), cmd.index('ip link show'))
        self.assertLess(
            cmd.index('ip link show'), cmd.index('%s up ' % self.quick)
        )
        self.assertLess(cmd.index('%s up ' % self.quick), cmd.index('syncconf'))

    def test_guard_is_conditional_and_never_restarts_the_interface(self):
        cmd = self.sync()
        # Up only runs when `ip link show` fails: `cmd || cmd up`.
        guard = re.search(
            r'ip link show (\S+) >/dev/null 2>&1 \|\| (\S+) up (\S+);', cmd
        )
        self.assertIsNotNone(guard, 'missing conditional link guard in: %s' % cmd)
        self.assertEqual(guard.group(1), self.iface)
        self.assertEqual(guard.group(2), self.quick)
        self.assertEqual(guard.group(3), self.config)
        # Idempotence: one guarded bring-up, no unconditional re-create.
        self.assertEqual(cmd.count('%s up %s' % (self.quick, self.config)), 1)
        self.assertNotIn('%s down' % self.quick, cmd)
        self.assertNotIn('restart', cmd)
        self.assertFalse(
            any(c.startswith('docker restart') for c in self.ssh.commands),
            self.ssh.commands,
        )

    def test_legacy_instance_uses_wg_naming(self):
        self.manager._sync_server_config('awg_legacy')
        cmd = next(c for c in self.ssh.commands if 'syncconf' in c)
        legacy_config = self.manager._config_path('awg_legacy')
        self.assertIn('ip link show wg0', cmd)
        self.assertIn('wg-quick up %s' % legacy_config, cmd)
        self.assertIn('wg syncconf wg0', cmd)


class ExitPeerPreservationTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = ExitManager(self.ssh)
        self.config = self.manager.CONFIG_PATH
        self.manager._configure_exit_container(
            '55520', ipaddress.ip_network('10.9.0.0/24'), None
        )
        self.cmd = self.ssh.commands[-1]
        # Strip the `bash -c '` wrapper and the closing quote.
        self.script = self.cmd.split("bash -c '", 1)[1].rsplit("'", 1)[0]

    def test_existing_peer_sections_are_carried_over(self):
        self.assertIn('PEERS=$(', self.script)
        # Everything from the first [Peer] to the end of the old file.
        self.assertIn(
            'awk "/^\\[Peer\\]/{inside=1} inside" %s' % self.config,
            self.script,
        )

    def test_script_cannot_break_the_bash_c_wrapper(self):
        # The body runs inside `bash -c '...'`; one single quote would end the
        # argument early and turn the rest into separate host commands.
        self.assertNotIn("'", self.script)

    def test_peers_are_appended_after_the_new_interface_section(self):
        write = self.script.index('cat > %s <<EOF' % self.config)
        append = self.script.index('>> %s' % self.config)
        self.assertLess(write, append)
        self.assertIn('printf "%s\\n" "$PEERS"', self.script)

    def test_rewrite_is_atomic_enough_to_keep_the_link_alive(self):
        # set -e: never leave a half-written config behind on an awk failure.
        self.assertTrue(self.script.lstrip().startswith('set -e'))
        self.assertIn('[Interface]', self.script)
        # umask 077 keeps the config private (awg-quick warns on world access).
        self.assertIn('umask 077', self.script)

    def test_missing_previous_config_is_not_an_error(self):
        # Preservation is guarded: a fresh install has no file to read.
        self.assertIn('if [ -f %s ]; then' % self.config, self.script)
        self.assertIn('if [ -n "$PEERS" ]; then', self.script)


if __name__ == '__main__':
    unittest.main()
