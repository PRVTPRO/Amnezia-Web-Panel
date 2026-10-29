"""WireGuard toggle/remove must not persist state that did not land.

The WireGuard manager has its own toggle/remove implementation (AWGManager's
hardening does not apply here). These tests pin the two failure modes that
left peers half-toggled in production:

* `wg syncconf` returns non-zero, but the clientsTable was already updated;
* `docker cp` reports success while the container still has the old config;
* the config file is updated, but the live interface (`wg show`) never
  picked the change up — a verified file masking a stale kernel state.

In all cases the manager must raise and leave the clientsTable untouched.
"""

import copy
import re
import unittest
from unittest import mock

from managers.wireguard_manager import WireGuardManager

CONFIG_PATH = WireGuardManager.CONFIG_PATH
CLIENTS_TABLE = WireGuardManager.CLIENTS_TABLE_PATH
PEER_A = 'PEER_A'
PEER_B = 'PEER_B'

SERVER_CONFIG = """[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.8.2.1/24
ListenPort = 51820

[Peer]
PublicKey = PEER_A
PresharedKey = PSK_A
AllowedIPs = 10.8.2.2/32

[Peer]
PublicKey = PEER_B
PresharedKey = PSK_B
AllowedIPs = 10.8.2.3/32
"""

CLIENTS = [
    {'clientId': PEER_A, 'userData': {'clientIp': '10.8.2.2', 'psk': 'PSK_A', 'enabled': True}},
    {'clientId': PEER_B, 'userData': {'clientIp': '10.8.2.3', 'psk': 'PSK_B', 'enabled': True}},
]


class FakeSSH:
    """In-memory stand-in for the container's wg0.conf.

    `skip_copy` models `docker cp` exiting 0 without changing the file.
    `fail_sync` models `wg syncconf` rejecting the new config.
    """

    def __init__(self, config, skip_copy=False, fail_sync=False):
        self.files = {CONFIG_PATH: config}
        self.uploads = {}
        self.skip_copy = skip_copy
        self.fail_sync = fail_sync
        self.fail_readback = False
        # When True, `wg show` keeps reporting the config as it was at init,
        # modelling a kernel interface that never picked up the new config.
        self.stale_iface = False
        self._config_at_init = config
        self.commands = []

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)

        m = re.search(r'docker cp (\S+) \S+?:(\S+)', command)
        if m:
            if not self.skip_copy:
                self.files[m.group(2)] = self.uploads[m.group(1)]
            return '', '', 0

        if 'syncconf' in command:
            return ('', 'boom', 1) if self.fail_sync else ('', '', 0)

        m = re.search(r'docker exec -i \S+ cat (\S+)', command)
        if m:
            if self.fail_readback:
                return '', 'read failed', 1
            if m.group(1) in self.files:
                return self.files[m.group(1)], '', 0
            return '', 'No such file or directory', 1

        if re.search(r'docker exec -i \S+ wg show \S+', command):
            if self.stale_iface:
                return self._config_at_init, '', 0
            return self.files.get(CONFIG_PATH, ''), '', 0

        return '', '', 0


class WireGuardToggleVerificationTests(unittest.TestCase):
    def make_manager(self, **ssh_kwargs):
        ssh = FakeSSH(SERVER_CONFIG, **ssh_kwargs)
        manager = WireGuardManager(ssh)
        saved = []
        manager._get_clients_table = lambda: copy.deepcopy(CLIENTS)
        manager._save_clients_table = lambda table: saved.append(table)
        return manager, ssh, saved

    def test_failed_syncconf_aborts_disable(self):
        manager, _ssh, saved = self.make_manager(fail_sync=True)

        with self.assertRaises(RuntimeError):
            manager.toggle_client(PEER_B, False)

        self.assertEqual(saved, [], 'clientsTable must not be written after a failed syncconf')

    def test_silent_config_copy_failure_aborts_disable(self):
        manager, ssh, saved = self.make_manager(skip_copy=True)

        with mock.patch('managers.wireguard_manager.time.sleep', return_value=None):
            with self.assertRaises(RuntimeError):
                manager.toggle_client(PEER_B, False)

        self.assertEqual(saved, [], 'clientsTable must not mark a still-present peer as off')
        self.assertIn(PEER_B, ssh.files[CONFIG_PATH])

    def test_remove_aborts_when_peer_still_present(self):
        manager, ssh, saved = self.make_manager(skip_copy=True)

        with self.assertRaises(RuntimeError):
            manager.remove_client(PEER_B)

        self.assertEqual(saved, [], 'clientsTable must not drop a peer still in the config')
        self.assertIn(PEER_B, ssh.files[CONFIG_PATH])

    def test_remove_aborts_when_readback_fails(self):
        manager, _ssh, saved = self.make_manager()
        manager.ssh.fail_readback = True

        with self.assertRaises(RuntimeError):
            manager.remove_client(PEER_B)

        self.assertEqual(saved, [], 'clientsTable must not change when removal is unverifiable')

    def test_disable_aborts_when_interface_lags_config(self):
        """File removed the peer but the kernel still serves it: the table
        must NOT flip to enabled=false (Cr0Nos's file-vs-interface gap)."""
        manager, ssh, saved = self.make_manager()
        ssh.stale_iface = True

        with mock.patch('managers.wireguard_manager.time.sleep', return_value=None):
            with self.assertRaises(RuntimeError):
                manager.toggle_client(PEER_B, False)

        self.assertEqual(saved, [], 'clientsTable must not mark a peer the interface still serves as off')
        self.assertNotIn(PEER_B, ssh.files[CONFIG_PATH])

    def test_remove_aborts_when_interface_lags_config(self):
        """File removal landed, kernel still has the peer: dropping it from
        the table would orphan a live, unmanaged peer."""
        manager, ssh, saved = self.make_manager()
        ssh.stale_iface = True

        with mock.patch('managers.wireguard_manager.time.sleep', return_value=None):
            with self.assertRaises(RuntimeError):
                manager.remove_client(PEER_B)

        self.assertEqual(saved, [], 'clientsTable must not drop a peer the interface still serves')


if __name__ == '__main__':
    unittest.main()
