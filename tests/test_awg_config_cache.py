import json
import re
import unittest

from managers.awg_manager import AWGManager


CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'
CLIENTS_TABLE = '/opt/amnezia/awg/clientsTable'

SERVER_CONFIG = """[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.8.1.1/24
ListenPort = 55424
Jc = 3
Jmin = 10
Jmax = 30
S1 = 15
S2 = 18
H1 = 1020325451
H2 = 3288052141
H3 = 1770004689
H4 = 2528465083

[Peer]
PublicKey = PEER_A
PresharedKey = PSK_A
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = PEER_B
PresharedKey = PSK_B
AllowedIPs = 10.8.1.3/32
"""


class FakeSSH:
    """Minimal stand-in for SSHManager that keeps the container's files in
    memory, so a config written by one manager call is what the next call
    reads back - exactly what the real docker cp / cat round-trip does."""

    def __init__(self, files):
        self.files = dict(files)
        self.uploads = {}
        self.commands = []

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)

        m = re.search(r"docker cp (\S+) \S+?:(\S+)", command)
        if m:
            self.files[m.group(2)] = self.uploads[m.group(1)]
            return '', '', 0

        m = re.search(r"for p in (.+?); do", command)
        if m:  # _resolve_config_path probe
            for path in m.group(1).split():
                if path in self.files:
                    return path + '\n', '', 0
            return '', '', 1

        m = re.search(r"echo \"(.*)\" >> (\S+)'$", command, re.S)
        if m:  # toggle_client enable path appends the peer in place
            self.files[m.group(2)] = self.files.get(m.group(2), '') + m.group(1)
            return '', '', 0

        m = re.search(r"docker exec -i \S+ cp (\S+) (\S+)", command)
        if m:
            self.files[m.group(2)] = self.files[m.group(1)]
            return '', '', 0

        m = re.search(r"docker exec -i \S+ cat (\S+)", command)
        if m:
            if m.group(1) in self.files:
                return self.files[m.group(1)], '', 0
            return '', 'No such file or directory', 1

        return '', '', 0


def peer_block(pubkey, ip):
    return f"\n[Peer]\nPublicKey = {pubkey}\nPresharedKey = PSK_X\nAllowedIPs = {ip}/32\n\n"


class ServerConfigCacheTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH({CONFIG_PATH: SERVER_CONFIG})
        self.manager = AWGManager(self.ssh)

    def test_next_ip_advances_after_peer_insert_on_same_manager(self):
        first = self.manager._get_next_ip('awg')
        self.assertEqual(first, '10.8.1.4')

        self.manager._insert_peer_sorted('awg', peer_block('PEER_C', first))

        # Same manager instance, well inside _CACHE_TTL: the allocator must see
        # the peer it just wrote, not the cached pre-insert config.
        self.assertEqual(self.manager._get_next_ip('awg'), '10.8.1.5')

    def test_remove_client_is_visible_to_next_read(self):
        self.manager._get_server_config('awg')  # warm the cache
        self.manager.remove_client('awg', 'PEER_B')

        config = self.manager._get_server_config('awg')
        self.assertNotIn('PEER_B', config)
        self.assertIn('PEER_A', config)

    def test_remove_then_reinsert_does_not_resurrect_old_peer(self):
        # The exit-node upsert: drop a peer and re-add it with a new key but
        # the same address, all through one manager instance.
        self.manager._get_server_config('awg')
        self.manager.remove_client('awg', 'PEER_B')
        self.manager._insert_peer_sorted('awg', peer_block('PEER_B2', '10.8.1.3'))

        config = self.ssh.files[CONFIG_PATH]
        self.assertNotIn('PEER_B\n', config)
        self.assertEqual(config.count('AllowedIPs = 10.8.1.3/32'), 1)
        self.assertEqual(config.count('[Peer]'), 2)

    def test_toggle_client_refreshes_cache_in_both_directions(self):
        self.ssh.files[CLIENTS_TABLE] = json.dumps([{
            'clientId': 'PEER_B',
            'userData': {'clientName': 'b', 'clientIp': '10.8.1.3', 'psk': 'PSK_B', 'enabled': True},
        }])
        self.manager._get_server_config('awg')

        self.manager.toggle_client('awg', 'PEER_B', False)
        self.assertNotIn('PEER_B', self.manager._get_server_config('awg'))

        self.manager.toggle_client('awg', 'PEER_B', True)
        self.assertIn('PEER_B', self.manager._get_server_config('awg'))

    def test_write_server_config_refreshes_cache(self):
        self.manager._get_server_config('awg')
        new_config = SERVER_CONFIG.replace('Jc = 3', 'Jc = 7')

        self.manager._write_server_config('awg', new_config)

        self.assertIn('Jc = 7', self.manager._get_server_config('awg'))


if __name__ == '__main__':
    unittest.main()
