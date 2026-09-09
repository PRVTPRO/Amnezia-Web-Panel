import json
import re
import unittest

import managers.awg_manager as awg_module
from managers.awg_manager import AWG_QUICK_FORCE_USERSPACE_PATCH, AWGManager
from managers.exit_manager import EXIT_DEFAULTS, ExitManager

CONF = ExitManager.CONFIG_PATH
TABLE = ExitManager.PEERS_TABLE
PUB = ExitManager.PUBLIC_KEY_PATH

TRANSIT_CONF = """[Interface]
# Managed by Amnezia Web Panel - exit node transit endpoint
# Subnet = 10.9.0.0/24
# Obfuscation = off
PrivateKey = EXITPRIVATEKEY
Address = 10.9.0.1/24
ListenPort = 55520
MTU = 1420

[Peer]
# peerId = uid-a:awg2
PublicKey = PEER_A
PresharedKey = PSK_A
AllowedIPs = 10.9.0.2/32

[Peer]
# peerId = uid-b:awg
PublicKey = PEER_B
PresharedKey = PSK_B
AllowedIPs = 10.9.0.4/32
"""

PEERS_TABLE = [
    {'clientId': 'PEER_A', 'userData': {'clientName': 'Paris / AmneziaWG 2.0', 'peerId': 'uid-a:awg2', 'clientIp': '10.9.0.2', 'creationDate': 't', 'enabled': True}},
    {'clientId': 'PEER_B', 'userData': {'clientName': 'Oslo / AmneziaWG', 'peerId': 'uid-b:awg', 'clientIp': '10.9.0.4', 'creationDate': 't', 'enabled': True}},
]

WG_SHOW = """interface: transit0
  public key: EXITPUB
  listening port: 55520

peer: PEER_A
  endpoint: 203.0.113.7:41234
  allowed ips: 10.9.0.2/32
  latest handshake: 12 seconds ago
  transfer: 1.50 MiB received, 3.00 MiB sent

peer: PEER_B
  allowed ips: 10.9.0.4/32
"""


class FakeSSH:
    """In-memory container filesystem plus canned docker/ip answers, so the
    real manager methods run end to end without a server."""

    def __init__(self, files=None, installed=False):
        self.files = dict(files or {})
        self.installed = installed
        self.uploads = {}
        self.sudo_uploads = {}
        self.commands = []

    def upload_file(self, content, path):
        self.uploads[path] = content

    def upload_file_sudo(self, content, path):
        self.sudo_uploads[path] = content

    def run_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if 'docker --version' in cmd:
            return 'Docker version 27.0', '', 0
        if 'systemctl is-active' in cmd:
            return 'active', '', 0
        return '', '', 0

    def run_sudo_script(self, script, timeout=120):
        return '', '', 0

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        m = re.search(r"docker cp (\S+) \S+?:(\S+)", cmd)
        if m:
            self.files[m.group(2)] = self.uploads[m.group(1)]
            return '', '', 0
        if 'docker ps -a' in cmd and 'amnezia-exit' in cmd:
            return ('amnezia-exit\n' if self.installed else ''), '', 0
        if cmd.startswith('docker ps') and 'amnezia-exit' in cmd:
            return ('Up 5 minutes' if self.installed else ''), '', 0
        if 'docker inspect --format' in cmd:
            return "'running'", '', 0
        if 'ip -6 route show default' in cmd or 'ip -6 addr show' in cmd:
            return '', '', 0
        if cmd.startswith('docker run'):
            self.installed = True
            return 'cid', '', 0
        if 'docker rm -fv' in cmd:
            self.installed = False
            return '', '', 0
        if 'cat > ' + CONF + ' <<EOF' in cmd:
            body = cmd.split('<<EOF\n', 1)[1].split('\nEOF', 1)[0]
            self.files[CONF] = body.replace('$(cat wireguard_server_private_key.key)', 'EXITPRIVATEKEY') + '\n'
            self.files[PUB] = 'EXITPUB\n'
            return '', '', 0
        if 'ip link show transit0' in cmd:
            return 'transit0: <POINTOPOINT> mtu 1420', '', 0
        if 'awg show all' in cmd:
            return WG_SHOW, '', 0
        if 'syncconf' in cmd:
            return '', '', 0
        m = re.search(r"docker exec -i \S+ cp (\S+) (\S+)", cmd)
        if m:
            self.files[m.group(2)] = self.files[m.group(1)]
            return '', '', 0
        m = re.search(r"docker exec -i \S+ cat (\S+)", cmd)
        if m:
            if m.group(1) in self.files:
                return self.files[m.group(1)], '', 0
            return '', 'No such file or directory', 1
        return '', '', 0


def installed_ssh():
    return FakeSSH({CONF: TRANSIT_CONF, TABLE: json.dumps(PEERS_TABLE), PUB: 'EXITPUB\n'}, installed=True)


class ExitInstallTests(unittest.TestCase):
    def setUp(self):
        self._sleep = awg_module.time.sleep
        awg_module.time.sleep = lambda seconds: None

    def tearDown(self):
        awg_module.time.sleep = self._sleep

    def test_install_plain_wireguard(self):
        ssh = FakeSSH()
        result = ExitManager(ssh).install_protocol('exit', port='55520')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['port'], '55520')
        self.assertEqual(result['subnet'], '10.9.0.0/24')
        self.assertEqual(result['public_key'], 'EXITPUB')
        self.assertFalse(result['obfuscation'])
        self.assertEqual(result['awg_params'], {})

        build = next(c for c in ssh.commands if c.startswith('docker build'))
        self.assertIn('-t amnezia-exit /opt/amnezia/amnezia-exit', build)
        run = next(c for c in ssh.commands if c.startswith('docker run'))
        self.assertIn('-p 55520:55520/udp', run)
        self.assertEqual(run.count('--name amnezia-exit'), 1)
        self.assertIn('docker network connect amnezia-dns-net amnezia-exit', ssh.commands)
        self.assertEqual(ssh.sudo_uploads['/opt/amnezia/amnezia-exit/Dockerfile'],
                         AWGManager._dockerfile_content(ExitManager.DOCKER_IMAGE, AWG_QUICK_FORCE_USERSPACE_PATCH))

        conf = ssh.files[CONF]
        self.assertIn('Address = 10.9.0.1/24', conf)
        self.assertIn('ListenPort = 55520', conf)
        self.assertIn('MTU = 1420', conf)
        self.assertIn('# Subnet = 10.9.0.0/24', conf)
        self.assertIn('# Obfuscation = off', conf)
        self.assertNotIn('Jc', conf)
        self.assertTrue(conf.startswith('[Interface]'), 'metadata must live inside [Interface]')
        self.assertIn('docker restart amnezia-exit', ssh.commands)
        self.assertTrue(any('ip link show transit0' in c for c in ssh.commands))

    def test_install_with_obfuscation_writes_handshake_keys_only(self):
        ssh = FakeSSH()
        result = ExitManager(ssh).install_protocol('exit', port='55520', obfuscation=True)

        conf = ssh.files[CONF]
        self.assertTrue(result['obfuscation'])
        for key in ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'):
            self.assertRegex(conf, rf'(?m)^{key} = \S+$')
        for key in ('S3', 'S4', 'I1'):
            self.assertNotRegex(conf, rf'(?m)^{key} = ')
        self.assertIn('# Obfuscation = on', conf)
        self.assertEqual(set(result['awg_params']), {'junk_packet_count', 'junk_packet_min_size', 'junk_packet_max_size', 'init_packet_junk_size', 'response_packet_junk_size', 'init_packet_magic_header', 'response_packet_magic_header', 'underload_packet_magic_header', 'transport_packet_magic_header'})

    def test_install_rejects_non_slash_24_subnet(self):
        ssh = FakeSSH()
        result = ExitManager(ssh).install_protocol('exit', subnet='10.9.0.0/23')
        self.assertEqual(result['status'], 'error')
        self.assertIn('/24', result['message'])
        self.assertFalse(any(c.startswith('docker') for c in ssh.commands))

    def test_install_uses_defaults_and_custom_subnet(self):
        ssh = FakeSSH()
        result = ExitManager(ssh).install_protocol('exit', port=None, subnet='10.77.5.0/24')
        self.assertEqual(result['port'], EXIT_DEFAULTS['port'])
        self.assertIn('Address = 10.77.5.1/24', ssh.files[CONF])
        self.assertIn('# Subnet = 10.77.5.0/24', ssh.files[CONF])

    def test_start_script_is_the_awg_script_with_exit_paths_and_mss_clamp(self):
        script = ExitManager(None)._render_start_script()
        self.assertIn('awg-quick up /opt/amnezia/exit/transit0.conf', script)
        self.assertIn('SUBNET=10.9.0.1/24', script)
        self.assertNotIn('awgprobe', script)
        self.assertEqual(script.count('TCPMSS --clamp-mss-to-pmtu'), 2)
        self.assertIn('-i transit0 -p tcp', script)
        self.assertIn('-o transit0 -p tcp', script)
        self.assertLess(script.index('TCPMSS'), script.index('tail -f /dev/null'))
        # the plain AWG script carries the entry-side block, not the exit clamp
        self.assertNotIn('transit0', AWGManager(None)._render_start_script('awg'))


class ExitPeerTests(unittest.TestCase):
    def setUp(self):
        self.ssh = installed_ssh()
        self.manager = ExitManager(self.ssh)

    def test_status_reports_peers_subnet_and_key(self):
        info = self.manager.get_server_status('exit')
        self.assertTrue(info['container_exists'])
        self.assertTrue(info['container_running'])
        self.assertEqual(info['port'], '55520')
        self.assertEqual(info['peers_count'], 2)
        self.assertNotIn('clients_count', info)
        self.assertEqual(info['subnet'], '10.9.0.0/24')
        self.assertFalse(info['obfuscation'])
        self.assertEqual(info['public_key'], 'EXITPUB')
        self.assertEqual(info['container_name'], 'amnezia-exit')
        self.assertEqual(info['base_protocol'], 'exit')

    def test_info_for_entry_nodes(self):
        info = self.manager.get_info()
        self.assertEqual(info, {'public_key': 'EXITPUB', 'port': '55520', 'subnet': '10.9.0.0/24',
                                'obfuscation': False, 'awg_params': {}})

    def test_list_peers_merges_table_live_data_and_external_blocks(self):
        self.ssh.files[CONF] += "\n[Peer]\nPublicKey = PEER_X\nAllowedIPs = 10.9.0.9/32\n"

        peers = {p['public_key']: p for p in self.manager.list_peers()}

        self.assertEqual(set(peers), {'PEER_A', 'PEER_B', 'PEER_X'})
        self.assertEqual(peers['PEER_A']['peer_id'], 'uid-a:awg2')
        self.assertEqual(peers['PEER_A']['transit_ip'], '10.9.0.2')
        self.assertEqual(peers['PEER_A']['latest_handshake'], '12 seconds ago')
        self.assertEqual(peers['PEER_A']['rx_bytes'], int(1.5 * 1024 * 1024))
        self.assertFalse(peers['PEER_A']['external'])
        self.assertEqual(peers['PEER_B']['latest_handshake'], '')
        self.assertTrue(peers['PEER_X']['external'])
        self.assertEqual(peers['PEER_X']['name'], 'External (10.9.0.9)')
        self.assertEqual(peers['PEER_X']['transit_ip'], '10.9.0.9')

    def test_add_peer_fills_the_first_free_address(self):
        peer = self.manager.add_peer('uid-c:awg3', 'Berlin / AmneziaWG 3.1', 'PEER_C')

        self.assertEqual(peer['transit_ip'], '10.9.0.3')
        self.assertEqual(peer['public_key'], 'EXITPUB')
        self.assertEqual(peer['port'], '55520')
        self.assertEqual(peer['subnet'], '10.9.0.0/24')
        self.assertTrue(peer['psk'])
        conf = self.ssh.files[CONF]
        block = conf.split('[Peer]')
        self.assertEqual(len(block) - 1, 3)
        self.assertIn('# peerId = uid-c:awg3\nPublicKey = PEER_C\nPresharedKey = ' + peer['psk'] + '\nAllowedIPs = 10.9.0.3/32', conf)
        # sorted by address: PEER_C (.3) sits between PEER_A (.2) and PEER_B (.4)
        self.assertLess(conf.index('PEER_A'), conf.index('PEER_C'))
        self.assertLess(conf.index('PEER_C'), conf.index('PEER_B'))
        table = json.loads(self.ssh.files[TABLE])
        self.assertEqual([e['clientId'] for e in table], ['PEER_A', 'PEER_B', 'PEER_C'])
        self.assertEqual(table[2]['userData']['peerId'], 'uid-c:awg3')
        self.assertEqual(table[2]['userData']['clientIp'], '10.9.0.3')
        self.assertTrue(any('syncconf transit0' in c for c in self.ssh.commands))

    def test_add_peer_upserts_by_peer_id_keeping_the_address(self):
        peer = self.manager.add_peer('uid-a:awg2', 'Paris / AmneziaWG 2.0', 'PEER_A_NEWKEY')

        self.assertEqual(peer['transit_ip'], '10.9.0.2')
        conf = self.ssh.files[CONF]
        self.assertNotIn('PEER_A\n', conf)
        self.assertEqual(conf.count('AllowedIPs = 10.9.0.2/32'), 1)
        self.assertEqual(conf.count('[Peer]'), 2)
        table = json.loads(self.ssh.files[TABLE])
        self.assertEqual(sorted(e['clientId'] for e in table), ['PEER_A_NEWKEY', 'PEER_B'])

    def test_add_peer_with_a_key_already_in_conf_replaces_that_block(self):
        self.ssh.files[CONF] += "\n[Peer]\nPublicKey = PEER_X\nAllowedIPs = 10.9.0.9/32\n"

        self.manager.add_peer('uid-x:awg', 'X', 'PEER_X')

        conf = self.ssh.files[CONF]
        self.assertEqual(conf.count('PublicKey = PEER_X'), 1)
        self.assertNotIn('10.9.0.9', conf)  # the stray block is gone, a panel-managed one replaced it

    def test_add_peer_validates_input(self):
        with self.assertRaises(ValueError):
            self.manager.add_peer('', 'x', 'PEER_C')
        with self.assertRaises(ValueError):
            self.manager.add_peer('uid-c:awg', 'x', '')

    def test_remove_peer_by_key_and_by_id(self):
        self.assertTrue(self.manager.remove_peer(public_key='PEER_A'))
        self.assertNotIn('PEER_A', self.ssh.files[CONF])
        self.assertEqual([e['clientId'] for e in json.loads(self.ssh.files[TABLE])], ['PEER_B'])

        self.assertTrue(self.manager.remove_peer(peer_id='uid-b:awg'))
        self.assertNotIn('[Peer]', self.ssh.files[CONF])
        self.assertEqual(json.loads(self.ssh.files[TABLE]), [])

        self.assertFalse(self.manager.remove_peer(peer_id='uid-b:awg'))
        self.assertFalse(self.manager.remove_peer(public_key='NOPE'))
        self.assertFalse(self.manager.remove_peer())

    def test_client_paths_are_closed(self):
        for method in ('add_client', 'get_client_config', 'toggle_client', 'rename_client', 'save_client_config', 'set_speed_limit'):
            with self.assertRaises(RuntimeError):
                getattr(self.manager, method)('exit', 'x')
        with self.assertRaises(RuntimeError):
            self.manager._get_server_psk()


if __name__ == '__main__':
    unittest.main()
