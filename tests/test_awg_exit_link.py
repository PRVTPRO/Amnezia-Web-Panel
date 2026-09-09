import os
import shutil
import subprocess
import tempfile
import unittest

from managers.awg_manager import (
    DNS_NET,
    EGRESS_CHECK_URLS,
    EXIT_CONF,
    EXIT_HANDSHAKE_UP_SECONDS,
    EXIT_KEY,
    ENTRY_PRIVATE_KEY_PLACEHOLDER,
    AWGManager,
)

LINK = {
    'exit_uid': 'abc123',
    'exit_name': 'Berlin-1',
    'transit_ip': '10.9.0.7',
    'subnet_cidr': '24',
    'exit_public_key': 'EXITPUB',
    'psk': 'PSK',
    'endpoint_host': '203.0.113.5',
    'endpoint_port': '55520',
    'obfuscation': False,
    'dns_via_exit': False,
    'awg_params': {},
}

OBFUSCATED_LINK = dict(LINK, obfuscation=True, awg_params={
    'junk_packet_count': '4', 'junk_packet_min_size': '8', 'junk_packet_max_size': '40',
    'init_packet_junk_size': '27', 'response_packet_junk_size': '19',
    'init_packet_magic_header': '1', 'response_packet_magic_header': '2',
    'underload_packet_magic_header': '3', 'transport_packet_magic_header': '4',
    'cookie_reply_packet_junk_size': '20', 'transport_packet_junk_size': '23',
})

WG_LISTS = """EXITPUB\t1700000000
---
EXITPUB\t1536\t4096
---
EXITPUB\t203.0.113.5:55520
"""


class RecordingSSH:
    def __init__(self):
        self.uploads = {}
        self.commands = []
        self.answers = {}   # substring -> (out, err, code)

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        for needle, answer in self.answers.items():
            if needle in command:
                return answer
        if 'for p in ' in command:
            return '/opt/amnezia/awg/awg0.conf\n', '', 0
        return '', '', 0


class ExitShellBlockTests(unittest.TestCase):
    def test_start_script_orders_killswitch_tunnel_link(self):
        script = AWGManager(None)._render_start_script('awg2')
        killswitch = script.index('[ -f "$EXIT_CONF" ] && x_killswitch_on')
        tunnel_up = script.index('awg-quick up /opt/amnezia/awg/awg0.conf')
        link_up = script.index('if [ -f "$EXIT_CONF" ]; then x_link_up')
        self.assertLess(killswitch, tunnel_up)
        self.assertLess(tunnel_up, link_up)
        self.assertLess(link_up, script.index('tail -f /dev/null'))
        self.assertIn(f'EXIT_CONF={EXIT_CONF}', script)
        self.assertIn(f'DNS_NET={DNS_NET}', script)
        self.assertIn('X_QUICK=awg-quick', script)

    def test_legacy_uses_wg_quick_for_the_link(self):
        script = AWGManager(None)._render_start_script('awg_legacy')
        self.assertIn('X_QUICK=wg-quick', script)
        self.assertIn('X_CONF=/opt/amnezia/awg/wg0.conf', script)

    def test_killswitch_and_link_invariants(self):
        block = AWGManager._exit_shell_functions('/opt/amnezia/awg/awg0.conf', 'awg-quick', '10.8.1.1/24')
        # blackhole first, catch-all rule last, exceptions in between
        on = block[block.index('x_killswitch_on()'):block.index('x_killswitch_off()')]
        self.assertLess(on.index('blackhole default'), on.index('x_rule -4 190'))
        self.assertLess(on.index('x_rule -4 191'), on.index('x_rule -4 $EXIT_PREF from $X_SUBNET lookup $EXIT_TABLE'))
        self.assertIn('unreachable default table $EXIT_TABLE', on)
        self.assertIn("grep -qs '^# DnsViaExit = on'", on)
        # link up verifies itself and never masquerades without the client subnet
        up = block[block.index('x_link_up()'):block.index('x_link_down()')]
        self.assertIn('return 3', up)
        self.assertIn('FATAL', up)
        self.assertIn('-s $X_SUBNET -o $EXIT_IF -j MASQUERADE', up)
        self.assertNotIn('conf.all.rp_filter', up)
        self.assertIn('conf.$EXIT_IF.rp_filter=2', up)
        self.assertIn('conntrack -D -s $X_SUBNET', up)
        self.assertEqual(up.count('TCPMSS --clamp-mss-to-pmtu'), 2)
        # teardown takes the interface down before touching the rules
        down = block[block.index('x_link_down()'):block.index('x_exit_sync()')]
        self.assertLess(down.index('ip link del $EXIT_IF'), down.index('x_ipt_del'))
        off = block[block.index('x_killswitch_off()'):block.index('x_link_up()')]
        self.assertIn('for p in 190 191 $EXIT_PREF; do x_unrule -4 $p; x_unrule -6 $p; done', off)
        self.assertIn('ip -4 route flush table $EXIT_TABLE', off)
        self.assertIn('ip -6 route flush table $EXIT_TABLE', off)

    @unittest.skipUnless(shutil.which('bash'), 'bash not available')
    def test_live_apply_scripts_parse_as_bash(self):
        functions = AWGManager._exit_shell_functions('/opt/amnezia/awg/awg0.conf', 'awg-quick', '10.8.1.1/24')
        for tail in ('x_exit_sync\n', 'x_link_down\nx_killswitch_off\nrm -f "$EXIT_CONF"\n'):
            with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
                f.write(functions + tail)
            try:
                result = subprocess.run(['bash', '-n', f.name], capture_output=True, text=True)
            finally:
                os.unlink(f.name)
            self.assertEqual(result.returncode, 0, result.stderr)


class ExitConfBodyTests(unittest.TestCase):
    def test_plain_link(self):
        conf = AWGManager._exit_conf_body(LINK)
        self.assertTrue(conf.startswith('[Interface]\n'))
        for line in ('# ExitUid = abc123', '# ExitName = Berlin-1', '# Obfuscation = off', '# DnsViaExit = off',
                     f'PrivateKey = {ENTRY_PRIVATE_KEY_PLACEHOLDER}', 'Address = 10.9.0.7/24', 'MTU = 1420',
                     'Table = off', 'PublicKey = EXITPUB', 'PresharedKey = PSK', 'AllowedIPs = 0.0.0.0/0',
                     'Endpoint = 203.0.113.5:55520', 'PersistentKeepalive = 25'):
            self.assertIn(line + '\n', conf)
        self.assertNotIn('Jc', conf)
        self.assertLess(conf.index('[Interface]'), conf.index('[Peer]'))

    def test_obfuscated_link_carries_handshake_keys_only(self):
        conf = AWGManager._exit_conf_body(OBFUSCATED_LINK)
        self.assertIn('# Obfuscation = on\n', conf)
        interface = conf.split('[Peer]')[0]
        for line in ('Jc = 4', 'Jmin = 8', 'Jmax = 40', 'S1 = 27', 'S2 = 19', 'H1 = 1', 'H2 = 2', 'H3 = 3', 'H4 = 4'):
            self.assertIn(line + '\n', interface)
        self.assertNotIn('S3 = ', conf)
        self.assertNotIn('S4 = ', conf)
        self.assertLess(interface.index('Table = off'), interface.index('Jc = 4'))

    def test_dns_via_exit_marker(self):
        self.assertIn('# DnsViaExit = on\n', AWGManager._exit_conf_body(dict(LINK, dns_via_exit=True)))


class ExitLinkMethodsTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = AWGManager(self.ssh)

    def test_prepare_keys_generates_once_and_returns_public_key(self):
        self.ssh.answers['pubkey <'] = ('ENTRYPUB\n', '', 0)
        self.assertEqual(self.manager.exit_prepare_keys('awg2'), 'ENTRYPUB')
        cmd = self.ssh.commands[-1]
        self.assertIn('docker exec -i amnezia-awg2', cmd)
        self.assertIn(f'[ -s {EXIT_KEY} ] || awg genkey > {EXIT_KEY}', cmd)
        self.assertIn('umask 077', cmd)

    def test_prepare_keys_raises_on_failure(self):
        self.ssh.answers['pubkey <'] = ('', 'boom', 1)
        with self.assertRaises(RuntimeError):
            self.manager.exit_prepare_keys('awg2')

    def test_link_writes_conf_refreshes_start_script_and_applies(self):
        self.ssh.answers['_amnz_exit.sh'] = ('exit link up: 10.9.0.7/24 -> table 200', '', 0)

        out = self.manager.exit_link('awg2', LINK)

        self.assertEqual(out, 'exit link up: 10.9.0.7/24 -> table 200')
        self.assertEqual(self.ssh.uploads['/tmp/_amnz_exit0.conf'], AWGManager._exit_conf_body(LINK))
        # every docker step is its own sudo call (sudo only covers the first
        # command of a `&&` chain) and none of them chains another docker call
        steps = [c for c in self.ssh.commands if 'amnezia-awg2' in c and '_amnz_exit0.conf' in c or 'exit_private.key' in c]
        self.assertTrue(any(c == f'docker cp /tmp/_amnz_exit0.conf amnezia-awg2:{EXIT_CONF}' for c in steps))
        substitute = next(c for c in steps if 'sed -i' in c)
        self.assertIn(f'sed -i "s|{ENTRY_PRIVATE_KEY_PLACEHOLDER}|$k|" {EXIT_CONF}', substitute)
        self.assertIn(f'chmod 600 {EXIT_CONF}', substitute)
        for c in self.ssh.commands:
            self.assertFalse(c.count('docker ') > 1 and '&&' in c, f'chained docker calls under one sudo: {c}')
        # start.sh refreshed for the resolved path, without a restart
        self.assertEqual(self.ssh.uploads['/tmp/_amnz_start.sh'],
                         self.manager._render_start_script('awg2', '/opt/amnezia/awg/awg0.conf'))
        self.assertFalse(any(c.startswith('docker restart') for c in self.ssh.commands))
        # live apply runs the sync entry point with the same functions
        apply_script = self.ssh.uploads['/tmp/_amnz_exit.sh']
        self.assertTrue(apply_script.endswith('x_exit_sync\n'))
        self.assertIn('x_killswitch_on()', apply_script)
        self.assertIn('docker cp /tmp/_amnz_exit.sh amnezia-awg2:/tmp/_amnz_exit.sh', self.ssh.commands)
        self.assertIn('docker exec amnezia-awg2 bash /tmp/_amnz_exit.sh', self.ssh.commands)

    def test_link_raises_when_apply_fails(self):
        self.ssh.answers['_amnz_exit.sh'] = ('! FATAL: policy routing for exit0 is not in place', '', 3)
        with self.assertRaises(RuntimeError) as ctx:
            self.manager.exit_link('awg2', LINK)
        self.assertIn('FATAL', str(ctx.exception))

    def test_unlink_tears_down_and_removes_the_file(self):
        self.manager.exit_unlink('awg2')
        apply_script = self.ssh.uploads['/tmp/_amnz_exit.sh']
        self.assertTrue(apply_script.endswith('x_link_down\nx_killswitch_off\nrm -f "$EXIT_CONF"\n'))
        self.assertNotIn('x_exit_sync\n', apply_script)

    def test_link_info_parses_metadata_only(self):
        self.ssh.answers['ExitUid|ExitName'] = (
            '# ExitUid = abc123\n# ExitName = Berlin-1\n# Obfuscation = on\n# DnsViaExit = off\n'
            'Address = 10.9.0.7/24\nEndpoint = 203.0.113.5:55520\n', '', 0)
        info = self.manager.exit_link_info('awg2')
        self.assertEqual(info, {'exit_uid': 'abc123', 'exit_name': 'Berlin-1', 'obfuscation': True,
                                'dns_via_exit': False, 'address': '10.9.0.7/24', 'endpoint': '203.0.113.5:55520'})
        self.assertNotIn('PrivateKey', self.ssh.commands[-1])

    def test_link_info_none_without_link(self):
        self.ssh.answers['ExitUid|ExitName'] = ('', '', 9)
        self.assertIsNone(self.manager.exit_link_info('awg2'))

    def test_parse_wg_peer_lists(self):
        peers = AWGManager._parse_wg_peer_lists(WG_LISTS + 'OTHER\t0\n')
        self.assertEqual(peers['EXITPUB'], {'latest_handshake': 1700000000, 'rx_bytes': 1536,
                                            'tx_bytes': 4096, 'endpoint': '203.0.113.5:55520'})
        self.assertEqual(AWGManager._parse_wg_peer_lists('NEVER\t0\n---\nNEVER\t0\t0\n---\nNEVER\t(none)\n')['NEVER'],
                         {'latest_handshake': 0, 'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''})

    def test_link_status_states(self):
        self.ssh.answers['latest-handshakes'] = (WG_LISTS, '', 0)
        fresh = self.manager.exit_link_status('awg2', now=1700000010)
        self.assertEqual(fresh, {'up': True, 'handshake_age': 10, 'rx_bytes': 1536, 'tx_bytes': 4096,
                                 'endpoint': '203.0.113.5:55520'})
        self.assertNotIn(' dump', self.ssh.commands[-1])
        stale = self.manager.exit_link_status('awg2', now=1700000000 + EXIT_HANDSHAKE_UP_SECONDS)
        self.assertFalse(stale['up'])
        self.assertEqual(stale['handshake_age'], EXIT_HANDSHAKE_UP_SECONDS)

        self.ssh.answers['latest-handshakes'] = ('NEVER\t0\n---\nNEVER\t0\t0\n---\nNEVER\t(none)\n', '', 0)
        never = self.manager.exit_link_status('awg2', now=1700000000)
        self.assertEqual(never['handshake_age'], None)
        self.assertFalse(never['up'])

        self.ssh.answers['latest-handshakes'] = ('', '', 9)
        self.assertIsNone(self.manager.exit_link_status('awg2'))

        self.ssh.answers['latest-handshakes'] = ('', 'Unable to access interface: No such device', 1)
        broken = self.manager.exit_link_status('awg2')
        self.assertFalse(broken['up'])
        self.assertIn('No such device', broken['error'])


class ExitEgressCheckTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = AWGManager(self.ssh)
        # the subnet IP comes from the server config the probe binds to
        self.ssh.answers['cat /opt/amnezia/awg/awg0.conf'] = (
            '[Interface]\nAddress = 172.16.21.1/24\nListenPort = 55424\n', '', 0)

    def test_probe_script_is_posix_sh_and_quote_free(self):
        script = AWGManager._egress_probe_script('10.8.1.1')
        # it is single-quoted into `docker exec sh -c '...'`
        self.assertNotIn("'", script)
        self.assertIn('--interface 10.8.1.1', script)
        for url in EGRESS_CHECK_URLS:
            self.assertIn(url, script)
        if shutil.which('sh'):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, 'probe.sh')
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(script + '\n')
                self.assertEqual(subprocess.run(['sh', '-n', path]).returncode, 0)

    def test_check_egress_splits_the_two_probes(self):
        self.ssh.answers['echo ---'] = ('203.0.113.5\n---\n198.51.100.1\n', '', 0)
        self.assertEqual(self.manager.exit_check_egress('awg2'),
                         {'via_exit': '203.0.113.5', 'direct': '198.51.100.1'})
        cmd = next(c for c in self.ssh.commands if 'echo ---' in c)
        self.assertIn('docker exec -i amnezia-awg2', cmd)
        # bound to the gateway of this instance, not to the default subnet
        self.assertIn('--interface 172.16.21.1', cmd)

    def test_check_egress_tolerates_empty_and_garbage_answers(self):
        self.ssh.answers['echo ---'] = ('\n---\n<html>error</html>\n', '', 0)
        self.assertEqual(self.manager.exit_check_egress('awg2'), {'via_exit': '', 'direct': ''})

    def test_check_egress_raises_when_the_container_is_gone(self):
        self.ssh.answers['echo ---'] = ('', 'No such container: amnezia-awg2', 1)
        with self.assertRaises(RuntimeError) as ctx:
            self.manager.exit_check_egress('awg2')
        self.assertIn('No such container', str(ctx.exception))
class ExitDnsViaExitTests(unittest.TestCase):
    def setUp(self):
        self.ssh = RecordingSSH()
        self.manager = AWGManager(self.ssh)

    def test_toggle_rewrites_the_marker_and_reapplies(self):
        self.ssh.answers['_amnz_exit.sh'] = ('exit link up: 10.9.0.7/24 -> table 200', '', 0)
        out = self.manager.exit_set_dns_via_exit('awg2', True)
        self.assertEqual(out, 'exit link up: 10.9.0.7/24 -> table 200')
        sed = next(c for c in self.ssh.commands if 'DnsViaExit' in c)
        self.assertIn(f'sed -i "s|^# DnsViaExit = .*|# DnsViaExit = on|" {EXIT_CONF}', sed)
        self.assertIn(f'test -f {EXIT_CONF} || exit 9', sed)
        # the same block that runs at container start puts the rules back
        self.assertTrue(self.ssh.uploads['/tmp/_amnz_exit.sh'].endswith('x_exit_sync\n'))

        self.manager.exit_set_dns_via_exit('awg2', False)
        self.assertIn('# DnsViaExit = off|', [c for c in self.ssh.commands if 'DnsViaExit' in c][-1])

    def test_toggle_without_a_link_file_raises(self):
        self.ssh.answers['DnsViaExit'] = ('', '', 9)
        with self.assertRaises(RuntimeError) as ctx:
            self.manager.exit_set_dns_via_exit('awg2', True)
        self.assertIn('no exit link file', str(ctx.exception))

    def test_dns_exception_rule_follows_the_marker(self):
        block = AWGManager._exit_shell_functions('/opt/amnezia/awg/awg0.conf', 'awg-quick', '10.8.1.1/24')
        # on -> the DNS exception is removed, off -> it is (re)installed
        self.assertIn("if grep -qs '^# DnsViaExit = on' \"$EXIT_CONF\"; then x_unrule -4 191", block)
        self.assertIn('x_rule -4 191 from $X_SUBNET to $DNS_NET lookup main', block)

    def test_awg_settings_report_the_link_ceiling(self):
        self.ssh.answers['ExitUid|ExitName'] = (
            '# ExitUid = abc123\n# ExitName = Berlin-1\n# Obfuscation = off\n# DnsViaExit = on\n'
            'Address = 10.9.0.7/24\nEndpoint = 203.0.113.5:55520\n', '', 0)
        self.ssh.answers['cat /opt/amnezia/awg/awg0.conf'] = (
            '[Interface]\nAddress = 10.8.1.1/24\n# MTU = 1376\n', '', 0)
        settings = self.manager.get_awg_settings('awg2')
        self.assertTrue(settings['exit_linked'])
        self.assertEqual(settings['exit_mtu'], 1420)

        self.ssh.answers['ExitUid|ExitName'] = ('', '', 9)
        self.assertFalse(self.manager.get_awg_settings('awg2')['exit_linked'])


if __name__ == '__main__':
    unittest.main()
