"""DNAT publishing of custom public ports (docker-published instances).

The panel used to REDIRECT a custom public port to the instance listen port on
the host itself. That path ends up in INPUT, where ufw drops it on docker
hosts. The fix forwards straight to the container with the destination taken
from Docker's own nat/DOCKER rule.
"""
import asyncio
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


DOCKER_V4 = ('-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p udp '
             '-m udp --dport 55424 -j DNAT --to-destination 172.17.0.2:55424')
DOCKER_V6 = ('-A DOCKER -d fd00::2/128 ! -i docker0 -o docker0 -p udp '
             '-m udp --dport 55424 -j DNAT --to-destination fd00::2:55424')
# Real ip6tables prints an IPv6 destination in brackets; the panel must pass
# that token through unchanged, because the bare form is rejected.
DOCKER_V6_BRACKETED = ('-A DOCKER ! -s fe80::/10 ! -i docker0 -p udp -m udp '
                       '--dport 55424 -j DNAT --to-destination [fd00:42::4]:55424')


def server_with(protocols):
    return {'name': 'Aeza', 'host': '198.51.100.1', 'ssh_port': 22,
            'username': 'root', 'password': 'x', 'private_key': '',
            'server_info': {}, 'uid': 'srv-uid', 'protocols': protocols}


class FakeDockerSSH:
    """Answers discovery (-S DOCKER) separately from forward commands."""

    def __init__(self, docker4='', docker6='', code4=0, code6=0):
        self.docker4, self.docker6 = docker4, docker6
        self.code4, self.code6 = code4, code6
        self.docker_queries = []
        self.forward_commands = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run_sudo_command(self, cmd, *args, **kwargs):
        if cmd.endswith('-S DOCKER'):
            self.docker_queries.append(cmd)
            if cmd.startswith('iptables '):
                return (self.docker4, '', self.code4)
            return (self.docker6, '', self.code6)
        self.forward_commands.append(cmd)
        return ('', '', 0)


class DockerDnatParseTests(unittest.TestCase):
    def test_match_returns_container_destination(self):
        self.assertEqual(panel._parse_docker_dnat(DOCKER_V4, '55424'),
                         '172.17.0.2:55424')

    def test_wrong_port_is_not_matched(self):
        self.assertIsNone(panel._parse_docker_dnat(DOCKER_V4, '55425'))
        self.assertIsNone(panel._parse_docker_dnat(DOCKER_V4, '5542'))
        self.assertIsNone(panel._parse_docker_dnat(DOCKER_V4, '155424'))

    def test_first_matching_rule_wins(self):
        output = DOCKER_V4 + '\n' + DOCKER_V4.replace('172.17.0.2', '172.17.0.9')
        self.assertEqual(panel._parse_docker_dnat(output, '55424'),
                         '172.17.0.2:55424')

    def test_empty_output_and_empty_port(self):
        self.assertIsNone(panel._parse_docker_dnat('', '55424'))
        self.assertIsNone(panel._parse_docker_dnat(None, '55424'))
        self.assertIsNone(panel._parse_docker_dnat(DOCKER_V4, ''))

    def test_ipv6_destination(self):
        self.assertEqual(panel._parse_docker_dnat(DOCKER_V6, '55424'),
                         'fd00::2:55424')

    def test_bracketed_ipv6_destination_is_passed_through(self):
        # ip6tables -S DOCKER prints [addr]:port, and only this form is valid
        self.assertEqual(panel._parse_docker_dnat(DOCKER_V6_BRACKETED, '55424'),
                         '[fd00:42::4]:55424')


class DockerDnatDiscoveryTests(unittest.TestCase):
    def test_both_families(self):
        ssh = FakeDockerSSH(DOCKER_V4, DOCKER_V6)
        self.assertEqual(panel._docker_dnat_destinations(ssh, '55424'),
                         {4: '172.17.0.2:55424', 6: 'fd00::2:55424'})
        self.assertEqual(ssh.docker_queries,
                         ['iptables -t nat -S DOCKER',
                          'ip6tables -t nat -S DOCKER'])

    def test_nonzero_code_means_no_destination(self):
        ssh = FakeDockerSSH(DOCKER_V4, DOCKER_V6, code6=1)
        self.assertEqual(panel._docker_dnat_destinations(ssh, '55424'),
                         {4: '172.17.0.2:55424', 6: None})

    def test_exception_is_swallowed_per_family(self):
        ssh = mock.Mock()
        ssh.run_sudo_command.side_effect = [RuntimeError('ssh crash'),
                                            (DOCKER_V6, '', 0)]
        self.assertEqual(panel._docker_dnat_destinations(ssh, '55424'),
                         {4: None, 6: 'fd00::2:55424'})


class DnatCommandBuilderTests(unittest.TestCase):
    def test_dnat_add_is_exactly_guarded(self):
        cmds, warning = panel.public_port_forward_commands(
            'awg2', '8443', '55424',
            container_dests={4: '172.17.0.2:55424', 6: 'fd00::2:55424'})
        self.assertEqual(warning, '')
        self.assertIn(
            "iptables -t nat -C PREROUTING -p udp --dport 8443 "
            "-j DNAT --to-destination '172.17.0.2:55424' 2>/dev/null "
            "|| iptables -t nat -I PREROUTING 1 -p udp --dport 8443 "
            "-j DNAT --to-destination '172.17.0.2:55424'", cmds)
        self.assertIn(
            "ip6tables -t nat -C PREROUTING -p udp --dport 8443 "
            "-j DNAT --to-destination 'fd00::2:55424' 2>/dev/null "
            "|| ip6tables -t nat -I PREROUTING 1 -p udp --dport 8443 "
            "-j DNAT --to-destination 'fd00::2:55424'", cmds)

    def test_missing_destination_falls_back_to_redirect(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '8443', '55424', container_dests={4: None, 6: None})
        self.assertTrue(all('-j REDIRECT --to-ports 55424' in c for c in cmds), cmds)
        self.assertTrue(all('-I PREROUTING 1' in c for c in cmds), cmds)

    def test_destination_is_quoted_against_shell_globbing(self):
        # The command runs through a remote shell. An unquoted [addr]:port is
        # a bracket expression there: a file named e.g. d:55425 in the home
        # directory would replace the container address silently.
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '8443', '55424',
            container_dests={4: '172.17.0.2:55424', 6: '[fd00:42::4]:55424'})
        for cmd in cmds:
            if 'DNAT' not in cmd:
                continue
            self.assertIn("--to-destination '", cmd, cmd)
            self.assertNotIn("--to-destination [", cmd, cmd)
            self.assertNotIn("--to-destination 1", cmd, cmd)

    def test_public_ip_scopes_the_family(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '8443', '55424', public_ip='203.0.113.9',
            container_dests={4: '172.17.0.2:55424', 6: 'fd00::2:55424'})
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('iptables '), cmds)
        self.assertIn('-d 203.0.113.9 --dport 8443', cmds[0])
        self.assertIn("-j DNAT --to-destination '172.17.0.2:55424'", cmds[0])

    def test_ipv6_public_ip_uses_ip6tables(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '8443', '55424', public_ip='[2001:db8::9]',
            container_dests={4: '172.17.0.2:55424', 6: 'fd00::2:55424'})
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('ip6tables '), cmds)
        self.assertIn('-d 2001:db8::9 --dport 8443', cmds[0])

    def test_bracketed_ipv6_add_rule_keeps_the_docker_form(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '8443', '55424',
            container_dests={4: None, 6: '[fd00:42::4]:55424'})
        v6 = [c for c in cmds if c.startswith('ip6tables ')]
        self.assertEqual(len(v6), 1, cmds)
        self.assertIn("-j DNAT --to-destination '[fd00:42::4]:55424'", v6[0])

    def test_tcp_for_xray(self):
        cmds, _ = panel.public_port_forward_commands(
            'xray', '8443', '443', container_dests={4: '172.17.0.2:443'})
        self.assertEqual(len(cmds), 2)  # v4 add + v6 REDIRECT fallback
        v4 = [c for c in cmds if c.startswith('iptables ')][0]
        self.assertIn('-p tcp', v4)
        self.assertIn("-j DNAT --to-destination '172.17.0.2:443'", v4)

    def test_clearing_removes_redirect_and_dnat(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '', '55424', '8443',
            container_dests={4: '172.17.0.2:55424', 6: None})
        v4 = [c for c in cmds if 'iptables -t nat -D' in c]
        self.assertEqual(len(v4), 2, cmds)  # REDIRECT removal + DNAT removal
        self.assertTrue(any('-j REDIRECT --to-ports 55424' in c for c in v4), v4)
        self.assertTrue(any("-j DNAT --to-destination '172.17.0.2:55424'" in c for c in v4), v4)
        self.assertTrue(all(c.startswith('for i in 1 2 3; do ') for c in cmds), cmds)
        self.assertTrue(all(c.endswith('2>/dev/null || break; done') for c in cmds), cmds)

    def test_clearing_without_destination_removes_only_redirect(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg2', '', '55424', '8443', container_dests={4: None, 6: None})
        self.assertTrue(all('-j REDIRECT' in c for c in cmds), cmds)
        self.assertFalse(any('DNAT' in c for c in cmds), cmds)

    def test_same_port_and_services_need_no_rule(self):
        self.assertIsNone(panel.public_port_forward_commands(
            'awg2', '55424', '55424', '55424')[0])
        self.assertIsNone(panel.public_port_forward_commands('dns', '8443', '53')[0])


class DnatApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [server_with({
                'awg2': {'installed': True, 'port': '55424', 'base_protocol': 'awg2'},
            })], 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        login = client.post('/api/auth/login',
                            json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)
        return client

    def test_saving_public_port_discovers_and_verifies_dnat(self):
        client = self.client()
        ssh = FakeDockerSSH(DOCKER_V4)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.post('/api/servers/0/protocol/public-endpoint',
                              json={'protocol': 'awg2', 'public_host': '203.0.113.9',
                                    'public_port': '8443'})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['warning'], '')
        self.assertEqual(ssh.docker_queries,
                         ['iptables -t nat -S DOCKER',
                          'ip6tables -t nat -S DOCKER'])
        add = [c for c in ssh.forward_commands if '--dport 8443' in c and 'DNAT' in c]
        self.assertTrue(add, ssh.forward_commands)
        self.assertIn("-j DNAT --to-destination '172.17.0.2:55424'", add[0])
        verify = [c for c in ssh.forward_commands if ' -C ' in c and 'DNAT' in c]
        self.assertTrue(verify, ssh.forward_commands)

    def test_missing_docker_rule_keeps_redirect(self):
        client = self.client()
        ssh = FakeDockerSSH()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.post('/api/servers/0/protocol/public-endpoint',
                              json={'protocol': 'awg2', 'public_host': '203.0.113.9',
                                    'public_port': '8443'})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertTrue(any('-j REDIRECT --to-ports 55424' in c
                            for c in ssh.forward_commands), ssh.forward_commands)


class DnatRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [server_with({
                'awg2': {'installed': True, 'port': '55424',
                         'public_host': '203.0.113.9', 'public_port': '8443'},
            })], 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self._delay = panel.RESTORE_FORWARD_DELAY
        panel.RESTORE_FORWARD_DELAY = 0

    def tearDown(self):
        panel.RESTORE_FORWARD_DELAY = self._delay
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_restore(self, ssh):
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            asyncio.run(panel.restore_public_port_forwards())

    def test_restore_discovers_and_adds_dnat(self):
        ssh = FakeDockerSSH(DOCKER_V4)
        self.run_restore(ssh)
        self.assertIn('iptables -t nat -S DOCKER', ssh.docker_queries)
        add = [c for c in ssh.forward_commands
               if '--dport 8443' in c and 'DNAT' in c and '-I PREROUTING 1' in c]
        self.assertTrue(add, ssh.forward_commands)
        self.assertIn("-j DNAT --to-destination '172.17.0.2:55424'", add[0])

    def test_repeated_restore_uses_the_guarded_add_not_a_bare_insert(self):
        ssh = FakeDockerSSH(DOCKER_V4)
        self.run_restore(ssh)
        self.run_restore(ssh)
        adds = [c for c in ssh.forward_commands
                if '--dport 8443' in c and '-I PREROUTING 1' in c]
        self.assertEqual(len(adds), 2)  # one per round, each still -C guarded
        for cmd in adds:
            self.assertIn(' -C ', cmd)
            self.assertIn('2>/dev/null || ', cmd)
