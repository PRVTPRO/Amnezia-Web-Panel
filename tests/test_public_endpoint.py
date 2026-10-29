"""Per-instance public address: the endpoint a client actually dials.

The panel handed out its own SSH address for every protocol on a server. A box
can publish an instance somewhere else -- a second IP, a port forward, a domain
name -- and the configs it issued were then unreachable; for telemt, which
prints its own tg:// links, they were wrong even when the tunnel worked. The
instance record now carries `public_host`/`public_port`, and these cover the
lookup, the API around it, and the places the address reaches a client.
"""

import json
import os
import re
import shutil
import socket
import tempfile
import unittest
import asyncio
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers.awg_manager import AWGManager
from managers.telemt_manager import TelemtManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager


def server_with(protocols):
    return {'name': 'Aeza', 'host': '198.51.100.1', 'ssh_port': 22, 'username': 'root',
            'password': 'x', 'private_key': '', 'server_info': {}, 'uid': 'srv-uid',
            'protocols': protocols}


class EndpointResolutionTests(unittest.TestCase):
    def test_without_an_override_the_panel_address_is_used(self):
        server = server_with({'awg2': {'port': '55424'}})
        self.assertEqual(panel.protocol_public_endpoint(server, 'awg2'), ('198.51.100.1', None))

    def test_public_host_replaces_the_panel_address(self):
        server = server_with({'telemt': {'port': '8443', 'public_host': '203.0.113.9'}})
        self.assertEqual(panel.protocol_public_endpoint(server, 'telemt'), ('203.0.113.9', None))

    def test_public_port_comes_back_for_the_managers(self):
        server = server_with({'telemt': {'port': '8443', 'public_host': '203.0.113.9',
                                         'public_port': '443'}})
        self.assertEqual(panel.protocol_public_endpoint(server, 'telemt'), ('203.0.113.9', '443'))

    def test_blank_and_missing_records_fall_back(self):
        server = server_with({'awg2': {'port': '55424', 'public_host': '   ', 'public_port': ''}})
        self.assertEqual(panel.protocol_public_endpoint(server, 'awg2'), ('198.51.100.1', None))
        # an instance the panel has no record of at all
        self.assertEqual(panel.protocol_public_endpoint(server, 'xray'), ('198.51.100.1', None))


class ValidationTests(unittest.TestCase):
    def test_addresses_and_names_pass(self):
        for value in ('198.51.100.1', 'vpn.example.com', '[2a01:e5c0:7bc2::2]', 'a-b_c.example'):
            self.assertEqual(panel.normalize_public_host(value), value)
        self.assertEqual(panel.normalize_public_host('  198.51.100.1  '), '198.51.100.1')
        self.assertEqual(panel.normalize_public_host(''), '')

    def test_anything_that_would_silently_break_a_config_is_rejected(self):
        for value in ('https://vpn.example.com', 'vpn.example.com/path', 'vpn example com',
                      'host&other', 'a' * 254,
                      # a bare IPv6 would read as host:port and never connect
                      '2a01:e5c0:7bc2::2'):
            with self.assertRaises(ValueError, msg=value):
                panel.normalize_public_host(value)

    def test_port_must_be_a_port(self):
        self.assertEqual(panel.normalize_public_port(' 443 '), '443')
        self.assertEqual(panel.normalize_public_port(''), '')
        for value in ('0', '65536', '-1', '44a3', 'http'):
            with self.assertRaises(ValueError, msg=value):
                panel.normalize_public_port(value)


class ClientConfigTests(unittest.TestCase):
    """Every manager that builds an endpoint must honour the override."""

    def wireguard(self):
        mgr = WireGuardManager(ssh_manager=mock.Mock())
        mgr._get_clients_table = lambda: [{'clientId': 'peer', 'userData': {
            'clientPrivateKey': 'priv', 'clientIp': '10.8.0.6', 'psk': 'psk'}}]
        mgr._get_server_public_key = lambda: 'serverpub'
        mgr._get_server_psk = lambda: 'serverpsk'
        mgr._get_listen_port = lambda: '51820'
        mgr._get_dns = lambda ud=None: '1.1.1.1'
        return mgr

    def awg(self):
        mgr = AWGManager(mock.Mock())
        mgr._get_clients_table = lambda proto: [{'clientId': 'peer', 'userData': {
            'clientPrivateKey': 'priv', 'clientIp': '10.8.1.6', 'psk': 'psk'}}]
        mgr._get_client_ipv6 = lambda proto, ip: ''
        mgr._get_server_public_key = lambda proto: 'serverpub'
        mgr._get_server_psk = lambda proto: 'serverpsk'
        mgr._get_awg_params_from_config = lambda proto: {}
        mgr._get_dns = lambda proto, ud: '1.1.1.1'
        mgr._get_mtu = lambda proto, ud: '1376'
        return mgr

    def xray(self):
        mgr = XrayManager(mock.Mock())
        mgr._get_clients_table = lambda: [{'clientId': 'uuid-1',
                                          'userData': {'clientName': 'laptop'}}]
        mgr._get_meta_json = lambda: {'port': 443, 'public_key': 'pbk', 'short_id': 'sid',
                                      'site_name': 'yahoo.com'}
        mgr._get_server_json = lambda: None
        return mgr

    def test_wireguard_endpoint_follows_the_public_port(self):
        config = self.wireguard().get_client_config('peer', 'vpn.example.com', '51820',
                                                    public_port='443')
        self.assertIn('Endpoint = vpn.example.com:443', config)

    def test_wireguard_keeps_the_listen_port_without_an_override(self):
        config = self.wireguard().get_client_config('peer', 'vpn.example.com', '51820')
        self.assertIn('Endpoint = vpn.example.com:51820', config)

    def test_awg_endpoint_follows_the_public_port(self):
        config = self.awg().get_client_config('awg2', 'peer', '203.0.113.9', '55424',
                                              public_port='443')
        self.assertIn('Endpoint = 203.0.113.9:443', config)

    def test_awg_keeps_the_listen_port_without_an_override(self):
        config = self.awg().get_client_config('awg2', 'peer', '198.51.100.1', '55424')
        self.assertIn('Endpoint = 198.51.100.1:55424', config)

    def test_xray_link_prefers_the_public_port_over_the_live_config(self):
        link = self.xray().get_client_config('xray', 'uuid-1', 'vpn.example.com', '55424',
                                             public_port='8443')
        self.assertIn('@vpn.example.com:8443?', link)

    def test_xray_link_without_an_override_still_trusts_meta(self):
        # meta.json is synced from the live server.json; the panel's own record
        # can be stale, so an unset override must not promote it.
        link = self.xray().get_client_config('xray', 'uuid-1', 'vpn.example.com', '55424')
        self.assertIn('@vpn.example.com:443?', link)


TELEMT_CONFIG = """[general]
port = 443

[general.links]
show = "*"
# public_host = "proxy.example.com"  # Host (IP or domain) for tg:// links
public_port = 443                  # Port for tg:// links

[access.users]
alice = "deadbeef"
"""


class TelemtLinkConfigTests(unittest.TestCase):
    """Telemt prints its own links, so the address has to land in config.toml."""

    def manager(self):
        ssh = mock.Mock()
        ssh.host = '198.51.100.1'
        return TelemtManager(ssh)

    def test_commented_host_is_activated_and_lines_stay_separate(self):
        patched = self.manager()._patch_public_links(TELEMT_CONFIG, '203.0.113.9', '443')
        self.assertIn('public_host = "203.0.113.9"', patched)
        self.assertIn('public_port = 443', patched)
        # A pattern allowed to span lines eats the newline before the key and
        # welds it onto the previous line, quietly corrupting the config.
        self.assertIn('show = "*"\n', patched)
        self.assertEqual(len(TELEMT_CONFIG.splitlines()), len(patched.splitlines()))

    def test_an_already_set_host_is_replaced_in_place(self):
        once = self.manager()._patch_public_links(TELEMT_CONFIG, '203.0.113.9', '443')
        twice = self.manager()._patch_public_links(once, '203.0.113.10', '8443')
        self.assertIn('public_host = "203.0.113.10"', twice)
        self.assertNotIn('203.0.113.9', twice)
        self.assertEqual(twice.count('public_host'), 1)
        self.assertEqual(len(once.splitlines()), len(twice.splitlines()))

    def test_keys_are_added_when_the_section_has_neither(self):
        bare = '[general.links]\nshow = "*"\n'
        patched = self.manager()._patch_public_links(bare, 'vpn.example.com', '443')
        self.assertIn('public_host = "vpn.example.com"', patched)
        self.assertIn('public_port = 443', patched)

    def test_set_public_endpoint_writes_and_reloads(self):
        mgr = self.manager()
        mgr._get_server_config = lambda: TELEMT_CONFIG
        saved = []
        mgr.save_server_config = lambda proto, content: saved.append(content)
        self.assertTrue(mgr.set_public_endpoint('203.0.113.9', '443'))
        self.assertEqual(len(saved), 1)
        self.assertIn('public_host = "203.0.113.9"', saved[0])

    def test_set_public_endpoint_reports_a_missing_config(self):
        mgr = self.manager()
        mgr._get_server_config = lambda: ''
        mgr.save_server_config = lambda proto, content: self.fail('nothing to save')
        self.assertFalse(mgr.set_public_endpoint('203.0.113.9', '443'))

class PublicEndpointApiTests(unittest.TestCase):
    """The API around the record, through the real app."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [server_with({
                'awg2': {'installed': True, 'port': '55424', 'base_protocol': 'awg2'},
                'telemt': {'installed': True, 'port': '8443', 'base_protocol': 'telemt'},
            })], 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stored(self, protocol):
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            return json.load(f)['servers'][0]['protocols'][protocol]

    def client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)
        return client

    def set_endpoint(self, client, **body):
        return client.post('/api/servers/0/protocol/public-endpoint', json=body)

    def working_ssh(self):
        """A mock SSH whose sudo commands succeed (returns a 3-tuple)."""
        ssh = mock.Mock()
        ssh.run_sudo_command.return_value = ('', '', 0)
        return ssh

    def test_set_and_clear_round_trip(self):
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()):
            res = self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                                    public_port='443')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['warning'], '')
        self.assertEqual(self.stored('awg2')['public_host'], '203.0.113.9')
        self.assertEqual(self.stored('awg2')['public_port'], '443')

        # empty fields mean "back to the server address and the listen port":
        # the keys go away rather than lingering as empty strings
        res = self.set_endpoint(client, protocol='awg2', public_host='', public_port='')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertNotIn('public_host', self.stored('awg2'))
        self.assertNotIn('public_port', self.stored('awg2'))
        self.assertEqual(self.stored('awg2')['port'], '55424', 'listen port must survive')

    def test_bad_input_is_refused_before_it_reaches_a_config(self):
        client = self.client()
        res = self.set_endpoint(client, protocol='awg2', public_host='https://vpn.example.com')
        self.assertEqual(res.status_code, 400, res.text)
        res = self.set_endpoint(client, protocol='awg2', public_port='70000')
        self.assertEqual(res.status_code, 400, res.text)
        self.assertNotIn('public_host', self.stored('awg2'))

    def test_unknown_protocol_and_server(self):
        client = self.client()
        self.assertEqual(self.set_endpoint(client, protocol='xray',
                                           public_host='203.0.113.9').status_code, 404)
        res = client.post('/api/servers/7/protocol/public-endpoint',
                          json={'protocol': 'awg2', 'public_host': '203.0.113.9'})
        self.assertEqual(res.status_code, 404)

    def test_anonymous_callers_are_refused(self):
        with TestClient(panel.app) as client:
            res = client.post('/api/servers/0/protocol/public-endpoint',
                              json={'protocol': 'awg2', 'public_host': '203.0.113.9'})
            self.assertEqual(res.status_code, 403)

    def test_telemt_override_is_pushed_into_the_running_config(self):
        client = self.client()
        manager = mock.Mock()
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()), \
             mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            res = self.set_endpoint(client, protocol='telemt', public_host='203.0.113.9',
                                    public_port='443')
        self.assertEqual(res.status_code, 200, res.text)
        manager.set_public_endpoint.assert_called_once_with('203.0.113.9', '443')

    def test_telemt_falls_back_to_the_instance_port(self):
        client = self.client()
        manager = mock.Mock()
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()), \
             mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            self.set_endpoint(client, protocol='telemt', public_host='203.0.113.9')
        manager.set_public_endpoint.assert_called_once_with('203.0.113.9', '8443')

    def test_an_unreachable_server_still_keeps_the_setting(self):
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', side_effect=RuntimeError('host is down')):
            res = self.set_endpoint(client, protocol='telemt', public_host='203.0.113.9')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn('host is down', res.json()['warning'])
        self.assertEqual(self.stored('telemt')['public_host'], '203.0.113.9')

    def test_reinstall_keeps_the_public_address(self):
        client = self.client()
        manager = mock.Mock()
        manager.install_protocol.return_value = {'status': 'success', 'awg_params': {}}
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()), \
             mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                              public_port='443')
            with mock.patch.object(panel, 'ensure_docker_installed', return_value=''), \
                 mock.patch.object(panel, 'get_used_ports', return_value={}):
                res = client.post('/api/servers/0/install',
                                  json={'protocol': 'awg2', 'port': '55424'})
        self.assertEqual(res.status_code, 200, res.text)
        # The install rebuilds the record from scratch; where the instance is
        # published is a property of the network, not of this install.
        self.assertEqual(self.stored('awg2')['public_host'], '203.0.113.9')
        self.assertEqual(self.stored('awg2')['public_port'], '443')

    def test_telemt_reinstall_writes_the_override_into_the_fresh_config(self):
        client = self.client()
        manager = mock.Mock()
        manager.install_protocol.return_value = {'status': 'success'}
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()), \
             mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            self.set_endpoint(client, protocol='telemt', public_host='203.0.113.9',
                              public_port='443')
            with mock.patch.object(panel, 'ensure_docker_installed', return_value=''), \
                 mock.patch.object(panel, 'get_used_ports', return_value={}):
                res = client.post('/api/servers/0/install',
                                  json={'protocol': 'telemt', 'port': '8443'})
        self.assertEqual(res.status_code, 200, res.text)
        kwargs = manager.install_protocol.call_args.kwargs
        self.assertEqual(kwargs['public_host'], '203.0.113.9')
        self.assertEqual(kwargs['public_port'], '443')

    def test_issued_config_uses_the_override(self):
        client = self.client()
        manager = mock.Mock()
        manager.add_client.return_value = {'client_id': 'peer', 'config': '[Interface]'}
        with mock.patch.object(panel, 'get_ssh', return_value=self.working_ssh()), \
             mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                              public_port='443')
            res = client.post('/api/servers/0/connections/add',
                              json={'protocol': 'awg2', 'name': 'laptop'})
        self.assertEqual(res.status_code, 200, res.text)
        args, kwargs = manager.add_client.call_args
        self.assertEqual(args[2], '203.0.113.9', 'the client must dial the published address')
        self.assertEqual(kwargs['public_port'], '443')

    def test_server_page_carries_the_endpoints_and_the_modal(self):
        client = self.client()
        self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9', public_port='443')
        page = client.get('/server/0').text
        self.assertIn('id="publicEndpointModal"', page)
        self.assertIn('function openPublicEndpointModal', page)
        endpoints = re.search(r'const PUBLIC_ENDPOINTS = (\{.*?\});', page, re.S).group(1)
        self.assertIn('"awg2"', endpoints)
        self.assertIn('203.0.113.9', endpoints)
        self.assertIn('"443"', endpoints)
        # a missing translation renders as the raw key
        self.assertEqual(re.findall(r'>\s*public_endpoint_[a-z0-9_]+\s*<', page), [])


class PortCheckApiTests(PublicEndpointApiTests):
    """The port checker behind the public-endpoint modal: parsing of `ss`
    output, auth, validation and the SSH call itself."""

    SS_SAMPLE = (
        'udp   UNCONN 0      0            0.0.0.0:55424       0.0.0.0:*    '
        'users:(("docker-proxy",pid=1234,fd=4))\n'
        'tcp   LISTEN 0      128          0.0.0.0:443         0.0.0.0:*    '
        'users:(("nginx",pid=99,fd=6))\n'
    )

    def test_parser_extracts_proto_address_process_and_pid(self):
        listeners = panel._parse_ss_listeners(self.SS_SAMPLE)
        self.assertEqual(listeners, [
            {'proto': 'udp', 'address': '0.0.0.0:55424', 'process': 'docker-proxy', 'pid': '1234'},
            {'proto': 'tcp', 'address': '0.0.0.0:443', 'process': 'nginx', 'pid': '99'},
        ])

    def test_parser_handles_an_empty_answer_and_header_noise(self):
        self.assertEqual(panel._parse_ss_listeners(''), [])
        self.assertEqual(panel._parse_ss_listeners('Netid State Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n'), [])

    def _ssh_returning(self, output):
        ssh = mock.Mock()
        ssh.run_command.return_value = (output, '', 0)
        return ssh

    def test_free_port_reports_no_listeners(self):
        client = self.client()
        ssh = self._ssh_returning('')
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.get('/api/servers/0/protocol/port-check?port=59999')
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body['port'], 59999)
        self.assertFalse(body['in_use'])
        self.assertEqual(body['listeners'], [])
        ssh.run_command.assert_called_once_with("ss -tulpnH '( sport = :59999 )'")

    def test_busy_port_names_the_holder(self):
        client = self.client()
        ssh = self._ssh_returning(self.SS_SAMPLE)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.get('/api/servers/0/protocol/port-check?port=443')
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertTrue(body['in_use'])
        self.assertEqual(body['listeners'][1]['process'], 'nginx')

    def test_bad_port_and_unknown_server_are_refused(self):
        client = self.client()
        self.assertEqual(client.get('/api/servers/0/protocol/port-check?port=70000').status_code, 400)
        self.assertEqual(client.get('/api/servers/0/protocol/port-check').status_code, 400)
        self.assertEqual(client.get('/api/servers/7/protocol/port-check?port=443').status_code, 404)

    def test_port_check_warns_when_docker_holds_the_port(self):
        client = self.client()
        ssh = self._ssh_returning(
            'udp   UNCONN 0      0            0.0.0.0:8443       0.0.0.0:*    '
            'users:(("docker-proxy",pid=1234,fd=4))\n')
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = client.get('/api/servers/0/protocol/port-check?port=8443')
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertTrue(body['in_use'])
        self.assertIn('warning', body)
        self.assertIn('Docker', body['warning'])

    def test_anonymous_and_unreachable_server(self):
        with TestClient(panel.app) as client:
            self.assertEqual(client.get('/api/servers/0/protocol/port-check?port=443').status_code, 403)
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', side_effect=RuntimeError('host is down')):
            res = client.get('/api/servers/0/protocol/port-check?port=443')
        self.assertEqual(res.status_code, 502, res.text)
        self.assertIn('host is down', res.json()['error'])


class PublicPortForwardTests(PublicEndpointApiTests):
    """A custom public port is published on the box itself: REDIRECT rules in
    iptables/ip6tables per address family, removed when the port is cleared
    or changed."""

    def ssh_recorder(self):
        ssh = mock.Mock()
        ssh.commands = []
        ssh.run_sudo_command.side_effect = lambda cmd, *a, **k: ssh.commands.append(cmd) or ('', '', 0)
        return ssh

    def test_command_builder_publishes_udp_for_wireguard_family(self):
        cmds, warning = panel.public_port_forward_commands('awg3', '8443', '55425')
        self.assertEqual(warning, '')
        self.assertEqual(len(cmds), 2)
        for ipt in ('iptables', 'ip6tables'):
            self.assertTrue(any(c.startswith(f'{ipt} -t nat -C PREROUTING -p udp --dport 8443') for c in cmds), cmds)

    def test_command_builder_uses_tcp_for_xray_and_skips_services(self):
        tcp, _ = panel.public_port_forward_commands('xray', '8443', '443')
        self.assertTrue(all('-p tcp' in c for c in tcp))
        self.assertIsNone(panel.public_port_forward_commands('dns', '8443', '53')[0])

    def test_same_or_empty_port_means_no_rule_but_clears_the_stale_one(self):
        self.assertIsNone(panel.public_port_forward_commands('awg3', '', '55425', '')[0])
        same, _ = panel.public_port_forward_commands('awg3', '55425', '55425', '55425')
        self.assertIsNone(same)
        cleared, _ = panel.public_port_forward_commands('awg3', '', '55425', '8443')
        self.assertEqual(len(cleared), 2)
        self.assertTrue(all('-D PREROUTING' in c and '--dport 8443' in c for c in cleared), cleared)
        changed, _ = panel.public_port_forward_commands('awg3', '9443', '55425', '8443')
        self.assertTrue(any('-D PREROUTING' in c and '--dport 8443' in c for c in changed), changed)
        self.assertTrue(any('-A PREROUTING' in c and '--dport 9443' in c for c in changed), changed)

    def test_rules_are_scoped_to_a_v4_public_ip(self):
        cmds, warning = panel.public_port_forward_commands(
            'awg3', '8443', '55425', public_ip='203.0.113.9')
        self.assertEqual(warning, '')
        self.assertEqual(len(cmds), 1)  # the v6 family is not this host's
        self.assertIn('iptables -t nat -C PREROUTING -p udp -d 203.0.113.9 --dport 8443', cmds[0])
        dropped, _ = panel.public_port_forward_commands(
            'awg3', '', '55425', '8443', public_ip='203.0.113.9')
        self.assertEqual(len(dropped), 1)
        self.assertIn('-D PREROUTING -p udp -d 203.0.113.9 --dport 8443', dropped[0])

    def test_rules_are_scoped_to_a_v6_public_ip(self):
        cmds, _ = panel.public_port_forward_commands(
            'awg3', '8443', '55425', public_ip='[2001:db8::9]')
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('ip6tables -t nat -C PREROUTING -p udp '
                                          '-d 2001:db8::9 --dport 8443'), cmds)

    def test_a_domain_resolves_into_per_family_scopes(self):
        def fake_getaddrinfo(host, port):
            self.assertEqual(host, 'vpn.example.com')
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.9', 0)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::9', 0, 0, 0))]
        with mock.patch.object(panel.socket, 'getaddrinfo', side_effect=fake_getaddrinfo):
            cmds, warning = panel.public_port_forward_commands(
                'awg3', '8443', '55425', public_ip='vpn.example.com')
        self.assertEqual(warning, '')
        self.assertEqual(len(cmds), 2)
        self.assertTrue(any('-d 203.0.113.9 --dport 8443' in c and c.startswith('iptables') for c in cmds), cmds)
        self.assertTrue(any('-d 2001:db8::9 --dport 8443' in c and c.startswith('ip6tables') for c in cmds), cmds)

    def test_an_unresolvable_domain_falls_back_unrestricted_with_warning(self):
        with mock.patch.object(panel.socket, 'getaddrinfo',
                               side_effect=OSError('Name or service not known')):
            cmds, warning = panel.public_port_forward_commands(
                'awg3', '8443', '55425', public_ip='vpn.example.com')
        self.assertEqual(len(cmds), 2)  # legacy shape: both families, no -d
        self.assertTrue(all(' -d ' not in c for c in cmds), cmds)
        self.assertIn('could not restrict the forward rule to the public IP', warning)
        self.assertIn('vpn.example.com does not resolve', warning)

    def test_saving_a_custom_port_scopes_the_rule_to_the_public_ip(self):
        client = self.client()
        ssh = self.ssh_recorder()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                                    public_port='8443')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['warning'], '')
        # 1 forward (add) + 1 verification (-C), the v4 family only - the
        # public IP is an IPv4 literal, ip6tables has no business there
        self.assertEqual(len(ssh.commands), 2)
        for cmd in ssh.commands:
            self.assertIn('iptables -t nat', cmd)
            self.assertIn('-p udp -d 203.0.113.9 --dport 8443', cmd)
            self.assertIn('--to-ports 55424', cmd)
        self.assertFalse(any(c.startswith('ip6tables') for c in ssh.commands))

    def test_saving_a_domain_scopes_each_family_to_its_address(self):
        client = self.client()
        ssh = self.ssh_recorder()

        def fake_getaddrinfo(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.9', 0)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::9', 0, 0, 0))]
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
             mock.patch.object(panel.socket, 'getaddrinfo', side_effect=fake_getaddrinfo):
            res = self.set_endpoint(client, protocol='awg2', public_host='vpn.example.com',
                                    public_port='8443')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['warning'], '')
        v4 = [c for c in ssh.commands if c.startswith('iptables')]
        v6 = [c for c in ssh.commands if c.startswith('ip6tables')]
        self.assertEqual(len(v4), 2)  # add + verify
        self.assertEqual(len(v6), 2)
        self.assertTrue(all('-d 203.0.113.9 --dport 8443' in c for c in v4), v4)
        self.assertTrue(all('-d 2001:db8::9 --dport 8443' in c for c in v6), v6)

    def test_an_unresolvable_domain_warns_and_leaves_the_rule_unrestricted(self):
        client = self.client()
        ssh = self.ssh_recorder()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
             mock.patch.object(panel.socket, 'getaddrinfo',
                               side_effect=OSError('Name or service not known')):
            res = self.set_endpoint(client, protocol='awg2', public_host='vpn.example.com',
                                    public_port='8443')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn('could not restrict the forward rule to the public IP',
                      res.json()['warning'])
        self.assertIn('vpn.example.com does not resolve', res.json()['warning'])
        # fallback shape: both families, no -d restriction; verification is
        # skipped when a warning already exists
        self.assertEqual(len(ssh.commands), 2)
        self.assertTrue(all(' -d ' not in c for c in ssh.commands), ssh.commands)

    def test_iptables_failure_warns_but_keeps_setting(self):
        client = self.client()
        ssh = mock.Mock()
        ssh.run_sudo_command.return_value = ('', 'Permission denied', 1)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            res = self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                                    public_port='8443')
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertIn('forward command failed', body['warning'])
        self.assertIn('Permission denied', body['warning'])
        self.assertEqual(self.stored('awg2')['public_port'], '8443')

    def test_clearing_the_port_removes_the_rules(self):
        client = self.client()
        ssh = self.ssh_recorder()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh):
            self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                              public_port='8443')
            ssh.commands.clear()
            res = self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                                    public_port='')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(len(ssh.commands), 1)  # v4 drop only, scoped like the add
        self.assertIn('-D PREROUTING', ssh.commands[0])
        self.assertIn('-d 203.0.113.9 --dport 8443', ssh.commands[0])

    def test_a_box_that_is_down_keeps_the_setting_and_warns(self):
        client = self.client()
        with mock.patch.object(panel, 'get_ssh', side_effect=RuntimeError('host is down')):
            res = self.set_endpoint(client, protocol='awg2', public_host='203.0.113.9',
                                    public_port='8443')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn('host is down', res.json()['warning'])
        self.assertEqual(self.stored('awg2')['public_port'], '8443')


class RestoreForwardTests(unittest.TestCase):
    """At startup the panel re-applies its public-port forwards on every
    server: hand-made iptables rules survive reboots on some hosts only, so
    the panel owns putting them back. Plain TestCase on purpose: inheriting
    PublicEndpointApiTests would re-run its tests against this fixture."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [
                server_with({
                    'awg2': {'installed': True, 'port': '55424',
                             'public_host': '203.0.113.9', 'public_port': '8443'},
                    'xray': {'installed': True, 'port': '443', 'public_port': '8443'},
                    'wireguard': {'installed': True, 'port': '51820'},  # no public port
                }),
                server_with({}),  # nothing to forward
            ], 'users': [], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self._delay = panel.RESTORE_FORWARD_DELAY
        panel.RESTORE_FORWARD_DELAY = 0

    def tearDown(self):
        panel.RESTORE_FORWARD_DELAY = self._delay
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_restore(self):
        seen = []

        def fake_ssh(server):
            ssh = mock.Mock()
            ssh.commands = []
            ssh.run_sudo_command.side_effect = lambda cmd, *a, **k: ssh.commands.append(cmd) or ('', '', 0)
            seen.append((server, ssh))
            return ssh

        with mock.patch.object(panel, 'get_ssh', side_effect=fake_ssh):
            asyncio.run(panel.restore_public_port_forwards())
        return seen

    def test_only_servers_with_public_ports_are_touched(self):
        seen = self.run_restore()
        self.assertEqual(len(seen), 1)
        server, ssh = seen[0]
        # awg2 udp + xray tcp, the v4 table each. awg2 carries its own
        # public_host; xray has none, so its rule is scoped to the panel's
        # own address for that server (protocol_public_endpoint fallback)
        self.assertEqual(len(ssh.commands), 2)
        self.assertTrue(any('-p udp -d 203.0.113.9 --dport 8443' in c for c in ssh.commands), ssh.commands)
        self.assertTrue(any('-p tcp -d 198.51.100.1 --dport 8443' in c for c in ssh.commands), ssh.commands)
        self.assertFalse(any('--dport 51820' in c for c in ssh.commands))

    def test_periodic_loop_reapplies_forwards(self):
        # a VPS rebooting on its own loses the rules while the panel keeps
        # running - the loop re-applies them every RESTORE_FORWARD_INTERVAL
        calls = []
        real_restore = panel.restore_public_port_forwards
        real_interval = panel.RESTORE_FORWARD_INTERVAL

        async def fake_restore():
            calls.append(1)

        panel.restore_public_port_forwards = fake_restore
        panel.RESTORE_FORWARD_INTERVAL = 0
        try:
            async def runner():
                task = asyncio.create_task(panel.restore_public_port_forwards_loop())
                for _ in range(100):
                    await asyncio.sleep(0.001)
                    if len(calls) >= 2:
                        break
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            asyncio.run(runner())
        finally:
            panel.restore_public_port_forwards = real_restore
            panel.RESTORE_FORWARD_INTERVAL = real_interval
        self.assertGreaterEqual(len(calls), 2)

    def test_restore_forward_logs_failed_command(self):
        panel.RESTORE_FORWARD_DELAY = 0

        def fake_ssh(server):
            ssh = mock.Mock()
            ssh.commands = []

            def run(cmd, *a, **k):
                ssh.commands.append(cmd)
                if len(ssh.commands) == 2:
                    return ('', 'Permission denied', 1)
                return ('', '', 0)
            ssh.run_sudo_command.side_effect = run
            return ssh

        with mock.patch.object(panel, 'get_ssh', side_effect=fake_ssh), \
             mock.patch.object(panel.logger, 'error') as log_err:
            asyncio.run(panel.restore_public_port_forwards())
        self.assertTrue(log_err.called)
        self.assertIn('Permission denied', log_err.call_args[0][0])

    def test_a_down_server_does_not_stop_the_rest(self):
        def fake_ssh(server):
            raise RuntimeError('host is down')

        with mock.patch.object(panel, 'get_ssh', side_effect=fake_ssh):
            asyncio.run(panel.restore_public_port_forwards())  # must not raise


if __name__ == '__main__':
    unittest.main()
