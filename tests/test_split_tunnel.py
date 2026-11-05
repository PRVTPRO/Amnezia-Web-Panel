"""Networks outside the VPN: parsing, AllowedIPs math, public lists, config
generation and the admin endpoints.

The list is a client-side setting only: it rewrites `0.0.0.0/0` in the
AllowedIPs line of generated WireGuard/AmneziaWG configs. Network access and
SSH are faked throughout.
"""
import hashlib
import ipaddress
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers import split_tunnel
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager

ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = 'awp_split-tunnel-regression-token'
EVERYTHING = 2 ** 32


def covered(nets):
    return sum(ipaddress.ip_network(n).num_addresses for n in ipaddress.collapse_addresses(
        ipaddress.ip_network(n) for n in nets))


class ParseNetworksTests(unittest.TestCase):
    def test_reads_every_common_list_format(self):
        text = '\n'.join([
            '# comment with 9.9.9.9 inside',
            '5.255.255.0/24, 77.88.0.0/18;87.240.128.0/18',
            'add rkn_extra_out4 95.163.0.0/16',
            '[{"hostname": "185.73.192.0/22", "ip": ""}]',
            '1.2.3.4 - 1.2.3.9',
            '213.180.204.242',
        ])
        nets, invalid, ipv6 = split_tunnel.parse_networks(text)
        self.assertEqual(invalid, [])
        self.assertEqual(ipv6, 0)
        self.assertEqual(split_tunnel.normalize(nets), [
            '1.2.3.4/30', '1.2.3.8/31', '5.255.255.0/24', '77.88.0.0/18',
            '87.240.128.0/18', '95.163.0.0/16', '185.73.192.0/22', '213.180.204.242/32'])

    def test_reports_broken_addresses_and_counts_ipv6(self):
        nets, invalid, ipv6 = split_tunnel.parse_networks(
            '300.1.1.1/24\n1.2.3.0/33\n2001:db8::/32\nversion 5.0.3 of 2026\n10.1.2.0/24')
        self.assertEqual(invalid, ['300.1.1.1/24', '1.2.3.0/33'])
        self.assertEqual(ipv6, 1)
        self.assertEqual([str(n) for n in nets], ['10.1.2.0/24'])

    def test_refuses_absurd_lists(self):
        with mock.patch.object(split_tunnel, 'MAX_NETWORKS', 3):
            with self.assertRaises(split_tunnel.SplitTunnelError) as ctx:
                split_tunnel.parse_networks('\n'.join(f'1.1.{i}.0/24' for i in range(5)))
        self.assertEqual(ctx.exception.code, 'too_many')

    def test_normalize_collapses_and_drops_local_ranges(self):
        nets = [ipaddress.IPv4Network(n) for n in
                ('10.0.0.0/8', '192.168.1.0/24', '5.0.0.0/9', '5.128.0.0/9', '5.1.0.0/16')]
        self.assertEqual(split_tunnel.normalize(nets), ['5.0.0.0/8'])


class AllowedIpsTests(unittest.TestCase):
    def test_entries_partition_the_address_space_exactly(self):
        bypass = ['5.255.255.0/24', '77.88.0.0/18', '87.240.128.0/18']
        entries = split_tunnel.tunnel_entries(bypass)
        local = [str(n) for n in split_tunnel.LOCAL_V4]
        self.assertEqual(covered(entries) + covered(bypass + local), EVERYTHING)
        self.assertEqual(covered(entries + bypass + local), EVERYTHING)
        for net in bypass + local:
            self.assertFalse(any(ipaddress.ip_network(e).overlaps(ipaddress.ip_network(net))
                                 for e in entries), net)

    def test_a_list_covering_everything_is_rejected(self):
        with self.assertRaises(split_tunnel.SplitTunnelError) as ctx:
            split_tunnel.tunnel_entries(['0.0.0.0/1', '128.0.0.0/1'])
        self.assertEqual(ctx.exception.code, 'covers_all')

    def test_rewrite_replaces_full_tunnel_and_keeps_the_rest(self):
        config = ('[Interface]\nAddress = 10.8.1.2/32\nPrivateKey = abc=\n\n'
                  '[Peer]\nPublicKey = def=\nAllowedIPs = 0.0.0.0/0, ::/0\r\nEndpoint = 203.0.113.1:1\n')
        out = split_tunnel.rewrite_allowed_ips(config, ['1.0.0.0/8', '2.0.0.0/7'])
        self.assertIn('AllowedIPs = 1.0.0.0/8, 2.0.0.0/7, ::/0\r\n', out)
        self.assertIn('PrivateKey = abc=\n', out)
        self.assertEqual(split_tunnel.fold_allowed_ips(out, ['2.0.0.0/7', '1.0.0.0/8']), config)

    def test_rewrite_leaves_narrowed_and_interface_lines_alone(self):
        narrowed = '[Peer]\nAllowedIPs = 10.8.0.0/24\n'
        self.assertEqual(split_tunnel.rewrite_allowed_ips(narrowed, ['1.0.0.0/8']), narrowed)
        interface_only = '[Interface]\nAllowedIPs = 0.0.0.0/0\n'
        self.assertEqual(split_tunnel.rewrite_allowed_ips(interface_only, ['1.0.0.0/8']), interface_only)

    def test_fold_ignores_lists_that_do_not_match(self):
        config = '[Peer]\nAllowedIPs = 1.0.0.0/8, ::/0\n'
        self.assertEqual(split_tunnel.fold_allowed_ips(config, ['1.0.0.0/8', '2.0.0.0/7']), config)

    def test_describe_counts_client_routes(self):
        info = split_tunnel.describe({'enabled': True, 'networks': ['77.88.0.0/18']})
        self.assertTrue(info['active'])
        self.assertEqual(info['network_count'], 1)
        self.assertEqual(info['allowed_ips_entries'], len(split_tunnel.tunnel_entries(['77.88.0.0/18'])))
        self.assertFalse(info['large'])
        self.assertEqual(split_tunnel.describe({})['allowed_ips_entries'], 1)


def ripestat_payload(prefixes):
    return json.dumps({'data': {'query_time': '2026-11-03T00:00:00',
                                'resources': {'ipv4': prefixes}}})


COUNTRY = [f'{a}.{b}.0.0/16' for a in (31, 37, 46) for b in range(0, 200, 4)]  # 150 networks


class PublicListTests(unittest.TestCase):
    def test_ripestat_ranges_and_prefixes_are_both_read(self):
        fetch = mock.Mock(return_value=ripestat_payload(COUNTRY + ['5.8.0.0-5.8.1.255']))
        nets, source = split_tunnel.fetch_country_networks('ru', fetch=fetch)
        self.assertEqual(source, 'RIPEstat 2026-11-03')
        self.assertIn(ipaddress.IPv4Network('5.8.0.0/23'), nets)
        self.assertIn('resource=RU', fetch.call_args[0][0])

    def test_falls_back_when_a_source_fails_or_is_too_small(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if 'ripe' in url:
                raise OSError('timeout')
            if 'ipdeny' in url:
                return '1.1.1.0/24\n'
            return '\n'.join(COUNTRY)

        nets, source = split_tunnel.fetch_country_networks('RU', fetch=fetch)
        self.assertEqual(source, 'herrbischoff/country-ip-blocks')
        self.assertEqual(len(nets), len(COUNTRY))
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[1].endswith('/ru-aggregated.zone'))

    def test_every_source_failing_is_reported(self):
        with self.assertRaises(split_tunnel.SplitTunnelError) as ctx:
            split_tunnel.fetch_country_networks('RU', fetch=mock.Mock(side_effect=OSError('down')))
        self.assertEqual(ctx.exception.code, 'fetch_failed')
        with self.assertRaises(split_tunnel.SplitTunnelError) as ctx:
            split_tunnel.fetch_country_networks('R1', fetch=mock.Mock())
        self.assertEqual(ctx.exception.code, 'bad_country')

    def test_shorten_keeps_big_networks_and_service_networks_only(self):
        nets = [ipaddress.IPv4Network(n) for n in
                ('77.88.0.0/18', '87.240.128.0/18', '95.163.0.0/16', '5.255.255.0/24', '46.0.0.0/12')]
        resolve = {'ya.ru': {'77.88.44.242'}, 'vk.com': {'87.240.132.67'},
                   'abroad.example': {'8.8.8.8'}, 'gone.example': set()}.get
        kept, unresolved = split_tunnel.shorten(nets, tuple(resolve.__self__), resolve=resolve)
        self.assertEqual([str(n) for n in kept],
                         ['46.0.0.0/12', '77.88.0.0/18', '87.240.128.0/18', '95.163.0.0/16'])
        self.assertEqual(unresolved, ['gone.example'])

    def test_build_public_list_shortens_by_default(self):
        fetch = mock.Mock(return_value=ripestat_payload(COUNTRY + ['5.255.255.0/24']))
        resolve = mock.Mock(return_value={'5.255.255.242'})
        result = split_tunnel.build_public_list('RU', fetch=fetch, resolve=resolve)
        self.assertTrue(result['shortened'])
        self.assertEqual(result['full_count'], len(COUNTRY) + 1)
        self.assertIn('5.255.255.0/24', result['networks'])
        self.assertEqual(result['source'], 'public:RU')
        self.assertEqual(resolve.call_count, len(split_tunnel.RU_SERVICE_HOSTS))
        full = split_tunnel.build_public_list('RU', shorten_list=False, fetch=fetch, resolve=resolve)
        self.assertFalse(full['shortened'])
        self.assertEqual(len(full['networks']), len(COUNTRY) + 1)


AWG_CLIENT = {'clientId': 'peer', 'userData': {'clientPrivateKey': 'priv', 'clientIp': '10.8.1.6', 'psk': 'psk'}}


def awg_manager(client=AWG_CLIENT):
    mgr = AWGManager(mock.Mock())
    mgr._get_clients_table = lambda proto: [client]
    mgr._get_client_ipv6 = lambda proto, ip: ''
    mgr._get_server_public_key = lambda proto: 'serverpub'
    mgr._get_server_psk = lambda proto: 'serverpsk'
    mgr._get_awg_params_from_config = lambda proto: {}
    mgr._get_dns = lambda proto, ud: '1.1.1.1'
    mgr._get_mtu = lambda proto, ud: '1376'
    return mgr


def allowed_line(config):
    return next(line for line in config.splitlines() if line.startswith('AllowedIPs'))


class GeneratedConfigTests(unittest.TestCase):
    """Generated configs follow the stored list through the data file."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, 'data.json')
        previous = split_tunnel._DATA_FILE_GETTER
        split_tunnel.configure(lambda: self.path)
        self.addCleanup(split_tunnel.configure, previous)

    def store(self, enabled, networks):
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump({'settings': {'split_tunnel': {'enabled': enabled, 'networks': networks}}}, f)
        split_tunnel.configure(lambda: self.path)  # drop the mtime cache

    def test_disabled_or_missing_list_keeps_the_full_tunnel(self):
        config = awg_manager().get_client_config('awg2', 'peer', '203.0.113.9', '55424')
        self.assertEqual(allowed_line(config), 'AllowedIPs = 0.0.0.0/0, ::/0')
        self.store(False, ['77.88.0.0/18'])
        config = awg_manager().get_client_config('awg2', 'peer', '203.0.113.9', '55424')
        self.assertEqual(allowed_line(config), 'AllowedIPs = 0.0.0.0/0, ::/0')

    def test_awg_config_routes_the_list_outside_the_tunnel(self):
        self.store(True, ['77.88.0.0/18'])
        config = awg_manager().get_client_config('awg3', 'peer', '203.0.113.9', '55424')
        entries = split_tunnel.tunnel_entries(['77.88.0.0/18'])
        self.assertEqual(allowed_line(config), 'AllowedIPs = ' + ', '.join(entries + ['::/0']))
        self.assertIn('Endpoint = 203.0.113.9:55424', config)
        self.assertIn('Address = 10.8.1.6/32', config)

    def test_hand_edited_config_is_rewritten_only_while_it_keeps_the_full_tunnel(self):
        self.store(True, ['77.88.0.0/18'])
        custom = dict(AWG_CLIENT, userData=dict(AWG_CLIENT['userData'], customConfig=(
            '[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = h:1\n')))
        config = awg_manager(custom).get_client_config('awg2', 'peer', 'h', '1')
        self.assertNotIn('0.0.0.0/0', config)
        narrowed = dict(AWG_CLIENT, userData=dict(AWG_CLIENT['userData'], customConfig=(
            '[Peer]\nAllowedIPs = 10.8.0.0/24\n')))
        self.assertEqual(awg_manager(narrowed).get_client_config('awg2', 'peer', 'h', '1'),
                         '[Peer]\nAllowedIPs = 10.8.0.0/24\n')

    def test_wireguard_config_follows_the_list_too(self):
        self.store(True, ['77.88.0.0/18'])
        mgr = WireGuardManager(mock.Mock())
        mgr._get_clients_table = lambda: [AWG_CLIENT]
        mgr._get_server_public_key = lambda: 'serverpub'
        mgr._get_server_psk = lambda: 'serverpsk'
        mgr._get_dns = lambda ud: '1.1.1.1'
        config = mgr.get_client_config('peer', '203.0.113.9', port='51820')
        self.assertTrue(allowed_line(config).endswith(', ::/0'))
        self.assertNotIn('0.0.0.0/0', config)

    def test_list_changes_are_picked_up_without_restart(self):
        self.store(True, ['77.88.0.0/18'])
        first = split_tunnel.current_entries()
        self.store(True, ['77.88.0.0/18', '95.163.0.0/16'])
        self.assertNotEqual(split_tunnel.current_entries(), first)
        self.store(False, ['77.88.0.0/18', '95.163.0.0/16'])
        self.assertIsNone(split_tunnel.current_entries())


class SplitTunnelApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self._data_file)
        self._conn_monitor_started = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._conn_monitor_started)
        previous = split_tunnel._DATA_FILE_GETTER
        split_tunnel.configure(lambda: panel.DATA_FILE)
        self.addCleanup(split_tunnel.configure, previous)
        now = datetime.now().isoformat()
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'servers': [{'uid': 'node-1', 'name': 'node', 'host': '192.0.2.10', 'ssh_port': 22,
                             'username': 'root', 'protocols': {'awg2': {'port': '55424'}}}],
                'users': [{'id': 'admin-id', 'username': 'admin', 'role': 'admin', 'enabled': True,
                           'password_hash': panel.hash_password('admin')},
                          {'id': 'bob-id', 'username': 'bob', 'role': 'user', 'enabled': True,
                           'password_hash': panel.hash_password('bob')}],
                'api_tokens': [{'id': 'admin-token', 'name': 'admin', 'user_id': 'admin-id',
                                'token_hash': hashlib.sha256(ADMIN_TOKEN.encode()).hexdigest(),
                                'token_prefix': ADMIN_TOKEN[:len(panel.API_TOKEN_PREFIX) + 4],
                                'created_at': now, 'last_used_at': now}],
            }, f)
        self.client = TestClient(panel.app)
        self.auth = {'Authorization': 'Bearer ' + ADMIN_TOKEN}

    def stored(self):
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            return json.load(f).get('settings', {}).get('split_tunnel', {})

    def test_defaults_and_admin_only(self):
        self.assertEqual(self.client.get('/api/settings/split-tunnel').status_code, 401)
        self.client.post('/api/auth/login', json={'username': 'bob', 'password': 'bob'})
        self.assertEqual(self.client.post('/api/settings/split-tunnel', json={}).status_code, 403)
        self.assertEqual(self.client.post('/api/settings/split-tunnel/public', json={}).status_code, 403)
        state = self.client.get('/api/settings/split-tunnel', headers=self.auth).json()
        self.assertFalse(state['enabled'])
        self.assertEqual(state['networks'], [])
        self.assertIn('split_tunnel', panel.load_data()['settings'])

    def test_save_validates_normalizes_and_toggles(self):
        bad = self.client.post('/api/settings/split-tunnel', headers=self.auth,
                               json={'enabled': True, 'networks': '1.2.3.0/24\n999.0.0.0/8'})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()['code'], 'invalid_networks')
        self.assertEqual(bad.json()['invalid'], ['999.0.0.0/8'])

        ok = self.client.post('/api/settings/split-tunnel', headers=self.auth, json={
            'enabled': True, 'source': 'file', 'networks': '77.88.0.0/19\n77.88.32.0/19\n2001:db8::/32'})
        self.assertEqual(ok.status_code, 200, ok.text)
        body = ok.json()
        self.assertTrue(body['active'])
        self.assertEqual(body['networks'], ['77.88.0.0/18'])
        self.assertEqual(body['ipv6_skipped'], 1)
        self.assertEqual(self.stored()['source'], 'file')

        off = self.client.post('/api/settings/split-tunnel', headers=self.auth,
                               json={'enabled': False, 'networks': '77.88.0.0/18', 'source': 'manual'})
        self.assertFalse(off.json()['active'])
        self.assertEqual(self.stored()['source'], 'file')  # same list: provenance kept
        self.assertEqual(self.stored()['networks'], ['77.88.0.0/18'])

        everything = self.client.post('/api/settings/split-tunnel', headers=self.auth,
                                      json={'enabled': True, 'networks': '0.0.0.0/0'})
        self.assertEqual(everything.json()['code'], 'covers_all')

    def test_public_list_is_stored_and_switched_on_in_one_call(self):
        result = {'networks': ['77.88.0.0/18', '95.163.0.0/16'], 'source': 'public:RU',
                  'source_detail': 'RIPEstat 2026-11-03', 'shortened': True,
                  'full_count': 8671, 'unresolved_hosts': ['lkfl2.nalog.ru']}
        with mock.patch.object(split_tunnel, 'build_public_list', return_value=result) as build:
            res = self.client.post('/api/settings/split-tunnel/public', headers=self.auth, json={})
        self.assertEqual(res.status_code, 200, res.text)
        build.assert_called_once_with('RU', shorten_list=True)
        body = res.json()
        self.assertTrue(body['active'])
        self.assertTrue(body['shortened'])
        self.assertEqual(body['full_count'], 8671)
        stored = self.stored()
        self.assertTrue(stored['enabled'])
        self.assertEqual(stored['networks'], ['77.88.0.0/18', '95.163.0.0/16'])
        self.assertEqual(stored['source_detail'], 'RIPEstat 2026-11-03')
        self.assertEqual(split_tunnel.current_entries(),
                         split_tunnel.tunnel_entries(['77.88.0.0/18', '95.163.0.0/16']))

    def test_public_fetch_failure_changes_nothing(self):
        error = split_tunnel.SplitTunnelError('fetch_failed', 'RIPEstat: timeout')
        with mock.patch.object(split_tunnel, 'build_public_list', side_effect=error):
            res = self.client.post('/api/settings/split-tunnel/public', headers=self.auth,
                                   json={'shorten': False})
        self.assertEqual(res.status_code, 502)
        self.assertEqual(res.json()['code'], 'fetch_failed')
        self.assertEqual(self.stored(), {})

    def test_edited_config_is_stored_folded(self):
        self.client.post('/api/settings/split-tunnel', headers=self.auth,
                         json={'enabled': True, 'networks': '77.88.0.0/18'})
        shown = split_tunnel.apply_to_config('[Interface]\nPrivateKey = k\n\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n')
        saved = []
        ssh = SimpleNamespace(connect=lambda: None, disconnect=lambda: None)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=object()), \
                mock.patch.object(panel, '_manager_call', side_effect=lambda *a: saved.append(a[-1])):
            res = self.client.post('/api/servers/0/connections/config/save', headers=self.auth,
                                   json={'protocol': 'awg2', 'client_id': 'peer', 'config': shown})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', saved[0])
        self.assertNotIn('0.0.0.0/0', res.json()['config'])


class SettingsCardTests(unittest.TestCase):
    def test_card_offers_one_click_shortened_russian_list(self):
        html = (ROOT / 'templates/settings.html').read_text(encoding='utf-8')
        self.assertIn('href="#settings-split-tunnel"', html)
        self.assertIn('id="settings-split-tunnel"', html)
        self.assertIn('<input type="checkbox" id="split_shorten" checked>', html)
        for needle in ("fetch('/api/settings/split-tunnel/public'", "fetch('/api/settings/split-tunnel'",
                       'onchange="loadSplitFile(this)"', "_('split_shorten_hint')", 'loadSplitTunnel();'):
            self.assertIn(needle, html)


if __name__ == '__main__':
    unittest.main()
