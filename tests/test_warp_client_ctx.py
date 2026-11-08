"""Warp context in client configs (issue #277, stage S4b-1).

Covers the manager contract (MTU/DNS budget, customConfig enforcement) and
the runtime reissue path (clearing per-client overrides and regenerating every
config inside the warp budget). No SSH, Docker or panel is touched.
"""

import asyncio
import concurrent.futures
import copy
import os
import shutil
import tempfile
import unittest
from unittest import mock

from managers.awg_manager import AWGManager
from warp_runtime import WarpRuntime
import warp_service as ws


def run_coro(coro):
    """Run a coroutine even when another test leaked a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()

WARP_CTX = {
    'active': True,
    'dns_via_warp': True,
    'client_mtu': 1220,
    'dns_ips': ['1.1.1.1'],
    'transit_cidr': '',
    'transit_gateway': '',
    'prefix': '/opt/amnezia/awg/warp/awg',
    'protocol': 'awg',
    'entry_uid': 'srv-1',
}


class FakeManager(AWGManager):
    """AWGManager with the transport replaced by in-memory state."""

    def __init__(self, ipv6='fd42:8:1::2'):
        self.ssh = mock.Mock()
        self.ssh.host = 'fake-host'
        self.ipv6 = ipv6
        self.clients = []
        self.inserted_peers = []
        self.saved_configs = []
        self.dns_calls = []
        self._server_config_cache = {}

    def _parse_peers_from_config(self, protocol_type):
        return []

    def peer_is_active(self, protocol_type, client_id):
        return False

    def _container_name(self, protocol_type):
        return 'amnezia-awg'

    def _wg_binary(self, protocol_type):
        return 'awg'

    def _resolve_config_path(self, protocol_type):
        return '/opt/amnezia/awg/awg0.conf'

    def _interface_name(self, protocol_type, config_path=None):
        return 'awg0'

    def _get_server_public_key(self, protocol_type):
        return 'serverpub'

    def _get_server_psk(self, protocol_type):
        return 'serverpsk'

    def _get_next_ip(self, protocol_type):
        return '10.8.1.6'

    def _get_client_ipv6(self, protocol_type, client_ip):
        return self.ipv6 if client_ip else ''

    def _get_awg_params_from_config(self, protocol_type):
        return {'port': '55424'}

    def _insert_peer_sorted(self, protocol_type, peer_section):
        self.inserted_peers.append(peer_section)

    def _syncconf_with_heal(self, protocol_type):
        return '', '', 0

    def _get_clients_table(self, protocol_type):
        return self.clients

    def _save_clients_table(self, protocol_type, clients_table):
        self.clients = clients_table

    def _get_dns(self, protocol_type, user_data=None):
        self.dns_calls.append(user_data)
        if user_data and user_data.get('dns'):
            return user_data['dns']
        return '9.9.9.9'

    def _get_dns6(self, protocol_type, user_data=None):
        return 'fd42:8:1::1'

    def _get_mtu(self, protocol_type, user_data=None):
        if user_data and user_data.get('mtu'):
            return str(user_data['mtu'])
        return '1376'


def dns_line(config):
    return next(line for line in config.splitlines()
                if line.startswith('DNS ='))


class ClientConfigWarpCtxTests(unittest.TestCase):
    def test_add_client_uses_warp_budget_and_cloudflare_dns(self):
        mgr = FakeManager()
        result = mgr.add_client(
            'awg', 'phone', '203.0.113.9', '55424', warp_ctx=WARP_CTX)
        config = result['config']

        self.assertIn('MTU = 1220', config)
        self.assertEqual(dns_line(config), 'DNS = 1.1.1.1')
        # No IPv6 resolver may ride through warp0.
        self.assertNotIn('fd42:8:1::1', config)

    def test_add_client_without_dns_toggle_keeps_server_dns(self):
        mgr = FakeManager()
        ctx = dict(WARP_CTX, dns_via_warp=False)
        config = mgr.add_client(
            'awg', 'phone', '203.0.113.9', '55424', warp_ctx=ctx)['config']

        self.assertIn('MTU = 1220', config)
        self.assertEqual(dns_line(config), 'DNS = 9.9.9.9')
        self.assertNotIn('fd42:8:1::1', config)

    def test_get_client_config_ignores_per_client_overrides(self):
        mgr = FakeManager()
        mgr.clients = [{
            'clientId': 'peer',
            'userData': {
                'clientPrivateKey': 'priv',
                'clientIp': '10.8.1.6',
                'psk': 'psk',
                'mtu': '1376',
                'dns': '8.8.4.4',
            },
        }]
        config = mgr.get_client_config(
            'awg', 'peer', '203.0.113.9', '55424', warp_ctx=WARP_CTX)

        self.assertIn('MTU = 1220', config)
        self.assertEqual(dns_line(config), 'DNS = 1.1.1.1')
        self.assertNotIn('8.8.4.4', config)

    def test_get_client_config_without_ctx_keeps_overrides(self):
        mgr = FakeManager()
        mgr.clients = [{
            'clientId': 'peer',
            'userData': {
                'clientPrivateKey': 'priv',
                'clientIp': '10.8.1.6',
                'psk': 'psk',
                'mtu': '1376',
                'dns': '8.8.4.4',
            },
        }]
        config = mgr.get_client_config(
            'awg', 'peer', '203.0.113.9', '55424')

        self.assertIn('MTU = 1376', config)
        self.assertTrue(dns_line(config).startswith('DNS = 8.8.4.4'))

    def test_prepare_client_forwards_ctx(self):
        import uuid

        mgr = FakeManager()
        from managers.awg_manager import generate_wg_keypair
        private, public = generate_wg_keypair()
        result = mgr.prepare_client(
            'awg', str(uuid.uuid4()), 'phone', private, public,
            '203.0.113.9', '55424', warp_ctx=WARP_CTX)

        self.assertIn('MTU = 1220', result['config'])
        self.assertEqual(dns_line(result['config']), 'DNS = 1.1.1.1')


class SaveClientConfigBudgetTests(unittest.TestCase):
    def make_manager(self):
        mgr = FakeManager()
        mgr.clients = [{
            'clientId': 'peer',
            'userData': {
                'clientName': 'phone',
                'clientPrivateKey': 'priv',
                'clientIp': '10.8.1.6',
                'psk': 'psk',
            },
        }]
        return mgr

    def test_custom_config_above_budget_is_rejected(self):
        mgr = self.make_manager()
        text = '[Interface]\nAddress = 10.8.1.6/32\nMTU = 1376\n'

        with self.assertRaises(ws.SrvWarpError) as ctx:
            mgr.save_client_config('awg', 'peer', text, warp_ctx=WARP_CTX)

        self.assertEqual(ctx.exception.code, 'srv_warp_budget_mismatch')
        self.assertEqual(ctx.exception.http_status, 409)
        self.assertNotIn('customConfig', mgr.clients[0]['userData'])

    def test_custom_config_within_budget_is_saved(self):
        mgr = self.make_manager()
        text = '[Interface]\nAddress = 10.8.1.6/32\nMTU = 1200\n'

        mgr.save_client_config('awg', 'peer', text, warp_ctx=WARP_CTX)

        self.assertEqual(mgr.clients[0]['userData']['customConfig'], text.strip())

    def test_custom_config_without_mtu_is_saved(self):
        mgr = self.make_manager()
        text = '[Interface]\nAddress = 10.8.1.6/32\n'

        mgr.save_client_config('awg', 'peer', text, warp_ctx=WARP_CTX)

        self.assertEqual(mgr.clients[0]['userData']['customConfig'], text.strip())


class _FakeLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class ReissueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = {'servers': [{
            'uid': 'srv-1',
            'host': '203.0.113.9',
            'protocols': {'awg': {'installed': True, 'port': '55424'}},
        }]}
        self.store = ws.WarpStateStore(os.path.join(self.tmp, 'state.json'))
        self.manager = FakeManager()
        self.manager.clients = [{
            'clientId': 'peer',
            'userData': {
                'clientName': 'phone',
                'clientPrivateKey': 'priv',
                'clientIp': '10.8.1.6',
                'psk': 'psk',
                'customConfig': '[Interface]\nAddress = 10.8.1.6/32\n'
                                'DNS = 8.8.4.4\nMTU = 1376\n',
                'mtu': '1376',
                'dns': '8.8.4.4',
            },
        }]

        def mutate(state):
            rec = ws.proto_record(state, 'srv-1', 'awg')
            rec['warp_link'] = {
                'active': True,
                'dns_via_warp': True,
                'applied_at': ws.now_ts(),
                'stale': None,
                'server_uid': 'srv-1',
                'entry_uid': 'srv-1',
                'protocol': 'awg',
            }
            rec['client_mtu_warp'] = 1220

        self.store.mutate(mutate)
        self.runtime = WarpRuntime(
            load_data=lambda: copy.deepcopy(self.data),
            save_data=lambda data: setattr(self, 'data', copy.deepcopy(data)),
            data_lock=_FakeLock(),
            get_ssh=lambda server: mock.Mock(),
            awg_manager_factory=lambda ssh: self.manager,
            state_store=self.store,
        )

    def test_reissue_clears_overrides_and_regenerates_with_budget(self):
        run_coro(self.runtime.reissue(0, 'srv-1', 'awg'))

        ud = self.manager.clients[0]['userData']
        self.assertIn('customConfig', ud)
        self.assertNotIn('MTU = 1376', ud['customConfig'])
        self.assertIn('MTU = 1220', ud['customConfig'])
        self.assertIn('DNS = 1.1.1.1', ud['customConfig'])
        self.assertNotEqual(ud.get('dns'), '8.8.4.4')
        self.assertEqual(ud.get('mtu'), '1220')

        record = ws.proto_record(self.store.load(), 'srv-1', 'awg')
        self.assertIsNotNone(record['warp']['last_reissue_at'])

    def test_reissue_applies_budget_to_every_client(self):
        self.manager.clients.append({
            'clientId': 'peer2',
            'userData': {
                'clientName': 'laptop',
                'clientPrivateKey': 'priv2',
                'clientIp': '10.8.1.7',
                'psk': 'psk',
                'mtu': '1376',
            },
        })

        run_coro(self.runtime.reissue(0, 'srv-1', 'awg'))

        for client in self.manager.clients:
            self.assertIn('MTU = 1220', client['userData']['customConfig'])
            self.assertNotIn('MTU = 1376', client['userData']['customConfig'])


if __name__ == '__main__':
    unittest.main()
