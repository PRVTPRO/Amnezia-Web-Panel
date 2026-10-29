"""Current public peer endpoint from `awg show` / `wg show` in Connections.

Display-only: the last-known source address WireGuard reports, empty when
unknown. No IP history and no block-by-IP actions.
"""
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import app as panel
from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager

ROOT = Path(__file__).resolve().parents[1]

WG_SHOW = """interface: awg0
  public key: SERVERPUB
  private key: (hidden)
  listening port: 55424

peer: KEY_LIVE
  endpoint: 203.0.113.10:51234
  allowed ips: 10.8.1.17/32
  latest handshake: 45 seconds ago
  transfer: 1.2 MiB received, 3.4 MiB sent

peer: KEY_V6
  endpoint: [2001:db8::10]:51820
  allowed ips: 10.8.1.18/32
  latest handshake: 12 seconds ago
  transfer: 10 B received, 20 B sent

peer: KEY_NONE
  endpoint: (none)
  allowed ips: 10.8.1.19/32
  transfer: 0 B received, 0 B sent

peer: KEY_OFFLINE
  allowed ips: 10.8.1.20/32
  transfer: 0 B received, 0 B sent
"""


def show_ssh(show_out=WG_SHOW, show_code=0):
    ssh = Mock()

    def sudo(command, timeout=60):
        if 'show all' in command:
            return show_out, '', show_code
        return '', '', 1

    ssh.run_sudo_command = sudo
    return ssh


class WgShowEndpointParseTests(unittest.TestCase):
    def test_awg_parses_current_endpoint_and_skips_unknown(self):
        peers = AWGManager(show_ssh())._wg_show('awg')
        self.assertEqual(peers['KEY_LIVE']['endpoint'], '203.0.113.10:51234')
        self.assertEqual(peers['KEY_V6']['endpoint'], '[2001:db8::10]:51820')
        self.assertEqual(peers['KEY_NONE']['endpoint'], '')
        self.assertEqual(peers['KEY_OFFLINE'].get('endpoint', ''), '')
        self.assertEqual(peers['KEY_LIVE']['allowedIps'], '10.8.1.17/32')
        self.assertEqual(peers['KEY_LIVE']['latestHandshake'], '45 seconds ago')

    def test_wireguard_parses_the_same_show_output(self):
        peers = WireGuardManager(show_ssh())._wg_show()
        self.assertEqual(peers['KEY_LIVE']['endpoint'], '203.0.113.10:51234')
        self.assertEqual(peers['KEY_V6']['endpoint'], '[2001:db8::10]:51820')
        self.assertEqual(peers['KEY_NONE']['endpoint'], '')
        self.assertEqual(peers['KEY_OFFLINE'].get('endpoint', ''), '')

    def test_empty_show_is_empty(self):
        self.assertEqual(AWGManager(show_ssh('', 1))._wg_show('awg'), {})
        self.assertEqual(WireGuardManager(show_ssh('', 1))._wg_show(), {})


class GetClientsEndpointTests(unittest.TestCase):
    def test_awg_copies_endpoint_onto_table_and_external_peers(self):
        mgr = AWGManager(Mock())
        mgr._get_clients_table = Mock(return_value=[{
            'clientId': 'KEY_LIVE',
            'userData': {'clientName': 'alice', 'clientIp': '10.8.1.17'},
        }])
        mgr._wg_show = Mock(return_value={
            'KEY_LIVE': {
                'latestHandshake': '45 seconds ago',
                'dataReceived': '1.2 MiB',
                'dataSent': '3.4 MiB',
                'dataReceivedBytes': 1258291,
                'dataSentBytes': 3565158,
                'allowedIps': '10.8.1.17/32',
                'endpoint': '203.0.113.10:51234',
            },
            'KEY_EXT': {
                'latestHandshake': '12 seconds ago',
                'dataReceived': '10 B',
                'dataSent': '20 B',
                'dataReceivedBytes': 10,
                'dataSentBytes': 20,
                'allowedIps': '10.8.1.18/32',
                'endpoint': '[2001:db8::10]:51820',
            },
            'KEY_OFFLINE': {
                'allowedIps': '10.8.1.20/32',
            },
        })
        mgr._parse_peers_from_config = Mock(return_value={
            'KEY_EXT': {'allowedIps': '10.8.1.18/32'},
            'KEY_OFFLINE': {'allowedIps': '10.8.1.20/32'},
        })
        mgr._load_conn_counts = Mock(return_value={'10.8.1.17': 1})
        mgr._load_conn_warnings = Mock(return_value={})

        clients = {c['clientId']: c['userData'] for c in mgr.get_clients('awg')}
        self.assertEqual(clients['KEY_LIVE']['endpoint'], '203.0.113.10:51234')
        self.assertEqual(clients['KEY_EXT']['endpoint'], '[2001:db8::10]:51820')
        self.assertEqual(clients['KEY_OFFLINE']['endpoint'], '')

    def test_wireguard_copies_endpoint_onto_table_and_external_peers(self):
        mgr = WireGuardManager(Mock())
        mgr._get_clients_table = Mock(return_value=[{
            'clientId': 'KEY_LIVE',
            'userData': {'clientName': 'alice', 'clientIp': '10.8.1.17'},
        }])
        mgr._wg_show = Mock(return_value={
            'KEY_LIVE': {
                'latestHandshake': '45 seconds ago',
                'dataReceived': '1.2 MiB',
                'dataSent': '3.4 MiB',
                'dataReceivedBytes': 1258291,
                'dataSentBytes': 3565158,
                'allowedIps': '10.8.1.17/32',
                'endpoint': '203.0.113.10:51234',
            },
            'KEY_EXT': {
                'allowedIps': '10.8.1.18/32',
                'endpoint': '198.51.100.8:9',
            },
        })
        mgr._parse_peers_from_config = Mock(return_value={
            'KEY_EXT': {'allowedIps': '10.8.1.18/32'},
        })

        clients = {c['clientId']: c['userData'] for c in mgr.get_clients()}
        self.assertEqual(clients['KEY_LIVE']['endpoint'], '203.0.113.10:51234')
        self.assertEqual(clients['KEY_EXT']['endpoint'], '198.51.100.8:9')


class ConnectionsApiEndpointTests(unittest.TestCase):
    def test_connections_api_forwards_peer_endpoint(self):
        data = {
            'servers': [{'name': 's'}],
            'user_connections': [],
            'users': [],
        }
        clients = [{
            'clientId': 'peer',
            'userData': {
                'clientName': 'alice',
                'clientIp': '10.8.1.2',
                'endpoint': '203.0.113.10:12345',
            },
        }]
        manager = Mock()
        manager.get_clients = Mock(return_value=clients)
        ssh = Mock()
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager):
            result = panel.api_get_connections(Mock(), 0, protocol='awg')
        self.assertEqual(result['clients'][0]['userData']['endpoint'], '203.0.113.10:12345')
        ssh.connect.assert_called_once()
        ssh.disconnect.assert_called_once()
        manager.get_clients.assert_called_once_with('awg')


class ConnectionsUiEndpointTests(unittest.TestCase):
    def setUp(self):
        self.page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        self.load = self.page.split('async function loadConnections(', 1)[1].split(
            'async function ', 1)[0]

    def test_load_connections_renders_escaped_endpoint(self):
        self.assertIn('userData.endpoint', self.load)
        self.assertIn('client-endpoint', self.load)
        self.assertIn("escapeHtml(endpoint)", self.load)
        self.assertIn("escapeHtml(_('peer_endpoint'))", self.load)
        # tunnel IP stays distinct from the public endpoint
        self.assertIn('client-ip', self.load)
        self.assertIn('${escapeHtml(name)}${ipHtml}${endpointHtml}', self.load)

    def test_rename_editor_strips_endpoint_from_the_name(self):
        rename = self.page.split('function startRenameConnection(', 1)[1].split(
            'async function ', 1)[0]
        self.assertIn('.client-ip, .client-endpoint', rename)

    def test_no_block_by_ip_actions(self):
        self.assertNotIn('block-ip', self.page)
        self.assertNotIn('blockByIp', self.page)
        self.assertNotIn('ip_history', self.page)


class TranslationKeyTests(unittest.TestCase):
    def test_peer_endpoint_key_is_present(self):
        for name in ('en', 'ru', 'fa', 'fr', 'zh'):
            table = json.loads((ROOT / 'translations' / f'{name}.json').read_text(encoding='utf-8'))
            self.assertTrue(table['peer_endpoint'].strip(), name)


if __name__ == '__main__':
    unittest.main()
