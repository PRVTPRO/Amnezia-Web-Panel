"""AWG client AllowedIPs must enable AmneziaVPN split tunneling.

AmneziaVPN treats a peer AllowedIPs line without ::/0 as a non-full-tunnel
server and disables split tunneling in the client UI (issues #158/#193).
The panel must emit both default routes even on IPv4-only tunnels; this does
not require assigning the client an IPv6 address or enabling AWG_IPV6.
"""

import unittest
from unittest import mock

from managers.awg_manager import AWGManager


CLIENT = {
    'clientId': 'peer',
    'userData': {
        'clientPrivateKey': 'priv',
        'clientIp': '10.8.1.6',
        'psk': 'psk',
    },
}


def make_manager(client_ipv6=''):
    mgr = AWGManager(mock.Mock())
    mgr._get_clients_table = lambda proto: [CLIENT]
    mgr._get_client_ipv6 = lambda proto, ip: client_ipv6
    mgr._get_server_public_key = lambda proto: 'serverpub'
    mgr._get_server_psk = lambda proto: 'serverpsk'
    mgr._get_awg_params_from_config = lambda proto: {}
    mgr._get_dns = lambda proto, ud: '1.1.1.1'
    mgr._get_mtu = lambda proto, ud: '1376'
    return mgr


class AwgSplitTunnelAllowedIpsTests(unittest.TestCase):
    def test_get_client_config_includes_ipv6_default_on_ipv4_only_tunnel(self):
        config = make_manager('').get_client_config(
            'awg2', 'peer', '203.0.113.9', '55424')
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', config)
        address = next(line for line in config.splitlines() if line.startswith('Address ='))
        self.assertEqual(address, 'Address = 10.8.1.6/32')

    def test_get_client_config_keeps_dual_stack_address_when_ipv6_assigned(self):
        mgr = make_manager('fd42:8:1::6')
        mgr._get_dns6 = lambda proto, ud=None: 'fd42:8:1::1'
        config = mgr.get_client_config('awg2', 'peer', '203.0.113.9', '55424')
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', config)
        self.assertIn('Address = 10.8.1.6/32, fd42:8:1::6/128', config)


if __name__ == '__main__':
    unittest.main()
