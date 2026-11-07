"""Unit tests for AWGManager IPv6 client behaviour.

No SSH is opened: the server-config read and the key reads are patched on
the manager. The tests pin the IPv6 contract the client configs rely on:
the deterministic client IPv6 derivation, the IPv6 DNS selection rules and
the ipv6_enabled flag, plus the generated client config text (AllowedIPs
keeps both default routes; DNS6 is added only on dual-stack tunnels).
"""
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager, AWG_DEFAULTS


def make_manager():
    """Manager whose remote calls all answer empty/OK, ready to patch."""
    ssh = Mock()
    ssh.run_sudo_command.return_value = ('', '', 0)
    ssh.docker_container_state.return_value = (True, True)
    return AWGManager(ssh)


DUAL_STACK_CONFIG = (
    "[Interface]\n"
    "Address = 10.8.1.1/24, fd42:8:1::1/64\n"
    "ListenPort = 55424\n"
    "PrivateKey = AAECAwQFBgcICQoLDA0ODw==\n"
)

IPV4_ONLY_CONFIG = (
    "[Interface]\n"
    "Address = 10.8.1.1/24\n"
    "ListenPort = 55424\n"
    "PrivateKey = AAECAwQFBgcICQoLDA0ODw==\n"
)

DNS6_COMMENT_CONFIG = (
    "[Interface]\n"
    "Address = 10.8.1.1/24, fd42:8:1::1/64\n"
    "# DNS6 = 2001:db8::53\n"
    "ListenPort = 55424\n"
)


class ClientIpv6Tests(unittest.TestCase):
    def test_derives_the_last_hextet_from_the_ipv4_octet(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=DUAL_STACK_CONFIG)
        self.assertEqual(manager._get_client_ipv6('awg3', '10.8.1.10'),
                         'fd42:8:1::a')

    def test_octet_37_maps_to_the_hex_hextet_25(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=DUAL_STACK_CONFIG)
        self.assertEqual(manager._get_client_ipv6('awg3', '10.8.1.37'),
                         'fd42:8:1::25')

    def test_returns_empty_when_the_tunnel_has_no_ipv6_gateway(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=IPV4_ONLY_CONFIG)
        self.assertEqual(manager._get_client_ipv6('awg3', '10.8.1.10'), '')


class DnsSixTests(unittest.TestCase):
    def test_per_client_override_wins(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=DNS6_COMMENT_CONFIG)
        self.assertEqual(manager._get_dns6('awg3', {'dns6': 'fd00::1'}),
                         'fd00::1')

    def test_comment_line_wins_over_the_default(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=DNS6_COMMENT_CONFIG)
        self.assertEqual(manager._get_dns6('awg3'), '2001:db8::53')

    def test_dual_stack_instance_falls_back_to_the_default(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=DUAL_STACK_CONFIG)
        self.assertEqual(manager._get_dns6('awg3'), AWG_DEFAULTS['dns6'])

    def test_ipv4_only_instance_has_no_ipv6_dns(self):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=IPV4_ONLY_CONFIG)
        self.assertEqual(manager._get_dns6('awg3'), '')


class AwgSettingsTests(unittest.TestCase):
    def _settings(self, config):
        manager = make_manager()
        manager._get_server_config = Mock(return_value=config)
        manager.exit_link_info = Mock(return_value=None)
        return manager.get_awg_settings('awg3')

    def test_ipv6_enabled_true_from_the_address_line(self):
        settings = self._settings(DUAL_STACK_CONFIG)
        self.assertTrue(settings['ipv6_enabled'])
        self.assertEqual(settings['dns6'], AWG_DEFAULTS['dns6'])
        self.assertEqual(settings['mtu'], '1376')

    def test_ipv6_enabled_false_from_the_address_line(self):
        settings = self._settings(IPV4_ONLY_CONFIG)
        self.assertFalse(settings['ipv6_enabled'])
        self.assertEqual(settings['dns6'], '')


class ClientConfigTests(unittest.TestCase):
    def _manager(self, client_ipv6='fd42:8:1::a',
                 dns6='2606:4700:4700::1111'):
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[{
            'clientId': 'CLIENT_PUB',
            'userData': {
                'clientName': 'alice',
                'clientPrivateKey': 'client_priv',
                'clientIp': '10.8.1.10',
                'psk': 'psk',
                'clientIpv6': client_ipv6,
                'enabled': True,
            },
        }])
        manager._get_server_public_key = Mock(return_value='SERVER_PUB')
        manager._get_server_psk = Mock(return_value='PSK')
        manager._get_awg_params_from_config = Mock(
            return_value={'port': '55424'})
        manager._get_mtu = Mock(return_value='1376')
        manager._get_dns = Mock(return_value='1.1.1.1, 1.0.0.1')
        manager._get_dns6 = Mock(return_value=dns6)
        manager._get_client_ipv6 = Mock(return_value=client_ipv6)
        return manager

    def _config(self, manager):
        return manager.get_client_config('awg3', 'CLIENT_PUB',
                                         'vpn.example.com', 55424)

    def test_dual_stack_config_keeps_both_routes_and_adds_dns6(self):
        config = self._config(self._manager())
        self.assertIn('Address = 10.8.1.10/32, fd42:8:1::a/128', config)
        self.assertIn('DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111', config)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', config)
        self.assertIn('Endpoint = vpn.example.com:55424', config)
        self.assertIn('PersistentKeepalive = 25', config)

    def test_ipv4_only_config_keeps_both_routes_but_omits_dns6(self):
        config = self._config(self._manager(client_ipv6='', dns6=''))
        self.assertIn('Address = 10.8.1.10/32', config)
        self.assertNotIn('fd42:8:1::a', config)
        self.assertNotIn('2606:4700:4700::1111', config)
        self.assertIn('DNS = 1.1.1.1, 1.0.0.1', config)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', config)


if __name__ == '__main__':
    unittest.main()
