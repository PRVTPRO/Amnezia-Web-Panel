"""Self-steal: point Reality at the local NGINX site (own domain, real cert)."""
import unittest
from unittest.mock import Mock

import app as panel

from managers.xray_manager import XrayManager


def make_manager(config=None):
    manager = XrayManager(Mock())
    manager._get_server_json = lambda: config
    written = {}
    manager._write_server_json = lambda data, restart=True: written.update(
        data=data, restart=restart)
    manager.written = written
    return manager


class ApplySelfstealTests(unittest.TestCase):
    def test_updates_reality_and_xhttp_host_then_restarts(self):
        config = {
            'inbounds': [{
                'protocol': 'vless',
                'settings': {'clients': []},
                'streamSettings': {
                    'network': 'xhttp',
                    'security': 'reality',
                    'xhttpSettings': {'path': '/abc', 'host': 'old.example'},
                    'realitySettings': {
                        'dest': 'old.example:443',
                        'serverNames': ['old.example'],
                        'privateKey': 'PRIV',
                        'shortIds': ['SID'],
                    },
                },
            }],
        }
        manager = make_manager(config)

        result = manager.apply_selfsteal('own.example', 'amnezia-nginx:443')

        stream = config['inbounds'][0]['streamSettings']
        reality = stream['realitySettings']
        self.assertEqual(reality['dest'], 'amnezia-nginx:443')
        self.assertEqual(reality['serverNames'], ['own.example'])
        self.assertEqual(stream['xhttpSettings']['host'], 'own.example')
        self.assertEqual(reality['privateKey'], 'PRIV')
        self.assertEqual(reality['shortIds'], ['SID'])
        self.assertEqual(manager.written['restart'], True)
        self.assertEqual(result, {'dest': 'amnezia-nginx:443', 'sni': 'own.example',
                                  'network': 'xhttp'})

    def test_tcp_config_keeps_transport_fields_untouched(self):
        config = {
            'inbounds': [{
                'protocol': 'vless',
                'streamSettings': {
                    'network': 'tcp',
                    'security': 'reality',
                    'realitySettings': {'dest': 'yahoo.com:443',
                                        'serverNames': ['yahoo.com']},
                },
            }],
        }
        manager = make_manager(config)

        result = manager.apply_selfsteal('own.example', '10.0.0.5:443')

        stream = config['inbounds'][0]['streamSettings']
        self.assertNotIn('xhttpSettings', stream)
        self.assertEqual(result['network'], 'tcp')
        self.assertEqual(stream['realitySettings']['dest'], '10.0.0.5:443')

    def test_missing_reality_is_rejected_without_a_write(self):
        config = {
            'inbounds': [{
                'protocol': 'vless',
                'streamSettings': {'network': 'tcp', 'security': 'tls'},
            }],
        }
        manager = make_manager(config)
        with self.assertRaises(RuntimeError):
            manager.apply_selfsteal('own.example', 'amnezia-nginx:443')
        self.assertNotIn('data', manager.written)


class RealityStateTests(unittest.TestCase):
    def test_state_reads_transport_dest_and_sni(self):
        config = {
            'inbounds': [{
                'protocol': 'vless',
                'streamSettings': {
                    'network': 'xhttp',
                    'realitySettings': {'serverNames': ['own.example'],
                                        'dest': 'amnezia-nginx:443'},
                },
            }],
        }
        manager = make_manager(config)
        self.assertEqual(manager.get_reality_state(),
                         {'network': 'xhttp', 'dest': 'amnezia-nginx:443',
                          'sni': 'own.example'})

    def test_state_is_none_without_config(self):
        self.assertIsNone(make_manager(None).get_reality_state())


class SelfstealHelpersTests(unittest.TestCase):
    def test_shared_network_resolves_the_container_name(self):
        dest = panel._selfsteal_dest({'amnezia-dns-net': {'IPAddress': '172.20.0.5'}},
                                     {'amnezia-dns-net': {'IPAddress': '172.20.0.9'}},
                                     'amnezia-nginx')
        self.assertEqual(dest, 'amnezia-nginx:443')

    def test_without_shared_network_falls_back_to_the_nginx_ip(self):
        dest = panel._selfsteal_dest({'bridge': {'IPAddress': '172.17.0.3'}},
                                     {'bridge2': {'IPAddress': '172.18.0.7'}},
                                     'amnezia-nginx')
        self.assertEqual(dest, '172.18.0.7:443')

    def test_no_networks_yields_no_dest(self):
        self.assertIsNone(panel._selfsteal_dest({}, {}, 'amnezia-nginx'))

    def test_site_check_demands_a_three_digit_curl_answer(self):
        ssh = Mock()
        ssh.run_command.return_value = ('200', '', 0)
        self.assertTrue(panel._selfsteal_site_ok(ssh, 'own.example', 443))
        ssh.run_command.return_value = ('', '', 1)
        self.assertFalse(panel._selfsteal_site_ok(ssh, 'own.example', 443))
        ssh.run_command.return_value = ('', '', 0)
        self.assertFalse(panel._selfsteal_site_ok(ssh, 'own.example', 443))


if __name__ == '__main__':
    unittest.main()
