import unittest
from unittest.mock import Mock

from managers.xray_manager import XrayManager


class XrayClientTests(unittest.TestCase):
    def test_add_client_accepts_inactive_warp_context(self):
        manager = XrayManager(Mock())
        config = {
            'inbounds': [{
                'protocol': 'vless',
                'settings': {'clients': []},
            }],
        }
        saved_tables = []
        manager._get_server_json = lambda: config
        manager._upgrade_config_for_stats = lambda *args, **kwargs: None
        manager._xray_api_add_user = lambda *args: True
        manager._write_server_json = lambda *args, **kwargs: None
        manager._get_clients_table = lambda: []
        manager._save_clients_table = saved_tables.append
        manager.get_client_config = lambda *args, **kwargs: 'vless://example'

        result = manager.add_client(
            'xray', 'phone', 'vpn.example.com', 443,
            warp_ctx={'active': False},
        )

        self.assertEqual(result['config'], 'vless://example')
        self.assertEqual(config['inbounds'][0]['settings']['clients'][0]['id'],
                         result['client_id'])
        self.assertEqual(saved_tables[0][0]['userData']['clientName'], 'phone')

    def test_strict_client_table_read_rejects_unknown_or_malformed_state(self):
        for response in (('', 'connection lost', -1), ('not-json', '', 0)):
            with self.subTest(response=response):
                ssh = Mock()
                ssh.run_sudo_command.return_value = response
                manager = XrayManager(ssh)
                manager._detect_layout = lambda: 'native'
                with self.assertRaises(RuntimeError):
                    manager._get_clients_table(strict=True)

    def test_strict_client_table_accepts_a_readable_empty_file(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ('', '', 0)
        manager = XrayManager(ssh)
        manager._detect_layout = lambda: 'native'
        self.assertEqual(manager._get_clients_table(strict=True), [])


if __name__ == '__main__':
    unittest.main()
