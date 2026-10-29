"""Official Amnezia app appends [Peer] without a leading newline (#252)."""
import json
import unittest
from unittest.mock import patch

from managers.awg_manager import AWGManager
from tests.test_awg_config_cache import FakeSSH, CONFIG_PATH, CLIENTS_TABLE, SERVER_CONFIG, peer_block


class StrippingSSH(FakeSSH):
    def run_sudo_command(self, command, timeout=60):
        out, err, code = super().run_sudo_command(command, timeout)
        # Production SSHManager strips stdout, including the config's last LF.
        return out.strip(), err.strip(), code


class ConfigNewlineTests(unittest.TestCase):
    def manager(self, protocol, content=SERVER_CONFIG):
        path = '/opt/amnezia/awg/wg0.conf' if protocol == 'awg_legacy' else CONFIG_PATH
        ssh = StrippingSSH({path: content, CLIENTS_TABLE: json.dumps([
            {'clientId': 'PEER_A', 'userData': {'enabled': True}},
            {'clientId': 'PEER_B', 'userData': {'enabled': True}},
        ])})
        return AWGManager(ssh), ssh, path

    def assert_append_safe(self, content):
        self.assertTrue(content.endswith('\n'), repr(content[-100:]))
        self.assertFalse(content.endswith('\n\n'))
        appended = content + '[Peer]\nPublicKey = APP_PEER\nAllowedIPs = 10.8.1.9/32\n'
        self.assertIn('\n[Peer]\nPublicKey = APP_PEER', appended)
        self.assertIn('PrivateKey = SERVERPRIVATEKEY', content)
        self.assertIn('PublicKey = PEER_A', content)
        self.assertIn('PresharedKey = PSK_A', content)
        self.assertIn('AllowedIPs = 10.8.1.2/32', content)

    def test_create_then_delete_keeps_append_boundary_all_variants(self):
        for protocol in ('awg', 'awg2', 'awg3', 'awg_legacy', 'awg__2'):
            with self.subTest(protocol=protocol):
                mgr, ssh, path = self.manager(protocol)
                mgr._insert_peer_sorted(protocol, peer_block('PEER_C', '10.8.1.4'))
                mgr.remove_client(protocol, 'PEER_B')
                self.assertNotIn('PEER_B', ssh.files[path])
                self.assert_append_safe(ssh.files[path])

    def test_disable_keeps_append_boundary(self):
        mgr, ssh, path = self.manager('awg2')
        mgr.toggle_client('awg2', 'PEER_B', False)
        self.assert_append_safe(ssh.files[path])

    def test_manual_save_normalizes_missing_lf_and_crlf(self):
        for suffix in ('', '\n', '\n\n', '\r\n\r\n'):
            with self.subTest(suffix=suffix):
                mgr, ssh, path = self.manager('awg2')
                with patch.object(mgr, '_write_start_script'):
                    mgr.save_server_config('awg2', SERVER_CONFIG.rstrip('\n') + suffix)
                self.assert_append_safe(ssh.files[path])

    def test_settings_writer_normalizes_eof_without_touching_config_body(self):
        mgr, ssh, path = self.manager('awg2')
        original = SERVER_CONFIG.rstrip('\n').replace('\n', '\r\n')
        mgr._write_server_config('awg2', original)
        self.assertEqual(ssh.files[path], SERVER_CONFIG)
        self.assert_append_safe(ssh.files[path])

    def test_disable_then_enable_keeps_append_boundary(self):
        mgr, ssh, path = self.manager('awg2')
        mgr.toggle_client('awg2', 'PEER_B', False)
        with patch.object(mgr, '_get_client_ipv6', return_value=''):
            mgr.toggle_client('awg2', 'PEER_B', True)
        self.assertIn('PublicKey = PEER_B', ssh.files[path])
        self.assert_append_safe(ssh.files[path])
