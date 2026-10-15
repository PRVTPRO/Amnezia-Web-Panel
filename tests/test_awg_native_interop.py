"""Native Amnezia clients must retain their address across panel toggles."""
import copy
import json
import re
import unittest
from unittest import mock

from managers.awg_manager import AWGManager
from tests.test_awg_config_cache import FakeSSH, CONFIG_PATH, CLIENTS_TABLE, SERVER_CONFIG


class NativeInteropTests(unittest.TestCase):
    def manager(self, entries, config=SERVER_CONFIG):
        ssh = FakeSSH({CONFIG_PATH: config, CLIENTS_TABLE: json.dumps(entries)})
        mgr = AWGManager(ssh)
        mgr._get_client_ipv6 = mock.Mock(return_value='')
        mgr._get_server_psk = mock.Mock(return_value='SERVER_PSK')
        return mgr, ssh

    def peers(self, ssh):
        peers = {}
        for block in ssh.files[CONFIG_PATH].split('[Peer]')[1:]:
            values = dict(re.findall(r'^([A-Za-z]+)\s*=\s*(.*?)\s*$', block, re.M))
            peers[values['PublicKey']] = {'allowed_ips': values['AllowedIPs'],
                                          'preshared_key': values.get('PresharedKey', '')}
        return peers

    def native(self, value=None, **extra):
        data = {'clientName': 'Native', 'enabled': False, **extra}
        if value is not None:
            data['allowed_ips'] = value
        return {'clientId': 'NATIVE', 'userData': data}

    def test_native_reservations_include_string_and_list_forms(self):
        for value in ('10.8.1.4/32', '10.8.1.4/32, fd42::4/128',
                      ['10.8.1.4/32', 'fd42::4/128'], ['fd42::4/128', '10.8.1.4']):
            with self.subTest(value=value):
                mgr, _ = self.manager([self.native(value)])
                self.assertEqual(mgr._get_next_ip('awg'), '10.8.1.5')

    def test_native_enable_restores_address_and_psk_sorted(self):
        config = SERVER_CONFIG.replace('10.8.1.3/32', '10.8.1.9/32')
        for value in ('10.8.1.5/32', ['fd42::5/128', '10.8.1.5/32']):
            with self.subTest(value=value):
                mgr, ssh = self.manager([self.native(value, psk='NATIVE_PSK')], config)
                mgr.toggle_client('awg', 'NATIVE', True)
                peers = self.peers(ssh)
                self.assertEqual(peers['NATIVE']['allowed_ips'], '10.8.1.5/32')
                self.assertEqual(peers['NATIVE']['preshared_key'], 'NATIVE_PSK')
                self.assertEqual(re.findall(r'AllowedIPs = (\S+)', ssh.files[CONFIG_PATH]),
                                 ['10.8.1.2/32', '10.8.1.5/32', '10.8.1.9/32'])
                self.assertTrue(json.loads(ssh.files[CLIENTS_TABLE])[0]['userData']['enabled'])

    def assert_rejected_without_mutation(self, entries, client_id='NATIVE', config=SERVER_CONFIG):
        entries = copy.deepcopy(entries)
        for entry in entries:
            # These cases exercise address validation, independently of PSK lookup.
            entry.setdefault('userData', {}).setdefault('psk', 'KNOWN_PSK')
        mgr, ssh = self.manager(entries, config)
        before = copy.deepcopy(ssh.files)
        with self.assertRaisesRegex(RuntimeError, '(?i)(not found|(address|IP).*(unavailable|unknown|missing|conflict|occupied|ambiguous|determin))'):
            mgr.toggle_client('awg', client_id, True)
        self.assertEqual(ssh.files, before)
        self.assertEqual(ssh.uploads, {})
        self.assertFalse(any('syncconf' in command for command in ssh.commands))

    def test_missing_native_or_unknown_address_is_not_allocated(self):
        for entries in ([self.native()], []):
            with self.subTest(entries=entries):
                self.assert_rejected_without_mutation(entries)

    def test_occupied_active_or_reserved_address_is_rejected(self):
        self.assert_rejected_without_mutation([self.native('10.8.1.2/32')])
        self.assert_rejected_without_mutation([
            self.native('10.8.1.5/32'),
            {'clientId': 'OTHER', 'userData': {'allowed_ips': ['10.8.1.5/32'], 'enabled': False}},
        ])

    def test_ambiguous_or_invalid_native_address_is_rejected(self):
        for value in (['10.8.1.5/32', '10.8.1.6/32'], '999.8.1.5/32', 'fd42::5/128'):
            with self.subTest(value=value):
                self.assert_rejected_without_mutation([self.native(value)])
        self.assert_rejected_without_mutation([self.native('10.8.1.5/32', clientIp='10.8.1.6')])

    def test_active_conflict_after_first_allowed_ip_is_rejected(self):
        config = SERVER_CONFIG.replace('10.8.1.2/32', '10.8.1.2/32, 10.8.1.5/32')
        self.assert_rejected_without_mutation([self.native('10.8.1.5/32')], config=config)

    def test_existing_duplicate_is_not_automatically_repaired(self):
        config = SERVER_CONFIG + '\n[Peer]\nPublicKey = NATIVE\nAllowedIPs = 10.8.1.2/32\n'
        self.assert_rejected_without_mutation([self.native('10.8.1.2/32')], config=config)

    def test_external_disable_enable_preserves_ip_and_peer_psk(self):
        mgr, ssh = self.manager([])
        mgr.toggle_client('awg', 'PEER_A', False)
        mgr.toggle_client('awg', 'PEER_A', True)
        peer = self.peers(ssh)['PEER_A']
        self.assertEqual(peer['allowed_ips'], '10.8.1.2/32')
        self.assertEqual(peer['preshared_key'], 'PSK_A')
        self.assertEqual(re.findall(r'AllowedIPs = (\S+)', ssh.files[CONFIG_PATH]),
                         ['10.8.1.2/32', '10.8.1.3/32'])

    def test_no_psk_round_trip_overwrites_stale_metadata(self):
        config = SERVER_CONFIG.replace('PresharedKey = PSK_A\n', '')
        for entries in ([], [{'clientId': 'PEER_A', 'userData': {'psk': 'STALE'}}]):
            with self.subTest(entries=entries):
                mgr, ssh = self.manager(entries, config)
                mgr.toggle_client('awg', 'PEER_A', False)
                data = json.loads(ssh.files[CLIENTS_TABLE])[0]['userData']
                self.assertIn('psk', data)
                self.assertEqual(data['psk'], '')
                mgr.toggle_client('awg', 'PEER_A', True)
                block = next(b for b in ssh.files[CONFIG_PATH].split('[Peer]')[1:]
                             if 'PEER_A' in b)
                self.assertNotIn('PresharedKey', block)
                mgr._get_server_psk.assert_not_called()

    def test_explicit_empty_psk_never_uses_global_fallback(self):
        for extra in ({}, {'clientPrivateKey': 'PRIVATE'}):
            with self.subTest(extra=extra):
                mgr, ssh = self.manager([self.native('10.8.1.5/32', psk='', **extra)])
                mgr.toggle_client('awg', 'NATIVE', True)
                block = next(b for b in ssh.files[CONFIG_PATH].split('[Peer]')[1:]
                             if 'NATIVE' in b)
                self.assertNotIn('PresharedKey', block)
                mgr._get_server_psk.assert_not_called()

    def test_unknown_native_psk_is_rejected_without_mutation(self):
        mgr, ssh = self.manager([self.native('10.8.1.5/32')])
        before = copy.deepcopy(ssh.files)
        with self.assertRaisesRegex(RuntimeError, 'PSK|preshared key'):
            mgr.toggle_client('awg', 'NATIVE', True)
        self.assertEqual(ssh.files, before)
        mgr._get_server_psk.assert_not_called()
        self.assertFalse(any('syncconf' in cmd or 'docker cp' in cmd
                             for cmd in ssh.commands))

    def test_repeated_disable_does_not_invent_psk(self):
        mgr, ssh = self.manager([self.native('10.8.1.5/32')])
        mgr.toggle_client('awg', 'NATIVE', False)
        self.assertNotIn('psk', json.loads(ssh.files[CLIENTS_TABLE])[0]['userData'])
        mgr._get_server_psk.assert_not_called()

    def test_panel_client_with_private_key_can_still_allocate_missing_address(self):
        mgr, ssh = self.manager([self.native(clientPrivateKey='PANEL_PRIVATE')])
        mgr.toggle_client('awg', 'NATIVE', True)
        self.assertEqual(self.peers(ssh)['NATIVE']['allowed_ips'], '10.8.1.4/32')
        self.assertEqual(self.peers(ssh)['NATIVE']['preshared_key'], 'SERVER_PSK')
        mgr._get_server_psk.assert_called_once_with('awg')


if __name__ == '__main__':
    unittest.main()
