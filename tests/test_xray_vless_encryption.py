"""VLESS Encryption toggle (Vision over XHTTP): server-side pair minting,
flow/encryption link derivation from the runtime config."""
import base64
import json
import unittest
import urllib.parse
from unittest.mock import Mock, patch

import app as panel
from managers.xray_manager import VLESS_ENC_KEY_FILE, XrayManager
from xray_fixtures import remote_answers

XHTTP_CONFIG = {
    'log': {'loglevel': 'error'},
    'inbounds': [{
        'protocol': 'vless', 'port': 443, 'tag': 'proxy',
        'settings': {'clients': [{'id': 'peer-1', 'email': 'peer-1',
                                  'flow': ''}], 'decryption': 'none'},
        'streamSettings': {
            'network': 'xhttp', 'security': 'reality',
            'xhttpSettings': {'path': '/abc', 'host': 'own.example', 'mode': 'auto'},
            'realitySettings': {'dest': 'mask:443', 'serverNames': ['own.example'],
                                'privateKey': 'PRIV', 'shortIds': ['SID']},
        },
        'sniffing': {'enabled': True},
    }],
    'outbounds': [{'protocol': 'freedom', 'domainStrategy': 'UseIPv4'}],
}


def make_manager(vlessenc_output, config=None):
    ssh = Mock()
    ssh.run_sudo_command = Mock(side_effect=remote_answers(vlessenc_output))
    manager = XrayManager(ssh)
    manager._get_server_json = lambda: config
    uploads = []
    ssh.upload_file_sudo = lambda content, path, mode=None: uploads.append((content, path))
    manager.uploads = uploads
    manager.sudo = []
    real_sudo = ssh.run_sudo_command

    def sudo(command, **kwargs):
        manager.sudo.append(command)
        return real_sudo(command, **kwargs)
    ssh.run_sudo_command = sudo
    return manager, ssh


class EncryptionStateTests(unittest.TestCase):
    def test_enabled_reflected_from_the_inbound(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['settings']['decryption'] = 'mlkem768x25519plus.native.600s.K'
        manager, _ = make_manager('', config)
        state = manager.get_vless_encryption_state()
        self.assertEqual(state, {'enabled': True, 'transport': 'xhttp',
                                 'decryption': 'mlkem768x25519plus.native.600s.K'})

    def test_disabled_when_decryption_is_none(self):
        manager, _ = make_manager('', XHTTP_CONFIG)
        state = manager.get_vless_encryption_state()
        self.assertEqual(state, {'enabled': False, 'transport': 'xhttp',
                                 'decryption': 'none'})

    def test_transport_is_reported_for_the_toggle_guard(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['streamSettings']['network'] = 'tcp'
        manager, _ = make_manager('', config)
        self.assertEqual(manager.get_vless_encryption_state()['transport'], 'tcp')


class ToggleTests(unittest.TestCase):
    VLESSENC_OUT = json.dumps({
        'decryption': 'mlkem768x25519plus.native.600s.ServerPriv',
        'encryption': 'mlkem768x25519plus.native.0rtt.ServerPub.ClientPart'})

    def test_enable_mints_pair_sets_vision_flow_and_restarts(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        manager, ssh = make_manager(self.VLESSENC_OUT, config)

        state = manager.set_vless_encryption(True)

        self.assertTrue(state['enabled'])
        self.assertEqual(state['transport'], 'xhttp')
        inbound = config['inbounds'][0]
        self.assertEqual(inbound['settings']['decryption'],
                         'mlkem768x25519plus.native.600s.ServerPriv')
        self.assertEqual(inbound['settings']['clients'][0]['flow'],
                         'xtls-rprx-vision')
        # the matched pair is installed for the link builder: staged beside
        # the live key file as a private file, then renamed over it, in the
        # same write as the configuration
        staged = [(content, path) for content, path in manager.uploads
                  if path.startswith(f'/opt/amnezia/xray/.{VLESS_ENC_KEY_FILE}.')]
        self.assertEqual(len(staged), 1)
        self.assertEqual(json.loads(staged[0][0]), json.loads(self.VLESSENC_OUT))
        self.assertIn(f'mv -f -- {staged[0][1]} /opt/amnezia/xray/{VLESS_ENC_KEY_FILE}',
                      manager.sudo)
        # the core is stopped and started again (and watched until it is back)
        self.assertTrue(any(cmd.startswith('docker stop ') for cmd in manager.sudo))
        self.assertTrue(any(cmd.startswith('docker start ') for cmd in manager.sudo))

    def test_enable_requires_the_xhttp_transport(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['streamSettings']['network'] = 'tcp'
        manager, _ = make_manager('', config)
        with self.assertRaises(RuntimeError):
            manager.set_vless_encryption(True)

    def test_unparsable_vlessenc_output_is_rejected(self):
        manager, _ = make_manager('??? garbage ???', XHTTP_CONFIG)
        with self.assertRaises(RuntimeError):
            manager.set_vless_encryption(True)

    def test_disable_reverts_to_none_and_empty_flows(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['settings']['decryption'] = 'mlkem768x25519plus.native.600s.K'
        config['inbounds'][0]['settings']['clients'][0]['flow'] = 'xtls-rprx-vision'
        manager, ssh = make_manager('', config)

        manager.set_vless_encryption(False)

        inbound = config['inbounds'][0]
        self.assertEqual(inbound['settings']['decryption'], 'none')
        self.assertEqual(inbound['settings']['clients'][0]['flow'], '')
        self.assertTrue(any('rm -f' in cmd and 'xray_vlessenc.key' in cmd
                            for cmd in manager.sudo))


class LinkDerivationTests(unittest.TestCase):
    def _manager(self, config, client_encryption=''):
        manager = XrayManager(Mock())
        manager._get_clients_table = lambda: [
            {'clientId': 'peer-1', 'userData': {'clientName': 'phone', 'enabled': True}}]
        manager._get_meta_json = lambda: {
            'public_key': 'PBK', 'short_id': 'SID', 'port': 443,
            'site_name': 'own.example',
            'vless_client_encryption': client_encryption}
        manager._get_server_json = lambda: config
        return manager

    def test_encryption_and_vision_flow_ride_the_xhttp_link(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['settings']['decryption'] = \
            'mlkem768x25519plus.native.600s.ServerPriv'
        config['inbounds'][0]['settings']['clients'][0]['flow'] = 'xtls-rprx-vision'
        manager = self._manager(
            config, client_encryption='mlkem768x25519plus.native.0rtt.E')
        manager._read_vlessenc_pair = lambda: {
            'decryption': 'mlkem768x25519plus.native.600s.ServerPriv',
            'encryption': 'mlkem768x25519plus.native.0rtt.E'}

        link = manager.get_client_config('xray', 'peer-1', '203.0.113.9', 443)
        query = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(link).query, keep_blank_values=True))
        self.assertEqual(query['type'], 'xhttp')
        self.assertEqual(query['flow'], 'xtls-rprx-vision')
        self.assertEqual(query['encryption'],
                         'mlkem768x25519plus.native.0rtt.E')

    def test_without_the_layer_xhttp_links_carry_no_flow_or_encryption(self):
        manager = self._manager(json.loads(json.dumps(XHTTP_CONFIG)))
        manager._read_vlessenc_pair = lambda: {}
        link = manager.get_client_config('xray', 'peer-1', '203.0.113.9', 443)
        query = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(link).query, keep_blank_values=True))
        self.assertNotIn('flow', query)
        self.assertNotIn('encryption', query)

    def test_a_leftover_key_file_does_not_reach_a_link_once_the_layer_is_off(self):
        manager = self._manager(json.loads(json.dumps(XHTTP_CONFIG)))
        manager._read_vlessenc_pair = lambda: {'decryption': 'native.gone',
                                               'encryption': 'native.0rtt.E'}
        link = manager.get_client_config('xray', 'peer-1', '203.0.113.9', 443)
        self.assertNotIn('encryption=', link)

    def test_no_link_is_issued_while_the_layer_is_on_and_the_key_file_is_gone(self):
        # a toggle off that stopped half-way used to leave exactly this:
        # the core demands the layer, and the link could not carry it
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['settings']['decryption'] = \
            'mlkem768x25519plus.native.600s.ServerPriv'
        manager = self._manager(
            config, client_encryption='mlkem768x25519plus.native.0rtt.E')
        manager._read_vlessenc_pair = lambda: {}
        with self.assertRaises(RuntimeError) as ctx:
            manager.get_client_config('xray', 'peer-1', '203.0.113.9', 443)
        self.assertIn('no client link can be issued', str(ctx.exception))

    def test_no_link_is_issued_while_the_key_file_belongs_to_another_pair(self):
        # a re-mint whose configuration did not stay would have left the
        # client string of a new pair next to the server string of the old
        config = json.loads(json.dumps(XHTTP_CONFIG))
        config['inbounds'][0]['settings']['decryption'] = \
            'mlkem768x25519plus.native.600s.ServerPriv'
        manager = self._manager(
            config, client_encryption='mlkem768x25519plus.native.0rtt.E')
        manager._read_vlessenc_pair = lambda: {
            'decryption': 'mlkem768x25519plus.native.600s.AnotherServer',
            'encryption': 'mlkem768x25519plus.native.0rtt.E'}
        with self.assertRaises(RuntimeError) as ctx:
            manager.get_client_config('xray', 'peer-1', '203.0.113.9', 443)
        self.assertIn('no client link can be issued', str(ctx.exception))



if __name__ == '__main__':
    unittest.main()
