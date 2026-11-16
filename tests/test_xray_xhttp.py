"""XHTTP transport preset: randomized install settings, links derived from
the live server.json, and the client-config export round trip."""
import json
import random
import unittest
import urllib.parse
from unittest.mock import Mock

import app as panel

from managers.xray_manager import XrayManager, _client_flow, _xhttp_extra


META = {'public_key': 'PBK', 'short_id': 'SID', 'port': 443, 'site_name': 'own.example'}

XHTTP_CONFIG = {
    'inbounds': [{
        'protocol': 'vless',
        'settings': {'clients': []},
        'streamSettings': {
            'network': 'xhttp',
            'security': 'reality',
            'xhttpSettings': {
                'path': '/abc123',
                'host': 'own.example',
                'mode': 'auto',
                'extra': {'xPaddingBytes': '100-1000',
                          'xmux': {'maxConcurrency': '8-16'}},
            },
            'realitySettings': {'serverNames': ['own.example']},
        },
    }],
}

TCP_CONFIG = {
    'inbounds': [{
        'protocol': 'vless',
        'settings': {'clients': []},
        'streamSettings': {
            'network': 'tcp',
            'security': 'reality',
            'realitySettings': {'serverNames': ['yahoo.com']},
        },
    }],
}


def make_link_manager(config):
    manager = XrayManager(Mock())
    manager._get_clients_table = lambda: [{
        'clientId': 'UUID-1',
        'userData': {'clientName': 'phone', 'enabled': True},
    }]
    manager._get_meta_json = lambda: dict(META)
    manager._get_server_json = lambda: config
    return manager


class XhttpInstallTests(unittest.TestCase):
    def _install(self, **kwargs):
        manager = XrayManager(Mock())
        manager.check_docker_installed = lambda: True
        manager.check_protocol_installed = lambda: False
        manager._config_dir = lambda: '/opt/amnezia/xray'
        manager.ssh.run_sudo_command = lambda *a, **k: ('', '', 0)
        manager.ssh.run_command = lambda *a, **k: ('', '', 0)
        uploads = []
        manager.ssh.upload_file_sudo = lambda content, path: uploads.append((content, path))
        manager.install_protocol(**kwargs)
        raw = next(content for content, path in uploads if path.endswith('/server.json'))
        return json.loads(raw)

    def test_xhttp_install_writes_xhttp_settings_with_random_ranges(self):
        server_json = self._install(port=8443, site_name='own.example', transport='xhttp')
        stream = server_json['inbounds'][0]['streamSettings']
        self.assertEqual(stream['network'], 'xhttp')
        settings = stream['xhttpSettings']
        self.assertTrue(settings['path'].startswith('/') and len(settings['path']) > 1)
        self.assertEqual(settings['host'], 'own.example')
        self.assertEqual(settings['mode'], 'auto')

        extra = settings['extra']
        low, high = extra['xPaddingBytes'].split('-')
        self.assertLess(int(low), int(high))
        low, high = extra['scStreamUpServerSecs'].split('-')
        self.assertLess(int(low), int(high))
        xmux = extra['xmux']
        for field in ('maxConcurrency', 'hMaxRequestTimes', 'hMaxReusableSecs'):
            low, high = xmux[field].split('-')
            self.assertLess(int(low), int(high), field)
        self.assertEqual(xmux['maxConnections'], 0)
        self.assertEqual(xmux['cMaxReuseTimes'], 0)
        self.assertEqual(xmux['hKeepAlivePeriod'], 0)

        reality = stream['realitySettings']
        self.assertEqual(reality['dest'], 'own.example:443')
        self.assertEqual(reality['serverNames'], ['own.example'])

    def test_tcp_install_keeps_the_legacy_preset(self):
        server_json = self._install(port=443, site_name='yahoo.com')
        stream = server_json['inbounds'][0]['streamSettings']
        self.assertEqual(stream['network'], 'tcp')
        self.assertNotIn('xhttpSettings', stream)
        self.assertEqual(stream['realitySettings']['dest'], 'yahoo.com:443')

    def test_unknown_transport_is_rejected_before_any_ssh_work(self):
        manager = XrayManager(Mock())
        manager.check_docker_installed = lambda: True
        manager.check_protocol_installed = lambda: False
        manager._config_dir = lambda: '/opt/amnezia/xray'
        with self.assertRaises(ValueError):
            manager.install_protocol(port=443, transport='ws')

    def test_extra_bounds_shift_between_installs(self):
        random.seed(1)
        first = _xhttp_extra()
        random.seed(2)
        second = _xhttp_extra()
        self.assertNotEqual(first['xPaddingBytes'], second['xPaddingBytes'])
        self.assertNotEqual(first['xmux']['maxConcurrency'],
                            second['xmux']['maxConcurrency'])


class XhttpLinkTests(unittest.TestCase):
    def test_link_is_derived_from_the_live_xhttp_settings(self):
        manager = make_link_manager(XHTTP_CONFIG)
        parts = urllib.parse.urlsplit(
            manager.get_client_config('xray', 'UUID-1', '203.0.113.9', 443))
        self.assertEqual(parts.scheme, 'vless')
        self.assertEqual(parts.hostname, '203.0.113.9')
        self.assertEqual(parts.port, 443)
        self.assertEqual(parts.fragment, 'phone')
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        self.assertEqual(query['type'], 'xhttp')
        self.assertNotIn('flow', query)
        self.assertEqual(query['security'], 'reality')
        self.assertEqual(query['pbk'], 'PBK')
        self.assertEqual(query['sid'], 'SID')
        self.assertEqual(query['sni'], 'own.example')
        self.assertEqual(query['path'], '/abc123')
        self.assertEqual(query['host'], 'own.example')
        self.assertEqual(query['mode'], 'auto')
        self.assertEqual(json.loads(query['extra']), XHTTP_CONFIG['inbounds'][0]
                         ['streamSettings']['xhttpSettings']['extra'])

    def test_missing_xhttp_host_falls_back_to_the_sni(self):
        config = json.loads(json.dumps(XHTTP_CONFIG))
        del config['inbounds'][0]['streamSettings']['xhttpSettings']['host']
        manager = make_link_manager(config)
        parts = urllib.parse.urlsplit(
            manager.get_client_config('xray', 'UUID-1', '203.0.113.9', 443))
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        self.assertEqual(query['host'], 'own.example')

    def test_legacy_tcp_link_is_unchanged(self):
        manager = make_link_manager(TCP_CONFIG)
        link = manager.get_client_config('xray', 'UUID-1', '203.0.113.9', 443)
        self.assertEqual(
            link,
            'vless://UUID-1@203.0.113.9:443?type=tcp&security=reality&pbk=PBK'
            '&sni=yahoo.com&fp=chrome&sid=SID&spx=%2F&flow=xtls-rprx-vision#phone')

    def test_hand_edited_non_tcp_transport_drops_the_vision_flow(self):
        config = json.loads(json.dumps(TCP_CONFIG))
        config['inbounds'][0]['streamSettings']['network'] = 'grpc'
        manager = make_link_manager(config)
        parts = urllib.parse.urlsplit(
            manager.get_client_config('xray', 'UUID-1', '203.0.113.9', 443))
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        self.assertEqual(query['type'], 'grpc')
        self.assertNotIn('flow', query)


class XhttpClientFlowTests(unittest.TestCase):
    def test_add_client_flow_follows_the_installed_transport(self):
        for network, expected_flow in (('xhttp', ''), ('tcp', 'xtls-rprx-vision')):
            with self.subTest(network=network):
                manager = XrayManager(Mock())
                config = {
                    'inbounds': [{
                        'protocol': 'vless',
                        'settings': {'clients': []},
                        'streamSettings': {'network': network},
                    }],
                }
                manager._get_server_json = lambda: config
                manager._upgrade_config_for_stats = lambda *args, **kwargs: None
                manager._xray_api_add_user = lambda *args: True
                manager._write_server_json = lambda *args, **kwargs: None
                manager._get_clients_table = lambda *args, **kwargs: []
                manager._save_clients_table = lambda table: None
                manager.get_client_config = lambda *args, **kwargs: 'vless://example'

                manager.add_client('xray', 'phone', 'vpn.example.com', 443)

                self.assertEqual(
                    config['inbounds'][0]['settings']['clients'][0]['flow'],
                    expected_flow)

    def test_client_flow_helper_rejects_vision_off_raw_tcp(self):
        self.assertEqual(_client_flow({'network': 'tcp'}), 'xtls-rprx-vision')
        self.assertEqual(_client_flow({'network': 'xhttp'}), '')
        self.assertEqual(_client_flow(None), 'xtls-rprx-vision')


class XhttpLinkExportTests(unittest.TestCase):
    def test_xhttp_link_round_trips_into_the_client_config(self):
        extra = {'xPaddingBytes': '100-1000', 'xmux': {'maxConcurrency': '8-16'}}
        params = {
            'type': 'xhttp', 'security': 'reality',
            'pbk': 'PBK', 'sni': 'own.example', 'fp': 'chrome',
            'sid': 'SID', 'spx': '/',
            'path': '/abc123', 'host': 'own.example', 'mode': 'auto',
            'extra': json.dumps(extra, separators=(',', ':')),
        }
        link = ('vless://UUID-1@203.0.113.9:443?'
                + urllib.parse.urlencode(params) + '#phone')

        config = panel.build_xray_client_config(link)

        self.assertIsNotNone(config)
        outbound = config['outbounds'][0]
        self.assertEqual(outbound['protocol'], 'vless')
        user = outbound['settings']['vnext'][0]['users'][0]
        self.assertEqual(user['id'], 'UUID-1')
        self.assertEqual(user['flow'], '')
        stream = outbound['streamSettings']
        self.assertEqual(stream['network'], 'xhttp')
        self.assertEqual(stream['security'], 'reality')
        settings = stream['xhttpSettings']
        self.assertEqual(settings['path'], '/abc123')
        self.assertEqual(settings['host'], 'own.example')
        self.assertEqual(settings['mode'], 'auto')
        self.assertEqual(settings['extra'], extra)
        reality = stream['realitySettings']
        self.assertEqual(reality['serverName'], 'own.example')
        self.assertEqual(reality['publicKey'], 'PBK')
        self.assertEqual(reality['shortId'], 'SID')
        self.assertEqual(reality['fingerprint'], 'chrome')


if __name__ == '__main__':
    unittest.main()
