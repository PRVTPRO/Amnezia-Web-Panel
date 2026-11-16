"""Instance-level Reality fingerprint in issued VLESS links.

The fingerprint is a client hello property, not a server setting: the panel
remembers one per xray connection in data.json and get_client_config embeds it
into every link it builds. These tests pin the default, the override and the
fallback for unknown values.
"""

import json
import re
import unittest

from managers.xray_manager import (
    XrayManager,
    XRAY_DEFAULT_FINGERPRINT,
    XRAY_FINGERPRINTS,
)

SERVER_JSON = {
    'log': {'loglevel': 'error'},
    'inbounds': [
        {
            'port': 443,
            'protocol': 'vless',
            'tag': 'proxy',
            'settings': {'clients': [], 'decryption': 'none'},
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'dest': 'yahoo.com:443',
                    'serverNames': ['yahoo.com'],
                    'privateKey': 'priv',
                    'shortIds': ['abcd1234'],
                },
            },
        },
    ],
    'outbounds': [{'protocol': 'freedom'}],
}

CLIENT_ID = '11111111-1111-1111-1111-111111111111'


def clients_table(fingerprint=None):
    user_data = {
        'clientName': 'Phone',
        'creationDate': '2026-11-12T00:00:00',
        'enabled': True,
    }
    return [{'clientId': CLIENT_ID, 'userData': user_data}]


class FakeSSH:
    """In-memory stand-in serving the native-layout config directory."""

    def __init__(self):
        self.files = {
            '/opt/amnezia/xray/server.json': json.dumps(SERVER_JSON),
            '/opt/amnezia/xray/clientsTable': json.dumps(clients_table()),
            '/opt/amnezia/xray/xray_private.key': 'priv\n',
            '/opt/amnezia/xray/xray_public.key': 'pub\n',
            '/opt/amnezia/xray/xray_short_id.key': 'abcd1234\n',
            '/opt/amnezia/xray/xray_uuid.key': '\n',
        }
        self.last_upload = None

    def upload_file_sudo(self, content, remote_path):
        self.files[remote_path] = content
        self.last_upload = (content, remote_path)
        return True

    def run_sudo_command(self, command, **kwargs):
        cmd = command.strip()
        if cmd.startswith('ls -1'):
            dir_path = cmd.split()[2]
            names = [p[len(dir_path):].lstrip('/')
                     for p in self.files if p.startswith(dir_path + '/')]
            return ('\n'.join(sorted(names)), '', 0)
        if 'docker cp ' in cmd:
            dest = cmd.rsplit(':', 1)[-1].split()[0]
            if self.last_upload:
                self.files[dest] = self.last_upload[0]
            return ('', '', 0)
        if ' cat ' in cmd:
            path = cmd.rsplit(' cat ', 1)[-1].split(' 2>', 1)[0].strip()
            return (self.files.get(path, ''), '', 0)
        return ('', '', 0)

    def run_command(self, command, **kwargs):
        return ('', '', 0)


class FingerprintLinkTests(unittest.TestCase):
    def setUp(self):
        self.mgr = XrayManager(FakeSSH())

    def link(self, **kwargs):
        return self.mgr.get_client_config('xray', CLIENT_ID, '1.2.3.4', 443, **kwargs)

    def test_link_defaults_to_chrome(self):
        self.assertIn('fp=chrome', self.link())

    def test_link_uses_stored_fingerprint(self):
        link = self.link(fingerprint='firefox')
        self.assertIn('fp=firefox', link)
        self.assertNotIn('fp=chrome', link)

    def test_link_falls_back_on_unknown_fingerprint(self):
        self.assertIn('fp=chrome', self.link(fingerprint='nordvpn-hello'))

    def test_fingerprint_stays_in_query_part(self):
        # The value must not leak into the URL fragment (the client name).
        link = self.link(fingerprint='safari')
        query = link.split('?', 1)[1].split('#', 1)[0]
        self.assertIn('fp=safari', query)
        self.assertEqual(re.findall(r'fp=([\w-]+)', link), ['safari'])


class AddClientFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.mgr = XrayManager(self.ssh)

    def test_add_client_persists_fingerprint_in_issued_link(self):
        result = self.mgr.add_client('xray', 'Laptop', '1.2.3.4', 443,
                                     fingerprint='ios')
        self.assertIn('fp=ios', result['config'])

    def test_add_client_without_fingerprint_keeps_default(self):
        result = self.mgr.add_client('xray', 'Laptop', '1.2.3.4', 443)
        self.assertIn('fp=chrome', result['config'])


class FingerprintWhitelistTests(unittest.TestCase):
    def test_chrome_is_the_default(self):
        self.assertEqual(XRAY_DEFAULT_FINGERPRINT, 'chrome')

    def test_whitelist_covers_xtls_fingerprints(self):
        self.assertEqual(
            set(XRAY_FINGERPRINTS),
            {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge',
             '360', 'qq', 'random', 'randomized'},
        )


if __name__ == '__main__':
    unittest.main()
