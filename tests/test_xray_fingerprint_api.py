"""HTTP contract of the xray fingerprint routes.

Covers store/reset through data.json and the phantom-record guard: saving a
fingerprint for an instance that is not installed must answer 404 and must
not mint an otherwise-empty protocol record (multi-instance records survive
/check pruning, so a minted one would linger as "installed but stopped").
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


def base_server(**extra):
    server = {'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
              'username': 'root', 'password': 'x', 'private_key': '',
              'server_info': {}, 'uid': 'srv-uid',
              'protocols': {'xray': {'installed': True, 'port': 443}}}
    server.update(extra)
    return server


def users():
    return [{'id': 'admin-id', 'username': 'admin',
             'password_hash': panel.hash_password('admin'),
             'role': 'admin', 'enabled': True}]


class XrayFingerprintApiBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        panel.peer_lifecycle_lock.configure(panel.DATA_FILE)
        self.addCleanup(panel.peer_lifecycle_lock.configure, self._data_file)
        self.write_data({'servers': [base_server()], 'users': users(),
                         'user_connections': []})
        ssh_patch = mock.patch.object(panel, 'get_ssh', return_value=mock.Mock())
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def read_data(self):
        with open(panel.DATA_FILE, encoding='utf-8') as f:
            return json.load(f)

    def client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        return client

    def post_fp(self, client, protocol='xray', fingerprint='firefox'):
        return client.post('/api/servers/0/xray/fingerprint',
                           json={'protocol': protocol, 'fingerprint': fingerprint})


class FingerprintSaveTests(XrayFingerprintApiBase):
    def test_store_and_read_back(self):
        client = self.client()
        res = self.post_fp(client)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['fingerprint'], 'firefox')
        record = self.read_data()['servers'][0]['protocols']['xray']
        self.assertEqual(record['fingerprint'], 'firefox')

        res = client.get('/api/servers/0/xray/fingerprint?protocol=xray')
        self.assertEqual(res.json()['fingerprint'], 'firefox')

    def test_reset_removes_the_field(self):
        client = self.client()
        self.post_fp(client)
        res = self.post_fp(client, fingerprint='')
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['fingerprint'], 'firefox')
        self.assertNotIn('fingerprint', self.read_data()['servers'][0]['protocols']['xray'])

    def test_unknown_fingerprint_value_is_400(self):
        res = self.post_fp(self.client(), fingerprint='nordvpn-hello')
        self.assertEqual(res.status_code, 400)

    def test_no_phantom_record_for_an_uninstalled_instance(self):
        client = self.client()
        res = self.post_fp(client, protocol='xray__2', fingerprint='safari')
        self.assertEqual(res.status_code, 404, res.text)
        # The route must not mint an otherwise-empty protocol record:
        # multi-instance records survive /check pruning, so a minted one
        # would linger as "installed but stopped".
        protocols = self.read_data()['servers'][0]['protocols']
        self.assertNotIn('xray__2', protocols)
        self.assertEqual(set(protocols.keys()), {'xray'})

    def test_non_xray_protocol_is_400(self):
        res = self.post_fp(self.client(), protocol='wireguard', fingerprint='firefox')
        self.assertEqual(res.status_code, 400)


if __name__ == '__main__':
    unittest.main()
