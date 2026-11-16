"""HTTP contract of the Xray core updater endpoints.

Covers the version probe (update_available logic), the update operation
lifecycle (operation_id -> background op -> success) and the server-wide
busy guard.
"""

import json
import os
import shutil
import tempfile
import time
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


class XrayUpdateApiBase(unittest.TestCase):
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
        panel._invalidate_ip_status()
        self.addCleanup(panel._invalidate_ip_status)
        # The install-op registry is process-wide and persisted.
        panel._INSTALL_OPS.clear()
        panel._INSTALL_ACTIVE.clear()
        self.addCleanup(panel._INSTALL_OPS.clear)
        self.addCleanup(panel._INSTALL_ACTIVE.clear)

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def client(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        return client

    def wait_op(self, op_id, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            op = panel._INSTALL_OPS.get(op_id)
            if op and op.get('state') != 'running':
                return op
            time.sleep(0.02)
        self.fail(f'operation {op_id} did not finish')


class CoreVersionTests(XrayUpdateApiBase):
    def _probe(self, client):
        with mock.patch.object(panel, 'XrayManager') as manager_cls, \
                mock.patch.object(panel, '_xray_latest_release',
                                  return_value='v26.11.7'):
            manager_cls.return_value.get_core_version.return_value = '26.10.31'
            return client.get('/api/servers/0/xray/core?protocol=xray')

    def test_update_available_when_versions_differ(self):
        res = self._probe(self.client())
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()['version'], '26.10.31')
        self.assertEqual(res.json()['latest'], 'v26.11.7')
        self.assertTrue(res.json()['update_available'])

    def test_no_update_when_core_matches_latest(self):
        with mock.patch.object(panel, 'XrayManager') as manager_cls, \
                mock.patch.object(panel, '_xray_latest_release',
                                  return_value='v26.10.31'):
            manager_cls.return_value.get_core_version.return_value = '26.10.31'
            res = self.client().get('/api/servers/0/xray/core?protocol=xray')
        self.assertFalse(res.json()['update_available'])

    def test_non_xray_protocol_is_rejected(self):
        res = self.client().get('/api/servers/0/xray/core?protocol=awg')
        self.assertEqual(res.status_code, 400)


class UpdateFlowTests(XrayUpdateApiBase):
    def _patched_manager(self):
        patcher = mock.patch.object(panel, 'XrayManager')
        manager_cls = patcher.start()
        self.addCleanup(patcher.stop)
        manager_cls.return_value.update_core.return_value = {
            'status': 'success', 'updated': True,
            'version': '26.11.7', 'previous': '26.10.31', 'log': []}
        return manager_cls

    def test_update_runs_as_an_install_flow_operation(self):
        manager_cls = self._patched_manager()
        with mock.patch.object(panel, '_xray_latest_release',
                               return_value='v26.11.7'):
            res = self.client().post('/api/servers/0/xray/update',
                                     json={'protocol': 'xray'})
        self.assertEqual(res.status_code, 200, res.text)
        op_id = res.json()['operation_id']
        op = self.wait_op(op_id)
        self.assertEqual(op['state'], 'success')
        self.assertEqual(op['result']['version'], '26.11.7')
        self.assertEqual(op['flow'], 'xray_update')
        manager_cls.return_value.update_core.assert_called_once()
        self.assertEqual(manager_cls.return_value.update_core.call_args.args[0],
                         'v26.11.7')

    def test_explicit_target_skips_the_release_lookup(self):
        manager_cls = self._patched_manager()
        with mock.patch.object(panel, '_xray_latest_release') as lookup:
            res = self.client().post('/api/servers/0/xray/update',
                                     json={'protocol': 'xray',
                                           'target': 'v26.12.1'})
            self.assertEqual(res.status_code, 200, res.text)
            self.wait_op(res.json()['operation_id'])
            lookup.assert_not_called()
        self.assertEqual(manager_cls.return_value.update_core.call_args.args[0],
                         'v26.12.1')

    def test_busy_server_is_409(self):
        panel._INSTALL_ACTIVE[(0, 'protocol')] = 'some-op'
        try:
            res = self.client().post('/api/servers/0/xray/update',
                                     json={'protocol': 'xray'})
            self.assertEqual(res.status_code, 409)
            self.assertEqual(res.json()['code'], 'operation_in_progress')
        finally:
            panel._INSTALL_ACTIVE.pop((0, 'protocol'), None)

    def test_failing_update_finishes_as_a_failed_operation(self):
        manager_cls = self._patched_manager()
        manager_cls.return_value.update_core.return_value = {
            'status': 'error', 'updated': False, 'version': '26.10.31',
            'message': 'Xray-core v26.11.7 did not start; rolled back'}
        with mock.patch.object(panel, '_xray_latest_release',
                               return_value='v26.11.7'):
            res = self.client().post('/api/servers/0/xray/update',
                                     json={'protocol': 'xray'})
        op = self.wait_op(res.json()['operation_id'])
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'update_failed')
        self.assertIn('did not start', op['error']['message'])

    def test_non_xray_protocol_is_rejected(self):
        res = self.client().post('/api/servers/0/xray/update',
                                 json={'protocol': 'wireguard'})
        self.assertEqual(res.status_code, 400)


class ReleaseLookupTests(unittest.TestCase):
    def test_latest_tag_is_cached(self):
        payload = mock.Mock()
        payload.__enter__ = mock.Mock(return_value=payload)
        payload.__exit__ = mock.Mock(return_value=False)
        payload.read = mock.Mock(
            return_value=json.dumps({'tag_name': 'v26.11.7'}).encode())
        panel._XRAY_RELEASE_CACHE.update(ts=0.0, tag=None)
        with mock.patch('urllib.request.urlopen', return_value=payload) as urlopen:
            self.assertEqual(panel._xray_latest_release(), 'v26.11.7')
            self.assertEqual(panel._xray_latest_release(), 'v26.11.7')
            self.assertEqual(urlopen.call_count, 1)
        panel._XRAY_RELEASE_CACHE.update(ts=0.0, tag=None)


if __name__ == '__main__':
    unittest.main()
