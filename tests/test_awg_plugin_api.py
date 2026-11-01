"""API guards for the AmneziaWG plugin update endpoints."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as panel


class FakeUpdater:
    def __init__(self):
        self.calls = []

    def status(self):
        return {
            'components': {
                'kernel_module': {
                    'installed': '3.1.20260812',
                    'available': '3.1.20260906',
                    'update_available': True,
                    'installed_detected': True,
                },
                'userspace': {
                    'installed': '3.1.20260812',
                    'available': '3.1.20260828',
                    'update_available': True,
                    'installed_detected': True,
                },
            },
            'checked_at': '2026-10-31T10:00:00+00:00',
        }

    def latest_versions(self):
        return {'kernel_module': '3.1.20260906', 'userspace': '3.1.20260828'}

    def changelog(self, component, version):
        return [{'sha': 'abcdef12', 'subject': 'fix: something'}]

    def update(self, component, target, allow_interrupt=False, log=None, should_cancel=None):
        self.calls.append((component, target, allow_interrupt))
        if log:
            log('preflight', 'checking %s' % target)
            log('build', 'building %s' % target)
            log('install', 'installing %s' % target)
            log('activate', 'activating %s' % target)
            log('done', 'finished')
        return {'component': component, 'previous': '3.1.20260812',
                'installed': target, 'state': 'updated', 'rolled_back': False}


class AwgPluginApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = str(Path(self.tmp.name) / 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        panel._awg_plugin_ops.clear()
        panel._awg_plugin_active.clear()
        self.addCleanup(panel._awg_plugin_ops.clear)
        self.addCleanup(panel._awg_plugin_active.clear)

        seed = {'servers': [{'name': 's', 'host': '127.0.0.1', 'ssh_port': 1,
                             'username': 'root', 'password': 'x', 'private_key': '',
                             'server_info': {}, 'uid': 'u0', 'protocols': {}}],
                'users': [], 'user_connections': []}
        Path(panel.DATA_FILE).write_text(json.dumps(seed), encoding='utf-8')

        self.updater = FakeUpdater()
        patcher = patch.object(panel, '_awg_plugin_updater', lambda server_id: self.updater)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.client = TestClient(panel.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        login = self.client.post('/api/auth/login',
                                 json={'username': 'admin', 'password': 'admin', 'captcha': None})
        self.assertEqual(login.status_code, 200, login.text)

    def test_status_requires_admin(self):
        client = TestClient(panel.app)
        response = client.get('/api/servers/0/awg-plugin/status')
        self.assertEqual(response.status_code, 403)

    def test_status_returns_components(self):
        response = self.client.get('/api/servers/0/awg-plugin/status')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['components']['kernel_module']['update_available'])
        self.assertEqual(body['components']['kernel_module']['available'], '3.1.20260906')

    def test_changelog_rejects_unknown_component(self):
        response = self.client.get(
            '/api/servers/0/awg-plugin/changelog?component=nope&version=3.1.20260906')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'unsupported')

    def test_update_rejects_unknown_component(self):
        response = self.client.post('/api/servers/0/awg-plugin/update',
                                    json={'component': 'nope'})
        self.assertEqual(response.status_code, 400)

    def test_second_update_is_rejected_while_running(self):
        panel._awg_plugin_active[(0, 'kernel_module')] = 'other-op'
        response = self.client.post('/api/servers/0/awg-plugin/update',
                                    json={'component': 'kernel_module'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['code'], 'update_in_progress')

    def test_update_creates_operation_and_journal(self):
        response = self.client.post('/api/servers/0/awg-plugin/update',
                                    json={'component': 'kernel_module'})
        self.assertEqual(response.status_code, 200, response.text)
        op_id = response.json()['operation_id']
        self.assertIn(op_id, panel._awg_plugin_ops)

        status = self.client.get('/api/servers/0/awg-plugin/update/%s' % op_id)
        self.assertEqual(status.status_code, 200, status.text)
        body = status.json()
        for key in ('state', 'component', 'lines', 'next_offset', 'result', 'error'):
            self.assertIn(key, body)
        self.assertEqual(body['component'], 'kernel_module')

    def test_journal_survives_a_panel_restart(self):
        """A killed update must never be resumed or shown as success."""
        store = panel._awg_plugin_store_path()
        Path(store).write_text(json.dumps([{
            'id': 'op-restart', 'server_id': 0, 'component': 'kernel_module',
            'target': '3.1.20260906', 'state': 'running', 'lines': [],
            'result': None, 'error': None, 'started_at': 't',
        }]), encoding='utf-8')
        panel._awg_plugin_ops.clear()
        panel._awg_plugin_loaded['done'] = False
        panel._awg_plugin_load()
        op = panel._awg_plugin_ops['op-restart']
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'interrupted')
        self.assertTrue(any('restarted' in line['text'] for line in op['lines']))

    def test_unknown_operation_is_404(self):
        response = self.client.get('/api/servers/0/awg-plugin/update/does-not-exist')
        self.assertEqual(response.status_code, 404)

    def test_journal_offset_advances(self):
        panel._awg_plugin_ops['op1'] = {
            'id': 'op1', 'server_id': 0, 'component': 'kernel_module',
            'target': '3.1.20260906', 'state': 'success', 'lines': [
                {'ts': 't', 'stage': 'a', 'text': 'one'},
                {'ts': 't', 'stage': 'b', 'text': 'two'},
            ], 'result': None, 'error': None,
            'started_at': 't', 'finished_at': 't',
        }
        first = self.client.get('/api/servers/0/awg-plugin/update/op1?offset=0').json()
        self.assertEqual(len(first['lines']), 2)
        self.assertEqual(first['next_offset'], 2)
        second = self.client.get('/api/servers/0/awg-plugin/update/op1?offset=2').json()
        self.assertEqual(second['lines'], [])


if __name__ == '__main__':
    unittest.main()
