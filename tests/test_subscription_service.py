"""Subscription files: path/token handling and the push into the NGINX
mask html root."""
import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as panel
from managers.nginx_manager import NginxManager


def state():
    return {
        'servers': [
            dict(uid='mask', host='198.51.100.9', name='mask-node',
                 protocols={'nginx': {}}),
            dict(uid='node', host='198.51.100.1', protocols={'xray': {'port': 443}}),
        ],
        'users': [dict(id='u1', username='alice')],
        'user_connections': [
            dict(id='c1', user_id='u1', server_id=1,
                 protocol='xray', client_id='peer-1'),
        ],
        'settings': {},
    }


class SubscriptionPathTests(unittest.TestCase):
    def test_path_normalization(self):
        self.assertEqual(panel.normalize_subscription_path('/Sub/'), 'sub')
        self.assertEqual(panel.normalize_subscription_path('a/b-c'), 'a/b-c')
        self.assertEqual(panel.normalize_subscription_path(''), 'sub')
        for bad in ('..', 'a b', 'SUB$', '/x/../y'):
            with self.assertRaises(ValueError):
                panel.normalize_subscription_path(bad)

    def test_settings_defaults(self):
        self.assertEqual(panel.subscription_settings({'settings': {}}),
                         {'enabled': False, 'server_id': None, 'path': 'sub'})

    def test_nginx_server_requires_an_nginx_protocol(self):
        data = state()
        self.assertIsNotNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_id': 0}))
        self.assertIsNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_id': 1}))
        self.assertIsNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_id': 99}))


class SubscriptionTokenTests(unittest.TestCase):
    def test_token_is_minted_once_and_replaced_when_invalid(self):
        user = {'id': 'u1'}
        token = panel.ensure_subscription_token(user)
        self.assertRegex(token, r'^[0-9a-f]{32}$')
        self.assertEqual(panel.ensure_subscription_token(user), token)
        user['sub_token'] = 'garbage'
        self.assertRegex(panel.ensure_subscription_token(user), r'^[0-9a-f]{32}$')


class SubscriptionPushTests(unittest.TestCase):
    def setUp(self):
        self.data = state()
        self.uploads = []
        self.sudo = []

    def _ssh(self):
        ssh = Mock()
        ssh.upload_file_sudo = lambda content, path: self.uploads.append((content, path))
        ssh.run_sudo_command = lambda *a, **k: (
            self.sudo.append(a[0] if a else '') or ('', '', 0))
        ssh.run_command = lambda *a, **k: ('', '', 0)
        return ssh

    def test_push_collects_links_and_writes_the_mask_file(self):
        user = self.data['users'][0]
        link_ssh = self._ssh()
        link_manager = Mock()
        link_manager.get_client_config = Mock(
            return_value='vless://peer-1@entry:443?type=tcp')
        ssh_factory = Mock(side_effect=lambda server: (
            link_ssh if server.get('uid') == 'node' else self._ssh()))
        with patch.object(panel, 'get_ssh', ssh_factory), \
             patch.object(panel, 'get_protocol_manager', return_value=link_manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}):
            token, links, errors = panel.push_user_subscription(
                self.data, user,
                {'enabled': True, 'server_id': 0, 'path': 'sub'},
                self.data['servers'][0])

        self.assertEqual(links, 1)
        self.assertEqual(errors, [])
        content, path = self.uploads[0]
        self.assertEqual(path, f"{NginxManager.HTML_DIR}/sub/{token}")
        self.assertEqual(base64.b64decode(content).decode(),
                         'vless://peer-1@entry:443?type=tcp')
        self.assertIn('mkdir -p', self.sudo[0])

    def test_push_reports_entry_failure_when_no_links_were_collected(self):
        user = self.data['users'][0]
        ssh = self._ssh()
        manager = Mock()
        manager.get_client_config = Mock(side_effect=RuntimeError('ssh down'))
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}):
            with self.assertRaises(RuntimeError) as ctx:
                panel.push_user_subscription(
                    self.data, user,
                    {'enabled': True, 'server_id': 0, 'path': 'sub'},
                    self.data['servers'][0])
        self.assertIn('198.51.100.1', str(ctx.exception))
        self.assertEqual(self.uploads, [])


class SubscriptionEndpointsTests(unittest.TestCase):
    def request(self):
        return SimpleNamespace(cookies={}, headers={})

    def test_settings_save_rejects_a_server_without_nginx(self):
        with patch.object(panel, 'load_data', return_value=state()), \
             patch.object(panel, '_check_admin', lambda request: True):
            result = panel.api_subscription_settings_save(
                self.request(),
                panel.SubscriptionSettingsRequest(enabled=True, server_id=1,
                                                  path='sub'))
        self.assertEqual(result.status_code, 400)
        self.assertIn('NGINX', json.loads(result.body)['error'])

    def test_settings_save_rejects_a_bad_path(self):
        with patch.object(panel, 'load_data', return_value=state()), \
             patch.object(panel, '_check_admin', lambda request: True):
            result = panel.api_subscription_settings_save(
                self.request(),
                panel.SubscriptionSettingsRequest(enabled=False, path='a b'))
        self.assertEqual(result.status_code, 400)

    def test_endpoints_require_admin(self):
        data = state()
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: False):
            for call in (lambda: panel.api_subscription_status(self.request()),
                         lambda: panel.api_subscription_push(self.request()),
                         lambda: panel.api_subscription_settings_save(
                             self.request(),
                             panel.SubscriptionSettingsRequest()),
                         lambda: panel.api_subscription_reset(self.request(), 'u1')):
                self.assertEqual(call().status_code, 403)


if __name__ == '__main__':
    unittest.main()
