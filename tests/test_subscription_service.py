"""Subscription files: path/token handling and the push into the NGINX
mask html root."""
import asyncio
import base64
import urllib.parse
import json
import re
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
        'users': [dict(id='u1', username='alice', role='admin')],
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
                         {'enabled': False, 'server_uid': None, 'path': 'sub',
                          'name': ''})

    def test_nginx_server_requires_an_nginx_protocol(self):
        data = state()
        self.assertIsNotNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_uid': 'mask'}))
        self.assertIsNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_uid': 'node'}))
        self.assertIsNone(panel.subscription_nginx_server(
            data, {'enabled': True, 'server_uid': 'gone'}))

    def test_legacy_index_settings_migrate_to_uid(self):
        # Pre-uid settings stored a list index: subscription_settings
        # resolves it to the server uid in-memory.
        data = state()
        data['settings'] = {'subscription': {
            'enabled': True, 'server_id': 0, 'path': 'sub'}}
        self.assertEqual(panel.subscription_settings(data)['server_uid'], 'mask')
        # An out-of-range legacy index resolves to None (no crash).
        data['settings']['subscription']['server_id'] = 99
        self.assertIsNone(panel.subscription_settings(data)['server_uid'])
        # A saved uid takes precedence over any legacy index.
        data['settings']['subscription']['server_uid'] = 'mask'
        data['settings']['subscription']['server_id'] = 1
        self.assertEqual(panel.subscription_settings(data)['server_uid'], 'mask')


class UserinfoTests(unittest.TestCase):
    def test_userinfo_fields(self):
        user = {'traffic_used': 450, 'traffic_limit': 700,
                'expiration_date': '2027-01-01T00:00:00'}
        value = panel._subscription_userinfo(user)
        self.assertIn('upload=0', value)
        self.assertIn('download=450', value)
        self.assertIn('total=700', value)
        self.assertIn('expire=', value)
        # expire is a unix timestamp parsed back to the same date
        expire = int(value.split('expire=')[1])
        import datetime as dt
        self.assertEqual(dt.datetime.fromtimestamp(expire).year, 2027)

    def test_userinfo_omits_missing_fields(self):
        self.assertEqual(panel._subscription_userinfo({}), 'upload=0')
        self.assertEqual(panel._subscription_userinfo({'traffic_used': 5}),
                         'upload=0; download=5')
        # limit 0 means unlimited: no total
        self.assertEqual(
            panel._subscription_userinfo({'traffic_used': 5, 'traffic_limit': 0}),
            'upload=0; download=5')
        # unparsable expiry is skipped
        self.assertEqual(
            panel._subscription_userinfo({'traffic_used': 5,
                                          'expiration_date': 'garbage'}),
            'upload=0; download=5')

    def test_nginx_quote_escapes_config_breakers(self):
        self.assertEqual(panel._nginx_quote('say "hi"'),
                         'say ' + chr(92) + '"hi' + chr(92) + '"')
        self.assertEqual(panel._nginx_quote('a' + chr(92) + 'b'),
                         'a' + chr(92) * 2 + 'b')

    def test_config_block_carries_per_token_userinfo(self):
        entries = [('t' * 32, 'upload=0; download=450; total=700')]
        block = panel._subscription_config_block('sub', 'My VPN', entries)
        self.assertIn('location = /sub/' + 't' * 32, block)
        self.assertIn('subscription-userinfo "upload=0; download=450; total=700"',
                      block)
        self.assertIn('profile-title "My VPN"', block)
        # generic fallback location still present for unknown tokens
        self.assertIn('location /sub/', block)
        # exactly one exact-match location per entry
        self.assertEqual(block.count('location = /sub/'), 1)

    def test_config_entries_cover_users_with_tokens_and_targets(self):
        data = state()
        data['users'][0]['sub_token'] = 't' * 32
        data['users'][0]['traffic_used'] = 450
        entries = panel._subscription_config_entries(data)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 't' * 32)
        self.assertIn('download=450', entries[0][1])
        # a user without xray targets is not listed even with a token
        data['user_connections'] = []
        self.assertEqual(panel._subscription_config_entries(data), [])


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
            token, links, errors, unchanged = panel.push_user_subscription(
                self.data, user,
                {'enabled': True, 'server_uid': 'mask', 'path': 'sub'},
                self.data['servers'][0])

        self.assertEqual(links, 1)
        self.assertEqual(errors, [])
        self.assertFalse(unchanged)
        content, path = self.uploads[0]
        self.assertEqual(path, f"{NginxManager.HTML_DIR}/sub/{token}")
        decoded = base64.b64decode(content).decode()
        # The fragment carries "server · instance", not the admin's private
        # connection note.
        base, _, fragment = decoded.rpartition('#')
        self.assertEqual(base, 'vless://peer-1@entry:443?type=tcp')
        self.assertEqual(urllib.parse.unquote(fragment), '198.51.100.1 · Xray')
        self.assertTrue(any('mkdir -p' in cmd for cmd in self.sudo))

    def test_push_uses_named_server_and_instance(self):
        user = self.data['users'][0]
        self.data['servers'][1]['name'] = 'Frankfurt'
        self.data['servers'][1]['protocols']['xray']['custom_name'] = 'VLESS+XHTTP+REALITY'
        ssh = self._ssh()
        manager = Mock()
        manager.get_client_config = Mock(
            return_value='vless://peer-1@entry:443?type=tcp#old-private-note')
        with patch.object(panel, 'get_ssh', return_value=ssh),              patch.object(panel, 'get_protocol_manager', return_value=manager),              patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)),              patch.object(panel, 'xray_fp_kwargs', return_value={}):
            panel.push_user_subscription(
                self.data, user,
                {'enabled': True, 'server_uid': 'mask', 'path': 'sub'},
                self.data['servers'][0])
        content, _ = self.uploads[0]
        base, _, fragment = base64.b64decode(content).decode().rpartition('#')
        self.assertEqual(base, 'vless://peer-1@entry:443?type=tcp')
        self.assertEqual(urllib.parse.unquote(fragment), 'Frankfurt · VLESS+XHTTP+REALITY')

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
                    {'enabled': True, 'server_uid': 'mask', 'path': 'sub'},
                    self.data['servers'][0])
        self.assertIn('198.51.100.1', str(ctx.exception))
        self.assertEqual(self.uploads, [])


class SubscriptionConfigTests(unittest.TestCase):
    def _base_config(self):
        return NginxManager(Mock())._build_ssl_config('d.example', 443)

    def test_inject_replace_and_remove_are_idempotent(self):
        base = self._base_config()
        injected = panel._apply_subscription_config_text(base, 'sub', 'My VPN')
        self.assertIn('location /sub/', injected)
        self.assertIn('add_header profile-title "My VPN" always;', injected)
        self.assertIn('profile-update-interval "6"', injected)

        replaced = panel._apply_subscription_config_text(
            injected, 'sub2', panel._subscription_profile_title('Другое имя'))
        self.assertNotIn('location /sub/', replaced)
        self.assertIn('location /sub2/', replaced)
        title = 'profile-title "base64:'
        self.assertIn(title, replaced)
        import base64 as b64
        encoded = replaced.split(title, 1)[1].split('"', 1)[0]
        self.assertEqual(b64.b64decode(encoded).decode(), 'Другое имя')

        removed = panel._apply_subscription_config_text(replaced, remove=True)
        self.assertNotIn('panel subscription (managed)', removed)
        normalize = lambda text: re.sub(r'\n{2,}', '\n', text).strip()
        self.assertEqual(normalize(removed), normalize(base))

    def test_injection_targets_the_last_server_block(self):
        injected = panel._apply_subscription_config_text(
            self._base_config(), 'sub', 'My VPN')
        # The managed location must live inside the 443 server block
        # (after its location /), not after the final brace.
        self.assertLess(injected.index('location /sub/'),
                        injected.rindex('try_files $uri $uri/ /index.html;') + 200)
        self.assertTrue(injected.rstrip().endswith('}'))


class AutoPushTests(unittest.TestCase):
    def setUp(self):
        self.data = state()
        self.uploads = []
        self.saved = []
        self.sudo = []
        self.ssh = Mock()
        self.ssh.upload_file_sudo = lambda content, path: self.uploads.append((content, path))
        self.ssh.run_sudo_command = lambda *a, **k: (
            self.sudo.append(a[0] if a else '') or ('', '', 0))
        self.ssh.run_command = lambda *a, **k: ('', '', 0)

    def test_auto_push_writes_file_and_caches_the_url(self):
        self.data['settings'] = {'subscription': {
            'enabled': True, 'server_uid': 'mask', 'path': 'sub'}}
        manager = Mock()
        manager.get_client_config = Mock(
            return_value='vless://peer-1@entry:443?type=tcp')
        with patch.object(panel, 'get_ssh', return_value=self.ssh),              patch.object(panel, 'get_protocol_manager', return_value=manager),              patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)),              patch.object(panel, 'xray_fp_kwargs', return_value={}),              patch.object(panel, '_subscription_mask_domain',
                          return_value='mask.example'),              patch.object(panel, 'save_data',
                          Mock(side_effect=lambda d: self.saved.append(d))):
            panel.auto_push_subscriptions(self.data, ['u1'])

        self.assertIn('https://mask.example/sub/', self.data['users'][0]['sub_url'])
        self.assertTrue(self.saved)
        content, _ = self.uploads[0]
        self.assertIn('peer-1', base64.b64decode(content).decode())

    def test_auto_push_skips_identical_files_and_clears_dead_urls(self):
        self.data['settings'] = {'subscription': {
            'enabled': True, 'server_uid': 'mask', 'path': 'sub'}}
        manager = Mock()
        manager.get_client_config = Mock(
            return_value='vless://peer-1@entry:443?type=tcp')
        self.data['users'][0]['sub_url'] = 'https://mask.example/sub/old'

        def cat(command, **kwargs):
            # First read: nothing there yet; later reads: the pushed content.
            if 'cat' in command and self.uploads:
                return (self.uploads[-1][0], '', 0)
            return ('', '', 0)
        self.ssh.run_sudo_command = lambda *a, **k: (
            self.sudo.append(a[0] if a else '') or cat(*a, **k))

        with patch.object(panel, 'get_ssh', return_value=self.ssh),              patch.object(panel, 'get_protocol_manager', return_value=manager),              patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)),              patch.object(panel, 'xray_fp_kwargs', return_value={}),              patch.object(panel, '_subscription_mask_domain',
                          return_value='mask.example'),              patch.object(panel, 'save_data', Mock()):
            panel.auto_push_subscriptions(self.data, ['u1'])
            first_write = len(self.uploads)
            self.assertTrue(self.data['users'][0]['sub_url'].startswith('https://'))
            panel.auto_push_subscriptions(self.data, ['u1'])
            self.assertEqual(len(self.uploads), first_write)  # unchanged: no rewrite

            # All xray connections are gone: the cached URL must clear.
            self.data['user_connections'] = []
            panel.auto_push_subscriptions(self.data, ['u1'])
        self.assertIsNone(self.data['users'][0].get('sub_url'))


    def test_auto_push_is_silent_when_disabled(self):
        self.data['settings'] = {'subscription': {
            'enabled': False, 'server_uid': 'mask', 'path': 'sub'}}
        self.data['users'][0]['sub_url'] = 'https://mask.example/sub/keep'
        # Any SSH or data write attempt while disabled is a test failure.
        self.ssh.upload_file_sudo = Mock(side_effect=AssertionError('ssh write'))
        self.ssh.run_sudo_command = Mock(side_effect=AssertionError('ssh cmd'))
        self.ssh.connect = Mock(side_effect=AssertionError('ssh connect'))
        save = Mock(side_effect=AssertionError('save_data'))
        with patch.object(panel, 'get_ssh', return_value=self.ssh),              patch.object(panel, 'save_data', save):
            panel.auto_push_subscriptions(self.data, ['u1'])
        self.assertEqual(self.uploads, [])
        self.assertEqual(self.data['users'][0]['sub_url'],
                         'https://mask.example/sub/keep')


class SubscriptionEndpointsTests(unittest.TestCase):
    def request(self):
        return SimpleNamespace(cookies={}, headers={})

    def test_settings_save_rejects_a_server_without_nginx(self):
        with patch.object(panel, 'load_data', return_value=state()), \
             patch.object(panel, '_check_admin', lambda request: True):
            result = panel.api_subscription_settings_save(
                self.request(),
                panel.SubscriptionSettingsRequest(enabled=True, server_uid='node',
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

    def test_users_list_carries_the_cached_sub_url(self):
        data = state()
        data['settings'] = {'subscription': {
            'enabled': True, 'server_uid': 'mask', 'path': 'sub'}}
        data['users'][0]['sub_url'] = 'https://mask.example/sub/tok'
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True):
            result = panel.api_list_users(self.request(), search='', page=1, size=10)
        self.assertEqual(result['users'][0]['sub_url'],
                         'https://mask.example/sub/tok')

    def test_server_scope_add_triggers_the_subscription_push(self):
        # Adding a connection from the server card
        # (/api/servers/{id}/connections/add) must refresh the owner's
        # subscription file just like the users-page endpoint does.
        data = state()
        data['settings'] = {'subscription': {
            'enabled': True, 'server_id': 0, 'path': 'sub'}}
        data['users'][0]['sub_url'] = 'https://mask.example/sub/tok'
        pushed = []
        manager = Mock()
        manager.add_client.return_value = {'client_id': 'peer-new',
                                           'config': 'vless://peer-new'}
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'save_data', Mock()), \
             patch.object(panel, 'auto_push_subscriptions',
                          Mock(side_effect=lambda d, ids: pushed.append(list(ids)))):
            result = asyncio.run(panel.api_add_connection(
                self.request(), 1,
                panel.AddConnectionRequest(protocol='xray', name='phone',
                                           user_id='u1')))
        self.assertIn('config', result)
        self.assertEqual(pushed, [['u1']])

    def test_server_scope_add_without_a_user_does_not_push(self):
        # An unowned connection has no subscription to refresh.
        data = state()
        data['settings'] = {'subscription': {
            'enabled': True, 'server_id': 0, 'path': 'sub'}}
        pushed = []
        manager = Mock()
        manager.add_client.return_value = {'client_id': 'peer-new',
                                           'config': 'vless://peer-new'}
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'save_data', Mock()), \
             patch.object(panel, 'auto_push_subscriptions',
                          Mock(side_effect=lambda d, ids: pushed.append(list(ids)))):
            asyncio.run(panel.api_add_connection(
                self.request(), 1,
                panel.AddConnectionRequest(protocol='xray', name='phone')))
        self.assertEqual(pushed, [])

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
