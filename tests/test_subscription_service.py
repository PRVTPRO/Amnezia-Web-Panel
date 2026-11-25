"""Subscription files: path/token handling and the push into the NGINX
mask html root."""
import asyncio
import base64
import urllib.parse
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

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


# A wg-quick config as the AWG manager hands it out, with the classic
# obfuscation knobs a client looks for to tell AmneziaWG from WireGuard.
AWG_CONF = (
    "[Interface]\n"
    "PrivateKey = cHJpdmF0ZWtleQ==\n"
    "Address = 10.8.0.2/32\n"
    "DNS = 1.1.1.1\n"
    "MTU = 1280\n"
    "Jc = 3\nJmin = 10\nJmax = 30\nS1 = 15\nS2 = 18\n"
    "H1 = 1020325451\nH2 = 3288052141\nH3 = 1766607858\nH4 = 2528465083\n"
    "[Peer]\nPublicKey = cHVibGlja2V5\nPresharedKey = cHJlc2hhcmVka2V5\n"
    "AllowedIPs = 0.0.0.0/0\nEndpoint = entry.example:55424\n")


def mixed_state():
    """A user with an xray and an AmneziaWG connection on the same server."""
    data = state()
    data['servers'][1]['protocols'] = {'xray': {'port': 443},
                                       'awg': {'port': '55424'}}
    data['user_connections'].append(
        dict(id='c2', user_id='u1', server_id=1,
             protocol='awg', client_id='peer-awg'))
    return data


def opt_in(data):
    data['settings'] = {'subscription': {
        'enabled': True, 'server_uid': 'mask', 'path': 'sub', 'include_awg': True}}
    return data


def fake_manager(broken=()):
    """Answers like both managers: a link for xray, a config for AmneziaWG.
    A connection whose client is in ``broken`` fails the way the AmneziaWG
    manager does when it cannot rebuild a client."""
    manager = Mock()

    def get_client_config(protocol, client_id, host, port, public_port=None, **kwargs):
        if client_id in broken:
            raise RuntimeError(f'Client {client_id} not found')
        if protocol.startswith('xray'):
            return f'vless://{client_id}@entry:443?type=tcp#old-private-note'
        return AWG_CONF

    manager.get_client_config = Mock(side_effect=get_client_config)
    return manager


# What the panel reads from the WARP state for an instance: a push must hand
# exactly this to the AmneziaWG manager.
WARP_CTX = {'active': True, 'client_mtu': 1280, 'dns_via_warp': True}


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
                          'name': '', 'include_awg': False})
        # AmneziaWG is opt-in: nothing stored means off.
        self.assertFalse(panel.subscription_settings(state())['include_awg'])

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

    def test_push_leaves_amneziawg_out_unless_the_admin_opted_in(self):
        user = self.data['users'][0]
        self.data = mixed_state()
        manager = fake_manager()
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}):
            panel.push_user_subscription(
                self.data, user,
                {'enabled': True, 'server_uid': 'mask', 'path': 'sub'},
                self.data['servers'][0])

        content, _ = self.uploads[0]
        self.assertEqual(base64.b64decode(content).decode().split('\n'),
                         ['vless://peer-1@entry:443?type=tcp#'
                          '198.51.100.1%20%C2%B7%20Xray'])
        # the AmneziaWG connection was never asked for
        self.assertEqual([c.args[0] for c in manager.get_client_config.call_args_list],
                         ['xray'])

    def test_push_carries_amneziawg_beside_vless_when_opted_in(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        manager = fake_manager()
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX):
            token, links, errors, unchanged = panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])

        self.assertEqual((links, errors, unchanged), (2, [], False))
        content, _ = self.uploads[0]
        xray_line, awg_line = base64.b64decode(content).decode().split('\n')
        self.assertTrue(xray_line.startswith('vless://'))
        self.assertEqual(awg_line,
                         panel.amneziawg_share_link(AWG_CONF, '198.51.100.1 · AmneziaWG'))
        # the config is asked for the way the panel hands it out to a user
        xray_call, awg_call = manager.get_client_config.call_args_list
        self.assertEqual(xray_call.args, ('xray', 'peer-1', 'entry.example', 443))
        self.assertEqual(xray_call.kwargs, {'public_port': None})
        self.assertEqual(awg_call.args, ('awg', 'peer-awg', 'entry.example', '55424'))

    def test_an_amneziawg_config_follows_the_instance_warp_link(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        manager = fake_manager()
        node = self.data['servers'][1]
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx',
                          return_value=WARP_CTX) as warp_ctx:
            panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])

        # Without the context the manager would rebuild the config with the
        # instance MTU and an IPv6 resolver, which a WARP-exit instance
        # cannot carry.
        warp_ctx.assert_called_once_with(node, 'awg')
        xray_call, awg_call = manager.get_client_config.call_args_list
        self.assertEqual(awg_call.kwargs, {'public_port': None, 'warp_ctx': WARP_CTX})
        # an xray link has no use for it
        self.assertNotIn('warp_ctx', xray_call.kwargs)

    def test_an_instance_without_a_stored_port_is_asked_on_the_awg_default(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        del self.data['servers'][1]['protocols']['awg']['port']
        manager = fake_manager()
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX):
            panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])

        # the port every other client-config endpoint falls back to
        awg_call = manager.get_client_config.call_args_list[1]
        self.assertEqual(awg_call.args, ('awg', 'peer-awg', 'entry.example', 55424))

    def test_a_connection_that_cannot_be_built_keeps_the_others(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        self.data['user_connections'].append(
            dict(id='c3', user_id='u1', server_id=1,
                 protocol='xray', client_id='peer-2'))
        # the AmneziaWG peer is gone from the server
        manager = fake_manager(broken={'peer-awg'})
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX):
            token, links, errors, unchanged = panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])

        self.assertEqual((links, unchanged), (2, False))
        self.assertEqual(errors, ['198.51.100.1: Client peer-awg not found'])
        content, _ = self.uploads[0]
        lines = base64.b64decode(content).decode().split('\n')
        self.assertEqual(len(lines), links)
        self.assertTrue(all(line.startswith('vless://') for line in lines))

    def test_an_amneziawg_link_survives_a_broken_xray_connection(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        manager = fake_manager(broken={'peer-1'})
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX):
            token, links, errors, unchanged = panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])

        self.assertEqual((links, unchanged), (1, False))
        self.assertEqual(errors, ['198.51.100.1: Client peer-1 not found'])
        content, _ = self.uploads[0]
        self.assertEqual(base64.b64decode(content).decode(),
                         panel.amneziawg_share_link(AWG_CONF, '198.51.100.1 · AmneziaWG'))

    def test_an_unreachable_server_is_reported_and_the_others_are_written(self):
        user = self.data['users'][0]
        self.data['servers'].append(
            dict(uid='node2', host='198.51.100.2', protocols={'xray': {'port': 443}}))
        self.data['user_connections'].append(
            dict(id='c2', user_id='u1', server_id=2,
                 protocol='xray', client_id='peer-2'))
        manager = Mock()
        manager.get_client_config = Mock(
            return_value='vless://peer-2@entry:443?type=tcp')

        def ssh_for(server):
            if server.get('uid') == 'node':
                raise OSError('ssh down')
            return self._ssh()
        with patch.object(panel, 'get_ssh', side_effect=ssh_for), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}):
            token, links, errors, unchanged = panel.push_user_subscription(
                self.data, user,
                {'enabled': True, 'server_uid': 'mask', 'path': 'sub'},
                self.data['servers'][0])

        self.assertEqual((links, unchanged), (1, False))
        self.assertEqual(errors, ['198.51.100.1: ssh down'])
        content, _ = self.uploads[0]
        self.assertIn(b'peer-2', base64.b64decode(content))

    def test_an_amneziawg_instance_keeps_its_own_name(self):
        user = self.data['users'][0]
        self.data = opt_in(mixed_state())
        self.data['servers'][1]['name'] = 'Frankfurt'
        self.data['servers'][1]['protocols']['awg']['custom_name'] = 'AWG 3.1'
        with patch.object(panel, 'get_ssh', return_value=self._ssh()), \
             patch.object(panel, 'get_protocol_manager', return_value=fake_manager()), \
             patch.object(panel, 'protocol_public_endpoint',
                          return_value=('entry.example', None)), \
             patch.object(panel, 'xray_fp_kwargs', return_value={}), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX):
            panel.push_user_subscription(
                self.data, user, panel.subscription_settings(self.data),
                self.data['servers'][0])
        content, _ = self.uploads[0]
        awg_line = base64.b64decode(content).decode().split('\n')[1]
        self.assertEqual(awg_line, panel.amneziawg_share_link(AWG_CONF, 'Frankfurt · AWG 3.1'))


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

    def test_an_amneziawg_only_user_is_served_once_the_admin_opts_in(self):
        self.data = opt_in(mixed_state())
        self.data['settings']['subscription']['include_awg'] = False
        self.data['user_connections'] = [
            c for c in self.data['user_connections'] if c['protocol'] == 'awg']
        self.data['users'][0]['sub_url'] = 'https://mask.example/sub/old'
        manager = fake_manager()
        with patch.object(panel, 'get_ssh', return_value=self.ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'save_data', Mock()):
            # off: nothing to serve, and the cached URL clears
            panel.auto_push_subscriptions(self.data, ['u1'])
        self.assertEqual(self.uploads, [])
        self.assertIsNone(self.data['users'][0].get('sub_url'))

        self.data['settings']['subscription']['include_awg'] = True
        with patch.object(panel, 'get_ssh', return_value=self.ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, 'srv_warp_ctx', return_value=WARP_CTX), \
             patch.object(panel, '_subscription_mask_domain',
                          return_value='mask.example'), \
             patch.object(panel, 'save_data', Mock()):
            panel.auto_push_subscriptions(self.data, ['u1'])
        self.assertEqual(len(self.uploads), 1)
        self.assertTrue(self.data['users'][0]['sub_url']
                        .startswith('https://mask.example/sub/'))
        self.assertIn('amneziawg://', base64.b64decode(self.uploads[0][0]).decode())

    def test_turning_the_option_off_retires_the_amneziawg_only_users_file(self):
        self.data = mixed_state()
        self.data['user_connections'] = [
            c for c in self.data['user_connections'] if c['protocol'] == 'awg']
        user = self.data['users'][0]
        # a real token: the prune only removes files named like one
        token = panel.ensure_subscription_token(user)
        user['sub_url'] = f'https://mask.example/sub/{token}'
        self.data['settings'] = {'subscription': {
            'enabled': True, 'server_uid': 'mask', 'path': 'sub',
            'include_awg': False}}

        def ls(command, **kwargs):
            # the mask still holds the file from when the option was on
            if command.startswith('ls -1'):
                return (token + '\n', '', 0)
            return ('', '', 0)
        self.ssh.run_sudo_command = lambda *a, **k: (
            self.sudo.append(a[0] if a else '') or ls(*a, **k))
        with patch.object(panel, 'get_ssh', return_value=self.ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=fake_manager()), \
             patch.object(panel, '_subscription_mask_domain',
                          return_value='mask.example'):
            outcome = panel.push_all_subscriptions(self.data)

        self.assertEqual(outcome['pushed'], [])
        self.assertEqual(self.uploads, [])
        self.assertIsNone(user.get('sub_url'))
        self.assertTrue(any('rm -f' in cmd and token in cmd for cmd in self.sudo))


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

    def test_adding_an_amneziawg_connection_pushes_once_the_admin_opted_in(self):
        # From the server card, and from the users page with an existing
        # client: both used to refresh the file for Xray only.
        for opted_in in (True, False):
            with self.subTest(opted_in=opted_in):
                data = state()
                data['settings'] = {'subscription': {
                    'enabled': True, 'server_uid': 'mask', 'path': 'sub',
                    'include_awg': opted_in}}
                data['servers'][1]['protocols'] = {'awg': {'port': '55424'}}
                pushed = []
                manager = Mock()
                manager.add_client.return_value = {'client_id': 'peer-new',
                                                   'config': AWG_CONF}
                manager.get_client_config.return_value = AWG_CONF
                with patch.object(panel, 'load_data', return_value=data), \
                     patch.object(panel, '_check_admin', lambda request: True), \
                     patch.object(panel, 'get_ssh', return_value=Mock()), \
                     patch.object(panel, 'get_protocol_manager', return_value=manager), \
                     patch.object(panel, 'save_data', Mock()), \
                     patch.object(panel, 'auto_push_subscriptions',
                                  Mock(side_effect=lambda d, ids: pushed.append(list(ids)))):
                    from_card = asyncio.run(panel.api_add_connection(
                        self.request(), 1,
                        panel.AddConnectionRequest(protocol='awg', name='phone',
                                                   user_id='u1')))
                    from_users = asyncio.run(panel.api_add_user_connection(
                        self.request(), 'u1',
                        panel.AddUserConnectionRequest(server_id=1, protocol='awg',
                                                       client_id='peer-awg')))
                self.assertIn('config', from_card)
                self.assertEqual(from_users.get('status'), 'success')
                self.assertEqual(pushed, [['u1'], ['u1']] if opted_in else [])

    def test_settings_save_keeps_the_amneziawg_choice(self):
        data = state()
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'save_data', Mock()):
            panel.api_subscription_settings_save(
                self.request(),
                panel.SubscriptionSettingsRequest(enabled=False, path='sub',
                                                  include_awg=True))
        self.assertTrue(panel.subscription_settings(data)['include_awg'])
        # a request that says nothing about it leaves it off
        data = state()
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'save_data', Mock()):
            panel.api_subscription_settings_save(
                self.request(), panel.SubscriptionSettingsRequest(enabled=False, path='sub'))
        self.assertFalse(panel.subscription_settings(data)['include_awg'])

    def test_status_reports_the_amneziawg_choice(self):
        data = opt_in(state())
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True):
            self.assertTrue(panel.api_subscription_status(self.request())['include_awg'])

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


class AmneziawgLinkTests(unittest.TestCase):
    """The AmneziaWG share link, in the form YPtun composes and reads:
    `amneziawg://`, then the wg-quick config in base64url without padding,
    then `#name` (ShareLinkParser.kt and ShareLinkComposer.kt in
    yanisplugg/yptun)."""

    def test_link_is_the_config_in_base64url_with_the_name_after_a_hash(self):
        link = panel.amneziawg_share_link(AWG_CONF, 'Frankfurt · AmneziaWG 3.1')
        config = AWG_CONF.strip()

        payload, hash_mark, fragment = link[len('amneziawg://'):].rpartition('#')
        self.assertEqual(hash_mark, '#')
        self.assertEqual(payload, base64.urlsafe_b64encode(
            config.encode()).decode().rstrip('='))
        self.assertNotIn('=', payload)
        self.assertNotIn('\n', link)
        self.assertNotIn('\r', link)
        self.assertEqual(urllib.parse.unquote(fragment), 'Frankfurt · AmneziaWG 3.1')
        # the client gets the whole config back, byte for byte
        padded = payload + '=' * (-len(payload) % 4)
        self.assertEqual(base64.urlsafe_b64decode(padded).decode(), config)

    def test_whitespace_around_the_config_is_dropped(self):
        self.assertEqual(panel.amneziawg_share_link(' \n' + AWG_CONF + '\n\n', 'x'),
                         panel.amneziawg_share_link(AWG_CONF, 'x'))

    def test_a_name_is_escaped_the_way_the_client_decodes_it(self):
        # YPtun takes everything after the first "#", reads "%" pairs and
        # turns a raw "+" into a space: none of these may travel raw.
        name = 'Frankfurt #2 · -50% +test'
        link = panel.amneziawg_share_link(AWG_CONF, name)
        payload, hash_mark, fragment = link[len('amneziawg://'):].partition('#')
        self.assertTrue(hash_mark)
        self.assertNotIn('#', payload)
        for raw in ('#', '+', ' ', '\n'):
            self.assertNotIn(raw, fragment)
        # "-50%" survives as itself, not as a broken "%xx" escape
        self.assertEqual(urllib.parse.unquote(fragment), name)
        # a line break would split one link into two in the subscription
        self.assertNotIn('\n', panel.amneziawg_share_link(AWG_CONF, 'two\nlines'))

    def test_targets_are_xray_only_until_the_admin_opts_in(self):
        data = mixed_state()
        data['user_connections'].append(
            dict(id='c3', user_id='u1', server_id=1,
                 protocol='wireguard', client_id='w'))

        def carried(subscription):
            data['settings'] = {'subscription': subscription}
            return [c['protocol'] for _, conns
                    in panel._subscription_user_targets(data, data['users'][0])
                    for c in conns]

        on = {'enabled': True, 'server_uid': 'mask', 'path': 'sub',
              'include_awg': True}
        self.assertEqual(carried(on), ['xray', 'awg'])
        # plain WireGuard is not AmneziaWG, opted in or not
        on['include_awg'] = False
        self.assertEqual(carried(on), ['xray'])
        self.assertEqual(carried({}), ['xray'])

    def test_every_amneziawg_instance_family_is_carried_when_opted_in(self):
        families = panel.AWG_PROTOCOLS + ('awg__2', 'awg3__3')
        for protocol in families:
            with self.subTest(protocol=protocol):
                data = opt_in(mixed_state())
                data['user_connections'] = [dict(
                    id='c', user_id='u1', server_id=1,
                    protocol=protocol, client_id='p')]
                targets = panel._subscription_user_targets(data, data['users'][0])
                self.assertEqual([c['protocol'] for _, conns in targets for c in conns],
                                 [protocol])


class SubscriptionSettingsTemplateTests(unittest.TestCase):
    def test_the_option_is_offered_with_its_hint_right_below_it(self):
        source = (Path(__file__).resolve().parents[1]
                  / 'templates' / 'settings.html').read_text(encoding='utf-8')
        box = source.index('id="sub_include_awg"')
        self.assertIn('{% if subscription_settings.include_awg %}checked{% endif %}',
                      source[box:box + 200])
        label = source.index("{{ _('subscription_include_awg') }}", box)
        hint = source.index("{{ _('subscription_include_awg_hint') }}", box)
        # label first, the hint directly after, then the next setting
        self.assertLess(box, label)
        self.assertLess(label, hint)
        self.assertLess(hint, source.index('id="subName"'))
        # the option sits inside the fields that only show when enabled
        self.assertLess(source.index('id="subFields"'), box)
        # and it is what the save request sends
        self.assertIn("include_awg: document.getElementById('sub_include_awg').checked",
                      source)


class SettingsPageRenderTests(unittest.TestCase):
    """The real /settings page: a Jinja mistake in the option would otherwise
    only show when an admin opens the page."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (panel.DATA_FILE, panel._conn_monitor_started)
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        panel._conn_monitor_started = True  # keep the background SSH monitor out

    def tearDown(self):
        panel.DATA_FILE, panel._conn_monitor_started = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _render_subscription_block(self, include_awg):
        data = {
            'servers': [dict(name='mask-node', host='198.51.100.9', ssh_port=22,
                             username='root', password='x', private_key='',
                             server_info={}, uid='mask', protocols={'nginx': {}})],
            'users': [dict(id='admin-id', username='admin',
                           password_hash=panel.hash_password('admin'),
                           role='admin', enabled=True)],
            'user_connections': [],
            'settings': {'subscription': {
                'enabled': True, 'server_uid': 'mask', 'path': 'sub',
                'name': 'My VPN', 'include_awg': include_awg}},
        }
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login',
                                json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)
            page = client.get('/settings')
        self.assertEqual(page.status_code, 200)
        html = page.text
        self.assertIn('Subscriptions (Xray / AmneziaWG)', html)
        block = html[html.index('id="subFields"'):]
        return block[:block.index('id="subName"')]

    def test_the_option_renders_checked_only_when_it_is_on(self):
        catalogue = json.loads((Path(__file__).resolve().parents[1]
                                / 'translations' / 'en.json').read_text(encoding='utf-8'))
        for include_awg in (True, False):
            with self.subTest(include_awg=include_awg):
                block = self._render_subscription_block(include_awg)
                checkbox = next(line for line in block.split('>')
                                if 'id="sub_include_awg"' in line.split('<')[-1])
                self.assertEqual('checked' in checkbox, include_awg)
                # the label, then the hint, both translated
                label = block.index(catalogue['subscription_include_awg'])
                hint = block.index(catalogue['subscription_include_awg_hint'])
                self.assertLess(label, hint)
                self.assertNotIn('{{', block)
                self.assertNotIn('{%', block)


if __name__ == '__main__':
    unittest.main()
