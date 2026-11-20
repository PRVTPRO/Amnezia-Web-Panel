"""Раздел «Прокси»: модель учёток и API статуса.

Проверяются чистые функции app.py (счётчики, ключи, валидация учётки) и
smoke-тест GET /api/servers/{id}/proxy/status. SSH и менеджер подменены,
поэтому тесты не ходят на сервер и не требуют Docker.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


def base_data(server_protocols):
    return {
        'servers': [{
            'name': 'srv', 'host': '198.51.100.10', 'uid': 'srv-uid',
            'protocols': server_protocols,
        }],
        'users': [{'id': 'admin-id', 'username': 'admin',
                   'password_hash': panel.hash_password('admin'),
                   'role': 'admin', 'enabled': True}],
        'user_connections': [],
    }


ACCOUNT = {
    'id': 'acct-1',
    'name': 'Алексей — ноутбук',
    'login': 'alex_laptop',
    'password': 's3cret',
    'type': 'both',
    'enabled': True,
    'user_id': None,
    'acl_ips': [],
    'max_conns': None,
    'rate_in_mbps': None,
    'rate_out_mbps': None,
    'quota_mb': None,
    'quota_period': 'M',
    'counter_in': None,
    'counter_out': None,
    'parent': None,
    'created_at': '2026-11-20T00:00:00+00:00',
}


class ProxyPureFunctionsTests(unittest.TestCase):
    def test_next_counter_starts_from_one(self):
        self.assertEqual(panel.proxy_next_counter([]), 1)
        self.assertEqual(panel.proxy_next_counter(None), 1)

    def test_next_counter_steps_after_both_fields(self):
        # Пара (countin/countout) занимает два номера: 11 и 12 → следующий 13.
        self.assertEqual(panel.proxy_next_counter([
            {'counter_in': 11, 'counter_out': 12},
            {'counter_in': 5, 'counter_out': 6},
        ]), 13)

    def test_next_counter_ignores_empty_values(self):
        self.assertEqual(panel.proxy_next_counter([
            {'counter_in': None, 'counter_out': ''},
            {'counter_in': '7', 'counter_out': None},
        ]), 8)

    def test_keys_for_each_account_type(self):
        server = {'host': '198.51.100.10',
                  'protocols': {'socks5': {'port': '1080', 'http_port': '8312',
                                           'http_enabled': True}}}
        account = {'login': 'alex', 'password': 's3cret', 'type': 'socks5'}
        self.assertEqual(
            panel.proxy_account_keys(server, 'socks5', account),
            ['socks5://alex:s3cret@198.51.100.10:1080'])
        account['type'] = 'http'
        self.assertEqual(
            panel.proxy_account_keys(server, 'socks5', account),
            ['http://alex:s3cret@198.51.100.10:8312'])
        account['type'] = 'both'
        self.assertEqual(
            panel.proxy_account_keys(server, 'socks5', account),
            ['socks5://alex:s3cret@198.51.100.10:1080',
             'http://alex:s3cret@198.51.100.10:8312'])

    def test_keys_prefer_public_host(self):
        server = {'host': '198.51.100.10',
                  'protocols': {'socks5': {'port': '1080', 'http_port': '8312',
                                           'http_enabled': True,
                                           'public_host': 'proxy.example.com'}}}
        keys = panel.proxy_account_keys(
            server, 'socks5', {'login': 'a', 'password': 'b', 'type': 'both'})
        self.assertEqual(keys[0], 'socks5://a:b@proxy.example.com:1080')
        self.assertEqual(keys[1], 'http://a:b@proxy.example.com:8312')

    def test_keys_hide_http_when_listener_disabled(self):
        """Выключенный HTTP-листенер не даёт рабочего ключа — не выдаём его."""
        server = {'host': '198.51.100.10',
                  'protocols': {'socks5': {'port': '1080', 'http_port': '8312',
                                           'http_enabled': False}}}
        account = {'login': 'a', 'password': 'b', 'type': 'both'}
        self.assertEqual(panel.proxy_account_keys(server, 'socks5', account),
                         ['socks5://a:b@198.51.100.10:1080'])
        account['type'] = 'http'
        self.assertEqual(panel.proxy_account_keys(server, 'socks5', account), [])

    def test_normalize_returns_exactly_the_model_fields(self):
        account = panel.proxy_normalize_account({
            'name': 'Ноутбук', 'login': 'alex_laptop', 'password': 'secret',
            'type': 'both', 'enabled': True, 'user_id': 'user-1',
            'acl_ips': ['203.0.113.7/32'], 'max_conns': '20',
            'rate_in_mbps': '10', 'rate_out_mbps': '10',
            'quota_mb': '51200', 'quota_period': 'M',
            'parent': {'type': 'socks5', 'host': '198.51.100.20',
                       'port': '1080', 'login': 'up', 'password': 'pw'},
        })
        self.assertEqual(tuple(account), panel.PROXY_ACCOUNT_FIELDS)
        self.assertEqual(account['login'], 'alex_laptop')
        self.assertEqual(account['acl_ips'], ['203.0.113.7/32'])
        self.assertEqual(account['max_conns'], 20)
        self.assertEqual(account['quota_mb'], 51200)
        self.assertEqual(account['parent']['port'], 1080)
        self.assertTrue(account['id'])
        self.assertTrue(account['created_at'])

    def test_normalize_rejects_bad_login(self):
        for login in ('bad login', 'юзер', 'a:b', ''):
            with self.subTest(login=login):
                if not login:
                    # Пустой логин не ошибка: он генерируется.
                    self.assertTrue(
                        panel.proxy_normalize_account({'login': ''})['login'])
                    continue
                with self.assertRaises(ValueError):
                    panel.proxy_normalize_account({'login': login})

    def test_normalize_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            panel.proxy_normalize_account({'login': 'ok', 'type': 'ftp'})

    def test_normalize_generates_password(self):
        account = panel.proxy_normalize_account({'login': 'alex', 'password': ''})
        self.assertEqual(len(account['password']), 16)
        self.assertRegex(account['password'], r'^[A-Za-z0-9]+$')

    def test_normalize_ipv6_acl_has_no_brackets(self):
        account = panel.proxy_normalize_account({
            'login': 'alex',
            'acl_ips': ['[2001:db8::1]', '[2001:db8::]/32', '198.51.100.7'],
        })
        self.assertEqual(account['acl_ips'],
                         ['2001:db8::1', '2001:db8::/32', '198.51.100.7'])

    def test_normalize_rejects_bad_acl(self):
        with self.assertRaises(ValueError):
            panel.proxy_normalize_account({'login': 'alex', 'acl_ips': ['nope']})

    def test_normalize_empty_numbers_become_none(self):
        account = panel.proxy_normalize_account({
            'login': 'alex', 'max_conns': '', 'rate_in_mbps': '',
            'rate_out_mbps': '', 'quota_mb': '',
        })
        self.assertIsNone(account['max_conns'])
        self.assertIsNone(account['rate_in_mbps'])
        self.assertIsNone(account['rate_out_mbps'])
        self.assertIsNone(account['quota_mb'])

    def test_normalize_clears_counters_without_quota(self):
        account = panel.proxy_normalize_account(
            {'login': 'alex', 'password': 'x', 'quota_mb': ''},
            existing={'counter_in': 11, 'counter_out': 12})
        self.assertIsNone(account['counter_in'])
        self.assertIsNone(account['counter_out'])

    def test_normalize_keeps_password_when_not_sent(self):
        account = panel.proxy_normalize_account(
            {'name': 'new name'}, existing={'login': 'alex', 'password': 'old'})
        self.assertEqual(account['password'], 'old')
        self.assertEqual(account['name'], 'new name')

    def test_normalize_parent_none_when_host_empty(self):
        account = panel.proxy_normalize_account({
            'login': 'alex',
            'parent': {'type': 'socks5', 'host': '', 'port': ''},
        })
        self.assertIsNone(account['parent'])

    def test_normalize_none_fields_keep_existing_values(self):
        # Форма может прислать null для незаполненных полей: это «не менять»,
        # а не сброс логина/типа/ACL.
        existing = {'login': 'alex', 'password': 'old', 'type': 'both',
                    'name': 'Старое', 'enabled': False,
                    'acl_ips': ['10.0.0.0/8'], 'quota_period': 'D'}
        account = panel.proxy_normalize_account(
            {'login': None, 'type': None, 'name': None, 'enabled': None,
             'acl_ips': None, 'quota_period': None}, existing=existing)
        self.assertEqual(account['login'], 'alex')
        self.assertEqual(account['type'], 'both')
        self.assertEqual(account['name'], 'Старое')
        self.assertFalse(account['enabled'])
        self.assertEqual(account['acl_ips'], ['10.0.0.0/8'])
        self.assertEqual(account['quota_period'], 'D')


class ProxyStatusApiTests(unittest.TestCase):
    """Реальный ASGI + сессия администратора; SSH и менеджер подменены."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='proxy-api-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        installed = {
            'installed': True, 'port': '1080', 'http_port': '8312',
            'http_enabled': True, 'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'maxconn': 200, 'log_rotate_days': 30,
            'log_format': panel.PROXY_DEFAULT_LOG_FORMAT,
            'accounts': [dict(ACCOUNT, quota_mb=1024, counter_in=1, counter_out=2)],
        }
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(base_data({'socks5': installed}), handle)
        self.client = TestClient(panel.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        response = self.client.post('/api/auth/login',
                                    json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)

    def test_status_without_installed_proxy_does_not_touch_ssh(self):
        self._replace_protocols({})
        with mock.patch.object(panel, 'get_ssh') as get_ssh:
            response = self.client.get('/api/servers/0/proxy/status')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body['installed'])
        self.assertEqual(body['accounts'], [])
        self.assertFalse(body['container']['running'])
        get_ssh.assert_not_called()

    def test_status_reports_container_accounts_usage_and_keys(self):
        fake_ssh = mock.Mock()
        manager = mock.Mock()
        manager.get_server_status.return_value = {
            'container_exists': True, 'container_running': True,
            'port': 1080, 'http_port': 8312, 'http_enabled': True,
            'image': '3proxy/3proxy:0.9.5', 'version': '0.9.5',
        }
        manager.read_stats.return_value = (
            {'alex_laptop': 3 * 1024 * 1024}, {'alex_laptop': 45})
        with mock.patch.object(panel, 'get_ssh', return_value=fake_ssh), \
                mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=manager):
            response = self.client.get('/api/servers/0/proxy/status')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['installed'])
        self.assertTrue(body['container']['running'])
        self.assertEqual(body['container']['version'], '0.9.5')
        self.assertEqual(body['socks_port'], '1080')
        self.assertEqual(body['http_port'], '8312')
        account = body['accounts'][0]
        self.assertEqual(account['login'], 'alex_laptop')
        self.assertEqual(account['usage_mb'], 3.0)
        self.assertTrue(account['online'])
        self.assertEqual(account['last_seen'], 45)
        self.assertEqual(account['counter_in'], 1)
        self.assertEqual(account['keys'], [
            'socks5://alex_laptop:s3cret@198.51.100.10:1080',
            'http://alex_laptop:s3cret@198.51.100.10:8312',
        ])
        self.assertTrue(body['socks_enabled'])
        self.assertEqual(body['listener_type'], 'both')
        fake_ssh.connect.assert_called_once()
        fake_ssh.disconnect.assert_called_once()

    def test_status_marks_account_without_recent_activity_offline(self):
        fake_ssh = mock.Mock()
        manager = mock.Mock()
        manager.get_server_status.return_value = {
            'container_exists': True, 'container_running': True,
            'port': 1080, 'http_port': 8312, 'http_enabled': True,
            'image': '3proxy/3proxy:0.9.5', 'version': '0.9.5',
        }
        manager.read_stats.return_value = ({}, {'alex_laptop': 5000})
        with mock.patch.object(panel, 'get_ssh', return_value=fake_ssh),                 mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=manager):
            response = self.client.get('/api/servers/0/proxy/status')
        self.assertEqual(response.status_code, 200, response.text)
        account = response.json()['accounts'][0]
        self.assertFalse(account['online'])
        self.assertEqual(account['last_seen'], 5000)

    def _servers(self):
        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            return json.load(handle)['servers']

    def _replace_protocols(self, protocols):
        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            data = json.load(handle)
        data['servers'][0]['protocols'] = protocols
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)

    def _ok_manager(self):
        manager = mock.Mock()
        manager.apply.return_value = {'status': 'success', 'log': ['applied'],
                                      'socks_port': 1080, 'http_port': 8312}
        return manager

    def test_create_account_applies_and_saves(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/accounts', json={
                'name': 'Телефон', 'login': 'phone', 'password': 'phone-pw',
                'type': 'socks5', 'quota_mb': 2048,
            })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body['account']['login'], 'phone')
        # Квота без счётчиков не применяется: пара номеров выдаётся сразу.
        self.assertEqual(body['account']['counter_in'], 3)
        self.assertEqual(body['account']['counter_out'], 4)
        self.assertEqual(body['keys'],
                         ['socks5://phone:phone-pw@198.51.100.10:1080'])
        accounts = self._servers()[0]['protocols']['socks5']['accounts']
        self.assertEqual([a['login'] for a in accounts], ['alex_laptop', 'phone'])
        self.assertEqual(manager.apply.call_count, 1)
        applied = manager.apply.call_args.args[0]
        self.assertEqual([a['login'] for a in applied], ['alex_laptop', 'phone'])

    def test_duplicate_login_is_rejected_before_apply(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/accounts', json={
                'login': 'alex_laptop', 'password': 'x', 'type': 'socks5',
            })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('already', response.json()['error'])
        manager.apply.assert_not_called()

    def test_apply_error_keeps_saved_accounts(self):
        manager = self._ok_manager()
        manager.apply.return_value = {'status': 'error', 'message': 'порт занят'}
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/accounts', json={
                'login': 'phone', 'password': 'x', 'type': 'socks5',
            })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['error'], 'порт занят')
        accounts = self._servers()[0]['protocols']['socks5']['accounts']
        self.assertEqual([a['login'] for a in accounts], ['alex_laptop'])

    def test_delete_last_account_is_allowed(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.delete('/api/servers/0/proxy/accounts/acct-1')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['accounts'], [])
        self.assertEqual(manager.apply.call_args.args[0], [])
        accounts = self._servers()[0]['protocols']['socks5']['accounts']
        self.assertEqual(accounts, [])

    def test_toggle_updates_enabled_flag(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post(
                '/api/servers/0/proxy/accounts/acct-1/toggle',
                json={'enabled': False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['account']['enabled'])
        accounts = self._servers()[0]['protocols']['socks5']['accounts']
        self.assertFalse(accounts[0]['enabled'])

    def test_key_endpoint_returns_both_urls(self):
        response = self.client.get('/api/servers/0/proxy/accounts/acct-1/key')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['keys'], [
            'socks5://alex_laptop:s3cret@198.51.100.10:1080',
            'http://alex_laptop:s3cret@198.51.100.10:8312',
        ])

    def test_settings_apply_options_and_save(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '2080', 'http_enabled': True, 'http_port': '8313',
                'dns_servers': ['9.9.9.9'], 'maxconn': '150',
                'log_rotate_days': '7', 'log_format': 'L%Y %U %I %O',
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(manager.apply.call_args.args[1], 2080)
        self.assertEqual(manager.apply.call_args.kwargs['http_port'], 8313)
        self.assertTrue(manager.apply.call_args.kwargs['http_enabled'])
        options = manager.apply.call_args.kwargs['options']
        self.assertEqual(options['maxconn'], 150)
        self.assertEqual(options['dns_servers'], ['9.9.9.9'])
        self.assertEqual(options['log_rotate_days'], 7)
        record = self._servers()[0]['protocols']['socks5']
        self.assertEqual(record['port'], '2080')
        self.assertEqual(record['http_port'], '8313')
        self.assertEqual(record['log_rotate_days'], 7)

    def test_settings_reject_busy_port_before_apply(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports',
                                  return_value={'tcp': {'2080': 'nginx'}}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings',
                                        json={'port': '2080'})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('nginx', response.json()['error'])
        manager.apply.assert_not_called()
        record = self._servers()[0]['protocols']['socks5']
        self.assertEqual(record['port'], '1080')

    def test_listener_type_socks5_disables_http_listener(self):
        """listener_type='socks5' → http_enabled=false, HTTP-порт сохраняется."""
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'http_port': '8312', 'listener_type': 'socks5',
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(manager.apply.call_args.kwargs['http_enabled'])
        record = self._servers()[0]['protocols']['socks5']
        self.assertFalse(record['http_enabled'])
        self.assertEqual(record['listener_type'], 'socks5')

    def test_listener_type_http_without_port_is_rejected(self):
        """HTTP-листенер без порта — ошибка валидации, а не молчаливый дефолт."""
        manager = self._ok_manager()
        self._replace_protocols({'socks5': {
            'installed': True, 'port': '1080', 'http_port': '', 'http_enabled': False,
        }})
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'listener_type': 'http', 'http_port': '',
            })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('listener_type=http', response.json()['error'])
        manager.apply.assert_not_called()

    def test_listener_type_both_keeps_both_ports(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '2080', 'http_port': '8313', 'listener_type': 'both',
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(manager.apply.call_args.kwargs['http_enabled'])
        self.assertEqual(manager.apply.call_args.kwargs['http_port'], 8313)
        record = self._servers()[0]['protocols']['socks5']
        self.assertEqual(record['port'], '2080')
        self.assertEqual(record['http_port'], '8313')
        self.assertEqual(record['listener_type'], 'both')

    def test_listener_type_rejects_unknown_value(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'listener_type': 'ftp',
            })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('listener_type', response.json()['error'])
        manager.apply.assert_not_called()

    def test_listener_type_http_disables_the_socks_container(self):
        """listener_type='http' — настоящий HTTP-only: SOCKS выключен."""
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'http_port': '8312', 'listener_type': 'http',
            })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(manager.apply.call_args.kwargs['socks_enabled'])
        self.assertTrue(manager.apply.call_args.kwargs['http_enabled'])
        record = self._servers()[0]['protocols']['socks5']
        self.assertFalse(record['socks_enabled'])
        self.assertTrue(record['http_enabled'])

    def test_http_only_instance_issues_only_http_key(self):
        """Учётка both на HTTP-only инстансе получает только http:// ключ."""
        good = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=good):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'http_port': '8312', 'listener_type': 'http',
            })
        self.assertEqual(response.status_code, 200, response.text)
        key = self.client.get('/api/servers/0/proxy/accounts/acct-1/key')
        self.assertEqual(key.status_code, 200, key.text)
        self.assertEqual(key.json()['keys'], [
            'http://alex_laptop:s3cret@198.51.100.10:8312',
        ])

    def test_socks_only_instance_issues_only_socks_key(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/settings', json={
                'port': '1080', 'http_port': '8312', 'listener_type': 'socks5',
            })
        self.assertEqual(response.status_code, 200, response.text)
        key = self.client.get('/api/servers/0/proxy/accounts/acct-1/key')
        self.assertEqual(key.status_code, 200, key.text)
        self.assertEqual(key.json()['keys'], [
            'socks5://alex_laptop:s3cret@198.51.100.10:1080',
        ])

    def test_port_check_treats_docker_publication_as_free(self):
        """Порт нашего же контейнера в `ss` держит docker-proxy — не занят."""
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports',
                                  return_value={'tcp': {'1080': 'docker-proxy'}}), \
                mock.patch.object(panel, '_proxy_published_ports',
                                  return_value={'1080'}):
            response = self.client.post('/api/servers/0/proxy/port-check',
                                        json={'port': 1080})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body['free'])
        self.assertEqual(body['holder'], '')
        self.assertTrue(body['valid'])

    def test_port_check_reports_foreign_docker_container(self):
        """Порт чужого контейнера (не нашего прокси) занят, хотя в ss docker-proxy."""
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports',
                                  return_value={'tcp': {'8080': 'docker-proxy'}}), \
                mock.patch.object(panel, '_proxy_published_ports',
                                  return_value=set()):
            response = self.client.post('/api/servers/0/proxy/port-check',
                                        json={'port': 8080})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body['free'])
        self.assertEqual(body['holder'], 'docker-proxy')

    def test_port_check_reports_foreign_holder(self):
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports',
                                  return_value={'tcp': {'8312': 'nginx'}}):
            response = self.client.post('/api/servers/0/proxy/port-check',
                                        json={'port': 8312})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body['free'])
        self.assertEqual(body['holder'], 'nginx')

    def test_port_check_rejects_invalid_ports(self):
        for bad in (0, 70000, 'abc'):
            with self.subTest(port=bad):
                response = self.client.post('/api/servers/0/proxy/port-check',
                                            json={'port': bad})
                self.assertEqual(response.status_code, 400, response.text)
                body = response.json()
                self.assertFalse(body['valid'])
                self.assertFalse(body['free'])

    def test_install_creates_first_account(self):
        manager = mock.Mock()
        manager.install_protocol.return_value = {'status': 'success', 'log': []}
        self._replace_protocols({})
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports', return_value={}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/install', json={
                'port': '1081', 'http_enabled': True, 'http_port': '8314',
                'username': 'first', 'password': 'first-pw',
            })
        self.assertEqual(response.status_code, 200, response.text)
        accounts = manager.install_protocol.call_args.kwargs['accounts']
        self.assertEqual(accounts[0]['login'], 'first')
        self.assertEqual(accounts[0]['type'], 'both')
        saved = self._servers()[0]['protocols']['socks5']
        self.assertTrue(saved['installed'])
        self.assertEqual(saved['port'], '1081')
        self.assertEqual(saved['http_port'], '8314')
        self.assertTrue(saved['http_enabled'])
        self.assertEqual(saved['accounts'][0]['login'], 'first')

    def test_install_rejects_busy_port(self):
        manager = self._ok_manager()
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_used_ports',
                                  return_value={'tcp': {'1081': 'nginx'}}), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            response = self.client.post('/api/servers/0/proxy/install',
                                        json={'port': '1081'})
        self.assertEqual(response.status_code, 400, response.text)
        manager.install_protocol.assert_not_called()
        self.assertEqual(self._servers()[0]['protocols']['socks5']['port'], '1080')


class ProxyCheckPayloadTests(unittest.TestCase):
    """`/check` отдаёт карточке счётчик учёток и DNS, но не креды."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='proxy-check-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        self._monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._monitor)
        panel._CHECK_CACHE.clear()
        self.addCleanup(panel._CHECK_CACHE.clear)
        installed = {
            'installed': True, 'base_protocol': 'socks5', 'port': '1089',
            'http_port': '8310', 'http_enabled': True, 'socks_enabled': True,
            'dns_servers': ['8.8.8.8', '1.1.1.1'],
            'accounts': [dict(ACCOUNT, password='top-secret', login='alex_laptop')],
        }
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(base_data({'socks5': installed}), handle)

    def test_check_includes_account_count_and_dns_without_credentials(self):
        class FakeSSH:
            def connect(self):
                return True

            def disconnect(self):
                pass

            def docker_ps_snapshot(self):
                return {'amnezia-socks5proxy': 'running'}

            def run_command(self, *args, **kwargs):
                return '', '', 0

            def run_sudo_command(self, *args, **kwargs):
                return '', '', 0

        class FakeManager:
            def check_docker_installed(self):
                return True

            def get_server_status(self, protocol_type):
                return {'container_exists': True, 'container_running': True,
                        'protocol': protocol_type, 'port': '1089',
                        'http_port': '8310', 'http_enabled': True}

        with mock.patch.object(panel, 'get_ssh', return_value=FakeSSH()),                 mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=FakeManager()),                 mock.patch.object(panel, 'AWGManager'):
            with TestClient(panel.app) as client:
                login = client.post('/api/auth/login',
                                    json={'username': 'admin', 'password': 'admin'})
                self.assertEqual(login.status_code, 200, login.text)
                response = client.post('/api/servers/0/check')
        self.assertEqual(response.status_code, 200, response.text)
        socks5 = response.json()['protocols']['socks5']
        self.assertEqual(socks5['accounts_count'], 1)
        self.assertEqual(socks5['dns_servers'], ['8.8.8.8', '1.1.1.1'])
        self.assertEqual(socks5['http_port'], '8310')
        self.assertNotIn('top-secret', response.text)
        self.assertNotIn('alex_laptop', response.text)



class ProxyListenerSettingsTests(unittest.TestCase):
    """Выключенный листенер не занимает порт — совпадение допустимо."""

    def test_http_port_may_equal_disabled_socks_port(self):
        settings, _ = panel.proxy_instance_settings(
            {'listener_type': 'http', 'port': 1080, 'http_port': 1080}, {})
        self.assertFalse(settings['socks_enabled'])
        self.assertTrue(settings['http_enabled'])
        self.assertEqual(settings['http_port'], '1080')

    def test_equal_ports_rejected_when_both_listeners_on(self):
        with self.assertRaises(ValueError):
            panel.proxy_instance_settings(
                {'listener_type': 'both', 'port': 1080, 'http_port': 1080}, {})


class ProxyCounterTests(unittest.TestCase):
    """Номер счётчика квоты не переиспользуется после удаления учётки."""

    def test_counter_is_not_reused_after_account_delete(self):
        record = {}
        first = {'quota_mb': 1024}
        panel.proxy_assign_counters([], first, record)
        self.assertEqual((first['counter_in'], first['counter_out']), (1, 2))
        self.assertEqual(record['counter_seq'], 2)
        # Учётку удалили: её номеров в списке больше нет.
        second = {'quota_mb': 1024}
        panel.proxy_assign_counters([], second, record)
        self.assertEqual((second['counter_in'], second['counter_out']), (3, 4))

    def test_assign_without_record_still_works(self):
        account = {'quota_mb': 512}
        panel.proxy_assign_counters([{'counter_in': 5, 'counter_out': 6}], account)
        self.assertEqual((account['counter_in'], account['counter_out']), (7, 8))
if __name__ == '__main__':
    unittest.main()
