"""Кэш ответа /check для мгновенной первой отрисовки страницы сервера.

Страница просит проверку с ?boot=1 и получает снимок последнего ответа сразу,
а свежую проверку запускает фоном. Ручная проверка (?boot нет) всегда свежая.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class FakeSSH:
    """SSH без сети: снимок docker задаётся вручную."""

    def __init__(self, snapshot=None):
        self.snapshot = {} if snapshot is None else dict(snapshot)

    def connect(self):
        return True

    def disconnect(self):
        pass

    def docker_ps_snapshot(self):
        return dict(self.snapshot)

    def run_command(self, *args, **kwargs):
        return '', '', 0

    def run_sudo_command(self, *args, **kwargs):
        return '', '', 0


class CountingManager:
    def __init__(self, calls):
        self.calls = calls

    def check_docker_installed(self):
        return True

    def get_server_status(self, protocol_type):
        self.calls.append(protocol_type)
        return {'container_exists': True, 'container_running': True,
                'protocol': protocol_type, 'port': '55424',
                'awg_params': {}, 'clients_count': 0}


class CheckCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True
        panel._CHECK_CACHE.clear()
        self.calls = []

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        panel._CHECK_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self, protocols=None):
        if protocols is None:
            protocols = {'awg': {'installed': True, 'port': '55424',
                                 'base_protocol': 'awg', 'instance': 1,
                                 'display_name': 'AmneziaWG',
                                 'container_name': 'amnezia-awg'}}
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({
                'servers': [{'name': 'node', 'host': '198.51.100.7',
                             'ssh_port': 22, 'username': 'root', 'password': 'x',
                             'uid': 'check-uid', 'protocols': protocols}],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': [],
            }, handle)

    def check(self, query='', snapshot=None):
        ssh = FakeSSH({'amnezia-awg': 'running'} if snapshot is None else snapshot)
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'get_protocol_manager',
                                  return_value=CountingManager(self.calls)), \
                mock.patch.object(panel, 'AWGManager') as awg_cls:
            awg_cls.return_value.prefetch_awg_state.return_value = None
            with TestClient(panel.app) as client:
                login = client.post('/api/auth/login',
                                    json={'username': 'admin', 'password': 'admin'})
                self.assertEqual(login.status_code, 200, login.text)
                response = client.post('/api/servers/0/check' + query)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_boot_request_returns_the_cached_snapshot(self):
        self.seed()
        first = self.check()
        self.assertEqual(self.calls, ['awg'])
        self.assertNotIn('cached', first)
        second = self.check('?boot=1')
        self.assertTrue(second.get('cached'))
        self.assertIn('cached_age', second)
        self.assertEqual(second['protocols']['awg']['container_exists'], True)
        # Кэш не запускает SSH повторно.
        self.assertEqual(self.calls, ['awg'])

    def test_manual_check_is_always_fresh(self):
        self.seed()
        self.check()
        self.check('?boot=1')
        fresh = self.check()
        self.assertNotIn('cached', fresh)
        self.assertEqual(self.calls, ['awg', 'awg'])

    def test_boot_without_cache_runs_the_real_check(self):
        self.seed()
        payload = self.check('?boot=1')
        self.assertNotIn('cached', payload)
        self.assertEqual(self.calls, ['awg'])

    def test_absent_container_skips_the_ssh_round_trip(self):
        self.seed(protocols={})
        payload = self.check(snapshot={})
        self.assertEqual(self.calls, [])
        self.assertEqual(payload['protocols']['awg2']['container_exists'], False)

    def test_mutation_invalidates_the_boot_snapshot(self):
        self.seed()
        self.check()
        self.check('?boot=1')
        # Любая мутация сбрасывает снимок: страница не должна показывать
        # состояние до установки/удаления/переключения протокола.
        panel._invalidate_ip_status_for_server(0)
        payload = self.check('?boot=1')
        self.assertNotIn('cached', payload)
        self.assertEqual(self.calls, ['awg', 'awg'])


if __name__ == '__main__':
    unittest.main()
