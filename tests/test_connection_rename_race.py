"""Real rename handler/persistence; deterministic mocked SSH, no application startup.

Adapted from the v1.7.5 connection-speed race reproducer.
"""
import ast
import asyncio
import inspect
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

from fastapi.responses import JSONResponse
from pydantic import BaseModel

SOURCE = Path(__file__).resolve().parents[1] / 'app.py'
GIB = 1024 ** 3


class NativeSpeedRace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel-speed-synthetic-')
        self.data_file = Path(self.temp.name) / 'data.json'
        self.entered, self.release = threading.Event(), threading.Event()
        self.gated = False
        self.fail_speed = False
        self.speed = 0
        self.admin = True
        self.next_client_id = None
        self.rename_error = False
        self.disconnects = 0
        self.remove_connection = False
        self.rebound_peer = None
        self.calls = []
        names = {'load_data', 'save_data', 'RenameConnectionRequest', 'api_rename_connection'}
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        nodes = [node for node in tree.body if getattr(node, 'name', None) in names]
        self.assertEqual({node.name for node in nodes}, names)
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.decorator_list = []
        self.ns = dict(os=os, json=json, tempfile=tempfile, BaseModel=BaseModel,
                       Request=object, asyncio=asyncio, DATA_LOCK=asyncio.Lock(), JSONResponse=JSONResponse, DATA_FILE=str(self.data_file),
                       DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={},
                       _check_admin=lambda request: self.admin,
                       logger=SimpleNamespace(warning=lambda *a: None, exception=lambda *a: None))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), self.ns)
        self.user = dict(id='synthetic-user', username='before', enabled=False,
                         traffic_used=430*GIB, traffic_limit=500*GIB,
                         expiration_date='2030-01-01T00:00:00')
        self.conn = dict(id='synthetic-connection', user_id=self.user['id'], server_id=0,
                         protocol='awg3', client_id='synthetic-peer', name='Keep this name')
        self.ns['save_data'](dict(users=[self.user], servers=[{'host': 'mock.invalid'}],
                                  user_connections=[self.conn]))

        def disconnect():
            self.disconnects += 1

        def connect():
            self.assertFalse(self.ns['DATA_LOCK'].locked(), 'DATA_LOCK must not cover SSH')
            if self.gated:
                self.entered.set()
                if not self.release.wait(5):
                    raise TimeoutError('synthetic SSH gate timeout')

        def manager_call(manager, method, protocol, client_id, value):
            self.calls.append((method, protocol, client_id, value))
            if method == 'rename_client':
                if self.rename_error: raise OSError('synthetic rename failure')
                return {'name': value, 'client_id': self.next_client_id or client_id}
            self.assertEqual(method, 'set_speed_limit')
            if self.fail_speed:
                raise TimeoutError('synthetic speed timeout')
            self.speed = value
            return {'status': 'success', 'max_speed': value}

        self.ns['get_ssh'] = lambda server: SimpleNamespace(connect=connect, disconnect=disconnect)
        self.ns['get_protocol_manager'] = lambda *args: SimpleNamespace(set_speed_limit=True)
        self.ns['_manager_call'] = manager_call

    def tearDown(self):
        self.temp.cleanup()

    def update_speed(self):
        req = self.ns['RenameConnectionRequest'](protocol='awg3', client_id='synthetic-peer',
                                                new_name=self.conn['name'], max_speed=20)
        result = self.ns['api_rename_connection'](object(), 0, req)
        return asyncio.run(result) if inspect.isawaitable(result) else result

    def run_race(self):
        self.gated = True
        response = {}
        errors = []

        def call():
            try:
                response.update(self.update_speed())
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=call)
        worker.start()
        try:
            self.assertTrue(self.entered.wait(5), 'endpoint did not reach SSH boundary')
            fresh = self.ns['load_data']()
            expected = dict(fresh['users'][0], traffic_used=480*GIB, traffic_limit=750*GIB,
                            expiration_date='2031-01-01T00:00:00', username='concurrent', enabled=True)
            fresh['users'][0] = expected
            fresh['user_connections'][0]['notes'] = 'concurrent metadata'
            fresh['user_connections'].append(dict(self.conn, id='other-connection',
                client_id='independent-peer', name='independent update'))
            if self.remove_connection:
                fresh['user_connections'].pop(0)
            elif self.rebound_peer:
                fresh['user_connections'][0]['client_id'] = self.rebound_peer
            self.ns['save_data'](fresh)
            self.assertEqual(self.ns['load_data']()['users'][0], expected, 'B was not persisted')
        finally:
            self.release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive(), 'mock SSH worker must terminate')
        self.assertFalse(errors, errors)
        return response, expected, self.ns['load_data']()

    def test_native_awg3_speed_and_unchanged_connection_name(self):
        response = self.update_speed()
        self.assertEqual(response['status'], 'success')
        self.assertNotIn('speed_warning', response)
        self.assertEqual(self.speed, 20)
        persisted = self.ns['load_data']()
        self.assertEqual(persisted['user_connections'][0], self.conn)
        self.assertEqual(persisted['users'][0], self.user)
        self.assertEqual(self.calls[0][-1], 'Keep this name')

    def test_success_must_preserve_concurrent_user_fields(self):
        response, expected, persisted = self.run_race()
        self.assertEqual(response['status'], 'success')
        self.assertEqual(self.speed, 20)
        self.assertEqual(persisted['users'][0], expected,
                         'speed endpoint restored a stale user snapshot after SSH')

    def test_speed_warning_must_preserve_concurrent_user_fields(self):
        self.fail_speed = True
        response, expected, persisted = self.run_race()
        self.assertEqual(response['status'], 'success')
        self.assertIn('speed_warning', response)
        self.assertEqual(self.speed, 0)
        self.assertEqual(persisted['users'][0], expected,
                         'even a failed speed change restored stale user fields')

    def test_changed_client_id_preserves_uuid_and_concurrent_metadata(self):
        self.next_client_id = 'new-peer-identity'
        response, expected, persisted = self.run_race()
        self.assertEqual(response['client_id'], 'new-peer-identity')
        self.assertEqual(persisted['user_connections'][0],
                         dict(self.conn, client_id='new-peer-identity', notes='concurrent metadata'))
        self.assertEqual(persisted['user_connections'][1]['name'], 'independent update')
        self.assertEqual(persisted['users'][0], expected)

    def test_fresh_process_reads_preserved_state(self):
        _, expected, persisted = self.run_race()
        # A separate process reads the atomic JSON file, not in-memory objects.
        code = 'import json,sys; print(json.dumps(json.load(open(sys.argv[1], encoding="utf-8"))))'
        reread = json.loads(subprocess.check_output(
            [sys.executable, '-c', code, str(self.data_file)], text=True))
        self.assertEqual(reread, persisted)
        self.assertEqual(reread['users'][0], expected)

    def test_rename_failure_does_not_write_json_and_disconnects(self):
        self.rename_error = True
        before = self.data_file.read_bytes()
        response = self.update_speed()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.data_file.read_bytes(), before)
        self.assertEqual(self.disconnects, 1)

    def test_denied_request_does_not_call_manager(self):
        self.admin = False
        before = self.data_file.read_bytes()
        response = self.update_speed()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.data_file.read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_retry_does_not_duplicate_connection(self):
        self.update_speed()
        self.update_speed()
        data = self.ns['load_data']()
        self.assertEqual(data['user_connections'], [self.conn])
        self.assertEqual(data['users'], [self.user])

    def test_deleted_connection_is_not_resurrected(self):
        self.remove_connection = True
        _, expected, data = self.run_race()
        self.assertEqual([c['id'] for c in data['user_connections']], ['other-connection'])
        self.assertEqual(data['users'][0], expected)

    def test_changed_connection_identity_is_not_rebound(self):
        self.rebound_peer = 'concurrent-peer-identity'
        _, expected, data = self.run_race()
        self.assertEqual(data['user_connections'][0]['client_id'], self.rebound_peer)
        self.assertEqual(data['users'][0], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
