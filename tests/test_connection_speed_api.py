"""Speed-only API: real ASGI/models/persistence, synthetic peers and mock SSH."""
import ast
import asyncio
import copy
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel, Field

SOURCE = Path(__file__).resolve().parents[1] / 'app.py'


class SpeedApi(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel-speed-only-')
        self.file = Path(self.temp.name) / 'data.json'
        self.peer_file = Path(self.temp.name) / 'peers.json'
        self.peer_file.write_text(json.dumps([
            {'clientId': 'peer-a', 'userData': {'clientName': 'keep', 'maxSpeed': 7}},
            {'clientId': 'peer-b', 'userData': {'clientName': 'other', 'maxSpeed': 99}},
        ]), encoding='utf-8')
        self.calls = []
        self.outcome = None
        self.supported = True
        self.gated = False
        self.entered, self.release = threading.Event(), threading.Event()
        self.disconnects = 0
        self.ssh_error = False
        self.ns = dict(os=os, json=json, tempfile=tempfile, asyncio=asyncio, math=math,
            BaseModel=BaseModel, Field=Field, Request=Request, JSONResponse=JSONResponse,
            DATA_FILE=str(self.file), DATA_LOCK=asyncio.Lock(), DEFAULT_MAIL_SETTINGS={},
            DEFAULT_SELF_SERVICE_SETTINGS={}, logger=Mock(), WireGuardManager=type('Unused', (), {}))
        self.ns['_check_admin'] = lambda r: {'role': r.headers.get('X-Synthetic-Role', 'none')}
        names = {'load_data', 'save_data', 'ConnectionSpeedRequest', 'api_set_connection_speed', '_manager_call'}
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        nodes = [n for n in tree.body if getattr(n, 'name', '') in names]
        self.assertEqual({n.name for n in nodes}, names)
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.decorator_list = []
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), self.ns)
        self.ns['save_data']({'servers': [{'protocols': {'awg3': {}, 'xray': {}}}],
            'users': [{'id': 'user-a', 'username': 'keep-user', 'enabled': False,
                       'traffic_used': 430, 'traffic_limit': 500, 'expiration_date': '2030-01-01'}],
            'user_connections': [{'id': 'connection-a', 'user_id': 'user-a',
                'server_id': 0, 'protocol': 'awg3', 'client_id': 'peer-a', 'name': 'keep'}]})
        fixture = self

        class Manager:
            def get_clients(self, protocol):
                if fixture.outcome == 'read_failure' and fixture.calls:
                    raise TimeoutError('synthetic read timeout')
                return fixture.peers()

            def set_speed_limit(self, protocol, client_id, speed):
                fixture.calls.append((protocol, client_id, speed))
                if fixture.outcome == 'raise':
                    raise TimeoutError('synthetic apply timeout')
                peers = fixture.peers()
                peer = next(p for p in peers if p['clientId'] == client_id)
                if speed == 0:
                    peer['userData'].pop('maxSpeed', None)
                else:
                    peer['userData']['maxSpeed'] = 10 if fixture.outcome == 'mismatch' else speed
                fixture.peer_file.write_text(json.dumps(peers), encoding='utf-8')
                return {'status': 'success', **({'speed_warning': 'synthetic warning'} if fixture.outcome == 'warning' else {})}

            def rename_client(self, *args):
                raise AssertionError('speed-only API must never rename')

        def connect():
            self.assertFalse(self.ns['DATA_LOCK'].locked())
            if self.ssh_error:
                raise OSError('synthetic SSH failure')
            if self.gated:
                self.entered.set()
                if not self.release.wait(5):
                    raise TimeoutError('synthetic SSH gate')

        def disconnect():
            self.disconnects += 1

        self.ns['get_ssh'] = lambda server: SimpleNamespace(connect=connect, disconnect=disconnect)
        self.ns['get_protocol_manager'] = lambda *args: Manager() if self.supported else SimpleNamespace()
        app = FastAPI()
        app.post('/api/servers/{server_id}/connections/speed')(self.ns['api_set_connection_speed'])
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
            base_url='http://synthetic.invalid', headers={'X-Synthetic-Role': 'admin'})

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp.cleanup()

    def peers(self):
        return json.loads(self.peer_file.read_text(encoding='utf-8'))

    async def post(self, speed=20, **kwargs):
        return await self.client.post('/api/servers/0/connections/speed',
            json={'protocol': 'awg3', 'client_id': 'peer-a', 'max_speed': speed}, **kwargs)

    async def test_twenty_changes_only_target_peer(self):
        before = self.file.read_bytes()
        peers = self.peers()
        response = await self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['max_speed'], 20)
        self.assertEqual(self.calls, [('awg3', 'peer-a', 20)])
        peers[0]['userData']['maxSpeed'] = 20
        self.assertEqual(self.peers(), peers)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_zero_removes_limit(self):
        self.assertEqual((await self.post(0)).status_code, 200)
        self.assertNotIn('maxSpeed', self.peers()[0]['userData'])
        self.assertEqual(self.peers()[1]['userData']['maxSpeed'], 99)

    async def test_retry_is_idempotent(self):
        await self.post()
        await self.post()
        self.assertEqual(len(self.peers()), 2)
        self.assertEqual(self.peers()[0]['clientId'], 'peer-a')
        self.assertEqual(self.peers()[0]['userData']['maxSpeed'], 20)

    async def test_apply_failures_and_warning_are_not_success(self):
        for outcome in ['raise', 'warning', 'mismatch', 'read_failure']:
            with self.subTest(outcome=outcome):
                self.outcome = outcome
                self.calls.clear()
                before = self.file.read_bytes()
                response = await self.post()
                self.assertEqual(response.status_code, 502)
                self.assertNotIn('success', response.json().values())
                self.assertEqual(self.file.read_bytes(), before)
                self.outcome = None
                self.assertEqual((await self.post()).status_code, 200)

    async def test_ssh_failure_disconnects_and_does_not_write(self):
        self.ssh_error = True
        before = self.file.read_bytes()
        self.assertEqual((await self.post()).status_code, 502)
        self.assertEqual(self.file.read_bytes(), before)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.disconnects, 1)

    async def test_admin_only_using_existing_auth_resolution(self):
        for role in ['user', 'support', 'none']:
            self.assertEqual((await self.post(headers={'X-Synthetic-Role': role})).status_code, 403)
        self.assertEqual(self.calls, [])

    async def test_unsupported_protocol(self):
        self.supported = False
        self.assertEqual((await self.post()).status_code, 501)
        self.assertEqual(self.calls, [])

    async def test_missing_server_protocol_and_client(self):
        body = {'protocol': 'awg3', 'client_id': 'peer-a', 'max_speed': 20}
        for sid in [-1, 1]:
            self.assertEqual((await self.client.post(f'/api/servers/{sid}/connections/speed', json=body)).status_code, 404)
        for key, value in [('protocol', 'missing'), ('client_id', 'missing')]:
            self.assertEqual((await self.client.post('/api/servers/0/connections/speed', json={**body, key: value})).status_code, 404)
        self.assertEqual(self.calls, [])

    async def test_bounds_and_finite_values(self):
        for value in [-1, 0.01, 0.05, 1000000.1]:
            self.assertEqual((await self.post(value)).status_code, 400)
        for raw in ['NaN', 'Infinity', '-Infinity', '1e400']:
            response = await self.client.post('/api/servers/0/connections/speed',
                content='{"protocol":"awg3","client_id":"peer-a","max_speed":'+raw+'}',
                headers={'Content-Type': 'application/json'})
            self.assertEqual(response.status_code, 400)
        for value in [True, '20', 'invalid']:
            self.assertEqual((await self.post(value)).status_code, 422)
        self.assertEqual(self.calls, [])
        for value in [0.1, 1.5, 1000000]:
            self.assertEqual((await self.post(value)).status_code, 200)

    async def test_concurrent_fields_and_restart(self):
        self.gated = True
        task = asyncio.create_task(self.post())
        try:
            self.assertTrue(await asyncio.to_thread(self.entered.wait, 3))
            async def concurrent_write():
                async with self.ns['DATA_LOCK']:
                    data = self.ns['load_data']()
                    data['users'][0].update(traffic_used=480, traffic_limit=750,
                        expiration_date='2031-01-01', username='concurrent', enabled=True)
                    data['user_connections'].append({'id': 'independent', 'name': 'new'})
                    self.ns['save_data'](data)
                    return copy.deepcopy(data)
            expected = await asyncio.wait_for(concurrent_write(), 3)
        finally:
            self.release.set()
            response = await asyncio.wait_for(task, 3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.ns['load_data'](), expected)
        code = 'import json,sys; print(json.dumps(json.load(open(sys.argv[1],encoding="utf-8"))))'
        for file, expected in [(self.file, expected), (self.peer_file, self.peers())]:
            self.assertEqual(json.loads(subprocess.check_output([sys.executable, '-c', code, str(file)], text=True)), expected)


class NativeManagerWarnings(unittest.TestCase):
    def test_actual_apply_checks_remote_exit_status(self):
        from test_clients_table_lock import fake_ssh, awg_mgr
        for step in ['_amnz_bwlimits', '_amnz_tc.sh']:
            with self.subTest(step=step):
                ssh, _, _ = fake_ssh()
                manager = awg_mgr(ssh)
                manager.check_container_running = Mock(return_value=True)
                manager._resolve_config_path = Mock(return_value='/opt/amnezia/awg/awg0.conf')
                ssh.run_sudo_command = Mock(side_effect=lambda command, **kwargs:
                    ('', 'synthetic command failure', 1) if step in command else ('', '', 0))
                with self.assertRaises(RuntimeError):
                    manager._apply_bw_limits('awg2', [])

    def test_stopped_container_is_not_reported_as_applied(self):
        from test_clients_table_lock import fake_ssh, awg_mgr
        ssh, _, _ = fake_ssh()
        manager = awg_mgr(ssh)
        manager.check_container_running = Mock(return_value=False)
        with self.assertRaisesRegex(RuntimeError, 'container is not running'):
            manager._apply_bw_limits('awg2', [])

    def test_actual_manager_persists_speed_and_zero(self):
        from test_clients_table_lock import fake_ssh, awg_mgr
        ssh, state, _ = fake_ssh()
        manager = awg_mgr(ssh)
        manager._apply_bw_limits = Mock(return_value=None)
        self.assertEqual(manager.set_speed_limit('awg2', 'KEY_A', 20)['max_speed'], 20)
        self.assertEqual(json.loads(state['table'])[0]['userData']['maxSpeed'], 20)
        self.assertEqual(awg_mgr(ssh)._get_clients_table('awg2')[0]['userData']['maxSpeed'], 20)
        manager.set_speed_limit('awg2', 'KEY_A', 0)
        table = json.loads(state['table'])
        self.assertNotIn('maxSpeed', table[0]['userData'])
        self.assertEqual(table[1]['userData'], {'clientName': 'beta'})

    def test_actual_manager_propagates_apply_exception(self):
        from test_clients_table_lock import fake_ssh, awg_mgr
        ssh, state, _ = fake_ssh()
        manager = awg_mgr(ssh)
        for error in [TimeoutError('synthetic apply failure'), TimeoutError()]:
            manager._apply_bw_limits = Mock(side_effect=error)
            with self.assertRaisesRegex(RuntimeError, 'Speed limit was not applied'):
                manager.set_speed_limit('awg2', 'KEY_A', 20)
        # Metadata may already be durable. A retry must re-apply, not assume success.
        self.assertEqual(json.loads(state['table'])[0]['userData']['maxSpeed'], 20)
        manager._apply_bw_limits = Mock(return_value=None)
        self.assertEqual(manager.set_speed_limit('awg2', 'KEY_A', 20)['status'], 'success')


if __name__ == '__main__':
    unittest.main(verbosity=2)
