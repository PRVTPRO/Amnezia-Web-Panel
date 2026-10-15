"""Real user handlers/persistence with synthetic JSON files and deterministic SSH gates."""
import ast
import asyncio
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from typing import Optional
import unittest

from pydantic import BaseModel
from fastapi.responses import JSONResponse

SOURCE = Path(__file__).resolve().parents[1] / 'app.py'
GIB = 1024 ** 3


def actual_code(path, data_file, request_type=object, response_type=JSONResponse):
    """Extract unchanged production functions rather than copying their logic."""
    names = {
        'load_data', 'save_data', 'perform_toggle_user', 'api_update_user',
        'api_toggle_user', 'UpdateUserRequest', 'ToggleUserRequest',
    }
    tree = ast.parse(path.read_text(encoding='utf-8'))
    nodes = [node for node in tree.body if getattr(node, 'name', '') in names]
    assert {node.name for node in nodes} == names
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.decorator_list = []
    ns = dict(
        asyncio=asyncio, datetime=datetime, os=os, json=json, tempfile=tempfile,
        BaseModel=BaseModel, Optional=Optional, Request=request_type,
        JSONResponse=response_type, DATA_FILE=str(data_file),
        DATA_LOCK=asyncio.Lock(), DEFAULT_MAIL_SETTINGS={},
        DEFAULT_SELF_SERVICE_SETTINGS={}, logger=logging.getLogger('mock-panel'),
        _check_admin=lambda request: request.admin,
        get_current_user=lambda request: {'role': 'admin' if request.admin else 'user'},
        _t=lambda key, lang: key,
        _normalize_telegram_id=lambda value: value,
        hash_password=lambda value: 'test-hash',
    )
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 str(path), 'exec'), ns)
    return ns


class SnapshotRace(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel174-synthetic-')
        self.file = Path(self.temp.name) / 'data.json'
        self.ns = actual_code(SOURCE, self.file)
        self.request = SimpleNamespace(admin=True, cookies={})
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.ssh_calls = []
        self.error = None
        self.gate = True
        user = dict(id='synthetic-a', username='alice', enabled=False,
                    traffic_used=430*GIB, traffic_total=900*GIB,
                    traffic_limit=500*GIB, expiration_date='2030-01-01T00:00:00',
                    email='alice@example.invalid', description='before',
                    traffic_reset_strategy='monthly', last_reset_at='2026-10-01T00:00:00')
        self.ns['save_data'](dict(users=[user, dict(user, id='synthetic-b', username='bob')],
            servers=[{'host': 'mock.invalid'}],
            user_connections=[dict(id='conn-a', user_id='synthetic-a', server_id=0,
                                   protocol='awg', client_id='mock-client')]))

        async def to_thread(function, *args, **kwargs):
            # A deterministic SSH boundary. No wall-clock sleeps or networking.
            if function is self.ns['get_ssh']:
                if self.gate:
                    self.entered.set()
                    await self.release.wait()
                if self.error:
                    raise self.error
            return function(*args, **kwargs)

        self.ns['get_ssh'] = lambda server: SimpleNamespace(
            connect=lambda: None, disconnect=lambda: None)
        self.ns['get_protocol_manager'] = lambda ssh, protocol: object()
        self.ns['_manager_call'] = lambda *args: self.ssh_calls.append(args[1:])
        # Only this extracted module's asyncio.to_thread is mocked.
        self.ns['asyncio'] = SimpleNamespace(to_thread=to_thread)

    async def asyncTearDown(self):
        self.temp.cleanup()

    def user(self):
        return next(u for u in self.ns['load_data']()['users'] if u['id'] == 'synthetic-a')

    async def update(self, **fields):
        return await self.ns['api_update_user'](
            self.request, 'synthetic-a', self.ns['UpdateUserRequest'](**fields))

    async def concurrent_change(self):
        # Same load/modify/atomic-save used by background traffic accounting,
        # with its existing DATA_LOCK. This writes a REAL JSON file.
        async with self.ns['DATA_LOCK']:
            data = self.ns['load_data']()
            user = next(u for u in data['users'] if u['id'] == 'synthetic-a')
            user.update(traffic_used=480*GIB, traffic_total=950*GIB,
                        expiration_date='2031-01-01T00:00:00', description='concurrent',
                        last_reset_at='2026-10-12T12:00:00')
            data['users'][1]['email'] = 'changed@example.invalid'
            data['user_connections'][0]['last_bytes'] = 12345
            self.ns['save_data'](data)

    async def race(self, operation, second=None):
        task = asyncio.create_task(operation)
        try:
            await asyncio.wait_for(self.entered.wait(), timeout=2)
            self.gate = False  # Only A is held at the synthetic SSH boundary.
            await asyncio.wait_for(second() if second else self.concurrent_change(), timeout=2)
        finally:
            self.release.set()
            result = await asyncio.wait_for(task, timeout=2)
        return result

    def assert_concurrent_fields(self):
        user = self.user()
        self.assertEqual(user['traffic_used'], 480*GIB)
        self.assertEqual(user['traffic_total'], 950*GIB)
        self.assertEqual(user['expiration_date'], '2031-01-01T00:00:00')
        self.assertEqual(user['description'], 'concurrent')
        self.assertEqual(user['last_reset_at'], '2026-10-12T12:00:00')
        data = self.ns['load_data']()
        self.assertEqual(data['users'][1]['email'], 'changed@example.invalid')
        self.assertEqual(data['user_connections'][0]['last_bytes'], 12345)

    async def test_quota_ssh_preserves_concurrent_persisted_state(self):
        result = await self.race(self.update(traffic_limit=1000))
        self.assertEqual(result, {'status': 'success'})
        self.assert_concurrent_fields()
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)
        self.assertTrue(self.user()['enabled'])
        self.assertEqual(len(self.ssh_calls), 1)

    async def test_toggle_ssh_preserves_concurrent_persisted_state(self):
        result = await self.race(self.ns['api_toggle_user'](
            self.request, 'synthetic-a', self.ns['ToggleUserRequest'](enabled=True)))
        self.assertEqual(result['status'], 'success')
        self.assert_concurrent_fields()

    async def test_later_quota_update_survives(self):
        await self.race(self.update(traffic_limit=1000),
                        lambda: self.update(traffic_limit=750, description='later'))
        self.assertEqual(self.user()['traffic_limit'], 750*GIB)
        self.assertEqual(self.user()['description'], 'later')

    async def test_later_expiration_update_survives(self):
        await self.race(self.update(traffic_limit=1000), lambda: self.update(
            expiration_date='2032-01-01T00:00:00', traffic_limit=None))
        self.assertEqual(self.user()['expiration_date'], '2032-01-01T00:00:00')

    async def test_later_disable_intent_is_not_overwritten(self):
        async def disable():
            self.gate = False
            await self.ns['api_toggle_user'](self.request, 'synthetic-a',
                self.ns['ToggleUserRequest'](enabled=False))
        await self.race(self.update(traffic_limit=1000), disable)
        self.assertFalse(self.user()['enabled'])

    async def test_ssh_failure_preserves_concurrent_data(self):
        self.error = OSError('synthetic SSH failure')
        result = await self.race(self.update(traffic_limit=1000))
        self.assertEqual(result, {'status': 'success'})  # existing best-effort policy
        self.assert_concurrent_fields()
        self.assertTrue(self.user()['enabled'])
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)

    async def test_ssh_timeout_preserves_concurrent_data(self):
        self.error = TimeoutError('synthetic SSH timeout')
        await self.race(self.update(traffic_limit=1000))
        self.assert_concurrent_fields()
        self.assertTrue(self.user()['enabled'])
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)

    async def test_cancellation_preserves_committed_enable_and_quota(self):
        task = asyncio.create_task(self.update(traffic_limit=1000))
        await asyncio.wait_for(self.entered.wait(), 2)
        await self.concurrent_change()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assert_concurrent_fields()
        self.assertTrue(self.user()['enabled'])
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)

    async def test_username_only_does_not_zero_quota_or_touch_usage(self):
        before = self.user()
        result = await self.update(username='renamed')
        expected = dict(before, username='renamed')
        self.assertEqual(self.user(), expected)
        self.assertEqual(result, {'status': 'success'})
        self.assertFalse(self.entered.is_set())

    async def test_explicit_zero_still_means_unlimited(self):
        before = self.user()
        await self.update(traffic_limit=0)
        self.assertEqual(self.user(), dict(before, traffic_limit=0))
        self.assertFalse(self.entered.is_set())

    async def test_explicit_null_quota_is_unchanged(self):
        before = self.user()
        await self.update(traffic_limit=None, email='new@example.invalid')
        self.assertEqual(self.user(), dict(before, email='new@example.invalid'))

    async def test_expiration_clear_and_omission(self):
        await self.update(expiration_date=None, traffic_limit=None)
        self.assertIsNone(self.user()['expiration_date'])
        await self.update(description='test', traffic_limit=None)
        self.assertIsNone(self.user()['expiration_date'])

    async def test_explicit_reset_strategy_keeps_existing_semantics(self):
        before = self.user()
        await self.update(traffic_reset_strategy='monthly', traffic_limit=None)
        self.assertEqual(self.user()['traffic_used'], before['traffic_used'])
        self.assertNotEqual(self.user()['last_reset_at'], before['last_reset_at'])

    async def test_limit_below_usage_does_not_auto_enable(self):
        await self.update(traffic_limit=100)
        self.assertFalse(self.user()['enabled'])
        self.assertFalse(self.entered.is_set())

    async def test_username_conflict_does_not_save(self):
        before = self.file.read_bytes()
        result = await self.update(username='bob', traffic_limit=None)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_forbidden_does_not_save_or_ssh(self):
        self.request.admin = False
        before = self.file.read_bytes()
        result = await self.update(traffic_limit=1000)
        self.assertEqual(result.status_code, 403)
        result = await self.ns['api_toggle_user'](self.request, 'synthetic-a',
                                                self.ns['ToggleUserRequest'](enabled=True))
        self.assertEqual(result.status_code, 403)
        self.assertEqual(self.file.read_bytes(), before)
        self.assertFalse(self.entered.is_set())

    async def test_missing_user_does_not_save_or_ssh(self):
        before = self.file.read_bytes()
        for function, model in [('api_update_user', 'UpdateUserRequest'),
                                ('api_toggle_user', 'ToggleUserRequest')]:
            req = self.ns[model](**({'enabled': True} if model == 'ToggleUserRequest' else {}))
            result = await self.ns[function](self.request, 'missing', req)
            self.assertEqual(result.status_code, 404)
        self.assertEqual(self.file.read_bytes(), before)
        self.assertFalse(self.entered.is_set())

    async def test_persistence_after_fresh_process(self):
        await self.race(self.update(traffic_limit=1000))
        code = """import ast,json,os,sys
from pathlib import Path
tree=ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'))
node=next(n for n in tree.body if getattr(n,'name','')=='load_data')
ns=dict(os=os,json=json,DATA_FILE=sys.argv[2],DEFAULT_MAIL_SETTINGS={},DEFAULT_SELF_SERVICE_SETTINGS={})
exec(compile(ast.Module(body=[node],type_ignores=[]),sys.argv[1],'exec'),ns)
print(json.dumps(ns['load_data']()))
"""
        persisted = json.loads(subprocess.check_output(
            [sys.executable, '-c', code, str(SOURCE), str(self.file)], text=True))
        user = next(u for u in persisted['users'] if u['id'] == 'synthetic-a')
        self.assertEqual(user['traffic_used'], 480*GIB)
        self.assertEqual(user['expiration_date'], '2031-01-01T00:00:00')
        self.assertEqual(persisted, self.ns['load_data']())


if __name__ == '__main__':
    unittest.main(verbosity=2)
