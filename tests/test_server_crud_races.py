"""Actual CRUD handlers + atomic JSON persistence; synthetic SSH/exit targets only."""
import ast
import asyncio
import copy
import inspect
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel
from typing import List, Optional

FUNCTIONS = {'load_data', 'save_data', 'find_server_by_uid', '_finish_locked_worker',
             '_finish_server_operation', '_server_identity',
             'api_add_server', 'api_edit_server', 'api_reorder_servers', 'api_delete_server'}
MODELS = {'AddServerRequest', 'EditServerRequest', 'ReorderServersRequest'}


def seed():
    return {'servers': [dict(uid=uid, name=uid, host=f'{uid}.example.test', ssh_port=22,
                            username='fixture', password='test-only', private_key='', protocols={})
                        for uid in ['a', 'b', 'c']],
            'users': [{'id': 'user', 'traffic_used': 17, 'expiration_date': '2030-01-01'}],
            'user_connections': [dict(user_id='user', server_id=i, protocol='awg', client_id=uid)
                                 for i, uid in enumerate(['a', 'b', 'c'])]}


class CrudTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'data.json'
        source = Path(os.environ.get('PANEL_CRUD_SOURCE', Path(__file__).resolve().parents[1] / 'app.py'))
        tree = ast.parse(source.read_text(encoding='utf-8'))
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in FUNCTIONS
                 or isinstance(n, ast.ClassDef) and n.name in MODELS]
        for node in nodes:
            node.decorator_list = []
        self.ssh = Mock()
        self.ssh.test_connection.return_value = {'os': 'synthetic'}
        self.exit = SimpleNamespace(detach_entries_for_exit=AsyncMock(return_value=[]),
                                    forget_entry_peers=AsyncMock(return_value=[]))
        self.p = dict(asyncio=asyncio, os=os, json=json, tempfile=tempfile, uuid=uuid,
                      Request=Request, JSONResponse=JSONResponse, BaseModel=BaseModel,
                      List=List, Optional=Optional, logger=Mock(), DATA_FILE=str(self.path),
                      DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={},
                      DATA_LOCK=asyncio.Lock(), SERVER_MUTATION_LOCK=asyncio.Lock(),
                      _check_admin=lambda r: r.headers.get('x-role', 'admin') == 'admin',
                      SSHManager=Mock(return_value=self.ssh), drop_ssh=Mock(), exit_link_svc=self.exit)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), self.p)
        self.save = self.p['save_data']
        self.save(seed())
        self.request = SimpleNamespace(headers={})

    def data(self):
        return json.loads(self.path.read_text(encoding='utf-8'))

    def uids(self):
        return [s['uid'] for s in self.data()['servers']]

    @staticmethod
    def status(result):
        return result.status_code if isinstance(result, JSONResponse) else 200

    async def add(self):
        req = self.p['AddServerRequest'](host='d.example.test', username='fixture', password='test-only', name='d')
        fn = self.p['api_add_server']
        return await fn(self.request, req) if inspect.iscoroutinefunction(fn) else await asyncio.to_thread(fn, self.request, req)

    async def reorder(self, order):
        return await self.p['api_reorder_servers'](self.request, self.p['ReorderServersRequest'](order=order))

    async def paused_delete(self, index=0, threaded=False):
        if threaded:
            started, release = threading.Event(), threading.Event()
            def worker(server):
                started.set()
                if not release.wait(5):
                    raise TimeoutError('fixture barrier not released')
                return []
            async def cleanup(server):
                return await asyncio.to_thread(worker, server)
        else:
            started, release = asyncio.Event(), asyncio.Event()
            async def cleanup(server):
                started.set()
                await release.wait()
                return []
        self.exit.forget_entry_peers.side_effect = cleanup
        task = asyncio.create_task(self.p['api_delete_server'](self.request, index))
        if threaded:
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
        else:
            await asyncio.wait_for(started.wait(), 2)
        return task, release

    async def test_delete_reorder_never_deletes_replacement_index(self):
        task, release = await self.paused_delete()
        other = asyncio.create_task(self.reorder([1, 0, 2]))
        await asyncio.sleep(0)  # scheduling checkpoint, not a timing delay
        release.set()
        deleted, reordered = await asyncio.gather(task, other)
        self.assertEqual(self.status(deleted), 200)
        self.assertIn(self.status(reordered), [200, 409])
        self.assertEqual(set(self.uids()), {'b', 'c'})
        self.assertEqual({c['client_id'] for c in self.data()['user_connections']}, {'b', 'c'})

    async def test_duplicate_delete_cleans_uid_only_once(self):
        task, release = await self.paused_delete()
        other = asyncio.create_task(self.p['api_delete_server'](self.request, 0))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(task, other)
        self.assertEqual(self.uids(), ['b', 'c'])
        self.assertEqual(self.exit.forget_entry_peers.await_count, 1)

    async def test_deletes_of_different_servers_preserve_remaining_connections(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def cleanup(server):
            if server['uid'] == 'a':
                started.set()
                await release.wait()
            return []
        self.exit.forget_entry_peers.side_effect = cleanup
        first = asyncio.create_task(self.p['api_delete_server'](self.request, 0))
        await started.wait()
        second = asyncio.create_task(self.p['api_delete_server'](self.request, 1))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first, second)
        self.assertEqual(self.uids(), ['c'])
        self.assertEqual(self.data()['user_connections'][0]['server_id'], 0)
        self.assertEqual([call.args[0]['uid'] for call in self.exit.forget_entry_peers.await_args_list], ['a', 'b'])

    async def test_add_and_reorder_cannot_commit_an_old_inventory(self):
        original = self.p['load_data']
        loop = asyncio.get_running_loop()
        changed = asyncio.Event()
        release = threading.Event()
        paused = []
        loop_thread = threading.get_ident()
        def load():
            data = original()
            if threading.get_ident() != loop_thread and not paused:
                paused.append(True)
                loop.call_soon_threadsafe(changed.set)
                if not release.wait(5):
                    raise TimeoutError('fixture load barrier')
            return data
        self.p['load_data'] = load
        task = asyncio.create_task(self.add())
        task.add_done_callback(lambda _: changed.set())
        try:
            await asyncio.wait_for(changed.wait(), 2)
            await self.reorder([1, 0, 2] if paused else [1, 0, 2, 3])
        finally:
            release.set()
        self.assertEqual(self.status(await task), 200)
        self.assertEqual([s['name'] for s in self.data()['servers']], ['b', 'a', 'c', 'd'])
        self.assertEqual(len(set(self.uids())), 4)

    async def test_edit_ssh_does_not_block_independent_data_updates(self):
        started, release = threading.Event(), threading.Event()
        def verify():
            started.set()
            if not release.wait(5):
                raise TimeoutError('fixture SSH barrier')
            return {'os': 'synthetic'}
        self.ssh.test_connection.side_effect = verify
        task = asyncio.create_task(self.p['api_edit_server'](self.request, 0, self.p['EditServerRequest'](host='new.example.test')))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
            self.assertFalse(self.p['DATA_LOCK'].locked(), 'DATA_LOCK held across SSH')
            async with self.p['DATA_LOCK']:
                data = self.p['load_data']()
                data['users'][0]['traffic_used'] = 99
                data['servers'][0]['protocols']['awg'] = {'installed': True}
                self.save(data)
        finally:
            release.set()
            result = await task
        self.assertEqual(self.status(result), 200)
        self.assertEqual(self.data()['users'][0]['traffic_used'], 99)
        self.assertTrue(self.data()['servers'][0]['protocols']['awg']['installed'])
        self.assertEqual(self.data()['servers'][0]['uid'], 'a')
        self.assertEqual(self.p['drop_ssh'].call_args.args[0]['host'], 'a.example.test')

    async def test_edit_then_delete_keeps_uid_binding(self):
        started, release = threading.Event(), threading.Event()
        def verify():
            started.set()
            if not release.wait(5):
                raise TimeoutError('fixture SSH barrier')
            return {}
        self.ssh.test_connection.side_effect = verify
        edit = asyncio.create_task(self.p['api_edit_server'](self.request, 0, self.p['EditServerRequest'](name='renamed')))
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        delete = asyncio.create_task(self.p['api_delete_server'](self.request, 0))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(edit, delete)
        self.assertEqual(self.uids(), ['b', 'c'])
        self.assertEqual(self.exit.forget_entry_peers.call_args.args[0]['uid'], 'a')

    async def test_delete_merges_concurrent_user_and_connection_changes(self):
        task, release = await self.paused_delete()
        async with self.p['DATA_LOCK']:
            data = self.p['load_data']()
            data['users'][0]['traffic_used'] = 99
            data['users'][0]['expiration_date'] = '2031-01-01'
            data['user_connections'].append(dict(user_id='user', server_id=1, protocol='awg', client_id='new'))
            self.save(data)
        release.set()
        await task
        self.assertEqual(self.data()['users'][0]['traffic_used'], 99)
        self.assertEqual(self.data()['users'][0]['expiration_date'], '2031-01-01')
        self.assertEqual(next(c for c in self.data()['user_connections'] if c['client_id'] == 'new')['server_id'], 0)

    async def test_exit_delete_reorder_cleanup_uses_original_uid(self):
        data = self.data()
        data['servers'][0]['protocols']['exit'] = {'installed': True}
        self.save(data)
        task, release = await self.paused_delete()
        other = asyncio.create_task(self.reorder([1, 0, 2]))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(task, other)
        self.exit.detach_entries_for_exit.assert_awaited_once_with('a', 'exit_server_deleted')
        self.assertNotIn('a', self.uids())
        self.assertIn('b', self.uids())

    async def test_failed_exit_cleanup_does_not_remove_server_or_connections(self):
        self.exit.forget_entry_peers.return_value = [{'status': 'error', 'error': 'synthetic unreachable'}]
        before = self.data()
        result = await self.p['api_delete_server'](self.request, 0)
        self.assertEqual(self.status(result), 409)
        self.assertEqual(self.data(), before)
        self.p['drop_ssh'].assert_not_called()

    async def test_cleanup_exception_is_not_swallowed(self):
        self.exit.forget_entry_peers.side_effect = RuntimeError('synthetic unreachable')
        before = self.data()
        result = await self.p['api_delete_server'](self.request, 0)
        self.assertNotEqual(self.status(result), 200)
        self.assertEqual(self.data(), before)

    async def test_cancelled_delete_finishes_before_unlocking(self):
        task, release = await self.paused_delete(threaded=True)
        try:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            self.assertFalse(task.done(), 'request cancellation abandoned running cleanup')
            self.assertTrue(self.p['SERVER_MUTATION_LOCK'].locked())
        finally:
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.uids(), ['b', 'c'])

    async def test_save_failure_reports_uncommitted_partial_result(self):
        def fail(data):
            raise OSError('synthetic disk failure')
        self.p['save_data'] = fail
        before = self.data()
        result = await self.p['api_delete_server'](self.request, 0)
        self.assertEqual(self.status(result), 500)
        payload = json.loads(result.body)
        self.assertTrue(payload['cleanup_completed'])
        self.assertFalse(payload['deletion_committed'])
        self.assertEqual(self.data(), before)
        self.p['drop_ssh'].assert_not_called()

    async def test_invalid_server_indices_never_touch_ssh_or_state(self):
        for index in [-1, -999, 3, 99]:
            with self.subTest(index=index):
                before = self.data()
                self.assertEqual(self.status(await self.p['api_delete_server'](self.request, index)), 404)
                self.assertEqual(self.status(await self.p['api_edit_server'](self.request, index, self.p['EditServerRequest']())), 404)
                self.assertEqual(self.data(), before)
        self.p['SSHManager'].assert_not_called()
        self.exit.forget_entry_peers.assert_not_awaited()

    async def test_old_endpoint_pool_is_invalidated_after_edit(self):
        result = await self.p['api_edit_server'](self.request, 0, self.p['EditServerRequest'](host='new.example.test'))
        self.assertEqual(self.status(result), 200)
        self.assertEqual(self.p['drop_ssh'].call_args.args[0]['host'], 'a.example.test')

    async def test_ssh_failure_leaves_edit_and_add_state_unchanged(self):
        self.ssh.connect.side_effect = RuntimeError('synthetic SSH failure')
        before = self.data()
        edited = await self.p['api_edit_server'](self.request, 0, self.p['EditServerRequest'](host='other.example.test'))
        added = await self.add()
        self.assertEqual(self.status(edited), 400)
        self.assertEqual(self.status(added), 400)
        self.assertEqual(self.data(), before)
        self.assertEqual(self.ssh.disconnect.call_count, 2)
        self.p['drop_ssh'].assert_not_called()

    async def test_save_failure_preserves_edit_and_add_state(self):
        def fail(data):
            raise OSError('synthetic disk failure')
        self.p['save_data'] = fail
        before = self.data()
        edited = await self.p['api_edit_server'](self.request, 0, self.p['EditServerRequest'](host='other.example.test'))
        added = await self.add()
        self.assertEqual(self.status(edited), 500)
        self.assertEqual(self.status(added), 500)
        self.assertEqual(self.data(), before)
        self.p['drop_ssh'].assert_not_called()

    async def test_http_crud_and_uid_remapping(self):
        app = FastAPI()
        for route, name in [('/api/servers/add', 'api_add_server'), ('/api/servers/reorder', 'api_reorder_servers'), ('/api/servers/{server_id}/delete', 'api_delete_server'), ('/api/servers/{server_id}/edit', 'api_edit_server')]:
            app.add_api_route(route, self.p[name], methods=['POST'])
        with TestClient(app) as client:
            r = client.post('/api/servers/add', json={'host': 'd.example.test', 'username': 'fixture', 'password': 'test-only', 'name': 'd'})
            self.assertEqual(r.status_code, 200, r.text)
            new_uid = self.uids()[3]
            r = client.post('/api/servers/0/edit?server_uid=a', json={'name': 'renamed'})
            self.assertEqual(r.status_code, 200, r.text)
            r = client.post('/api/servers/reorder', json={'order': [2, 0, 1, 3], 'server_uids': ['c', 'a', 'b', new_uid]})
            self.assertEqual(r.status_code, 200, r.text)
            before = self.data()
            r = client.post('/api/servers/0/delete?server_uid=a')
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(self.data(), before)
            r = client.post('/api/servers/1/delete?server_uid=a')
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(self.uids(), ['c', 'b', new_uid])
            self.assertEqual([(c['client_id'], c['server_id']) for c in self.data()['user_connections']], [('b', 1), ('c', 0)])
            r = client.post('/api/servers/1/delete?server_uid=a')
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(self.uids(), ['c', 'b', new_uid])

    async def test_http_stale_uid_and_negative_indices_are_rejected(self):
        app = FastAPI()
        for route, name in [('/api/servers/{server_id}/delete', 'api_delete_server'), ('/api/servers/{server_id}/edit', 'api_edit_server')]:
            app.add_api_route(route, self.p[name], methods=['POST'])
        with TestClient(app) as client:
            before = self.data()
            for path, body in [('/api/servers/-1/delete', {}), ('/api/servers/0/delete?server_uid=obsolete', {}), ('/api/servers/0/edit?server_uid=obsolete', {'name': 'unsafe'})]:
                r = client.post(path, json=body)
                self.assertIn(r.status_code, [404, 409], r.text)
                self.assertEqual(self.data(), before)
            r = client.post('/api/servers/0/delete', headers={'x-role': 'user'})
            self.assertEqual(r.status_code, 403)
            self.assertEqual(self.data(), before)


if __name__ == '__main__':
    unittest.main()
