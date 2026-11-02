"""Run the real unlink handler and atomic JSON storage without SSH/startup."""
import ast
import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid

from fastapi.responses import JSONResponse

from peer_finalization import (
    connection_scope,
    find_connection,
    finalize_connection_record,
    commit_finalize,
    make_intent,
)
from user_state import apply_traffic_samples, traffic_server_identity


SOURCE = Path(__file__).resolve().parents[1] / 'app.py'
GIB = 1024 ** 3


class UnlinkAccountingGuard(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel-unlink-accounting-')
        self.addAsyncCleanup(self.cleanup)
        self.file = Path(self.temp.name) / 'data.json'
        names = {'load_data', 'save_data', 'api_unlink_user_connection',
                 '_traffic_removal_guard', '_actor_id'}
        nodes = [n for n in ast.parse(SOURCE.read_text(encoding='utf-8')).body
                 if getattr(n, 'name', '') in names]
        self.assertEqual({n.name for n in nodes}, names)
        for node in nodes:
            node.decorator_list = []

        self.ssh_mock = SimpleNamespace(
            connect=lambda: None,
            disconnect=lambda: None,
        )
        self.manager_mock = SimpleNamespace()
        self.peer_state = (None, False)  # (observed_bytes, quiescent)
        self.stop_succeeds = True

        def read_peer_state(manager, protocol, client_id):
            return self.peer_state

        def get_ssh(server):
            return self.ssh_mock

        def get_protocol_manager(ssh, protocol):
            return self.manager_mock

        def manager_call(manager, method, protocol, *args, **kwargs):
            if method == 'toggle_client' and self.stop_succeeds:
                self.peer_state = (self.peer_state[0], True)
            return None

        self.ns = dict(
            asyncio=asyncio, os=os, json=json, tempfile=tempfile, uuid=uuid,
            copy=copy, time=time,
            DATA_FILE=str(self.file), DATA_LOCK=asyncio.Lock(),
            DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={},
            Request=object, UnlinkConnectionRequest=object,
            JSONResponse=JSONResponse, _check_admin=lambda request: request.admin,
            get_current_user=lambda request: {'id': 'admin-1'},
            get_ssh=get_ssh, get_protocol_manager=get_protocol_manager,
            _manager_call=manager_call,
            pathlib_read_data_bytes=lambda: self.file.read_bytes() if self.file.exists() else b'',
            connection_scope=connection_scope,
            find_connection=find_connection,
            read_peer_state=read_peer_state,
            finalize_connection_record=finalize_connection_record,
            commit_finalize=commit_finalize,
            make_intent=make_intent,
            apply_traffic_samples=apply_traffic_samples,
            traffic_server_identity=traffic_server_identity,
        )
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(SOURCE), 'exec'), self.ns)
        self.data = {
            'users': [dict(id='user-a', enabled=True, traffic_limit=500*GIB,
                           traffic_used=450*GIB, traffic_total=700*GIB),
                      dict(id='user-b', enabled=True)],
            'servers': [dict(uid='server-a'), dict(uid='server-b')],
            'user_connections': [dict(id='conn-a', user_id='user-a', server_id=0,
                                      protocol='awg3', client_id='peer-a', last_bytes=10*GIB),
                                 dict(id='conn-b', user_id='user-b', server_id=0,
                                      protocol='awg3', client_id='peer-b', last_bytes=4*GIB)],
        }
        self.ns['save_data'](copy.deepcopy(self.data))
        self.request = SimpleNamespace(admin=True)
        self.req = SimpleNamespace(server_id=0, protocol='awg3', client_id='peer-a',
                                   stop=False, allow_unverified=False)

    async def cleanup(self):
        self.temp.cleanup()

    async def unlink(self, user='user-a', **changes):
        req = SimpleNamespace(**(vars(self.req) | changes))
        return await self.ns['api_unlink_user_connection'](self.request, user, req)

    def _load(self):
        return self.ns['load_data']()

    def _reset_data(self):
        if self.file.exists():
            self.file.unlink()
        recovery = Path(str(self.file) + '.recovery')
        if recovery.exists():
            import shutil
            shutil.rmtree(recovery)
        self.ns['save_data'](copy.deepcopy(self.data))

    def _status(self, result):
        return result.status_code if isinstance(result, JSONResponse) else 200

    def _body(self, result):
        if isinstance(result, JSONResponse):
            return json.loads(result.body)
        return result

    async def test_disabled_peer_unlinks_and_commits_accounting(self):
        self.peer_state = (12 * GIB, True)
        before = self.file.read_bytes()
        result = await self.unlink()
        self.assertEqual(self._status(result), 200)
        data = self._load()
        self.assertEqual(len(data['user_connections']), 1)
        self.assertIsNone(next((c for c in data['user_connections']
                                if c.get('id') == 'conn-a'), None))
        self.assertEqual(data['users'][0]['traffic_used'], 452 * GIB)
        self.assertEqual(data['users'][0]['traffic_total'], 702 * GIB)
        self.assertEqual(len(data.get('accounting_recoveries', [])), 1)
        self.assertNotEqual(self.file.read_bytes(), before)

    async def test_absent_peer_unlinks_without_counter(self):
        self.peer_state = (None, True)
        result = await self.unlink()
        self.assertEqual(self._status(result), 200)
        data = self._load()
        self.assertEqual(len(data['user_connections']), 1)
        self.assertEqual(len(data.get('accounting_recoveries', [])), 1)

    async def test_active_peer_requires_stop(self):
        self.peer_state = (12 * GIB, False)
        before = self.file.read_bytes()
        result = await self.unlink()
        self.assertEqual(self._status(result), 409)
        body = self._body(result)
        self.assertEqual(body['code'], 'peer_active_stop_required')
        self.assertTrue(body.get('can_stop'))
        self.assertEqual(self.file.read_bytes(), before)

    async def test_stop_and_unlink_disables_then_unlinks(self):
        self.peer_state = (12 * GIB, False)
        result = await self.unlink(stop=True)
        self.assertEqual(self._status(result), 200)
        data = self._load()
        self.assertEqual(len(data['user_connections']), 1)
        self.assertEqual(len(data.get('accounting_recoveries', [])), 1)

    async def test_active_peer_that_cannot_stop_is_rejected(self):
        self.peer_state = (12 * GIB, False)
        self.stop_succeeds = False
        before = self.file.read_bytes()
        result = await self.unlink(stop=True)
        self.assertEqual(self._status(result), 409)
        body = self._body(result)
        self.assertEqual(body['code'], 'peer_stop_failed')
        self.assertEqual(self.file.read_bytes(), before)

    async def test_disabled_metadata_is_not_finalization_proof(self):
        # A disabled *user* does not change peer quiescence logic.
        for reasons in (None, ['manual'], ['quota'], ['expired'], ['legacy']):
            with self.subTest(reasons=reasons):
                self._reset_data()
                data = self._load()
                data['users'][0].update(enabled=False, access_sync_pending=True)
                if reasons is not None:
                    data['users'][0]['disable_reasons'] = reasons
                self.ns['save_data'](data)
                self.peer_state = (12 * GIB, True)
                result = await self.unlink()
                self.assertEqual(self._status(result), 200)

    async def test_unlimited_quota_still_retains_lifetime_accounting(self):
        data = self._load()
        data['users'][0]['traffic_limit'] = 0
        self.ns['save_data'](data)
        self.peer_state = (12 * GIB, True)
        result = await self.unlink()
        self.assertEqual(self._status(result), 200)
        data = self._load()
        self.assertEqual(data['users'][0]['traffic_total'], 700 * GIB + 2 * GIB)

    async def test_repeated_and_concurrent_unlink_are_non_destructive(self):
        self.peer_state = (12 * GIB, True)
        results = await asyncio.gather(self.unlink(), self.unlink())
        codes = sorted([self._status(r) for r in results])
        self.assertEqual(codes, [200, 404])
        self.assertEqual(self._status(await self.unlink()), 404)

    async def test_target_is_resolved_after_waiting_for_current_data(self):
        lock = self.ns['DATA_LOCK']
        await lock.acquire()
        entered = asyncio.Event()

        async def queued():
            entered.set()
            return await self.unlink()

        task = asyncio.create_task(queued())
        await entered.wait()
        try:
            self.assertFalse(task.done())
            self._reset_data()
            data = self._load()
            data['user_connections'][0]['user_id'] = 'user-b'
            self.ns['save_data'](data)
            before = self.file.read_bytes()
        finally:
            lock.release()
        self.assertEqual(self._status(await task), 404)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_wrong_user_server_protocol_or_client_cannot_touch_links(self):
        self.peer_state = (12 * GIB, True)
        for user, change in [('user-b', {}), ('user-a', {'server_id': 1}),
                             ('user-a', {'protocol': 'wireguard'}),
                             ('user-a', {'client_id': 'unknown'})]:
            with self.subTest(user=user, change=change):
                self._reset_data()
                before = self.file.read_bytes()
                self.assertEqual(self._status(await self.unlink(user, **change)), 404)
                self.assertEqual(self.file.read_bytes(), before)

    async def test_anonymous_or_nonadmin_is_rejected_without_mutation(self):
        self.request.admin = False
        before = self.file.read_bytes()
        self.assertEqual(self._status(await self.unlink()), 403)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_cancellation_while_waiting_cannot_commit_a_late_unlink(self):
        lock = self.ns['DATA_LOCK']
        await lock.acquire()
        entered = asyncio.Event()

        async def queued():
            entered.set()
            return await self.unlink()

        task = asyncio.create_task(queued())
        await entered.wait()
        before = self.file.read_bytes()
        task.cancel()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            lock.release()
        self.assertEqual(self.file.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
