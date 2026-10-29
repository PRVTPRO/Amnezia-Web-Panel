"""Account intent, calendar enforcement and persisted state; no remote SSH."""
import asyncio
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch, AsyncMock

import app
from user_state import apply_traffic_samples, reset_calendar_traffic, traffic_server_identity

assert Path(app.__file__).resolve() == Path(__file__).resolve().parents[1] / 'app.py'


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 11, 1, 0, 1)
        return value if tz is None else value.replace(tzinfo=tz)


class AccountStates(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'data.json'
        self.patches = [patch.object(app, 'DATA_FILE', str(self.path)),
                        patch.object(app, 'DATA_LOCK', asyncio.Lock()),
                        patch.object(app, '_USER_STATE_TASKS', {}, create=True),
                        patch.object(app, '_TRAFFIC_SYNC_LOCK', asyncio.Lock(), create=True),
                        patch.object(app, '_check_admin', return_value=True),
                        patch.object(app, 'get_current_user', return_value={'role': 'admin'}),
                        patch.object(app, 'datetime', Clock)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.request = SimpleNamespace(cookies={})
        self.seed()

    def seed(self, **fields):
        user = dict(id='test', username='synthetic', role='none', enabled=True,
                    traffic_used=500, traffic_total=1000, traffic_limit=500,
                    traffic_reset_strategy='monthly', last_reset_at='2026-10-01T00:00:00',
                    expiration_date='2030-01-01T00:00:00')
        user.update(fields)
        app.save_data(dict(users=[user], servers=[], user_connections=[]))

    def user(self):
        return app.load_data()['users'][0]

    async def update(self, **fields):
        return await app.api_update_user(self.request, 'test', app.UpdateUserRequest(**fields))

    async def one_cycle(self):
        count = 0
        async def sleep(_):
            nonlocal count
            count += 1
            if count > 1:
                raise asyncio.CancelledError()
        namespace = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio)})
        namespace.sleep = sleep
        with patch.object(app, 'asyncio', namespace), \
             patch.object(app, 'run_auto_backups_if_due', AsyncMock()):
            with self.assertRaises(asyncio.CancelledError):
                await app.periodic_background_tasks()

    async def test_legacy_disabled_is_not_enabled_by_quota_edit(self):
        self.seed(enabled=False)
        await self.update(traffic_limit=1)
        self.assertFalse(self.user()['enabled'])

    async def test_manual_disable_survives_limit_and_expiration_changes(self):
        await app.api_toggle_user(self.request, 'test', app.ToggleUserRequest(enabled=False))
        await self.update(traffic_limit=1, expiration_date='2032-01-01T00:00:00')
        self.assertFalse(self.user()['enabled'])

    async def test_calendar_reset_without_traffic_recovers_only_quota_block(self):
        self.seed(enabled=False, disable_reasons=['quota'])
        await self.one_cycle()
        user = self.user()
        self.assertEqual(user['traffic_used'], 0)
        self.assertEqual(user['traffic_total'], 1000)
        self.assertTrue(user['enabled'])

    async def test_expiration_is_enforced_without_traffic_or_connections(self):
        self.seed(traffic_used=0, expiration_date='2026-10-31T23:59:00')
        await self.one_cycle()
        self.assertFalse(self.user()['enabled'])

    async def test_expiration_extension_recovers_known_automatic_block(self):
        self.seed(enabled=False, traffic_used=0, expiration_date='2026-10-31T23:59:00',
                  disable_reasons=['expired'])
        await self.update(expiration_date='2032-01-01T00:00:00')
        self.assertTrue(self.user()['enabled'])

    async def test_legacy_disabled_remains_disabled_after_calendar_reset(self):
        self.seed(enabled=False)
        await self.one_cycle()
        self.assertEqual(self.user()['traffic_used'], 0)
        self.assertFalse(self.user()['enabled'])

    async def test_multiple_blockers_and_explicit_manual_enable(self):
        self.seed(enabled=False, disable_reasons=['manual', 'quota', 'expired'],
                  expiration_date='2026-10-31T23:59:00')
        await self.update(traffic_limit=0)
        self.assertEqual(self.user()['disable_reasons'], ['expired', 'manual'])
        await app.api_toggle_user(self.request, 'test', app.ToggleUserRequest(enabled=True))
        self.assertFalse(self.user()['enabled'])
        await self.update(expiration_date=None)
        self.assertTrue(self.user()['enabled'])

    async def test_explicit_reset_preserves_lifetime_and_manual_disable(self):
        self.seed(enabled=False, disable_reasons=['manual', 'quota'])
        await app.api_reset_user_traffic(self.request, 'test')
        self.assertEqual(self.user()['traffic_used'], 0)
        self.assertEqual(self.user()['traffic_total'], 1000)
        self.assertFalse(self.user()['enabled'])
        self.assertEqual(self.user()['disable_reasons'], ['manual'])

    async def test_external_enable_cannot_clear_manual_or_legacy_block(self):
        for reasons in [None, ['manual']]:
            self.seed(enabled=False)
            if reasons is not None:
                data = app.load_data()
                data['users'][0]['disable_reasons'] = reasons
                app.save_data(data)
            self.assertTrue(await app.perform_mass_operations(toggle_uids=[('test', True)]))
            self.assertFalse(self.user()['enabled'])

    async def test_legacy_lifetime_is_not_zeroed_by_calendar_reset(self):
        data = app.load_data()
        del data['users'][0]['traffic_total']
        apply_traffic_samples(data, [], Clock.now())
        self.assertEqual(data['users'][0]['traffic_total'], 500)
        self.assertEqual(data['users'][0]['traffic_used'], 0)

    def attach_peer(self, enabled=False):
        data = app.load_data()
        data['servers'] = [dict(uid='node', host='synthetic.invalid', username='test')]
        data['user_connections'] = [dict(id='conn', user_id='test', server_id=0,
                                         protocol='awg3', client_id='peer', last_bytes=0)]
        app.save_data(data)
        self.peer_enabled = enabled
        self.calls = []
        self.connect_error = None
        self.toggle_gate = None
        def connect():
            if self.connect_error:
                raise self.connect_error
        ssh = SimpleNamespace(connect=connect, disconnect=lambda: None)
        def manager_call(manager, method, protocol, *args):
            if method == 'get_clients':
                return [{'clientId': 'peer', 'enabled': self.peer_enabled,
                         'userData': {'dataReceivedBytes': 0, 'dataSentBytes': 0}}]
            self.calls.append(args[-1])
            if self.toggle_gate:
                entered, release = self.toggle_gate
                self.toggle_gate = None
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('synthetic barrier timeout')
            self.peer_enabled = args[-1]
        for p in [patch.object(app, 'get_ssh', return_value=ssh),
                  patch.object(app, 'get_protocol_manager', return_value=object()),
                  patch.object(app, '_manager_call', side_effect=manager_call)]:
            p.start()
            self.addCleanup(p.stop)

    async def test_old_ssh_command_cannot_win_over_later_manual_disable(self):
        self.seed(enabled=False, disable_reasons=['quota'])
        self.attach_peer(False)
        entered, release = threading.Event(), threading.Event()
        self.toggle_gate = entered, release
        first = asyncio.create_task(self.update(traffic_limit=1))
        self.assertTrue(await asyncio.to_thread(entered.wait, 3))
        committed = asyncio.Event()
        save = app.save_data
        def saved(data):
            save(data)
            if 'manual' in data['users'][0].get('disable_reasons', []):
                committed.set()
        with patch.object(app, 'save_data', side_effect=saved):
            second = asyncio.create_task(app.api_toggle_user(
                self.request, 'test', app.ToggleUserRequest(enabled=False)))
            try:
                await asyncio.wait_for(committed.wait(), 3)
                self.assertFalse(self.user()['enabled'])
            finally:
                release.set()
            await asyncio.wait_for(asyncio.gather(first, second), 4)
        self.assertEqual(self.calls, [True, False])
        self.assertFalse(self.peer_enabled)
        self.assertFalse(self.user()['access_sync_pending'])

    async def test_http_cancellation_does_not_cancel_inflight_ssh_worker(self):
        self.seed(enabled=False, disable_reasons=['quota'])
        self.attach_peer(False)
        entered, release = threading.Event(), threading.Event()
        self.toggle_gate = entered, release
        request = asyncio.create_task(self.update(traffic_limit=1))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            worker = app._USER_STATE_TASKS['test']
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            self.assertTrue(self.user()['access_sync_pending'])
        finally:
            release.set()
        self.assertTrue(await asyncio.wait_for(worker, 4))
        self.assertTrue(self.peer_enabled)
        self.assertFalse(self.user()['access_sync_pending'])

    async def test_ssh_timeout_is_reported_and_background_retry_is_safe(self):
        self.seed(traffic_used=0, disable_reasons=[])
        self.attach_peer(True)
        self.connect_error = TimeoutError('synthetic timeout')
        result = await app.api_toggle_user(self.request, 'test', app.ToggleUserRequest(enabled=False))
        self.assertEqual(result.status_code, 503)
        self.assertTrue(self.user()['access_sync_pending'])
        self.assertFalse(self.user()['enabled'])
        self.assertTrue(self.peer_enabled)
        self.connect_error = None
        await self.one_cycle()
        self.assertFalse(self.peer_enabled)
        self.assertFalse(self.user()['access_sync_pending'])
        self.assertEqual(self.calls, [False])

    async def test_external_ssh_failure_retains_retry_marker(self):
        self.seed(traffic_used=0, disable_reasons=[])
        self.attach_peer(True)
        self.connect_error = OSError('synthetic connection reset')
        self.assertFalse(await app.perform_mass_operations(toggle_uids=[('test', False)]))
        self.assertTrue(self.user()['access_sync_pending'])
        self.assertEqual(self.user()['disable_reasons'], ['external'])
        self.assertFalse(self.user()['enabled'])

    async def test_offset_expiration_preserves_absolute_instant(self):
        from user_state import reconcile_user_state
        user = dict(enabled=True, traffic_limit=0, traffic_used=0,
                    expiration_date='2026-11-01T02:00:00+03:00')
        reconcile_user_state(user, datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertEqual(user['disable_reasons'], ['expired'])
        user['expiration_date'] = '2026-11-01T04:00:00+03:00'
        reconcile_user_state(user, datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertTrue(user['enabled'])

    async def test_failed_local_commit_does_not_execute_ssh(self):
        self.seed(traffic_used=0)
        self.attach_peer(True)
        before = self.path.read_bytes()
        with patch.object(app, 'save_data', side_effect=OSError('synthetic disk failure')):
            result = await app.api_toggle_user(self.request, 'test', app.ToggleUserRequest(enabled=False))
        self.assertEqual(result.status_code, 500)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.calls, [])

    async def test_raw_samples_are_committed_against_fresh_baselines(self):
        self.seed(traffic_used=100, traffic_total=100, last_reset_at='2026-11-01T00:00:00')
        self.attach_peer(True)
        data = app.load_data()
        data['user_connections'][0]['last_bytes'] = 100
        identity = traffic_server_identity(data['servers'][0])
        start = Clock.now().timestamp()
        def sample(value, tick):
            return dict(id='conn', user_id='test', protocol='awg3', client_id='peer',
                        server_identity=identity, bytes=value, observed_at=start + tick)
        for samples in [[sample(200, 2), sample(200, 3)], [sample(150, 1)], [sample(20, 4)]]:
            apply_traffic_samples(data, samples, Clock.now())
            app.save_data(data)
            data = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(data['users'][0]['traffic_used'], 220)
        self.assertEqual(data['users'][0]['traffic_total'], 220)
        self.assertEqual(data['user_connections'][0]['last_bytes'], 20)
        # A changed client or server identity cannot consume an old sample.
        data['user_connections'][0]['client_id'] = 'replacement'
        apply_traffic_samples(data, [sample(500, 5)], Clock.now())
        self.assertEqual(data['users'][0]['traffic_total'], 220)

    async def test_parallel_cycles_serialize_collection_and_commit(self):
        self.seed(traffic_used=0, traffic_total=0, last_reset_at='2026-11-01T00:00:00')
        self.attach_peer(True)
        entered, release = threading.Event(), threading.Event()
        calls = []
        def scrape(server, sid, conns):
            calls.append(1)
            if len(calls) == 1:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('synthetic barrier timeout')
            return [dict(id='conn', user_id='test', protocol='awg3', client_id='peer',
                         server_identity=traffic_server_identity(server), bytes=200,
                         observed_at=Clock.now().timestamp() + len(calls))]
        with patch.object(app, '_scrape_server_traffic', side_effect=scrape):
            first = asyncio.create_task(app.sync_user_traffic_and_state())
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            attempted = asyncio.Event()
            async def another():
                attempted.set()
                await app.sync_user_traffic_and_state()
            second = asyncio.create_task(another())
            try:
                await attempted.wait()
                self.assertEqual(len(calls), 1)
            finally:
                release.set()
            await asyncio.wait_for(asyncio.gather(first, second), 4)
        self.assertEqual(self.user()['traffic_total'], 200)
        self.assertEqual(self.user()['traffic_used'], 200)

    async def test_calendar_boundaries_and_iso_week_year(self):
        for strategy, last, now, expected in [
                ('daily', '2026-10-31T23:00:00', datetime(2026, 11, 1), True),
                ('monthly', '2026-12-31T23:00:00', datetime(2027, 1, 1), True),
                ('monthly', '2028-01-31T23:00:00', datetime(2028, 2, 1), True),
                ('weekly', '2020-12-31T23:00:00', datetime(2021, 1, 1), False),
                ('weekly', '2020-12-31T23:00:00', datetime(2021, 1, 4), True)]:
            user = dict(traffic_reset_strategy=strategy, last_reset_at=last,
                        traffic_used=123, traffic_total=456)
            self.assertEqual(reset_calendar_traffic(user, now), expected)
            self.assertEqual(user['traffic_total'], 456)
            self.assertEqual(user['traffic_used'], 0 if expected else 123)


if __name__ == '__main__':
    unittest.main()
