"""App-level wiring for the Smart Route self-heal.

The reconcile pass and the timer migration are started as background tasks, so
their gating (installed/enabled, done_at, pending count, the hook after a plugin
update) is not exercised by the service tests. These mirror the RKN/ICMP
migration tests: import the real app, patch every file and SSH side effect.
"""
import asyncio
import copy
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from smartroute_service import SmartRouteError


class SmartRouteAppCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import app
        self.app = app
        self.data = {
            'servers': [
                {'name': 'A', 'uid': 'uid-a', 'host': '192.0.2.1',
                 'smartroute': {'installed': True, 'enabled': True},
                 'protocols': {'awg2': {'exit_link': {'exit_uid': 'E',
                                                      'smart_route': True}}}},
            ],
            'settings': {'appearance': {'title': 'x'}},
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(
            app, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(app, 'save_data', side_effect=self._save))
        self.stack.enter_context(patch.object(app, 'SMARTR_TIMER_MIGRATION', True))
        self.stack.enter_context(patch.object(app, 'SMARTR_TIMER_MIGRATION_DELAY', 0))

    def _save(self, data):
        self.data = copy.deepcopy(data)


class TimerMigrationTests(SmartRouteAppCase):
    async def test_writes_done_at_when_nothing_is_pending(self):
        async def fake(_server_id=None):
            return [{'server': 'A', 'uid': 'uid-a', 'state': 'unchanged'}]

        with patch.object(self.app.smartroute_svc, 'migrate_timer', side_effect=fake):
            await self.app.smartroute_timer_migration()
        rec = self.data['panel_migrations']['smartroute_timer_v1']
        self.assertTrue(rec['done_at'])
        self.assertEqual(rec['pending'], 0)

    async def test_failed_host_keeps_the_migration_pending(self):
        async def fake(_server_id=None):
            return [{'server': 'A', 'uid': 'uid-a', 'state': 'failed-not-armed'}]

        with patch.object(self.app.smartroute_svc, 'migrate_timer', side_effect=fake):
            await self.app.smartroute_timer_migration()
        rec = self.data['panel_migrations']['smartroute_timer_v1']
        self.assertNotIn('done_at', rec)
        self.assertEqual(rec['pending'], 1)

    async def test_done_at_skips_the_whole_pass(self):
        self.data['panel_migrations'] = {'smartroute_timer_v1': {'done_at': 'yes'}}
        with patch.object(self.app.smartroute_svc, 'migrate_timer') as migrate:
            await self.app.smartroute_timer_migration()
        migrate.assert_not_called()

    async def test_disabled_by_the_environment_flag(self):
        with patch.object(self.app, 'SMARTR_TIMER_MIGRATION', False), \
                patch.object(self.app.smartroute_svc, 'migrate_timer') as migrate:
            await self.app.smartroute_timer_migration()
        migrate.assert_not_called()


class ReconcilePassTests(SmartRouteAppCase):
    async def test_logs_a_repaired_instance(self):
        async def fake(_server_id=None):
            return [{'server': 'A', 'protocol': 'awg2', 'throw_routes': 0,
                     'repaired': True, 'throw_routes_after': 8664}]

        with patch.object(self.app.smartroute_svc, 'reconcile', side_effect=fake), \
                self.assertLogs('app', level='WARNING') as logs:
            await self.app.smartroute_reconcile_pass()
        self.assertTrue(any('re-applied' in line for line in logs.output))

    async def test_survives_a_failing_service(self):
        # The loop must never die on one bad pass: the next round retries.
        async def boom(_server_id=None):
            raise RuntimeError('ssh exploded')

        with patch.object(self.app.smartroute_svc, 'reconcile', side_effect=boom):
            self.assertEqual(await self.app.smartroute_reconcile_pass(), [])

    async def test_hook_after_plugin_update_calls_reconcile(self):
        calls = []

        async def fake(server_id):
            calls.append(server_id)

        with patch.object(self.app.smartroute_svc, 'reconcile', side_effect=fake):
            await self.app._smartroute_reconcile_after(3)
        self.assertEqual(calls, [3])

    async def test_hook_never_raises(self):
        async def boom(_server_id):
            raise SmartRouteError('ssh_failed', 'nope')

        with patch.object(self.app.smartroute_svc, 'reconcile', side_effect=boom):
            await self.app._smartroute_reconcile_after(0)   # no exception


if __name__ == '__main__':
    unittest.main()
