"""Exit-link failover on top of ExitLinkService: opt-in, switch, restore, lock."""
import asyncio
import json
import os
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

import app as panel
from exit_link_service import ExitLinkError
from tests.test_exit_link_service import Harness, base_data, run


def with_third_exit(data=None):
    data = data or base_data()
    data['servers'].append({
        'name': 'Madrid', 'host': '203.0.113.20', 'uid': 'exit-c',
        'protocols': {
            'exit': {'installed': True, 'port': '55520', 'subnet': '10.9.0.0/24',
                     'obfuscation': False},
        },
    })
    return data


class FailoverConfigTests(unittest.TestCase):
    def linked(self):
        h = Harness(with_third_exit())
        run(h.service.link(0, 'awg2', 'exit-a'))
        return h

    def test_disabled_by_default_is_a_noop(self):
        h = self.linked()
        self.assertNotIn('exit_failover', h.record())
        tick = run(h.service.tick_failover(0, 'awg2'))
        self.assertEqual(tick['action'], 'noop')
        self.assertEqual(tick['reason'], 'disabled')
        self.assertEqual(run(h.service.run_failover_pass()), [])
        # the live link is untouched
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')
        self.assertNotIn('exit_backup_conf', [c[0] for c in h.awg().calls])

    def test_enable_requires_a_link_and_a_backup(self):
        h = Harness(with_third_exit())
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-c']))
        self.assertEqual(ctx.exception.code, 'not_linked')
        h = self.linked()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=[]))
        self.assertEqual(ctx.exception.code, 'failover_no_backups')

    def test_unknown_and_self_uids_are_dropped(self):
        h = self.linked()
        result = run(h.service.configure_failover(
            0, 'awg2', enabled=True,
            backup_uids=['exit-c', 'entry-uid', 'gone', 'exit-a', 'exit-c']))
        self.assertEqual(result['exit_failover']['backup_uids'], ['exit-c'])
        fo = h.record()['exit_failover']
        self.assertEqual(fo['state']['primary_uid'], 'exit-a')
        self.assertEqual(fo['state']['active_uid'], 'exit-a')

    def test_config_persists_and_survives_reorder(self):
        h = self.linked()
        run(h.service.configure_failover(
            0, 'awg2', enabled=True, backup_uids=['exit-c'],
            check_interval_seconds=10, failure_threshold=2))
        h.data['servers'] = [h.data['servers'][2], h.data['servers'][0], h.data['servers'][1],
                             h.data['servers'][3]]
        view = h.service.failover_view(h.data, h.record(1, 'awg2'), 'entry-uid')
        self.assertTrue(view['enabled'])
        self.assertEqual(view['backup_uids'], ['exit-c'])
        self.assertEqual(view['primary']['uid'], 'exit-a')


class FailoverSwitchTests(unittest.TestCase):
    def ready(self, threshold=2, interval=10, failback=30):
        h = Harness(with_third_exit())
        run(h.service.link(0, 'awg2', 'exit-a'))
        run(h.service.configure_failover(
            0, 'awg2', enabled=True, backup_uids=['exit-c'],
            check_interval_seconds=interval, failure_threshold=threshold,
            failback_stable_seconds=failback, probe_egress=False,
            handshake_max_age_seconds=120))
        h.awg().calls.clear()
        h.events.clear()
        return h

    def tick(self, h, advance=10):
        h.now += advance
        return run(h.service.tick_failover(0, 'awg2'))

    def test_not_due_is_skipped(self):
        h = self.ready()
        first = self.tick(h, advance=10)
        self.assertEqual(first['action'], 'stay')
        again = run(h.service.tick_failover(0, 'awg2'))
        self.assertEqual(again['reason'], 'not_due')

    def test_failover_after_threshold(self):
        h = self.ready(threshold=2)
        h.awg().handshake_age = None
        first = self.tick(h)
        self.assertEqual(first['action'], 'stay')
        self.assertEqual(first['consecutive_failures'], 1)
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')
        second = self.tick(h)
        self.assertEqual(second['action'], 'failover')
        self.assertEqual(second['from_uid'], 'exit-a')
        self.assertEqual(second['to_uid'], 'exit-c')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-c')
        self.assertEqual(h.record()['exit_failover']['state']['primary_uid'], 'exit-a')
        self.assertEqual(h.record()['exit_failover']['state']['active_uid'], 'exit-c')
        events = h.record()['exit_failover']['events']
        self.assertEqual(events[0]['action'], 'failover')
        self.assertIn(('198.51.100.1', 'exit_backup_conf'), h.events)
        # old peer dropped only after the new link is confirmed
        self.assertEqual(h.events[-1], ('203.0.113.5', 'remove_peer'))

    def test_apply_failure_restores_previous_link(self):
        h = self.ready(threshold=1)
        h.awg().handshake_age = None
        h.awg().link_error = 'apply failed'
        result = self.tick(h)
        self.assertEqual(result['action'], 'switch_failed')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')
        self.assertIsNone(h.record()['exit_link'].get('stale'))
        self.assertIn(('198.51.100.1', 'exit_restore_conf'), h.events)
        self.assertEqual(h.record()['exit_failover']['events'][0]['action'], 'switch_failed')
        # clients still have a conf pointing at the previous exit
        self.assertEqual(h.awg().applied_link['exit_uid'], 'exit-a')

    def test_restore_failure_falls_back_to_unlink_stale(self):
        h = self.ready(threshold=1)
        h.awg().handshake_age = None
        h.awg().link_error = 'apply failed'
        h.awg().restore_error = 'restore exploded'
        result = self.tick(h)
        self.assertEqual(result['action'], 'switch_failed')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')
        self.assertEqual(h.record()['exit_link']['stale'], 'switch_failed')
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)

    def test_failback_after_stable_period(self):
        h = self.ready(threshold=1, failback=30)
        h.awg().handshake_age = None
        self.assertEqual(self.tick(h)['action'], 'failover')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-c')
        h.awg().handshake_age = 4
        h.awg().link_error = None
        # primary container is up but the stable window has not elapsed
        stay = self.tick(h, advance=10)
        self.assertEqual(stay['action'], 'stay')
        back = self.tick(h, advance=30)
        self.assertEqual(back['action'], 'failback')
        self.assertEqual(back['to_uid'], 'exit-a')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')
        self.assertEqual(h.record()['exit_failover']['events'][0]['action'], 'failback')

    def test_auto_failback_off_stays_on_backup(self):
        h = self.ready(threshold=1, failback=30)
        run(h.service.configure_failover(0, 'awg2', enabled=True, backup_uids=['exit-c'],
                                         auto_failback=False, probe_egress=False,
                                         check_interval_seconds=10, failure_threshold=1,
                                         failback_stable_seconds=30))
        h.awg().handshake_age = None
        self.assertEqual(self.tick(h)['action'], 'failover')
        h.awg().handshake_age = 4
        later = self.tick(h, advance=120)
        self.assertEqual(later['action'], 'stay')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-c')

    def test_skips_when_the_per_instance_lock_is_held(self):
        h = self.ready()

        async def hold_and_tick():
            lock = h.service._locks[('entry-uid', 'awg2')]
            await lock.acquire()
            try:
                return await h.service.tick_failover(0, 'awg2')
            finally:
                lock.release()

        result = run(hold_and_tick())
        self.assertEqual(result['reason'], 'skipped_busy')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')

    def test_second_tick_is_busy_while_the_first_holds_the_lock(self):
        h = self.ready(threshold=1)
        h.awg().handshake_age = None
        h.now += 10
        seen = []

        original_locked = h.service._tick_failover_locked

        async def locked(entry_uid, protocol, now):
            seen.append('in')
            # A overlapping tick must observe the held per-instance lock.
            overlapping = await h.service.tick_failover(0, 'awg2')
            seen.append(overlapping['reason'])
            return await original_locked(entry_uid, protocol, now)

        h.service._tick_failover_locked = locked
        result = run(h.service.tick_failover(0, 'awg2'))
        self.assertEqual(result['action'], 'failover')
        self.assertEqual(seen, ['in', 'skipped_busy'])
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-c')

    def test_manual_link_becomes_the_new_primary(self):
        h = self.ready()
        run(h.service.link(0, 'awg2', 'exit-c'))
        fo = h.record()['exit_failover']
        self.assertEqual(fo['state']['primary_uid'], 'exit-c')
        self.assertNotIn('exit-c', fo['backup_uids'])

    def test_unlink_disables_failover_but_keeps_backups(self):
        h = self.ready()
        run(h.service.unlink(0, 'awg2'))
        self.assertNotIn('exit_link', h.record())
        fo = h.record()['exit_failover']
        self.assertFalse(fo['enabled'])
        self.assertEqual(fo['backup_uids'], ['exit-c'])
        self.assertEqual(run(h.service.tick_failover(0, 'awg2'))['reason'], 'disabled')

    def test_status_includes_failover_view(self):
        h = self.ready()
        status = run(h.service.status(0, 'awg2'))
        self.assertTrue(status['exit_failover']['enabled'])
        self.assertEqual(status['exit_failover']['backup_uids'], ['exit-c'])
        self.assertEqual(status['exit_failover']['primary']['uid'], 'exit-a')

    def test_egress_leak_counts_as_failure_when_probe_enabled(self):
        h = self.ready(threshold=1)
        run(h.service.configure_failover(
            0, 'awg2', enabled=True, backup_uids=['exit-c'],
            check_interval_seconds=10, failure_threshold=1, probe_egress=True))
        h.awg().handshake_age = 3
        h.awg().egress = {'via_exit': '198.51.100.1', 'direct': '198.51.100.1'}
        result = self.tick(h)
        self.assertEqual(result['action'], 'failover')
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-c')

    def test_down_backup_is_skipped_for_the_next_healthy(self):
        h = Harness(with_third_exit())
        run(h.service.link(0, 'awg2', 'exit-a'))
        run(h.service.configure_failover(
            0, 'awg2', enabled=True, backup_uids=['exit-b', 'exit-c'],
            check_interval_seconds=10, failure_threshold=1, probe_egress=False))
        h.exit('203.0.113.9').running = False  # exit-b down
        h.awg().handshake_age = None
        result = self.tick(h)
        self.assertEqual(result['action'], 'failover')
        self.assertEqual(result['to_uid'], 'exit-c')


class FailoverHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'servers': with_third_exit()['servers'],
                'users': [],
                'user_connections': [],
            }, f)
        self._monitor_flag = panel._conn_monitor_started
        self._loop_flag = panel._exit_failover_loop_enabled
        panel._conn_monitor_started = True
        panel._exit_failover_loop_enabled = False

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        panel._exit_failover_loop_enabled = self._loop_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_failover_endpoints_require_admin(self):
        with TestClient(panel.app) as client:
            for path in ('/api/servers/0/exit-link/failover',
                         '/api/servers/0/exit-link/failover/check'):
                response = client.post(path, json={'protocol': 'awg2'})
                self.assertEqual(response.status_code, 403, path)

    def test_failover_save_roundtrip_when_logged_in(self):
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)
            # not linked yet — enabling is rejected
            denied = client.post('/api/servers/0/exit-link/failover',
                                 json={'protocol': 'awg2', 'enabled': True, 'backup_uids': ['exit-c']})
            self.assertEqual(denied.status_code, 400, denied.text)
            self.assertEqual(denied.json()['error'], 'not_linked')


if __name__ == '__main__':
    unittest.main()
