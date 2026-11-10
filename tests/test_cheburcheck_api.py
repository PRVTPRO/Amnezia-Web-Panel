"""API/settings-level tests for the Cheburcheck integration."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import cheburcheck


def _seed(tmp, servers, settings=None):
    import app
    df = Path(tmp) / 'data.json'
    df.write_text(json.dumps({
        'servers': servers,
        'users': [{'id': 'a', 'username': 'admin',
                   'password_hash': app.hash_password('admin'),
                   'role': 'admin', 'enabled': True}],
        'settings': settings or {},
    }), encoding='utf-8')
    return df


SRV = [{'name': 'FINN', 'host': '95.81.126.149', 'ssh_port': 54645, 'uid': 'u1'},
       {'name': 'EURO', 'host': '46.30.41.17', 'ssh_port': 1803, 'uid': 'u2'}]


class CheburcheckApiTests(unittest.TestCase):
    def setUp(self):
        import app
        from starlette.testclient import TestClient
        self.app = app
        self._tmp = tempfile.TemporaryDirectory()
        self.df = _seed(self._tmp.name, [dict(s) for s in SRV],
                        {'cheburcheck': {'enabled': True, 'interval_hours': 2,
                                         'servers': {'u1': True, 'u2': False}}})
        self.app.CHEBURCHECK_CACHE.clear()
        # The patch must stay alive for the whole test: some handlers re-read
        # DATA_FILE on each request, and reverting it mid-test points the panel
        # at the repository's own data.json.
        self._patch = patch.object(self.app, 'DATA_FILE', str(self.df))
        self._patch.start()
        with TestClient(self.app.app) as client:
            self.client = client
            r = client.post('/api/auth/login',
                            json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(r.status_code, 200, r.text)

    def tearDown(self):
        self.app.CHEBURCHECK_CACHE.clear()
        self.app._CHEBURCHECK_RUNNING.clear()
        self._patch.stop()
        self._tmp.cleanup()

    # --- settings -----------------------------------------------------------
    def test_settings_get_is_uid_keyed(self):
        r = self.client.get('/api/settings/cheburcheck')
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body['enabled'])
        self.assertEqual(body['interval_hours'], 2)
        self.assertEqual(body['servers'], {'u1': True, 'u2': False})

    def test_settings_post_updates_only_known_uids(self):
        r = self.client.post('/api/settings/cheburcheck',
                             json={'enabled': False, 'interval_hours': 3,
                                   'servers': {'u1': False, 'u2': True,
                                               'FINN': True, 'ghost': True}})
        self.assertEqual(r.status_code, 200, r.text)
        saved = json.loads(self.df.read_text(encoding='utf-8'))
        flags = saved['settings']['cheburcheck']['servers']
        self.assertEqual(flags, {'u1': False, 'u2': True})
        self.assertFalse(saved['settings']['cheburcheck']['enabled'])
        self.assertEqual(saved['settings']['cheburcheck']['interval_hours'], 3)

    def test_server_page_sees_uid_flag(self):
        r = self.client.get('/api/servers/0/cheburcheck')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['enabled_for_server'])
        self.assertTrue(r.json()['global_enabled'])
        r2 = self.client.get('/api/servers/1/cheburcheck')
        self.assertFalse(r2.json()['enabled_for_server'])

    # --- migration ----------------------------------------------------------
    def test_name_keyed_flags_migrate_to_uid(self):
        data = {'servers': [dict(s) for s in SRV],
                'settings': {'cheburcheck': {'enabled': True, 'interval_hours': 1,
                                             'servers': {'FINN': True, 'OLD': True}}}}
        changed = self.app._cheburcheck_migrate_settings(data)
        self.assertTrue(changed)
        self.assertEqual(data['settings']['cheburcheck']['servers'],
                         {'u1': True})      # unknown name dropped

    def test_migration_is_idempotent(self):
        data = {'servers': [dict(s) for s in SRV],
                'settings': {'cheburcheck': {'servers': {'u1': True}}}}
        self.assertFalse(self.app._cheburcheck_migrate_settings(data))
        self.assertEqual(data['settings']['cheburcheck']['servers'], {'u1': True})

    # --- run / flags --------------------------------------------------------
    def test_run_all_refuses_when_master_off(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'enabled': False, 'servers': {'u1': True}})
        r = self.client.post('/api/servers/cheburcheck/run_all')
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'disabled'})

    def test_run_all_starts_enabled_servers(self):
        r = self.client.post('/api/servers/cheburcheck/run_all')
        self.assertEqual(r.json()['started'], 1)

    def test_flags_only_lists_relevant_servers(self):
        self.app.CHEBURCHECK_CACHE['u2'] = {'status': 'clean', 'checked_at': 'x',
                                            'probe': {'blocking_regions': 0,
                                                      'response_count': 5}}
        r = self.client.get('/api/servers/cheburcheck_flags')
        ids = r.json()['flags']
        self.assertIn('0', ids)      # enabled, no data yet
        self.assertIn('1', ids)      # has data
        self.assertTrue(ids['0']['enabled'])
        self.assertEqual(ids['1']['status'], 'clean')

    def test_flags_hides_server_with_no_data_and_box_off(self):
        r = self.client.get('/api/servers/cheburcheck_flags')
        self.assertNotIn('1', r.json()['flags'])

    # --- single run ---------------------------------------------------------
    def test_run_endpoint_is_background_and_reports_running(self):
        """The check runs in the background; the flag clears when it ends."""
        async def fake_check(target):
            return {'blocked': False, 'geo': {'asn': 'AS207569'}, 'id': 'tok'}

        async def fake_probe(cid):
            return {'regions': [{'region': 'X', 'verdicts': ['ok']}],
                    'response_count': 1, 'verdicts': ['ok'],
                    'online_probes': 5, 'verdict_counts': {'ok': 1}}

        with patch.object(cheburcheck, 'fetch_check', fake_check),              patch.object(cheburcheck, 'fetch_probe', fake_probe):
            r = self.client.post('/api/servers/0/cheburcheck/run', json={})
            self.assertEqual(r.json(), {'ok': True, 'started': 1})
            st = self.client.get('/api/servers/0/cheburcheck').json()
            for _ in range(50):
                if not st['running'] and st['data']:
                    break
                time.sleep(0.05)
                st = self.client.get('/api/servers/0/cheburcheck').json()
            self.assertFalse(st['running'])
            self.assertEqual(st['data']['status'], 'clean')

    def test_run_endpoint_refuses_when_master_off(self):
        self.client.post('/api/settings/cheburcheck', json={'enabled': False})
        r = self.client.post('/api/servers/0/cheburcheck/run', json={})
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'disabled'})


class RunOneTests(unittest.TestCase):
    """_run_cheburcheck_one must always leave a record behind."""

    def setUp(self):
        import app
        self.app = app
        self._tmp = tempfile.TemporaryDirectory()
        self.df = _seed(self._tmp.name, [dict(s) for s in SRV])
        self._patch = patch.object(app, 'DATA_FILE', str(self.df))
        self._patch.start()
        app.CHEBURCHECK_CACHE.clear()

    def tearDown(self):
        self.app.CHEBURCHECK_CACHE.clear()
        self.app._CHEBURCHECK_RUNNING.clear()
        self._patch.stop()
        self._tmp.cleanup()

    def tearDown(self):
        self.app.CHEBURCHECK_CACHE.clear()
        self._tmp.cleanup()

    def test_records_error_when_check_fails(self):
        """A failed check must still leave a record, or yesterday's verdict
        stays on screen and reads as today's answer."""
        import asyncio

        async def go():
            async def boom(target):
                raise RuntimeError('503 from upstream')
            with patch.object(cheburcheck, 'fetch_check', boom):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149'}
                await self.app._run_cheburcheck_one(srv)
            return self.app.CHEBURCHECK_CACHE.get('u1')

        rec = asyncio.run(go())
        self.assertIsNotNone(rec)
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('check failed', rec['error'])

    def test_writes_unknown_when_only_probe_fails(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check',
                              new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe',
                              new=_fake_probe_raise):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149'}
                await self.app._run_cheburcheck_one(srv)
                return self.app.CHEBURCHECK_CACHE.get('u1')

        rec = asyncio.run(go())
        self.assertIsNotNone(rec)
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('probe failed', rec['error'])

    def test_writes_unknown_when_probe_returns_nothing(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_none):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149'}
                await self.app._run_cheburcheck_one(srv)
                return self.app.CHEBURCHECK_CACHE.get('u1')

        rec = asyncio.run(go())
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('no verdicts', rec['error'])

    def test_writes_banned_on_static_block(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check_blocked), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_none):
                srv = {'uid': 'u2', 'name': 'EURO', 'host': '46.30.41.17'}
                await self.app._run_cheburcheck_one(srv)
                return self.app.CHEBURCHECK_CACHE.get('u2')

        rec = asyncio.run(go())
        self.assertEqual(rec['status'], 'banned')
        self.assertNotIn('error', rec)


async def _fake_check(target):
    return {'blocked': False, 'geo': {'asn': 'AS207569'}, 'id': 'tok'}


async def _fake_check_blocked(target):
    return {'blocked': True, 'geo': {}, 'id': 'tok',
            'blocked_subnets': ['46.30.41.0/24']}


async def _fake_probe_raise(check_id):
    raise RuntimeError('429')


async def _fake_probe_none(check_id):
    return None


class QuietHoursApiTests(CheburcheckApiTests):
    """Quiet-hour settings round-trip and normalisation."""

    def _seed(self, settings=None):
        base = {'cheburcheck': {'enabled': True, 'interval_hours': 2,
                                'servers': {'u1': True, 'u2': False}}}
        if settings:
            base['cheburcheck'].update(settings)
        self.df = _seed(self._tmp.name, [dict(s) for s in SRV], base)

    def test_defaults_are_off(self):
        self._seed()
        r = self.client.get('/api/settings/cheburcheck').json()
        self.assertFalse(r['quiet_enabled'])
        self.assertEqual(r['quiet_start'], 0)
        self.assertEqual(r['quiet_end'], 0)

    def test_quiet_hours_round_trip(self):
        self._seed()
        r = self.client.post('/api/settings/cheburcheck',
                             json={'quiet_enabled': True, 'quiet_start': 22,
                                   'quiet_end': 6})
        self.assertEqual(r.status_code, 200, r.text)
        saved = json.loads(self.df.read_text(encoding='utf-8'))
        cb = saved['settings']['cheburcheck']
        self.assertTrue(cb['quiet_enabled'])
        self.assertEqual((cb['quiet_start'], cb['quiet_end']), (22, 6))

    def test_hours_are_clamped(self):
        self._seed()
        self.client.post('/api/settings/cheburcheck',
                         json={'quiet_start': 99, 'quiet_end': -5})
        cb = json.loads(self.df.read_text(encoding='utf-8'))['settings']['cheburcheck']
        self.assertEqual((cb['quiet_start'], cb['quiet_end']), (23, 0))

    def test_empty_window_disables_quiet_hours(self):
        self._seed({'quiet_enabled': True, 'quiet_start': 5, 'quiet_end': 5})
        r = self.client.post('/api/settings/cheburcheck',
                             json={'quiet_start': 5, 'quiet_end': 5})
        self.assertEqual(r.status_code, 200)
        cb = json.loads(self.df.read_text(encoding='utf-8'))['settings']['cheburcheck']
        self.assertFalse(cb['quiet_enabled'])


class MasterSwitchApiTests(CheburcheckApiTests):
    """The master switch gates every check."""

    def test_run_all_and_run_refuse_when_master_off(self):
        self.client.post('/api/settings/cheburcheck', json={'enabled': False})
        self.assertEqual(self.client.post('/api/servers/cheburcheck/run_all').json(),
                         {'ok': True, 'started': 0, 'reason': 'disabled'})
        self.assertEqual(self.client.post('/api/servers/0/cheburcheck/run', json={}).json(),
                         {'ok': True, 'started': 0, 'reason': 'disabled'})

    def test_enabled_by_default_is_false(self):
        df = _seed(self._tmp.name, [dict(s) for s in SRV])      # no cheburcheck block
        data = json.loads(df.read_text(encoding='utf-8'))
        self.assertNotIn('cheburcheck', data['settings'])
        self.assertFalse(self.app.cheburcheck_enabled(data))
