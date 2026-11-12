"""API/settings-level tests for the Cheburcheck integration (multi-target)."""
import json
import os
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


def _rec(target, status='clean', **extra):
    record = {
        'target': target,
        'status': status,
        'checked_at': '2026-11-12T00:00:00+00:00',
        'probe': {'online_probes': 40, 'response_count': 5,
                  'verdict_counts': {}, 'blocking_regions': 0,
                  'clear_regions': 5},
        'static': {}, 'partial': False,
    }
    record.update(extra)
    return record


SRV = [{'name': 'FINN', 'host': '95.81.126.149', 'ssh_port': 54645, 'uid': 'u1',
        'protocols': {'awg': {}}},
       {'name': 'EURO', 'host': '46.30.41.17', 'ssh_port': 1803, 'uid': 'u2',
        'protocols': {'xray': {}}}]


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
        body = self.client.get('/api/settings/cheburcheck').json()
        self.assertTrue(body['enabled'])
        self.assertEqual(body['interval_hours'], 2)
        self.assertEqual(body['servers'], {'u1': True, 'u2': False})
        self.assertEqual(body['targets'], {})
        self.assertEqual(body['targets_resolved'],
                         {'u1': ['95.81.126.149'], 'u2': ['46.30.41.17']})

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

    def test_settings_post_without_servers_key_survives(self):
        """Regression: a block without 'servers' must not 500 (D2)."""
        data = json.loads(self.df.read_text(encoding='utf-8'))
        data['settings']['cheburcheck'] = {'enabled': True}
        self.df.write_text(json.dumps(data), encoding='utf-8')
        r = self.client.post('/api/settings/cheburcheck', json={'enabled': True})
        self.assertEqual(r.status_code, 200, r.text)
        saved = json.loads(self.df.read_text(encoding='utf-8'))
        self.assertEqual(saved['settings']['cheburcheck']['servers'],
                         {'u1': False, 'u2': False})

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

    def test_run_all_no_servers(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'servers': {'u1': False, 'u2': False}})
        r = self.client.post('/api/servers/cheburcheck/run_all')
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'no_servers'})

    def test_run_all_no_targets(self):
        df = _seed(self._tmp.name, [{'name': 'EMPTY', 'host': '',
                                     'uid': 'u3'}],
                   {'cheburcheck': {'enabled': True, 'servers': {'u3': True}}})
        self.df = df
        r = self.client.post('/api/servers/cheburcheck/run_all')
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'no_targets'})

    def test_flags_only_lists_flagged_servers(self):
        self.app.CHEBURCHECK_CACHE['u2'] = {'46.30.41.17': _rec('46.30.41.17')}
        r = self.client.get('/api/servers/cheburcheck_flags')
        ids = r.json()['flags']
        self.assertIn('0', ids)            # flagged, synthetic "not checked yet"
        self.assertNotIn('1', ids)         # cache exists but the box is off
        self.assertEqual(ids['0']['status'], 'unknown')
        self.assertEqual(ids['0']['probe'], {'response_count': 0,
                                             'blocking_regions': 0,
                                             'restricted_regions': 0,
                                             'clear_regions': 0})

    def test_flags_show_cached_verdict_for_flagged_server(self):
        self.client.post('/api/settings/cheburcheck', json={'servers': {'u2': True}})
        self.app.CHEBURCHECK_CACHE['u2'] = {'46.30.41.17': _rec('46.30.41.17')}
        ids = self.client.get('/api/servers/cheburcheck_flags').json()['flags']
        self.assertEqual(ids['1']['status'], 'clean')
        self.assertEqual(ids['1']['probe']['blocking_regions'], 0)

    def test_get_returns_synthetic_even_when_flag_off(self):
        body = self.client.get('/api/servers/1/cheburcheck').json()
        self.assertFalse(body['enabled_for_server'])
        self.assertEqual(body['status'], 'unknown')
        self.assertEqual(body['target'], '46.30.41.17')
        self.assertIn('not checked yet', body['targets']['46.30.41.17']['error'])
        self.assertNotIn('data', body)

    def test_get_empty_resolution_uses_service_key(self):
        df = _seed(self._tmp.name, [{'name': 'EMPTY', 'host': '',
                                     'uid': 'u3'}],
                   {'cheburcheck': {'enabled': True, 'servers': {'u3': True}}})
        self.df = df
        body = self.client.get('/api/servers/0/cheburcheck').json()
        self.assertEqual(body['status'], 'unknown')
        self.assertEqual(body['target'], '')
        self.assertEqual(body['error'], 'no target configured')
        self.assertIn('', body['targets'])


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

    def _record(self, uid, target):
        return self.app.CHEBURCHECK_CACHE.get(uid, {}).get(target)

    def test_records_error_when_check_fails(self):
        import asyncio

        async def go():
            async def boom(target):
                raise RuntimeError('503 from upstream')
            with patch.object(cheburcheck, 'fetch_check', boom):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149',
                       'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149')

        asyncio.run(go())
        rec = self._record('u1', '95.81.126.149')
        self.assertIsNotNone(rec)
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('check failed', rec['error'])

    def test_writes_unknown_when_only_probe_fails(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_raise):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149',
                       'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149')

        asyncio.run(go())
        rec = self._record('u1', '95.81.126.149')
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('probe failed', rec['error'])

    def test_writes_unknown_when_probe_returns_nothing(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_none):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149',
                       'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149')

        asyncio.run(go())
        rec = self._record('u1', '95.81.126.149')
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('no verdicts', rec['error'])

    def test_writes_banned_on_static_block(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check_blocked), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_none):
                srv = {'uid': 'u2', 'name': 'EURO', 'host': '46.30.41.17',
                       'protocols': {'xray': {}}}
                await self.app._run_cheburcheck_one(srv, '46.30.41.17')

        asyncio.run(go())
        rec = self._record('u2', '46.30.41.17')
        self.assertEqual(rec['status'], 'banned')
        self.assertNotIn('error', rec)

    def test_empty_target_never_reaches_network(self):
        import asyncio

        async def go():
            async def boom(target):
                raise AssertionError('network must not be touched')
            with patch.object(cheburcheck, 'fetch_check', boom):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149'}
                await self.app._run_cheburcheck_one(srv, '')

        asyncio.run(go())
        self.assertNotIn('', self.app.CHEBURCHECK_CACHE.get('u1', {}))

    def test_logs_started_and_finished(self):
        import asyncio

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe', new=_fake_probe_none):
                srv = {'uid': 'u1', 'name': 'FINN', 'host': '95.81.126.149',
                       'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149',
                                                   ['95.81.126.149'])

        with self.assertLogs(self.app.logger, level='INFO') as logs:
            asyncio.run(go())
        text = '\n'.join(logs.output)
        self.assertIn('cheburcheck: 95.81.126.149 for FINN started', text)
        self.assertIn('cheburcheck: 95.81.126.149 for FINN finished', text)


async def _fake_check(target):
    return {'blocked': False, 'geo': {'asn': 'AS207569'}, 'id': 'tok'}


async def _fake_check_blocked(target):
    return {'blocked': True, 'geo': {}, 'id': 'tok',
            'blocked_subnets': ['46.30.41.0/24']}


async def _fake_probe_raise(check_id):
    raise RuntimeError('429')


async def _fake_probe_none(check_id):
    return None


class TargetResolutionTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app = app

    @staticmethod
    def server(**kwargs):
        base = {'uid': 'u', 'host': '10.0.0.1', 'protocols': {}}
        base.update(kwargs)
        return base

    def test_ssh_address_always_checked_plus_public_host(self):
        srv = self.server(protocols={'awg3': {'public_host': 'vpn.example.com'}})
        self.assertEqual(self.app.cheburcheck_targets(srv, {}),
                         ['10.0.0.1', 'vpn.example.com'])

    def test_host_only_when_no_public_host(self):
        srv = self.server(protocols={'awg': {}})
        self.assertEqual(self.app.cheburcheck_targets(srv, {}), ['10.0.0.1'])

    def test_dedupe_and_sort(self):
        srv = self.server(protocols={
            'awg': {},
            'xray': {'public_host': '10.0.0.1'},
            'awg2': {'public_host': 'a.example'},
        })
        self.assertEqual(self.app.cheburcheck_targets(srv, {}),
                         ['10.0.0.1', 'a.example'])

    def test_infrastructure_protocols_never_added_but_ssh_stays(self):
        srv = self.server(protocols={
            'awg': {'installed': False},
            'nginx': {'public_host': 'site.example'},
            'adguard': {'public_host': 'dns.example'},
            'mystery': {},
        })
        self.assertEqual(self.app.cheburcheck_targets(srv, {}), ['10.0.0.1'])

    def test_missing_installed_key_means_installed(self):
        srv = self.server(protocols={'xray': {'public_host': 'vpn.example'}})
        self.assertEqual(self.app.cheburcheck_targets(srv, {}),
                         ['10.0.0.1', 'vpn.example'])

    def test_public_port_is_not_part_of_target(self):
        srv = self.server(protocols={'xray': {'public_host': 'vpn.example',
                                              'public_port': '8443'}})
        self.assertEqual(self.app.cheburcheck_targets(srv, {}),
                         ['10.0.0.1', 'vpn.example'])

    def test_extra_addresses_are_added_on_top(self):
        cfg = {'targets': {'u': ['9.9.9.9']}}
        srv = self.server(protocols={'awg': {'public_host': 'vpn.example'}})
        self.assertEqual(self.app.cheburcheck_targets(srv, cfg),
                         ['10.0.0.1', '9.9.9.9', 'vpn.example'])

    def test_extra_addresses_deduplicated_and_sorted(self):
        cfg = {'targets': {'u': ['b.example', 'a.example', 'a.example',
                                 '10.0.0.1']}}
        self.assertEqual(self.app.cheburcheck_targets(self.server(), cfg),
                         ['10.0.0.1', 'a.example', 'b.example'])

    def test_invalid_extra_addresses_are_ignored(self):
        cfg = {'targets': {'u': ['bad host']}}
        self.assertEqual(self.app.cheburcheck_targets(self.server(), cfg),
                         ['10.0.0.1'])

    def test_invalid_targets_raise(self):
        with self.assertRaises(ValueError):
            self.app._cheburcheck_normalize_targets([''])
        with self.assertRaises(ValueError):
            self.app._cheburcheck_normalize_targets(['bad host'])


class SettingsTargetsTests(CheburcheckApiTests):
    """Override validation, prune and the 400 contract (A2/A6)."""

    def _saved_targets(self):
        saved = json.loads(self.df.read_text(encoding='utf-8'))
        return saved['settings']['cheburcheck'].get('targets')

    def test_override_round_trip_and_resolved(self):
        r = self.client.post('/api/settings/cheburcheck',
                             json={'targets': {'u1': ['extra.example.com']}})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._saved_targets(), {'u1': ['extra.example.com']})
        body = self.client.get('/api/settings/cheburcheck').json()
        self.assertEqual(body['targets'], {'u1': ['extra.example.com']})
        # The extra list adds to the SSH address, it does not replace it.
        self.assertEqual(body['targets_resolved']['u1'],
                         ['95.81.126.149', 'extra.example.com'])

    def test_override_invalid_value_rejects_whole_post(self):
        before = self.df.read_text(encoding='utf-8')
        for payload in ({'targets': {'u1': ['']}},
                        {'targets': {'u1': 'abc'}},
                        {'targets': {'u1': None}},
                        {'targets': None},
                        {'targets': ['a']},
                        {'targets': {'u1': ['bad host']}}):
            r = self.client.post('/api/settings/cheburcheck', json=payload)
            self.assertEqual(r.status_code, 400, (payload, r.text))
        self.assertEqual(self.df.read_text(encoding='utf-8'), before)

    def test_empty_list_removes_override(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'targets': {'u1': ['vpn.example.com']}})
        r = self.client.post('/api/settings/cheburcheck',
                             json={'targets': {'u1': []}})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._saved_targets(), {})

    def test_absent_targets_field_keeps_override(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'targets': {'u1': ['vpn.example.com'],
                                           'u2': ['vpn2.example.com']}})
        self.client.post('/api/settings/cheburcheck', json={'enabled': False})
        self.assertEqual(self._saved_targets(),
                         {'u1': ['vpn.example.com'],
                          'u2': ['vpn2.example.com']})

    def test_partial_targets_post_merges_existing_overrides(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'targets': {'u2': ['vpn2.example.com']}})
        self.client.post('/api/settings/cheburcheck',
                         json={'targets': {'u1': ['vpn.example.com']}})
        self.assertEqual(self._saved_targets(),
                         {'u1': ['vpn.example.com'],
                          'u2': ['vpn2.example.com']})

    def test_unknown_uid_is_pruned(self):
        self.client.post('/api/settings/cheburcheck',
                         json={'targets': {'u1': ['vpn.example.com'],
                                           'ghost': ['evil.example']}})
        self.assertEqual(self._saved_targets(), {'u1': ['vpn.example.com']})


class SingleRunTests(CheburcheckApiTests):
    def test_run_endpoint_is_background_and_reports_running(self):
        async def fake_check(target):
            return {'blocked': False, 'geo': {'asn': 'AS207569'}, 'id': 'tok'}

        async def fake_probe(cid):
            return {'regions': [{'region': 'X', 'verdicts': ['ok']}],
                    'response_count': 1, 'verdicts': ['ok'],
                    'online_probes': 5, 'verdict_counts': {'ok': 1}}

        with patch.object(cheburcheck, 'fetch_check', fake_check), \
             patch.object(cheburcheck, 'fetch_probe', fake_probe):
            r = self.client.post('/api/servers/0/cheburcheck/run', json={})
            self.assertEqual(r.json(), {'ok': True, 'started': 1})
            st = self.client.get('/api/servers/0/cheburcheck').json()
            for _ in range(100):
                if not st['running']:
                    break
                time.sleep(0.05)
                st = self.client.get('/api/servers/0/cheburcheck').json()
            self.assertFalse(st['running'])
            self.assertEqual(st['status'], 'clean')
            self.assertEqual(st['targets']['95.81.126.149']['status'], 'clean')

    def test_run_endpoint_refuses_when_master_off(self):
        self.client.post('/api/settings/cheburcheck', json={'enabled': False})
        r = self.client.post('/api/servers/0/cheburcheck/run', json={})
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'disabled'})

    def test_run_endpoint_already_running(self):
        self.app._CHEBURCHECK_RUNNING['u1'] = None
        r = self.client.post('/api/servers/0/cheburcheck/run', json={})
        self.assertEqual(r.json(), {'ok': True, 'already_running': True})

    def test_run_endpoint_no_targets(self):
        self.df = _seed(self._tmp.name, [{'name': 'EMPTY', 'host': '',
                                          'uid': 'u3'}],
                        {'cheburcheck': {'enabled': True,
                                         'servers': {'u3': True}}})
        r = self.client.post('/api/servers/0/cheburcheck/run', json={})
        self.assertEqual(r.json(), {'ok': True, 'started': 0, 'reason': 'no_targets'})

    def test_run_all_then_run_reports_nothing_started(self):
        self.app._CHEBURCHECK_RUNNING['u1'] = None
        self.client.post('/api/settings/cheburcheck',
                         json={'servers': {'u1': True, 'u2': False}})
        r = self.client.post('/api/servers/cheburcheck/run_all')
        self.assertEqual(r.json(), {'ok': True, 'started': 0,
                                    'reason': 'nothing_started'})


class CacheTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app = app
        self._tmp = tempfile.TemporaryDirectory()
        self.df = Path(self._tmp.name) / 'data.json'
        self.df.write_text('{}', encoding='utf-8')
        self._patch = patch.object(app, 'DATA_FILE', str(self.df))
        self._patch.start()
        app.CHEBURCHECK_CACHE.clear()

    def tearDown(self):
        self.app.CHEBURCHECK_CACHE.clear()
        self._patch.stop()
        self._tmp.cleanup()

    def _legacy(self):
        path = os.path.join(self._tmp.name, 'state', 'cheburcheck.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def test_flat_cache_migrates_and_legacy_is_removed(self):
        path = self._legacy()
        path_obj = Path(path)
        path_obj.write_text(json.dumps({'u1': _rec('95.81.126.149')}),
                            encoding='utf-8')
        loaded = self.app._cheburcheck_load_cache()
        self.assertEqual(loaded['u1']['95.81.126.149']['status'], 'clean')
        self.assertFalse(path_obj.exists())

    def test_record_without_target_is_dropped(self):
        path = self._legacy()
        bad = _rec('95.81.126.149')
        bad['target'] = ''
        Path(path).write_text(json.dumps({'u1': bad}), encoding='utf-8')
        self.assertEqual(self.app._cheburcheck_load_cache(), {})

    def test_sibling_wins_and_legacy_is_removed(self):
        legacy = self._legacy()
        Path(legacy).write_text(json.dumps({'u1': _rec('old.example')}),
                                encoding='utf-8')
        sibling = Path(self.app._cheburcheck_cache_path())
        sibling.write_text(json.dumps({'u1': {'new.example': _rec('new.example')}}),
                           encoding='utf-8')
        loaded = self.app._cheburcheck_load_cache()
        self.assertIn('new.example', loaded['u1'])
        self.assertFalse(Path(legacy).exists())

    def test_corrupt_sibling_falls_back_to_legacy(self):
        legacy = self._legacy()
        Path(legacy).write_text(json.dumps({'u1': _rec('old.example')}),
                                encoding='utf-8')
        sibling = Path(self.app._cheburcheck_cache_path())
        sibling.write_text('{not json', encoding='utf-8')
        loaded = self.app._cheburcheck_load_cache()
        self.assertEqual(loaded['u1']['old.example']['status'], 'clean')
        self.assertTrue(self.app._cheburcheck_cache_path())
        self.assertFalse(Path(legacy).exists())

    def test_startup_writes_sibling_after_consuming_legacy(self):
        path = self._legacy()
        Path(path).write_text(json.dumps({'u1': _rec('95.81.126.149')}),
                              encoding='utf-8')
        data = {'servers': [{'uid': 'u1'}]}
        self.app._cheburcheck_startup_cache(data)
        sibling = Path(self.app._cheburcheck_cache_path())
        self.assertTrue(sibling.exists())
        saved = json.loads(sibling.read_text(encoding='utf-8'))
        self.assertEqual(saved['u1']['95.81.126.149']['status'], 'clean')

    def test_startup_drops_orphan_uids(self):
        sibling = Path(self.app._cheburcheck_cache_path())
        sibling.write_text(json.dumps({'ghost': {'a': _rec('a')}}),
                           encoding='utf-8')
        self.app._cheburcheck_startup_cache({'servers': [{'uid': 'u1'}]})
        self.assertNotIn('ghost', self.app.CHEBURCHECK_CACHE)

    def test_persist_prunes_stale_targets_only_when_given(self):
        self.app.CHEBURCHECK_CACHE['u1'] = {'old': _rec('old'),
                                            'keep': _rec('keep')}
        self.app._cheburcheck_persist('u1', ['keep'])
        self.assertEqual(set(self.app.CHEBURCHECK_CACHE['u1']), {'keep'})
        self.app.CHEBURCHECK_CACHE['u1']['extra'] = _rec('extra')
        self.app._cheburcheck_persist()
        self.assertIn('extra', self.app.CHEBURCHECK_CACHE['u1'])

    def test_persist_is_atomic_on_failure(self):
        path = self.app._cheburcheck_cache_path()
        Path(path).write_text('{"old": true}', encoding='utf-8')
        self.app.CHEBURCHECK_CACHE['u1'] = {'a': _rec('a')}
        with patch.object(self.app.os, 'replace', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                self.app._cheburcheck_persist()
        self.assertEqual(Path(path).read_text(encoding='utf-8'), '{"old": true}')
        self.assertFalse(os.path.exists(path + '.tmp'))

    def test_reader_distinguishes_not_checked_from_target_change(self):
        server = {'uid': 'u1', 'host': '10.0.0.1',
                  'protocols': {'awg': {'public_host': 'a.example'}}}
        records = self.app._cheburcheck_records_for(server, {}, {})
        self.assertEqual(records['a.example']['error'], 'not checked yet')
        cache = {'u1': {'b.example': _rec('b.example')}}
        records = self.app._cheburcheck_records_for(server, {}, cache)
        self.assertEqual(records['a.example']['error'],
                         'target changed, re-check required')

    def test_out_of_resolution_records_are_not_returned(self):
        server = {'uid': 'u1', 'host': '10.0.0.1',
                  'protocols': {'awg': {'public_host': 'a.example'}}}
        cache = {'u1': {'old.example': _rec('old.example')}}
        records = self.app._cheburcheck_records_for(server, {}, cache)
        self.assertEqual(set(records), {'10.0.0.1', 'a.example'})

    def test_aggregate_takes_worst_verdict_and_sums_probes(self):
        records = {
            'a.example': _rec('a.example', 'clean'),
            'b.example': _rec('b.example', 'banned', error='probe failed: 429',
                              probe={'online_probes': 40, 'response_count': 3,
                                     'verdict_counts': {},
                                     'blocking_regions': 2,
                                     'clear_regions': 0}),
        }
        agg = self.app._cheburcheck_aggregate(records)
        self.assertEqual(agg['status'], 'banned')
        self.assertEqual(agg['target'], 'b.example')
        self.assertEqual(agg['probe'], {'response_count': 8,
                                        'blocking_regions': 2,
                                        'restricted_regions': 0,
                                        'clear_regions': 5})
        self.assertIn('probe failed', agg['error'])


class SummarySemanticsTests(unittest.TestCase):
    def test_clear_regions_and_partial_use_collected_regions(self):
        probe = {
            'regions': [
                {'region': 'A', 'verdicts': ['ok']},
                {'region': 'B', 'verdicts': ['tspu_block']},
                {'region': 'C', 'verdicts': []},
            ],
            'response_count': 10,       # stream closed before delivering the rest
            'verdicts': ['ok', 'tspu_block'],
        }
        rec = cheburcheck.build_summary('h', {'blocked': False}, probe)
        self.assertEqual(rec['probe']['blocking_regions'], 1)
        self.assertEqual(rec['probe']['clear_regions'], 1)
        self.assertTrue(rec['partial'])
        self.assertNotIn('regions', rec['probe'])


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
        self.assertEqual(self.client.post('/api/servers/0/cheburcheck/run',
                                          json={}).json(),
                         {'ok': True, 'started': 0, 'reason': 'disabled'})

    def test_enabled_by_default_is_false(self):
        df = _seed(self._tmp.name, [dict(s) for s in SRV])   # no cheburcheck block
        data = json.loads(df.read_text(encoding='utf-8'))
        self.assertNotIn('cheburcheck', data['settings'])
        self.assertFalse(self.app.cheburcheck_enabled(data))