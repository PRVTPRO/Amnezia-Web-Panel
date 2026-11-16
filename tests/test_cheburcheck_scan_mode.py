"""Scan-mode regressions for the Cheburcheck integration.

`scan_mode` says what a check actually did: 'full' (probes answered),
'static_only' (no probe data: no API token, 401/403, 429, network),
'partial' (some probes answered) or 'failed' (static check itself failed).
The aggregate, both API endpoints and the templates must agree on it.
No real HTTP: every network call is patched.
"""
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cheburcheck


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_TEMPLATE = os.path.join(ROOT, 'templates', 'server.html')
INDEX_TEMPLATE = os.path.join(ROOT, 'templates', 'index.html')

SRV = [{'name': 'FINN', 'host': '95.81.126.149', 'ssh_port': 54645,
        'uid': 'u1', 'protocols': {'awg': {}}},
       {'name': 'EURO', 'host': '46.30.41.17', 'ssh_port': 1803,
        'uid': 'u2', 'protocols': {'xray': {}}}]


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


def _rec(target, scan_mode='full', status='clean'):
    return {'target': target, 'status': status,
            'checked_at': '2026-11-12T00:00:00+00:00',
            'probe': {'online_probes': 40, 'response_count': 5,
                      'verdict_counts': {}, 'blocking_regions': 0,
                      'clear_regions': 5},
            'static': {}, 'partial': False, 'scan_mode': scan_mode}


async def _fake_check(target):
    return {'blocked': False, 'id': 'x', 'geo': {}}


def _probe(online, answered):
    async def fetch(check_id):
        return {'online_probes': online, 'response_count': answered,
                'verdict_counts': {}, 'regions': []}
    return fetch


class AggregateScanModeTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app = app

    def test_all_full(self):
        records = {'a': _rec('a', 'full'), 'b': _rec('b', 'full')}
        self.assertEqual(
            self.app._cheburcheck_aggregate(records)['scan_mode'], 'full')

    def test_all_static_only(self):
        records = {'a': _rec('a', 'static_only'),
                   'b': _rec('b', 'static_only')}
        self.assertEqual(
            self.app._cheburcheck_aggregate(records)['scan_mode'],
            'static_only')

    def test_all_failed(self):
        records = {'a': _rec('a', 'failed'), 'b': _rec('b', 'failed')}
        self.assertEqual(
            self.app._cheburcheck_aggregate(records)['scan_mode'], 'failed')

    def test_mixed_full_and_static_only_is_partial(self):
        records = {'a': _rec('a', 'full'), 'b': _rec('b', 'static_only')}
        self.assertEqual(
            self.app._cheburcheck_aggregate(records)['scan_mode'], 'partial')

    def test_synthetic_none_mode_counts_as_failed(self):
        records = {'a': self.app._cheburcheck_synthetic('a', 'not checked yet')}
        self.assertIsNone(records['a']['scan_mode'])
        self.assertEqual(
            self.app._cheburcheck_aggregate(records)['scan_mode'], 'failed')


class RunOneScanModeTests(unittest.TestCase):
    """_run_cheburcheck_one must label the record with the real scan mode."""

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

    def _record(self, uid='u1', target='95.81.126.149'):
        return self.app.CHEBURCHECK_CACHE.get(uid, {}).get(target)

    def _run(self, check, probe):
        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=check), \
                 patch.object(cheburcheck, 'fetch_probe', new=probe):
                srv = {'uid': 'u1', 'name': 'FINN',
                       'host': '95.81.126.149', 'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149')
        asyncio.run(go())

    def test_without_token_is_static_only_and_no_probe_request(self):
        async def no_token_probe(check_id):
            raise cheburcheck.CheburcheckApiError(
                user_message=cheburcheck.NO_TOKEN_MESSAGE,
                documentation_url=cheburcheck.TOKEN_DOC_URL)

        async def go():
            with patch.object(cheburcheck, 'fetch_check', new=_fake_check), \
                 patch.object(cheburcheck, 'fetch_probe', new=no_token_probe), \
                 patch.object(cheburcheck, '_read_probe_stream') as stream:
                srv = {'uid': 'u1', 'name': 'FINN',
                       'host': '95.81.126.149', 'protocols': {'awg': {}}}
                await self.app._run_cheburcheck_one(srv, '95.81.126.149')
                stream.assert_not_called()
        asyncio.run(go())
        rec = self._record()
        self.assertIsNotNone(rec)
        self.assertEqual(rec['scan_mode'], 'static_only')
        self.assertEqual(rec['status'], 'unknown')
        self.assertIn('API-токен', rec['error'])

    def test_full_probe_is_full(self):
        self._run(_fake_check, _probe(40, 40))
        self.assertEqual(self._record()['scan_mode'], 'full')

    def test_partial_probe_is_partial(self):
        self._run(_fake_check, _probe(40, 3))
        self.assertEqual(self._record()['scan_mode'], 'partial')


class ApiScanModeTests(unittest.TestCase):
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

    def test_get_endpoint_returns_scan_mode(self):
        self.app.CHEBURCHECK_CACHE['u1'] = {
            '95.81.126.149': _rec('95.81.126.149', 'static_only')}
        body = self.client.get('/api/servers/0/cheburcheck').json()
        self.assertIn('scan_mode', body)
        self.assertEqual(body['scan_mode'], 'static_only')

    def test_flags_endpoint_returns_scan_mode(self):
        self.app.CHEBURCHECK_CACHE['u1'] = {
            '95.81.126.149': _rec('95.81.126.149', 'static_only')}
        flags = self.client.get(
            '/api/servers/cheburcheck_flags').json()['flags']
        self.assertIn('scan_mode', flags['0'])
        self.assertEqual(flags['0']['scan_mode'], 'static_only')


class TemplateScanModeTests(unittest.TestCase):
    def test_server_template_references_scan_mode(self):
        with open(SERVER_TEMPLATE, encoding='utf-8') as handle:
            html = handle.read()
        self.assertIn('scan_mode', html)
        self.assertIn('cheburcheck_static_only', html)
        self.assertIn('cheburcheck_static_only_note', html)

    def test_index_template_references_static_only(self):
        with open(INDEX_TEMPLATE, encoding='utf-8') as handle:
            html = handle.read()
        self.assertIn("f.scan_mode === 'static_only'", html)
        self.assertIn('cheburcheck_static_only', html)


if __name__ == '__main__':
    unittest.main()
