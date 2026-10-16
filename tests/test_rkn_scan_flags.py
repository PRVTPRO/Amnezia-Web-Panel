"""RKN scan flags/overview endpoint and the shared parser: isolated, no SSH."""
import ast
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fastapi.responses import JSONResponse

FUNCTIONS = {'_parse_rkn_scan_output', 'api_rkn_scan_flags', 'api_rkn_scans',
             'api_rkn_scans_clear'}


def isolated_panel():
    path = Path(__file__).resolve().parents[1] / 'app.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    nodes = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in FUNCTIONS]
    assert {node.name for node in nodes} == FUNCTIONS
    for node in nodes:
        node.decorator_list = []
    namespace = {
        'Request': object, 'JSONResponse': JSONResponse, 'logger': Mock(), 'get_ssh': Mock(),
        'load_data': Mock(), 'save_data': Mock(), '_check_admin': Mock(return_value=True),
        'RKN_FLAG_CACHE': {}, 'RKN_FLAG_CACHE_TTL': 900, 'RKN_SCAN_SSH_CMD': 'cmd',
        'asyncio': __import__('asyncio'), 'time': __import__('time'), 'json': json, 're': __import__('re'),
        'datetime': dt.datetime, 'timedelta': dt.timedelta, 'timezone': dt.timezone,
    }

    async def fake_fetch(server):
        return server.pop('_canned_out')

    namespace['_fetch_rkn_scan_output'] = fake_fetch
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


STATUS_ON = ('rkn_extra_block: on\n'
             '  входящие (РКН, DROP NEW):  v4=1151 сетей  v6=21 сетей\n'
             '  исходящие (VK/Max, REJECT): v4=204 сетей  v6=3 сетей')
EV_TPL = '{"t": "%s", "dir": "in", "ip": "87.240.135.44", "dpt": 22, "org": "VKONTAKTE-SPB-AS (LLC VK)"}'


def canned_output(events):
    return STATUS_ON + '\n===LOG===\n' + '\n'.join(EV_TPL % t for t in events)


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.panel = isolated_panel()
        self.parse = self.panel['_parse_rkn_scan_output']

    def test_not_installed_yields_unknown(self):
        out = "===LOG===\n"
        d = self.parse(out, False)
        self.assertEqual(d['agent_state'], 'unknown')
        self.assertFalse(d['flag_enabled'])
        self.assertEqual(d['total_events'], 0)

    def test_parses_status_and_aggregates(self):
        now = dt.datetime.now(dt.timezone.utc)
        fresh = now.isoformat()
        old = (now - dt.timedelta(hours=25)).isoformat()
        d = self.parse(canned_output([fresh, fresh, old]), True)
        self.assertEqual(d['agent_state'], 'on')
        self.assertTrue(d['flag_enabled'])
        self.assertEqual(d['total_events'], 3)
        self.assertEqual(d['last_24h'], 2)
        self.assertEqual(d['by_org'][0][0], 'VKONTAKTE-SPB-AS (LLC VK)')
        self.assertEqual(d['by_dpt'][0][0], 22)
        self.assertEqual(d['by_dir'], {'in': 3})
        self.assertEqual(d['sets'], {'in4': 1151, 'in6': 21, 'out4': 204, 'out6': 3})
        self.assertEqual(len(d['recent']), 3)

    def test_sets_default_to_zero_without_counters(self):
        out = 'rkn_extra_block: on\n===LOG===\n'
        d = self.parse(out, False)
        self.assertEqual(d['sets'], {'in4': 0, 'in6': 0, 'out4': 0, 'out6': 0})

    def test_garbage_lines_are_skipped(self):
        out = STATUS_ON + '\n===LOG===\nnot json\n{"broken"\n' + EV_TPL % '2026-10-04T10:00:00+00:00'
        d = self.parse(out, False)
        self.assertEqual(d['total_events'], 1)

    def test_flags_and_last_update_are_parsed(self):
        out = (STATUS_ON + '\n'
               '  flags: block_in=on block_out=off log_in=on log_out=off\n'
               '  last_update: 2026-10-16T12:00:00Z\n'
               '  правила: iptables INPUT/OUTPUT/FORWARD — вешаются\n===LOG===\n')
        d = self.parse(out, True)
        self.assertEqual(d['flags'], {'block_in': 'on', 'block_out': 'off',
                                      'log_in': 'on', 'log_out': 'off'})
        self.assertEqual(d['last_update'], '2026-10-16T12:00:00Z')

    def test_flags_default_empty_without_status_lines(self):
        d = self.parse(STATUS_ON + '\n===LOG===\n', True)
        self.assertEqual(d['flags'], {})
        self.assertIsNone(d['last_update'])


class FlagsEndpointTests(unittest.TestCase):
    def setUp(self):
        self.panel = isolated_panel()
        self.request = SimpleNamespace(session={'user_id': 'admin'}, headers={})
        recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
        self.servers = [
            {'name': 'A', 'protocols': {}, '_canned_out': canned_output([recent])},
            {'name': 'B', 'protocols': {}, '_canned_out': '===LOG===\n'},
        ]
        self.panel['load_data'] = Mock(return_value={'servers': self.servers,
                                                     'users': [], 'user_connections': []})
        self.panel['RKN_FLAG_CACHE'].clear()

    def run_flags(self):
        return self.panel['asyncio'].run(
            self.panel['api_rkn_scan_flags'](self.request))

    def test_flags_returned_only_for_responding_servers(self):
        result = self.run_flags()
        self.assertIn('0', result)
        self.assertIn('1', result)
        self.assertEqual(result['0']['events24'], 1)
        self.assertEqual(result['0']['agent_state'], 'on')
        self.assertEqual(result['1']['agent_state'], 'unknown')

    def test_results_are_cached(self):
        self.run_flags()
        # Poison the canned output: a cache hit must NOT re-fetch.
        self.servers[0]['_canned_out'] = '===LOG===\n'
        result = self.run_flags()
        self.assertEqual(result['0']['events24'], 1)

    def test_forbidden_without_admin(self):
        self.panel['_check_admin'] = Mock(return_value=False)
        resp = self.run_flags()
        self.assertIsInstance(resp, JSONResponse)
        self.assertEqual(resp.status_code, 403)


if __name__ == '__main__':
    unittest.main()


class ClearEndpointTests(unittest.TestCase):
    def setUp(self):
        self.panel = isolated_panel()
        self.request = SimpleNamespace(session={'user_id': 'admin'}, headers={})
        self.ran = []
        ssh = SimpleNamespace(
            connect=lambda: None,
            disconnect=lambda: None,
            run_sudo_command=lambda cmd, timeout=60: self.ran.append(cmd) or ('', '', 0))
        self.panel['get_ssh'] = Mock(return_value=ssh)
        self.panel['load_data'] = Mock(return_value={
            'servers': [{'name': 'A', 'protocols': {}}], 'users': [], 'user_connections': []})
        self.panel['RKN_FLAG_CACHE'][0] = {'ts': 1, 'data': {'events24': 5}}
        self.panel['asyncio'] = __import__('asyncio')

    def call(self):
        return self.panel['asyncio'].run(
            self.panel['api_rkn_scans_clear'](self.request, 0))

    def test_clear_truncates_remote_log_and_evicts_cache(self):
        result = self.call()
        self.assertEqual(result, {'status': 'cleared'})
        self.assertEqual(self.ran,
                         ['rkn-extra-block clearscans 2>/dev/null || : > /var/log/rkn-scans.json'])
        self.assertNotIn(0, self.panel['RKN_FLAG_CACHE'])

    def test_clear_forbidden_without_admin(self):
        self.panel['_check_admin'] = Mock(return_value=False)
        resp = self.call()
        self.assertIsInstance(resp, JSONResponse)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.ran, [])

    def test_clear_unknown_server(self):
        result = self.panel['asyncio'].run(
            self.panel['api_rkn_scans_clear'](self.request, 99))
        self.assertIsInstance(result, JSONResponse)
        self.assertEqual(result.status_code, 404)
