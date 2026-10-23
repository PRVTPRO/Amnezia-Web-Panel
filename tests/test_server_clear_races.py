"""Clear never executes real commands: persisted JSON and SSH doubles only."""
import ast
import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


class ClearTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'data.json'
        source = Path(__file__).resolve().parents[1] / 'app.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        names = {'load_data', 'save_data', 'find_server_by_uid', 'api_clear_server'}
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
        for n in nodes:
            n.decorator_list = []
        self.ssh = Mock()
        self.ssh.run_sudo_script.return_value = ('synthetic', '', 0)
        self.targets = []
        def get_ssh(server):
            self.targets.append(copy.deepcopy(server))
            return self.ssh
        self.exit = SimpleNamespace(detach_entries_for_exit=AsyncMock(return_value=[]),
                                    forget_entry_peers=AsyncMock(return_value=[]))
        self.p = dict(asyncio=asyncio, json=json, os=os, tempfile=tempfile,
                      DATA_FILE=str(self.path), DATA_LOCK=asyncio.Lock(),
                      DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={},
                      Request=Request, Optional=Optional, JSONResponse=JSONResponse,
                      _check_admin=lambda r: r.headers.get('x-role', 'admin') == 'admin',
                      get_ssh=get_ssh, exit_link_svc=self.exit, logger=Mock())
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), self.p)
        self.save = self.p['save_data']
        self.save(dict(servers=[dict(uid=u, host=u+'.example.test', username='fixture', ssh_port=22,
                                    protocols={'awg': {'installed': True}}) for u in ['a', 'b']],
                       users=[{'id': 'user', 'traffic_used': 17}], user_connections=[]))
        self.request = SimpleNamespace(headers={})

    def data(self):
        return json.loads(self.path.read_text(encoding='utf-8'))

    async def clear(self, index=0):
        return await self.p['api_clear_server'](self.request, index)

    async def pause_ssh(self):
        started, release = threading.Event(), threading.Event()
        def run(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError('synthetic SSH barrier')
            return ('', '', 0)
        self.ssh.run_sudo_script.side_effect = run
        task = asyncio.create_task(self.clear())
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        return task, release

    @staticmethod
    def status(r):
        return r.status_code if isinstance(r, JSONResponse) else 200

    async def test_reorder_during_exit_cleanup_never_redirects_remote_clear(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def cleanup(server):
            started.set()
            await release.wait()
            return []
        self.exit.forget_entry_peers.side_effect = cleanup
        task = asyncio.create_task(self.clear())
        await started.wait()
        data = self.data()
        data['servers'].reverse()
        self.save(data)
        release.set()
        self.assertEqual(self.status(await task), 200)
        self.assertEqual([s['uid'] for s in self.targets], ['a'])
        data = self.data()
        self.assertEqual(data['servers'][0]['uid'], 'b')
        self.assertTrue(data['servers'][0]['protocols']['awg']['installed'])
        self.assertEqual(data['servers'][1]['protocols'], {})

    async def test_concurrent_user_changes_survive_remote_clear(self):
        task, release = await self.pause_ssh()
        data = self.data()
        data['users'][0]['traffic_used'] = 99
        data['user_connections'].append({'server_id': 1, 'client_id': 'new'})
        self.save(data)
        release.set()
        self.assertEqual(self.status(await task), 200)
        self.assertEqual(self.data()['users'][0]['traffic_used'], 99)
        self.assertEqual(self.data()['user_connections'], [{'server_id': 1, 'client_id': 'new'}])

    async def test_deleted_uid_is_not_resurrected_after_ssh(self):
        task, release = await self.pause_ssh()
        data = self.data()
        data['servers'].pop(0)
        self.save(data)
        release.set()
        result = await task
        self.assertEqual(self.status(result), 409)
        self.assertTrue(json.loads(result.body)['remote_cleanup_completed'])
        self.assertEqual(self.data(), data)

    async def test_changed_endpoint_is_not_overwritten_after_ssh(self):
        task, release = await self.pause_ssh()
        data = self.data()
        data['servers'][0]['host'] = 'replacement.example.test'
        self.save(data)
        release.set()
        self.assertEqual(self.status(await task), 409)
        self.assertEqual(self.data(), data)

    async def test_nonzero_remote_status_preserves_protocol_metadata(self):
        before = self.data()
        self.ssh.run_sudo_script.return_value = ('', 'synthetic failure', 7)
        result = await self.clear()
        self.assertEqual(self.status(result), 502)
        self.assertEqual(self.data(), before)
        self.ssh.disconnect.assert_called_once()

    async def test_failed_exit_cleanup_never_starts_remote_clear(self):
        before = self.data()
        self.exit.forget_entry_peers.return_value = [{'status': 'error', 'error': 'synthetic failure'}]
        result = await self.clear()
        self.assertEqual(self.status(result), 409)
        self.assertEqual(self.targets, [])
        self.assertEqual(self.data(), before)

    async def test_failed_save_reports_remote_completion(self):
        before = self.data()
        self.p['save_data'] = lambda d: (_ for _ in ()).throw(OSError('synthetic disk failure'))
        result = await self.clear()
        self.assertEqual(self.status(result), 500)
        self.assertTrue(json.loads(result.body)['remote_cleanup_completed'])
        self.assertFalse(json.loads(result.body)['local_commit_completed'])
        self.assertEqual(self.data(), before)
        self.ssh.disconnect.assert_called_once()

    async def test_cancellation_does_not_abandon_remote_clear(self):
        task, release = await self.pause_ssh()
        try:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.data()['servers'][0]['protocols'], {})
        self.ssh.disconnect.assert_called_once()

    async def test_http_stale_uid_negative_bounds_and_authorization(self):
        app = FastAPI()
        app.add_api_route('/api/servers/{server_id}/clear', self.p['api_clear_server'], methods=['POST'])
        with TestClient(app) as client:
            before = self.data()
            for path, headers, expected in [('/api/servers/-1/clear', {}, 404), ('/api/servers/9/clear', {}, 404), ('/api/servers/0/clear?server_uid=obsolete', {}, 409), ('/api/servers/0/clear', {'x-role':'user'}, 403)]:
                result = client.post(path, headers=headers)
                self.assertEqual(result.status_code, expected, result.text)
                self.assertEqual(self.data(), before)
        self.assertEqual(self.targets, [])


class ClearBrowserTests(unittest.TestCase):
    def test_actual_clear_handler_sends_the_page_uid(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest('Playwright is not installed')
        template = (Path(__file__).resolve().parents[1] / 'templates/server.html').read_text(encoding='utf-8')
        start = template.index('    async function clearServer()')
        end = template.index('    async function removeServer()', start)
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}))
            except Exception as exc:
                self.skipTest(f'Chromium is not installed: {type(exc).__name__}')
            try:
                page = browser.new_page()
                page.set_content('<body data-server-uid="entry"></body>')
                page.add_script_tag(content="""
const SERVER_ID = 0;
const calls = [];
const apiCall = async (...args) => {calls.push(args); return {};};
const showToast = () => {};
window.confirm = () => true;
window.setTimeout = () => 0;
""" + template[start:end])
                page.evaluate('clearServer()')
                self.assertEqual(page.evaluate('calls'), [['/api/servers/0/clear?server_uid=entry', 'POST']])
            finally:
                browser.close()


if __name__ == '__main__':
    unittest.main()
