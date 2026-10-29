"""Cross-PR integration guards; no live SSH, Telegram, or user data."""
import ast
import asyncio
import copy
from collections import Counter
from contextlib import ExitStack
import inspect
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import app as panel
from managers.ssh_manager import SSHManager

ROOT = Path(__file__).resolve().parents[1]


class IntegrationTests(unittest.TestCase):
    def test_unlink_finalizes_active_peer_with_stop(self):
        link = dict(id='link', user_id='u', server_id=0, protocol='wg', client_id='peer', last_bytes=60)
        retained = dict(link, user_id='other')
        data = {'users': [{'id': 'u', 'enabled': True, 'traffic_used': 60, 'traffic_total': 60}],
                'servers': [{'uid': 's'}], 'user_connections': [link, retained]}
        reads = iter([(70, False), (70, True)])
        saved = []
        def fake_commit(data_file, operation_id, actor, kind, intent, before, after):
            saved.append(copy.deepcopy(after))
            return {'status': 'success', 'operation_id': 'op', 'replayed': False,
                    'counters_verified_final': False}
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'get_current_user', return_value={'id': 'admin'}), \
             patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, 'commit_finalize', side_effect=fake_commit), \
             patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call', return_value=True), \
             patch.object(panel, 'read_peer_state', side_effect=lambda *a, **k: next(reads)):
            result = asyncio.run(panel.api_unlink_user_connection(
                Mock(), 'u', panel.UnlinkConnectionRequest(server_id=0, protocol='wg', client_id='peer', stop=True)))
            self.assertEqual(result.status_code if hasattr(result, 'status_code') else 200, 200)
            self.assertEqual(saved[-1]['user_connections'], [retained])
            self.assertEqual(len(saved[-1].get('accounting_recoveries', [])), 1)

    def test_unlink_rejects_active_peer_without_stop(self):
        link = dict(id='link', user_id='u', server_id=0, protocol='wg', client_id='peer', last_bytes=60)
        data = {'users': [{'id': 'u', 'enabled': True, 'traffic_used': 60, 'traffic_total': 60}],
                'servers': [{'uid': 's'}], 'user_connections': [link]}
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'get_current_user', return_value={'id': 'admin'}), \
             patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, 'save_data') as save, \
             patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call', return_value=True), \
             patch.object(panel, 'read_peer_state', return_value=(70, False)):
            result = asyncio.run(panel.api_unlink_user_connection(
                Mock(), 'u', panel.UnlinkConnectionRequest(server_id=0, protocol='wg', client_id='peer')))
            self.assertEqual(result.status_code, 409)
            self.assertEqual(json.loads(result.body)['code'], 'peer_active_stop_required')
            save.assert_not_called()

    def test_ssh_failure_cooldown_prevents_reconnect_storm(self):
        ssh = SSHManager('192.0.2.1', 22, 'root', 'fake')
        try:
            with patch('managers.ssh_manager.paramiko.SSHClient.connect', side_effect=OSError('isolated unreachable')) as connect, \
                 patch('managers.ssh_manager.time.time', return_value=100):
                with self.assertRaisesRegex(Exception, 'isolated unreachable'):
                    ssh.connect()
                with self.assertRaisesRegex(Exception, 'backing off'):
                    ssh.ensure_connected()
                self.assertEqual(connect.call_count, 2)
        finally:
            ssh.disconnect()

    def test_ssh_routes_stay_threadpool_handlers(self):
        for name in ('api_get_connections', 'api_get_user_connections', 'api_get_connection_config', 'api_my_connection_config'):
            self.assertFalse(inspect.iscoroutinefunction(getattr(panel, name)), name)

    def test_merge_keeps_editor_linking_and_forced_poll_refresh(self):
        source = (ROOT / 'templates/server.html').read_text(encoding='utf-8')
        editor = source.split('async function saveRenameConnection(', 1)[1].split('async function ', 1)[0]
        self.assertIn('connections/unlink', editor)
        self.assertIn('connections/add', editor)
        self.assertIn('await loadConnections(true, true)', editor)
        self.assertLess(editor.index('connections/add'), editor.index('await loadConnections(true, true)'))
        self.assertIn("if (isPoll && !force && listEl.querySelector('.rename-editor')) return;", source)
        self.assertIn("btn.classList.toggle('peer-toggle-off', !enable)", source)

    def test_no_duplicate_top_level_python_definitions(self):
        for path in [ROOT / 'app.py', *sorted((ROOT / 'managers').glob('*.py'))]:
            tree = ast.parse(path.read_text(encoding='utf-8-sig'))
            counts = Counter(node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
            self.assertEqual([name for name, count in counts.items() if count > 1], [], str(path))

    @unittest.skipUnless(shutil.which('node'), 'node is required')
    def test_rendered_pages_javascript_all_locales(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            data_path = Path(tmp) / 'data.json'
            data_path.write_text(json.dumps({'servers': [{'name': 'Isolated', 'host': '192.0.2.1', 'protocols': {}, 'server_info': {}}], 'users': [], 'user_connections': [], 'settings': {'session_secret': 'test-only'}}), encoding='utf-8')
            stack.enter_context(patch.object(panel, 'DATA_FILE', str(data_path)))
            stack.enter_context(patch.object(panel, '_start_conn_monitor'))
            stack.enter_context(patch.object(panel, 'periodic_background_tasks'))
            stack.enter_context(patch.object(panel.tg_bot, 'launch_bot'))
            stack.enter_context(patch.object(panel, 'get_ssh', side_effect=AssertionError('no live SSH')))
            with TestClient(panel.app) as client:
                response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
                self.assertEqual(response.status_code, 200)
                for locale in ('en', 'fa', 'fr', 'ru', 'zh'):
                    client.cookies.set('lang', locale)
                    for route in ('/server/0', '/users'):
                        with self.subTest(locale=locale, route=route):
                            page = client.get(route)
                            self.assertEqual(page.status_code, 200)
                            script = Path(tmp) / 'rendered.js'
                            script.write_text('\n'.join(re.findall(r'<script(?:[^>]*)>(.*?)</script>', page.text, re.S)), encoding='utf-8')
                            result = subprocess.run(['node', '--check', str(script)], capture_output=True, text=True)
                            self.assertEqual(result.returncode, 0, result.stderr)
