"""Real entry points, synthetic state, no SSH connections or application startup."""
import asyncio
import copy
import io
import html
import json
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi import UploadFile
import app as panel
import telegram_bot
from connection_service import SelfServiceError
from peer_accounting import FINALIZATION_MESSAGE, TrafficFinalizationRequired, require_unowned, serialize_peer_lifecycle
from tests import test_connection_service as fixtures


def state():
    return {
        'servers': [dict(uid='node-a', host='192.0.2.1', protocols={'awg3': {}})],
        'users': [dict(id='u', enabled=True, traffic_used=450, traffic_total=700)],
        'user_connections': [dict(id='link', user_id='u', server_id=0,
                                  protocol='awg3', client_id='peer', last_bytes=10)],
    }


class DestructiveAccountingGuards(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.data = state()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(panel, '_check_admin', return_value=True))
        self.stack.enter_context(patch.object(panel, 'get_current_user', return_value={'id': 'admin', 'role': 'admin'}))
        self.stack.enter_context(patch.object(panel, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.save = self.stack.enter_context(patch.object(panel, 'save_data'))
        self.ssh = self.stack.enter_context(patch.object(panel, 'get_ssh', side_effect=AssertionError('SSH forbidden')))
        self.exit = self.stack.enter_context(patch.object(panel, 'exit_link_svc', new=Mock()))
        self.request = SimpleNamespace(cookies={})

    def rejected(self, result):
        self.assertEqual(result.status_code, 409, getattr(result, 'body', result))
        self.assertEqual(json.loads(result.body)['code'], 'traffic_finalization_required')
        self.save.assert_not_called()
        self.ssh.assert_not_called()
        self.assertEqual(self.exit.mock_calls, [])

    def finalized(self, result, saved_data=None, expect_delta=2):
        status = result.status_code if hasattr(result, 'status_code') else 200
        self.assertEqual(status, 200, getattr(result, 'body', result))
        body = json.loads(result.body) if hasattr(result, 'body') else result
        self.assertTrue(body.get('finalized'))
        self.assertIn('accounting', body)
        if saved_data is not None:
            self.assertEqual(saved_data['users'][0]['traffic_total'], 700 + expect_delta)
            self.assertEqual(len(saved_data['user_connections']), 0)
            self.assertEqual(len(saved_data.get('accounting_recoveries', [])), 1)

    async def test_raw_remove_finalizes_accounting(self):
        ssh = Mock()
        saved = []
        def fake_commit(data_file, operation_id, actor, kind, intent, before, after):
            saved.append(copy.deepcopy(after))
            return {'status': 'success', 'operation_id': 'op', 'replayed': False,
                    'counters_verified_final': False}
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call', return_value=True), \
             patch.object(panel, 'read_peer_state', return_value=(12, True)), \
             patch.object(panel, 'commit_finalize', side_effect=fake_commit):
            req = panel.ConnectionActionRequest(protocol='awg3', client_id='peer')
            result = await panel.api_remove_connection(self.request, 0, req)
        self.finalized(result, saved[-1] if saved else None)

    async def test_remove_unknown_counter_requires_explicit_confirmation(self):
        with patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call') as remote, \
             patch.object(panel, 'read_peer_state', return_value=(None, False)), \
             patch.object(panel, 'commit_finalize') as commit:
            result = await panel.api_remove_connection(
                self.request, 0, panel.ConnectionActionRequest(protocol='awg3', client_id='peer'))
        self.assertEqual(result.status_code, 409)
        self.assertEqual(json.loads(result.body)['code'], 'final_counter_read_failed')
        self.assertTrue(json.loads(result.body)['can_force'])
        remote.assert_not_called()
        commit.assert_not_called()

    async def test_server_delete_and_clear_are_guarded_before_exit_cleanup(self):
        for name in ('api_delete_server', 'api_clear_server'):
            with self.subTest(name=name):
                self.rejected(await getattr(panel, name)(self.request, 0))

    async def test_protocol_uninstall_and_raw_replace_are_guarded(self):
        req = panel.ProtocolRequest(protocol='awg3')
        self.rejected(await panel.api_uninstall_protocol(self.request, 0, req))
        self.rejected(await panel.api_server_config_save(
            self.request, 0, SimpleNamespace(protocol='awg3', config='[Interface]')))

    async def test_protocol_restore_is_guarded_before_remote_restore(self):
        req = panel.BackupDownloadRequest(protocol='awg3', filename='backup.tar.gz')
        self.rejected(await panel.api_protocol_backup_restore(self.request, 0, req))

    async def test_panel_restore_cannot_remove_owner_or_rewind_baselines(self):
        for data in ({'servers': [], 'users': []}, dict(self.data, user_connections=[])):
            with self.subTest(data=data):
                file = UploadFile(filename='backup.json', file=io.BytesIO(json.dumps(data).encode()))
                self.rejected(await panel.api_backup_restore(self.request, file))

    async def test_delete_user_retains_all_links(self):
        self.rejected(await panel.api_delete_user(self.request, 'u'))

    async def test_sync_delete_reports_conflict_instead_of_success_count(self):
        self.data['users'][0]['remnawave_uuid'] = 'external'
        self.rejected(await panel.api_sync_delete(self.request))

    async def test_batch_delete_fails_before_any_toggle_create_or_ssh(self):
        with self.assertRaises(TrafficFinalizationRequired):
            await panel.perform_mass_operations(delete_uids=['u'], toggle_uids=[('u', False)])
        self.save.assert_not_called()
        self.ssh.assert_not_called()

    async def test_sync_delete_helper_is_guarded_for_non_http_callers(self):
        before = copy.deepcopy(self.data)
        with self.assertRaises(TrafficFinalizationRequired):
            panel.perform_delete_user(self.data, 'u')
        self.assertEqual(self.data, before)
        self.ssh.assert_not_called()

    async def test_disabled_unlimited_and_dangling_user_still_finalized(self):
        ssh = Mock()
        def fake_commit(*args, **kwargs):
            return {'status': 'success', 'operation_id': 'op', 'replayed': False,
                    'counters_verified_final': False}
        for value in ({'enabled': False}, {'traffic_limit': 0}, {'id': 'different-user'}):
            with self.subTest(value=value):
                self.data = state()
                self.data['users'][0].update(value)
                with patch.object(panel, 'get_ssh', return_value=ssh), \
                     patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
                     patch.object(panel, '_manager_call', return_value=True), \
                     patch.object(panel, 'read_peer_state', return_value=(12, True)), \
                     patch.object(panel, 'commit_finalize', side_effect=fake_commit):
                    result = await panel.api_remove_connection(
                        self.request, 0, panel.ConnectionActionRequest(protocol='awg3', client_id='peer'))
                self.assertEqual(result.status_code if hasattr(result, 'status_code') else 200, 200, getattr(result, 'body', result))

    async def test_unlinked_peer_on_same_server_remains_removable(self):
        ssh = Mock()
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call', return_value=True) as call:
            result = await panel.api_remove_connection(self.request, 0,
                panel.ConnectionActionRequest(protocol='awg3', client_id='unowned'))
        self.assertEqual(result, {'status': 'success', 'finalized': False})
        self.assertEqual(call.call_args.args[1:], ('remove_client', 'awg3', 'unowned'))
        self.save.assert_not_called()
        self.assertEqual(self.data['user_connections'], state()['user_connections'])

    async def test_same_client_key_in_other_protocol_is_unowned(self):
        ssh = Mock()
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, '_manager_call', return_value=True):
            result = await panel.api_remove_connection(self.request, 0,
                panel.ConnectionActionRequest(protocol='awg2', client_id='peer'))
        self.assertEqual(result, {'status': 'success', 'finalized': False})
        self.save.assert_not_called()
        self.assertEqual(self.data['user_connections'], state()['user_connections'])

    async def test_empty_user_still_deletes(self):
        self.data['users'].append({'id': 'empty'})
        self.assertEqual(await panel.api_delete_user(self.request, 'empty'), {'status': 'success'})
        self.assertEqual(self.save.call_args.args[0]['users'], [self.data['users'][0]])

    async def test_negative_server_id_cannot_select_last_node(self):
        self.assertEqual((await panel.api_remove_connection(self.request, -1,
            panel.ConnectionActionRequest(protocol='awg3', client_id='peer'))).status_code, 404)
        self.ssh.assert_not_called()

    async def test_same_container_protocol_alias_finalizes_not_bypasses(self):
        ssh = Mock()
        def fake_commit(*args, **kwargs):
            return {'status': 'success', 'operation_id': 'op', 'replayed': False,
                    'counters_verified_final': False}
        for protocol in ('awg3__1', 'awg3__0', 'awg3__bad'):
            with self.subTest(protocol=protocol):
                self.data = state()
                with patch.object(panel, 'get_ssh', return_value=ssh), \
                     patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
                     patch.object(panel, '_manager_call', return_value=True), \
                     patch.object(panel, 'read_peer_state', return_value=(12, True)), \
                     patch.object(panel, 'commit_finalize', side_effect=fake_commit):
                    result = await panel.api_remove_connection(self.request, 0,
                        panel.ConnectionActionRequest(protocol=protocol, client_id='peer'))
                self.assertEqual(result.status_code if hasattr(result, 'status_code') else 200, 200, getattr(result, 'body', result))

    async def test_self_service_delete_cannot_drop_baselines(self):
        data = fixtures.base_data()
        data['user_connections'] = [dict(id='self', user_id='user-1', server_id=0,
            protocol='awg', client_id='peer', created_by='self_service', last_bytes=10)]
        helper = fixtures.ConnectionServiceTest()
        service, saved, manager = helper.make_service(data)
        before = copy.deepcopy(saved)
        with self.assertRaises(SelfServiceError) as error:
            await service.delete_user_connection('user-1', 'self', 'web')
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(saved, before)
        self.assertEqual(manager.removed, [])

    async def test_telegram_remove_cannot_bypass_http_guard(self):
        api = SimpleNamespace(edit_message=AsyncMock())
        with patch.object(telegram_bot, '_get_ssh_and_manager') as ssh:
            await telegram_bot._admin_remove_client(api, 1, 2, 0, 'awg3', 'peer',
                lambda: copy.deepcopy(self.data), self.save)
        ssh.assert_not_called()
        self.save.assert_not_called()
        self.assertIn(FINALIZATION_MESSAGE, html.unescape(api.edit_message.call_args.args[2]))

    async def test_concurrent_link_is_finalized_by_remove(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def manager_call(manager, method, *args, **kwargs):
            calls.append(method)
            if method == 'get_client_config':
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('test barrier')
                return 'synthetic config'
            if method == 'remove_client':
                return True
            if method == 'read_peer_state':
                return (12, True)
            raise AssertionError(f'unexpected manager call: {method}')
        def save(data):
            self.data = copy.deepcopy(data)
        with patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager', return_value=Mock()), \
             patch.object(panel, 'protocol_public_endpoint', return_value=('192.0.2.1', None)), \
             patch.object(panel, 'config_payloads', return_value={}), \
             patch.object(panel, '_manager_call', side_effect=manager_call), \
             patch.object(panel, 'read_peer_state', side_effect=lambda *a, **k: (12, True)), \
             patch.object(panel, 'save_data', side_effect=save):
            add = asyncio.create_task(panel.api_add_user_connection(self.request, 'u',
                panel.AddUserConnectionRequest(server_id=0, protocol='awg3', client_id='unowned')))
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            queued = asyncio.Event()
            async def remove():
                queued.set()
                return await panel.api_remove_connection(self.request, 0,
                    panel.ConnectionActionRequest(protocol='awg3', client_id='unowned'))
            removal = asyncio.create_task(remove())
            await queued.wait()
            # Traffic/state writers remain free while lifecycle SSH runs.
            async with panel.DATA_LOCK:
                self.data['users'][0]['traffic_used'] += 1
            self.assertFalse(removal.done())
            release.set()
            self.assertEqual((await add)['status'], 'success')
            result = await removal
        self.assertEqual(result.status_code if hasattr(result, 'status_code') else 200, 200)
        self.assertIn('get_client_config', calls)
        self.assertIn('remove_client', calls)
        self.assertEqual(self.data['users'][0]['traffic_used'], 451)


class InterlockCancellation(unittest.IsolatedAsyncioTestCase):
    async def test_started_cancelled_worker_keeps_interlock_until_network_finishes(self):
        entered, release = threading.Event(), threading.Event()
        completed = asyncio.Event()
        @serialize_peer_lifecycle
        async def first():
            entered.set()
            await asyncio.to_thread(release.wait, 5)
            completed.set()
        @serialize_peer_lifecycle
        async def second():
            self.assertTrue(completed.is_set())
        request = asyncio.create_task(first())
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        follower = asyncio.create_task(second())
        try:
            self.assertFalse(completed.is_set())
        finally:
            release.set()
        await follower

    async def test_cancelled_waiter_never_starts_mutation(self):
        entered, release = asyncio.Event(), asyncio.Event()
        called = []
        @serialize_peer_lifecycle
        async def first():
            entered.set()
            await release.wait()
        @serialize_peer_lifecycle
        async def waiting():
            called.append(True)
        leader = asyncio.create_task(first())
        await entered.wait()
        follower = asyncio.create_task(waiting())
        # Explicit scheduling barrier; do not rely on a timing sleep.
        scheduled = asyncio.Event()
        asyncio.get_running_loop().call_soon(scheduled.set)
        await scheduled.wait()
        follower.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await follower
        release.set()
        await leader
        self.assertEqual(called, [])


class ScopeMatching(unittest.TestCase):
    def test_exact_instance_and_user_scope(self):
        data = state()
        for scope in ({'protocol': 'awg3__2'}, {'server_id': 1},
                      {'client_id': 'other'}, {'user_ids': {'other'}}):
            require_unowned(data, **scope)
        with self.assertRaises(TrafficFinalizationRequired):
            require_unowned(data, user_ids={'u'})

    def test_physical_instance_aliases_preserve_separate_instances(self):
        data = state()
        data['user_connections'][0]['protocol'] = 'awg3__2'
        with self.assertRaises(TrafficFinalizationRequired):
            require_unowned(data, protocol='awg3__02')
        require_unowned(data, protocol='awg3')
        data['user_connections'][0]['protocol'] = 'wireguard'
        with self.assertRaises(TrafficFinalizationRequired):
            require_unowned(data, protocol='wireguard__2')
