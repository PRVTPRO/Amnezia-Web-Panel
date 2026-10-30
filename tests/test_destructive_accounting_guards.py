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


class ConfigAccountingEdits(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.data = state()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (('_check_admin', lambda request: True),
                            ('load_data', lambda: copy.deepcopy(self.data))):
            self.stack.enter_context(patch.object(panel, name, value))
        self.ssh, self.manager = Mock(), Mock()
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=self.ssh))
        self.stack.enter_context(patch.object(panel, 'get_protocol_manager', return_value=self.manager))
        self.stack.enter_context(patch.object(panel, 'AWGManager', return_value=self.manager))
        self.save = self.stack.enter_context(patch.object(panel, 'save_data'))
        self.request = SimpleNamespace(cookies={})
        self.config = '[Interface]\nPrivateKey = synthetic\nAddress = 10.8.0.1/24\nListenPort = 51820\n# DNS = 1.1.1.1\nPostUp = echo original # meaningful shell argument\n[Peer]\nPublicKey = peer\nAllowedIPs = 10.8.0.2/32\n'
        self.manager._get_server_config.return_value = self.config

    async def call(self, config=None, protocol='awg3'):
        return await panel.api_server_config_save(self.request, 0, panel.ServerConfigSaveRequest(
            protocol=protocol, config=self.config if config is None else config))

    def untouched(self):
        self.save.assert_not_called()
        self.manager.save_server_config.assert_not_called()
        self.manager._save_server_json.assert_not_called()
        self.ssh.upload_file.assert_not_called()
        self.ssh.upload_file_sudo.assert_not_called()

    async def test_parsed_noop_preserves_ownership_counters_and_baselines(self):
        before = copy.deepcopy(self.data)
        for _ in range(2):
            result = await self.call('# harmless heading\n' + self.config.replace('PrivateKey =', 'PrivateKey='))
            self.assertEqual(result, {'status': 'success', 'unchanged': True})
        self.assertEqual(self.data, before)
        self.untouched()

    async def test_meaningful_changes_are_rejected_without_counter_reset(self):
        for old, new in (('synthetic', 'changed'), ('PublicKey = peer', 'PublicKey = replacement'),
                         ('10.8.0.2/32', '10.8.0.3/32'), ('51820', '51821'),
                         ('1.1.1.1', '8.8.8.8'), ('10.8.0.1/24', '10.9.0.1/24'),
                         ('meaningful shell argument', 'changed shell argument')):
            with self.subTest(old=old):
                result = await self.call(self.config.replace(old, new))
                self.assertEqual(result.status_code, 409)
                self.assertEqual(json.loads(result.body)['code'], 'traffic_finalization_required')
        self.untouched()
        self.assertEqual(self.data['users'][0]['traffic_total'], 700)
        self.assertEqual(self.data['user_connections'][0]['last_bytes'], 10)

    async def test_additional_peer_fields_and_executable_commands_are_significant(self):
        for section, field in (('[Interface]', 'MTU = 1420'), ('[Peer]', 'PresharedKey = synthetic'),
                               ('[Peer]', 'Endpoint = 192.0.2.2:51820'),
                               ('[Peer]', 'PersistentKeepalive = 25'),
                               *[('[Interface]', key + ' = echo synthetic')
                                 for key in ('PreUp', 'PreDown', 'PostDown')]):
            with self.subTest(field=field):
                self.assertEqual((await self.call(self.config.replace(section, section + '\n' + field))).status_code, 409)
        self.untouched()

    async def test_peer_removal_and_invalid_configuration_remain_guarded(self):
        for text in (self.config.split('[Peer]')[0], '[Broken]', '[Interface]',
                     self.config + '\n[Interface]\nPrivateKey=duplicate'):
            result = await self.call(text)
            self.assertEqual(result.status_code, 409)
        self.untouched()

    async def test_wireguard_noop_uses_same_protection(self):
        self.data['user_connections'][0]['protocol'] = 'wireguard'
        result = await self.call(protocol='wireguard')
        self.assertEqual(result, {'status': 'success', 'unchanged': True})
        self.untouched()

    async def test_json_and_toml_noop_never_reload_or_restart(self):
        for protocol, old, new in (
            ('xray', '{"inbounds":[],"stats":{}}', '{"stats": {}, "inbounds": []}'),
            ('telemt', '[access.users]\nfixture="synthetic"\n', '# comment\n[access.users]\nfixture = "synthetic"\n')):
            with self.subTest(protocol=protocol):
                self.data['user_connections'][0]['protocol'] = protocol
                self.manager._get_server_config.return_value = old
                self.ssh.run_sudo_command.return_value = (old, '', 0)
                self.manager.container_name = 'amnezia-xray'
                self.manager._config_path.return_value = '/opt/amnezia/xray/server.json'
                self.assertEqual(await self.call(new, protocol), {'status': 'success', 'unchanged': True})
        self.untouched()

    async def test_current_xray_duplicate_keys_cannot_be_collapsed_into_noop(self):
        self.data['user_connections'][0]['protocol'] = 'xray'
        self.manager._get_server_json.return_value = {'stats': {}}
        self.manager.container_name = 'amnezia-xray'
        self.manager._config_path.return_value = '/opt/amnezia/xray/server.json'
        self.ssh.run_sudo_command.return_value = ('{"stats":{"changed":true},"stats":{}}', '', 0)
        self.assertEqual((await self.call('{"stats":{}}', 'xray')).status_code, 409)
        self.untouched()

    async def test_toml_client_secret_and_json_peer_changes_remain_blocked(self):
        for protocol, current, proposed in (
                ('telemt', '[access.users]\nfixture="original"', '[access.users]\nfixture="changed"'),
                ('xray', '{"inbounds":[{"settings":{"clients":[{"id":"original"}]}}]}',
                 '{"inbounds":[{"settings":{"clients":[{"id":"changed"}]}}]}')):
            with self.subTest(protocol=protocol):
                self.data['user_connections'][0]['protocol'] = protocol
                self.manager._get_server_config.return_value = current
                self.ssh.run_sudo_command.return_value = (current, '', 0)
                self.manager.container_name = 'amnezia-xray'
                self.manager._config_path.return_value = '/opt/amnezia/xray/server.json'
                self.assertEqual((await self.call(proposed, protocol)).status_code, 409)
        self.untouched()

    async def test_json_ambiguous_keys_are_not_a_safe_noop(self):
        self.data['user_connections'][0]['protocol'] = 'xray'
        result = await self.call('{"stats":{},"stats":{}}', 'xray')
        self.assertEqual(result.status_code, 409)
        self.ssh.connect.assert_not_called()
        self.untouched()

    async def test_peerless_edit_keeps_existing_writer(self):
        self.data['user_connections'] = []
        self.assertEqual(await self.call(), {'status': 'success'})
        self.manager.save_server_config.assert_called_once_with('awg3', self.config)
        self.ssh.disconnect.assert_called_once()

    async def test_peerless_exit_link_is_protected_even_through_alias(self):
        self.data['user_connections'] = []
        self.data['servers'][0]['protocols']['awg3']['exit_link'] = {'exit_uid': 'exit-fixture'}
        result = await self.call(self.config.replace('51820', '51821'), 'awg3__1')
        self.assertEqual(result.status_code, 409)
        self.untouched()

    async def test_stale_page_uid_is_rejected_before_ssh(self):
        result = await panel.api_server_config_save(self.request, 0,
            panel.ServerConfigSaveRequest(protocol='awg3', config=self.config), server_uid='removed-node')
        self.assertEqual(result.status_code, 409)
        self.ssh.connect.assert_not_called()

    async def test_ssh_failure_disconnects_without_writes(self):
        self.ssh.connect.side_effect = OSError('synthetic SSH outage')
        result = await self.call()
        self.assertEqual(result.status_code, 500)
        self.ssh.disconnect.assert_called_once()
        self.untouched()

    async def test_config_read_revalidates_identity_and_always_disconnects(self):
        for phase in ('connect', 'read', 'failure'):
            with self.subTest(phase=phase):
                self.data = state()
                self.ssh.reset_mock(side_effect=True)
                self.manager.reset_mock(side_effect=True)
                def read(protocol):
                    if phase == 'failure':
                        raise OSError('synthetic read failure')
                    self.data['servers'][0]['uid'] = 'replacement-node'
                    return self.config
                if phase == 'connect':
                    self.ssh.connect.side_effect = lambda: self.data['servers'][0].update(uid='replacement-node')
                self.manager._get_server_config.side_effect = read
                result = await panel.api_server_config(self.request, 0, panel.ProtocolRequest(protocol='awg3'), 'node-a')
                self.assertEqual(result.status_code, 500 if phase == 'failure' else 409)
                self.ssh.disconnect.assert_called_once()
                if phase == 'connect':
                    self.manager._get_server_config.assert_not_called()
        self.untouched()

    async def test_identity_change_during_read_is_rejected(self):
        def read(protocol):
            self.data['servers'][0]['uid'] = 'replacement-node'
            return self.config
        self.manager._get_server_config.side_effect = read
        self.assertEqual((await self.call()).status_code, 409)
        self.untouched()

    async def test_ownership_and_exit_link_changes_during_read_are_rejected(self):
        for change in ('owner', 'client', 'unlink', 'exit_link'):
            with self.subTest(change=change):
                self.data = state()
                def read(protocol):
                    if change == 'owner':
                        self.data['user_connections'][0]['user_id'] = 'another-user'
                    elif change == 'client':
                        self.data['user_connections'][0]['client_id'] = 'another-peer'
                    elif change == 'unlink':
                        self.data['user_connections'] = []
                    else:
                        self.data['servers'][0]['protocols']['awg3']['exit_link'] = {'exit_uid': 'other'}
                    return self.config
                self.manager._get_server_config.side_effect = read
                self.assertEqual((await self.call()).status_code, 409)
        self.untouched()

    async def test_concurrent_noops_do_not_overwrite_later_accounting(self):
        before = copy.deepcopy(self.data)
        results = await asyncio.gather(self.call(), self.call())
        self.assertEqual(results, [{'status': 'success', 'unchanged': True}] * 2)
        self.assertEqual(self.data, before)
        self.untouched()

    async def test_live_accounting_commit_during_read_is_preserved(self):
        def read(protocol):
            self.data['users'][0].update(traffic_used=510, traffic_total=760)
            self.data['user_connections'][0]['last_bytes'] = 70
            return self.config
        self.manager._get_server_config.side_effect = read
        self.assertEqual(await self.call(), {'status': 'success', 'unchanged': True})
        self.assertEqual(self.data['users'][0]['traffic_used'], 510)
        self.assertEqual(self.data['users'][0]['traffic_total'], 760)
        self.assertEqual(self.data['user_connections'][0]['last_bytes'], 70)
        self.untouched()

    async def test_cancelled_config_request_keeps_interlock_until_read_finishes(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def read(protocol):
            calls.append(protocol)
            if len(calls) == 1:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('synthetic read barrier')
            return self.config
        self.manager._get_server_config.side_effect = read
        first = asyncio.create_task(self.call())
        self.assertTrue(await asyncio.to_thread(entered.wait, 3))
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(self.call())
        self.assertEqual(len(calls), 1)
        release.set()
        self.assertEqual(await second, {'status': 'success', 'unchanged': True})
        self.assertEqual(len(calls), 2)
        self.untouched()

    async def test_unknown_read_result_and_new_ownership_do_not_write(self):
        self.manager._get_server_config.side_effect = TimeoutError('synthetic read timeout')
        self.assertEqual((await self.call()).status_code, 500)
        self.untouched()
        original = copy.deepcopy(self.data)
        initial = dict(original, user_connections=[])
        with patch.object(panel, 'load_data', side_effect=[initial, original]):
            self.assertEqual((await self.call()).status_code, 409)
        self.untouched()


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
