import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as panel
from managers.xray_manager import XrayManager
from peer_recovery import RecoveryError


def state():
    return {
        'servers': [dict(uid='node-a', host='192.0.2.1', protocols={
            'xray': {}, 'awg2': {},
        })],
        'users': [dict(id='u', enabled=True, traffic_used=450, traffic_total=700)],
        'user_connections': [
            dict(id=f'xray-link-{n}', user_id='u', server_id=0,
                 protocol='xray', client_id=f'xray-peer-{n}', last_bytes=10)
            for n in range(3)
        ] + [dict(id='awg-link', user_id='u', server_id=0,
                  protocol='awg2', client_id='awg-peer', last_bytes=20)],
    }


class ProtocolUninstallAccountingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.data = state()
        self.saved = []
        self.commits = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_file = Path(self.tmp.name) / 'data.json'
        self.data_file.write_bytes(json.dumps(self.data).encode())
        self.stack = []
        self.addCleanup(lambda: [p.stop() for p in reversed(self.stack)])
        self.patch('_check_admin', lambda request: True)
        self.patch('get_current_user', lambda request: {'id': 'admin', 'role': 'admin'})
        self.patch('load_data', lambda: copy.deepcopy(self.data))
        self.patch('DATA_FILE', str(self.data_file))
        self.patch('save_data', Mock(side_effect=lambda value: self.saved.append(copy.deepcopy(value))))
        self.patch('commit_finalize', Mock(side_effect=self._commit))
        self.patch('srv_warp_ctx', lambda server, protocol: {})
        self.ssh = Mock()
        self.manager = Mock()
        self.patch('get_ssh', Mock(return_value=self.ssh))
        self.patch('get_protocol_manager', Mock(return_value=self.manager))
        self.request = SimpleNamespace(cookies={}, headers={})

    def patch(self, name, value):
        patcher = patch.object(panel, name, value)
        self.stack.append(patcher)
        patcher.start()

    def _commit(self, data_file, operation_id, actor, kind, intent, before, after):
        self.commits.append({'kind': kind, 'before': before, 'after': copy.deepcopy(after)})
        return {'status': 'success', 'operation_id': operation_id, 'replayed': False,
                'counters_verified_final': False}

    async def uninstall(self, **kwargs):
        return await panel.api_uninstall_protocol(
            self.request, 0, panel.ProtocolRequest(protocol='xray'), **kwargs)

    def body(self, result):
        return json.loads(result.body) if hasattr(result, 'body') else result

    async def test_xray_uninstall_archives_only_verified_absent_rows(self):
        with patch.object(panel, '_probe_blocking_peer', return_value=(None, True)) as probe:
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(self.body(result), {'status': 'success', 'archived': 3})
        self.assertEqual(probe.call_count, 3)
        self.manager.remove_container.assert_called_once_with()
        self.assertEqual(len(self.commits), 1)
        self.assertEqual(self.commits[0]['kind'], 'protocol_archive_uninstall')
        after = self.commits[0]['after']
        self.assertNotIn('xray', after['servers'][0]['protocols'])
        self.assertIn('awg2', after['servers'][0]['protocols'])
        self.assertEqual([c['id'] for c in after['user_connections']], ['awg-link'])
        self.assertEqual(len(after['accounting_recoveries']), 3)
        self.assertTrue(all(r['operation'] == 'protocol_uninstall_absent'
                            and r['quiescent'] and not r['counters_verified_final']
                            for r in after['accounting_recoveries']))
        self.assertEqual(self.saved, [])

    async def test_xray_uninstall_rejects_active_blocking_peer(self):
        with patch.object(panel, '_probe_blocking_peer', return_value=(12, False)):
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.body(result)['code'], 'blocked_peer_still_active')
        self.assertEqual(self.body(result)['blocking'][0]['connection_id'], 'xray-link-0')
        self.manager.remove_container.assert_not_called()
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_xray_uninstall_aborts_when_blocking_rows_change_after_probe(self):
        def probe(server, conn):
            self.data['user_connections'][0]['id'] = 'replacement'
            return None, True

        with patch.object(panel, '_probe_blocking_peer', side_effect=probe):
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.body(result)['code'], 'traffic_finalization_required')
        self.manager.remove_container.assert_not_called()
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_xray_probe_rejects_unreadable_live_config(self):
        ssh = Mock()
        ssh.run_sudo_command.return_value = ('', 'connection lost', -1)
        manager = XrayManager(ssh)
        conn = self.data['user_connections'][0]
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager):
            with self.assertRaises(RecoveryError):
                await asyncio.to_thread(
                    panel._probe_blocking_peer, self.data['servers'][0], conn)
        ssh.disconnect.assert_called_once_with()

    async def test_xray_remove_failure_preserves_accounting_and_metadata(self):
        self.ssh.run_sudo_command.return_value = ('', 'connection lost', -1)
        manager = XrayManager(self.ssh)
        with patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, '_probe_blocking_peer', return_value=(None, True)):
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(result.status_code, 500)
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])
        self.assertIn('xray', self.data['servers'][0]['protocols'])
        self.assertEqual(len(self.data['user_connections']), 4)

    async def test_archive_option_does_not_bypass_other_protocol_guards(self):
        with patch.object(panel, '_probe_blocking_peer') as probe:
            result = await panel.api_uninstall_protocol(
                self.request, 0, panel.ProtocolRequest(protocol='awg2'),
                archive_blocking=True)

        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.body(result)['code'], 'traffic_finalization_required')
        probe.assert_not_called()
        self.ssh.connect.assert_not_called()
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_xray_uninstall_does_not_apply_counter_older_than_live_baseline(self):
        self.data['user_connections'] = [
            self.data['user_connections'][0], self.data['user_connections'][-1]]

        def probe(server, conn):
            if conn['protocol'] == 'xray':
                self.data['user_connections'][0]['last_bytes'] = 30
                self.data['users'][0]['traffic_total'] = 720
            return 25, True

        with patch.object(panel, '_probe_blocking_peer', side_effect=probe):
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(self.body(result)['archived'], 1)
        after = self.commits[0]['after']
        self.assertEqual(after['users'][0]['traffic_total'], 720)
        tombstone = after['accounting_recoveries'][0]
        self.assertIsNone(tombstone['observed_bytes'])
        self.assertEqual(tombstone['committed_delta'], 0)

    async def test_xray_archive_commit_holds_state_file_lock(self):
        class TrackingLock:
            def __init__(self):
                self.active = False
                self.entered = 0

            def __enter__(self):
                self.active = True
                self.entered += 1

            def __exit__(self, *args):
                self.active = False

        lock = TrackingLock()
        def commit(*args):
            self.assertTrue(lock.active, 'commit must run under STATE_FILE_LOCK')
            return self._commit(*args)

        with patch.object(panel, 'STATE_FILE_LOCK', lock), \
             patch.object(panel, 'commit_finalize', Mock(side_effect=commit)), \
             patch.object(panel, '_probe_blocking_peer', return_value=(None, True)):
            result = await self.uninstall(archive_blocking=True)

        self.assertEqual(self.body(result)['archived'], 3)
        self.assertEqual(lock.entered, 1)
        self.assertFalse(lock.active)


if __name__ == '__main__':
    unittest.main()
