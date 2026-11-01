"""Deleting a server must not be permanently blocked by stale accounting rows.

The guard stays fail-stop by default; an admin may explicitly archive leftover
rows only when the live peer is verified stopped or absent.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import app as panel
from peer_recovery import RecoveryError


def state(connections=None):
    return {
        'servers': [dict(uid='node-a', name='a', host='192.0.2.1', protocols={'awg3': {}})],
        'users': [dict(id='u', enabled=True, traffic_used=450, traffic_total=700)],
        'user_connections': connections if connections is not None else [
            dict(id='link', user_id='u', server_id=0, protocol='awg3',
                 client_id='peer', last_bytes=10),
        ],
    }


class ServerDeleteAccountingTests(unittest.IsolatedAsyncioTestCase):
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
        self.patch('load_data', lambda: copy.deepcopy(self.data))
        self.patch('get_current_user', lambda request: {'id': 'admin', 'role': 'admin'})
        self.patch('DATA_FILE', str(self.data_file))
        self.patch('save_data', Mock(side_effect=lambda value: self.saved.append(copy.deepcopy(value))))
        self.patch('commit_finalize', Mock(side_effect=self._commit))
        self.patch('_finish_locked_worker', AsyncMock())
        self.patch('drop_ssh', Mock())
        self.exit = Mock()
        self.exit.detach_entries_for_exit = AsyncMock(return_value=[])
        self.exit.forget_entry_peers = AsyncMock(return_value=[])
        self.patch('exit_link_svc', self.exit)
        self.request = SimpleNamespace(cookies={}, headers={})

    def patch(self, name, value):
        p = patch.object(panel, name, value)
        self.stack.append(p)
        p.start()

    def _commit(self, data_file, operation_id, actor, kind, intent, before, after):
        self.commits.append({'kind': kind, 'before': before, 'after': copy.deepcopy(after)})
        return {'status': 'success', 'operation_id': operation_id, 'replayed': False,
                'counters_verified_final': False}

    async def delete(self, **kwargs):
        return await panel.api_delete_server(self.request, 0, server_uid='node-a', **kwargs)

    def status(self, result):
        return result.status_code if hasattr(result, 'status_code') else 200

    def body(self, result):
        return json.loads(result.body) if hasattr(result, 'body') else result

    async def test_delete_without_archive_names_the_blocking_rows(self):
        with patch.object(panel, 'get_ssh', side_effect=AssertionError('SSH forbidden')):
            result = await self.delete()
        self.assertEqual(self.status(result), 409)
        payload = self.body(result)
        self.assertEqual(payload['code'], 'traffic_finalization_required')
        self.assertEqual(payload['blocking'], [{
            'connection_id': 'link', 'user_id': 'u',
            'protocol': 'awg3', 'client_id': 'peer'}])
        self.assertEqual(self.saved, [])
        self.assertEqual(self.data['servers'][0]['uid'], 'node-a')

    async def test_archive_rejects_a_peer_that_is_still_active(self):
        with patch.object(panel, '_probe_blocking_peer', return_value=(12, False)):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 409)
        self.assertEqual(self.body(result)['code'], 'blocked_peer_still_active')
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_archive_absent_peer_commits_tombstone_and_removes_server(self):
        with patch.object(panel, '_probe_blocking_peer', return_value=(None, True)):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 200)
        self.assertEqual(self.body(result), {'status': 'success', 'archived': 1})
        self.assertEqual(len(self.commits), 1)
        after = self.commits[0]['after']
        self.assertEqual(after['servers'], [])
        self.assertEqual(after['user_connections'], [])
        tombstone = after['accounting_recoveries'][0]
        self.assertEqual(tombstone['operation'], 'archive_blocking_absent')
        self.assertTrue(tombstone['quiescent'])
        self.assertFalse(tombstone['counters_verified_final'])
        self.assertEqual(tombstone['scope']['server_uid'], 'node-a')
        self.assertEqual(self.commits[0]['kind'], 'server_archive_delete')
        self.exit.detach_entries_for_exit.assert_not_called()

    async def test_archive_disabled_peer_commits_observed_counters(self):
        with patch.object(panel, '_probe_blocking_peer', return_value=(25, True)):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 200)
        after = self.commits[0]['after']
        self.assertEqual(after['users'][0]['traffic_total'], 715)  # 25 - baseline 10
        tombstone = after['accounting_recoveries'][0]
        self.assertEqual(tombstone['observed_bytes'], 25)
        self.assertEqual(tombstone['committed_delta'], 15)
        self.assertFalse(tombstone['counters_verified_final'])

    async def test_archive_aborts_when_ownership_changes_after_the_probe(self):
        def probe(server, conn):
            self.data['user_connections'][0]['id'] = 'replaced'
            return None, True
        with patch.object(panel, '_probe_blocking_peer', side_effect=probe):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 409)
        payload = self.body(result)
        self.assertEqual(payload['code'], 'traffic_finalization_required')
        self.assertEqual(payload['blocking'][0]['connection_id'], 'replaced')
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_non_admin_cannot_archive(self):
        self.patch('_check_admin', lambda request: False)
        result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 403)
        self.assertEqual(self.commits, [])

    async def test_archive_without_blockers_uses_the_plain_delete_path(self):
        self.data['user_connections'] = []
        with patch.object(panel, '_probe_blocking_peer', side_effect=AssertionError('no probe')):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 200)
        self.assertEqual(self.body(result), {'status': 'success'})
        self.assertEqual(self.commits, [])
        self.assertEqual(len(self.saved), 1)
        self.assertEqual(self.saved[0]['servers'], [])

    async def test_row_appearing_during_plain_delete_is_not_dropped(self):
        self.data['user_connections'] = []

        async def forget(server):
            self.data['user_connections'].append(dict(
                id='late', user_id='u', server_id=0, protocol='awg3',
                client_id='peer', last_bytes=0))
            return []

        self.exit.forget_entry_peers = AsyncMock(side_effect=forget)
        result = await self.delete()
        self.assertEqual(self.status(result), 409)
        self.assertEqual(self.body(result)['code'], 'traffic_finalization_required')
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])

    async def test_row_appearing_before_commit_is_not_dropped_silently(self):
        def probe(server, conn):
            self.data['user_connections'].append(dict(
                id='late', user_id='u', server_id=0, protocol='awg3',
                client_id='peer-two', last_bytes=0))
            return None, True

        with patch.object(panel, '_probe_blocking_peer', side_effect=probe):
            result = await self.delete(archive_blocking=True)
        self.assertEqual(self.status(result), 409)
        payload = self.body(result)
        self.assertEqual(payload['code'], 'traffic_finalization_required')
        self.assertEqual([b['connection_id'] for b in payload['blocking']], ['link', 'late'])
        self.assertEqual(self.commits, [])
        self.assertEqual(self.saved, [])


class BlockingPeerProbeTests(unittest.TestCase):
    def probe(self, clients):
        ssh = Mock()
        manager = Mock()
        with patch.object(panel, 'get_ssh', return_value=ssh), \
             patch.object(panel, 'get_protocol_manager', return_value=manager), \
             patch.object(panel, '_manager_call', return_value=clients):
            return panel._probe_blocking_peer({'uid': 'node-a'}, {'protocol': 'awg3',
                                                                 'client_id': 'peer'})

    def test_absent_peer_is_quiescent(self):
        self.assertEqual(self.probe([]), (None, True))

    def test_enabled_peer_is_not_quiescent(self):
        clients = [{'clientId': 'peer', 'userData': {'enabled': True,
                                                     'dataReceivedBytes': 3,
                                                     'dataSentBytes': 4}}]
        self.assertEqual(self.probe(clients), (7, False))

    def test_disabled_peer_is_quiescent(self):
        clients = [{'clientId': 'peer', 'userData': {'enabled': False,
                                                     'dataReceivedBytes': 3,
                                                     'dataSentBytes': 4}}]
        self.assertEqual(self.probe(clients), (7, True))

    def test_unknown_counter_with_disabled_peer_is_quiescent(self):
        clients = [{'clientId': 'peer', 'userData': {'enabled': False}}]
        self.assertEqual(self.probe(clients), (None, True))

    def test_incomplete_peer_list_is_an_error(self):
        with self.assertRaises(RecoveryError):
            self.probe(None)

    def test_ambiguous_peer_identity_is_an_error(self):
        clients = [{'clientId': 'peer'}, {'clientId': 'peer'}]
        with self.assertRaises(RecoveryError):
            self.probe(clients)


if __name__ == '__main__':
    unittest.main()
