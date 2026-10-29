"""Reviewer regressions: synthetic JSON, local files and mocked SSH only."""
import asyncio
import copy
import io
import json
import pathlib
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

import app as panel
import peer_lifecycle_lock as interlock
from connection_service import SelfServiceError
import peer_recovery as recovery
from scripts.panel_recovery import restore, CONFIRM, complete_restore, FINISH_CONFIRM
from fastapi import UploadFile
from fastapi.testclient import TestClient


class ReviewReproduction(unittest.IsolatedAsyncioTestCase):
    async def test_orphan_recovery_is_not_a_manual_json_edit(self):
        self.assertTrue(callable(getattr(panel, 'api_orphan_recovery', None)))

    async def test_disaster_restore_has_a_separate_offline_entrypoint(self):
        self.assertTrue((pathlib.Path(panel.__file__).parent / 'scripts/panel_recovery.py').is_file())

    async def test_self_service_preserves_machine_code(self):
        error = SelfServiceError("This connection can't be removed right now because its usage accounting is still being finalized. Please contact your administrator.", status_code=409)
        error.code = 'traffic_finalization_required'
        response = panel._self_service_error_response(error)
        self.assertEqual(json.loads(response.body).get('code'), error.code)

    async def test_detached_worker_exception_is_logged_with_traceback(self):
        entered, release = asyncio.Event(), asyncio.Event()
        @interlock.serialize_peer_lifecycle
        async def worker():
            entered.set()
            await release.wait()
            raise RuntimeError('synthetic-sensitive-value')
        request = asyncio.create_task(worker())
        await entered.wait()
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        with self.assertLogs('peer_lifecycle_lock', level='ERROR') as logs:
            release.set()
            for _ in range(4):
                barrier = asyncio.Event()
                asyncio.get_running_loop().call_soon(barrier.set)
                await barrier.wait()
        self.assertIn('Traceback', '\n'.join(logs.output))
        self.assertNotIn('synthetic-sensitive-value', '\n'.join(logs.output))

    async def test_queued_wait_has_a_bound(self):
        entered, release = asyncio.Event(), asyncio.Event()
        @interlock.serialize_peer_lifecycle
        async def leader():
            entered.set()
            await release.wait()
        @interlock.serialize_peer_lifecycle
        async def follower():
            self.fail('queued work must not start')
        task = asyncio.create_task(leader())
        await entered.wait()
        try:
            with patch.object(interlock, 'QUEUE_WAIT_SECONDS', .02, create=True):
                with self.assertRaisesRegex(Exception, 'peer_lifecycle_busy'):
                    await asyncio.wait_for(follower(), .3)
        finally:
            release.set()
            await task


def fixture():
    return {'servers': [{'uid': 'node-a', 'host': '192.0.2.1', 'username': 'test', 'protocols': {'awg3': {}}}],
            'users': [{'id': 'admin', 'role': 'admin', 'enabled': True, 'traffic_used': 450, 'traffic_total': 710},
                      {'id': 'owner', 'enabled': True, 'traffic_used': 510, 'traffic_total': 910}],
            'user_connections': [{'id': 'orphan', 'user_id': 'missing', 'server_id': 0, 'protocol': 'awg3', 'client_id': 'peer',
                                  'last_bytes': 60, 'traffic_sample_at': 123, 'baseline': {'month': 31}},
                                 {'id': 'other', 'user_id': 'owner', 'server_id': 0, 'protocol': 'awg3__2', 'client_id': 'other-peer', 'last_bytes': 99}],
            'settings': {}}


class OrphanRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / 'data.json'
        recovery.atomic_json(self.path, fixture())
        self.before = self.path.read_bytes()
        self.peers = [{'clientId': 'peer', 'userData': {'dataReceivedBytes': 30, 'dataSentBytes': 31, 'privateKey': 'SYNTHETIC-SECRET'}}]
        self.native = ''
        self.table = '[]'
        self.config = '[Interface]\n'
        self.ssh = Mock()
        def command(text, **kwargs):
            self.assertFalse(panel.DATA_LOCK.locked(), 'DATA_LOCK over SSH')
            if 'clientsTable' in text:
                return self.table, '', 0
            if 'show all peers' in text:
                return self.native, '', 0
            if '/wg0.conf' in text:
                return '', '', 44
            return self.config, '', 0
        self.ssh.run_sudo_command.side_effect = command
        self.stack = __import__('contextlib').ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in [('DATA_FILE', str(self.path)), ('DATA_LOCK', asyncio.Lock())]:
            self.stack.enter_context(patch.object(panel, name, value))
        self.stack.enter_context(patch.object(panel, '_check_admin', return_value=True))
        self.stack.enter_context(patch.object(panel, 'get_current_user', return_value={'id': 'admin', 'role': 'admin'}))
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=self.ssh))
        self.stack.enter_context(patch.object(panel, 'get_protocol_manager', return_value=Mock()))
        self.call = self.stack.enter_context(patch.object(panel, '_manager_call', side_effect=lambda *a: copy.deepcopy(self.peers)))
        interlock.configure(self.path)
        self.addCleanup(interlock.configure, panel.DATA_FILE)
        self.request = SimpleNamespace(headers={}, base_url='http://testserver', cookies={})

    def req(self, mode='repair', op='a' * 32):
        preview = panel.api_orphan_recovery_preview(self.request, 'orphan')
        return panel.OrphanRecoveryRequest(operation_id=op, connection_id='orphan',
            expected_digest=preview['expected_digest'], expected_peer_digest=preview['expected_peer_digest'],
            mode=mode, target_user_id='owner', confirmation={
                'repair': 'RESTORE OWNERSHIP; USAGE IS UNVERIFIED',
                'archive_absent': 'ARCHIVE ABSENT PEER; FINAL USAGE IS UNKNOWN'}[mode])

    def data(self):
        return json.loads(self.path.read_bytes())

    async def test_repair_preserves_usage_lifetime_baselines_and_other_connections(self):
        req = self.req()
        result = await panel.api_orphan_recovery(self.request, req)
        self.assertEqual(result['status'], 'success')
        data = self.data()
        self.assertEqual(data['users'], fixture()['users'])
        self.assertEqual(data['user_connections'][1], fixture()['user_connections'][1])
        conn = data['user_connections'][0]
        self.assertEqual((conn['user_id'], conn['last_bytes'], conn['baseline']), ('owner', 60, {'month': 31}))
        record = json.loads((pathlib.Path(str(self.path) + '.recovery') / (req.operation_id + '.json')).read_bytes())
        self.assertEqual(__import__('base64').b64decode(record['before_base64']), self.before)
        self.assertEqual(record['phase'], 'committed')
        self.assertFalse(record['counters_verified_final'])
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(record['audit']))
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(data['accounting_recoveries']))
        self.assertEqual(data['accounting_recoveries'][0]['observed_counters']['dataSentBytes'], 31)
        self.assertTrue((await panel.api_orphan_recovery(self.request, req))['replayed'])
        self.assertEqual(len(self.data()['accounting_recoveries']), 1)
        self.assertTrue(all(call.args[1] == 'get_clients' for call in self.call.call_args_list))

    async def test_active_peer_cannot_be_emergency_archived(self):
        result = await panel.api_orphan_recovery(self.request, self.req('archive_absent'))
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_absent_awg_peer_archival_keeps_full_original_evidence(self):
        self.peers = []
        result = await panel.api_orphan_recovery(self.request, self.req('archive_absent'))
        self.assertEqual(result['status'], 'success')
        data = self.data()
        self.assertEqual(data['user_connections'], [fixture()['user_connections'][1]])
        self.assertEqual(data['accounting_recoveries'][0]['connection'], fixture()['user_connections'][0])
        self.assertEqual(data['users'], fixture()['users'])
        with self.assertRaisesRegex(Exception, 'finalized'):
            __import__('peer_accounting').require_unowned(data, protocol='awg3', include_archived=True)
        # UID, not the old numeric index, binds the archival guard after reorder.
        data['servers'].insert(0, {'uid': 'other-node'})
        with self.assertRaises(Exception):
            __import__('peer_accounting').require_unowned(data, server_id=1, protocol='awg3', include_archived=True)

    async def test_swallowed_empty_api_does_not_prove_absence(self):
        self.peers = []
        req = self.req('archive_absent')
        self.ssh.run_sudo_command.side_effect = lambda *a, **k: ('', 'unavailable', 1)
        self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_persistent_or_live_peer_blocks_archive_even_when_api_says_absent(self):
        self.peers = []
        req = self.req('archive_absent')
        for table, conf, native in [(' [{"clientId":"peer"}]', '[Interface]\n', ''),
                                     ('[]', '[Interface]\n[Peer]\nPublicKey = peer\n', ''),
                                     ('[]', '[Interface]\n', 'awg0\tpeer\n')]:
            self.table, self.config, self.native = table, conf, native
            self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 409)
            self.assertEqual(self.path.read_bytes(), self.before)

    async def test_commented_or_case_variant_persisted_peer_is_not_treated_as_absent(self):
        self.peers = []
        req = self.req('archive_absent')
        self.config = '[Interface]\n[Peer]\n  publicKEY = peer # retained peer\n'
        self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_confirm_and_origin_are_enforced(self):
        req = self.req()
        bad = req.model_copy(update={'confirmation': 'yes'})
        self.assertEqual((await panel.api_orphan_recovery(self.request, bad)).status_code, 409)
        self.request.headers = {'origin': 'https://other.invalid'}
        self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 403)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_peer_changed_after_preview_is_rejected(self):
        req = self.req()
        self.peers[0]['userData']['dataSentBytes'] += 1
        self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_repair_does_not_attach_an_active_orphan_to_a_blocked_or_expired_user(self):
        for fields in ({'enabled': False}, {'disable_reasons': ['manual']},
                       {'expiration_date': '2000-01-01T00:00:00'}, {'traffic_limit': 500}):
            data = fixture()
            data['users'][1].update(fields)
            recovery.atomic_json(self.path, data)
            before = self.path.read_bytes()
            response = await panel.api_orphan_recovery(self.request, self.req())
            self.assertEqual(response.status_code, 409)
            self.assertEqual(self.path.read_bytes(), before)

    async def test_fresh_server_uid_and_owner_are_checked_after_ssh(self):
        req = self.req()
        def change(*args):
            data = self.data()
            data['servers'][0]['uid'] = 'replaced-node'
            recovery.atomic_json(self.path, data)
            return self.peers
        self.call.side_effect = change
        result = await panel.api_orphan_recovery(self.request, req)
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.data()['user_connections'], fixture()['user_connections'])
        self.assertEqual(self.data()['servers'][0]['uid'], 'replaced-node')

    async def test_snapshot_or_audit_failure_does_not_change_data(self):
        req = self.req()
        with patch.object(recovery, 'atomic_json', side_effect=OSError('synthetic disk failure')):
            self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 503)
        self.assertEqual(self.path.read_bytes(), self.before)

    async def test_data_write_failure_retains_snapshot_and_retries_once(self):
        req = self.req()
        original = recovery.atomic_bytes
        def fail(path, raw):
            if pathlib.Path(path) == self.path:
                raise OSError('synthetic rename failure')
            return original(path, raw)
        with patch.object(recovery, 'atomic_bytes', side_effect=fail):
            self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 503)
        self.assertEqual(self.path.read_bytes(), self.before)
        self.assertTrue(list(pathlib.Path(str(self.path) + '.recovery').glob('*.json')))
        self.assertEqual((await panel.api_orphan_recovery(self.request, req))['status'], 'success')
        self.assertEqual(len(self.data()['accounting_recoveries']), 1)

    async def test_commit_audit_failure_is_not_success_and_retry_does_not_reapply(self):
        req = self.req()
        original = recovery.atomic_json
        def fail(path, data):
            if data.get('phase') == 'committed':
                raise OSError('synthetic final audit failure')
            return original(path, data)
        with patch.object(recovery, 'atomic_json', side_effect=fail):
            self.assertEqual((await panel.api_orphan_recovery(self.request, req)).status_code, 503)
        self.assertEqual((await panel.api_orphan_recovery(self.request, req))['replayed'], True)
        self.assertEqual(len(self.data()['accounting_recoveries']), 1)

    async def test_old_snapshot_cannot_undo_recovery(self):
        old = panel.load_data()
        await panel.api_orphan_recovery(self.request, self.req())
        committed = self.path.read_bytes()
        with self.assertRaisesRegex(recovery.RecoveryError, 'stale_snapshot'):
            panel.save_data(old)
        self.assertEqual(self.path.read_bytes(), committed)

    async def test_cancelled_http_keeps_interlock_and_commits_once(self):
        req = self.req()
        entered, release = threading.Event(), threading.Event()
        def wait(*args):
            entered.set()
            if not release.wait(5):
                raise AssertionError('test barrier timeout')
            return self.peers
        self.call.side_effect = wait
        task = asyncio.create_task(panel.api_orphan_recovery(self.request, req))
        self.assertTrue(await asyncio.to_thread(entered.wait, 5))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        # Same id waits behind the admitted worker, then observes its durable result.
        result = await panel.api_orphan_recovery(self.request, req)
        self.assertTrue(result['replayed'])
        self.assertEqual(len(self.data()['accounting_recoveries']), 1)

    async def test_http_admin_authorization(self):
        client = TestClient(panel.app)
        req = self.req().model_dump()
        with patch.object(panel, '_check_admin', return_value=False):
            self.assertEqual(client.get('/api/recovery/status').status_code, 403)
            self.assertEqual(client.get('/api/recovery/orphans/orphan').status_code, 403)
            self.assertEqual(client.post('/api/recovery/orphans', json=req).status_code, 403)

    async def test_ordinary_restore_retains_linked_counters_and_points_to_offline_recovery(self):
        upload = UploadFile(filename='backup.json', file=io.BytesIO(b'{"users":[],"servers":[]}'))
        response = await panel.api_backup_restore(self.request, upload)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)
        self.assertEqual(json.loads(response.body)['code'], 'traffic_finalization_required')

    async def test_http_ordinary_restore_retry_does_not_overwrite_newer_state(self):
        recovery.atomic_json(self.path, {'users': [], 'servers': []})
        client = TestClient(panel.app)
        content = b'{"users":[],"servers":[],"marker":"restored"}'
        def send():
            return client.post('/api/settings/backup/restore', files={'file': ('backup.json', content, 'application/json')}, data={'operation_id': 'c' * 32})
        first = send()
        self.assertEqual(first.status_code, 200, first.text)
        data = self.data()
        data['marker'] = 'newer'
        panel.save_data(data)
        current = self.path.read_bytes()
        second = send()
        self.assertEqual(second.status_code, 200, second.text)
        self.assertTrue(second.json()['replayed'])
        self.assertEqual(self.path.read_bytes(), current)

    async def test_unfinished_create_journal_cannot_be_dropped_by_restore_or_orphan_repair(self):
        req = self.req()
        operation = {'id': 'create-id', 'identity': ['missing', 'node-a', 'awg3', 'peer-name'],
                     'public': 'peer', 'phase': 'intent', 'private': 'SYNTHETIC'}
        recovery.atomic_json(pathlib.Path(str(self.path) + '.peer-creates.json'), {'create-id': operation})
        response = await panel.api_orphan_recovery(self.request, req)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.path.read_bytes(), self.before)


class OfflineRestore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / 'data.json'
        self.backup = pathlib.Path(self.tmp.name) / 'backup.json'
        data = fixture()
        data['user_connections'][0]['user_id'] = 'owner'
        recovery.atomic_json(self.backup, data)
        recovery.atomic_json(self.path, dict(data, marker='newer'))
        self.before = self.path.read_bytes()

    def run_restore(self, op='b' * 32):
        return restore(self.path, self.backup, op, recovery.file_hash(self.before), CONFIRM)

    def test_running_panel_lease_blocks_restore_without_touching_counters(self):
        with recovery.PanelLease(self.path):
            with self.assertRaisesRegex(recovery.RecoveryError, 'running'):
                self.run_restore()
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_asgi_shutdown_does_not_allow_restore_until_the_runtime_process_exits(self):
        # A closed runtime handle can still have live background SSH threads.
        with recovery.PanelLease(self.path, runtime=True):
            pass
        with self.assertRaisesRegex(recovery.RecoveryError, 'process_still_running'):
            self.run_restore()
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_full_restore_from_corruption_has_exact_rollback_and_idempotency(self):
        self.path.write_bytes(b'{corrupt-original')
        self.before = self.path.read_bytes()
        result = self.run_restore()
        self.assertFalse(result['counters_verified_final'])
        record = json.loads((pathlib.Path(str(self.path) + '.recovery') / ('b' * 32 + '.json')).read_bytes())
        self.assertEqual(__import__('base64').b64decode(record['before_base64']), self.before)
        data = json.loads(self.path.read_bytes())
        expected = json.loads(self.backup.read_bytes())
        self.assertEqual(data['users'], expected['users'])
        self.assertEqual(data['user_connections'], expected['user_connections'])
        data['users'][1]['traffic_used'] += 5
        recovery.atomic_json(self.path, data)
        latest = self.path.read_bytes()
        self.assertTrue(self.run_restore()['replayed'])
        self.assertEqual(self.path.read_bytes(), latest)

    def test_invalid_backup_confirmation_and_newer_state_are_rejected(self):
        with self.assertRaises(recovery.RecoveryError):
            restore(self.path, self.backup, 'b' * 32, recovery.file_hash(self.before), 'yes')
        with self.assertRaises(recovery.RecoveryError):
            restore(self.path, self.backup, 'b' * 32, '0' * 64, CONFIRM)
        self.backup.write_text('{"servers":[],"users":[],"user_connections":[{"id":"orphan"}]}')
        with self.assertRaises(recovery.RecoveryError):
            self.run_restore()
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_crash_before_snapshot_and_before_replace_leave_current_unchanged(self):
        for function in ('atomic_json', 'atomic_bytes'):
            with self.subTest(phase=function):
                with patch.object(recovery, function, side_effect=OSError('synthetic crash')):
                    with self.assertRaises(OSError):
                        self.run_restore()
                self.assertEqual(self.path.read_bytes(), self.before)

    def test_operation_id_cannot_restore_different_content(self):
        self.run_restore()
        self.backup.write_text('{"users":[],"servers":[]}')
        before = self.path.read_bytes()
        with self.assertRaisesRegex(recovery.RecoveryError, 'operation_conflict'):
            self.run_restore()
        self.assertEqual(self.path.read_bytes(), before)

    def test_restored_panel_cannot_start_before_node_reconciliation(self):
        self.run_restore()
        before = self.path.read_bytes()
        with patch.object(panel, 'DATA_FILE', str(self.path)), \
             patch.object(panel, '_panel_lease', None), \
             patch.object(panel, '_start_conn_monitor') as monitor, \
             patch.object(panel, '_start_duckdns_monitor') as dns:
            try:
                with self.assertRaisesRegex(RuntimeError, 'node reconciliation'):
                    asyncio.run(panel.startup())
                monitor.assert_not_called()
                dns.assert_not_called()
            finally:
                asyncio.run(panel.close_panel_lease())
        self.assertEqual(self.path.read_bytes(), before)

    def test_finishing_restore_requires_explicit_confirmation_and_does_not_touch_counters(self):
        self.run_restore()
        before = self.path.read_bytes()
        with self.assertRaises(recovery.RecoveryError):
            complete_restore(self.path, 'b' * 32, 'd' * 32, recovery.file_hash(before), 'yes')
        result = complete_restore(self.path, 'b' * 32, 'd' * 32, recovery.file_hash(before), FINISH_CONFIRM)
        self.assertFalse(result['counters_verified_final'])
        data = json.loads(self.path.read_bytes())
        self.assertNotIn(recovery.DISASTER_HOLD, data)
        self.assertEqual(data['users'], json.loads(before)['users'])
        self.assertEqual(data['user_connections'], json.loads(before)['user_connections'])
        self.assertTrue(complete_restore(self.path, 'b' * 32, 'd' * 32, recovery.file_hash(before), FINISH_CONFIRM)['replayed'])

    def test_pending_create_journal_is_not_silently_replayed_after_restore(self):
        journal = pathlib.Path(str(self.path) + '.peer-creates.json')
        recovery.atomic_json(journal, {'id': {'id': 'id', 'identity': ['owner', 'node-a', 'awg3', 'name'], 'public': 'peer', 'phase': 'intent'}})
        original_journal = journal.read_bytes()
        with self.assertRaisesRegex(recovery.RecoveryError, 'peer_create_recovery_required'):
            self.run_restore()
        self.assertEqual(self.path.read_bytes(), self.before)
        self.assertEqual(journal.read_bytes(), original_journal)

    def test_completed_create_journal_requires_matching_backup_ownership_and_is_snapshotted(self):
        data = json.loads(self.backup.read_bytes())
        data['user_connections'][0]['id'] = 'create-id'
        recovery.atomic_json(self.backup, data)
        journal = pathlib.Path(str(self.path) + '.peer-creates.json')
        recovery.atomic_json(journal, {'id': {'id': 'create-id', 'identity': ['owner', 'node-a', 'awg3', 'name'], 'public': 'peer',
                                            'phase': 'complete', 'endpoint': ['192.0.2.1', 22, 'test'], 'private': 'SYNTHETIC'}})
        before = journal.read_bytes()
        self.run_restore()
        self.assertEqual(journal.read_bytes(), before)
        record = json.loads((pathlib.Path(str(self.path) + '.recovery') / ('b' * 32 + '.json')).read_bytes())
        self.assertEqual(__import__('base64').b64decode(record['peer_creates_snapshot']['base64']), before)


class InterlockBudgets(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        interlock.configure(pathlib.Path(self.tmp.name) / 'data.json')
        self.addCleanup(interlock.configure, panel.DATA_FILE)

    async def test_response_deadline_does_not_release_running_ssh(self):
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []
        @interlock.serialize_peer_lifecycle
        async def slow():
            entered.set()
            await release.wait()
            calls.append('finished')
        @interlock.serialize_peer_lifecycle
        async def next_one():
            calls.append('next')
        with patch.object(interlock, 'RESPONSE_WAIT_SECONDS', .02):
            with self.assertRaisesRegex(interlock.PeerLifecycleBusy, 'still_running'):
                await slow()
        with patch.object(interlock, 'QUEUE_WAIT_SECONDS', .02):
            with self.assertRaisesRegex(interlock.PeerLifecycleBusy, 'busy'):
                await next_one()
        self.assertEqual(calls, [])
        release.set()
        await next_one()
        self.assertEqual(calls, ['finished', 'next'])

    async def test_unknown_ssh_result_fences_admission_across_restart(self):
        calls = []
        @interlock.serialize_peer_lifecycle
        async def unknown():
            interlock.note_ssh_uncertainty()
            return {'status': 'success'}  # Must never be reported as success.
        @interlock.serialize_peer_lifecycle
        async def later():
            calls.append(True)
        with self.assertRaises(interlock.PeerLifecycleUncertain):
            await unknown()
        path = interlock._fence_path
        self.assertTrue(path.is_file())
        interlock.configure(str(path).removesuffix('.lifecycle-uncertain.json'))
        self.assertTrue(interlock.diagnostics()['blocked'])
        with self.assertRaises(interlock.PeerLifecycleUncertain):
            await later()
        self.assertEqual(calls, [])
