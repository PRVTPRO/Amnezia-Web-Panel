"""Deterministic admin endpoint tests with remote state, no real SSH."""
import asyncio
import copy
import json
import tempfile
import threading
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as panel
from peer_create import PeerCreateService, access_signature
from managers.awg_manager import AWGManager, generate_wg_keypair


class Remote:
    def __init__(self):
        self.peers = {}
        self.prepares = self.activations = 0
        self.entered, self.release = threading.Event(), threading.Event()
        self.release.set()
        self.activation_entered, self.activation_release = threading.Event(), threading.Event()
        self.activation_release.set()
        self.timeout = False
        self.lock = threading.Lock()

    def prepare_client(self, proto, op_id, name, private, public, host, port, public_port=None):
        self.entered.set()
        if not self.release.wait(5):
            raise TimeoutError('test barrier')
        with self.lock:
            self.prepares += 1
            if public in self.peers:
                assert self.peers[public]['operation'] == op_id
            else:
                self.peers[public] = dict(operation=op_id, active=False)
        if self.timeout:
            self.timeout = False
            raise TimeoutError('remote write succeeded, response lost')
        return dict(client_id=public, config='synthetic config')

    def add_client(self, proto, name, host, port, public_port=None):
        # Original unsafe path, so these tests expose the upstream defect.
        self.entered.set()
        assert self.release.wait(5)
        _, public = generate_wg_keypair()
        self.peers[public] = dict(active=True)
        return dict(client_id=public, config='synthetic config')

    def peer_is_active(self, proto, key):
        return self.peers[key]['active']

    def toggle_client(self, proto, key, enabled):
        if enabled:
            self.activation_entered.set()
            assert self.activation_release.wait(5)
            self.activations += 1
        self.peers[key]['active'] = enabled

    def get_client_config(self, *args, **kwargs):
        return 'synthetic config'


class AdminCreateLifecycle(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'operations.json'
        self.data = dict(users=[dict(id='u', enabled=True, access_revision=1)],
                        servers=[dict(uid='node', host='192.0.2.1', protocols={'awg3': {}})],
                        user_connections=[])
        self.remote = Remote()
        self.fail_save = False
        def save(data):
            if self.fail_save:
                raise OSError('isolated disk failure')
            self.data = copy.deepcopy(data)
        self.save = save
        self.service = PeerCreateService(path=lambda: str(self.path),
            load_data=lambda: copy.deepcopy(self.data), save_data=save, data_lock=asyncio.Lock(),
            get_ssh=lambda server: Mock(), get_manager=lambda ssh, proto: self.remote,
            public_endpoint=lambda server, proto: (server['host'], None))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name,value in (
            ('peer_creates', self.service), ('_check_admin', lambda request: True),
            ('load_data', lambda: copy.deepcopy(self.data)), ('save_data', save),
            ('get_ssh', lambda server: Mock()), ('get_protocol_manager', lambda ssh, proto: self.remote),
            ('protocol_public_endpoint', lambda server, proto: (server['host'], None)),
            ('config_payloads', lambda *args: {})):
            self.stack.enter_context(patch.object(panel, name, value, create=True))
        self.request = SimpleNamespace(cookies={})
        self.op_id = str(uuid.uuid4())

    async def create(self, **changes):
        req = SimpleNamespace(**(dict(server_id=0, protocol='awg3', name='device',
                                     client_id=None, operation_id=self.op_id) | changes))
        return await panel.api_add_user_connection(self.request, 'u', req)

    async def wait_for(self, event):
        self.assertTrue(await asyncio.to_thread(event.wait, 5), 'deterministic barrier timed out')

    def assert_inactive(self):
        self.assertFalse(any(peer['active'] for peer in self.remote.peers.values()))

    async def test_disabled_user_never_creates_active_peer(self):
        self.data['users'][0]['enabled'] = False
        result = await self.create()
        self.assertEqual(self.remote.peers, {})
        self.assertEqual(result.status_code, 409)

    async def test_journal_is_durable_before_any_remote_action(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        try:
            operation = json.loads(self.path.read_text())[self.op_id]
            self.assertEqual(operation['phase'], 'intent')
            self.assertTrue(operation['public'])
            self.assertEqual(self.data['user_connections'], [])
        finally:
            self.remote.release.set()
        self.assertEqual((await task)['status'], 'success')

    async def test_save_failure_leaves_only_inactive_reservation_then_recovers(self):
        self.fail_save = True
        result = await self.create()
        self.assert_inactive()
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.data['user_connections'], [])
        self.assertEqual(len(self.remote.peers), 1)
        self.fail_save = False
        self.assertEqual((await self.create())['status'], 'success')
        self.assertEqual(len(self.remote.peers), 1)
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_timeout_after_remote_write_uses_same_operation_and_keypair(self):
        self.remote.timeout = True
        result = await self.create()
        self.assert_inactive()
        self.assertEqual(result.status_code, 503)
        key = next(iter(self.remote.peers))
        self.assertEqual((await self.create())['status'], 'success')
        self.assertEqual(list(self.remote.peers), [key])
        self.assertEqual(self.data['user_connections'][0]['client_id'], key)

    async def test_disable_during_prepare_retains_link_without_activation(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        self.data['users'][0].update(enabled=False, access_revision=2, disable_reasons=['manual'])
        self.remote.release.set()
        self.assertEqual((await task).status_code, 409)
        self.assert_inactive()
        self.assertEqual(self.remote.activations, 0)
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_disable_while_activation_in_flight_is_reconciled(self):
        self.remote.activation_release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.activation_entered)
        self.assertEqual(len(self.data['user_connections']), 1, 'owner must precede activation')
        self.data['users'][0].update(enabled=False, access_revision=2)
        self.remote.activation_release.set()
        self.assertEqual((await task).status_code, 409)
        self.assert_inactive()

    async def test_concurrent_same_request_is_coalesced(self):
        first,second = await asyncio.gather(self.create(), self.create())
        self.assertEqual(first['status'], 'success')
        self.assertEqual(second['status'], 'success')
        self.assertEqual(self.remote.prepares, 1)
        self.assertEqual(len(self.remote.peers), 1)
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_distinct_concurrent_operations_merge_current_inventory(self):
        results = await asyncio.gather(self.create(), self.create(name='second', operation_id=str(uuid.uuid4())))
        self.assertTrue(all(result['status'] == 'success' for result in results))
        self.assertEqual(len(self.remote.peers), 2)
        self.assertEqual(len(self.data['user_connections']), 2)

    async def test_cancelled_http_does_not_abandon_operation(self):
        self.remote.release.clear()
        request = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.data['users'][0].update(enabled=False, access_revision=2)
        pending = list(self.service.tasks.values())
        self.remote.release.set()
        await asyncio.gather(*pending, return_exceptions=True)
        self.assert_inactive()
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_replay_success_never_undoes_later_manual_disable(self):
        self.assertEqual((await self.create())['status'], 'success')
        key = next(iter(self.remote.peers))
        self.data['users'][0].update(enabled=False, access_revision=2)
        self.remote.peers[key]['active'] = False
        activations = self.remote.activations
        self.assertEqual((await self.create())['status'], 'success')
        self.assert_inactive()
        self.assertEqual(self.remote.activations, activations)

    async def test_server_reorder_uses_uid_not_stale_index(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        self.data['servers'].insert(0, dict(uid='other', host='192.0.2.2', protocols={}))
        self.remote.release.set()
        self.assertEqual((await task)['status'], 'success')
        self.assertEqual(self.data['user_connections'][0]['server_id'], 1)

    async def test_deleted_user_during_prepare_never_activates(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        self.data['users'] = []
        self.remote.release.set()
        self.assertEqual((await task).status_code, 409)
        self.assert_inactive()
        self.assertTrue(self.path.exists())

    async def test_journal_recreated_service_recovers_same_peer(self):
        self.fail_save = True
        await self.create()
        self.assert_inactive()
        key = next(iter(self.remote.peers))
        self.fail_save = False
        service = PeerCreateService(path=lambda: str(self.path),
            load_data=lambda: copy.deepcopy(self.data), save_data=self.save, data_lock=asyncio.Lock(),
            get_ssh=lambda server: Mock(), get_manager=lambda ssh, proto: self.remote,
            public_endpoint=lambda server, proto: (server['host'], None))
        await service.recover()
        self.assertEqual(list(self.remote.peers), [key])
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_unrecoverable_head_entries_do_not_starve_later_operations(self):
        for index in range(5):
            private, public = generate_wg_keypair()
            op_id = str(uuid.uuid4())
            self.service.journal.put(dict(id=op_id,
                identity=['u' if index == 4 else 'deleted-user-' + str(index),
                          'node', 'awg3', 'device-' + str(index)],
                private=private, public=public, access=access_signature(self.data['users'][0]),
                phase='intent', endpoint=['192.0.2.1', 22, None]))
        await self.service.recover(limit=4)
        self.assertEqual(self.remote.peers, {})
        await self.service.recover(limit=4)
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual(len(self.remote.peers), 1)

    async def test_background_recovery_does_not_block_tick_or_duplicate_tasks(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def slow_recovery():
            entered.set()
            await release.wait()
        with patch.object(self.service, 'recover', side_effect=slow_recovery):
            task = self.service.schedule_recovery()
            await entered.wait()
            self.assertIs(self.service.schedule_recovery(), task)
            self.assertFalse(task.done())
            release.set()
            await task

    async def test_bad_journal_does_not_abort_unrelated_background_work(self):
        self.path.write_text('not-json', encoding='utf-8')
        with self.assertLogs('peer_create', level='WARNING') as logs:
            await self.service.schedule_recovery()
        self.assertIn('journal retained', logs.output[0])
        self.assertEqual(self.remote.peers, {})

    async def test_operation_id_cannot_be_rebound(self):
        await self.create()
        result = await self.create(name='foreign-intent')
        self.assertEqual(result.status_code, 409)
        self.assertEqual(len(self.remote.peers), 1)

    async def test_activation_timeout_keeps_durable_owner_and_recovers_disabled(self):
        original = self.remote.toggle_client
        def uncertain(proto, key, enabled):
            original(proto, key, enabled)
            if enabled:
                raise TimeoutError('activation succeeded, response lost')
        self.remote.toggle_client = uncertain
        self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual(json.loads(self.path.read_text())[self.op_id]['phase'], 'activating')
        self.data['users'][0].update(enabled=False, access_revision=2)
        self.remote.toggle_client = original
        self.assertEqual((await self.create()).status_code, 409)
        self.assert_inactive()
        self.assertEqual(len(self.remote.peers), 1)

    async def test_completed_journal_write_failure_never_loses_owner(self):
        put = self.service.journal.put
        def fail_completion(operation):
            if operation['phase'] == 'complete':
                raise OSError('completion journal failure')
            return put(operation)
        with patch.object(self.service.journal, 'put', side_effect=fail_completion):
            self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual((await self.create())['status'], 'success')
        self.assertEqual(len(self.remote.peers), 1)
        self.assertEqual(self.remote.activations, 1)

    async def test_journal_failure_before_ssh_has_no_remote_side_effects(self):
        with patch.object(self.service.journal, 'put', side_effect=OSError('journal unavailable')):
            result = await self.create()
        self.assertGreaterEqual(result.status_code, 500)
        self.assertEqual(self.remote.peers, {})

    async def test_nonadmin_never_writes_journal_or_contacts_ssh(self):
        with patch.object(panel, '_check_admin', return_value=False):
            self.assertEqual((await self.create()).status_code, 403)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.remote.peers, {})

    async def test_endpoint_changed_before_prepare_completes_stays_inactive(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        self.data['servers'][0]['host'] = '192.0.2.2'
        self.remote.release.set()
        self.assertEqual((await task).status_code, 409)
        self.assert_inactive()

    async def test_ssh_port_change_is_part_of_endpoint_identity(self):
        self.remote.release.clear()
        task = asyncio.create_task(self.create())
        await self.wait_for(self.remote.entered)
        self.data['servers'][0]['ssh_port'] = 2222
        self.remote.release.set()
        self.assertEqual((await task).status_code, 409)
        self.assert_inactive()

    async def test_expired_and_quota_blocked_users_fail_before_remote_action(self):
        for fields in ({'expiration_date': '2020-01-01T00:00:00'},
                       {'traffic_limit': 10, 'traffic_used': 10},
                       {'disable_reasons': ['manual']}):
            with self.subTest(fields=fields):
                self.data['users'][0] = dict(id='u', enabled=True, access_revision=1, **fields)
                self.assertEqual((await self.create()).status_code, 409)
                self.assertEqual(self.remote.peers, {})

    async def test_negative_server_and_unknown_uid_fail_before_ssh(self):
        self.assertEqual((await self.create(server_id=-1)).status_code, 404)
        self.data['servers'][0].pop('uid')
        self.assertEqual((await self.create()).status_code, 409)
        self.assertEqual(self.remote.peers, {})


class PreparedAdapter(unittest.TestCase):
    def setUp(self):
        self.ssh = Mock(host='synthetic-node')
        self.manager = AWGManager(self.ssh)
        self.clients = []
        self.manager._get_clients_table = lambda proto: copy.deepcopy(self.clients)
        def save(proto, clients):
            self.clients = copy.deepcopy(clients)
        self.manager._save_clients_table = save
        self.manager._parse_peers_from_config = lambda proto: {}
        self.manager.peer_is_active = lambda proto,key: False
        self.manager._get_next_ip = lambda proto: '10.0.0.2'
        self.manager._get_client_ipv6 = lambda *args: ''
        self.manager._get_server_psk = lambda proto: 'synthetic-psk'
        self.manager.get_client_config = lambda *args,**kwargs: 'synthetic config'
        self.private,self.public = generate_wg_keypair()
        self.op_id = str(uuid.uuid4())

    def prepare(self):
        return self.manager.prepare_client('awg3', self.op_id, 'device',
            self.private,self.public,'192.0.2.1','51820')

    def test_prepare_and_retry_never_install_or_sync_live_peer(self):
        self.assertEqual(self.prepare()['client_id'], self.public)
        self.assertEqual(self.prepare()['client_id'], self.public)
        self.assertEqual(len(self.clients), 1)
        self.assertFalse(self.clients[0]['userData']['enabled'])
        self.ssh.run_sudo_command.assert_not_called()
        self.ssh.upload_file.assert_not_called()

    def test_prepare_rejects_foreign_operation_ownership(self):
        self.prepare()
        self.clients[0]['userData']['panelCreateOperation'] = str(uuid.uuid4())
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.prepare()

    def test_prepare_rejects_wrong_keypair_before_remote_mutation(self):
        self.private,_ = generate_wg_keypair()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(self.clients, [])



class NativeTelemtFixture:
    """Real manager logic with a persistent/native-API boundary, not legacy add_client."""
    def __init__(self, protocol='telemt'):
        from managers.telemt_manager import TelemtManager
        self.users = {'seed': {'secret': '01' * 16, 'enabled': True, 'in_runtime': True}}
        self.creates = self.enables = 0
        self.timeout_prepare = self.timeout_activate = False
        self.entered, self.release = threading.Event(), threading.Event()
        self.release.set()
        self.old_api = False
        self.manager = TelemtManager(Mock(), protocol)
        self.manager._get_server_config = self.config
        self.manager._lifecycle_api = self.api
        self.manager._api_request = lambda *args, **kwargs: {'ok': True, 'data': self.api('GET', '/v1/users')}
        prepare, activate = self.manager.prepare_client, self.manager.set_prepared_active
        def prepared(*args, **kwargs):
            self.entered.set()
            assert self.release.wait(5)
            value = prepare(*args, **kwargs)
            if self.timeout_prepare:
                self.timeout_prepare = False
                raise TimeoutError('synthetic reply loss')
            return value
        def activated(*args, **kwargs):
            value = activate(*args, **kwargs)
            if self.timeout_activate and args[-1]:
                self.timeout_activate = False
                raise TimeoutError('synthetic activation reply loss')
            return value
        self.manager.prepare_client, self.manager.set_prepared_active = prepared, activated

    def config(self):
        rows = ['[censorship]', 'tls_emulation = true', 'tls_domain = "example.com"', '[access.users]']
        rows += [key + ' = "' + value['secret'] + '"' for key, value in self.users.items()]
        rows += ['[access.user_enabled]']
        rows += [key + ' = false' for key, value in self.users.items() if not value['enabled']]
        return '\n'.join(rows) + '\n'

    def api(self, method, path, data=None):
        if path == '/v1/health':
            return {'read_only': False}
        if method == 'GET':
            return [dict(username=k, **({} if self.old_api else {'enabled': v['enabled'], 'in_runtime': v['in_runtime']}))
                    for k, v in self.users.items()]
        if method == 'POST':
            key = data['username']
            assert key not in self.users and data['enabled'] is False
            self.users[key] = dict(secret=data['secret'], enabled=False, in_runtime=True)
            self.creates += 1
            return {'user': {'username': key, 'enabled': False}, 'secret': data['secret']}
        key = path.rsplit('/', 1)[1]
        assert method == 'PATCH' and key in self.users and set(data) == {'enabled'}
        self.users[key]['enabled'] = data['enabled']
        self.enables += int(data['enabled'])
        return {'username': key, 'enabled': data['enabled'], 'in_runtime': True}


class TelemtCreateLifecycle(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await AdminCreateLifecycle.asyncSetUp(self)
        self.data['servers'][0]['protocols'] = {'telemt': {'installed': True, 'port': '443'},
                                               'telemt__2': {'installed': True, 'port': '8443'}}
        self.native = NativeTelemtFixture()
        self.other = NativeTelemtFixture('telemt__2')
        self.service.get_manager = lambda ssh, protocol: (self.other if protocol == 'telemt__2' else self.native).manager
        self.stack.enter_context(patch.object(panel, 'get_protocol_manager', self.service.get_manager))
        panel._CREATE_CAPABILITIES_CACHE.clear()

    async def create(self, **changes):
        req = SimpleNamespace(**(dict(server_id=0, server_uid='node', protocol='telemt', name='device',
                                     client_id=None, operation_id=self.op_id) | changes))
        return await panel.api_add_user_connection(self.request, 'u', req)

    def restarted(self):
        return PeerCreateService(path=lambda: str(self.path), load_data=lambda: copy.deepcopy(self.data),
            save_data=self.save, data_lock=asyncio.Lock(), get_ssh=lambda server: Mock(),
            get_manager=self.service.get_manager, public_endpoint=lambda server, proto: (server['host'], None))

    async def test_create_replay_and_faketls_link_use_one_secret(self):
        first, second = await self.create(), await self.create()
        self.assertEqual(first, second)
        operation = self.service.journal.read()[self.op_id]
        self.assertEqual(operation['public'], 'pc_' + uuid.UUID(self.op_id).hex)
        self.assertIn('secret=ee' + operation['private'] + '6578616d706c652e636f6d', first['config'])
        self.assertEqual((self.native.creates, self.native.enables), (1, 1))
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    async def test_timeout_after_preparation_restarts_without_regeneration(self):
        self.native.timeout_prepare = True
        self.assertEqual((await self.create()).status_code, 503)
        old = self.service.journal.read()[self.op_id]
        self.assertFalse(self.native.users[old['public']]['enabled'])
        await self.restarted().recover()
        self.assertEqual(self.service.journal.read()[self.op_id]['private'], old['private'])
        self.assertEqual(self.native.creates, 1)
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_crash_before_owner_save_leaves_disabled_credential(self):
        self.fail_save = True
        self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(self.data['user_connections'], [])
        operation = self.service.journal.read()[self.op_id]
        self.assertFalse(self.native.users[operation['public']]['enabled'])
        self.fail_save = False
        await self.restarted().recover()
        self.assertEqual(self.native.creates, 1)

    async def test_crash_after_owner_save_recovers_one_link(self):
        put = self.service.journal.put
        def failed(operation):
            if operation['phase'] == 'activating':
                raise OSError('synthetic crash after owner commit')
            return put(operation)
        with patch.object(self.service.journal, 'put', side_effect=failed):
            self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual(self.native.enables, 0)
        await self.restarted().recover()
        self.assertEqual(len(self.data['user_connections']), 1)
        self.assertEqual(self.native.creates, 1)

    async def test_crash_after_activation_keeps_owner_and_does_not_activate_twice(self):
        self.native.timeout_activate = True
        self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(len(self.data['user_connections']), 1)
        await self.restarted().recover()
        self.assertEqual((self.native.creates, self.native.enables), (1, 1))

    async def test_concurrent_same_operation_is_one_credential(self):
        values = await asyncio.gather(self.create(), self.create())
        self.assertTrue(all(v['status'] == 'success' for v in values))
        self.assertEqual(self.native.creates, 1)
        self.assertEqual(len(self.data['user_connections']), 1)

    async def test_expected_uid_mismatch_and_reorder(self):
        self.assertEqual((await self.create(server_uid='wrong')).status_code, 409)
        self.assertEqual(self.native.creates, 0)
        self.native.release.clear()
        task = asyncio.create_task(self.create())
        self.assertTrue(await asyncio.to_thread(self.native.entered.wait, 5))
        self.data['servers'].insert(0, dict(uid='other', host='192.0.2.9', protocols={}))
        self.native.release.set()
        self.assertEqual((await task)['status'], 'success')
        self.assertEqual(self.data['user_connections'][0]['server_id'], 1)

    async def test_two_instances_do_not_share_credential_or_owner(self):
        await self.create()
        await self.create(protocol='telemt__2', operation_id=str(uuid.uuid4()))
        links = self.data['user_connections']
        self.assertEqual({c['protocol'] for c in links}, {'telemt', 'telemt__2'})
        self.assertEqual(len({c['client_id'] for c in links}), 2)
        self.assertEqual((self.native.creates, self.other.creates), (1, 1))

    async def test_manual_block_expiration_and_explicit_reenable_keep_secret(self):
        self.data['users'][0]['expiration_date'] = '2000-01-01'
        self.assertEqual((await self.create()).status_code, 409)
        self.assertEqual(self.native.creates, 0)
        self.data['users'][0].pop('expiration_date')
        self.native.release.clear()
        task = asyncio.create_task(self.create())
        self.assertTrue(await asyncio.to_thread(self.native.entered.wait, 5))
        self.data['users'][0].update(enabled=False, access_revision=2)
        self.native.release.set()
        self.assertEqual((await task).status_code, 409)
        operation = self.service.journal.read()[self.op_id]
        key, secret = operation['public'], operation['private']
        self.assertFalse(self.native.users[key]['enabled'])
        self.assertEqual((await self.create()).status_code, 409)
        self.data['users'][0].update(enabled=True, access_revision=3)
        self.assertTrue(await panel._propagate_user_state('u'))
        self.assertEqual((await self.create())['status'], 'success')
        self.data['users'][0].update(enabled=False, access_revision=4)
        self.assertTrue(await panel._propagate_user_state('u'))
        self.assertFalse(self.native.users[key]['enabled'])
        self.data['users'][0].update(enabled=True, access_revision=5)
        self.assertTrue(await panel._propagate_user_state('u'))
        self.assertEqual(self.native.users[key]['secret'], secret)
        self.assertEqual(self.native.creates, 1)

    async def test_foreign_credential_is_neither_adopted_nor_modified(self):
        key = 'pc_' + uuid.UUID(self.op_id).hex
        foreign = dict(secret='fe' * 16, enabled=True, in_runtime=True)
        self.native.users[key] = copy.deepcopy(foreign)
        self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(self.native.users[key], foreign)
        self.assertEqual(self.data['user_connections'], [])

    async def test_intent_parameters_and_endpoint_are_immutable(self):
        self.native.timeout_prepare = True
        await self.create()
        self.assertEqual((await self.create(telemt_max_ips=2)).status_code, 409)
        self.data['servers'][0]['protocols']['telemt']['port'] = '8443'
        self.assertEqual((await self.create()).status_code, 409)
        operation = self.service.journal.read()[self.op_id]
        self.assertFalse(self.native.users[operation['public']]['enabled'])

    async def test_old_runtime_is_refused_and_capability_is_admin_only(self):
        self.native.old_api = True
        self.assertEqual((await self.create()).status_code, 503)
        self.assertEqual(self.native.creates, 0)
        self.native.old_api = False
        result = await panel.api_create_connection_capabilities(self.request)
        self.assertEqual(result['contract'], 'peer-create-v2')
        self.assertTrue(result['servers']['node']['telemt'])
        with patch.object(panel, '_check_admin', return_value=False):
            self.assertEqual((await panel.api_create_connection_capabilities(self.request)).status_code, 403)
