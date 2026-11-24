"""HTTP contract for the per-instance WARP contour (issue #277, S3a MVP).

The SSH work itself is mocked: these tests fix the status payload, the
identity/ToS/XOR guards and the 202-job -> state transition.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers.awg_manager import AWGManager
from warp_service import WarpStateStore


async def _warp_up_stub(self, manager, protocol, attempts=5, delay=2.0):
    """Dataplane probe stub: the SSH transport is mocked."""
    return {'up': True, 'facts': {}, 'detail': ''}


def server_record(protocols, warp=None):
    server = {
        'name': 'Warp box',
        'host': '198.51.100.10',
        'ssh_port': 22,
        'username': 'root',
        'password': 'x',
        'private_key': '',
        'server_info': {},
        'uid': 'srv-uid',
        'protocols': protocols,
    }
    if warp is not None:
        server['warp'] = warp
    return server


class WarpApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        self._state_store = panel.warp_state_store
        self._runtime_store = panel.warp_runtime.state_store
        self._monitor_flag = panel._conn_monitor_started

        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        panel.warp_state_store = WarpStateStore(
            os.path.join(self.tmp, 'data.json.srv_warp_state.json'))
        panel.warp_runtime.state_store = panel.warp_state_store
        panel._conn_monitor_started = True
        panel._WARP_JOBS.clear()

        self.write_data()

        self.client = TestClient(panel.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        login = self.client.post('/api/auth/login',
                                 json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel.warp_state_store = self._state_store
        panel.warp_runtime.state_store = self._runtime_store
        panel._conn_monitor_started = self._monitor_flag
        panel._WARP_JOBS.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_data(self, protocols=None, warp=None):
        if protocols is None:
            protocols = {'awg': {'installed': True, 'base_protocol': 'awg',
                                 'port': '55424'}}
        existing = {}
        if os.path.exists(panel.DATA_FILE):
            try:
                with open(panel.DATA_FILE, encoding='utf-8') as handle:
                    existing = json.load(handle)
            except (OSError, ValueError):
                existing = {}
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({'servers': [server_record(protocols, warp=warp)],
                       'users': existing.get('users') or [{'id': 'admin-id', 'username': 'admin',
                              'password_hash': panel.hash_password('admin'),
                              'role': 'admin', 'enabled': True}],
                       'user_connections': []}, handle)

    def post(self, path, body):
        return self.client.post('/api/servers/0/warp/%s' % path, json=body)

    # ----- install guard over every instance -------------------------------

    def two_instances(self):
        self.write_data(protocols={
            'awg': {'installed': True, 'base_protocol': 'awg'},
            'awg2': {'installed': True, 'base_protocol': 'awg2'},
        })

    def mark_registered(self, proto):
        def mutate(state):
            panel.proto_record(state, 'srv-uid', proto)['warp']['registered'] = True
        panel.warp_state_store.mutate(mutate)

    def test_install_guard_covers_every_instance(self):
        """A host-level install must refuse when *any* instance is registered.

        The request used to collapse to the first AWG instance, so a host with
        awg2 already registered was allowed to install WARP over it.
        """
        self.two_instances()
        self.mark_registered('awg2')
        server = panel.load_data()['servers'][0]

        with self.assertRaises(panel.SrvWarpError) as ctx:
            panel._warp_install_guard(server, 'srv-uid', None)

        self.assertEqual(ctx.exception.code, 'srv_warp_registered_unlink_first')

    def test_install_guard_refuses_a_store_only_instance(self):
        """A registered record without a protocol entry is still a target.

        Deleting an instance as a protocol while it was unlinked left its
        warp record in the store; a host-level install then registered a
        second Cloudflare account beside the leftover record.
        """
        def mark(state):
            panel.proto_record(state, 'srv-uid', 'awg2')['warp']['registered'] = True

        panel.warp_state_store.mutate(mark)
        server = panel.load_data()['servers'][0]
        self.assertEqual(list(server['protocols']), ['awg'])

        with self.assertRaises(panel.SrvWarpError) as ctx:
            panel._warp_install_guard(server, 'srv-uid', None)

        self.assertEqual(ctx.exception.code, 'srv_warp_registered_unlink_first')

    def test_install_guard_with_an_explicit_protocol_stays_narrow(self):
        self.two_instances()
        self.mark_registered('awg2')
        server = panel.load_data()['servers'][0]

        # Targeting the free instance explicitly is still allowed.
        panel._warp_install_guard(server, 'srv-uid', 'awg')

    def wait_for_link(self):
        for _ in range(100):
            state = panel.warp_state_store.load()
            record = ((state.get('servers') or {}).get('srv-uid') or {}) \
                .get('protocols', {}).get('awg') or {}
            link = record.get('warp_link') or {}
            # The link is persisted before the worker writes/uploads scripts.
            # Keep SSH mocks alive until the whole job has finished.
            if link.get('active') and not panel._warp_job_active('srv-uid'):
                return link
            time.sleep(0.02)
        self.fail('warp link job did not finish')

    def wait_for_install(self, op_id):
        for _ in range(200):
            op = panel._INSTALL_OPS.get(op_id) or {}
            if op.get('state') != 'running':
                return op
            time.sleep(0.01)
        self.fail('warp install operation did not finish')

    def seed_link(self, dns_via_warp=False):
        def mutate(state):
            rec = panel.proto_record(state, 'srv-uid', 'awg')
            rec['warp_link'] = {
                'active': True,
                'dns_via_warp': dns_via_warp,
                'applied_at': 1,
                'stale': None,
                'server_uid': 'srv-uid',
                'entry_uid': 'srv-uid',
                'protocol': 'awg',
            }
            rec['client_mtu_warp'] = 1280

        panel.warp_state_store.mutate(mutate)

    def test_drop_warp_instance_state_removes_only_named_protocol(self):
        def seed(state):
            for proto in ('awg', 'awg2', 'awg3'):
                panel.proto_record(state, 'srv-uid', proto)['warp']['registered'] = True

        panel.warp_state_store.mutate(seed)
        panel._drop_warp_instance_state('srv-uid', 'awg2')

        protocols = panel.warp_state_store.load()['servers']['srv-uid']['protocols']
        self.assertNotIn('awg2', protocols)
        self.assertIn('awg3', protocols)
        self.assertTrue(protocols['awg3']['warp']['registered'])

    # ----- GET status ------------------------------------------------------

    def test_status_payload_shape(self):
        response = self.client.get('/api/servers/0/warp/status?server_uid=srv-uid')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        for key in ('aggregate', 'instances', 'budget', 'orphans', 'quota', 'jobs'):
            self.assertIn(key, body)
        self.assertIsInstance(body['instances'], list)
        self.assertEqual(body['instances'][0]['protocol'], 'awg')
        self.assertIn('state', body['instances'][0])
        self.assertEqual(body['quota']['limit'], 3)
        self.assertEqual(body['orphans'], [])
        self.assertEqual(body['jobs'], [])

    def test_status_payload_exposes_repair_state(self):
        repair = {'state': 'error', 'last_error': 'srv_warp_repair_failed',
                  'queue_reason': None}

        def seed(state):
            rec = panel.proto_record(state, 'srv-uid', 'awg')
            rec['warp']['repair_state'] = repair

        panel.warp_state_store.mutate(seed)
        server = panel.load_data()['servers'][0]
        body = panel._warp_status_payload(server, panel.warp_state_store.load())

        instance = next(item for item in body['instances']
                        if item['protocol'] == 'awg')
        self.assertEqual(instance['repair_state']['state'], 'error')
        self.assertEqual(instance['repair_state']['last_error'],
                         'srv_warp_repair_failed')

    def test_status_uid_mismatch_is_404(self):
        response = self.client.get('/api/servers/0/warp/status?server_uid=other')
        self.assertEqual(response.status_code, 404, response.text)

    def test_install_without_protocol_targets_every_instance(self):
        self.write_data(protocols={
            'awg': {'installed': True, 'base_protocol': 'awg', 'port': '55424'},
            'awg2': {'installed': True, 'base_protocol': 'awg2', 'port': '55425'},
        }, warp={'tos_ack': {'version': panel.WARP_TOS_VERSION, 'ts': 1}})
        seen = []

        async def fake_install(server_id, uid, protocol=None, job_id=None,
                               progress=None):
            seen.append(protocol)

        with mock.patch.object(panel.warp_runtime, 'install', fake_install):
            response = self.post('install', {'server_uid': 'srv-uid',
                                             'accept_tos': True})
            self.assertIn(response.status_code, (200, 202), response.text)
            self.wait_for_install(response.json()['operation_id'])

        self.assertEqual(seen, [None])

    def test_install_with_explicit_protocol_targets_one_instance(self):
        self.write_data(protocols={
            'awg': {'installed': True, 'base_protocol': 'awg', 'port': '55424'},
            'awg2': {'installed': True, 'base_protocol': 'awg2', 'port': '55425'},
        }, warp={'tos_ack': {'version': panel.WARP_TOS_VERSION, 'ts': 1}})
        seen = []

        async def fake_install(server_id, uid, protocol=None, job_id=None,
                               progress=None):
            seen.append(protocol)

        with mock.patch.object(panel.warp_runtime, 'install', fake_install):
            response = self.post('install', {'server_uid': 'srv-uid',
                                             'accept_tos': True,
                                             'protocol': 'awg2'})
            self.assertIn(response.status_code, (200, 202), response.text)
            self.wait_for_install(response.json()['operation_id'])

        self.assertEqual(seen, ['awg2'])

    def test_status_linked_instance_is_not_degraded(self):
        # A registered + linked instance has no live handshake data in the
        # status projection: it must read as "connecting" (aggregate
        # "installed"), not as a degraded "disconnected" instance.
        self.seed_link()

        def mark_registered(state):
            rec = panel.proto_record(state, 'srv-uid', 'awg')
            rec['warp']['registered'] = True
            rec['warp']['conf_hash'] = 'deadbeef'

        panel.warp_state_store.mutate(mark_registered)
        response = self.client.get(
            '/api/servers/0/warp/status?server_uid=srv-uid')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body['aggregate'], 'installed')
        self.assertEqual(body['instances'][0]['state'], 'connecting')
        self.assertTrue(body['instances'][0]['link_active'])
        self.assertTrue(body['instances'][0]['installed'])

    def test_uninstall_without_protocol_covers_every_instance(self):
        seen = []

        async def fake_uninstall(server_id, uid, protocol=None, job_id=None):
            seen.append(protocol)

        with mock.patch.object(panel.warp_runtime, 'uninstall',
                               fake_uninstall):
            response = self.post('uninstall', {'server_uid': 'srv-uid'})
            self.assertIn(response.status_code, (200, 202), response.text)
            for _ in range(200):
                if seen:
                    break
                time.sleep(0.01)

        self.assertEqual(seen, [None])

    def test_uninstall_with_explicit_protocol_targets_one_instance(self):
        seen = []

        async def fake_uninstall(server_id, uid, protocol=None, job_id=None):
            seen.append(protocol)

        with mock.patch.object(panel.warp_runtime, 'uninstall',
                               fake_uninstall):
            response = self.post('uninstall', {'server_uid': 'srv-uid',
                                               'protocol': 'awg2'})
            self.assertIn(response.status_code, (200, 202), response.text)
            for _ in range(200):
                if seen:
                    break
                time.sleep(0.01)

        self.assertEqual(seen, ['awg2'])

    # ----- POST guards -----------------------------------------------------

    def test_install_with_non_awg_protocol_is_409(self):
        response = self.post('install', {'server_uid': 'srv-uid',
                                         'protocol': 'xray', 'accept_tos': True})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'],
                         'srv_warp_protocol_unsupported')

    def test_post_uid_mismatch_is_409(self):
        response = self.post('install', {'server_uid': 'other'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_identity_mismatch')

    def test_install_without_tos_is_409(self):
        response = self.post('install', {'server_uid': 'srv-uid'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_tos_required')

    def test_install_creates_a_store_operation_with_progress(self):
        self.write_data(warp={'tos_ack': {'version': panel.WARP_TOS_VERSION,
                                          'ts': 1}})
        seen = []

        async def fake_install(server_id, uid, protocol=None, job_id=None,
                               progress=None):
            seen.append((server_id, uid, protocol, job_id))
            for stage in ('start', 'download', 'register', 'profile',
                          'startsh', 'done'):
                if progress:
                    progress(stage, 'stage %s' % stage)

        with mock.patch.object(panel.warp_runtime, 'install', fake_install):
            response = self.post('install', {'server_uid': 'srv-uid',
                                             'accept_tos': True})
            self.assertIn(response.status_code, (200, 202), response.text)
            op_id = response.json()['operation_id']
            self.wait_for_install(op_id)

        op = panel._INSTALL_OPS[op_id]
        self.assertEqual(op['flow'], 'warp')
        self.assertEqual(op['state'], 'success')
        self.assertEqual(op['total'], panel.WARP_INSTALL_TOTAL)
        self.assertEqual(seen[0][1], 'srv-uid')
        # No protocol in the request: the host-level install covers every
        # registered AWG instance, so None is passed through to the runtime,
        # which expands it to the full AWG list.
        self.assertIsNone(seen[0][2])
        self.assertTrue(seen[0][3])

        progress = self.client.get(
            '/api/servers/0/install/progress',
            params={'operation_id': op_id})
        self.assertEqual(progress.status_code, 200, progress.text)
        payload = progress.json()
        self.assertEqual(payload['flow'], 'warp')
        self.assertEqual(payload['state'], 'success')
        self.assertEqual(payload['percent'], 100)
        self.assertEqual(payload['total'], panel.WARP_INSTALL_TOTAL)
        stages = [line['stage'] for line in payload['lines']]
        self.assertIn('start', stages)
        self.assertIn('download', stages)
        self.assertIn('register', stages)
        self.assertIn('profile', stages)
        self.assertIn('startsh', stages)
        self.assertIn('done', stages)

    def test_install_is_409_when_an_install_is_already_active(self):
        self.write_data(warp={'tos_ack': {'version': panel.WARP_TOS_VERSION,
                                          'ts': 1}})
        panel._INSTALL_ACTIVE[(0, 'warp')] = 'already-running'
        try:
            response = self.post('install', {'server_uid': 'srv-uid',
                                             'accept_tos': True})
        finally:
            panel._INSTALL_ACTIVE.pop((0, 'warp'), None)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'install_in_progress')

    def test_install_failure_is_reported_on_the_operation(self):
        self.write_data(warp={'tos_ack': {'version': panel.WARP_TOS_VERSION,
                                          'ts': 1}})

        async def failing_install(server_id, uid, protocol=None, job_id=None,
                                  progress=None):
            raise panel.SrvWarpError('srv_warp_arch_unsupported', 409)

        with mock.patch.object(panel.warp_runtime, 'install',
                               failing_install):
            response = self.post('install', {'server_uid': 'srv-uid',
                                             'accept_tos': True})
            self.assertIn(response.status_code, (200, 202), response.text)
            op_id = response.json()['operation_id']
            self.wait_for_install(op_id)

        op = panel._INSTALL_OPS[op_id]
        self.assertEqual(op['state'], 'error')
        self.assertEqual(op['error']['code'], 'srv_warp_arch_unsupported')

    def test_link_with_active_exit_link_is_xor_conflict(self):
        self.write_data(
            {'awg': {'installed': True, 'base_protocol': 'awg', 'port': '55424',
                     'exit_link': {'exit_uid': 'exit-uid', 'exit_name': 'B'}}},
            warp={'tos_ack': {'version': panel.WARP_TOS_VERSION, 'ts': 1}})
        response = self.post('link', {'server_uid': 'srv-uid', 'protocol': 'awg'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_xor_conflict')

    def test_awg_settings_save_locked_while_warp_active(self):
        self.seed_link()
        with mock.patch.object(panel, 'get_ssh') as ssh:
            response = self.client.post(
                '/api/servers/0/awg/settings/save',
                json={'protocol': 'awg', 'mtu': '1280'})

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_settings_locked')
        ssh.assert_not_called()

    def test_exit_link_rejected_while_warp_active(self):
        self.seed_link()
        response = self.client.post(
            '/api/servers/0/exit-link',
            json={'protocol': 'awg', 'exit_uid': 'exit-uid'})

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_xor_conflict')

    # ----- link job --------------------------------------------------------

    def test_link_queues_a_job_and_writes_state(self):
        self.write_data(warp={'tos_ack': {'version': panel.WARP_TOS_VERSION,
                                          'ts': 1}})
        seen = []

        def read_mtu(manager, protocol, key):
            return '1376'

        def write_script(manager, protocol_type=None, config_path=None,
                         warp_ctx=None):
            seen.append(('write', protocol_type, warp_ctx))

        def upload_script(manager, protocol_type=None, warp_ctx=None):
            seen.append(('upload', protocol_type, warp_ctx))

        runtime_cls = type(panel.warp_runtime)
        with mock.patch.object(AWGManager, '_read_config_key_live', read_mtu), \
             mock.patch.object(AWGManager, '_write_start_script', write_script), \
             mock.patch.object(AWGManager, '_upload_start_script', upload_script), \
             mock.patch.object(runtime_cls, '_ensure_wgcf',
                               lambda self, manager, protocol: None), \
             mock.patch.object(runtime_cls, '_conf_present',
                               lambda self, manager, protocol: True), \
             mock.patch.object(runtime_cls, '_wait_warp_dataplane',
                               _warp_up_stub), \
             mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()):
            response = self.post('link', {'server_uid': 'srv-uid',
                                          'protocol': 'awg'})
            self.assertEqual(response.status_code, 202, response.text)
            body = response.json()
            self.assertEqual(body['status'], 'queued')
            self.assertTrue(body['job_id'])
            link = self.wait_for_link()

        self.assertEqual(link['protocol'], 'awg')
        self.assertEqual(link['entry_uid'], 'srv-uid')
        self.assertFalse(link['dns_via_warp'])
        state = panel.warp_state_store.load()
        record = state['servers']['srv-uid']['protocols']['awg']
        self.assertEqual(record['client_mtu_warp'], 1280)
        self.assertTrue(any(call[0] == 'write' and call[2]['active']
                            for call in seen))
        self.assertTrue(any(call[0] == 'upload' and call[2]['active']
                            for call in seen))

        status = self.client.get('/api/servers/0/warp/status?server_uid=srv-uid')
        self.assertEqual(status.status_code, 200, status.text)
        instance = status.json()['instances'][0]
        self.assertTrue(instance['link_active'])

    # ----- plugin delete guard --------------------------------------------

    def seed_link_for(self, proto):
        def mutate(state):
            rec = panel.proto_record(state, 'srv-uid', proto)
            rec['warp_link'] = {
                'active': True, 'dns_via_warp': False, 'applied_at': 1,
                'stale': None, 'server_uid': 'srv-uid',
                'entry_uid': 'srv-uid', 'protocol': proto,
            }
            rec['client_mtu_warp'] = 1280

        panel.warp_state_store.mutate(mutate)

    def test_uninstall_is_409_while_any_instance_is_linked(self):
        self.seed_link()
        response = self.post('uninstall', {'server_uid': 'srv-uid'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_in_use')
        # Refused before a job could be queued.
        self.assertFalse(panel._warp_job_active('srv-uid'))

    def test_uninstall_is_409_when_another_instance_is_linked(self):
        self.write_data({'awg': {'installed': True, 'base_protocol': 'awg',
                                 'port': '55424'},
                         'awg3': {'installed': True, 'base_protocol': 'awg3',
                                  'port': '55425', 'instance': 2}})
        self.seed_link_for('awg3')
        # Target the unlinked instance: the guard is server-wide by design.
        response = self.post('uninstall', {'server_uid': 'srv-uid',
                                           'protocol': 'awg'})
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()['code'], 'srv_warp_in_use')

    def test_uninstall_allowed_when_registered_but_not_linked(self):
        def mutate(state):
            rec = panel.proto_record(state, 'srv-uid', 'awg')
            rec['warp']['registered'] = True

        panel.warp_state_store.mutate(mutate)
        with mock.patch.object(panel.warp_runtime, 'uninstall',
                               new=mock.AsyncMock(return_value=None)) as uninst:
            response = self.post('uninstall', {'server_uid': 'srv-uid'})
        self.assertEqual(response.status_code, 202, response.text)
        uninst.assert_called_once()

    def test_uninstall_ignores_links_on_other_servers(self):
        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            data = json.load(handle)
        other = server_record({'awg': {'installed': True,
                                       'base_protocol': 'awg',
                                       'port': '55426'}})
        other['uid'] = 'other-uid'
        data['servers'].append(other)
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)

        def mutate(state):
            rec = panel.proto_record(state, 'other-uid', 'awg')
            rec['warp_link'] = {'active': True, 'protocol': 'awg',
                                'server_uid': 'other-uid',
                                'entry_uid': 'other-uid'}

        panel.warp_state_store.mutate(mutate)
        with mock.patch.object(panel.warp_runtime, 'uninstall',
                               new=mock.AsyncMock(return_value=None)):
            response = self.post('uninstall', {'server_uid': 'srv-uid'})
        self.assertEqual(response.status_code, 202, response.text)


if __name__ == '__main__':
    unittest.main()
