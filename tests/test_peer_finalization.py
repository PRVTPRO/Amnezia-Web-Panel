import unittest
from unittest.mock import Mock

import peer_finalization as pf


def make_data():
    return {
        'users': [
            {'id': 7, 'name': 'alice', 'traffic_total': 100, 'traffic_used': 90},
            {'id': 8, 'name': 'bob', 'traffic_total': 50, 'traffic_used': 50},
        ],
        'servers': [
            {'uid': 'srv-uid-1', 'host': 'h1', 'ssh_port': 22, 'username': 'root'},
        ],
        'user_connections': [
            {'id': 'c1', 'user_id': 7, 'server_id': 0, 'protocol': 'awg__2',
             'client_id': 'cid-1', 'last_bytes': 10},
            {'id': 'c3', 'user_id': 8, 'server_id': 0, 'protocol': 'awg__2',
             'client_id': 'cid-1', 'last_bytes': 20},
            {'id': 'c2', 'user_id': 7, 'server_id': 0, 'protocol': 'xray',
             'client_id': 'cid-2', 'last_bytes': 0},
        ],
    }


def make_server():
    return {'uid': 'srv-uid-1', 'host': 'h1', 'ssh_port': 22, 'username': 'root'}


class FindConnectionTests(unittest.TestCase):
    def test_matches_exact_scope(self):
        data = make_data()
        conn = pf.find_connection(data, 0, 'awg__2', 'cid-1', user_id=7)
        self.assertIsNotNone(conn)
        self.assertEqual(conn['user_id'], 7)

    def test_protocol_scope_alias_matches(self):
        data = make_data()
        # xray has no instances, so bare xray matches xray__1-style scope
        conn = pf.find_connection(data, 0, 'xray__1', 'cid-2', user_id=7)
        self.assertIsNotNone(conn)

    def test_mismatched_protocol_instance(self):
        data = make_data()
        self.assertIsNone(pf.find_connection(data, 0, 'awg__3', 'cid-1', user_id=7))

    def test_mismatched_server_id(self):
        data = make_data()
        self.assertIsNone(pf.find_connection(data, 5, 'awg__2', 'cid-1', user_id=7))

    def test_mismatched_client_id(self):
        data = make_data()
        self.assertIsNone(pf.find_connection(data, 0, 'awg__2', 'other', user_id=7))

    def test_mismatched_user_id(self):
        data = make_data()
        self.assertIsNone(pf.find_connection(data, 0, 'awg__2', 'cid-1', user_id=99))


class ReadPeerStateTests(unittest.TestCase):
    def _manager(self, clients):
        manager = Mock()
        manager.get_clients = Mock(return_value=clients)
        return manager

    def test_enabled_peer_returns_counters(self):
        manager = self._manager([
            {'clientId': 'cid-1',
             'userData': {'dataReceivedBytes': 11, 'dataSentBytes': 22,
                          'enabled': True}},
        ])
        observed, quiescent = pf.read_peer_state(manager, 'awg', 'cid-1')
        self.assertEqual(observed, 33)
        self.assertFalse(quiescent)

    def test_disabled_peer_is_quiescent(self):
        manager = self._manager([
            {'clientId': 'cid-1',
             'userData': {'dataReceivedBytes': 11, 'dataSentBytes': 22,
                          'enabled': False}},
        ])
        observed, quiescent = pf.read_peer_state(manager, 'awg', 'cid-1')
        self.assertEqual(observed, 33)
        self.assertTrue(quiescent)

    def test_absent_peer_quiescent_without_counter(self):
        manager = self._manager([])
        observed, quiescent = pf.read_peer_state(manager, 'awg', 'cid-1')
        self.assertIsNone(observed)
        self.assertTrue(quiescent)

    def test_manager_exception_not_quiescent(self):
        manager = self._manager([])
        manager.get_clients = Mock(side_effect=RuntimeError('down'))
        observed, quiescent = pf.read_peer_state(manager, 'awg', 'cid-1')
        self.assertIsNone(observed)
        self.assertFalse(quiescent)

    def test_non_list_clients_not_quiescent(self):
        manager = self._manager({'error': 'boom'})
        observed, quiescent = pf.read_peer_state(manager, 'awg', 'cid-1')
        self.assertIsNone(observed)
        self.assertFalse(quiescent)


class ApplyFinalSampleTests(unittest.TestCase):
    def test_commits_delta_and_updates_conn(self):
        data = make_data()
        conn = pf.find_connection(data, 0, 'awg__2', 'cid-1', user_id=7)
        delta = pf.apply_final_sample(
            data, conn, make_server(), 110, 5000)
        self.assertEqual(delta, 100)  # observed 110 - last_bytes 10
        self.assertEqual(conn['last_bytes'], 110)
        self.assertEqual(conn['traffic_observed_at'], 5000)
        user = data['users'][0]
        self.assertEqual(user['traffic_total'], 200)  # 100 + delta 100
        self.assertEqual(user['traffic_used'], 190)   # 90 + delta 100
        # Other user untouched
        self.assertEqual(data['users'][1]['traffic_total'], 50)

    def test_none_observed_is_noop(self):
        data = make_data()
        conn = pf.find_connection(data, 0, 'awg__2', 'cid-1', user_id=7)
        delta = pf.apply_final_sample(data, conn, make_server(), None, 5000)
        self.assertEqual(delta, 0)
        self.assertEqual(conn['last_bytes'], 10)
        self.assertEqual(data['users'][0]['traffic_total'], 100)


class FinalizeConnectionRecordTests(unittest.TestCase):
    def test_removes_matched_row_and_appends_tombstone(self):
        data = make_data()
        conn = pf.find_connection(data, 0, 'awg__2', 'cid-1', user_id=7)
        obs_at = 5000
        result = pf.finalize_connection_record(
            data, conn, make_server(), 110, obs_at, 'delete_finalized',
            'op-123', False)

        self.assertEqual(result['mode'], 'delete_finalized')
        self.assertEqual(result['committed_delta'], 100)
        self.assertEqual(result['observed_bytes'], 110)
        self.assertEqual(result['tombstone_id'], 'op-123')
        self.assertFalse(result['counters_verified_final'])
        self.assertFalse(result['quiescent'])

        rows = [(c['id'], c['user_id']) for c in data['user_connections']]
        self.assertNotIn(('c1', 7), rows)
        self.assertIn(('c3', 8), rows)  # same peer, other user kept
        self.assertIn(('c2', 7), rows)  # unrelated row kept
        self.assertEqual(len(data['user_connections']), 2)

        recoveries = data['accounting_recoveries']
        self.assertEqual(len(recoveries), 1)
        tomb = recoveries[0]
        self.assertEqual(tomb['operation_id'], 'op-123')
        self.assertEqual(tomb['operation'], 'delete_finalized')
        self.assertEqual(tomb['observed_bytes'], 110)
        self.assertEqual(tomb['committed_delta'], 100)
        self.assertFalse(tomb['counters_verified_final'])
        self.assertFalse(tomb['quiescent'])
        self.assertEqual(tomb['scope'],
                         {'connection_id': 'c1', 'server_uid': 'srv-uid-1',
                          'protocol': 'awg', 'instance': 2,
                          'client_id': 'cid-1'})
        self.assertEqual(tomb['connection']['user_id'], 7)
        self.assertTrue(tomb['finalized_at'])

    def test_row_already_removed_raises(self):
        data = make_data()
        data['user_connections'] = []
        with self.assertRaises(pf.FinalizationError) as cm:
            pf.finalize_connection_record(
                data, {'id': 'c1', 'user_id': 7, 'server_id': 0,
                       'protocol': 'awg__2', 'client_id': 'cid-1',
                       'last_bytes': 0},
                make_server(), 110, 5000, 'delete_finalized', 'op-1', True)
        self.assertEqual(cm.exception.code, 'connection_not_found')


class ConnectionScopeTests(unittest.TestCase):
    def test_returns_base_protocol_and_instance(self):
        conn = {'id': 'c1', 'protocol': 'awg__2', 'client_id': 'cid-1'}
        server = {'uid': 'srv-uid-1'}
        scope = pf.connection_scope(conn, server)
        self.assertEqual(scope, {
            'connection_id': 'c1',
            'server_uid': 'srv-uid-1',
            'protocol': 'awg',
            'instance': 2,
            'client_id': 'cid-1',
        })

    def test_single_instance_protocol(self):
        conn = {'id': 'c2', 'protocol': 'wireguard', 'client_id': 'cid-2'}
        scope = pf.connection_scope(conn, {'uid': 'u'})
        self.assertEqual(scope['protocol'], 'wireguard')
        self.assertEqual(scope['instance'], 1)


if __name__ == '__main__':
    unittest.main()
