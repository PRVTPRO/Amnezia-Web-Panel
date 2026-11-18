"""Protected config edits for xray: a real change finalizes the owned
peers' counters (counter-preserving apply) instead of refusing."""
import copy
import json
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app as panel

CONFIG = json.dumps({
    'log': {'loglevel': 'error'},
    'inbounds': [{'protocol': 'vless', 'port': 443, 'settings': {
        'clients': [{'id': 'peer-1', 'email': 'peer-1'}],
        'decryption': 'none'}}],
    'outbounds': [{'protocol': 'freedom'}],
})
CONFIG_CHANGED = CONFIG.replace('443', '8443')


def state():
    return {
        'servers': [dict(uid='node-a', host='192.0.2.1', protocols={'xray': {}})],
        'users': [dict(id='u', username='alice', role='admin',
                       traffic_used=450, traffic_total=700)],
        'user_connections': [dict(id='link', user_id='u', server_id=0,
                                  protocol='xray', client_id='peer-1',
                                  last_bytes=10)],
        'settings': {'appearance': {'title': 'Panel'}},
    }


class CounterPreservingApplyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.data = state()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (('_check_admin', lambda request: True),
                            ('get_current_user', lambda request: {'id': 'a', 'role': 'admin'}),
                            ('load_data', lambda: copy.deepcopy(self.data))):
            self.stack.enter_context(patch.object(panel, name, value))
        self.ssh, self.manager = Mock(), Mock()
        self.manager.container_name = 'amnezia-xray'
        self.manager._config_path.return_value = '/opt/amnezia/xray/server.json'
        # The running container's raw config (the protected-mode read).
        self.manager_run = Mock(return_value=(CONFIG, '', 0))
        self.ssh.run_sudo_command = self.manager_run
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=self.ssh))
        self.stack.enter_context(patch.object(panel, 'get_protocol_manager',
                                              return_value=self.manager))
        self.stack.enter_context(patch.object(panel, 'xray_fp_kwargs',
                                              return_value={}))
        self.saved = []
        self.stack.enter_context(patch.object(
            panel, 'save_data',
            Mock(side_effect=lambda d: self.saved.append(copy.deepcopy(d))))
        )
        self.request = SimpleNamespace(cookies={}, headers={})

    async def call(self, config=CONFIG_CHANGED, protocol='xray'):
        return await panel.api_server_config_save(
            self.request, 0, panel.ServerConfigSaveRequest(protocol=protocol,
                                                           config=config))

    def saved_data(self):
        return self.saved[-1] if self.saved else None

    async def test_changed_config_finalizes_counters_and_applies(self):
        owned = panel.ownership_rows(copy.deepcopy(self.data), server_id=0,
                                     protocol='xray')
        print('OWNED_ROWS:', owned)
        import peer_finalization
        import user_state
        real_apply = peer_finalization.apply_traffic_samples
        def traced(data, samples, now):
            s = samples[0]
            c = next(c for c in data['user_connections'] if c['id'] == s['id'])
            users = {u['id']: u for u in data['users']}
            print('TRACE:', 'user?', s['user_id'] in users,
                  '| conn?', bool(c),
                  '| fields', all(c.get(k) == s[k] for k in ('user_id', 'protocol', 'client_id')),
                  '| identity', user_state.traffic_server_identity(data['servers'][0]) == tuple(s['server_identity']),
                  '| observed_at', repr(s['observed_at']), 'vs', repr(c.get('traffic_observed_at', 0)))
            return real_apply(data, samples, now)
        with patch.object(panel, 'read_peer_state', return_value=(120, False)),              patch.object(peer_finalization, 'apply_traffic_samples', traced):
            result = await self.call()

        self.assertEqual(result, {'status': 'success'})
        # The new config was written and applied (restart included): the
        # write path builds a real XrayManager, so assert via its SSH calls.
        restarts = [str(c) for c in self.ssh.run_sudo_command.call_args_list
                    if 'docker restart' in str(c)]
        self.assertTrue(restarts, 'the core must be restarted')
        self.assertTrue(any('8443' in str(c)
                            for c in self.ssh.upload_file_sudo.call_args_list))
        # The owned peer's counters were finalized against its baseline
        # (real accounting path): 10 were already counted, 110 new.
        conn = self.saved[0]['user_connections'][0]
        self.assertEqual(conn['last_bytes'], 120)
        self.assertEqual(self.saved[0]['users'][0]['traffic_total'], 810)
        # The restarted core reports zero counters: baselines moved to zero.
        final = self.saved[-1]['user_connections'][0]
        self.assertEqual(final['last_bytes'], 0)

    async def test_absent_peer_is_rebased_without_a_final_sample(self):
        with patch.object(panel, 'read_peer_state', return_value=(None, True)):
            result = await self.call()

        self.assertEqual(result, {'status': 'success'})
        conn = self.saved_data()['user_connections'][0]
        self.assertEqual(conn['last_bytes'], 0)

    async def test_noop_config_still_short_circuits(self):
        with patch.object(panel, 'read_peer_state', return_value=(120, False)):
            result = await self.call(config=CONFIG)

        self.assertEqual(result, {'status': 'success', 'unchanged': True})
        self.manager._save_server_json.assert_not_called()

    async def test_non_xray_protocols_keep_the_read_only_guard(self):
        self.data['servers'][0]['protocols'] = {'awg3': {}}
        self.data['user_connections'][0]['protocol'] = 'awg3'
        self.manager._get_server_config.return_value = '[Interface]\nPrivateKey = k\n'
        with patch.object(panel, 'read_peer_state', return_value=(120, False)):
            result = await self.call(config='[Interface]\nPrivateKey = changed\n',
                                     protocol='awg3')

        self.assertEqual(result.status_code, 409)
        self.assertEqual(json.loads(result.body)['code'],
                         'traffic_finalization_required')


if __name__ == '__main__':
    unittest.main()
