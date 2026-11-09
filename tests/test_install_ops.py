"""Staged install operation engine: journal, stages and polling endpoints.

Covers the shared engine (stage maps, monotonic percent, restart-interrupted
semantics, prune) and both new polling endpoints with fake services, so no
SSH, Docker or marketplace app is touched.
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

STAGE_KEYS = ('step', 'total', 'percent', 'state', 'lines',
              'result', 'error', 'started_at', 'finished_at')


def base_data():
    return {
        'servers': [{'name': 'srv', 'host': '198.51.100.1', 'ssh_port': 22,
                     'username': 'root', 'password': 'x', 'private_key': '',
                     'server_info': {}, 'uid': 'srv-uid', 'protocols': {}}],
        'users': [{'id': 'admin-id', 'username': 'admin',
                   'password_hash': panel.hash_password('admin'),
                   'role': 'admin', 'enabled': True}],
        'user_connections': [],
    }


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        self._ops = dict(panel._INSTALL_OPS)
        self._active = dict(panel._INSTALL_ACTIVE)
        self._loaded = dict(panel._INSTALL_OPS_LOADED)
        panel._INSTALL_OPS.clear()
        panel._INSTALL_ACTIVE.clear()
        panel._INSTALL_OPS_LOADED['done'] = False
        self.addCleanup(self.restore, panel)

    def restore(self, module):
        module._INSTALL_OPS.clear()
        module._INSTALL_OPS.update(self._ops)
        module._INSTALL_ACTIVE.clear()
        module._INSTALL_ACTIVE.update(self._active)
        module._INSTALL_OPS_LOADED.clear()
        module._INSTALL_OPS_LOADED.update(self._loaded)

    def write_data(self, data=None):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(data or base_data(), handle)

    def admin(self):
        client = TestClient(panel.app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(res.status_code, 200, res.text)
        return client

    def wait_finished(self, state_of, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = state_of()
            if state not in (None, 'running', 'starting'):
                return state
            time.sleep(0.01)
        self.fail('operation did not finish in time')


class StageMapTests(unittest.TestCase):
    def test_every_flow_has_increasing_steps(self):
        for flow, stages in panel.FLOW_STAGES.items():
            with self.subTest(flow=flow):
                steps = list(stages.values())
                self.assertEqual(steps, sorted(steps))
                self.assertEqual(len(steps), len(set(steps)))
                self.assertEqual(stages['start'], 1)
                self.assertEqual(stages['done'], max(steps))
                self.assertEqual(panel.FLOW_TOTALS[flow], max(steps))

    def test_flow_step_lookup(self):
        self.assertEqual(panel._install_stage_step('protocol', 'build'), (4, 10))
        self.assertEqual(panel._install_stage_step('smartroute', 'download'), (6, 8))
        self.assertEqual(panel._install_stage_step('rknblock', 'services'), (6, 9))
        self.assertIsNone(panel._install_stage_step('smartroute', 'docker'))
        self.assertIsNone(panel._install_stage_step('unknown', 'start'))


class OperationEngineTests(EngineCase):
    def test_create_registers_a_running_operation(self):
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        self.assertEqual(op['state'], 'running')
        self.assertEqual(op['step'], 0)
        self.assertEqual(op['percent'], 0)
        self.assertEqual(op['total'], 10)
        self.assertEqual(panel._INSTALL_ACTIVE[(0, 'protocol')], op['id'])
        with open(panel._install_ops_store_path(), encoding='utf-8') as handle:
            stored = json.load(handle)
        self.assertEqual([item['id'] for item in stored], [op['id']])

    def test_percent_is_monotonic_and_stage_mapped(self):
        op = panel.op_create(0, 'rknblock', panel.RKNBLOCK_INSTALL_TOTAL)
        panel.op_log(op, 'preflight', 'checking dpkg')
        self.assertEqual((op['step'], op['percent']), (2, 22))
        panel.op_log(op, 'packages', 'installing packages')
        self.assertEqual((op['step'], op['percent']), (3, 33))
        panel.op_log(op, 'services', 'enabling units')
        self.assertEqual((op['step'], op['percent']), (6, 67))
        # A later line with an earlier stage must not move the bar backwards.
        panel.op_log(op, 'preflight', 'late detail')
        self.assertEqual((op['step'], op['percent']), (6, 67))
        # Unknown stages are detail only.
        panel.op_log(op, 'custom', 'no step here')
        self.assertEqual((op['step'], op['percent']), (6, 67))
        self.assertEqual(op['lines'][-1]['stage'], 'custom')
        self.assertEqual(op['lines'][-1]['text'], 'no step here')

    def test_line_text_is_capped_and_panel_logged(self):
        op = panel.op_create(0, 'smartroute', panel.SMARTROUTE_INSTALL_TOTAL)
        with mock.patch.object(panel, 'logger') as logger:
            panel.op_log(op, 'prepare', 'x' * 5000)
        self.assertEqual(len(op['lines'][0]['text']), 2000)
        logger.info.assert_called_once()
        args = logger.info.call_args.args
        self.assertIn('install %s server %s stage %s', args[0])
        self.assertEqual(args[1:4], ('smartroute', 0, 'prepare'))

    def test_finish_success_reaches_hundred_and_frees_the_flow(self):
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        panel.op_log(op, 'firewall', 'links done')
        panel.op_finish(op, 'success', {'protocol': 'awg3'})
        self.assertEqual(op['state'], 'success')
        self.assertEqual(op['stage'], 'done')
        self.assertEqual(op['percent'], 100)
        self.assertEqual(op['step'], op['total'])
        self.assertNotIn((0, 'protocol'), panel._INSTALL_ACTIVE)
        self.assertEqual(op['result'], {'protocol': 'awg3'})
        self.assertTrue(op['finished_at'])

    def test_finish_failure_keeps_the_progress_and_marks_error(self):
        op = panel.op_create(0, 'rknblock', panel.RKNBLOCK_INSTALL_TOTAL)
        panel.op_log(op, 'packages', 'installing packages')
        panel.op_finish(op, 'failed', error={'code': 'install_failed',
                                             'message': 'boom'})
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['stage'], 'error')
        self.assertEqual(op['percent'], 33)
        self.assertEqual(op['error']['code'], 'install_failed')
        self.assertNotIn((0, 'rknblock'), panel._INSTALL_ACTIVE)

    def test_journal_restart_marks_a_running_operation_interrupted(self):
        op = panel.op_create(0, 'smartroute', panel.SMARTROUTE_INSTALL_TOTAL)
        panel.op_log(op, 'script', 'writing the updater')
        # Simulate a restart: registry empty, journal still says running.
        panel._INSTALL_OPS.clear()
        panel._INSTALL_ACTIVE.clear()
        panel._INSTALL_OPS_LOADED['done'] = False
        panel._install_ops_load()
        loaded = panel._INSTALL_OPS[op['id']]
        self.assertEqual(loaded['state'], 'failed')
        self.assertEqual(loaded['error']['code'], 'interrupted')
        self.assertIn('panel restarted during the installation',
                      loaded['error']['message'])
        self.assertEqual(loaded['stage'], 'error')
        self.assertEqual(loaded['lines'][-1]['stage'], 'error')
        self.assertTrue(loaded['finished_at'])
        # A killed operation never comes back as running or success.
        self.assertNotIn((0, 'smartroute'), panel._INSTALL_ACTIVE)

    def test_prune_drops_old_and_excess_finished_operations(self):
        now = time.time()
        old = panel.op_create(0, 'protocol', 10)
        panel.op_finish(old, 'success', {})
        old['finished_ts'] = now - panel.INSTALL_OP_TTL - 60
        for _ in range(panel.INSTALL_OP_KEEP + 5):
            op = panel.op_create(0, 'protocol', 10)
            panel.op_finish(op, 'success', {})
        panel._install_ops_prune()
        ids = set(panel._INSTALL_OPS)
        self.assertNotIn(old['id'], ids)
        finished = [op for op in panel._INSTALL_OPS.values()
                    if op.get('finished_ts')]
        self.assertLessEqual(len(finished), panel.INSTALL_OP_KEEP)
        self.assertLessEqual(len(panel._INSTALL_OPS), panel.INSTALL_OP_KEEP)

    def test_prune_keeps_running_operations(self):
        running = panel.op_create(0, 'smartroute', panel.SMARTROUTE_INSTALL_TOTAL)
        for _ in range(panel.INSTALL_OP_KEEP + 5):
            op = panel.op_create(0, 'protocol', 10)
            op['finished_ts'] = time.time()
            op['state'] = 'success'
        panel._install_ops_prune()
        self.assertIn(running['id'], panel._INSTALL_OPS)


class SmartRoutePollTests(EngineCase):
    def test_install_returns_operation_id_and_real_stage_lines(self):
        self.write_data()
        seen = []

        async def fake_install(server_id, progress=None):
            for stage, line in (('prepare', 'smartroute: prepare: ok'),
                                ('script', 'smartroute: script: ok'),
                                ('units', 'smartroute: units: ok'),
                                ('activate', 'smartroute: activate: ok'),
                                ('download', 'smartroute: download: ok'),
                                ('verify', 'smartroute: verify: ok')):
                seen.append((stage, line))
                progress(stage, line)
            return {'status': 'success', 'log': 'ok'}

        client = self.admin()
        with mock.patch.object(panel.smartroute_svc, 'install', fake_install):
            res = client.post('/api/servers/0/smartroute/install')
            self.assertEqual(res.status_code, 200, res.text)
            op_id = res.json()['operation_id']
            self.wait_finished(
                lambda: panel._INSTALL_OPS[op_id]['state'])
            poll = client.get(f'/api/servers/0/smartroute/install/{op_id}')
        self.assertEqual(poll.status_code, 200, poll.text)
        payload = poll.json()
        for key in ('operation_id', 'flow', 'state', 'step', 'total',
                    'percent', 'result', 'error', 'started_at',
                    'finished_at', 'lines', 'next_offset'):
            self.assertIn(key, payload)
        self.assertEqual(payload['operation_id'], op_id)
        self.assertEqual(payload['flow'], 'smartroute')
        self.assertEqual(payload['state'], 'success')
        self.assertEqual(payload['percent'], 100)
        self.assertEqual(payload['step'], panel.SMARTROUTE_INSTALL_TOTAL)
        self.assertEqual([line['stage'] for line in payload['lines']],
                         ['start'] + [stage for stage, _ in seen])
        self.assertEqual(seen[-1][1], 'smartroute: verify: ok')

    def test_second_install_of_the_flow_is_rejected(self):
        self.write_data()
        client = self.admin()
        op = panel.op_create(0, 'smartroute', panel.SMARTROUTE_INSTALL_TOTAL)
        self.addCleanup(panel._INSTALL_OPS.pop, op['id'], None)
        self.addCleanup(panel._INSTALL_ACTIVE.pop, (0, 'smartroute'), None)
        res = client.post('/api/servers/0/smartroute/install')
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'install_in_progress')

    def test_already_installed_is_refused(self):
        data = base_data()
        data['servers'][0]['smartroute'] = {'installed': True}
        self.write_data(data)
        client = self.admin()
        res = client.post('/api/servers/0/smartroute/install')
        self.assertEqual(res.status_code, 409, res.text)
        self.assertEqual(res.json()['code'], 'already_installed')

    def test_unknown_operation_is_404(self):
        self.write_data()
        client = self.admin()
        res = client.get('/api/servers/0/smartroute/install/nope')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 'not_found')


class RknBlockPollTests(EngineCase):
    def test_install_returns_operation_id_and_reports_each_phase(self):
        self.write_data()

        async def fake_phases(server, phases, timeout, on_phase=None, on_start=None):
            for phase in phases:
                if on_start is not None:
                    on_start(phase)
                on_phase(phase, f'rknblock: {phase}: ok\n', '', 0)
            return None

        client = self.admin()
        with mock.patch.object(panel, '_rkn_install_phases', fake_phases):
            res = client.post('/api/servers/0/rknblock/install?server_uid=srv-uid')
            self.assertEqual(res.status_code, 200, res.text)
            op_id = res.json()['operation_id']
            self.wait_finished(lambda: panel._INSTALL_OPS[op_id]['state'])
            poll = client.get(f'/api/servers/0/rknblock/install/{op_id}')
        self.assertEqual(poll.status_code, 200, poll.text)
        payload = poll.json()
        self.assertEqual(payload['flow'], 'rknblock')
        self.assertEqual(payload['state'], 'success')
        self.assertEqual(payload['percent'], 100)
        self.assertEqual(payload['result'],
                         {'status': 'success', 'installed': True, 'enabled': True})
        stages = [line['stage'] for line in payload['lines']]
        self.assertEqual(list(dict.fromkeys(stages)),
                         ['start'] + list(panel.RKN_INSTALL_PHASES) + ['done'])
        self.assertIn('phase start: preflight',
                      [line['text'] for line in payload['lines']])
        record = panel.load_data()['servers'][0]['rknblock']
        self.assertEqual(record, {'installed': True, 'enabled': True,
                                  'last_error': None})

    def test_failure_stops_without_writing_the_record(self):
        self.write_data()

        async def failing_phases(server, phases, timeout, on_phase=None, on_start=None):
            on_start('preflight')
            on_phase('preflight', 'rknblock: preflight: ok\n', '', 0)
            on_start('packages')
            on_phase('packages', '', 'boom', 1)
            from fastapi.responses import JSONResponse
            return JSONResponse({'error': 'command failed: boom'}, status_code=500)

        client = self.admin()
        with mock.patch.object(panel, '_rkn_install_phases', failing_phases):
            res = client.post('/api/servers/0/rknblock/install')
            op_id = res.json()['operation_id']
            self.wait_finished(lambda: panel._INSTALL_OPS[op_id]['state'])
        op = panel._INSTALL_OPS[op_id]
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'install_failed')
        self.assertNotIn('rknblock', panel.load_data()['servers'][0])

    def test_unknown_operation_is_404(self):
        self.write_data()
        client = self.admin()
        res = client.get('/api/servers/0/rknblock/install/nope')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 'not_found')


class ProtocolProgressTests(EngineCase):
    def test_progress_returns_the_last_finished_operation(self):
        self.write_data()
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        op['protocol'] = 'awg3'
        panel.op_log(op, 'docker', 'Docker is already installed')
        panel.op_log(op, 'done', 'installation complete')
        panel.op_finish(op, 'success', {'protocol': 'awg3'})
        client = self.admin()
        res = client.get('/api/servers/0/install/progress',
                         params={'protocol': 'awg3'})
        self.assertEqual(res.status_code, 200, res.text)
        payload = res.json()
        for key in STAGE_KEYS + ('operation_id', 'flow', 'protocol',
                                 'next_offset'):
            self.assertIn(key, payload)
        self.assertEqual(payload['state'], 'success')
        self.assertEqual(payload['percent'], 100)
        self.assertEqual(payload['operation_id'], op['id'])
        self.assertEqual(payload['protocol'], 'awg3')
        self.assertTrue(payload['lines'])

    def test_progress_offset_slices_lines(self):
        self.write_data()
        op = panel.op_create(0, 'protocol', panel.PROTOCOL_INSTALL_TOTAL)
        op['protocol'] = 'awg3'
        panel.op_log(op, 'start', 'one')
        panel.op_log(op, 'docker', 'two')
        client = self.admin()
        full = client.get('/api/servers/0/install/progress',
                          params={'protocol': 'awg3'}).json()
        tail = client.get('/api/servers/0/install/progress',
                          params={'protocol': 'awg3', 'offset': 1}).json()
        self.assertEqual(len(tail['lines']), len(full['lines']) - 1)
        self.assertEqual(tail['next_offset'], full['next_offset'])

    def test_progress_unknown_protocol_is_404(self):
        self.write_data()
        client = self.admin()
        res = client.get('/api/servers/0/install/progress',
                         params={'protocol': 'xray'})
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 'install_not_found')


if __name__ == '__main__':
    unittest.main()
