"""Торрент-фильтр: правила, поколения цепочек, журнал событий, отказоустойчивость.

Проверки текстовые и на чистых функциях: SSH-ответы подменяются, ни один
контейнер не трогается. Отдельно проверяются сценарии деградации: нет
xt_string, правила отклонены, потеря state, потерянные хуки.
"""

import json
import os
import re
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from managers import torrent_events
from managers.torrent_guard import (
    CAPABLE_RETRY_SECONDS,
    SIGNATURES,
    TorrentGuard,
    build_apply_script,
    build_probe_script,
    build_read_script,
    chain_peer,
    diff_counters,
    normalize_mode,
    parse_report,
    signatures_for,
    target_for,
)


class ApplyScriptTests(unittest.TestCase):
    def test_hooks_and_generation(self):
        script = build_apply_script('awg0', 'on', 'awg show', 7)
        self.assertIn('GEN=7', script)
        self.assertIn('add -I INPUT 1 -i "$IFACE" -j "$I"', script)
        self.assertIn('add -I FORWARD 1 -i "$IFACE" -j "$I"', script)
        self.assertIn('add -I FORWARD 1 -o "$IFACE" -j "$O"', script)
        self.assertIn('ic=TGI${GEN}_$n', script)
        self.assertIn('oc=TGO${GEN}_$n', script)
        self.assertIn('TARGET=DROP', script)
        self.assertIn('echo "@FAIL $FAIL"', script)
        self.assertIn('echo "@GEN $GEN"', script)

    def test_handshake_uses_binary_prefix(self):
        # Голый текст «BitTorrent protocol» ловил обычные страницы в
        # направлении к клиенту и ронял их DROP'ом.
        script = build_apply_script('awg0', 'on', 'awg show', 1)
        self.assertIn("'|13|BitTorrent protocol'", script)
        self.assertNotIn("--string 'BitTorrent protocol'", script)
        self.assertNotIn('--from', script)
        self.assertNotIn('--to', script)

    def test_tracker_rule_only_towards_internet(self):
        # info_hash= в ответах серверов встречается в обычных страницах.
        script = build_apply_script('awg0', 'on', 'awg show', 1)
        for line in script.splitlines():
            if 'info_hash=' in line:
                self.assertIn('"$ic"', line)

    def test_signatures_split_by_direction(self):
        self.assertEqual([s['key'] for s in signatures_for('in')],
                         ['handshake', 'dht_query', 'dht_short', 'tracker'])
        self.assertEqual([s['key'] for s in signatures_for('out')],
                         ['handshake', 'dht_query', 'dht_short'])
        script = build_apply_script('awg0', 'on', 'awg show', 1)
        self.assertEqual(script.count('-j "$TARGET"'), 7)

    def test_count_mode_returns_instead_of_drop(self):
        script = build_apply_script('wg0', 'count', 'wg show', 2)
        self.assertIn('TARGET=RETURN', script)
        self.assertNotIn('TARGET=DROP', script)

    def test_off_mode_only_removes(self):
        script = build_apply_script('awg0', 'off', 'awg show', 3)
        self.assertNotIn('add -I INPUT', script)
        self.assertNotIn('add -I FORWARD', script)
        self.assertNotIn('TARGET=', script)
        self.assertIn('@MODE off', script)

    def test_iptables_wait_is_bounded(self):
        # `-w` без значения ждёт xtables-lock бесконечно.
        for script in (build_apply_script('awg0', 'on', 'awg show', 1),
                       build_read_script('awg0', 'awg show'),
                       build_probe_script()):
            self.assertIn('-w 5', script)


class ReadScriptTests(unittest.TestCase):
    def test_reads_generation_hooks_and_health(self):
        script = build_read_script('awg0', 'awg show')
        self.assertIn('@HOOK $h 3', script)
        self.assertIn('@GEN', script)
        self.assertIn('@BAD', script)
        self.assertIn('@PEERS', script)
        # Хуки ищутся в живом наборе, а не сравнением с константой.
        self.assertIn('-S INPUT', script)
        self.assertIn('-S FORWARD', script)

    def test_rule_count_expected_per_direction(self):
        script = build_read_script('awg0', 'awg show')
        self.assertIn('TGI*) want=%d' % len(signatures_for('in')), script)
        self.assertIn('*) want=%d' % len(signatures_for('out')), script)

    def test_multiple_generations_are_flagged(self):
        # Два активных поколения (обрыв apply) = мусор и двойной matching.
        script = build_read_script('awg0', 'awg show')
        self.assertIn('c1=', script)
        self.assertIn('c2=', script)
        self.assertIn('bad=$((bad+1))', script)

    def test_container_lock_is_reentrant(self):
        from managers.torrent_guard import _container_lock
        lock = _container_lock(('host', 'amnezia-awg2'))
        with lock:
            with lock:
                pass
    def test_peer_discovery_is_not_arithmetic(self):
        for script in (build_apply_script('awg0', 'on', 'awg show', 1),
                       build_read_script('awg0', 'awg show')):
            self.assertNotIn('$(( ', script)
            self.assertIn("sh -c 'awg show'", script)


class ParseReportTests(unittest.TestCase):
    def test_full_report(self):
        out = '\n'.join([
            '@MODE on', '@GEN 7', '@HOOK 3 3', '@BAD 0',
            '@C TGI7_1 12 0 3 1', '@C TGO7_1 0 7 0',
            '@P 1 10.8.1.17',
            '@PEERS 10.8.1.17 10.8.1.18 ',
            '@FAIL 0', '@END ok',
        ])
        report = parse_report(out)
        self.assertTrue(report['hook'])
        self.assertEqual(report['gen'], 7)
        self.assertEqual(report['mode'], 'on')
        self.assertTrue(report['ended'])
        self.assertEqual(report['counters']['TGI7_1'], [12, 0, 3, 1])
        self.assertEqual(report['peers'], ['10.8.1.17', '10.8.1.18'])

    def test_missing_hook_is_false(self):
        self.assertFalse(parse_report('@HOOK 2 3')['hook'])
        self.assertFalse(parse_report('')['hook'])

    def test_fail_bad_and_probe_flags(self):
        self.assertEqual(parse_report('@FAIL 3')['fail'], 3)
        self.assertEqual(parse_report('@FAIL xx')['fail'], 1)
        self.assertEqual(parse_report('@BAD 2')['bad'], 2)
        self.assertTrue(parse_report('@PROBE 1')['probe'])
        self.assertFalse(parse_report('@PROBE 0')['probe'])
        self.assertIsNone(parse_report('')['probe'])

    def test_garbage_values_do_not_raise(self):
        report = parse_report('@GEN xx\n@C TGI7_1 3 xx\n@P 1 10.8.1.17 extra')
        self.assertEqual(report['gen'], 0)
        self.assertEqual(report['counters']['TGI7_1'], [3, 0])


class DiffTests(unittest.TestCase):
    def test_growth_becomes_event_per_direction(self):
        prev = {'TGI7_1': [10, 0, 0, 0], 'TGO7_1': [0, 0, 0]}
        cur = {'TGI7_1': [17, 2, 0, 0], 'TGO7_1': [1, 0, 0]}
        events = diff_counters(prev, cur)
        self.assertEqual([e['sig'] for e in events],
                         ['handshake', 'dht_query', 'handshake'])
        self.assertEqual(events[0]['count'], 7)

    def test_no_baseline_means_no_event(self):
        self.assertEqual(diff_counters({}, {'TGI7_1': [99, 0, 0, 0]}), [])

    def test_counter_reset_does_not_go_negative(self):
        prev = {'TGI7_1': [50, 0, 0, 0]}
        cur = {'TGI7_1': [3, 0, 0, 0]}
        self.assertEqual(diff_counters(prev, cur), [])

    def test_non_peer_chains_are_ignored(self):
        prev = {'TGIN7': [1, 2, 3], 'TGOUT7': [4, 5], 'TG_IN': [9]}
        cur = {'TGIN7': [9, 2, 3], 'TGOUT7': [9, 9], 'TG_IN': [99]}
        self.assertEqual(diff_counters(prev, cur), [])

    def test_chain_to_peer(self):
        peers = ['10.8.1.17', '10.8.1.18']
        self.assertEqual(chain_peer('TGI7_2', peers), '10.8.1.18')
        self.assertEqual(chain_peer('TGO7_1', peers), '10.8.1.17')
        self.assertEqual(chain_peer('TGI7_9', peers), '')
        self.assertEqual(chain_peer('TG_I1', peers), '')

    def test_mode_targets(self):
        self.assertEqual(target_for('on'), 'DROP')
        self.assertEqual(target_for('count'), 'RETURN')
        self.assertEqual(normalize_mode('bogus'), 'on')
        self.assertEqual(normalize_mode('off'), 'off')


if __name__ == '__main__':
    unittest.main()


class ApplyStateTests(unittest.TestCase):
    """apply() сам пишет состояние: иначе UI-путь оставлял capable=False."""

    def _guard(self, report_text, state=None):
        guard = TorrentGuard(MagicMock(), 'amnezia-awg2', 'awg0')
        guard._run_in_container = MagicMock(return_value=(report_text, '', 0))
        guard.load_state = MagicMock(return_value=state or {})
        guard.save_state = MagicMock()
        return guard

    def test_apply_persists_generation_and_capability(self):
        out = '@MODE on\n@GEN 8\n@P 1 10.8.1.17\n@FAIL 0\n@END ok'
        guard = self._guard(out, {'gen': 7})
        report = guard.apply('on')
        self.assertEqual(report['gen'], 8)
        saved = guard.save_state.call_args[0][0]
        self.assertEqual(saved['gen'], 8)
        self.assertEqual(saved['peers'], ['10.8.1.17'])
        self.assertTrue(saved['capable'])
        self.assertEqual(saved['counters'], {})

    def test_rejected_rules_mark_container_incapable(self):
        out = '@MODE on\n@GEN 8\n@FAIL 2\n@END ok'
        guard = self._guard(out, {'gen': 7, 'capable': True})
        report = guard.apply('on')
        self.assertIn('rejected', report['error'])
        saved = guard.save_state.call_args[0][0]
        self.assertFalse(saved['capable'])

    def test_transport_error_keeps_capability(self):
        guard = self._guard('', {'gen': 7, 'capable': True})
        guard._run_in_container = MagicMock(return_value=('', 'ssh down', 1))
        report = guard.apply('on')
        self.assertTrue(report['error'])
        saved = guard.save_state.call_args[0][0]
        self.assertTrue(saved['capable'])

    def test_off_clears_capability_cache(self):
        guard = self._guard('@MODE off\n@GEN 9\n', {'gen': 8, 'capable': False})
        guard.apply('off')
        saved = guard.save_state.call_args[0][0]
        self.assertEqual(saved['mode'], 'off')
        self.assertIsNone(saved['capable'])


class CollectTests(unittest.TestCase):
    def _guard(self, report, state):
        guard = TorrentGuard(MagicMock(), 'amnezia-awg2', 'awg0')
        guard.read = MagicMock(return_value=report)
        guard.apply = MagicMock(return_value={'mode': 'on', 'gen': 5,
                                              'peers': ['10.8.1.17'],
                                              'error': ''})
        guard.probe = MagicMock(return_value={'probe': True, 'error': ''})
        guard.load_state = MagicMock(return_value=state)
        guard.save_state = MagicMock()
        return guard

    def _state(self, **kw):
        now = int(time.time())
        state = {'mode': 'on', 'gen': 5, 'peers': ['10.8.1.17'],
                 'counters': {'TGI5_1': [1, 0, 0, 0], 'TGO5_1': [0, 0, 0]},
                 'capable': True, 'capable_ts': now}
        state.update(kw)
        return state

    def _report(self, **kw):
        report = {'hook': True, 'gen': 5, 'peers': ['10.8.1.17'],
                  'counters': {'TGI5_1': [4, 2, 0, 0], 'TGO5_1': [0, 0, 0]},
                  'bad': 0, 'error': ''}
        report.update(kw)
        return report

    def test_deltas_become_events(self):
        guard = self._guard(self._report(), self._state())
        result = guard.collect('on')
        guard.apply.assert_not_called()
        self.assertEqual([e['sig'] for e in result['events']],
                         ['handshake', 'dht_query'])
        self.assertEqual(result['events'][0]['ip'], '10.8.1.17')
        self.assertTrue(guard.save_state.called)

    def test_unchanged_state_is_not_rewritten(self):
        state = self._state()
        report = self._report(counters=dict(state['counters']))
        guard = self._guard(report, state)
        guard.collect('on')
        guard.save_state.assert_not_called()

    def test_missing_hooks_trigger_reinstall(self):
        guard = self._guard(self._report(hook=False), self._state())
        self.assertTrue(guard.collect('on')['applied'])
        guard.apply.assert_called_once_with('on')

    def test_generation_mismatch_triggers_reinstall(self):
        guard = self._guard(self._report(gen=4), self._state())
        self.assertTrue(guard.collect('on')['applied'])

    def test_broken_rules_trigger_reinstall(self):
        guard = self._guard(self._report(bad=1), self._state())
        self.assertTrue(guard.collect('on')['applied'])

    def test_peer_change_triggers_reinstall(self):
        guard = self._guard(self._report(peers=['10.8.1.17', '10.8.1.18']),
                            self._state())
        self.assertTrue(guard.collect('on')['applied'])

    def test_mode_change_triggers_reinstall(self):
        guard = self._guard(self._report(), self._state(mode='off'))
        guard.collect('on')
        guard.apply.assert_called_once_with('on')

    def test_unreadable_peers_skip_round(self):
        guard = self._guard(self._report(peers=[]), self._state())
        result = guard.collect('on')
        guard.apply.assert_not_called()
        self.assertTrue(result['skipped'])
        guard.save_state.assert_not_called()

    def test_incapable_container_is_cached_for_an_hour(self):
        state = self._state(capable=False, capable_ts=int(time.time()))
        guard = self._guard(self._report(), state)
        result = guard.collect('on')
        self.assertTrue(result.get('cached'))
        self.assertIn('unsupported', result['error'])
        guard.read.assert_not_called()
        guard.apply.assert_not_called()

    def test_incapable_container_is_rechecked_after_the_hour(self):
        state = self._state(capable=False,
                            capable_ts=int(time.time()) - CAPABLE_RETRY_SECONDS - 1)
        guard = self._guard(self._report(hook=False), state)
        guard.probe = MagicMock(return_value={'probe': False, 'error': ''})
        result = guard.collect('on')
        self.assertIn('unsupported', result['error'])
        guard.apply.assert_not_called()
        self.assertFalse(guard.save_state.call_args[0][0]['capable'])

    def test_off_mode_is_stable(self):
        state = self._state(mode='off', peers=[], counters={})
        guard = self._guard(self._report(hook=False, peers=[], counters={}),
                            state)
        result = guard.collect('off')
        guard.apply.assert_not_called()
        self.assertEqual(result['events'], [])

    def test_off_mode_removes_returned_rules(self):
        state = self._state(mode='off', peers=[], counters={})
        guard = self._guard(self._report(peers=[], counters={}), state)
        self.assertTrue(guard.collect('off')['applied'])

    def test_read_error_is_reported(self):
        guard = self._guard({'error': 'ssh down', 'hook': False,
                             'counters': {}, 'peers': [], 'gen': 0}, {})
        result = guard.collect('on')
        self.assertEqual(result['error'], 'ssh down')
        guard.apply.assert_not_called()


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='torrent-journal-')
        self.path = os.path.join(self.dir, 'torrent_events.json')
        self.data = torrent_events.empty()

    def test_record_and_summary(self):
        added = torrent_events.record(
            self.data, 'srv1', 'awg2', '10.8.1.17',
            [{'ts': 100, 'sig': 'handshake', 'count': 7}], client_id='CID')
        self.assertEqual(added, 1)
        summary = torrent_events.summary(self.data, 'srv1')
        self.assertEqual(summary['awg2']['events'], 1)
        self.assertEqual(summary['awg2']['ip'], '10.8.1.17')
        self.assertEqual(summary['awg2']['client_id'], 'CID')

    def test_save_load_roundtrip(self):
        torrent_events.record(self.data, 'srv1', 'awg', '10.8.1.17',
                              [{'ts': int(time.time())}])
        torrent_events.save(self.path, self.data)
        loaded = torrent_events.load(self.path)
        self.assertEqual(
            len(torrent_events.peer_buckets(loaded, 'srv1', 'awg')), 1)

    def test_broken_file_is_ignored(self):
        with open(self.path, 'w', encoding='utf-8') as fh:
            fh.write('{oops')
        self.assertEqual(torrent_events.load(self.path)['servers'], {})

    def test_ttl_prunes_old_events(self):
        now = 10 * 86400
        torrent_events.record(self.data, 'srv', 'awg', '10.0.0.1',
                              [{'ts': now - 40 * 86400}])
        torrent_events.record(self.data, 'srv', 'awg', '10.0.0.2',
                              [{'ts': now - 3600}])
        self.assertEqual(torrent_events.prune(self.data, now=now), 1)

    def test_events_per_key_are_capped(self):
        for i in range(30):
            torrent_events.record(self.data, 'srv', 'awg', '10.0.0.1',
                                  [{'ts': i}])
        events = torrent_events.peer_buckets(
            self.data, 'srv', 'awg')['10.0.0.1']['events']
        self.assertEqual(len(events), torrent_events.MAX_EVENTS_PER_KEY)

    def test_ip_reuse_resets_history(self):
        torrent_events.record(self.data, 'srv', 'awg', '10.8.1.17',
                              [{'ts': 1}], client_id='OLD')
        torrent_events.record(self.data, 'srv', 'awg', '10.8.1.17',
                              [{'ts': 2}], client_id='NEW')
        bucket = torrent_events.peer_buckets(
            self.data, 'srv', 'awg')['10.8.1.17']
        self.assertEqual(bucket['client_id'], 'NEW')
        self.assertEqual(len(bucket['events']), 1)

    def test_clear_by_ip_and_by_client(self):
        torrent_events.record(self.data, 'srv', 'awg', '10.0.0.1',
                              [{'ts': 1}], client_id='A')
        self.assertEqual(
            torrent_events.clear(self.data, 'srv', ip='10.0.0.1'), 1)
        torrent_events.record(self.data, 'srv', 'awg', '10.0.0.2',
                              [{'ts': 1}], client_id='B')
        self.assertEqual(
            torrent_events.clear(self.data, 'srv', client_id='B'), 1)


class SudoPathTests(unittest.TestCase):
    """Под non-root SSH всё идёт через sudo: один вызов на действие."""

    def _ssh(self, staging='/tmp/amnz-tg.AbC12345'):
        ssh = MagicMock()
        ssh.run_command = MagicMock(
            side_effect=[(staging + '\n', '', 0), ('', '', 0)])
        ssh.run_sudo_script = MagicMock(return_value=('@HOOK 3 3', '', 0))
        return ssh

    def test_container_script_runs_as_one_sudo_script(self):
        ssh = self._ssh()
        guard = TorrentGuard(ssh, 'amnezia-awg2', 'awg0')
        out, err, code = guard._run_in_container('#!/bin/sh\necho hi\n')
        self.assertEqual((out, err, code), ('@HOOK 3 3', '', 0))
        wrapper = ssh.run_sudo_script.call_args[0][0]
        self.assertIn('docker cp', wrapper)
        self.assertIn('docker exec', wrapper)
        self.assertNotIn('&&', wrapper)
        uploaded = ssh.upload_file.call_args[0][1]
        self.assertTrue(uploaded.startswith('/tmp/amnz-tg.AbC12345/'))
        self.assertIn('rm -rf /tmp/amnz-tg.AbC12345', wrapper)

    def test_private_staging_failure_is_loud(self):
        ssh = MagicMock()
        ssh.run_command = MagicMock(return_value=('', 'mktemp: denied', 1))
        with self.assertRaises(RuntimeError):
            TorrentGuard(ssh, 'amnezia-awg2', 'awg0')._run_in_container(
                '#!/bin/sh\n')

    def test_state_read_does_not_take_stdin(self):
        ssh = MagicMock()
        ssh.run_sudo_command = MagicMock(return_value=('{"mode":"on"}', '', 0))
        state = TorrentGuard(ssh, 'amnezia-awg2', 'awg0').load_state()
        self.assertEqual(state, {'mode': 'on'})
        cmd = ssh.run_sudo_command.call_args[0][0]
        self.assertNotIn(' -i ', cmd)

    def test_state_save_failure_is_not_silent(self):
        ssh = MagicMock()
        ssh.run_sudo_command = MagicMock(return_value=('', 'no such dir', 1))
        with self.assertRaises(RuntimeError):
            TorrentGuard(ssh, 'amnezia-wireguard', 'wg0').save_state(
                {'mode': 'on'})

    def test_state_file_is_chmodded(self):
        ssh = MagicMock()
        ssh.run_command = MagicMock(return_value=('', '', 0))
        ssh.run_sudo_command = MagicMock(return_value=('', '', 0))
        TorrentGuard(ssh, 'amnezia-awg2', 'awg0').save_state({'mode': 'on'})
        cmds = [c[0][0] for c in ssh.run_sudo_command.call_args_list]
        self.assertTrue(any('chmod 600' in c for c in cmds))


class ManagerWiringTests(unittest.TestCase):
    def test_awg_manager_picks_container_and_interface(self):
        from managers.awg_manager import AWGManager
        mgr = AWGManager(MagicMock())
        guard = mgr.torrent_guard('awg2')
        self.assertEqual(guard.container, 'amnezia-awg2')
        self.assertEqual(guard.iface, 'awg0')
        self.assertEqual(guard.state_path, '/opt/amnezia/awg/torrent_guard.json')
        legacy = mgr.torrent_guard('awg_legacy')
        self.assertEqual(legacy.container, 'amnezia-awg-legacy')
        self.assertEqual(legacy.iface, 'wg0')

    def test_wireguard_manager_uses_its_own_state_path(self):
        from managers.wireguard_manager import WireGuardManager
        guard = WireGuardManager(MagicMock()).torrent_guard('wireguard')
        self.assertEqual(guard.container, 'amnezia-wireguard')
        self.assertEqual(guard.iface, 'wg0')
        self.assertEqual(guard.state_path,
                         '/opt/amnezia/wireguard/torrent_guard.json')


class AppPluginRouteTests(unittest.TestCase):
    """Фича живёт в плагине: ядровых торрент-роутов в приложении больше нет."""

    def test_plugin_routes_registered_and_core_routes_removed(self):
        import app as panel
        paths = {getattr(route, 'path', '') for route in panel.app.routes}
        for path in ('/api/servers/{server_id}/plugins/torrent_guard',
                     '/api/plugins/torrent_guard/flags',
                     '/api/servers/{server_id}/plugins/torrent_guard/install',
                     '/api/servers/{server_id}/plugins/torrent_guard/uninstall',
                     '/api/servers/{server_id}/plugins/torrent_guard/settings',
                     '/api/servers/{server_id}/plugins/torrent_guard/enabled',
                     '/api/servers/{server_id}/plugins/torrent_guard/mode',
                     '/api/servers/{server_id}/plugins/torrent_guard/refresh',
                     '/api/servers/{server_id}/plugins/torrent_guard/marks/clear'):
            self.assertIn(path, paths)
        for gone in ('/api/servers/torrent_flags',
                     '/api/servers/{server_id}/connections/torrent_guard',
                     '/api/servers/{server_id}/connections/torrent_clear',
                     '/api/servers/{server_id}/torrent_guard'):
            self.assertNotIn(gone, paths)

    def test_default_mode_is_protection(self):
        from torrent_plugin_service import CAPABLE_PROTOCOLS, DEFAULT_SETTINGS
        self.assertEqual(DEFAULT_SETTINGS['default_mode'], 'on')
        self.assertIn('wireguard', CAPABLE_PROTOCOLS)

    def test_capable_protocols_only_awg_and_wireguard(self):
        import tempfile
        from torrent_plugin_service import TorrentPlugin
        plugin = TorrentPlugin(
            lambda: os.path.join(tempfile.gettempdir(), 'tg-capable.json'))
        server = {'protocols': {'awg': {}, 'awg3': {}, 'wireguard': {},
                                'xray': {}, 'telemt': {}}}
        self.assertEqual(sorted(plugin.capable(server, True)),
                         ['awg', 'awg3', 'wireguard'])
        self.assertEqual(sorted(plugin.capable(server, False)), ['awg', 'awg3'])
        # Нумерованные инстансы: база отделяется по `__`, а не суффиксом.
        numbered = {'protocols': {'awg3__2': {}, 'awg2__3': {},
                                  'wireguard__2': {}}}
        self.assertEqual(sorted(plugin.capable(numbered, True)),
                         ['awg2__3', 'awg3__2', 'wireguard__2'])

    def test_health_registry_roundtrip(self):
        import tempfile
        from torrent_plugin_service import TorrentPlugin
        plugin = TorrentPlugin(
            lambda: os.path.join(tempfile.gettempdir(), 'tg-health.json'))
        server = {'uid': 'health-test-uid', 'host': 'h'}
        self.assertEqual(plugin.health_for(server)['state'], 'unknown')
        plugin.set_health(server, 'awg2', {'error': ''})
        health = plugin.health_for(server)
        self.assertEqual(health['state'], 'ok')
        plugin.set_health(server, 'awg2', {'error': 'iptables rejected'})
        health = plugin.health_for(server)
        self.assertEqual(health['state'], 'degraded')
        self.assertIn('rejected', health['error'])

    def test_management_modal_has_no_torrent_controls(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'static', 'js', 'server-management.js'),
                  encoding='utf-8') as fh:
            js = fh.read()
        # Тумблер уехал в плагин: в общей модалке его нет ни в разметке, ни в
        # обработчиках, ни в запросах.
        self.assertNotIn('torrentGuardCardToggle', js)
        self.assertNotIn('/torrent_guard', js)
        self.assertNotIn('refreshTorrentGuard', js)


if __name__ == '__main__':
    unittest.main()
