"""Exact live samples, instance scopes and persisted baselines; no remote SSH."""
import ast
import base64
import copy
import json
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import time
from datetime import datetime
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager
from managers.traffic_counters import parse_transfer_snapshot, read_transfer_snapshot
from user_state import apply_traffic_samples, traffic_server_identity


KEYS = [base64.b64encode(bytes([i]) * 32).decode() for i in range(1, 11)]
HEADER = 'COUNTERS_V1\n' + 'a' * 64 + ' 2026-10-01T00:00:00Z 123\n' + '12345678-1234-1234-1234-123456789abc\n10\nno-socket'
_TREE = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
_SCRAPE_NODE = next(n for n in _TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_scrape_server_traffic')
_SCRAPE_CODE = compile(ast.Module(body=[_SCRAPE_NODE], type_ignores=[]), 'selected-scrape', 'exec')
del _TREE


def output(rows, header=HEADER):
    return header + '\nTRANSFER\n' + '\n'.join(rows) + '\nEND'


def fixture(protocol='awg3'):
    return dict(users=[dict(id='account', enabled=True, traffic_used=0, traffic_total=0,
                           traffic_limit=500, traffic_reset_strategy='monthly',
                           last_reset_at='2026-10-01T00:00:00')],
                servers=[dict(uid='node', host='192.0.2.1', protocols={protocol: {'installed': True}})],
                user_connections=[dict(id=str(i), user_id='account', server_id=0,
                                       protocol=protocol, client_id=k) for i, k in enumerate(KEYS)])


class CounterSSH:
    """Transport substitute; real manager and exact counter parser are used."""
    def __init__(self):
        self.rx, self.tx, self.code, self.calls = 40, 0, 0, []
        self.header = HEADER
        self.custom = None
        self.closed = False
    def connect(self):
        pass
    def disconnect(self):
        self.closed = True
    def run_sudo_command(self, command, timeout=60):
        self.calls.append(command)
        raw = self.custom if self.custom is not None else output([f'{k}\t{self.rx}\t{self.tx}' for k in KEYS], self.header)
        return raw, 'synthetic unavailable' if self.code else '', self.code


class DisplayManager(AWGManager):
    def _resolve_config_path(self, protocol):
        return '/opt/amnezia/awg/awg0.conf'
    def _get_clients_table(self, protocol):
        return [dict(clientId=k, userData=dict(dataReceivedBytes=9999, dataSentBytes=9999)) for k in KEYS]
    def _wg_show(self, protocol):
        raise OSError('unavailable display read')
    def _parse_peers_from_config(self, protocol):
        return {}
    def _load_conn_counts(self, protocol):
        return {'synthetic': 1}
    def _load_conn_warnings(self, protocol):
        return {}


class SharedTrafficAccounting(unittest.TestCase):
    def setUp(self):
        self.data, self.ssh = fixture(), CounterSSH()
        self.manager = DisplayManager(self.ssh)
        self.env = dict(time=time, logger=logging.getLogger('accounting-test'),
                        traffic_server_identity=traffic_server_identity,
                        get_ssh=lambda server: self.ssh,
                        get_protocol_manager=lambda ssh, protocol: self.manager,
                        _manager_call=lambda manager, method, protocol: (getattr(manager, method)()
                            if isinstance(manager, WireGuardManager) else getattr(manager, method)(protocol)))
        exec(_SCRAPE_CODE, self.env)
        self.now = datetime(2026, 10, 28, 12)
        self.tick = self.now.timestamp()

    def scrape(self):
        rows = self.env['_scrape_server_traffic'](self.data['servers'][0], 0, self.data['user_connections'])
        self.tick += 1
        for row in rows:
            row['observed_at'] = self.tick
        return rows

    def apply(self):
        apply_traffic_samples(self.data, self.scrape(), self.now)
        self.data = json.loads(json.dumps(self.data))  # JSON format actually persisted by the panel.

    def test_live_read_outage_preserves_baselines(self):
        self.apply()
        before = copy.deepcopy(self.data)
        self.ssh.code = 1
        self.apply()
        self.assertEqual(self.data, before)
        self.assertEqual([c['last_bytes'] for c in self.data['user_connections']], [40] * 10)

    def test_recovery_does_not_double_charge_or_false_block(self):
        self.apply()
        self.ssh.code = 1
        self.apply()
        self.ssh.code, self.ssh.rx = 0, 41
        self.apply()
        user = self.data['users'][0]
        self.assertEqual((user['traffic_used'], user['traffic_total'], user['enabled']), (410, 410, True))

    def test_secondary_instance_is_accounted(self):
        self.data = fixture('awg3__2')
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_used'], 400)
        self.assertTrue(all(c['protocol'] == 'awg3__2' for c in self.data['user_connections']))
        self.assertIn('amnezia-awg3-2', self.ssh.calls[0])

    def test_display_fallback_is_not_an_accounting_sample(self):
        self.assertEqual(self.manager.get_clients('awg3')[0]['userData']['dataReceivedBytes'], 9999)
        self.ssh.code = 1
        self.assertEqual(self.scrape(), [])

    def test_valid_zero_and_identical_scrape(self):
        self.ssh.rx = 0
        self.apply()
        self.assertEqual([c['last_bytes'] for c in self.data['user_connections']], [0] * 10)
        self.ssh.rx = 40
        self.apply()
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 400)

    def test_one_instance_failure_does_not_starve_another(self):
        self.data['servers'][0]['protocols']['awg3__2'] = {'installed': True}
        other = dict(self.data['user_connections'][0], id='other', protocol='awg3__2')
        self.data['user_connections'].append(other)
        original = self.manager.get_traffic_snapshot
        def snapshot(protocol):
            if protocol == 'awg3':
                raise OSError('unavailable instance')
            return original(protocol)
        self.manager.get_traffic_snapshot = snapshot
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_used'], 40)
        self.assertNotIn('last_bytes', self.data['user_connections'][0])

    def test_aliases_are_queried_once_and_full_link_identity_is_preserved(self):
        self.data['servers'][0]['protocols']['awg3__1'] = {'installed': True}
        self.data['user_connections'][0]['protocol'] = 'awg3__1'
        self.apply()
        self.assertEqual(len(self.ssh.calls), 1)
        self.assertEqual(self.data['users'][0]['traffic_used'], 400)
        self.assertEqual(self.data['user_connections'][0]['protocol'], 'awg3__1')

    def test_two_instances_share_one_quota_without_merging_peer_identities(self):
        self.data['servers'][0]['protocols']['awg3__2'] = {'installed': True}
        self.data['user_connections'] += [dict(c, id='other-' + c['id'], protocol='awg3__2')
                                          for c in list(self.data['user_connections'])]
        self.apply()
        user = self.data['users'][0]
        self.assertEqual((user['traffic_used'], user['traffic_total'], user['enabled']), (800, 800, False))
        self.assertEqual(user['disable_reasons'], ['quota'])
        self.assertEqual(len(self.ssh.calls), 2)
        self.assertEqual(len(self.data['user_connections']), 20)
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 800)

    def test_duplicate_physical_peer_ownership_is_not_charged_twice(self):
        self.data['user_connections'].append(dict(self.data['user_connections'][0], id='duplicate', protocol='awg3__1'))
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_used'], 360)
        self.assertNotIn('last_bytes', self.data['user_connections'][-1])

    def test_not_installed_instance_is_not_queried(self):
        self.data['servers'][0]['protocols']['awg3__2'] = {'installed': False}
        self.apply()
        self.assertEqual(len(self.ssh.calls), 1)

    def test_missing_peer_and_failed_sample_never_rewrite_baseline(self):
        self.apply()
        before = copy.deepcopy(self.data)
        self.ssh.custom = output([])
        self.apply()
        self.assertEqual(self.data, before)

    def test_stale_raw_sample_is_ignored(self):
        rows = self.scrape()
        self.apply()
        before = copy.deepcopy(self.data)
        apply_traffic_samples(self.data, rows, self.now)
        self.assertEqual(self.data, before)

    def test_epoch_change_counts_new_counter_even_when_it_exceeds_old(self):
        self.apply()
        self.ssh.header = HEADER.replace(' 123\n', ' 124\n')
        self.ssh.rx = 50
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 900)
        self.assertTrue(all(c['traffic_accounting_gap']['reason'] == 'epoch_changed' for c in self.data['user_connections']))
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 900)

    def test_decrease_records_unknown_gap_and_counts_new_generation_once(self):
        self.apply()
        self.ssh.rx = 2
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 420)
        conn = self.data['user_connections'][0]
        self.assertEqual(conn['traffic_accounting_gap']['previous_bytes'], 40)
        self.assertFalse(conn['traffic_accounting_gap']['counters_verified_final'])
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 420)

    def test_legacy_baseline_adopts_epoch_without_recharging(self):
        for c in self.data['user_connections']:
            c['last_bytes'] = 40
        self.data['users'][0].update(traffic_total=400, traffic_used=400)
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_total'], 400)

    def test_calendar_reset_and_manual_block_keep_lifetime_and_baselines(self):
        self.apply()
        self.data['users'][0].update(enabled=False, disable_reasons=['manual'])
        self.now = datetime(2026, 11, 1)
        self.tick = self.now.timestamp()
        self.apply()
        user = self.data['users'][0]
        self.assertEqual((user['traffic_used'], user['traffic_total'], user['enabled']), (0, 400, False))

    def test_invalid_raw_sample_is_rejected_atomically(self):
        self.apply()
        before = copy.deepcopy(self.data)
        for changes in ({'bytes': True}, {'rx_bytes': -1}, {'tx_bytes': None}, {'counter_valid': False}, {'counter_epoch': ''}):
            row = self.scrape()[0]
            row.update(changes)
            apply_traffic_samples(self.data, [row], self.now)
            self.assertEqual(self.data, before)

    def test_compatible_legacy_restore_keeps_live_epoch_and_gap(self):
        from peer_recovery import prepare_online_restore
        self.data['users'][0]['traffic_limit'] = 5000
        self.apply()
        backup = copy.deepcopy(self.data)
        for conn in backup['user_connections']:
            for key in ('traffic_counter_epoch', 'last_rx_bytes', 'last_tx_bytes', 'traffic_accounting_gap'):
                conn.pop(key, None)
        self.ssh.header = HEADER.replace(' 123\n', ' 124\n')
        self.apply()
        result = prepare_online_restore(self.data, backup)
        self.assertEqual(result['user_connections'], self.data['user_connections'])
        self.assertEqual(result['users'], self.data['users'])

    def test_orphan_sample_does_not_discard_baseline(self):
        rows = self.scrape()
        self.data['users'] = []
        apply_traffic_samples(self.data, rows, self.now)
        self.assertNotIn('last_bytes', self.data['user_connections'][0])

    def test_wireguard_uses_same_strict_reader(self):
        self.data = fixture('wireguard__1')
        self.manager = WireGuardManager(self.ssh)
        self.apply()
        self.assertEqual(self.data['users'][0]['traffic_used'], 400)


class StrictTransferParser(unittest.TestCase):
    def test_large_exact_values_and_zero(self):
        value = 2**63 + 123
        self.assertEqual(parse_transfer_snapshot(output([f'{KEYS[0]} {value} 0']))['peers'][KEYS[0]], {'rx_bytes': value, 'tx_bytes': 0})

    def test_empty_snapshot(self):
        self.assertEqual(parse_transfer_snapshot(output([]))['peers'], {})

    def test_malformed_partial_and_duplicate_rows_reject_whole_snapshot(self):
        for rows in ([f'{KEYS[0]} 1'], [f'{KEYS[0]} -1 2'], [f'{KEYS[0]} 1.5 2'],
                     [f'{KEYS[0]} NaN 2'], [f'{KEYS[0]} 1 2', f'{KEYS[0]} 3 4'], ['bad-key 1 2']):
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, '^Invalid live traffic snapshot$'):
                parse_transfer_snapshot(output(rows))

    def test_epoch_read_failure_does_not_fallback_to_counters(self):
        with self.assertRaises(ValueError):
            parse_transfer_snapshot(output([f'{KEYS[0]} 1 2'], HEADER.replace('\n10\n', '\n\n')))

    def test_both_compatible_uapi_paths_fit_one_epoch(self):
        header = HEADER.replace('no-socket', '100:200:300:400')
        self.assertEqual(parse_transfer_snapshot(output([f'{KEYS[0]} 1 2'], header))['peers'][KEYS[0]]['rx_bytes'], 1)

    def test_only_read_commands_and_no_secret_dump(self):
        ssh = CounterSSH()
        read_transfer_snapshot(ssh, 'amnezia-awg3-2', 'awg', 'awg0')
        command = ssh.calls[0]
        self.assertIn('show awg0 transfer', command)
        for forbidden in (' dump', 'private-key', 'psk', ' set ', ' restart ', ' rm '):
            self.assertNotIn(forbidden, command)
        with self.assertRaises(ValueError):
            read_transfer_snapshot(ssh, 'container; unsafe', 'wg', 'wg0')


@unittest.skipUnless(os.name == 'posix', 'POSIX collector shell; exercised on Linux CI')
class CollectorShell(unittest.TestCase):
    """Run the actual shell wrapper with local fake Docker/wg executables."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.mode = 'ok'
        self.env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                        COUNTER_TEST_STATE=str(root / 'inspect-count'))
        scripts = {
            'docker': '''import os,pathlib,subprocess,sys
a=sys.argv[1:]
if a[0]=='inspect':
 p=pathlib.Path(os.environ['COUNTER_TEST_STATE']);n=int(p.read_text())if p.exists()else 0;p.write_text(str(n+1))
 key='b'if os.environ['COUNTER_TEST_MODE']=='race'and n else'a'
 print(key*64+' 2026-10-01T00:00:00Z 123')
elif a[0]=='exec':sys.exit(subprocess.call(a[2:]))
else:sys.exit(1)
''',
            'cat': '''import sys
p=sys.argv[1]
if p=='/proc/sys/kernel/random/boot_id':print('12345678-1234-1234-1234-123456789abc')
elif p.startswith('/sys/class/net/'):print('10')
else:sys.exit(1)
''',
            'wg': '''import os,sys
mode=os.environ['COUNTER_TEST_MODE']
if sys.argv[1:]!=['show','wg0','transfer']or mode=='unavailable':sys.exit(1)
if mode!='empty':print('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\\t40\\t1')
''',
        }
        for name, content in scripts.items():
            path = root / name
            path.write_text('#!/usr/bin/env python3\n' + content)
            path.chmod(0o700)
        def run(command, timeout=60):
            env = dict(self.env, COUNTER_TEST_MODE=self.mode)
            process = subprocess.run(command, shell=True, env=env, text=True,
                                     capture_output=True, timeout=timeout)
            return process.stdout.strip(), process.stderr, process.returncode
        self.ssh = SimpleNamespace(run_sudo_command=run)

    def test_actual_shell_returns_exact_live_sample(self):
        result = read_transfer_snapshot(self.ssh, 'synthetic-container', 'wg', 'wg0')
        self.assertEqual(result['peers'][KEYS[0]], {'rx_bytes': 40, 'tx_bytes': 1})

    def test_actual_shell_empty_interface_is_valid(self):
        self.mode = 'empty'
        self.assertEqual(read_transfer_snapshot(self.ssh, 'synthetic-container', 'wg', 'wg0')['peers'], {})

    def test_actual_shell_failure_is_not_empty_success(self):
        self.mode = 'unavailable'
        with self.assertRaisesRegex(RuntimeError, '^Live traffic snapshot unavailable$'):
            read_transfer_snapshot(self.ssh, 'synthetic-container', 'wg', 'wg0')

    def test_actual_shell_rejects_container_restart_during_collection(self):
        self.mode = 'race'
        with self.assertRaises(RuntimeError):
            read_transfer_snapshot(self.ssh, 'synthetic-container', 'wg', 'wg0')


if __name__ == '__main__':
    unittest.main()
