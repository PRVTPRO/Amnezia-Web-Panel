"""Online restores must retain live accounting, without touching VPN nodes."""
import copy
import io
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from fastapi import UploadFile
import app as panel
from peer_recovery import RecoveryError
import peer_recovery as recovery


def state():
    return {
        'servers': [{'uid': 'node', 'host': '192.0.2.1', 'protocols': {'awg': {}}}],
        'users': [{'id': 'u', 'enabled': True, 'traffic_used': 80, 'traffic_total': 180,
                   'last_reset_at': '2026-10-01T00:00:00', 'access_revision': 4}],
        'user_connections': [{'id': 'c', 'user_id': 'u', 'server_id': 0,
                              'protocol': 'awg', 'client_id': 'public-key',
                              'last_bytes': 100, 'traffic_observed_at': 5}],
        'accounting_recoveries': [],
        '_recovery_generation': 3,
        'settings': {'language': 'ru'},
    }


class OnlineRestoreTests(unittest.TestCase):
    def test_stale_backup_restores_settings_without_rewinding_usage(self):
        current = state()
        backup = copy.deepcopy(current)
        backup['settings']['language'] = 'en'
        backup['users'][0].update(traffic_used=1, traffic_total=1, access_revision=1)
        backup['users'][0].pop('last_reset_at')
        backup['user_connections'][0].update(last_bytes=1, traffic_observed_at=1)
        backup['_recovery_generation'] = 1
        original = copy.deepcopy(backup)
        merged = recovery.prepare_online_restore(current, backup)
        self.assertEqual(merged['settings'], backup['settings'])
        self.assertEqual(merged['users'], current['users'])
        self.assertEqual(merged['user_connections'], current['user_connections'])
        self.assertEqual(merged['_recovery_generation'], 3)
        self.assertEqual(backup, original)

    def test_manual_reset_and_missing_fields_are_not_undone(self):
        current = state()
        current['users'][0].pop('traffic_total')
        current['users'][0]['traffic_used'] = 0
        backup = state()
        merged = recovery.prepare_online_restore(current, backup)
        self.assertEqual(merged['users'], current['users'])

    def test_rejects_topology_policy_and_server_changes(self):
        changes = [
            lambda b: b['user_connections'].clear(),
            lambda b: b['user_connections'][0].update(user_id='other'),
            lambda b: b['user_connections'][0].update(client_id='different-key'),
            lambda b: b['servers'][0].update(host='192.0.2.2'),
            lambda b: b['users'].clear(),
            lambda b: b['users'][0].update(traffic_limit=1),
            lambda b: b['accounting_recoveries'].append({'operation_id': 'old'}),
        ]
        for change in changes:
            with self.subTest(change=change):
                backup = state()
                change(backup)
                with self.assertRaises(RecoveryError):
                    recovery.prepare_online_restore(state(), backup)

    def test_archive_and_disaster_hold_cannot_be_overwritten(self):
        current = state()
        current['accounting_recoveries'] = [{'operation_id': 'deleted', 'connection': {'id': 'old'}}]
        current['_disaster_recovery_hold'] = {'pending': True}
        backup = copy.deepcopy(current)
        backup.pop('_disaster_recovery_hold')
        merged = recovery.prepare_online_restore(current, backup)
        self.assertEqual(merged['accounting_recoveries'], current['accounting_recoveries'])
        self.assertEqual(merged['_disaster_recovery_hold'], current['_disaster_recovery_hold'])

    def test_fresh_install_accepts_backup(self):
        self.assertEqual(recovery.prepare_online_restore({'servers': [], 'users': []}, state()), state())


class OnlineRestoreEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_restore_commits_retained_accounting_and_replays(self):
        current = state()
        backup = copy.deepcopy(current)
        backup['settings']['language'] = 'en'
        backup['users'][0]['traffic_used'] = 1
        backup['user_connections'][0]['last_bytes'] = 1
        content = json.dumps(backup).encode()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'data.json'
            target.write_text(json.dumps(current), encoding='utf-8')
            with patch.object(panel, 'DATA_FILE', str(target)), \
                 patch.object(panel, '_check_admin', return_value=True), \
                 patch.object(panel, 'get_current_user', return_value={'id': 'admin'}), \
                 patch.object(panel, 'load_data', side_effect=lambda: json.loads(target.read_text())), \
                 patch.object(panel, 'pathlib_read_data_bytes', side_effect=target.read_bytes), \
                 patch.object(panel, 'backfill_server_uids'), \
                 patch.object(panel, 'get_ssh', side_effect=AssertionError('No SSH on restore')):
                def upload():
                    return UploadFile(filename='data.json', file=io.BytesIO(content))
                result = await panel.api_backup_restore(SimpleNamespace(), upload(), 'a' * 32)
                self.assertEqual(result['status'], 'success')
                saved = json.loads(target.read_text())
                self.assertEqual(saved['users'], current['users'])
                self.assertEqual(saved['user_connections'], current['user_connections'])
                self.assertEqual(saved['settings'], backup['settings'])
                saved['users'][0]['traffic_used'] = 90
                target.write_text(json.dumps(saved), encoding='utf-8')
                replay = await panel.api_backup_restore(SimpleNamespace(), upload(), 'a' * 32)
                self.assertTrue(replay['replayed'])
                self.assertEqual(replay['operation_id'], result['operation_id'])
                self.assertEqual(json.loads(target.read_text())['users'][0]['traffic_used'], 90)
