"""Complete archive regressions. Synthetic files only; no network or real pins."""
import asyncio
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

import paramiko
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from starlette.middleware.sessions import SessionMiddleware
from types import SimpleNamespace

import app as panel
import panel_backup as backup
import peer_lifecycle_lock as lifecycle
import peer_recovery as recovery
from scripts.panel_recovery import complete_restore, FINISH_CONFIRM


def fixture():
    return {'users': [{'id': 'admin', 'role': 'admin', 'enabled': True, 'traffic_used': 510,
                       'traffic_total': 910, 'traffic_limit': 500},
                      {'id': 'support', 'role': 'support', 'enabled': True},
                      {'id': 'owner', 'role': 'user', 'enabled': False}],
            'servers': [{'uid': 'synthetic-node', 'host': '192.0.2.1', 'ssh_port': 22,
                         'username': 'fixture', 'password': 'synthetic-sensitive-password',
                         'protocols': {'awg3': {'installed': True}}}],
            'user_connections': [{'id': 'conn', 'user_id': 'owner', 'server_id': 0,
                                  'protocol': 'awg3', 'client_id': 'synthetic-peer',
                                  'last_bytes': 60, 'baseline': {'month': 31}}], 'settings': {}}


class StateFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'custom' / 'accounts.json'
        self.data.parent.mkdir()
        self.original = fixture()
        self.data.write_text(json.dumps(self.original), encoding='utf-8')
        self.trust = self.root / 'pins' / 'custom_known_hosts'
        self.trust.parent.mkdir()
        public = paramiko.RSAKey.generate(1024)
        # Hashed names and non-default ports must be preserved byte for byte.
        self.trust.write_text(paramiko.HostKeys.hash_host('[node.example.test]:2222') +
                              ' ssh-rsa ' + public.get_base64() + '\n', encoding='utf-8')
        self.system = self.root / 'absent-system-pins'
        self.journal = Path(str(self.data) + '.peer-creates.json')
        self.journal.write_text(json.dumps({'fixture-op': {'phase': 'intent', 'private': 'synthetic-key'}}))
        self.fence = Path(str(self.data) + '.lifecycle-uncertain.json')
        self.fence.write_text('{"version":1,"reason":"ssh_result_unknown"}')
        self.recovery = Path(str(self.data) + '.recovery')
        self.recovery.mkdir(mode=0o700)
        self.record = self.recovery / ('b' * 32 + '.json')
        self.record.write_text('{"phase":"prepared","before_base64":"c3ludGhldGlj"}')
        self.record.chmod(0o600)
        self.journal_lock, self.trust_lock = threading.RLock(), threading.RLock()

    def job(self):
        job = backup.ArchiveJob()
        self.addCleanup(job.close)
        return job

    def create(self, job=None):
        return (job or self.job()).create(str(self.data), str(self.trust), 'v-test',
                                          journal_lock=self.journal_lock, trust_lock=self.trust_lock,
                                          system_trust=str(self.system))

    def archive(self):
        job = self.create()
        target = self.root / 'fixture.zip'
        target.write_bytes(job.file.read())
        return target

    def changed_zip(self, change):
        source = self.archive()
        with zipfile.ZipFile(source) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        result = self.root / 'malformed.zip'
        with zipfile.ZipFile(result, 'w') as archive:
            change(files, archive)
        return result


class ArchiveTests(StateFixture, unittest.TestCase):
    def test_all_sidecars_custom_paths_hashes_and_hashed_pins(self):
        unrelated = self.data.parent / 'not-a-panel-secret'
        unrelated.write_text('do-not-copy')
        Path(str(self.data) + '.runtime.lock').write_text('stale PID must not restore')
        (self.recovery / '.recovery-scratch').write_text('incomplete')
        manifest, files, checksum = backup.read_archive(self.archive())
        self.assertEqual(set(files), {'state/data.json', 'state/data.json.peer-creates.json',
                                      'state/data.json.lifecycle-uncertain.json',
                                      'state/data.json.recovery/' + self.record.name, 'trust/ssh_known_hosts'})
        self.assertEqual(files['state/data.json'], self.data.read_bytes())
        self.assertEqual(files['trust/ssh_known_hosts'], self.trust.read_bytes())
        self.assertEqual(manifest['source']['data_file'], str(self.data))
        self.assertFalse(manifest['counters_verified_final'])
        self.assertFalse(manifest['remote_nodes_included'])
        self.assertIn('trust/system_known_hosts', manifest['absent'])
        for item in manifest['files']:
            self.assertEqual(hashlib.sha256(files[item['path']]).hexdigest(), item['sha256'])
            self.assertEqual(len(files[item['path']]), item['size'])

    def test_system_pins_included_and_missing_panel_pins_explicit(self):
        self.trust.replace(self.system)
        manifest, files, _ = backup.read_archive(self.archive())
        self.assertIn('trust/ssh_known_hosts', manifest['absent'])
        self.assertIn('trust/system_known_hosts', files)

    def test_corrupt_critical_json_never_returns_partial_archive(self):
        for path in [self.data, self.journal, self.fence, self.record]:
            with self.subTest(path=path.name):
                before = path.read_bytes()
                path.write_bytes(b'{broken')
                job = self.job()
                with self.assertRaises(backup.BackupError):
                    self.create(job)
                self.assertTrue(job.file is None or job.file.closed)
                path.write_bytes(before)

    def test_duplicate_json_keys_and_invalid_host_key_rejected(self):
        self.journal.write_text('{"op":1,"op":2}')
        with self.assertRaises(backup.BackupError):
            self.create()
        self.journal.write_text('{}')
        self.trust.write_text('not a host key\n')
        with self.assertRaises(backup.BackupError):
            self.create()

    def test_linked_source_does_not_read_arbitrary_host_file(self):
        sentinel = self.root / 'unrelated'
        sentinel.write_text('synthetic-private-sentinel')
        self.record.unlink()
        try:
            self.record.symlink_to(sentinel)
        except OSError as error:
            self.skipTest('Creating symlinks is unavailable: ' + type(error).__name__)
        with self.assertRaisesRegex(backup.BackupError, 'unsafe_state_path'):
            self.create()
        self.assertEqual(sentinel.read_text(), 'synthetic-private-sentinel')

    def test_hardlink_rejected(self):
        os.link(self.data, self.root / 'hardlink')
        with self.assertRaises(backup.BackupError):
            self.create()

    def test_permission_error_closes_tempfile(self):
        original = backup.os.open
        def deny(path, *args, **kwargs):
            if Path(path) == self.data:
                raise PermissionError('synthetic-secret-path-not-for-logs')
            return original(path, *args, **kwargs)
        job = self.job()
        with patch.object(backup.os, 'open', side_effect=deny):
            with self.assertRaisesRegex(backup.BackupError, '^state_read_failed$'):
                self.create(job)
        self.assertTrue(job.file.closed)

    @unittest.skipIf(os.name == 'nt', 'POSIX private-directory mode')
    def test_non_private_recovery_directory_is_refused_not_repaired(self):
        self.recovery.chmod(0o755)
        before = self.record.read_bytes()
        with self.assertRaisesRegex(backup.BackupError, 'recovery_directory_not_private'):
            self.create()
        self.assertEqual(self.recovery.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.record.read_bytes(), before)
        self.recovery.chmod(0o700)

    @unittest.skipIf(os.name == 'nt', 'POSIX directory search/read modes')
    def test_unreadable_nested_recovery_is_not_silently_omitted_even_as_root(self):
        nested = self.recovery / 'nested'
        nested.mkdir(mode=0o700)
        evidence = nested / 'evidence.json'
        evidence.write_text('{"phase":"prepared"}')
        nested.chmod(0)
        try:
            with self.assertRaisesRegex(backup.BackupError, 'unreadable_recovery_directory'):
                self.create()
        finally:
            nested.chmod(0o700)
        self.assertEqual(evidence.read_text(), '{"phase":"prepared"}')

    def test_directory_listing_error_never_returns_incomplete_evidence(self):
        with patch.object(backup.os, 'scandir', side_effect=PermissionError('synthetic-secret')):
            with self.assertRaisesRegex(backup.BackupError, '^state_read_failed$'):
                self.create()

    @unittest.skipIf(os.name == 'nt', 'POSIX mode bits; error path tested on all platforms')
    def test_unreadable_mode_even_under_root_is_rejected(self):
        self.data.chmod(0)
        try:
            with self.assertRaises(backup.BackupError):
                self.create()
        finally:
            self.data.chmod(0o600)

    def test_file_total_and_member_limits(self):
        before = self.data.read_bytes()
        with self.data.open('wb') as large:
            large.truncate(backup.MAX_FILE_BYTES + 1)
        with self.assertRaises(backup.BackupError):
            self.create()
        self.data.write_bytes(before)
        for name, value in [('MAX_TOTAL_BYTES', 10), ('MAX_FILES', 1)]:
            with self.subTest(limit=name), patch.object(backup, name, value):
                with self.assertRaises(backup.BackupError):
                    self.create()

    def test_disk_full_and_fsync_error_cleanup(self):
        for target in ['zip', 'fsync']:
            job = self.job()
            patcher = patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError(28, 'synthetic disk full')) if target == 'zip' else patch.object(backup.os, 'fsync', side_effect=OSError(28, 'synthetic disk full'))
            with patcher, self.assertRaises(OSError):
                self.create(job)
            self.assertTrue(job.file.closed)

    def test_manifest_budget_never_exports_an_unreadable_archive(self):
        job=self.job()
        with patch.object(backup,'MAX_MANIFEST_BYTES',10):
            with self.assertRaisesRegex(backup.BackupError,'manifest_too_large'):
                self.create(job)
        self.assertTrue(job.file.closed)

    def test_unmanaged_write_detected(self):
        entered, release = threading.Event(), threading.Event()
        original = backup._read
        def read(path, *args):
            result = original(path, *args)
            if Path(path) == self.data:
                entered.set()
                self.assertTrue(release.wait(5))
            return result
        errors = []
        def worker():
            try:
                self.create()
            except BaseException as error:
                errors.append(error)
        with patch.object(backup, '_read', side_effect=read):
            thread = threading.Thread(target=worker)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.data.write_text(json.dumps({**self.original, 'marker': 'newer'}))
            finally:
                release.set(); thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(any(isinstance(e, backup.BackupError) for e in errors))

    def test_managed_data_journal_and_trust_writers_wait_for_snapshot(self):
        for lock, path in [(recovery.STATE_FILE_LOCK, self.data), (self.journal_lock, self.journal), (self.trust_lock, self.trust)]:
            with self.subTest(file=path.name):
                entered, release, waiting, finished = [threading.Event() for _ in range(4)]
                original = backup._read; before = path.read_bytes(); jobs = []
                def read(name, *args):
                    if Path(name) == self.data:
                        entered.set(); self.assertTrue(release.wait(5))
                    return original(name, *args)
                def writer():
                    waiting.set()
                    with lock:
                        path.write_bytes(before + b'\n')
                    finished.set()
                with patch.object(backup, '_read', side_effect=read):
                    export = threading.Thread(target=lambda: jobs.append(self.create()))
                    export.start(); self.assertTrue(entered.wait(5))
                    update = threading.Thread(target=writer); update.start(); self.assertTrue(waiting.wait(5))
                    self.assertFalse(finished.is_set())
                    release.set(); export.join(5); update.join(5)
                self.assertFalse(export.is_alive() or update.is_alive())
                self.assertTrue(finished.is_set())
                self.assertEqual(path.read_bytes(), before + b'\n')
                with zipfile.ZipFile(jobs[0].file) as archive:
                    member = 'trust/ssh_known_hosts' if path == self.trust else 'state/data.json.peer-creates.json' if path == self.journal else 'state/data.json'
                    self.assertEqual(archive.read(member), before)


class RestoreTests(StateFixture, unittest.TestCase):
    def test_nested_recovery_evidence_round_trip_keeps_all_directories_private(self):
        nested = self.recovery / 'nested'
        nested.mkdir(mode=0o700)
        (nested / 'evidence.json').write_text('{"phase":"prepared"}')
        target = self.root / 'restored'
        backup.stage_restore(self.archive(), target, backup.STAGE_CONFIRM)
        path = target / 'state/data.json.recovery/nested/evidence.json'
        self.assertEqual(path.read_text(), '{"phase":"prepared"}')
        if os.name != 'nt':
            for directory in [path.parent, path.parent.parent, path.parent.parent.parent]:
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertIn(recovery.DISASTER_HOLD, json.loads((target / 'state/data.json').read_bytes()))

    def test_complete_staging_preserves_accounting_and_all_evidence(self):
        archive = self.archive(); target = self.root / 'restored'
        result = backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
        data = json.loads((target / 'state/data.json').read_text())
        self.assertTrue(result['startup_held'])
        self.assertEqual(data[recovery.DISASTER_HOLD], result['restore_id'])
        for key in self.original:
            self.assertEqual(data[key], self.original[key])
        self.assertEqual((target / 'state/data.json.peer-creates.json').read_bytes(), self.journal.read_bytes())
        self.assertEqual((target / 'state/data.json.lifecycle-uncertain.json').read_bytes(), self.fence.read_bytes())
        self.assertEqual((target / 'state/data.json.recovery' / self.record.name).read_bytes(), self.record.read_bytes())
        self.assertEqual((target / 'trust/ssh_known_hosts').read_bytes(), self.trust.read_bytes())
        self.assertEqual(self.data.read_text(), json.dumps(self.original))
        self.assertFalse((target / 'state/data.json.runtime.lock').exists())
        with self.assertRaises(recovery.RecoveryError):
            complete_restore(target / 'state/data.json', result['restore_id'], 'e' * 32,
                             recovery.file_hash((target / 'state/data.json').read_bytes()), FINISH_CONFIRM)

    def test_clean_archive_finish_uses_existing_audited_recovery(self):
        self.fence.unlink(); self.journal.write_text('{}')
        target = self.root / 'restored'; result = backup.stage_restore(self.archive(), target, backup.STAGE_CONFIRM)
        path = target / 'state/data.json'; raw = path.read_bytes()
        done = complete_restore(path, result['restore_id'], 'e' * 32, recovery.file_hash(raw), FINISH_CONFIRM)
        self.assertEqual(done['status'], 'success')
        self.assertFalse(done['counters_verified_final'])
        self.assertNotIn(recovery.DISASTER_HOLD, json.loads(path.read_bytes()))
        for key in self.original:
            self.assertEqual(json.loads(path.read_bytes())[key], self.original[key])

    def test_existing_destination_and_retry_never_overwrite_newer_state(self):
        archive = self.archive(); target = self.root / 'restored'
        backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
        path = target / 'state/data.json'; path.write_bytes(path.read_bytes() + b'\n')
        before = path.read_bytes()
        with self.assertRaises(backup.BackupError):
            backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
        self.assertEqual(path.read_bytes(), before)

    def test_staging_write_failure_does_not_publish_or_touch_current_tree(self):
        archive = self.archive(); original = self.data.read_bytes()
        target = self.root / 'restored'
        with patch.object(recovery, 'atomic_bytes', side_effect=OSError(28, 'synthetic full disk')):
            with self.assertRaises(OSError):
                backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
        self.assertFalse(target.exists())
        self.assertEqual(self.data.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.panel-restore-*')), [])
        self.assertEqual(list(self.root.glob('*.restore-claim')), [])

    def test_unconfirmed_staging_has_no_effect(self):
        target = self.root / 'restored'
        with self.assertRaises(backup.BackupError):
            backup.stage_restore(self.archive(), target, '')
        self.assertFalse(target.exists())

    def test_post_publication_fsync_failure_keeps_held_tree_not_false_success(self):
        archive=self.archive();target=self.root/'restored';original=recovery._fsync_directory
        def fail_parent(path):
            if Path(path)==self.root:raise OSError(28,'synthetic directory fsync failure')
            return original(path)
        with patch.object(recovery,'_fsync_directory',side_effect=fail_parent):
            with self.assertRaises(OSError):backup.stage_restore(archive,target,backup.STAGE_CONFIRM)
        data_file=target/'state/data.json';before=data_file.read_bytes()
        self.assertIn(recovery.DISASTER_HOLD,json.loads(before))
        with self.assertRaises(backup.BackupError):backup.stage_restore(archive,target,backup.STAGE_CONFIRM)
        self.assertEqual(data_file.read_bytes(),before)

    def test_traversal_extra_duplicate_corruption_and_symlink_members_rejected(self):
        for kind in ['traversal', 'extra', 'duplicate', 'hash', 'symlink', 'missing']:
            with self.subTest(kind=kind):
                def change(files, archive):
                    if kind == 'hash':files['state/data.json'] += b'\n'
                    if kind == 'missing':files.pop('state/data.json')
                    for name, raw in files.items():archive.writestr(name, raw)
                    if kind == 'traversal':archive.writestr('../outside', b'sentinel')
                    if kind == 'extra':archive.writestr('unlisted', b'sentinel')
                    if kind == 'duplicate':archive.writestr('state/data.json', b'{}')
                    if kind == 'symlink':
                        item = zipfile.ZipInfo('state/data.json.recovery/link');item.create_system = 3;item.external_attr = (stat.S_IFLNK | 0o777) << 16;archive.writestr(item, b'/etc/shadow')
                malformed = self.changed_zip(change)
                with self.assertRaises(backup.BackupError):
                    backup.stage_restore(malformed, self.root / 'restored', backup.STAGE_CONFIRM)
                self.assertFalse((self.root / 'restored').exists())

    def test_manifest_source_paths_are_not_restore_destinations(self):
        def change(files, archive):
            manifest = json.loads(files['manifest.json']);manifest['source'] = {'data_file': '/never/write/host/file'}
            files['manifest.json'] = json.dumps(manifest).encode()
            for name, raw in files.items():archive.writestr(name, raw)
        target = self.root / 'restored'
        result = backup.stage_restore(self.changed_zip(change), target, backup.STAGE_CONFIRM)
        self.assertTrue(result['startup_held'])
        self.assertTrue((target / 'state/data.json').is_file())

    def test_truncated_zip_and_oversized_members_fail_before_staging(self):
        archive = self.archive();archive.write_bytes(archive.read_bytes()[:30])
        with self.assertRaises(backup.BackupError):backup.read_archive(archive)
        archive = self.archive()
        with patch.object(backup, 'MAX_FILE_BYTES', 10):
            with self.assertRaises(backup.BackupError):backup.read_archive(archive)

    def test_concurrent_staging_cannot_overwrite_or_publish_partial_tree(self):
        archive = self.archive();target = self.root / 'restored'
        entered, release = threading.Event(), threading.Event();original = recovery.atomic_bytes;errors=[]
        def pause(path, raw):
            if Path(path).name == 'data.json':
                entered.set();self.assertTrue(release.wait(5))
            return original(path, raw)
        def worker():
            try:backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
            except BaseException as error:errors.append(error)
        with patch.object(recovery, 'atomic_bytes', side_effect=pause):
            thread = threading.Thread(target=worker);thread.start();self.assertTrue(entered.wait(5))
            try:
                self.assertFalse(target.exists())
                with self.assertRaises(FileExistsError):backup.stage_restore(archive, target, backup.STAGE_CONFIRM)
            finally:release.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        self.assertIn(recovery.DISASTER_HOLD,json.loads((target/'state/data.json').read_text()))


class HTTPTests(StateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.stack = __import__('contextlib').ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(panel, 'DATA_FILE', str(self.data)))
        self.stack.enter_context(patch.object(panel, 'DATA_LOCK', asyncio.Lock()))
        self.stack.enter_context(patch.object(lifecycle, '_fence_path', self.fence))
        self.stack.enter_context(patch.object(lifecycle, '_fenced', False))
        self.stack.enter_context(patch.dict(os.environ, {'SSH_KNOWN_HOSTS_FILE': str(self.trust)}))
        original = os.path.expanduser
        self.stack.enter_context(patch.object(os.path, 'expanduser', side_effect=lambda p: str(self.system) if p == '~/.ssh/known_hosts' else original(p)))
        self.client = TestClient(panel.app)
        self.secret = next(m.kwargs['secret_key'] for m in panel.app.user_middleware if m.cls is SessionMiddleware)
        self.headers = {'Content-Type': 'application/json', 'Origin': 'http://testserver',
                        'Sec-Fetch-Site': 'same-origin', 'X-Backup-CSRF': 'fixture-csrf'}

    def identity(self, role):
        self.client.cookies.clear()
        if role:
            value = TimestampSigner(self.secret).sign(base64.b64encode(json.dumps({'user_id': role, 'backup_csrf': 'fixture-csrf'}).encode())).decode()
            self.client.cookies.set('session', value, domain='testserver.local', path='/')

    def test_anonymous_support_user_and_csrf_denied_without_leak(self):
        for role in [None, 'support', 'owner']:
            self.identity(role)
            result = self.client.post('/api/settings/backup/archive', headers=self.headers, json={})
            self.assertEqual(result.status_code, 403)
            self.assertIn('no-store', result.headers['cache-control'])
            self.assertNotIn('synthetic-sensitive-password', result.text)
            self.assertNotIn(str(self.root), result.text)
        self.identity('admin')
        for extra in [{'X-Backup-CSRF': ''}, {'X-Backup-CSRF': 'wrong'},
                      {'X-Backup-CSRF': '', 'Authorization': 'Bearer invalid'},
                      {'Origin': 'https://attacker.invalid', 'Sec-Fetch-Site': 'cross-site'}]:
            result = self.client.post('/api/settings/backup/archive', headers={**self.headers, **extra}, json={})
            self.assertEqual(result.status_code, 403)

    def test_real_http_archive_contains_all_sources_and_is_private(self):
        self.identity('admin')
        result = self.client.post('/api/settings/backup/archive', headers=self.headers, json={})
        self.assertEqual(result.status_code, 200, result.text[:100] if result.status_code != 200 else '')
        self.assertEqual(result.headers['content-type'], 'application/zip')
        self.assertIn('no-store', result.headers['cache-control'])
        self.assertIn('attachment;', result.headers['content-disposition'])
        with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
            self.assertEqual(archive.read('state/data.json'), self.data.read_bytes())
            self.assertEqual(archive.read('trust/ssh_known_hosts'), self.trust.read_bytes())
            self.assertIn('state/data.json.lifecycle-uncertain.json', archive.namelist())
            self.assertEqual(json.loads(archive.read('manifest.json'))['panel_version'], panel.CURRENT_VERSION)
        self.assertEqual(self.client.get('/api/settings/backup/archive').status_code, 405)

    def test_error_is_safe_not_partial_archive(self):
        self.identity('admin');self.journal.write_text('{invalid synthetic-sensitive-password')
        with self.assertLogs(panel.logger, level='WARNING') as logs:
            result = self.client.post('/api/settings/backup/archive', headers=self.headers, json={})
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.json()['code'], 'panel_backup_unavailable')
        self.assertNotIn('synthetic-sensitive-password', result.text + str(logs.output))

    def test_legacy_json_download_and_ordinary_restore_protection_remain(self):
        self.identity('admin')
        result = self.client.get('/api/settings/backup/download')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, self.data.read_bytes())
        # Exercise topology protection independently of a pre-existing unknown
        # SSH result (which correctly fences every ordinary restore with 503).
        self.fence.unlink()
        self.journal.write_text('{}')
        before = self.data.read_bytes()
        incompatible = json.loads(before)
        incompatible['servers'][0]['uid'] = 'different-node'
        result = self.client.post('/api/settings/backup/restore', files={'file': ('old.json', json.dumps(incompatible).encode(), 'application/json')})
        self.assertEqual(result.status_code, 409)
        self.assertEqual(result.json()['code'], 'traffic_finalization_required')
        self.assertEqual(self.data.read_bytes(), before)

    def test_ordinary_restore_cannot_clear_uncertain_lifecycle_evidence(self):
        self.identity('admin')
        before = {path: path.read_bytes() for path in (self.data, self.fence, self.journal, self.record)}
        result = self.client.post('/api/settings/backup/restore', files={
            'file': ('old.json', self.data.read_bytes(), 'application/json')})
        self.assertEqual(result.status_code, 503)
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_compatible_legacy_restore_preserves_live_usage_and_baselines(self):
        self.identity('admin');self.fence.unlink();self.journal.write_text('{}')
        lifecycle.configure(self.data)
        data = panel.load_data();panel.save_data(data)
        old = copy.deepcopy(data)
        old['users'][0]['traffic_used'] = 1;old['users'][0]['traffic_total'] = 2
        old['user_connections'][0]['last_bytes'] = 3
        old['settings']['appearance']['title'] = 'Restored settings only'
        result = self.client.post('/api/settings/backup/restore',files={'file':('old.json',json.dumps(old).encode(),'application/json')})
        self.assertEqual(result.status_code,200,result.text)
        saved=json.loads(self.data.read_bytes())
        self.assertEqual(saved['users'],data['users'])
        self.assertEqual(saved['user_connections'],data['user_connections'])
        self.assertEqual(saved['settings']['appearance']['title'],'Restored settings only')

    def test_verified_admin_bearer_and_disabled_owner(self):
        raw = 'awp_synthetic-fixture-token'
        data = copy.deepcopy(self.original)
        data['api_tokens'] = [{'id':'fixture-token','user_id':'admin','token_hash':hashlib.sha256(raw.encode()).hexdigest()}]
        self.data.write_text(json.dumps(data))
        headers = {k:v for k,v in self.headers.items() if k != 'X-Backup-CSRF'}
        headers['Authorization']='Bearer '+raw
        result = self.client.post('/api/settings/backup/archive',headers=headers,json={})
        self.assertEqual(result.status_code,200)
        data = json.loads(self.data.read_text());data['users'][0]['enabled']=False;self.data.write_text(json.dumps(data))
        self.assertEqual(self.client.post('/api/settings/backup/archive',headers=headers,json={}).status_code,403)

    def test_settings_nonce_enables_real_browser_session(self):
        self.identity('admin')
        result = self.client.get('/settings')
        self.assertEqual(result.status_code,200)
        signed = self.client.cookies.get('session')
        session = json.loads(base64.b64decode(TimestampSigner(self.secret).unsign(signed)))
        self.assertTrue(session['backup_csrf'])
        result = self.client.post('/api/settings/backup/archive',headers={**self.headers,'X-Backup-CSRF':session['backup_csrf']},json={})
        self.assertEqual(result.status_code,200)


class CancellationTests(StateFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.stack = __import__('contextlib').ExitStack();self.addCleanup(self.stack.close)
        self.lock = asyncio.Lock()
        self.stack.enter_context(patch.object(panel, 'DATA_FILE', str(self.data)))
        self.stack.enter_context(patch.object(panel, 'DATA_LOCK', self.lock))
        self.stack.enter_context(patch.object(panel, '_ssh_trust_admin', return_value=True))
        self.stack.enter_context(patch.object(panel, 'get_current_user', return_value={'id': 'admin'}))
        self.stack.enter_context(patch.dict(os.environ, {'SSH_KNOWN_HOSTS_FILE': str(self.trust)}))
        original = os.path.expanduser
        self.stack.enter_context(patch.object(os.path, 'expanduser', side_effect=lambda p: str(self.system) if p == '~/.ssh/known_hosts' else original(p)))
        self.request = SimpleNamespace(headers={'content-type': 'application/json', 'x-backup-csrf': 'nonce'}, session={'backup_csrf': 'nonce'})

    async def test_archive_waits_for_v182_finalization_and_keeps_tombstone_and_audit(self):
        from peer_finalization import finalize_connection_record, commit_finalize
        self.fence.unlink()
        self.journal.write_text('{}')
        self.stack.enter_context(patch.object(lifecycle, '_fence_path', self.fence))
        self.stack.enter_context(patch.object(lifecycle, '_fenced', False))
        data = json.loads(self.data.read_bytes())
        data['users'][2].update(traffic_used=450, traffic_total=900, traffic_limit=500)
        self.data.write_text(json.dumps(data))
        entered, release, authorized = asyncio.Event(), asyncio.Event(), asyncio.Event()
        operation = 'c' * 32

        @lifecycle.serialize_peer_lifecycle
        async def finalization():
            # Controlled mock SSH completion; the actual v1.8.2 accounting and
            # durable RecoveryStore commit below are not mocked.
            entered.set()
            await release.wait()
            async with self.lock:
                before = self.data.read_bytes()
                current = json.loads(before)
                with recovery.STATE_FILE_LOCK:
                    finalize_connection_record(current, current['user_connections'][0],
                        current['servers'][0], 120, time.time(), 'unlink_finalized', operation, True)
                    commit_finalize(self.data, operation, 'admin', 'peer_unlink', 'fixture-intent', before, current)

        def allowed(request):
            authorized.set()
            return True

        task = asyncio.create_task(finalization())
        await entered.wait()
        try:
            with patch.object(panel, '_ssh_trust_admin', side_effect=allowed):
                download = asyncio.create_task(panel.api_backup_archive(self.request))
                await authorized.wait()
                self.assertFalse(download.done())
                release.set()
                response = await download
            try:
                with zipfile.ZipFile(response.job.file) as archive:
                    saved = json.loads(archive.read('state/data.json'))
                    self.assertEqual(saved['users'][2]['traffic_used'], 510)
                    self.assertEqual(saved['users'][2]['traffic_total'], 960)
                    self.assertEqual(saved['user_connections'], [])
                    tombstone = saved['accounting_recoveries'][0]
                    self.assertEqual(tombstone['connection']['user_id'], 'owner')
                    self.assertEqual(tombstone['connection']['baseline'], {'month': 31})
                    self.assertEqual(tombstone['committed_delta'], 60)
                    self.assertFalse(tombstone['counters_verified_final'])
                    record = json.loads(archive.read('state/data.json.recovery/' + operation + '.json'))
                    self.assertEqual(record['phase'], 'committed')
                    self.assertEqual(record['after_sha256'], hashlib.sha256(archive.read('state/data.json')).hexdigest())
                    self.assertEqual(record['audit'][-1]['event'], 'committed')
                    self.assertFalse(json.loads(archive.read('manifest.json'))['counters_verified_final'])
            finally:
                response.job.close()
        finally:
            release.set()
            await task

    async def test_cancel_keeps_all_interlocks_until_worker_finishes_then_cleans(self):
        entered, release = threading.Event(), threading.Event();jobs = [];read = backup._read
        def blocked(path, *args):
            if Path(path) == self.data:
                entered.set();self.assertTrue(release.wait(5))
            return read(path, *args)
        def job():
            result = backup.ArchiveJob();jobs.append(result);return result
        before = self.data.read_bytes()
        with patch.object(backup, '_read', side_effect=blocked), patch.object(panel, 'ArchiveJob', side_effect=job):
            task = asyncio.create_task(panel.api_backup_archive(self.request))
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            task.cancel()
            barrier = asyncio.Event();asyncio.get_running_loop().call_soon(barrier.set);await barrier.wait()
            self.assertFalse(task.done())
            self.assertTrue(self.lock.locked())
            self.assertTrue(lifecycle._mutation_locks[asyncio.get_running_loop()].locked())
            release.set()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertTrue(jobs[0].file.closed)
        self.assertEqual(self.data.read_bytes(), before)
        self.assertFalse(self.lock.locked())
        async with lifecycle.snapshot_interlock():pass

    async def test_lifecycle_queue_timeout_returns_busy_without_archive(self):
        entered, release = asyncio.Event(), asyncio.Event()
        @lifecycle.serialize_peer_lifecycle
        async def leader():
            entered.set();await release.wait()
        lifecycle.configure(self.data)
        # The fence is intentional fixture evidence; leader must start first.
        self.fence.unlink()
        task = asyncio.create_task(leader());await entered.wait()
        try:
            with patch.object(lifecycle, 'QUEUE_WAIT_SECONDS', .01):
                result = await panel.api_backup_archive(self.request)
            self.assertEqual(result.status_code, 503)
            self.assertEqual(json.loads(result.body)['code'], 'panel_backup_busy')
        finally:
            release.set();await task;lifecycle.configure(panel.DATA_FILE)

    async def test_stream_disconnect_closes_anonymous_file(self):
        job = self.create();response = panel.PrivateBackupResponse(job)
        async def send(message):
            if message['type'] == 'http.response.body':raise asyncio.CancelledError
        async def receive():return {'type': 'http.disconnect'}
        with self.assertRaises(asyncio.CancelledError):
            await response({'type': 'http', 'asgi': {'spec_version': '2.4'}}, receive, send)
        self.assertTrue(job.file.closed)

    async def test_admin_revoked_while_waiting_cannot_download_secrets(self):
        self.fence.unlink();lifecycle.configure(self.data)
        entered, release, authorized = asyncio.Event(), asyncio.Event(), asyncio.Event()
        @lifecycle.serialize_peer_lifecycle
        async def leader():
            entered.set();await release.wait()
        def allowed(request):
            authorized.set()
            return json.loads(self.data.read_bytes())['users'][0]['enabled']
        task=asyncio.create_task(leader());await entered.wait()
        try:
            with patch.object(panel,'_ssh_trust_admin',side_effect=allowed):
                download=asyncio.create_task(panel.api_backup_archive(self.request));await authorized.wait()
                data=json.loads(self.data.read_bytes());data['users'][0]['enabled']=False;self.data.write_text(json.dumps(data))
                release.set();response=await download
            self.assertEqual(response.status_code,403)
            self.assertNotIn('synthetic-sensitive-password',response.body.decode())
            self.assertFalse(json.loads(self.data.read_bytes())['users'][0]['enabled'])
        finally:
            release.set();await task;lifecycle.configure(panel.DATA_FILE)
