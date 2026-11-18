"""panel_storage: S3 mirror of the data directory. In-memory fake S3 only; no network."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import contextlib
from datetime import datetime, timezone
import email.utils
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import signal
import stat
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import panel_storage as storage

try:
    from botocore.exceptions import ClientError, ReadTimeoutError
except ImportError:  # CI installs botocore from requirements.txt
    ClientError = ReadTimeoutError = None


MASTER = bytes(range(32))
OTHER_MASTER = bytes(range(32, 64))
PREFIX = 'amnezia-panel/'
SECRET = 'test-secret-access-value'
ACCESS = 'AKIATESTACCESSKEY'
DATA = {'users': [{'id': 'admin', 'role': 'admin'}],
        'servers': [{'uid': 'node-1', 'host': '192.0.2.1', 'username': 'root'}],
        'settings': {}}
RECOVERY = 'data.json.recovery/' + 'a' * 32 + '.json'


class Clock:
    def __init__(self):
        self.wall = time.time()
        self.mono = 1000.0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


class FakeS3:
    """The botocore S3 client methods panel_storage uses, with conditional PUT semantics.

    conditions: 'enforce' (AWS-like), 'ignore' (accepts and ignores If-Match/If-None-Match),
    'create_only' (enforces If-None-Match:* but ignores If-Match), 'reject' (501
    NotImplemented on conditional headers) or 'reject_400' (400 InvalidArgument on them).
    """

    def __init__(self, clock, bucket='panel-test'):
        self.clock = clock
        self.bucket = bucket
        self.objects = {}  # key -> [body, etag, modified]
        self.conditions = 'enforce'
        self.faults = []
        self.calls = []
        self.meta = types.SimpleNamespace(endpoint_url='http://127.0.0.1:9000', region_name='us-east-1')
        self.lock = threading.RLock()

    # fault injection: action 'error' | 'timeout' (not applied) | 'apply_then_timeout' | 'before'
    def fail(self, op, key='', action='error', code='InternalError', status=500, times=1, before=None):
        self.faults.append({'op': op, 'key': key, 'action': action, 'code': code, 'status': status,
                            'times': times, 'before': before})

    def _fault(self, op, key):
        for fault in self.faults:
            if fault['op'] == op and fault['key'] in key and fault['times'] > 0:
                fault['times'] -= 1
                return fault
        return None

    def _headers(self, extra=None):
        headers = {'date': email.utils.formatdate(self.clock.time(), usegmt=True)}
        headers.update(extra or {})
        return headers

    def _error(self, op, code, status):
        return ClientError({'Error': {'Code': code, 'Message': 'fake'},
                            'ResponseMetadata': {'HTTPStatusCode': status, 'HTTPHeaders': self._headers()}}, op)

    def _check(self, op, bucket, key):
        if bucket != self.bucket:
            raise self._error(op, 'NoSuchBucket', 404)
        fault = self._fault(op, key)
        if fault is None:
            return None
        if fault['action'] == 'before':
            fault['before']()
            return None
        if fault['action'] == 'timeout':
            raise ReadTimeoutError(endpoint_url=self.meta.endpoint_url)
        if fault['action'] == 'error':
            raise self._error(op, fault['code'], fault['status'])
        return fault

    def force_put(self, key, body, modified=None):
        etag = '"%s"' % hashlib.md5(body).hexdigest()
        self.objects[key] = [bytes(body), etag, self.clock.time() if modified is None else modified]
        return etag

    def put_object(self, Bucket, Key, Body, IfMatch=None, IfNoneMatch=None):
        with self.lock:
            self.calls.append(('put_object', Key, IfMatch, IfNoneMatch))
            fault = self._check('put_object', Bucket, Key)
            conditional = IfMatch is not None or IfNoneMatch is not None
            if conditional and self.conditions == 'reject':
                raise self._error('PutObject', 'NotImplemented', 501)
            if conditional and self.conditions == 'reject_400':
                raise self._error('PutObject', 'InvalidArgument', 400)
            if conditional and self.conditions in ('enforce', 'create_only'):
                current = self.objects.get(Key)
                if IfNoneMatch == '*' and current is not None:
                    raise self._error('PutObject', 'PreconditionFailed', 412)
                if IfMatch is not None and self.conditions == 'enforce':
                    if current is None:
                        raise self._error('PutObject', 'NoSuchKey', 404)
                    if current[1] != IfMatch:
                        raise self._error('PutObject', 'PreconditionFailed', 412)
            etag = self.force_put(Key, Body)
            if fault is not None:  # apply_then_timeout: the write landed, the response is lost
                raise ReadTimeoutError(endpoint_url=self.meta.endpoint_url)
            return {'ETag': etag, 'ResponseMetadata': {'HTTPStatusCode': 200,
                                                       'HTTPHeaders': self._headers({'etag': etag})}}

    def get_object(self, Bucket, Key):
        with self.lock:
            self.calls.append(('get_object', Key))
            self._check('get_object', Bucket, Key)
            obj = self.objects.get(Key)
            if obj is None:
                raise self._error('GetObject', 'NoSuchKey', 404)
            body, etag, modified = obj
            return {'Body': io.BytesIO(body), 'ETag': etag, 'ContentLength': len(body),
                    'LastModified': datetime.fromtimestamp(int(modified), timezone.utc),
                    'ResponseMetadata': {'HTTPStatusCode': 200, 'HTTPHeaders': self._headers({
                        'etag': etag, 'last-modified': email.utils.formatdate(modified, usegmt=True)})}}

    def delete_object(self, Bucket, Key):
        with self.lock:
            self.calls.append(('delete_object', Key))
            self._check('delete_object', Bucket, Key)
            self.objects.pop(Key, None)
            return {'ResponseMetadata': {'HTTPStatusCode': 204, 'HTTPHeaders': self._headers()}}

    def list_objects_v2(self, Bucket, Prefix='', MaxKeys=1000, ContinuationToken=None):
        with self.lock:
            self.calls.append(('list_objects_v2', Prefix))
            self._check('list_objects_v2', Bucket, Prefix)
            keys = sorted(key for key in self.objects if key.startswith(Prefix))
            start = int(ContinuationToken or 0)
            page = keys[start:start + MaxKeys]
            response = {'KeyCount': len(page), 'IsTruncated': start + MaxKeys < len(keys),
                        'ResponseMetadata': {'HTTPStatusCode': 200, 'HTTPHeaders': self._headers()}}
            if page:
                response['Contents'] = [{'Key': key, 'Size': len(self.objects[key][0]), 'ETag': self.objects[key][1],
                                         'LastModified': datetime.fromtimestamp(int(self.objects[key][2]),
                                                                                timezone.utc)}
                                        for key in page]
            if response['IsTruncated']:
                response['NextContinuationToken'] = str(start + MaxKeys)
            return response

    def keys(self, sub):
        return sorted(key for key in self.objects if key.startswith(PREFIX + sub))

    def count(self, op, key_part=''):
        return sum(1 for call in self.calls if call[0] == op and key_part in call[1])


class HungFlush:
    """flush_done of a final commit that never finishes: each wait times out and moves the clock."""

    def __init__(self, clock):
        self.clock = clock
        self.waits = []

    def is_set(self):
        return False

    def set(self):
        pass

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.clock.advance(timeout)
        return False


def history_aad(key):
    return storage._history_aad(PREFIX, key[len(PREFIX + 'history/'):])


def make_codec(s3, key=MASTER):
    st = storage._State()
    st.cfg = storage._Config()
    st.cfg.prefix = PREFIX
    st.cfg.bucket = s3.bucket
    st.cfg.startup_timeout = 1
    st.keys = storage._Keys(key)
    st.client = s3
    return st


def tree(base):
    """{rel: bytes} of the files the mirror would see."""
    result = {}
    for directory, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if not storage._excluded(d)]
        for name in files:
            if storage._excluded(name):
                continue
            path = os.path.join(directory, name)
            result[os.path.relpath(path, base).replace(os.sep, '/')] = Path(path).read_bytes()
    return result


class EnvCase(unittest.TestCase):
    def setUp(self):
        storage._reset()
        self.addCleanup(storage._reset)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.app_dir = self.root / 'app'
        self.app_dir.mkdir()
        self.data_dir = self.root / 'state'
        self.data_file = self.data_dir / 'data.json'
        env = mock.patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        for name in list(os.environ):
            if name.startswith('PANEL_S3_') or name in ('PANEL_STORAGE', 'DATA_FILE', 'CREDENTIAL_KEY_FILE',
                                                        'SSH_KNOWN_HOSTS_FILE'):
                del os.environ[name]
        null = logging.NullHandler()
        storage.log.addHandler(null)
        self.addCleanup(storage.log.removeHandler, null)
        propagate = storage.log.propagate
        storage.log.propagate = False
        self.addCleanup(setattr, storage.log, 'propagate', propagate)

    def set_env(self, **extra):
        """The baseline environment plus extra; earlier overrides do not leak into the next start."""
        for name in list(os.environ):
            if name.startswith('PANEL_S3_') or name in ('CREDENTIAL_KEY_FILE', 'SSH_KNOWN_HOSTS_FILE'):
                del os.environ[name]
        os.environ.update({
            'PANEL_STORAGE': 's3', 'PANEL_S3_BUCKET': 'panel-test', 'PANEL_S3_REGION': 'us-east-1',
            'PANEL_S3_ENDPOINT_URL': 'http://127.0.0.1:9000', 'PANEL_S3_ACCESS_KEY_ID': ACCESS,
            'PANEL_S3_SECRET_ACCESS_KEY': SECRET, 'PANEL_S3_ENCRYPTION_KEY': base64.b64encode(MASTER).decode(),
            'DATA_FILE': str(self.data_file), 'PANEL_S3_STARTUP_TIMEOUT': '5'})
        os.environ.update(extra)

    def write(self, rel, content, base=None):
        path = Path(base or self.data_dir) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode('utf-8'))
        return path


class LocalBackendTests(EnvCase):
    def test_local_backend_is_a_no_op(self):
        factory = mock.Mock(side_effect=AssertionError('no S3 client in local mode'))
        with mock.patch.object(storage, '_client_factory', factory):
            storage.bootstrap(str(self.data_file), app_dir=str(self.app_dir), panel_version='v')
            storage.start()
            storage.stop()
        self.assertFalse(self.data_dir.exists())
        self.assertEqual(storage.backend(), 'local')
        self.assertEqual(storage.uvicorn_overrides(), {})
        os.environ['DATA_FILE'] = str(self.data_file)
        self.assertEqual(storage.status(), {'backend': 'local', 'path': str(self.data_dir)})

    def test_backend_values(self):
        os.environ['PANEL_STORAGE'] = ''
        self.assertEqual(storage.backend(), 'local')
        os.environ['PANEL_STORAGE'] = ' S3 '
        self.assertEqual(storage.backend(), 's3')
        self.assertEqual(storage.uvicorn_overrides(), {'timeout_graceful_shutdown': 20})
        os.environ['PANEL_STORAGE'] = 'nfs'
        with self.assertRaises(storage.StorageConfigError):
            storage.backend()
        self.assertEqual(storage.status(), {'backend': 'invalid'})

    def test_start_raises_when_bootstrap_did_not_run(self):
        self.set_env()
        with self.assertRaisesRegex(storage.StorageError, 'bootstrap'):
            storage.start()
        self.assertEqual(storage.status()['last_error'], 'not_bootstrapped')
        storage.stop()  # never raises


class ConfigTests(EnvCase):
    def boot(self):
        with mock.patch.object(storage, '_client_factory', mock.Mock(side_effect=AssertionError('no client'))):
            storage.bootstrap(str(self.data_file), app_dir=str(self.app_dir), panel_version='v')

    def assertConfigError(self, pattern):
        with self.assertRaisesRegex(storage.StorageConfigError, pattern) as caught:
            self.boot()
        message = str(caught.exception)
        for secret in (SECRET, base64.b64encode(MASTER).decode(), 'hunter2'):
            self.assertNotIn(secret, message)
        return message

    def test_missing_required_values(self):
        for name, pattern in (('PANEL_S3_BUCKET', 'PANEL_S3_BUCKET'), ('PANEL_S3_REGION', 'PANEL_S3_REGION'),
                              ('PANEL_S3_ENCRYPTION_KEY', 'PANEL_S3_ENCRYPTION_KEY')):
            with self.subTest(name=name):
                self.set_env()
                del os.environ[name]
                self.assertConfigError(pattern)

    def test_bad_values(self):
        cases = (
            ({'PANEL_S3_ENCRYPTION_KEY': base64.b64encode(b'x' * 16).decode()}, 'exactly 32'),
            ({'PANEL_S3_ENCRYPTION_KEY': 'not base64 !!'}, 'exactly 32'),
            ({'PANEL_S3_ENDPOINT_URL': 'http://user:hunter2@minio:9000'}, 'user:password'),
            ({'PANEL_S3_ENDPOINT_URL': 'https://minio:9000/?x=hunter2'}, 'query'),
            ({'PANEL_S3_ENDPOINT_URL': 'ftp://minio'}, 'http'),
            ({'PANEL_S3_FENCING': 'maybe'}, 'PANEL_S3_FENCING'),
            ({'PANEL_S3_ADDRESSING_STYLE': 'weird'}, 'ADDRESSING_STYLE'),
            ({'PANEL_S3_SYNC_INTERVAL': '0'}, 'SYNC_INTERVAL'),
            ({'PANEL_S3_LEASE_INTERVAL': 'x'}, 'LEASE_INTERVAL'),
        )
        for extra, pattern in cases:
            with self.subTest(extra=extra):
                self.set_env(**extra)
                self.assertConfigError(pattern)

    def test_lease_interval_must_cover_three_sync_intervals(self):
        # Heartbeats come from the sync loop: with SYNC 20 s and LEASE 30 s a live panel
        # would look stale (3 x 30 s) between two late heartbeats.
        self.set_env(PANEL_S3_SYNC_INTERVAL='20')
        self.assertConfigError(r'PANEL_S3_LEASE_INTERVAL \(30\) must be at least 3 x PANEL_S3_SYNC_INTERVAL')
        self.set_env(PANEL_S3_SYNC_INTERVAL='10', PANEL_S3_LEASE_INTERVAL='29')
        self.assertConfigError('at least 3 x')
        self.set_env(PANEL_S3_SYNC_INTERVAL='10', PANEL_S3_LEASE_INTERVAL='30')
        cfg = storage._load_config()
        self.assertEqual((cfg.sync_interval, cfg.lease_interval), (10.0, 30))

    def test_endpoint_requires_keys_and_keys_come_in_pairs(self):
        self.set_env()
        del os.environ['PANEL_S3_ACCESS_KEY_ID']
        self.assertConfigError('PANEL_S3_ACCESS_KEY_ID')
        self.set_env()
        del os.environ['PANEL_S3_ACCESS_KEY_ID']
        del os.environ['PANEL_S3_SECRET_ACCESS_KEY']
        self.assertConfigError('required with PANEL_S3_ENDPOINT_URL')

    def test_data_directory_validation(self):
        self.set_env()
        del os.environ['DATA_FILE']
        self.assertConfigError('DATA_FILE')
        for data_file, pattern in ((self.app_dir / 'data.json', 'application directory'),
                                   (self.root / 'data.json', 'application directory'),
                                   (self.data_dir / '.data.json', 'must not start')):
            with self.subTest(data_file=data_file):
                self.data_file = data_file
                self.set_env()
                self.assertConfigError(pattern)
        self.data_file = Path(tempfile.gettempdir()) / 'data.json'
        self.app_dir = Path(storage.__file__).resolve().parent  # outside the temp directory
        self.set_env()
        self.assertConfigError('temp directory')

    def test_secrets_are_popped_and_file_variants_read(self):
        key_file = self.write('enc.key', base64.b64encode(MASTER).decode() + '\n', self.root)
        secret_file = self.write('secret', SECRET + '\n', self.root)
        self.set_env(PANEL_S3_ENCRYPTION_KEY_FILE=str(key_file), PANEL_S3_SECRET_ACCESS_KEY_FILE=str(secret_file))
        del os.environ['PANEL_S3_ENCRYPTION_KEY']
        del os.environ['PANEL_S3_SECRET_ACCESS_KEY']
        cfg = storage._load_config(str(self.data_file), str(self.app_dir))
        self.assertEqual(cfg.master_key, MASTER)
        self.assertEqual(cfg.secret_access_key, SECRET)
        self.assertEqual(cfg.prefix, PREFIX)
        self.assertEqual(cfg.addressing_style, 'path')
        self.assertNotIn(SECRET, repr(cfg))
        for name in storage.SECRET_VARS:
            self.assertNotIn(name, os.environ)
            self.assertNotIn(name + '_FILE', os.environ)
        # Even a failing parse removes them.
        self.set_env(PANEL_S3_SECRET_ACCESS_KEY_FILE=str(secret_file))
        self.assertConfigError('not both')
        self.assertNotIn('PANEL_S3_SECRET_ACCESS_KEY', os.environ)

    def test_prefix_normalisation(self):
        self.set_env(PANEL_S3_PREFIX='/team/panel')
        self.assertEqual(storage._load_config().prefix, 'team/panel/')
        self.set_env(PANEL_S3_PREFIX='a/../b')
        with self.assertRaises(storage.StorageConfigError):
            storage._load_config()


@unittest.skipIf(ClientError is None, 'botocore is not installed')
class StorageCase(EnvCase):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.s3 = FakeS3(self.clock)
        self.exits = []
        self.sleeps = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.advance(seconds)

        for name, value in (('_now', self.clock.time), ('_monotonic', self.clock.monotonic),
                            ('_sleep', sleep), ('_exit', self.exits.append),
                            ('_client_factory', lambda cfg, attempts: self.s3)):
            patcher = mock.patch.object(storage, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.codec = make_codec(self.s3)
        self.set_env()

    def boot(self, data_file=None):
        data_file = Path(data_file or self.data_file)
        os.environ['DATA_FILE'] = str(data_file)
        storage.bootstrap(str(data_file), app_dir=str(self.app_dir), panel_version='v-test')
        return storage._S

    def restart(self, data_file=None, **env):
        """A new process: module state is forgotten without a flush (crash) and bootstrap runs again."""
        storage._reset()
        self.set_env(**env)
        return self.boot(data_file)

    def seed(self, base=None):
        base = base or self.data_dir
        self.write('data.json', json.dumps(DATA), base)
        self.write(RECOVERY, json.dumps({'version': 2, 'phase': 'committed'}), base)
        self.write('install_ops.json', '[]', base)
        self.write('ssh_known_hosts', '192.0.2.1 ssh-ed25519 AAAA\n', base)

    def manifest(self):
        return storage._decode_manifest(self.codec, self.s3.objects[PREFIX + 'manifest'][0])

    def history_manifest(self, key):
        return storage._decode_manifest(self.codec, self.s3.objects[key][0], history_aad(key))

    def content(self, rel, manifest=None):
        entry = (manifest or self.manifest())['files'][rel]
        return storage._get_blob(self.codec, entry)

    def rewrite_manifest(self, mutate):
        manifest = self.manifest()
        mutate(manifest)
        self.s3.force_put(PREFIX + 'manifest', storage._encode_manifest(self.codec, manifest))
        return manifest

    def foreign_commit(self, released=False):
        def mutate(manifest):
            manifest.update(commit_id='f' * 16, owner='intruder-1-beef', generation=manifest['generation'] + 1)
            manifest['lease'] = {'owner': 'intruder-1-beef', 'released': released, 'interval': 30}
        return self.rewrite_manifest(mutate)

    def sync(self):
        return storage._commit_round(storage._S, 'run')


class BootstrapTests(StorageCase):
    def test_fresh_init_on_empty_prefix(self):
        st = self.boot()
        manifest = self.manifest()
        self.assertTrue(self.data_dir.is_dir())
        self.assertEqual(manifest['format'], storage.FORMAT)
        self.assertEqual(manifest['generation'], 1)
        self.assertEqual(manifest['files'], {})
        self.assertEqual(manifest['lease'], {'owner': st.owner, 'released': False, 'interval': 30})
        self.assertIsNone(manifest['parent_commit_id'])
        self.assertEqual(manifest['panel_version'], 'v-test')
        self.assertTrue(st.initialised_here)
        self.assertEqual(st.fencing, 'enforced')
        self.assertEqual(self.s3.keys('probe/'), [])  # the probe cleans up
        create = [call for call in self.s3.calls if call[0] == 'put_object' and call[1] == PREFIX + 'manifest']
        self.assertEqual(create[0][3], '*')
        state = json.loads((self.data_dir / storage.STATE_NAME).read_text())
        self.assertEqual(state['last_commit_id'], manifest['commit_id'])
        self.assertIsNone(state['pending_commit_id'])

    def test_seed_migration_and_cold_restore_reproduce_the_tree(self):
        self.seed()
        self.write('data.json.runtime.lock', '{"runtime":true}')
        self.write('.recovery-tmp', 'x')
        self.boot()
        manifest = self.manifest()
        self.assertEqual(sorted(manifest['files']),
                         ['data.json', RECOVERY, 'install_ops.json', 'ssh_known_hosts'])
        self.assertEqual(json.loads(self.content('data.json')), DATA)
        # A blob is encrypted: no plaintext in the bucket.
        for key in self.s3.keys('blobs/'):
            self.assertNotIn(b'192.0.2.1', self.s3.objects[key][0])
        self.assertNotIn(b'admin', self.s3.objects[PREFIX + 'manifest'][0])
        storage.stop()
        other = self.root / 'other' / 'data.json'
        self.restart(other)
        self.assertEqual(tree(other.parent), tree(self.data_dir))
        self.assertNotIn('data.json.runtime.lock', tree(other.parent))
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(os.stat(other.parent / 'data.json').st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(other.parent / 'data.json.recovery').st_mode), 0o700)

    def test_refuses_init_when_blobs_or_history_exist_without_manifest(self):
        for sub in ('blobs/' + 'a' * 64, 'history/000000000003-' + 'b' * 16):
            with self.subTest(sub=sub):
                storage._reset()
                self.s3.objects.clear()
                self.s3.force_put(PREFIX + sub, b'x')
                self.set_env()
                with self.assertRaisesRegex(storage.StorageError, 'PANEL_S3_ALLOW_REINIT'):
                    self.boot()
                self.assertNotIn(PREFIX + 'manifest', self.s3.objects)
        storage._reset()
        self.set_env(PANEL_S3_ALLOW_REINIT='1')
        self.boot()
        self.assertIn(PREFIX + 'manifest', self.s3.objects)

    def test_warm_start_keeps_unuploaded_local_changes(self):
        self.seed()
        self.boot()
        self.write('install_ops.json', '[{"id": "late"}]')
        self.write('torrent_events.json', '{}')
        self.restart()  # crash: no final flush, lease still held
        self.assertEqual(self.sleeps, [])  # no lease wait for our own lineage
        manifest = self.manifest()
        self.assertEqual(manifest['generation'], 2)
        self.assertEqual(self.content('install_ops.json'), b'[{"id": "late"}]')
        self.assertIn('torrent_events.json', manifest['files'])
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))

    def test_cold_restore_into_an_empty_directory(self):
        self.seed()
        self.boot()
        storage.stop()
        self.assertTrue(self.manifest()['lease']['released'])
        other = self.root / 'fresh' / 'data.json'
        st = self.restart(other)
        self.assertEqual(self.sleeps, [])  # released lease: no wait
        self.assertEqual(tree(other.parent), tree(self.data_dir))
        self.assertEqual(st.generation, 3)
        self.assertFalse((other.parent / storage.RESTORE_MARKER).exists())
        self.assertTrue((other.parent / storage.STATE_NAME).exists())

    def test_cold_restore_moves_stray_files_aside_and_never_deletes(self):
        self.seed()
        self.boot()
        storage.stop()
        other = self.root / 'fresh'
        self.write('install_ops.json', 'local version', other)
        self.write('notes/extra.txt', 'keep me', other)
        self.restart(other / 'data.json')
        self.assertEqual((other / 'install_ops.json').read_bytes(), b'[]')
        displaced = list(other.glob(storage.DISPLACED_PREFIX + '*'))
        self.assertEqual(len(displaced), 1)
        self.assertEqual((displaced[0] / 'install_ops.json').read_text(), 'local version')
        self.assertEqual((displaced[0] / 'notes' / 'extra.txt').read_text(), 'keep me')
        self.assertNotIn('notes/extra.txt', self.manifest()['files'])

    def test_refuses_to_overwrite_a_foreign_local_data_file(self):
        self.seed()
        self.boot()
        storage.stop()
        other = self.root / 'compose-volume'
        self.write('data.json', '{"users": [{"id": "someone-else"}]}', other)
        with self.assertRaisesRegex(storage.StorageError, 'PANEL_S3_RESTORE_OVERWRITE'):
            self.restart(other / 'data.json')
        self.assertEqual(tree(other), {'data.json': b'{"users": [{"id": "someone-else"}]}'})
        self.assertFalse((other / storage.RESTORE_MARKER).exists())
        self.restart(other / 'data.json', PANEL_S3_RESTORE_OVERWRITE='1')
        self.assertEqual(json.loads((other / 'data.json').read_text()), DATA)
        displaced = list(other.glob(storage.DISPLACED_PREFIX + '*'))
        self.assertEqual((displaced[0] / 'data.json').read_text(), '{"users": [{"id": "someone-else"}]}')

    def test_restore_guard_ignores_a_state_file_of_another_prefix(self):
        self.seed()
        self.boot()
        storage.stop()  # the panel that owns the default prefix
        volume = self.root / 'compose-volume'
        self.write('data.json', '{"users": [{"id": "volume-owner"}]}', volume)
        self.restart(volume / 'data.json', PANEL_S3_PREFIX='old-prefix/')  # this volume mirrored another prefix
        storage.stop()
        self.assertTrue((volume / storage.STATE_NAME).exists())
        before = tree(volume)
        # The operator changes PANEL_S3_PREFIX: the old state file says nothing about this prefix.
        with self.assertRaisesRegex(storage.StorageError, 'PANEL_S3_RESTORE_OVERWRITE'):
            self.restart(volume / 'data.json')
        self.assertEqual(tree(volume), before)
        self.assertFalse(list(volume.glob(storage.DISPLACED_PREFIX + '*')))
        (volume / storage.STATE_NAME).write_text('not json')  # nor does an unreadable one
        with self.assertRaisesRegex(storage.StorageError, 'PANEL_S3_RESTORE_OVERWRITE'):
            self.restart(volume / 'data.json')
        self.assertEqual(tree(volume), before)
        self.restart(volume / 'data.json', PANEL_S3_RESTORE_OVERWRITE='1')
        self.assertEqual(json.loads((volume / 'data.json').read_text()), DATA)
        displaced = list(volume.glob(storage.DISPLACED_PREFIX + '*'))
        self.assertEqual((displaced[0] / 'data.json').read_text(), '{"users": [{"id": "volume-owner"}]}')

    def test_state_file_of_another_endpoint_counts_as_foreign(self):
        # Another panel keeps its state in a bucket of the same name, under the same prefix,
        # at a second provider.
        elsewhere = self.root / 'other-panel'
        self.write('data.json', json.dumps({'users': [{'id': 'other-panel'}], 'servers': []}), elsewhere)
        self.boot(elsewhere / 'data.json')
        storage.stop()
        second_provider = dict(self.s3.objects)
        self.s3.objects.clear()
        # This panel and its volume at the first provider.
        self.seed()
        self.restart()
        storage.stop()
        first_provider = dict(self.s3.objects)
        state = json.loads((self.data_dir / storage.STATE_NAME).read_text())
        self.assertEqual(state['endpoint'], 'http://127.0.0.1:9000')
        before = tree(self.data_dir)
        # Pointed at the second provider with the same bucket and prefix: no lineage, the guard applies.
        self.s3.objects = second_provider
        with self.assertRaisesRegex(storage.StorageError, 'PANEL_S3_RESTORE_OVERWRITE'):
            self.restart(PANEL_S3_ENDPOINT_URL='https://other-provider.example.test')
        self.assertEqual(tree(self.data_dir), before)
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))
        # A state file written before the endpoint was recorded matches any endpoint: warm start.
        self.s3.objects = first_provider
        del state['endpoint']
        (self.data_dir / storage.STATE_NAME).write_text(json.dumps(state))
        self.write('install_ops.json', '[{"after": "the stop"}]')
        self.restart()
        self.assertEqual(self.content('install_ops.json'), b'[{"after": "the stop"}]')
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))
        state = json.loads((self.data_dir / storage.STATE_NAME).read_text())
        self.assertEqual(state['endpoint'], 'http://127.0.0.1:9000')

    def test_interrupted_restore_resumes_over_a_newer_snapshot(self):
        # The restore marker shows that the local data.json came from this bucket, although the
        # state file is gone and the bucket moved on meanwhile: resume instead of refusing.
        self.seed()
        self.boot()
        storage.stop()
        files = self.manifest()['files']
        names = sorted(files)
        self.assertEqual(names[0], 'data.json')
        other = self.root / 'fresh'
        self.s3.fail('get_object', files[names[1]]['blob'], code='AccessDenied', status=403)
        with self.assertRaises(storage.StorageConfigError):
            self.restart(other / 'data.json')
        self.assertTrue((other / storage.RESTORE_MARKER).exists())
        self.assertFalse((other / storage.STATE_NAME).exists())
        restored = (other / 'data.json').read_bytes()
        self.restart()  # the first volume's panel changes data.json and stops
        self.write('data.json', json.dumps(dict(DATA, settings={'changed': True})))
        self.assertEqual(self.sync(), 'committed')
        storage.stop()
        self.restart(other / 'data.json')
        self.assertEqual(tree(other), tree(self.data_dir))
        self.assertFalse((other / storage.RESTORE_MARKER).exists())
        displaced = list(other.glob(storage.DISPLACED_PREFIX + '*'))
        self.assertEqual((displaced[0] / 'data.json').read_bytes(), restored)

    def test_interrupted_cold_restore_resumes_without_downloading_twice(self):
        self.seed()
        self.boot()
        storage.stop()
        files = self.manifest()['files']
        names = sorted(files)
        other = self.root / 'fresh'
        # The third file fails: the first two are already in place.
        self.s3.fail('get_object', files[names[2]]['blob'], code='AccessDenied', status=403)
        with self.assertRaises(storage.StorageConfigError):
            self.restart(other / 'data.json')
        self.assertTrue((other / storage.RESTORE_MARKER).exists())
        self.assertEqual(sorted(tree(other)), names[:2])
        gets = {rel: self.s3.count('get_object', files[rel]['blob']) for rel in names}
        self.restart(other / 'data.json')
        self.assertEqual(tree(other), tree(self.data_dir))
        self.assertFalse((other / storage.RESTORE_MARKER).exists())
        for rel in names[:2]:
            self.assertEqual(self.s3.count('get_object', files[rel]['blob']), gets[rel], rel)
        self.assertFalse(list(other.glob(storage.DISPLACED_PREFIX + '*')))

    def test_cold_restart_over_matching_files_downloads_and_moves_nothing(self):
        self.seed()
        self.boot()
        storage.stop()
        (self.data_dir / storage.STATE_NAME).unlink()  # e.g. a copy of the volume without the dot files
        gets = self.s3.count('get_object', 'blobs/')
        st = self.restart()
        self.assertEqual(self.s3.count('get_object', 'blobs/'), gets)
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))
        self.assertEqual(st.generation, 3)

    def test_wrong_encryption_key(self):
        self.seed()
        self.boot()
        storage._reset()
        self.set_env(PANEL_S3_ENCRYPTION_KEY=base64.b64encode(OTHER_MASTER).decode())
        with self.assertRaisesRegex(storage.StorageConfigError, 'encryption key does not match bucket'):
            self.boot(self.root / 'fresh' / 'data.json')

    def test_history_copied_over_the_manifest_fails_authentication(self):
        # A bucket writer without the encryption key copies an old history snapshot over
        # the manifest to bring back deleted users or revoked tokens.
        self.seed()
        self.boot()
        history = self.s3.keys('history/')[0]
        self.write('install_ops.json', '[1]')
        self.sync()
        self.s3.force_put(PREFIX + 'manifest', self.s3.objects[history][0])
        self.write('install_ops.json', '[2]')
        with self.assertRaises(storage._Fenced):
            self.sync()  # the running owner sees a foreign object and stops
        self.assertEqual(self.exits, [3])
        with self.assertRaisesRegex(storage.StorageConfigError, 'encryption key does not match bucket.*replaced'):
            self.restart()  # and the restarted one refuses instead of restoring generation 1
        self.assertEqual((self.data_dir / 'install_ops.json').read_bytes(), b'[2]')
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))
        # The snapshot still opens as what it is.
        self.assertEqual(storage._history_manifest(self.codec, 1)['generation'], 1)
        with self.assertRaises(storage.StorageError):
            storage._decode_manifest(self.codec, self.s3.objects[history][0],
                                     storage._history_aad(PREFIX, '000000000002-' + 'f' * 16))

    def test_manifest_older_than_the_state_file_is_refused(self):
        self.seed()
        self.boot()
        replay = self.s3.objects[PREFIX + 'manifest'][0]  # generation 1, captured by someone with bucket access
        self.write('install_ops.json', '[1]')
        self.sync()
        self.s3.force_put(PREFIX + 'manifest', replay)
        with self.assertLogs(storage.log, 'CRITICAL') as logs:
            with self.assertRaisesRegex(storage.StorageError, 'went back from generation 2 to 1'):
                self.restart()
        self.assertIn('went back from generation 2 to 1', '\n'.join(logs.output))
        self.assertEqual((self.data_dir / 'install_ops.json').read_bytes(), b'[1]')
        self.assertEqual(self.manifest()['generation'], 1)  # nothing claimed over it
        # A deliberate rollback is accepted once, as a cold restore. The replay is this
        # directory's own lineage, yet a warm start would commit the newer local file on top
        # and silently undo the rollback.
        st = self.restart(PANEL_S3_RESTORE_OVERWRITE='1')
        self.assertEqual(st.generation, 2)
        self.assertEqual(self.manifest()['parent_commit_id'], storage._decode_manifest(self.codec, replay)['commit_id'])
        self.assertEqual((self.data_dir / 'install_ops.json').read_bytes(), b'[]')
        self.assertEqual(self.content('install_ops.json'), b'[]')
        displaced = list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*'))
        self.assertEqual(len(displaced), 1)
        self.assertEqual((displaced[0] / 'install_ops.json').read_bytes(), b'[1]')
        self.assertEqual(self.sleeps, [])  # own lineage: no lease wait

    def test_manifest_that_goes_back_during_the_lease_wait_is_refused(self):
        self.seed()
        self.boot()
        storage.stop()
        replay = self.s3.objects[PREFIX + 'manifest'][0]  # generation 2, lease released
        self.restart()  # warm start: claim 3
        storage.stop()  # release 4: the state file says 4
        self.restart(self.root / 'other' / 'data.json')  # another panel claims 5 and keeps running
        storage._reset()
        replayed = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.advance(seconds)
            if not replayed:  # put back while this directory waits for the other panel's lease
                replayed.append(self.s3.force_put(PREFIX + 'manifest', replay))

        with mock.patch.object(storage, '_sleep', sleep):
            self.set_env()
            with self.assertRaisesRegex(storage.StorageError, 'went back from generation 4 to 2'):
                self.boot()
        self.assertEqual(self.sleeps, [30])
        self.assertEqual(self.manifest()['generation'], 2)  # nothing claimed over it
        self.assertFalse(list(self.data_dir.glob(storage.DISPLACED_PREFIX + '*')))
        self.assertTrue((self.data_dir / storage.STATE_NAME).exists())

    def test_unknown_manifest_format_is_never_touched(self):
        raw = json.dumps({'format': 'amnezia-panel-s3-v9'}).encode()
        body = storage._seal(self.codec.keys.enc, raw, storage._manifest_aad(PREFIX))
        self.s3.force_put(PREFIX + 'manifest', body)
        with self.assertRaisesRegex(storage.StorageError, 'unknown manifest format'):
            self.boot()
        self.assertEqual(self.s3.objects[PREFIX + 'manifest'][0], body)

    def test_lease_wait_until_released(self):
        self.seed()
        self.boot()  # this panel keeps running (lease held)
        storage._reset()
        released = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.advance(seconds)
            if len(self.sleeps) == 2:
                released.append(self.rewrite_manifest(lambda m: m['lease'].update(released=True)))

        with mock.patch.object(storage, '_sleep', sleep):
            self.set_env()
            self.boot(self.root / 'next' / 'data.json')
        self.assertEqual(self.sleeps, [30, 30])
        self.assertTrue(released)
        self.assertEqual(tree(self.root / 'next'), tree(self.data_dir))

    def test_lease_wait_until_stale(self):
        self.seed()
        self.boot()
        storage._reset()
        self.set_env()
        # The new pod's clock runs two minutes ahead: the lease age still comes from the
        # server's Date and Last-Modified, so the live owner does not look stale.
        with mock.patch.object(storage, '_now', lambda: self.clock.time() + 120):
            self.boot(self.root / 'next' / 'data.json')
        self.assertEqual(self.sleeps, [30, 30, 30])  # stale after 3 x 30 s of server time
        self.assertEqual(self.manifest()['lease']['owner'], storage._S.owner)

    def test_claim_conflict_starts_over(self):
        self.seed()
        self.boot()
        storage.stop()
        self.s3.fail('put_object', 'manifest', action='before', before=lambda: self.foreign_commit(released=True))
        st = self.restart(self.root / 'next' / 'data.json')
        manifest = self.manifest()
        self.assertEqual(manifest['owner'], st.owner)
        self.assertEqual(manifest['parent_commit_id'], 'f' * 16)

    def test_fencing_probe_ignored_or_rejected_conditions(self):
        # create_only: If-None-Match:* works but If-Match is ignored, so every runtime
        # commit (If-Match) would be unfenced; only the probe's third PUT can tell.
        # reject_400: the first conditional PUT gets a 400, and the same PUT without the
        # condition goes through, so the 400 was about the header.
        for mode in ('ignore', 'reject', 'create_only', 'reject_400'):
            with self.subTest(mode=mode):
                storage._reset()
                self.s3.objects.clear()
                self.s3.calls.clear()
                self.s3.conditions = mode
                self.set_env()
                self.assertEqual(self.boot().fencing, 'unfenced')
                self.assertEqual(self.s3.keys('probe/'), [])
                probes = [(call[2], call[3]) for call in self.s3.calls
                          if call[0] == 'put_object' and '/probe/' in call[1]]
                if mode == 'reject_400':
                    self.assertEqual(probes, [(None, '*'), (None, None)])
                else:
                    self.assertNotIn((None, None), probes)  # no plain PUT unless a first 400 needs one
                storage._reset()
                self.s3.objects.clear()
                self.set_env(PANEL_S3_FENCING='required')
                with self.assertRaisesRegex(storage.StorageConfigError, 'conditional writes'):
                    self.boot()

    def test_fencing_probe_plain_put_rides_out_an_outage(self):
        # The plain PUT that tells a header 400 from a configuration 400 retries temporary
        # errors like every other startup call, and reports a lasting outage as one.
        self.s3.conditions = 'reject_400'
        real_put = self.s3.put_object
        failures = {'left': 2}

        def put(**kwargs):
            plain = '/probe/' in kwargs['Key'] and not (kwargs.get('IfMatch') or kwargs.get('IfNoneMatch'))
            if plain and failures['left']:
                failures['left'] -= 1
                raise self.s3._error('PutObject', 'ServiceUnavailable', 503)
            return real_put(**kwargs)

        with mock.patch.object(self.s3, 'put_object', put):
            self.assertEqual(self.boot().fencing, 'unfenced')
        self.assertEqual(len(self.sleeps), 2)
        self.assertEqual(self.s3.keys('probe/'), [])

        storage._reset()
        self.s3.objects.clear()
        self.set_env()
        failures['left'] = 10 ** 6
        with mock.patch.object(self.s3, 'put_object', put):
            with self.assertRaisesRegex(storage.StorageError, 'fencing probe failed: S3 unreachable'):
                self.boot()
        self.assertNotIn(PREFIX + 'manifest', self.s3.objects)

    def test_fencing_probe_fails_fast_on_fatal_400s(self):
        # A wrong region, bucket name or token is a 400 as well; it must not read as
        # "conditional writes unsupported" (auto: a false UNFENCED, required: a wrong reason).
        for code, hint in (('AuthorizationHeaderMalformed', 'check PANEL_S3_REGION'),
                           ('ExpiredToken', 'credentials expired'), ('InvalidBucketName', 'check PANEL_S3_BUCKET'),
                           ('InvalidRequest', 'failed: InvalidRequest \\(400\\)')):
            for fencing in ('auto', 'required'):
                with self.subTest(code=code, fencing=fencing):
                    storage._reset()
                    self.s3.faults.clear()
                    self.s3.fail('put_object', 'probe/', code=code, status=400, times=10)
                    self.set_env(PANEL_S3_FENCING=fencing)
                    with self.assertNoLogs(storage.log, 'WARNING'):
                        with self.assertRaisesRegex(storage.StorageConfigError, hint) as caught:
                            self.boot()
                    self.assertNotIn('does not enforce conditional writes', str(caught.exception))
                    self.assertNotIn(PREFIX + 'manifest', self.s3.objects)
        self.assertEqual(self.sleeps, [])
        # Once the first probe PUT went through, a 400 on If-Match is about the header.
        real_put = self.s3.put_object

        def put(**kwargs):
            if kwargs.get('IfMatch') == '"0"':
                raise self.s3._error('PutObject', 'InvalidArgument', 400)
            return real_put(**kwargs)

        storage._reset()
        self.s3.faults.clear()
        self.set_env()
        with mock.patch.object(self.s3, 'put_object', put):
            self.assertEqual(self.boot().fencing, 'unfenced')

    def test_fencing_probe_400_without_the_condition_too_names_both_codes(self):
        # A first-probe 400 that a plain PUT of the same key repeats is not about the header.
        real_put = self.s3.put_object
        for plain, status, expected in (('InvalidRequest', 400, 'failed too: InvalidRequest \\(400\\)\\.'),
                                        ('InvalidArgument', 400, 'failed too\\. Check'),
                                        ('AccessDenied', 403, 'failed too: AccessDenied \\(403\\).*s3:ListBucket')):
            for fencing in ('auto', 'required'):
                with self.subTest(plain=plain, fencing=fencing):
                    probes = []

                    def put(**kwargs):
                        if '/probe/' not in kwargs['Key']:
                            return real_put(**kwargs)
                        probes.append((kwargs.get('IfMatch'), kwargs.get('IfNoneMatch')))
                        if kwargs.get('IfMatch') or kwargs.get('IfNoneMatch'):
                            raise self.s3._error('PutObject', 'InvalidArgument', 400)
                        raise self.s3._error('PutObject', plain, status)

                    storage._reset()
                    self.s3.calls.clear()
                    self.set_env(PANEL_S3_FENCING=fencing)
                    with mock.patch.object(self.s3, 'put_object', put), self.assertNoLogs(storage.log, 'WARNING'):
                        with self.assertRaisesRegex(storage.StorageConfigError,
                                                    'failed: InvalidArgument \\(400\\) with a conditional header, '
                                                    'and the same PUT without it ' + expected) as caught:
                            self.boot()
                    message = str(caught.exception)
                    self.assertEqual(message.count('InvalidArgument'), 1)
                    self.assertNotIn('does not enforce conditional writes', message)
                    self.assertEqual(probes, [(None, '*'), (None, None)])
                    self.assertEqual(self.s3.count('delete_object', 'probe/'), 1)  # cleaned up as usual
                    self.assertNotIn(PREFIX + 'manifest', self.s3.objects)
        self.assertEqual(self.sleeps, [])

    def test_access_denied_fails_fast_with_a_hint(self):
        self.s3.fail('get_object', 'manifest', code='AccessDenied', status=403)
        with self.assertRaisesRegex(storage.StorageConfigError, 's3:ListBucket'):
            self.boot()
        self.assertEqual(self.sleeps, [])

    def test_transient_errors_are_retried_within_the_startup_budget(self):
        self.s3.fail('get_object', 'manifest', action='timeout', times=2)
        self.boot()
        self.assertEqual(len(self.sleeps), 2)
        storage._reset()
        self.s3.fail('get_object', 'manifest', code='ServiceUnavailable', status=503, times=100)
        self.set_env()
        with self.assertRaisesRegex(storage.StorageError, 'unreachable'):
            self.boot()

    def test_key_safety(self):
        from credential_store import CredentialStore, default_key_path
        data = json.loads(json.dumps(DATA))
        data['servers'][0]['password'] = 'synthetic-password'
        self.data_dir.mkdir()
        CredentialStore(default_key_path(self.data_file)).seal_document(data)
        self.write('data.json', json.dumps(data))
        key = self.data_dir / 'data.json.credential.key'
        # Wrong key: refuse before anything is claimed.
        original = key.read_bytes()
        key.write_bytes(bytes(32))
        with self.assertRaisesRegex(storage.StorageError, 'does not open'):
            self.boot()
        self.assertNotIn(PREFIX + 'manifest', self.s3.objects)
        key.unlink()
        with self.assertRaisesRegex(storage.StorageError, 'key file is missing'):
            self.restart()
        key.write_bytes(original)
        if os.name != 'nt':
            os.chmod(key, 0o600)
        self.restart()
        self.assertIn('data.json.credential.key', self.manifest()['files'])

    def test_key_safety_covers_sealed_recovery_records(self):
        # Every server was deleted, but a recovery record still holds a sealed snapshot:
        # starting without the right key would make it unreadable for good.
        from credential_store import CredentialStore, default_key_path
        self.data_dir.mkdir()
        self.write('data.json', json.dumps(dict(DATA, servers=[])))
        envelope = CredentialStore(default_key_path(self.data_file)).seal_bytes(b'{"servers": []}', 'recovery-before')
        self.write(RECOVERY, json.dumps({'version': 2, 'phase': 'committed', 'before_sealed': envelope}))
        key = self.data_dir / 'data.json.credential.key'
        original = key.read_bytes()
        key.write_bytes(bytes(32))
        with self.assertRaisesRegex(storage.StorageError, 'does not open'):
            self.boot()
        key.unlink()
        with self.assertRaisesRegex(storage.StorageError, 'key file is missing'):
            self.restart()
        self.assertNotIn(PREFIX + 'manifest', self.s3.objects)
        key.write_bytes(original)
        if os.name != 'nt':
            os.chmod(key, 0o600)
        self.restart()
        self.assertIn(RECOVERY, self.manifest()['files'])

    def test_sigterm_during_the_lease_wait_exits_without_claiming(self):
        self.seed()
        self.boot()  # this panel keeps running (lease held)
        storage._reset()
        handlers = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.advance(seconds)
            handlers.append(signal.getsignal(signal.SIGTERM))
            storage._on_sigterm(signal.SIGTERM, None)  # kubectl delete while the new pod waits

        with mock.patch.object(storage, '_sleep', sleep):
            self.set_env()
            with self.assertRaises(SystemExit) as caught:
                self.boot(self.root / 'next' / 'data.json')
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(handlers, [storage._on_sigterm])  # installed at the start, not after the claim
        self.assertEqual(self.sleeps, [30])  # ended the wait at once
        self.assertFalse(storage._S.claimed)
        self.assertEqual(self.manifest()['generation'], 1)
        self.assertNotEqual(self.manifest()['lease']['owner'], storage._S.owner)
        # After a failed start the handler only chains to the previous one.
        chained = []
        with mock.patch.object(storage, '_previous_sigterm', lambda signum, frame: chained.append(signum)):
            storage._on_sigterm(signal.SIGTERM, None)
        self.assertEqual(chained, [signal.SIGTERM])

    def test_sigterm_during_the_claim_releases_the_lease_and_exits(self):
        self.seed()
        self.boot()
        storage.stop()
        handled = []
        self.s3.fail('put_object', 'manifest', action='before',
                     before=lambda: handled.append(storage._on_sigterm(signal.SIGTERM, None)))
        with self.assertRaises(SystemExit) as caught:
            self.restart(self.root / 'next' / 'data.json')
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(handled, [None])  # mid-PUT the handler only notes the signal
        manifest = self.manifest()
        self.assertEqual(manifest['owner'], storage._S.owner)
        self.assertTrue(manifest['lease']['released'])
        self.assertEqual(manifest['generation'], 4)  # the claim, then the release

    def test_sigterm_between_restored_files_stops_and_the_next_start_resumes(self):
        self.seed()
        self.boot()
        storage.stop()
        files = self.manifest()['files']
        names = sorted(files)
        other = self.root / 'fresh'
        self.s3.fail('get_object', files[names[1]]['blob'], action='before',
                     before=lambda: storage._on_sigterm(signal.SIGTERM, None))
        with self.assertRaises(SystemExit):
            self.restart(other / 'data.json')
        self.assertEqual(sorted(tree(other)), names[:2])  # the file in flight is finished, then it stops
        self.assertTrue((other / storage.RESTORE_MARKER).exists())
        self.assertEqual(self.manifest()['generation'], 2)
        self.restart(other / 'data.json')
        self.assertEqual(tree(other), tree(self.data_dir))
        self.assertFalse((other / storage.RESTORE_MARKER).exists())

    def test_second_sigterm_during_the_release_lets_it_finish(self):
        self.seed()
        self.boot()
        storage.stop()
        handled = []
        # The first SIGTERM lands during the claim PUT, the second during the release PUT that
        # bootstrap() runs on the main thread: raising there would abort it and keep the lease.
        self.s3.fail('put_object', 'manifest', action='before', times=2,
                     before=lambda: handled.append(storage._on_sigterm(signal.SIGTERM, None)))
        with self.assertRaises(SystemExit) as caught:
            self.restart(self.root / 'next' / 'data.json')
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(handled, [None, None])
        manifest = self.manifest()
        self.assertEqual(manifest['owner'], storage._S.owner)
        self.assertTrue(manifest['lease']['released'])
        self.assertEqual(manifest['generation'], 4)

    def test_sigterm_just_before_the_claim_exits_without_claiming(self):
        # The signal lands while the manifest is read; no sleep follows, so only the check
        # right before the claim can stop it.
        self.seed()
        self.s3.fail('get_object', 'manifest', action='before',
                     before=lambda: storage._on_sigterm(signal.SIGTERM, None))
        with self.assertRaises(SystemExit) as caught:
            self.boot()
        self.assertEqual(caught.exception.code, 0)
        self.assertTrue(storage._S.term_requested)
        self.assertFalse(storage._S.claimed)
        self.assertEqual(self.s3.count('put_object', 'manifest'), 0)
        self.assertNotIn(PREFIX + 'manifest', self.s3.objects)

    def test_sigterm_during_the_probe_exits_without_cleaning_up(self):
        # Leaving on SIGTERM: no cleanup request that could hang on a flaky S3; the probe
        # object is litter that the next start does not care about.
        real_put = self.s3.put_object
        probes = []

        def put(**kwargs):
            if '/probe/' in kwargs['Key']:
                probes.append(kwargs['Key'])
                if len(probes) == 2:
                    raise self.s3._error('PutObject', 'ServiceUnavailable', 503)
            return real_put(**kwargs)

        def sleep(seconds):
            self.sleeps.append(seconds)
            storage._on_sigterm(signal.SIGTERM, None)  # kubectl delete during the retry backoff

        with mock.patch.object(self.s3, 'put_object', put), mock.patch.object(storage, '_sleep', sleep):
            with self.assertRaises(SystemExit) as caught:
                self.boot()
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(self.sleeps, [1])
        self.assertEqual(self.s3.count('delete_object', 'probe/'), 0)
        self.assertEqual(self.s3.keys('probe/'), [probes[0]])
        self.assertNotIn(PREFIX + 'manifest', self.s3.objects)

    @unittest.skipIf(os.name == 'nt', 'a real SIGTERM to this process is POSIX only')
    def test_real_sigterm_ends_a_startup_sleep_at_once(self):
        self.seed()
        self.boot()  # this panel keeps running (lease held)
        storage._reset()
        self.set_env()
        sent = []

        def send():
            # Only into the lease wait's sleep, and only to our own handler.
            deadline = time.monotonic() + 10
            while not storage._S.pausing and time.monotonic() < deadline:
                time.sleep(0.01)
            if storage._S.pausing and signal.getsignal(signal.SIGTERM) is storage._on_sigterm:
                sent.append(time.monotonic())
                os.kill(os.getpid(), signal.SIGTERM)

        def real_sleep(seconds):
            # A real 30 s sleep in the lease wait; the fake clock follows it, so a
            # regression (no signal sent, or the handler not ending the sleep) fails
            # once the lease goes stale instead of hanging the suite.
            time.sleep(seconds)
            self.clock.advance(seconds)

        sender = threading.Thread(target=send, daemon=True)
        with mock.patch.object(storage, '_sleep', real_sleep):
            sender.start()
            with self.assertRaises(SystemExit) as caught:
                self.boot(self.root / 'next' / 'data.json')
            ended = time.monotonic()
        sender.join(10)
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(len(sent), 1)
        self.assertLess(ended - sent[0], 5)  # not after the 30 s sleep
        self.assertFalse(storage._S.claimed)
        self.assertEqual(self.manifest()['generation'], 1)

    @unittest.skipIf(os.name == 'nt', 'fcntl.flock is POSIX only')
    def test_owner_lock_refuses_a_second_process(self):
        import fcntl
        self.data_dir.mkdir()
        fd = os.open(self.data_dir / storage.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(storage.StorageError, 'already mirrors'):
            self.boot()

    def test_bootstrap_installs_hooks_and_is_idempotent(self):
        st = self.boot()
        self.assertIs(signal.getsignal(signal.SIGTERM), storage._on_sigterm)
        self.boot()
        self.assertIs(storage._S, st)
        self.assertEqual(self.manifest()['generation'], 1)


class CommitTests(StorageCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.st = self.boot()

    def manifest_puts(self):
        return self.s3.count('put_object', 'manifest')

    def test_commit_after_a_local_change_and_heartbeat(self):
        self.write('install_ops.json', '[1]')
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.content('install_ops.json'), b'[1]')
        self.assertEqual(self.manifest()['generation'], 2)
        self.assertFalse(storage.status()['pending'])
        puts = self.manifest_puts()
        self.assertEqual(self.sync(), 'unchanged')
        self.assertEqual(self.manifest_puts(), puts)
        self.clock.advance(31)  # no commit within the lease interval: heartbeat
        files = self.manifest()['files']
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.manifest()['files'], files)
        self.assertEqual(self.manifest()['generation'], 3)

    def test_unchanged_blobs_are_not_uploaded_again(self):
        blobs = self.s3.count('put_object', 'blobs/')
        self.write('install_ops.json', '[2]')
        self.sync()
        self.assertEqual(self.s3.count('put_object', 'blobs/'), blobs + 1)

    def test_second_walk_detects_a_change_and_redoes_the_round(self):
        real_scan = storage._scan
        calls = []

        def scan(st, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:  # between W1 and W2 of the first round
                self.write('install_ops.json', '[3, 3, 3]')
            return real_scan(st, *args, **kwargs)

        self.write('install_ops.json', '[3]')
        with mock.patch.object(storage, '_scan', scan):
            self.assertEqual(self.sync(), 'committed')
        self.assertGreaterEqual(len(calls), 4)
        self.assertEqual(self.content('install_ops.json'), b'[3, 3, 3]')

    def test_exclusion_rules(self):
        for rel in ('.hidden', 'x.tmp', 'y.temp', 'data.json.runtime.lock', '.recovery-abc',
                    '.dotdir/inside.json', 'sub/.dotfile', 'sub/z.tmp'):
            self.write(rel, 'excluded')
        self.write('sub/ok.json', '{}')
        try:
            os.symlink(self.data_dir / 'install_ops.json', self.data_dir / 'link.json')
        except (OSError, NotImplementedError):
            pass
        self.sync()
        self.assertEqual(sorted(self.manifest()['files']),
                         ['data.json', RECOVERY, 'install_ops.json', 'ssh_known_hosts', 'sub/ok.json'])

    def test_process_local_paths_inside_the_data_directory_are_never_mirrored(self):
        self.write('tunnels.json', '{"pid": 7}')
        self.write('bin/cloudflared', 'binary')
        env = {'TUNNEL_STATE_FILE': str(self.data_dir / 'tunnels.json'), 'TUNNEL_BIN_DIR': str(self.data_dir / 'bin'),
               'TMPDIR': str(self.data_dir / 'scratch')}
        cached = tempfile.tempdir  # gettempdir() caches; let each start look at TMPDIR afresh
        self.addCleanup(setattr, tempfile, 'tempdir', cached)
        storage._reset()
        self.set_env()
        with mock.patch.dict(os.environ, env):
            # TMPDIR does not exist yet, so this process uses another temp directory, but
            # children (acme.sh) inherit TMPDIR and may create it later.
            tempfile.tempdir = None
            self.boot()
            tempfile.tempdir = cached
        self.write('scratch/tmpfile', 'temp')
        self.write('install_ops.json', '[21]')
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(sorted(self.manifest()['files']),
                         ['data.json', RECOVERY, 'install_ops.json', 'ssh_known_hosts'])
        # An existing TMPDIR inside the data directory is refused outright.
        storage._reset()
        self.set_env()
        with mock.patch.dict(os.environ, env):
            tempfile.tempdir = None
            try:
                with self.assertRaisesRegex(storage.StorageConfigError, 'temp directory'):
                    self.boot()
            finally:
                tempfile.tempdir = cached

    def test_env_files_outside_the_data_directory(self):
        known_hosts = self.write('trust/known_hosts', 'pinned\n', self.root)
        (self.data_dir / 'ssh_known_hosts').unlink()  # the panel now uses SSH_KNOWN_HOSTS_FILE instead
        storage._reset()
        self.set_env(SSH_KNOWN_HOSTS_FILE=str(known_hosts))
        self.boot()
        self.assertEqual(self.content('@env/SSH_KNOWN_HOSTS_FILE'), b'pinned\n')
        storage.stop()
        other_hosts = self.root / 'trust2' / 'known_hosts'
        self.restart(self.root / 'fresh' / 'data.json', SSH_KNOWN_HOSTS_FILE=str(other_hosts))
        self.assertEqual(other_hosts.read_bytes(), b'pinned\n')
        storage.stop()
        # Without the variable the file lands at its default place inside D.
        self.restart(self.root / 'plain' / 'data.json')
        self.assertEqual((self.root / 'plain' / 'ssh_known_hosts').read_bytes(), b'pinned\n')
        self.assertFalse(list((self.root / 'plain').glob(storage.DISPLACED_PREFIX + '*')))

    def test_applied_then_timeout_is_success_not_fencing(self):
        self.write('install_ops.json', '[4]')
        self.s3.fail('put_object', 'manifest', action='apply_then_timeout')
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.exits, [])
        self.assertEqual(self.manifest()['commit_id'], self.st.last_commit_id)
        self.assertEqual(self.s3.objects[PREFIX + 'manifest'][1], self.st.etag)
        self.write('install_ops.json', '[5]')
        self.assertEqual(self.sync(), 'committed')  # the adopted ETag works for the next If-Match

    def test_lost_put_conflict_and_server_errors_are_retried(self):
        for action, code, status in (('timeout', None, None), ('error', 'ConditionalRequestConflict', 409),
                                     ('error', 'InternalError', 500)):
            with self.subTest(code=code):
                self.write('install_ops.json', json.dumps([action, code]))
                self.s3.fail('put_object', 'manifest', action=action, code=code, status=status)
                self.assertEqual(self.sync(), 'committed')
                self.assertEqual(self.content('install_ops.json'), json.dumps([action, code]).encode())
        self.assertEqual(self.exits, [])

    def test_lost_response_of_an_earlier_own_commit_is_adopted(self):
        self.write('install_ops.json', '[6]')
        self.s3.fail('put_object', 'manifest', action='apply_then_timeout')
        self.s3.fail('get_object', 'manifest', action='timeout', times=10)
        with self.assertRaises(Exception):
            self.sync()
        self.s3.faults.clear()
        self.write('install_ops.json', '[7]')
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.exits, [])
        self.assertEqual(self.content('install_ops.json'), b'[7]')

    def test_foreign_commit_fences_and_exits(self):
        self.foreign_commit()
        self.write('install_ops.json', '[8]')
        with self.assertRaises(storage._Fenced):
            self.sync()
        self.assertEqual(self.exits, [3])
        self.assertTrue(storage.status()['fenced'])
        self.assertEqual(self.manifest()['owner'], 'intruder-1-beef')
        puts = self.s3.count('put_object', 'manifest')
        storage.stop()
        self.assertEqual(self.s3.count('put_object', 'manifest'), puts)
        self.assertEqual(self.sync(), 'closed')

    def test_unfenced_provider_detects_a_foreign_commit_by_reading_first(self):
        storage._reset()
        self.s3.objects.clear()
        self.s3.conditions = 'ignore'
        self.set_env()
        self.boot()
        self.write('install_ops.json', '[9]')
        self.assertEqual(self.sync(), 'committed')
        self.foreign_commit()
        self.write('install_ops.json', '[10]')
        with self.assertRaises(storage._Fenced):
            self.sync()
        self.assertEqual(self.exits, [3])
        self.assertEqual(self.manifest()['owner'], 'intruder-1-beef')

    def test_manifest_deleted_under_the_owner_is_recreated_with_every_blob(self):
        for key in list(self.s3.objects):
            del self.s3.objects[key]
        self.write('install_ops.json', '[11]')
        self.assertEqual(self.sync(), 'committed')
        manifest = self.manifest()
        self.assertEqual(manifest['generation'], 2)
        for entry in manifest['files'].values():
            self.assertIn(PREFIX + 'blobs/' + entry['blob'], self.s3.objects)
        self.assertEqual(self.exits, [])

    def test_final_flush_releases_the_lease_and_stops_commits(self):
        generation = self.manifest()['generation']
        storage.stop()
        manifest = self.manifest()
        self.assertTrue(manifest['lease']['released'])
        self.assertEqual(manifest['generation'], generation + 1)  # even though nothing changed
        puts = self.manifest_puts()
        self.write('install_ops.json', '[12]')
        self.assertEqual(self.sync(), 'closed')
        storage.stop()
        storage.start()
        self.assertEqual(self.manifest_puts(), puts)

    def test_sync_thread_commits_and_final_flush_via_stop(self):
        storage._reset()
        self.set_env(PANEL_S3_SYNC_INTERVAL='0.02')
        self.boot()
        storage.start()
        storage.start()  # idempotent
        self.write('install_ops.json', '[13]')
        deadline = time.time() + 10
        while time.time() < deadline and self.content('install_ops.json') != b'[13]':
            time.sleep(0.02)
        self.assertEqual(self.content('install_ops.json'), b'[13]')
        storage.stop(timeout=10)
        self.assertTrue(self.manifest()['lease']['released'])
        self.assertFalse(storage._S.thread.is_alive())

    def test_sigterm_handler_flushes_then_chains(self):
        chained = []
        with mock.patch.object(storage, '_previous_sigterm', lambda signum, frame: chained.append(signum)):
            storage._on_sigterm(signal.SIGTERM, None)
        self.assertEqual(chained, [signal.SIGTERM])
        self.assertTrue(self.manifest()['lease']['released'])
        with mock.patch.object(storage, '_previous_sigterm', signal.SIG_DFL):
            with self.assertRaises(SystemExit):
                storage._on_sigterm(signal.SIGTERM, None)

    def test_second_sigterm_during_the_handlers_own_flush_lets_it_finish(self):
        # Before the startup event the handler commits the release itself, on the main
        # thread; a second SIGTERM inside that PUT must not abort it.
        handled = []
        self.s3.fail('put_object', 'manifest', action='before',
                     before=lambda: handled.append(storage._on_sigterm(signal.SIGTERM, None)))
        with mock.patch.object(storage, '_previous_sigterm', signal.SIG_DFL):
            with self.assertRaises(SystemExit) as caught:
                storage._on_sigterm(signal.SIGTERM, None)
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(handled, [None])
        self.assertTrue(self.manifest()['lease']['released'])
        self.assertTrue(storage._S.closed)

    def test_shutdown_waits_share_one_deadline(self):
        stuck = threading.Event()
        self.addCleanup(stuck.set)
        self.st.thread = threading.Thread(target=stuck.wait, daemon=True)  # a sync thread hung on S3
        self.st.thread.start()
        self.st.flush_done = done = HungFlush(self.clock)
        storage.stop(timeout=10)  # a caller with a shorter limit of its own
        chained = []
        with mock.patch.object(storage, '_previous_sigterm', lambda signum, frame: chained.append(signum)):
            storage._on_sigterm(signal.SIGTERM, None)  # uvicorn re-raises the SIGTERM it captured
        storage.stop()  # atexit
        asyncio.run(storage.stop_async())
        # 25 s in total from the first request, not 25 s per waiter.
        self.assertEqual(done.waits, [10.0, 15.0, 0.0])
        self.assertEqual(chained, [signal.SIGTERM])
        self.assertEqual(self.sleeps, [])  # the flush was requested already: no drain

    def test_stop_async_waits_without_the_default_executor(self):
        storage._reset()
        self.set_env(PANEL_S3_SYNC_INTERVAL='0.02')
        self.boot()
        storage.start()
        self.write('install_ops.json', '[30]')
        hung = threading.Event()
        self.addCleanup(hung.set)

        async def shutdown():
            loop = asyncio.get_running_loop()
            loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
            busy = loop.run_in_executor(None, hung.wait, 30)  # a hung SSH call holds the only worker
            await asyncio.wait_for(storage.stop_async(), 10)
            released = self.manifest()['lease']['released']
            hung.set()
            await busy
            return released

        self.assertTrue(asyncio.run(shutdown()))
        self.assertEqual(self.content('install_ops.json'), b'[30]')
        self.assertFalse(storage._S.thread.is_alive())

    def test_stop_async_flushes_on_its_own_thread_when_the_sync_thread_is_not_running(self):
        names = []
        real = storage._final_flush

        def flush(st):
            names.append(threading.current_thread().name)
            real(st)

        with mock.patch.object(storage, '_final_flush', flush):
            asyncio.run(storage.stop_async())
        self.assertEqual(names, ['s3-final-flush'])
        self.assertTrue(self.manifest()['lease']['released'])
        storage.start()
        self.assertIsNone(storage._S.thread)  # nothing commits after the final flush

    def front_shutdown(self, late_writes):
        """PANEL_FRONT=1: SIGTERM reaches our handler first while requests may still be writing."""
        storage._reset()
        self.set_env(PANEL_S3_SYNC_INTERVAL='100', PANEL_S3_LEASE_INTERVAL='300')
        self.boot()
        storage.start()
        polls = []

        def sleep(seconds):
            polls.append(seconds)
            self.clock.advance(seconds)
            if len(polls) in late_writes:  # a request in the uvicorn thread writes state
                self.write('install_ops.json', json.dumps(['late'] * len(polls)))

        chained = []
        with mock.patch.object(storage, '_sleep', sleep), \
                mock.patch.object(storage, '_previous_sigterm', lambda signum, frame: chained.append(signum)):
            storage._on_sigterm(signal.SIGTERM, None)
        self.assertEqual(chained, [signal.SIGTERM])
        self.assertTrue(self.manifest()['lease']['released'])
        return polls

    def test_front_mode_sigterm_waits_for_quiet_files_before_the_final_flush(self):
        polls = self.front_shutdown(late_writes={2, 4})
        self.assertEqual(sum(polls), 2.0 + storage.DRAIN_QUIET)  # quiet for 3 s after the last write
        self.assertEqual(self.content('install_ops.json'), json.dumps(['late'] * 4).encode())

    def test_front_mode_drain_is_capped(self):
        polls = self.front_shutdown(late_writes=set(range(1, 1000)))
        self.assertEqual(sum(polls), storage.DRAIN_LIMIT)
        self.assertEqual(self.content('install_ops.json'), json.dumps(['late'] * len(polls)).encode())

    def test_sigterm_after_the_shutdown_hook_does_not_drain(self):
        storage._reset()
        self.set_env(PANEL_S3_SYNC_INTERVAL='100', PANEL_S3_LEASE_INTERVAL='300')
        self.boot()
        storage.start()
        asyncio.run(storage.stop_async())  # plain mode: uvicorn drained, then its shutdown hook ran
        chained = []
        with mock.patch.object(storage, '_previous_sigterm', lambda signum, frame: chained.append(signum)):
            storage._on_sigterm(signal.SIGTERM, None)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(chained, [signal.SIGTERM])
        self.assertTrue(self.manifest()['lease']['released'])

    def guard_tripped(self, name):
        files = self.manifest()['files']
        self.assertEqual(self.sync(), 'unchanged')
        self.assertEqual(storage.status()['last_error'], 'guard:' + name)
        self.assertTrue(storage.status()['pending'])
        self.assertEqual(self.manifest()['files'], files)
        self.clock.advance(31)  # heartbeat keeps the last good map
        self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.manifest()['files'], files)
        # A one-shot override at the next start lets it through, then guards are armed again.
        storage._reset()
        self.set_env(PANEL_S3_ALLOW_SHRINK='1')
        self.boot()
        self.assertFalse(storage._S.cfg.allow_shrink)
        self.assertIsNone(storage.status()['last_error'])
        return self.manifest()['files']

    def test_unstable_tree_still_heartbeats_the_last_consistent_snapshot(self):
        files = self.manifest()['files']
        self.write('install_ops.json', '[20]')
        with mock.patch.object(storage, '_build_map', return_value=None):
            self.assertEqual(self.sync(), 'unstable')
            self.clock.advance(31)
            self.assertEqual(self.sync(), 'committed')
        self.assertEqual(self.manifest()['files'], files)
        self.assertEqual(self.manifest()['generation'], 2)
        self.assertTrue(storage.status()['pending'])
        self.assertEqual(self.sync(), 'committed')
        self.assertFalse(storage.status()['pending'])
        self.assertEqual(self.content('install_ops.json'), b'[20]')

    def test_guard_data_file_removed(self):
        (self.data_dir / 'data.json').unlink()
        self.assertNotIn('data.json', self.guard_tripped('data_file_removed'))

    def test_guard_users_and_servers_emptied(self):
        self.write('data.json', json.dumps({'users': [], 'servers': [], 'settings': {}}))
        self.guard_tripped('users_and_servers_emptied')
        self.assertEqual(json.loads(self.content('data.json'))['users'], [])

    def test_guard_recovery_record_removed(self):
        (self.data_dir / RECOVERY).unlink()
        self.assertNotIn(RECOVERY, self.guard_tripped('recovery_record_removed'))

    def test_guard_credential_key_changed(self):
        self.write('data.json.credential.key', b'k' * 32)
        self.sync()
        self.write('data.json.credential.key', b'j' * 32)
        self.guard_tripped('credential_key_changed')

    def test_guard_sealed_data_without_key(self):
        data = json.loads(json.dumps(DATA))
        data['servers'][0]['ssh_credentials'] = {'format': 'amnezia-ssh-credentials-v1'}
        self.write('data.json', json.dumps(data))
        self.assertEqual(self.sync(), 'unchanged')
        self.assertEqual(storage.status()['last_error'], 'guard:credential_key_missing')

    def test_guard_clears_when_the_tree_recovers(self):
        (self.data_dir / 'data.json').unlink()
        self.sync()
        self.write('data.json', json.dumps(DATA))
        self.write('install_ops.json', '[14]')
        self.assertEqual(self.sync(), 'committed')
        self.assertIsNone(storage.status()['last_error'])

    def test_history_is_written_at_most_hourly(self):
        self.assertEqual(len(self.s3.keys('history/')), 1)  # the seeding commit
        self.write('install_ops.json', '[15]')
        self.sync()
        self.assertEqual(len(self.s3.keys('history/')), 1)
        self.clock.advance(31)
        self.sync()  # heartbeat, no file change
        self.clock.advance(3600)
        self.write('install_ops.json', '[16]')
        self.sync()
        history = self.s3.keys('history/')
        self.assertEqual(len(history), 2)
        latest = self.manifest()
        self.assertEqual(history[-1], PREFIX + 'history/%012d-%s' % (latest['generation'], latest['commit_id']))
        self.assertEqual(self.history_manifest(history[-1]), latest)
        # Sealed for its own name: the bytes can never pass as the manifest.
        self.assertNotEqual(self.s3.objects[history[-1]][0], self.s3.objects[PREFIX + 'manifest'][0])

    def test_status_has_no_secrets(self):
        self.write('install_ops.json', '[17]')
        self.sync()
        status = storage.status()
        text = json.dumps(status)
        for secret in (SECRET, ACCESS, base64.b64encode(MASTER).decode()):
            self.assertNotIn(secret, text)
        self.assertEqual(set(status), {'backend', 'bucket', 'prefix', 'endpoint', 'region', 'fencing', 'generation',
                                       'files', 'bytes', 'last_commit_at', 'last_error', 'last_error_at', 'fenced',
                                       'pending', 'lease_owner'})
        self.assertEqual(status['endpoint'], 'http://127.0.0.1:9000')
        self.assertEqual(status['fencing'], 'enforced')
        self.assertEqual(status['generation'], 2)
        self.assertEqual(status['files'], 4)
        self.assertIsNone(status['last_error'])
        self.assertEqual(status['lease_owner'], self.st.owner)
        self.assertRegex(status['last_commit_at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

    def wait_for(self, predicate):
        deadline = time.time() + 10
        while time.time() < deadline and not predicate():
            time.sleep(0.01)
        return predicate()

    def test_transient_runtime_error_is_reported_and_recovers(self):
        storage._reset()
        self.set_env(PANEL_S3_SYNC_INTERVAL='0.02')
        self.boot()
        self.s3.fail('put_object', 'blobs/', code='SlowDown', status=503, times=1000)
        storage.start()  # the real sync loop meets the failing client
        self.write('install_ops.json', '[18]')
        self.assertTrue(self.wait_for(lambda: storage.status()['last_error'] == 'SlowDown (503)'),
                        storage.status()['last_error'])
        with self.s3.lock:
            self.s3.faults.clear()
        self.assertTrue(self.wait_for(lambda: storage.status()['last_error'] is None))
        self.assertTrue(self.wait_for(lambda: self.content('install_ops.json') == b'[18]'))


class GarbageCollectionTests(StorageCase):
    def history(self, key_age, blob, generation):
        manifest = {'format': storage.FORMAT, 'generation': generation, 'commit_id': '%016x' % generation,
                    'parent_commit_id': None, 'owner': 'old', 'committed_at': storage._iso(self.clock.time()),
                    'panel_version': 'v', 'lease': {'owner': 'old', 'released': True, 'interval': 30},
                    'files': {'old.json': {'blob': blob, 'sha256': '0' * 64, 'size': 1}}}
        key = PREFIX + 'history/%012d-%016x' % (generation, generation)
        self.s3.force_put(key, storage._encode_manifest(self.codec, manifest, history_aad(key)),
                          self.clock.time() - key_age)
        return key

    def test_gc_keeps_live_and_young_blobs_and_deletes_old_unreferenced_ones(self):
        self.seed()
        self.boot()
        st = self.restart()  # warm start: this process did not initialise the prefix
        self.assertFalse(st.initialised_here)
        now = self.clock.time()
        blob = lambda c: PREFIX + 'blobs/' + c * 64
        self.s3.force_put(blob('a'), b'x', now - 7200)        # old, unreferenced
        self.s3.force_put(blob('b'), b'x', now - 60)          # young, unreferenced
        self.s3.force_put(blob('c'), b'x', now - 7200)        # old, kept by retained history
        self.s3.force_put(blob('d'), b'x', now - 9 * 86400)   # only in expired history
        kept_history = self.history(7200, 'c' * 64, 1)
        expired_history = self.history(8 * 86400, 'd' * 64, 0)
        live = [PREFIX + 'blobs/' + e['blob'] for e in self.manifest()['files'].values()]
        for key in live:
            self.s3.objects[key][2] = now - 7200
        self.assertEqual(storage._maybe_gc(st), 3)
        self.assertNotIn(blob('a'), self.s3.objects)
        self.assertNotIn(blob('d'), self.s3.objects)
        self.assertNotIn(expired_history, self.s3.objects)
        for key in [blob('b'), blob('c'), kept_history] + live:
            self.assertIn(key, self.s3.objects)
        self.assertEqual(self.s3.count('delete_object', 'blobs/'), 2)
        lists = self.s3.count('list_objects_v2')
        self.assertEqual(storage._maybe_gc(st), 0)  # at most hourly
        self.assertEqual(self.s3.count('list_objects_v2'), lists)
        self.clock.advance(3601)
        storage._maybe_gc(st)
        self.assertGreater(self.s3.count('list_objects_v2'), lists)

    def test_failed_gc_never_leaves_a_deleted_blob_marked_as_uploaded(self):
        self.seed()
        self.boot()
        st = self.restart()  # warm start: GC is allowed
        record = self.data_dir / RECOVERY
        saved = record.read_bytes()
        record.unlink()  # a guard holds the next commits back...
        self.write('notes.json', 'A' * 50)
        self.clock.advance(31)
        self.sync()
        blob = st.known['notes.json']['blob']
        self.assertIn(blob, st.uploaded)  # ...so this blob is uploaded but not committed
        self.assertNotIn('notes.json', self.manifest()['files'])
        self.clock.advance(7200)
        self.sync()  # heartbeat of the last good map
        orphan = 'f' * 64
        self.assertLess(blob, orphan)
        self.s3.force_put(PREFIX + 'blobs/' + orphan, b'x', self.clock.time() - 7200)
        self.s3.fail('delete_object', orphan, code='InternalError', status=500)
        self.assertEqual(storage._maybe_gc(st), 0)  # deleted the old uncommitted blob, then failed
        self.assertNotIn(PREFIX + 'blobs/' + blob, self.s3.objects)
        record.write_bytes(saved)  # the guard clears: notes.json is committed now
        self.clock.advance(31)
        self.assertEqual(self.sync(), 'committed')
        entry = self.manifest()['files']['notes.json']
        self.assertEqual(entry['blob'], blob)
        self.assertIn(PREFIX + 'blobs/' + blob, self.s3.objects)  # uploaded again
        self.assertEqual(self.content('notes.json'), b'A' * 50)

    def test_gc_never_runs_in_the_initialising_process_or_when_not_ours(self):
        st = self.boot()
        self.s3.force_put(PREFIX + 'blobs/' + 'a' * 64, b'x', self.clock.time() - 7200)
        self.assertEqual(storage._maybe_gc(st), 0)
        st = self.restart()
        self.foreign_commit()
        self.assertEqual(storage._maybe_gc(st), 0)
        self.assertIn(PREFIX + 'blobs/' + 'a' * 64, self.s3.objects)


class CliTests(StorageCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch('logging.basicConfig')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.seed()
        self.boot()

    def cli(self, *argv):
        self.set_env()  # bootstrap popped the secrets
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = storage.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_status_prints_the_manifest_without_secrets(self):
        code, out, _ = self.cli('status')
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report['manifest']['generation'], 1)
        self.assertFalse(report['manifest']['lease']['released'])
        self.assertEqual(report['manifest']['files'], 4)
        for secret in (SECRET, ACCESS, base64.b64encode(MASTER).decode()):
            self.assertNotIn(secret, out)
        self.assertEqual(report['endpoint'], 'http://127.0.0.1:9000')
        puts = self.s3.count('put_object')
        self.cli('status')
        self.assertEqual(self.s3.count('put_object'), puts)  # read-only: no fencing probe

    def test_pull_push_round_trip(self):
        storage.stop()  # scale to 0: the lease is released
        pulled = self.root / 'offline'
        code, _, err = self.cli('pull', str(pulled))
        self.assertEqual(code, 0, err)
        self.assertEqual(tree(pulled), tree(self.data_dir))
        info = json.loads((pulled / storage.PULL_NAME).read_text())
        self.assertEqual(info['generation'], 2)
        self.write('install_ops.json', '[{"offline": true}]', pulled)
        (pulled / 'data.json.lifecycle-uncertain.json').write_text('{}')
        code, _, err = self.cli('push', str(pulled))
        self.assertEqual(code, 0, err)
        manifest = self.manifest()
        self.assertEqual(manifest['generation'], 3)
        self.assertTrue(manifest['lease']['released'])
        self.assertTrue(manifest['owner'].startswith('cli-'))
        self.assertEqual(self.content('install_ops.json'), b'[{"offline": true}]')
        # A second push from the same pull would overwrite generation 3.
        code, _, err = self.cli('push', str(pulled))
        self.assertEqual(code, 2)
        self.assertIn('pull again', err)
        # The panel starts again with a cold restore of the pushed state.
        st = self.restart()
        self.assertEqual((self.data_dir / 'install_ops.json').read_bytes(), b'[{"offline": true}]')
        self.assertEqual(st.generation, 4)
        self.assertEqual(self.sleeps, [])

    def test_push_refuses_while_the_lease_is_held_and_guards_shrink(self):
        pulled = self.root / 'offline'
        self.assertEqual(self.cli('pull', str(pulled))[0], 0)
        code, _, err = self.cli('push', str(pulled))
        self.assertEqual(code, 2)
        self.assertIn('still holds the lease', err)
        storage._reset()  # the panel crashed; after 3 lease intervals the lease is stale
        self.clock.advance(91)
        (pulled / 'data.json').unlink()
        code, _, err = self.cli('push', str(pulled))
        self.assertEqual(code, 2)
        self.assertIn('guard:data_file_removed', err)
        code, _, err = self.cli('push', str(pulled), '--allow-shrink')
        self.assertEqual(code, 0, err)
        self.assertNotIn('data.json', self.manifest()['files'])

    def test_push_needs_a_pull_record_and_pull_needs_an_empty_directory(self):
        storage.stop()
        code, _, err = self.cli('push', str(self.data_dir))
        self.assertEqual(code, 2)
        self.assertIn(storage.PULL_NAME, err)
        code, _, err = self.cli('pull', str(self.data_dir))
        self.assertEqual(code, 2)
        self.assertIn('empty directory', err)

    def test_pull_an_older_generation_from_history(self):
        self.write('install_ops.json', '[19]')
        self.sync()
        pulled = self.root / 'old'
        code, _, err = self.cli('pull', str(pulled), '--generation', '1')
        self.assertEqual(code, 0, err)
        self.assertEqual((pulled / 'install_ops.json').read_bytes(), b'[]')
        info = json.loads((pulled / storage.PULL_NAME).read_text())
        self.assertEqual((info['generation'], info['base_generation']), (1, 2))
        code, _, err = self.cli('pull', str(self.root / 'missing'), '--generation', '7')
        self.assertEqual(code, 2)
        self.assertIn('no history snapshot', err)


class BotocoreClientTests(EnvCase):
    @unittest.skipIf(ClientError is None, 'botocore is not installed')
    def test_real_client_configuration(self):
        os.environ.update({'PANEL_STORAGE': 's3', 'PANEL_S3_BUCKET': 'panel-test', 'PANEL_S3_REGION': 'ru-msk',
                           'PANEL_S3_ENDPOINT_URL': 'https://hb.example.test', 'PANEL_S3_ACCESS_KEY_ID': ACCESS,
                           'PANEL_S3_SECRET_ACCESS_KEY': SECRET,
                           'PANEL_S3_ENCRYPTION_KEY': base64.b64encode(MASTER).decode()})
        cfg = storage._load_config()
        client = storage._make_client(cfg, 1)
        self.assertEqual(client.meta.endpoint_url, 'https://hb.example.test')
        self.assertEqual(client.meta.region_name, 'ru-msk')
        self.assertEqual(client.meta.config.retries, {'mode': 'standard', 'total_max_attempts': 1})
        self.assertEqual(client.meta.config.s3, {'addressing_style': 'path'})
        self.assertEqual(client.meta.config.read_timeout, 20)
        self.assertEqual(client.meta.config.request_checksum_calculation, 'when_required')
        # A namespace-wide AWS_ENDPOINT_URL must not silently redirect the panel.
        os.environ.update({'PANEL_S3_ACCESS_KEY_ID': ACCESS, 'PANEL_S3_SECRET_ACCESS_KEY': SECRET,
                           'PANEL_S3_ENCRYPTION_KEY': base64.b64encode(MASTER).decode(),
                           'AWS_ENDPOINT_URL': 'https://elsewhere.example.test'})
        del os.environ['PANEL_S3_ENDPOINT_URL']
        cfg = storage._load_config()
        self.assertEqual(cfg.addressing_style, 'auto')
        client = storage._make_client(cfg, 3)
        self.assertNotIn('elsewhere', client.meta.endpoint_url)
        self.assertEqual(client.meta.config.retries, {'mode': 'standard', 'total_max_attempts': 3})

    def test_round_trip_through_real_botocore_when_moto_is_available(self):
        # Optional (moto is not a panel dependency): real request shapes for If-Match /
        # If-None-Match, list pagination and the probe against an emulated S3.
        try:
            from moto import mock_aws
        except ImportError:
            self.skipTest('moto is not installed')
        os.environ.update({'PANEL_STORAGE': 's3', 'PANEL_S3_BUCKET': 'panel-moto-test', 'PANEL_S3_REGION': 'us-east-1',
                           'PANEL_S3_ACCESS_KEY_ID': ACCESS, 'PANEL_S3_SECRET_ACCESS_KEY': SECRET,
                           'PANEL_S3_ENCRYPTION_KEY': base64.b64encode(MASTER).decode(),
                           'DATA_FILE': str(self.data_file)})
        environment = dict(os.environ)
        with mock_aws():
            import botocore.session
            botocore.session.get_session().create_client(
                's3', region_name='us-east-1', aws_access_key_id=ACCESS,
                aws_secret_access_key=SECRET).create_bucket(Bucket='panel-moto-test')
            self.write('data.json', json.dumps(DATA))
            self.write(RECOVERY, '{}')
            storage.bootstrap(str(self.data_file), app_dir=str(self.app_dir), panel_version='v')
            self.assertEqual(storage._S.fencing, 'enforced')
            self.write('install_ops.json', '[1]')
            self.assertEqual(storage._commit_round(storage._S, 'run'), 'committed')
            storage.stop()
            storage._reset()
            other = self.root / 'other' / 'data.json'
            os.environ.update(environment, DATA_FILE=str(other))
            storage.bootstrap(str(other), app_dir=str(self.app_dir), panel_version='v')
            self.assertEqual(tree(other.parent), tree(self.data_dir))
            self.assertEqual(storage.status()['generation'], 4)


if __name__ == '__main__':
    unittest.main()
