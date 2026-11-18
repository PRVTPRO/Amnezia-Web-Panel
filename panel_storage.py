"""Optional S3 mirror of the panel data directory.

PANEL_STORAGE unset or ``local`` (the default): nothing here does anything.

PANEL_STORAGE=s3: the panel keeps working on its local data directory
D = dirname(DATA_FILE), e.g. a Kubernetes emptyDir. bootstrap() restores D from
the bucket before anything reads it, then a single sync thread mirrors D back
as an encrypted, atomic, fenced snapshot: content-addressed blobs plus one
manifest written with conditional PUTs. Configuration is env-only because
data.json itself lives in the bucket. See docs/S3_STORAGE.md.

CLI (same environment variables):
    python panel_storage.py status
    python panel_storage.py pull <dir> [--generation N]
    python panel_storage.py push <dir> [--allow-shrink]
"""
import asyncio
import atexit
import base64
import binascii
from datetime import datetime, timezone
import email.utils
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import shutil
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


log = logging.getLogger('panel_storage')

FORMAT = 'amnezia-panel-s3-v1'
MAGIC = b'APS3'
ENVELOPE_VERSION = 1
NONCE_BYTES = 12
KEY_BYTES = 32
DEFAULT_PREFIX = 'amnezia-panel/'

STATE_NAME = '.s3-sync-state.json'
LOCK_NAME = '.s3-owner.lock'
RESTORE_MARKER = '.s3-restore-pending'
DISPLACED_PREFIX = '.s3-displaced-'
PULL_NAME = '.s3-pull.json'
EXCLUDED_SUFFIXES = ('.tmp', '.temp', '.runtime.lock')
ENV_FILES = ('CREDENTIAL_KEY_FILE', 'SSH_KNOWN_HOSTS_FILE')
SECRET_VARS = ('PANEL_S3_ACCESS_KEY_ID', 'PANEL_S3_SECRET_ACCESS_KEY', 'PANEL_S3_ENCRYPTION_KEY')

WARN_FILES = 5000
WARN_BYTES = 256 * 1024 * 1024
RACY_SECONDS = 2
MAX_ROUND_REDO = 5
CLAIM_ATTEMPTS = 5
RESTORE_ATTEMPTS = 3
PUT_ATTEMPTS = 3
BACKOFF_CAP = 60
GC_INTERVAL = 3600
GC_MIN_AGE = 3600
GC_BATCH = 100
HISTORY_INTERVAL = 3600
# Shutdown budget inside terminationGracePeriodSeconds 60: uvicorn drains for GRACEFUL_SHUTDOWN
# (PANEL_FRONT=1: our own drain of at most DRAIN_LIMIT), then every wait for the final commit
# shares one deadline FINAL_FLUSH_TIMEOUT after the first request: 20 + 25 or 15 + 25 seconds.
FINAL_FLUSH_TIMEOUT = 25.0
GRACEFUL_SHUTDOWN = 20
DRAIN_QUIET = 3.0
DRAIN_LIMIT = 15.0
DRAIN_POLL = 0.5
FLUSH_POLL = 0.1

# Error codes that will not heal by retrying: fail fast with a hint.
FATAL_HINTS = {
    'NoSuchBucket': 'the bucket does not exist: check PANEL_S3_BUCKET, PANEL_S3_ENDPOINT_URL and PANEL_S3_REGION',
    'AccessDenied': ('the key needs s3:GetObject, s3:PutObject and s3:DeleteObject on <prefix>* and '
                     's3:ListBucket on the bucket (without s3:ListBucket a missing object is reported as 403)'),
    'InvalidAccessKeyId': 'check PANEL_S3_ACCESS_KEY_ID',
    'SignatureDoesNotMatch': 'check PANEL_S3_SECRET_ACCESS_KEY and PANEL_S3_REGION',
    'AuthorizationHeaderMalformed': 'check PANEL_S3_REGION',
    'InvalidBucketName': 'check PANEL_S3_BUCKET',
    'PermanentRedirect': 'the bucket is served elsewhere: check PANEL_S3_REGION and PANEL_S3_ENDPOINT_URL',
    'AllAccessDisabled': 'access to the bucket is disabled',
    'InvalidToken': 'the S3 credentials are not valid',
    'ExpiredToken': 'the S3 credentials expired',
}
TRANSIENT_CODES = {'RequestTimeout', 'SlowDown', 'InternalError', 'ServiceUnavailable', 'Throttling',
                   'ThrottlingException', 'RequestLimitExceeded', 'OperationAborted',
                   'ConditionalRequestConflict', 'Busy'}
GUARD_TEXT = {
    'data_file_removed': 'data.json disappeared',
    'users_and_servers_emptied': 'data.json lost all of its users and servers',
    'recovery_record_removed': 'a recovery record disappeared',
    'credential_key_changed': 'the credential key changed or disappeared',
    'credential_key_missing': 'sealed credentials exist but the credential key is not in the snapshot',
}

# Injection points for tests: wall clock, monotonic clock, sleeping, the fenced
# exit, random identifiers and the S3 client factory (cfg, max_attempts) -> client.
_now = time.time
_monotonic = time.monotonic
_sleep = time.sleep
_exit = os._exit
_random_hex = secrets.token_hex
_client_factory = None


class StorageConfigError(RuntimeError):
    """Bad or missing configuration; the message is safe to log (never contains secrets)."""


class StorageError(RuntimeError):
    """Runtime or S3 failure; the message is safe to log."""


class _Conflict(StorageError):
    """Another writer committed while we were claiming."""


class _ManifestMissing(StorageError):
    """The manifest disappeared under a running owner."""


class _BlobMissing(StorageError):
    """A blob referenced by the manifest does not exist."""


class _Fenced(StorageError):
    """A verified foreign commit; only reached when _exit is replaced by a test."""


class _Config:
    """Parsed environment. Holds secrets until the clients exist: never log or return it."""

    def __repr__(self):
        return '<panel_storage config>'


class _Keys:
    def __init__(self, master):
        self.enc = _hkdf(master, b'amnezia-panel-s3 enc')
        self.mac = _hkdf(master, b'amnezia-panel-s3 mac')

    def blob_name(self, raw):
        return hmac.new(self.mac, raw, hashlib.sha256).hexdigest()


class _Remote:
    """One GET of the manifest: decoded content plus the response metadata."""

    def __init__(self, manifest, etag, body, headers, last_modified):
        self.manifest = manifest
        self.etag = etag
        self.body = body
        self.headers = headers
        self.last_modified = last_modified


class _State:
    def __init__(self):
        self.cfg = None
        self.keys = None
        self.client = None
        self.put_client = None
        self.root = None            # mirrored directory: D, or the CLI push directory
        self.env_files = {}         # '@env/NAME' -> path outside D
        self.key_rels = ()          # manifest names the credential key may have
        self.state_path = None      # D/.s3-sync-state.json; None for the CLI
        self.lock_fd = None
        self.owner = None
        self.panel_version = None
        self.fencing = None
        self.starting = False       # bootstrap() is running
        self.term_requested = False # SIGTERM before the claim: bootstrap exits at a safe point
        self.pausing = False        # bootstrap sleeps at a safe point: SIGTERM may end it at once
        self.bootstrapped = False
        self.claimed = False
        self.initialised_here = False
        self.fenced = False
        self.closed = False
        self.allow_shrink = False   # CLI --allow-shrink
        self.etag = None
        self.generation = 0
        self.last_commit_id = None
        self.pending_commit_id = None
        self.files = None           # last committed map; None = no manifest yet
        self.remote_blobs = set()   # blobs of the current manifest (dedup set)
        self.uploaded = set()       # blobs PUT since then but not committed yet
        self.known = {}             # rel -> content info keyed by stat stamp
        self.committed_people = 0
        self.lease_owner = None
        self.lease_released = None
        self.last_commit_mono = None
        self.last_commit_at = None
        self.last_history_mono = None
        self.last_gc_mono = None
        self.history_cache = {}
        self.guard = None
        self.pending = False
        self.last_error = None
        self.last_error_at = None
        self.warned = set()
        self.size_warned = False
        self.thread = None
        self.flusher = None         # final-flush thread of stop_async() when the sync thread is not running
        self.flush_deadline = None  # one shared deadline for every wait on the final flush
        self.commit_mutex = threading.Lock()
        self.flush_request = threading.Event()
        self.flush_done = threading.Event()


_S = _State()
_start_lock = threading.Lock()
_previous_sigterm = None
_sigterm_installed = False
_atexit_registered = False


# ---------------------------------------------------------------- configuration

def backend():
    value = (os.environ.get('PANEL_STORAGE') or '').strip().lower()
    if value in ('', 'local'):
        return 'local'
    if value == 's3':
        return 's3'
    raise StorageConfigError('PANEL_STORAGE must be "local" or "s3"')


def _env(name):
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _secret(name):
    direct = os.environ.get(name)
    path = os.environ.get(name + '_FILE')
    if direct and direct.strip() and path and path.strip():
        raise StorageConfigError('set %s or %s_FILE, not both' % (name, name))
    if path and path.strip():
        try:
            with open(path.strip(), 'r', encoding='utf-8') as source:
                value = source.read().strip()
        except (OSError, UnicodeError):
            raise StorageConfigError('cannot read the file named by %s_FILE' % name) from None
        if not value:
            raise StorageConfigError('the file named by %s_FILE is empty' % name)
        return value
    return direct.strip() if direct and direct.strip() else None


def _pop_secrets():
    # Child processes (tunnels, acme.sh) inherit os.environ.copy(); keep our secrets out.
    for name in SECRET_VARS:
        os.environ.pop(name, None)
        os.environ.pop(name + '_FILE', None)


def _number(name, default, minimum, integer=False):
    raw = _env(name)
    if raw is None:
        return default
    try:
        value = int(raw) if integer else float(raw)
    except ValueError:
        value = None
    if value is None or not math.isfinite(value) or value < minimum:
        raise StorageConfigError('%s must be a number >= %s' % (name, minimum))
    return value


def _normalize_prefix(raw):
    if raw is None or not raw.strip():
        return DEFAULT_PREFIX
    prefix = raw.strip().lstrip('/')
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    return prefix


def _check_endpoint(value):
    try:
        parts = urlsplit(value)
        parts.port
    except ValueError:
        raise StorageConfigError('PANEL_S3_ENDPOINT_URL is not a valid URL') from None
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise StorageConfigError('PANEL_S3_ENDPOINT_URL must be an http:// or https:// URL')
    if '@' in parts.netloc:
        raise StorageConfigError('PANEL_S3_ENDPOINT_URL must not contain user:password@; '
                                 'use PANEL_S3_ACCESS_KEY_ID and PANEL_S3_SECRET_ACCESS_KEY')
    if parts.query or parts.fragment or '?' in value or '#' in value:
        raise StorageConfigError('PANEL_S3_ENDPOINT_URL must not contain a query string or fragment')
    return value.rstrip('/')


def _display_endpoint(url):
    # scheme://host[:port] only: never echo userinfo, path or query.
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    if ':' in host:
        host = '[%s]' % host
    return '%s://%s%s' % (parts.scheme, host, ':%d' % port if port else '')


def _decode_master_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raw = b''
    if len(raw) != KEY_BYTES:
        raise StorageConfigError('PANEL_S3_ENCRYPTION_KEY must be base64 of exactly 32 random bytes '
                                 '(openssl rand -base64 32)')
    return raw


def _load_config(data_file=None, app_dir=None):
    """Parse PANEL_S3_*; validate D when data_file is given. Always pops the secret variables."""
    try:
        cfg = _Config()
        cfg.bucket = _env('PANEL_S3_BUCKET')
        if not cfg.bucket:
            raise StorageConfigError('PANEL_S3_BUCKET is required')
        cfg.prefix = _normalize_prefix(os.environ.get('PANEL_S3_PREFIX'))
        if any(part in ('.', '..') for part in cfg.prefix.split('/')):
            raise StorageConfigError('PANEL_S3_PREFIX must not contain "." or ".." segments')
        endpoint = _env('PANEL_S3_ENDPOINT_URL')
        cfg.endpoint = _check_endpoint(endpoint) if endpoint else None
        cfg.region = _env('PANEL_S3_REGION')
        if not cfg.region:
            raise StorageConfigError('PANEL_S3_REGION is required (us-east-1 for MinIO, ru-msk for VK Cloud, '
                                     'ru-central1 for Yandex)')
        cfg.access_key_id = _secret('PANEL_S3_ACCESS_KEY_ID')
        cfg.secret_access_key = _secret('PANEL_S3_SECRET_ACCESS_KEY')
        if bool(cfg.access_key_id) != bool(cfg.secret_access_key):
            raise StorageConfigError('set both PANEL_S3_ACCESS_KEY_ID and PANEL_S3_SECRET_ACCESS_KEY, or neither')
        if cfg.endpoint and not cfg.access_key_id:
            # Without keys botocore would wander into IMDS on a non-AWS provider.
            raise StorageConfigError('PANEL_S3_ACCESS_KEY_ID and PANEL_S3_SECRET_ACCESS_KEY are required '
                                     'with PANEL_S3_ENDPOINT_URL')
        style = (_env('PANEL_S3_ADDRESSING_STYLE') or ('path' if cfg.endpoint else 'auto')).lower()
        if style not in ('auto', 'path', 'virtual'):
            raise StorageConfigError('PANEL_S3_ADDRESSING_STYLE must be auto, path or virtual')
        cfg.addressing_style = style
        key = _secret('PANEL_S3_ENCRYPTION_KEY')
        if not key:
            raise StorageConfigError('PANEL_S3_ENCRYPTION_KEY is required (openssl rand -base64 32); '
                                     'losing it means losing the bucket state')
        cfg.master_key = _decode_master_key(key)
        cfg.sync_interval = _number('PANEL_S3_SYNC_INTERVAL', 5.0, 0.01)
        cfg.lease_interval = _number('PANEL_S3_LEASE_INTERVAL', 30, 1, integer=True)
        if cfg.lease_interval < 3 * cfg.sync_interval:
            # Heartbeats come from the sync loop, so they can be one scan late: keep that
            # far inside the 3 x lease after which another panel takes over.
            raise StorageConfigError('PANEL_S3_LEASE_INTERVAL (%s) must be at least 3 x PANEL_S3_SYNC_INTERVAL (%s), '
                                     'or a running panel can look stale to the next one'
                                     % (cfg.lease_interval, cfg.sync_interval))
        cfg.startup_timeout = _number('PANEL_S3_STARTUP_TIMEOUT', 120.0, 0)
        cfg.fencing = (_env('PANEL_S3_FENCING') or 'auto').lower()
        if cfg.fencing not in ('auto', 'required'):
            raise StorageConfigError('PANEL_S3_FENCING must be auto or required')
        cfg.history_days = _number('PANEL_S3_HISTORY_DAYS', 7.0, 0)
        cfg.allow_reinit = _env('PANEL_S3_ALLOW_REINIT') == '1'
        cfg.restore_overwrite = _env('PANEL_S3_RESTORE_OVERWRITE') == '1'
        cfg.allow_shrink = _env('PANEL_S3_ALLOW_SHRINK') == '1'
        cfg.data_file = None
        cfg.dir = None
        cfg.skip_rels = frozenset()
        cfg.data_rel = os.path.basename(_env('DATA_FILE') or 'data.json') or 'data.json'
        cfg.env_paths = {}
        for name in ENV_FILES:
            value = _env(name)
            if value:
                cfg.env_paths[name] = os.path.abspath(os.path.expanduser(value))
        if data_file is not None:
            _check_data_dir(cfg, data_file, app_dir)
        return cfg
    finally:
        _pop_secrets()


def _is_within(path, parent):
    path = os.path.normcase(os.path.abspath(path))
    parent = os.path.normcase(os.path.abspath(parent))
    try:
        return os.path.commonpath([path, parent]) == parent
    except ValueError:
        return False


def _check_data_dir(cfg, data_file, app_dir):
    if not _env('DATA_FILE'):
        raise StorageConfigError('PANEL_STORAGE=s3 requires DATA_FILE to be set explicitly, '
                                 'e.g. /app/data/data.json')
    data_file = os.path.abspath(os.path.expanduser(str(data_file)))
    name = os.path.basename(data_file)
    if not name or name.startswith('.'):
        raise StorageConfigError('the DATA_FILE name must not start with "." in s3 mode '
                                 '(dot files are never mirrored)')
    directory = os.path.dirname(data_file)
    real = os.path.realpath(directory)
    if os.path.dirname(real) == real:
        raise StorageConfigError('the data directory must not be the filesystem root')
    home = os.path.expanduser('~')
    for label, other in (('the application directory', app_dir),
                         ('the temp directory', tempfile.gettempdir()),
                         ('the home directory', home if home != '~' else None)):
        # Mirroring (and the cold-restore displacement pass) must only ever see panel state.
        if other and _is_within(os.path.realpath(other), real):
            raise StorageConfigError('the data directory (dirname of DATA_FILE) must be a dedicated directory, '
                                     'not %s or one of its parents' % label)
    cfg.data_file = data_file
    cfg.data_rel = name
    cfg.dir = directory
    # Process-local paths are never mirrored even when configured inside D:
    # tunnel PIDs, downloaded binaries, temp files and the plaintext ssl_temp copy.
    skip = set()
    for value in (_env('TUNNEL_STATE_FILE'), _env('TUNNEL_BIN_DIR'), _env('TMPDIR'),
                  os.path.join(os.getcwd(), 'ssl_temp')):
        if value:
            path = os.path.abspath(os.path.expanduser(value))
            if _is_within(path, directory) and os.path.normcase(path) != os.path.normcase(directory):
                skip.add(os.path.relpath(path, directory).replace(os.sep, '/'))
    cfg.skip_rels = frozenset(skip)


def _excluded(name):
    return name.startswith('.') or name.endswith(EXCLUDED_SUFFIXES)


def _mirrored_rel(rel):
    return all(part and not _excluded(part) for part in rel.split('/'))


def _env_files(cfg):
    result = {}
    for name, path in cfg.env_paths.items():
        if _is_within(path, cfg.dir):
            rel = os.path.relpath(path, cfg.dir).replace(os.sep, '/')
            if _mirrored_rel(rel):
                continue
        result['@env/' + name] = path
    return result


def _key_rels(cfg):
    rels = []
    path = cfg.env_paths.get('CREDENTIAL_KEY_FILE')
    if path and cfg.dir and _is_within(path, cfg.dir):
        rels.append(os.path.relpath(path, cfg.dir).replace(os.sep, '/'))
    rels += ['@env/CREDENTIAL_KEY_FILE', cfg.data_rel + '.credential.key']
    return tuple(rels)


def _valid_rel(rel):
    if not isinstance(rel, str) or not rel or '\\' in rel or '\x00' in rel or rel.startswith('/'):
        return False
    parts = rel.split('/')
    if parts[0] == '@env':
        return len(parts) == 2 and parts[1] in ENV_FILES
    if os.name == 'nt' and any(':' in part for part in parts):
        return False
    return all(part and part not in ('.', '..') and not _excluded(part) for part in parts)


# ---------------------------------------------------------------- crypto

def _hkdf(master, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def _seal(key, plaintext, aad):
    nonce = os.urandom(NONCE_BYTES)
    return (MAGIC + bytes([ENVELOPE_VERSION]) + nonce +
            AESGCM(key).encrypt(nonce, zlib.compress(plaintext, 6), aad))


def _unseal(key, body, aad):
    """Plaintext; InvalidTag for a wrong key or AAD, ValueError for a foreign object."""
    header = len(MAGIC) + 1 + NONCE_BYTES
    if len(body) < header + 16 or body[:len(MAGIC)] != MAGIC:
        raise ValueError('not a panel_storage object')
    if body[len(MAGIC)] != ENVELOPE_VERSION:
        raise ValueError('unsupported envelope version')
    plain = AESGCM(key).decrypt(body[len(MAGIC) + 1:header], body[header:], aad)
    try:
        return zlib.decompress(plain)
    except zlib.error:
        raise ValueError('corrupt envelope') from None


def _manifest_aad(prefix):
    return b'manifest:' + prefix.encode('utf-8')


def _history_aad(prefix, name):
    # Bound to its own key name (<generation>-<commit_id>), so a history copy can never
    # pass as <prefix>manifest: a bucket writer without the key cannot roll the panel back.
    return b'history:' + prefix.encode('utf-8') + b':' + name.encode('utf-8')


def _history_name(st, key):
    return key[len(_key(st, 'history/')):]


def _encode_manifest(st, manifest, aad=None):
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return _seal(st.keys.enc, raw, aad or _manifest_aad(st.cfg.prefix))


def _decode_manifest(st, body, aad=None):
    """aad None: the current manifest; a history snapshot passes its _history_aad()."""
    try:
        raw = _unseal(st.keys.enc, body, aad or _manifest_aad(st.cfg.prefix))
    except InvalidTag:
        if aad is not None:
            raise StorageError('a history snapshot failed authentication (another encryption key, or an object '
                               'that was not written under this name)') from None
        raise StorageConfigError('encryption key does not match bucket (PANEL_S3_ENCRYPTION_KEY differs from '
                                 'the key that wrote this prefix), or the manifest was replaced by a foreign '
                                 'object such as a copied history snapshot') from None
    except ValueError:
        raise StorageError('the manifest under this prefix is not a panel_storage object; '
                           'refusing to start and never overwriting it') from None
    try:
        manifest = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise StorageError('the S3 manifest is not valid JSON') from None
    if not isinstance(manifest, dict) or manifest.get('format') != FORMAT:
        raise StorageError('unknown manifest format under this prefix; refusing to start and never overwriting it')
    _check_manifest(manifest)
    return manifest


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _check_manifest(manifest):
    generation = manifest.get('generation')
    files = manifest.get('files')
    ok = (isinstance(generation, int) and not isinstance(generation, bool) and generation >= 0 and
          isinstance(manifest.get('commit_id'), str) and isinstance(files, dict) and
          isinstance(manifest.get('lease', {}), dict))
    if ok:
        for rel, entry in files.items():
            if not (_valid_rel(rel) and isinstance(entry, dict) and _is_hex64(entry.get('blob')) and
                    _is_hex64(entry.get('sha256')) and isinstance(entry.get('size'), int) and
                    not isinstance(entry.get('size'), bool) and entry['size'] >= 0):
                ok = False
                break
    if not ok:
        raise StorageError('the S3 manifest is malformed; refusing to start and never overwriting it')


# ---------------------------------------------------------------- S3 helpers

def _make_client(cfg, max_attempts):
    if _client_factory is not None:
        return _client_factory(cfg, max_attempts)
    import botocore.session
    from botocore.config import Config
    # total_max_attempts counts the first request; botocore's max_attempts would add one
    # more, and the manifest client must not retry on its own at all.
    options = {'signature_version': 's3v4', 's3': {'addressing_style': cfg.addressing_style},
               'connect_timeout': 5, 'read_timeout': 20,
               'retries': {'mode': 'standard', 'total_max_attempts': max_attempts}}
    # Newer options: skip them on a botocore that does not know them.
    optional = {'request_checksum_calculation': 'when_required',
                'response_checksum_validation': 'when_required',
                'ignore_configured_endpoint_urls': True}
    known = getattr(Config, 'OPTION_DEFAULTS', {})
    options.update({name: value for name, value in optional.items() if name in known})
    kwargs = {'region_name': cfg.region, 'config': Config(**options)}
    if cfg.endpoint:
        kwargs['endpoint_url'] = cfg.endpoint
    if cfg.access_key_id:
        kwargs['aws_access_key_id'] = cfg.access_key_id
        kwargs['aws_secret_access_key'] = cfg.secret_access_key
    return botocore.session.get_session().create_client('s3', **kwargs)


def _key(st, name):
    return st.cfg.prefix + name


def _code(exc):
    response = getattr(exc, 'response', None)
    if not isinstance(response, dict):
        return None, None
    code = str((response.get('Error') or {}).get('Code') or '')
    status = (response.get('ResponseMetadata') or {}).get('HTTPStatusCode')
    return code, status


def _transport_classes():
    try:
        from botocore import exceptions as boto_exceptions
    except ImportError:
        return (ConnectionError, TimeoutError)
    return (boto_exceptions.ConnectionError, boto_exceptions.HTTPClientError, ConnectionError, TimeoutError)


def _is_missing(exc):
    return _code(exc)[0] == 'NoSuchKey'


def _is_precondition(exc):
    code, status = _code(exc)
    return code == 'PreconditionFailed' or status == 412


def _transient(exc):
    if isinstance(exc, _transport_classes()):
        return True
    code, status = _code(exc)
    return code in TRANSIENT_CODES or status == 409 or (isinstance(status, int) and status >= 500)


def _ambiguous(exc):
    # The PUT may or may not have been applied: only a GET of the manifest can tell.
    return _is_precondition(exc) or _is_missing(exc) or _transient(exc)


def _short_error(exc):
    if isinstance(exc, str):
        return exc
    if isinstance(exc, StorageError):
        return str(exc)[:200]
    code, status = _code(exc)
    if code or status:
        return '%s (%s)' % (code or 'HTTP', status) if status else code
    return type(exc).__name__


def _raise_if_fatal(exc, what):
    code, status = _code(exc)
    if code in FATAL_HINTS:
        raise StorageConfigError('%s failed: %s (%s). %s' % (what, code, status, FATAL_HINTS[code])) from None
    if type(exc).__name__ in ('NoCredentialsError', 'PartialCredentialsError'):
        raise StorageConfigError('%s failed: no S3 credentials found; set PANEL_S3_ACCESS_KEY_ID and '
                                 'PANEL_S3_SECRET_ACCESS_KEY' % what) from None


def _retrying(st, what, call):
    """Run call(), retrying transient errors with backoff for up to PANEL_S3_STARTUP_TIMEOUT."""
    deadline = _monotonic() + st.cfg.startup_timeout
    attempt = 0
    while True:
        try:
            return call()
        except (StorageError, StorageConfigError):
            raise
        except Exception as exc:
            _raise_if_fatal(exc, what)
            if not _transient(exc):
                raise StorageError('%s failed: %s' % (what, _short_error(exc))) from None
            remaining = deadline - _monotonic()
            if remaining <= 0:
                raise StorageError('%s failed: S3 unreachable for %ss (%s)'
                                   % (what, st.cfg.startup_timeout, _short_error(exc))) from None
            delay = min(BACKOFF_CAP, 2 ** attempt, remaining)
            log.warning('panel_storage: %s failed (%s); retrying in %.0fs', what, _short_error(exc), delay)
            _pause(st, delay)
            attempt += 1


def _check_term(st):
    if st.term_requested and not st.claimed:
        log.warning('panel_storage: SIGTERM during startup; exiting before claiming the S3 prefix')
        raise SystemExit(0)


def _pause(st, seconds):
    """A startup sleep at a safe point: nothing is half-written, so a SIGTERM may end the process here."""
    _check_term(st)
    st.pausing = True
    try:
        _sleep(seconds)
    finally:
        st.pausing = False
    _check_term(st)


def _headers(response):
    raw = (response.get('ResponseMetadata') or {}).get('HTTPHeaders') or {}
    return {str(name).lower(): value for name, value in raw.items()}


def _http_time(value):
    if not value:
        return None
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _iso_time(value):
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _server_time(headers):
    value = _http_time(headers.get('date'))
    return value if value is not None else _now()


def _obj_time(obj):
    value = obj.get('LastModified')
    if isinstance(value, datetime):
        return value.timestamp()
    return None


def _read_body(response):
    body = response['Body']
    try:
        return body.read()
    finally:
        close = getattr(body, 'close', None)
        if close:
            close()


def _get_manifest(st):
    """The current manifest as a _Remote, or None when the key does not exist (NoSuchKey only)."""
    try:
        response = st.client.get_object(Bucket=st.cfg.bucket, Key=_key(st, 'manifest'))
    except Exception as exc:
        if _is_missing(exc):
            return None
        raise
    body = _read_body(response)
    headers = _headers(response)
    return _Remote(_decode_manifest(st, body), response.get('ETag') or headers.get('etag'), body, headers,
                   response.get('LastModified'))


def _get_blob(st, entry):
    name = entry['blob']
    try:
        response = st.client.get_object(Bucket=st.cfg.bucket, Key=_key(st, 'blobs/' + name))
    except Exception as exc:
        if _is_missing(exc):
            raise _BlobMissing(name) from None
        raise
    try:
        raw = _unseal(st.keys.enc, _read_body(response), b'blob:' + name.encode('ascii'))
    except (InvalidTag, ValueError):
        raise StorageError('blob %s failed authentication' % name) from None
    if len(raw) != entry['size'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
        raise StorageError('blob %s does not match the manifest' % name)
    return raw


def _put_blob(st, name, raw):
    body = _seal(st.keys.enc, raw, b'blob:' + name.encode('ascii'))
    st.client.put_object(Bucket=st.cfg.bucket, Key=_key(st, 'blobs/' + name), Body=body)
    st.uploaded.add(name)


def _lease_age(remote):
    now = _server_time(remote.headers)
    modified = remote.last_modified.timestamp() if isinstance(remote.last_modified, datetime) else None
    if modified is None:
        modified = _http_time(remote.headers.get('last-modified'))
    if modified is None:
        modified = _iso_time(remote.manifest.get('committed_at'))
    if modified is None:
        return float('inf')
    return max(0.0, now - modified)


def _lease_of(manifest):
    lease = manifest.get('lease')
    return lease if isinstance(lease, dict) else {}


# ---------------------------------------------------------------- local files

def _stamp(st_result):
    # ctime on Windows has a different meaning across Python versions; POSIX adds it.
    return (st_result.st_dev, st_result.st_ino, st_result.st_size, st_result.st_mtime_ns,
            st_result.st_ctime_ns if os.name != 'nt' else None)


def _warn_once(st, rel, message):
    if rel not in st.warned:
        st.warned.add(rel)
        log.warning('panel_storage: %s: %s', message, rel)


def _scan(st, root=None, env_files=None):
    """{rel: (path, stamp)} of every mirrored regular file."""
    skip = st.cfg.skip_rels if root is None else frozenset()
    root = st.root if root is None else root
    env_files = st.env_files if env_files is None else env_files
    found = {}
    pending = [('', root)]
    while pending:
        rel_dir, directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            rel = rel_dir + entry.name
            if _excluded(entry.name) or rel in skip:
                continue
            try:
                info = os.lstat(entry.path)
            except FileNotFoundError:
                continue
            junction = getattr(entry, 'is_junction', lambda: False)()
            if stat.S_ISLNK(info.st_mode) or junction:
                _warn_once(st, rel, 'symlink in the data directory is not mirrored')
            elif stat.S_ISDIR(info.st_mode):
                pending.append((rel + '/', entry.path))
            elif not _valid_rel(rel):
                _warn_once(st, rel, 'name cannot be mirrored')
            elif stat.S_ISREG(info.st_mode):
                found[rel] = (entry.path, _stamp(info))
            else:
                _warn_once(st, rel, 'special file in the data directory is not mirrored')
    for rel, path in env_files.items():
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            found[rel] = (path, _stamp(info))
        else:
            _warn_once(st, rel, 'not a regular file, not mirrored')
    return found


def _read_path(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as source:
        return source.read()


def _read_or_none(path, rel):
    try:
        return _read_path(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise StorageError('read_failed: %s' % rel) from None


def _fsync_dir(path):
    if os.name == 'nt':
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path, raw):
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix='.s3-tmp-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    _fsync_dir(directory)


def _make_private_dirs(root, path):
    """Create the directories between root and path one level at a time as 0700."""
    if not _is_within(path, root):
        if not os.path.isdir(path):
            os.makedirs(path, 0o700)
            os.chmod(path, 0o700)
        return
    relative = os.path.relpath(path, root)
    current = root
    for part in ([] if relative == '.' else relative.split(os.sep)):
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise StorageError('a symlinked directory blocks the restore: %s' % os.path.relpath(current, root))
        if os.path.isdir(current):
            continue
        os.mkdir(current, 0o700)
        os.chmod(current, 0o700)  # the umask applies to mkdir()


def _data_facts(raw):
    """(users + servers, sealed envelopes present) of a data.json body."""
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        return 0, False
    if not isinstance(data, dict):
        return 0, False
    users, servers = data.get('users'), data.get('servers')
    people = (len(users) if isinstance(users, list) else 0) + (len(servers) if isinstance(servers, list) else 0)
    sealed = isinstance(servers, list) and any(isinstance(s, dict) and s.get('ssh_credentials') for s in servers)
    return people, bool(sealed)


def _record_envelope(record):
    """(envelope, context) of the first sealed blob in a recovery record, or None."""
    if not isinstance(record, dict):
        return None
    if isinstance(record.get('before_sealed'), dict):
        return record['before_sealed'], 'recovery-before'
    snapshot = record.get('peer_creates_snapshot')
    if isinstance(snapshot, dict) and isinstance(snapshot.get('sealed'), dict):
        return snapshot['sealed'], 'peer-creates-snapshot'
    return None


def _is_recovery_record(rel):
    parts = rel.split('/')
    return len(parts) >= 2 and parts[-1].endswith('.json') and any(p.endswith('.recovery') for p in parts[:-1])


def _describe(st, rel, raw, stamp, hashed_at):
    info = {'stamp': stamp, 'hashed_at': hashed_at, 'sha256': hashlib.sha256(raw).hexdigest(),
            'size': len(raw), 'blob': st.keys.blob_name(raw), 'people': 0, 'sealed': False}
    if rel == st.cfg.data_rel:
        info['people'], info['sealed'] = _data_facts(raw)
    elif _is_recovery_record(rel):
        try:
            info['sealed'] = _record_envelope(json.loads(raw.decode('utf-8'))) is not None
        except (ValueError, UnicodeError):
            pass
    return info


# ---------------------------------------------------------------- sync state file

def _read_state(st):
    try:
        with open(st.state_path, 'rb') as source:
            state = json.loads(source.read().decode('utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, UnicodeError):
        log.warning('panel_storage: %s is unreadable; treating this start as cold', STATE_NAME)
        return None
    return state if isinstance(state, dict) else None


def _save_state(st, strict=False):
    if not st.state_path:
        return
    # The endpoint in display form (scheme://host[:port], None on AWS): never credentials.
    state = {'format': 1, 'endpoint': _display_endpoint(st.cfg.endpoint), 'bucket': st.cfg.bucket,
             'prefix': st.cfg.prefix, 'owner': st.owner,
             'last_commit_id': st.last_commit_id, 'pending_commit_id': st.pending_commit_id,
             'etag': st.etag, 'generation': st.generation, 'files': st.files}
    try:
        _atomic_write(st.state_path, json.dumps(state, sort_keys=True).encode('utf-8'))
    except OSError as exc:
        if strict:
            raise StorageError('cannot write %s (%s)' % (STATE_NAME, type(exc).__name__)) from None
        log.error('panel_storage: cannot write %s (%s)', STATE_NAME, type(exc).__name__)


def _adopt(st, remote):
    manifest = remote.manifest
    st.etag = remote.etag
    st.generation = manifest['generation']
    st.last_commit_id = manifest['commit_id']
    st.pending_commit_id = None
    st.files = dict(manifest['files'])
    st.remote_blobs = {entry['blob'] for entry in st.files.values()}
    lease = _lease_of(manifest)
    st.lease_owner = lease.get('owner')
    st.lease_released = lease.get('released')


# ---------------------------------------------------------------- bootstrap

def bootstrap(data_file, *, app_dir, panel_version):
    """Restore D from S3 and claim the prefix. No-op unless PANEL_STORAGE=s3. Main thread, before any state read."""
    if backend() == 'local':
        return
    st = _S
    if st.bootstrapped:
        return
    # First thing: in a container python is PID 1, and until a handler exists the
    # kernel drops SIGTERM instead of delivering it.
    _install_sigterm()
    st.starting = True
    try:
        _bootstrap(st, data_file, app_dir, panel_version)
    finally:
        st.starting = False
    if st.term_requested:
        # SIGTERM arrived while the claim was in flight: give the lease back at once.
        log.warning('panel_storage: SIGTERM during startup; releasing the S3 lease and exiting')
        stop()
        raise SystemExit(0)


def _bootstrap(st, data_file, app_dir, panel_version):
    global _atexit_registered
    cfg = _load_config(data_file, app_dir)
    st.cfg = cfg
    st.root = cfg.dir
    st.panel_version = str(panel_version)
    st.env_files = _env_files(cfg)
    st.key_rels = _key_rels(cfg)
    st.state_path = os.path.join(cfg.dir, STATE_NAME)
    if not os.path.isdir(cfg.dir):
        os.makedirs(cfg.dir, 0o700)
        os.chmod(cfg.dir, 0o700)
    st.lock_fd = _take_owner_lock(cfg.dir)
    st.keys = _Keys(cfg.master_key)
    cfg.master_key = None
    st.client = _make_client(cfg, 3)
    st.put_client = _make_client(cfg, 1)  # manifest PUTs: our own idempotent retry loop
    cfg.access_key_id = cfg.secret_access_key = None
    st.owner = _owner_id()
    log.info('panel_storage: s3 mode, bucket %s, prefix %s, data directory %s',
             cfg.bucket, cfg.prefix or '(bucket root)', cfg.dir)
    st.fencing = _probe_fencing(st)
    for _ in range(CLAIM_ATTEMPTS):
        _prepare(st)
        _check_key_safety(st)
        _check_term(st)
        try:
            _retrying(st, 'claiming the S3 prefix', lambda: _commit_round(st, 'claim'))
        except _Conflict as exc:
            log.warning('panel_storage: another writer (%s) committed during startup; starting over', exc)
            st.uploaded.clear()
            continue
        break
    else:
        raise StorageError('could not claim the S3 prefix after %d attempts' % CLAIM_ATTEMPTS)
    st.claimed = True
    log.info('panel_storage: claimed generation %d (%d files, fencing %s)',
             st.generation, len(st.files or {}), st.fencing)
    if not _atexit_registered:
        atexit.register(stop)
        _atexit_registered = True
    st.bootstrapped = True


def _owner_id():
    return '%s-%d-%s' % (socket.gethostname() or 'panel', os.getpid(), _random_hex(4))


def _take_owner_lock(directory):
    try:
        import fcntl
    except ImportError:
        log.debug('panel_storage: fcntl is not available; the owner lock is skipped on this platform')
        return None
    fd = os.open(os.path.join(directory, LOCK_NAME), os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise StorageError('another process already mirrors this data directory to S3 (%s is locked); '
                           'run one panel per data directory' % LOCK_NAME) from None
    return fd


PROBE_BODY = b'panel_storage fencing probe\n'


def _probe_put(st, key, cond, first):
    """'ok', 'precondition' or 'unsupported' for one conditional probe PUT."""
    deadline = _monotonic() + st.cfg.startup_timeout
    attempt = 0
    while True:
        try:
            st.put_client.put_object(Bucket=st.cfg.bucket, Key=key, Body=PROBE_BODY, **cond)
            return 'ok'
        except Exception as exc:
            if _is_precondition(exc):
                # A create retried after a lost response was applied by the earlier attempt.
                return 'ok' if first and attempt else 'precondition'
            code, status = _code(exc)
            if code == 'NotImplemented' or status == 501:
                return 'unsupported'
            # A wrong region, bucket name or token is a 400 too and must not pass as "unfenced".
            _raise_if_fatal(exc, 'the S3 fencing probe')
            if status == 400 and code not in TRANSIENT_CODES:
                if first:
                    # Bucket, region and credentials are not proven yet: the same PUT without
                    # the condition tells "header rejected" from "request wrong anyway".
                    _plain_probe_put(st, key, code)
                # A plain PUT went through, so this 400 can only be about the conditional header.
                return 'unsupported'
            if not _transient(exc) or _monotonic() >= deadline:
                raise StorageError('the S3 fencing probe failed: %s' % _short_error(exc)) from None
            _pause(st, min(BACKOFF_CAP, 2 ** attempt))
            attempt += 1


def _plain_probe_put(st, key, code):
    """After a 400 on the first conditional probe PUT: the same PUT without a condition.

    Returns when it succeeds (the provider rejects conditional headers); raises
    StorageConfigError naming both codes when it fails as well.
    """
    deadline = _monotonic() + st.cfg.startup_timeout
    attempt = 0
    while True:
        try:
            st.put_client.put_object(Bucket=st.cfg.bucket, Key=key, Body=PROBE_BODY)
        except Exception as exc:
            if _transient(exc):
                if _monotonic() >= deadline:
                    # An outage, not a configuration problem: report it like every other startup call.
                    raise StorageError('the S3 fencing probe failed: S3 unreachable for %ss (%s)'
                                       % (st.cfg.startup_timeout, _short_error(exc))) from None
                _pause(st, min(BACKOFF_CAP, 2 ** attempt))
                attempt += 1
                continue
            plain = _code(exc)[0]
            raise StorageConfigError(
                'the S3 fencing probe (a PUT under <prefix>probe/) failed: %s (400) with a conditional header, and the '
                'same PUT without it failed too%s. Check PANEL_S3_BUCKET, PANEL_S3_REGION, PANEL_S3_ENDPOINT_URL and '
                'the credentials%s' % (code or 'HTTP', '' if plain == code else ': ' + _short_error(exc),
                                       '; ' + FATAL_HINTS[plain] if plain in FATAL_HINTS else '')) from None
        log.warning('panel_storage: the S3 provider rejects conditional PUTs (%s, 400) but accepts plain ones',
                    code or 'HTTP')
        return


def _probe_fencing(st):
    key = _key(st, 'probe/' + _random_hex(8))
    supported = False
    try:
        if _probe_put(st, key, {'IfNoneMatch': '*'}, True) == 'ok':
            supported = (_probe_put(st, key, {'IfNoneMatch': '*'}, False) == 'precondition' and
                         _probe_put(st, key, {'IfMatch': '"0"'}, False) == 'precondition')
    finally:
        try:
            if not st.term_requested:  # leaving on SIGTERM: do not wait on a flaky S3 for litter
                st.client.delete_object(Bucket=st.cfg.bucket, Key=key)
        except Exception as exc:
            log.debug('panel_storage: probe cleanup failed (%s)', _short_error(exc))
    if supported:
        return 'enforced'
    if st.cfg.fencing == 'required':
        raise StorageConfigError('this S3 provider does not enforce conditional writes (If-None-Match/If-Match); '
                                 'PANEL_S3_FENCING=required refuses to start')
    log.warning('panel_storage: WARNING: this S3 provider ignores or rejects conditional writes, running UNFENCED '
                '(read-before-write only). Two panels on one prefix can overwrite each other: run exactly one '
                'replica (replicas: 1, strategy: Recreate). PANEL_S3_FENCING=required refuses to start instead.')
    return 'unfenced'


def _prepare(st):
    """Step 4: initialise an empty prefix, keep a warm directory, or cold-restore."""
    st.known = {}
    st.initialised_here = False
    while True:
        remote = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
        if remote is None:
            _check_empty_prefix(st)
            st.initialised_here = True
            st.files = None
            st.remote_blobs = set()
            st.etag = None
            st.generation = 0
            st.last_commit_id = None
            st.pending_commit_id = None
            st.committed_people = 0
            log.info('panel_storage: the prefix is empty; initialising it from the local data directory')
            return
        state = _read_state(st)
        rollback = _check_rollback(st, state, remote)
        lineage = _is_lineage(st, state, remote)
        if lineage and not rollback:
            log.info('panel_storage: warm start at generation %d; local files are kept as they are',
                     remote.manifest['generation'])
            _adopt(st, remote)
            if os.path.exists(os.path.join(st.root, RESTORE_MARKER)):
                os.unlink(os.path.join(st.root, RESTORE_MARKER))
            break
        if not lineage:
            # Our own lineage needs no lease wait: the process that held it ran on this
            # directory and is gone. Anyone else's lease is waited for.
            waited_on = remote.manifest.get('commit_id')
            remote = _wait_for_lease(st, remote)
            if remote is None:
                continue
            if remote.manifest.get('commit_id') != waited_on:
                _check_rollback(st, state, remote)  # the manifest may have gone back meanwhile
        # An accepted rollback always restores: a warm start would keep the newer local
        # files and commit them on top, silently undoing it.
        _cold_restore(st, remote, state)
        break
    st.committed_people = _remote_people(st, st.files)


def _synced_here(st, state):
    """The state file was written for this endpoint, bucket and prefix.

    A state file without an endpoint (written before it was recorded) matches any endpoint.
    """
    endpoint = _display_endpoint(st.cfg.endpoint)
    return (bool(state) and state.get('bucket') == st.cfg.bucket and state.get('prefix') == st.cfg.prefix and
            state.get('endpoint', endpoint) == endpoint)


def _check_rollback(st, state, remote):
    """True when the manifest went back and PANEL_S3_RESTORE_OVERWRITE=1 accepts that (cold restore)."""
    # Honest commits only ever raise the generation, so an older one than this directory
    # already synced was put back: a replayed manifest or a bucket rolled back.
    if not _synced_here(st, state):
        return False
    synced, found = state.get('generation'), remote.manifest['generation']
    if not isinstance(synced, int) or isinstance(synced, bool) or found >= synced:
        return False
    log.critical('panel_storage: the S3 manifest went back from generation %d to %d: an older manifest was put back '
                 '(replayed, or restored from bucket versioning)', synced, found)
    if not st.cfg.restore_overwrite:
        raise StorageError('the S3 manifest went back from generation %d to %d; refusing to start. If the bucket was '
                           'rolled back on purpose, set PANEL_S3_RESTORE_OVERWRITE=1 once (local files that differ '
                           'are moved to %s*, never deleted)' % (synced, found, DISPLACED_PREFIX))
    log.warning('panel_storage: PANEL_S3_RESTORE_OVERWRITE=1: accepting the older manifest; restoring it, local files '
                'that differ are moved to %s*', DISPLACED_PREFIX)
    return True


def _is_lineage(st, state, remote):
    if not _synced_here(st, state):
        return False
    ids = {state.get('last_commit_id'), state.get('pending_commit_id')} - {None}
    # Owner ids are random per process, so a commit by the process that last owned this
    # directory is ours too (an earlier pending id may have been replaced by a later one).
    return remote.manifest['commit_id'] in ids or bool(
        state.get('owner') and remote.manifest.get('owner') == state.get('owner'))


def _check_empty_prefix(st):
    for sub in ('blobs/', 'history/'):
        response = _retrying(st, 'listing the S3 prefix', lambda sub=sub: st.client.list_objects_v2(
            Bucket=st.cfg.bucket, Prefix=_key(st, sub), MaxKeys=1))
        if response.get('KeyCount') or response.get('Contents'):
            if st.cfg.allow_reinit:
                log.warning('panel_storage: PANEL_S3_ALLOW_REINIT=1: the manifest is missing but %s holds objects; '
                            'initialising a new state anyway', sub)
                return
            log.critical('panel_storage: the S3 manifest is missing but %s%s holds objects: this is not an empty '
                         'prefix. Refusing to start a fresh panel over it.', st.cfg.prefix, sub)
            raise StorageError('the manifest is missing but blobs/ or history/ hold objects; refusing to initialise '
                               '(restore the manifest, or set PANEL_S3_ALLOW_REINIT=1 once to start anew)')


def _wait_for_lease(st, remote):
    while True:
        lease = _lease_of(remote.manifest)
        if lease.get('released'):
            return remote
        try:
            interval = float(lease.get('interval') or st.cfg.lease_interval)
        except (TypeError, ValueError):
            interval = float(st.cfg.lease_interval)
        age = _lease_age(remote)
        if age >= 3 * interval:
            log.warning('panel_storage: the S3 lease of %s is stale (%.0fs old); taking over',
                        lease.get('owner'), age)
            return remote
        log.warning('panel_storage: waiting for %s to release the S3 lease (last heartbeat %.0fs ago, stale after '
                    '%.0fs). Is another replica still running?', lease.get('owner'), age, 3 * interval)
        _pause(st, st.cfg.lease_interval)
        remote = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
        if remote is None:
            return None


def _same_content(path, entry):
    try:
        if os.lstat(path).st_size != entry['size']:
            return False
        return hashlib.sha256(_read_path(path)).hexdigest() == entry['sha256']
    except OSError:
        return False


def _target(st, rel, files):
    """Local path for a manifest name; None when an @env file has no place to go."""
    parts = rel.split('/')
    if parts[0] != '@env':
        return os.path.join(st.root, *parts)
    path = st.cfg.env_paths.get(parts[1])
    if path:
        return path
    # The variable is unset now: the panel uses the default path inside D.
    fallback = st.cfg.data_rel + '.credential.key' if parts[1] == 'CREDENTIAL_KEY_FILE' else 'ssh_known_hosts'
    if fallback in files:
        log.warning('panel_storage: %s is not set and %s is in the snapshot; %s is not restored',
                    parts[1], fallback, rel)
        return None
    log.warning('panel_storage: %s is not set; restoring %s to %s', parts[1], rel, fallback)
    return os.path.join(st.root, fallback)


def _cold_restore(st, remote, state):
    for _ in range(RESTORE_ATTEMPTS):
        try:
            _restore_snapshot(st, remote, state)
            return
        except _BlobMissing as exc:
            log.warning('panel_storage: blob %s is missing; re-reading the manifest', exc)
            remote = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
            if remote is None:
                raise StorageError('the S3 manifest disappeared during the cold restore') from None
    raise StorageError('cold restore failed: the manifest references blobs that do not exist')


def _restore_snapshot(st, remote, state):
    """Cold restore: never deletes; differing or extra local files are moved aside."""
    files = remote.manifest['files']
    root = st.root
    marker = os.path.join(root, RESTORE_MARKER)
    data_path = os.path.join(root, st.cfg.data_rel)
    # A state file of another endpoint, bucket or prefix (a changed PANEL_S3_PREFIX over an
    # old volume, or another provider) or an unreadable one says nothing about this bucket:
    # guard as if absent.
    if os.path.lexists(data_path) and not _synced_here(st, state) and not os.path.exists(marker):
        entry = files.get(st.cfg.data_rel)
        if entry is None or not _same_content(data_path, entry):
            if not st.cfg.restore_overwrite:
                raise StorageError('the data directory already holds a different %s that this panel never synced '
                                   '(migration into a non-empty prefix, a changed prefix, or a staged restore). '
                                   'Refusing to replace it; set PANEL_S3_RESTORE_OVERWRITE=1 once to restore the '
                                   'bucket state (local files are moved to %s*, never deleted)'
                                   % (st.cfg.data_rel, DISPLACED_PREFIX))
            log.warning('panel_storage: PANEL_S3_RESTORE_OVERWRITE=1: replacing the local %s with the bucket state',
                        st.cfg.data_rel)
    _atomic_write(marker, b'cold restore in progress\n')
    if os.path.exists(st.state_path):
        os.unlink(st.state_path)
    # Everything that must move aside is decided before the first download.
    local = _scan(st)
    move = {rel: path for rel, (path, _) in local.items()
            if rel not in files or not _same_content(path, files[rel])}
    targets = {rel: _target(st, rel, files) for rel in files}
    moving = {os.path.normcase(os.path.abspath(path)) for path in move.values()}
    skip = {rel for rel, path in targets.items() if path is None}
    for rel, path in targets.items():
        if path is None:
            continue
        if os.path.normcase(os.path.abspath(path)) in moving:
            continue  # moved aside first, then downloaded
        if rel in local:
            skip.add(rel)  # same content already
        elif os.path.lexists(path):
            # A target the scan did not see: a symlink, a directory, or an @env file restored
            # to its fallback location.
            if os.path.isfile(path) and not os.path.islink(path) and _same_content(path, files[rel]):
                skip.add(rel)
            elif os.path.isdir(path) and not os.path.islink(path) and not os.listdir(path):
                os.rmdir(path)  # an empty directory where a file belongs holds no data
            else:
                move[rel] = path
                moving.add(os.path.normcase(os.path.abspath(path)))
    displaced = _displace(st, move) if move else None
    touched = {root}
    for rel in sorted(files):
        if rel in skip:
            continue
        _check_term(st)  # between files: the marker makes the next start resume here
        path = targets[rel]
        raw = _retrying(st, 'downloading the S3 snapshot', lambda entry=files[rel]: _get_blob(st, entry))
        _make_private_dirs(root, os.path.dirname(path))
        _atomic_write(path, raw)
        touched.add(os.path.dirname(path))
    for directory in touched:
        _fsync_dir(directory)
    _adopt(st, remote)
    _save_state(st, strict=True)
    os.unlink(marker)
    _fsync_dir(root)
    log.info('panel_storage: cold restore of generation %d: %d files downloaded, %d already present%s',
             st.generation, len(files) - len(skip), len(skip),
             ', %d local files moved to %s' % (len(move), displaced) if move else '')


def _displace(st, move):
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(_now()))
    base = os.path.join(st.root, DISPLACED_PREFIX + stamp)
    suffix = 1
    while os.path.lexists(base):
        suffix += 1
        base = os.path.join(st.root, '%s%s-%d' % (DISPLACED_PREFIX, stamp, suffix))
    for rel in sorted(move):
        if not os.path.lexists(move[rel]):
            continue  # already moved together with its parent directory
        destination = os.path.join(base, *rel.split('/'))
        _make_private_dirs(st.root, os.path.dirname(destination))
        shutil.move(move[rel], destination)
        log.warning('panel_storage: cold restore moved the local %s to %s', rel, os.path.relpath(destination, st.root))
    return os.path.basename(base)


def _remote_people(st, files):
    """users + servers of the committed data.json: the baseline of the emptying guard."""
    entry = (files or {}).get(st.cfg.data_rel)
    if not entry:
        return 0
    try:
        raw = _read_path(os.path.join(st.root, st.cfg.data_rel))
        if hashlib.sha256(raw).hexdigest() == entry['sha256']:
            return _data_facts(raw)[0]
    except OSError:
        pass
    try:
        return _data_facts(_retrying(st, 'reading data.json from S3', lambda: _get_blob(st, entry)))[0]
    except _BlobMissing:
        log.warning('panel_storage: the committed data.json blob is missing; the emptying guard is disarmed')
        return 0


def _check_key_safety(st):
    """Refuse to start when sealed credentials exist but the key is missing or does not open them."""
    import credential_store  # lazily, and never app
    data_file = st.cfg.data_file
    server = None
    try:
        data = json.loads(_read_path(data_file).decode('utf-8'))
    except (OSError, ValueError, UnicodeError):
        data = None
    if isinstance(data, dict) and isinstance(data.get('servers'), list):
        server = next((s for s in data['servers'] if isinstance(s, dict) and s.get('ssh_credentials')), None)
    sealed = None
    if server is None:
        for rel, (path, _) in sorted(_scan(st, env_files={}).items()):
            if not _is_recovery_record(rel):
                continue
            try:
                sealed = _record_envelope(json.loads(_read_path(path).decode('utf-8')))
            except (OSError, ValueError, UnicodeError):
                continue
            if sealed:
                break
    if server is None and sealed is None:
        return
    key_path = credential_store.default_key_path(data_file)
    if not os.path.isfile(key_path):
        raise StorageError('sealed SSH credentials exist but the credential key file is missing; refusing to start '
                           '(the panel would generate a new key and lose access to them)')
    store = credential_store.CredentialStore(key_path)
    try:
        if server is not None:
            store.resolve(server)
        else:
            store.open_bytes(sealed[0], sealed[1])
    except credential_store.CredentialError as exc:
        raise StorageError('the credential key does not open the sealed data (%s); refusing to start' % exc) from None


# ---------------------------------------------------------------- commits

def _commit_round(st, mode):
    """mode: 'run' (sync thread), 'claim' (bootstrap), 'final' (lease release) or 'push' (CLI)."""
    with st.commit_mutex:
        if st.closed or st.fenced:
            return 'closed'
        return _commit_locked(st, mode)


def _commit_locked(st, mode):
    try:
        return _commit_once(st, mode)
    except _ManifestMissing:
        if mode in ('claim', 'push'):
            raise _Conflict('the manifest disappeared') from None
        log.critical('panel_storage: the S3 manifest disappeared while this panel owned it; '
                     're-uploading every blob and recreating it')
        st.etag = None
        st.remote_blobs = set()
        st.uploaded = set()
        return _commit_once(st, mode)


def _build_map(st):
    """W1 stat walk, hash and upload what changed, W2 stat walk; None while the tree keeps changing."""
    for _ in range(MAX_ROUND_REDO):
        round_start = time.time()  # compared with file mtimes, so the real clock
        first = _scan(st)
        _warn_size(st, first)
        files, known, stable = {}, {}, True
        for rel in sorted(first):
            path, stamp = first[rel]
            info = st.known.get(rel)
            raw = None
            # Racy clean: a file modified within 2 s of its hashing may change again
            # without a visible stamp change, so it is hashed again.
            if info is None or info['stamp'] != stamp or stamp[3] >= (info['hashed_at'] - RACY_SECONDS) * 1e9:
                raw = _read_or_none(path, rel)
                if raw is None:
                    stable = False
                    break
                info = _describe(st, rel, raw, stamp, round_start)
            blob = info['blob']
            if blob not in st.remote_blobs and blob not in st.uploaded:
                if raw is None:
                    raw = _read_or_none(path, rel)
                    if raw is None or hashlib.sha256(raw).hexdigest() != info['sha256']:
                        st.known.pop(rel, None)
                        stable = False
                        break
                # Re-PUT anything the current manifest does not reference, even if it
                # may exist: refreshes LastModified, so GC never races a reused blob.
                _put_blob(st, blob, raw)
            known[rel] = info
            files[rel] = {'blob': blob, 'sha256': info['sha256'], 'size': info['size']}
        if stable:
            second = _scan(st)
            stable = second.keys() == first.keys() and all(second[rel][1] == first[rel][1] for rel in first)
        if stable:
            st.known = known
            return files
        st.known.update(known)
    return None


def _warn_size(st, found):
    if st.size_warned:
        return
    total = sum(stamp[2] for _, stamp in found.values())
    if len(found) > WARN_FILES or total > WARN_BYTES:
        st.size_warned = True
        log.warning('panel_storage: the mirrored state is large (%d files, %d MiB); commits and cold restores '
                    'get slower', len(found), total // (1024 * 1024))


def _key_sha(st, files):
    for rel in st.key_rels:
        if rel in files:
            return files[rel]['sha256']
    return None


def _check_guards(st, files):
    old = st.files
    data_rel = st.cfg.data_rel
    if data_rel in old and data_rel not in files:
        return 'data_file_removed'
    people = st.known[data_rel]['people'] if data_rel in files and data_rel in st.known else 0
    if st.committed_people > 0 and people == 0:
        return 'users_and_servers_emptied'
    if any(_is_recovery_record(rel) and rel not in files for rel in old):
        return 'recovery_record_removed'
    old_key, new_key = _key_sha(st, old), _key_sha(st, files)
    if old_key and new_key != old_key:
        return 'credential_key_changed'
    state_files = [rel for rel in files if rel == data_rel or _is_recovery_record(rel)]
    if new_key is None and any(st.known.get(rel, {}).get('sealed') for rel in state_files):
        return 'credential_key_missing'
    return None


def _record_error(st, error):
    st.last_error = _short_error(error)
    st.last_error_at = _iso(_now())


def _heartbeat_due(st):
    return st.last_commit_mono is None or _monotonic() - st.last_commit_mono >= st.cfg.lease_interval


def _commit_once(st, mode):
    files = _build_map(st)
    stale = files is None
    if stale:
        st.pending = True
        if mode == 'run' and not (_heartbeat_due(st) and st.files is not None):
            log.debug('panel_storage: the data directory kept changing; trying again next round')
            return 'unstable'
        if mode in ('run', 'final') and st.files is not None:
            # No consistent cut right now: keep the lease alive with the last consistent snapshot.
            log.warning('panel_storage: the data directory kept changing; committing the last consistent snapshot')
            files = dict(st.files)
        else:
            raise StorageError('the data directory kept changing; no consistent snapshot')
    guard = _check_guards(st, files) if st.files is not None and not stale else None
    overridden = None
    if stale:
        guard = st.guard  # not evaluated this round; keep whatever was reported
    elif guard and not (st.cfg.allow_shrink or st.allow_shrink):
        if mode == 'push':
            raise StorageError('guard:%s: %s; pass --allow-shrink if this is intended' % (guard, GUARD_TEXT[guard]))
        if st.guard != guard:
            log.critical('panel_storage: refusing to upload the local state (guard:%s: %s). S3 keeps the last good '
                         'snapshot; set PANEL_S3_ALLOW_SHRINK=1 once if this is intended', guard, GUARD_TEXT[guard])
        st.guard = guard
        _record_error(st, 'guard:' + guard)
        files = dict(st.files)  # keep heartbeating the last good map
    else:
        if guard:
            overridden = guard
            log.warning('panel_storage: guard:%s (%s) overridden by %s', guard, GUARD_TEXT[guard],
                        '--allow-shrink' if st.allow_shrink else 'PANEL_S3_ALLOW_SHRINK=1')
            guard = None
        if st.guard:
            log.warning('panel_storage: guard:%s cleared', st.guard)
            st.guard = None
    changed = files != (st.files or {})
    st.pending = changed or bool(guard) or stale
    if mode == 'run' and not changed and not _heartbeat_due(st):
        return 'unchanged'
    manifest, _ = _publish(st, files, mode in ('final', 'push'), mode)
    if overridden and st.cfg.allow_shrink:
        # One-shot: the override accepted this shrink; later ones are guarded again.
        st.cfg.allow_shrink = False
        log.warning('panel_storage: PANEL_S3_ALLOW_SHRINK=1 was used for guard:%s; remove it from the environment',
                    overridden)
    if guard is None and not stale:
        st.pending = False
        st.last_error = None
        data = st.known.get(st.cfg.data_rel)
        st.committed_people = data['people'] if data and st.cfg.data_rel in files else 0
    if changed:
        _maybe_history(st, manifest)
    return 'committed'


def _new_manifest(st, files, released):
    manifest = {'format': FORMAT, 'generation': st.generation + 1, 'commit_id': _random_hex(8),
                'parent_commit_id': st.last_commit_id, 'owner': st.owner, 'committed_at': _iso(_now()),
                'panel_version': st.panel_version,
                'lease': {'owner': st.owner, 'released': bool(released), 'interval': st.cfg.lease_interval},
                'files': files}
    body = _encode_manifest(st, manifest)
    st.pending_commit_id = manifest['commit_id']
    _save_state(st, strict=True)  # before the PUT, so a restart recognises the commit as its own
    return manifest, body


def _publish(st, files, released, mode):
    """Idempotent manifest PUT: success is decided by our commit_id, never by the error alone."""
    create = st.etag is None
    manifest = body = last_error = None
    for attempt in range(PUT_ATTEMPTS):
        if attempt:
            _sleep(min(BACKOFF_CAP, 2 ** attempt))
        if manifest is None:
            manifest, body = _new_manifest(st, files, released)
        current = None
        try:
            conditions = {}
            if st.fencing == 'enforced':
                conditions = {'IfNoneMatch': '*'} if create else {'IfMatch': st.etag}
            else:
                # Unfenced provider: read-before-write is the only protection we have.
                current = _current(st, mode)
                verdict = _verdict(st, current, manifest['commit_id'], create)
                if verdict not in ('retry', 'ours'):
                    raise _Verdict(verdict)
                if verdict == 'ours':
                    return _committed(st, manifest, body, current.etag)
            response = st.put_client.put_object(Bucket=st.cfg.bucket, Key=_key(st, 'manifest'), Body=body,
                                                **conditions)
            return _committed(st, manifest, body, response.get('ETag'))
        except _Verdict as decided:
            verdict = str(decided)
        except StorageError:
            raise
        except Exception as exc:
            if not _ambiguous(exc):
                raise
            last_error = exc
            log.warning('panel_storage: manifest PUT got %s; checking whether it was applied', _short_error(exc))
            try:
                current = _current(st, mode)
            except StorageError:
                raise
            except Exception as get_error:
                if not _transient(get_error):
                    raise
                last_error = get_error
                continue
            verdict = _verdict(st, current, manifest['commit_id'], create)
        if verdict == 'ours':
            return _committed(st, manifest, body, current.etag)
        if verdict == 'foreign':
            _foreign(st, current, mode)
        if verdict == 'missing':
            raise _ManifestMissing()
        if verdict == 'own':
            # An earlier commit of this process whose response was lost: build on it.
            _adopt(st, current)
            manifest = None
            create = False
        elif current is not None:
            st.etag = current.etag  # still the manifest we built on: retry with its fresh ETag
            create = False
    raise last_error if last_error is not None else StorageError('manifest PUT did not settle')


class _Verdict(Exception):
    pass


def _current(st, mode):
    try:
        return _get_manifest(st)
    except (StorageError, StorageConfigError):
        # We decoded this prefix at claim time; an unreadable manifest now means a foreign writer.
        _foreign(st, None, mode)


def _verdict(st, current, commit_id, create):
    if current is None:
        return 'retry' if create else 'missing'
    found = current.manifest['commit_id']
    if found == commit_id:
        return 'ours'
    if not create and found == st.last_commit_id:
        return 'retry'
    if current.manifest.get('owner') == st.owner and current.manifest['generation'] > st.generation:
        return 'own'
    return 'foreign'


def _committed(st, manifest, body, etag):
    if not etag:
        current = _get_manifest(st)
        if current is not None and current.manifest['commit_id'] == manifest['commit_id']:
            etag = current.etag
    st.etag = etag
    st.generation = manifest['generation']
    st.last_commit_id = manifest['commit_id']
    st.pending_commit_id = None
    st.files = dict(manifest['files'])
    st.remote_blobs = {entry['blob'] for entry in st.files.values()}
    st.uploaded -= st.remote_blobs
    st.lease_owner = manifest['lease']['owner']
    st.lease_released = manifest['lease']['released']
    st.last_commit_mono = _monotonic()
    st.last_commit_at = manifest['committed_at']
    _save_state(st)
    return manifest, body


def _foreign(st, current, mode):
    owner = 'unknown'
    if current is not None:
        owner = str(current.manifest.get('owner') or 'unknown')
    if mode == 'claim':
        raise _Conflict(owner)
    if mode == 'push':
        raise StorageError('the manifest was changed by %s during the push; nothing was overwritten' % owner)
    st.fenced = True
    _record_error(st, 'fenced')
    log.critical('panel_storage: FENCED: the S3 manifest was committed by another panel (%s). This process exits '
                 'so it cannot overwrite that state; the restarted container waits for the lease.', owner)
    for handler in logging.getLogger().handlers + log.handlers:
        try:
            handler.flush()
        except Exception:
            pass
    _exit(3)
    raise _Fenced(owner)


def _maybe_history(st, manifest):
    if st.cfg.history_days <= 0:
        return
    now = _monotonic()
    if st.last_history_mono is not None and now - st.last_history_mono < HISTORY_INTERVAL:
        return
    name = '%012d-%s' % (manifest['generation'], manifest['commit_id'])
    try:
        body = _encode_manifest(st, manifest, _history_aad(st.cfg.prefix, name))
        st.client.put_object(Bucket=st.cfg.bucket, Key=_key(st, 'history/' + name), Body=body)
        st.last_history_mono = now
    except Exception as exc:
        log.warning('panel_storage: history snapshot failed (%s)', _short_error(exc))


# ---------------------------------------------------------------- garbage collection

def _list_all(st, prefix):
    items, token, server_now = [], None, None
    while True:
        kwargs = {'Bucket': st.cfg.bucket, 'Prefix': prefix}
        if token:
            kwargs['ContinuationToken'] = token
        response = st.client.list_objects_v2(**kwargs)
        if server_now is None:
            server_now = _server_time(_headers(response))
        items.extend(response.get('Contents') or [])
        token = response.get('NextContinuationToken')
        if not response.get('IsTruncated') or not token:
            return items, server_now


def _maybe_gc(st):
    if st.fenced or st.closed or st.initialised_here or not st.claimed:
        return 0
    now = _monotonic()
    if st.last_gc_mono is not None and now - st.last_gc_mono < GC_INTERVAL:
        return 0
    st.last_gc_mono = now
    try:
        return _gc(st)
    except _Fenced:
        raise
    except Exception as exc:
        # GC problems are not sync problems: logged only, not shown in status.
        log.warning('panel_storage: garbage collection failed (%s)', _short_error(exc))
        return 0


def _gc(st):
    bucket = st.cfg.bucket
    live = {entry['blob'] for entry in (st.files or {}).values()}
    history, server_now = _list_all(st, _key(st, 'history/'))
    keep = st.cfg.history_days * 86400
    expired = []
    for obj in history:
        modified = _obj_time(obj)
        if modified is not None and server_now - modified > keep:
            expired.append(obj['Key'])
            continue
        blobs = st.history_cache.get(obj['Key'])
        if blobs is None:
            # History objects are immutable, so their decrypted blob sets are cached.
            body = _read_body(st.client.get_object(Bucket=bucket, Key=obj['Key']))
            manifest = _decode_manifest(st, body, _history_aad(st.cfg.prefix, _history_name(st, obj['Key'])))
            blobs = frozenset(entry['blob'] for entry in manifest['files'].values())
            st.history_cache[obj['Key']] = blobs
        live |= blobs
    listed, server_now = _list_all(st, _key(st, 'blobs/'))
    victims = []
    for obj in listed:
        modified = _obj_time(obj)
        if obj['Key'].rsplit('/', 1)[-1] in live or modified is None or server_now - modified <= GC_MIN_AGE:
            continue
        victims.append(obj['Key'])
    victims += expired
    removed = 0
    if victims:
        # Before the first deletion, not after the last: a GC that fails halfway must not
        # leave a deleted blob marked as uploaded, or the next commit would reference it.
        st.uploaded.clear()
    for start in range(0, len(victims), GC_BATCH):
        if st.flush_request.is_set() or st.fenced or st.closed:
            break
        current = _get_manifest(st)
        if current is None or current.manifest['commit_id'] != st.last_commit_id:
            log.warning('panel_storage: garbage collection stopped: the manifest is no longer ours')
            break
        for key in victims[start:start + GC_BATCH]:
            # DeleteObject per key: DeleteObjects needs Content-MD5, which MinIO/Ceph insist on.
            st.client.delete_object(Bucket=bucket, Key=key)
            st.history_cache.pop(key, None)
            removed += 1
    if removed:
        log.info('panel_storage: garbage collection removed %d objects', removed)
    return removed


# ---------------------------------------------------------------- runtime

def uvicorn_overrides():
    return {'timeout_graceful_shutdown': GRACEFUL_SHUTDOWN} if backend() == 's3' else {}


def start():
    """FastAPI startup hook: start the single sync thread."""
    if backend() == 'local':
        return
    st = _S
    if not st.bootstrapped:
        raise StorageError('PANEL_STORAGE=s3 but panel_storage.bootstrap() did not run in this process: start the '
                           'panel with "python app.py" (not "uvicorn app:app" or --workers); tests must unset '
                           'PANEL_STORAGE')
    with _start_lock:
        if st.thread is not None or st.closed or st.flush_request.is_set():
            return
        st.thread = threading.Thread(target=_sync_loop, args=(st,), name='s3-sync', daemon=True)
        st.thread.start()


def _request_flush(st, timeout=None):
    """Ask for the final flush; returns the moment when waiting for it must end.

    The first request fixes one deadline that every later wait shares (shutdown hook,
    SIGTERM handler, atexit), so the waits never add up past the pod's grace period.
    """
    if st.flush_deadline is None:
        st.flush_deadline = _monotonic() + FINAL_FLUSH_TIMEOUT
    st.flush_request.set()
    if timeout is None:
        return st.flush_deadline
    return min(st.flush_deadline, _monotonic() + timeout)


def _flush_thread(st):
    """The running thread that will do the final flush, if any."""
    for thread in (st.thread, st.flusher):
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            return thread
    return None


def stop(timeout=None):
    """Final flush with lease release (atexit, CLI, tests); idempotent, never raises.

    Waits until the shared shutdown deadline, or for timeout seconds if that ends sooner.
    """
    try:
        if backend() == 'local':
            return
        st = _S
        if not st.bootstrapped or st.closed:
            return
        remaining = _request_flush(st, timeout) - _monotonic()
        if _flush_thread(st) is not None:
            st.flush_done.wait(max(0.0, remaining))
        elif remaining > 0 and st.commit_mutex.acquire(timeout=remaining):
            # No thread to do it (stopped before the startup event): flush here.
            try:
                _final_flush_locked(st)
            finally:
                st.commit_mutex.release()
                st.flush_done.set()
    except Exception as exc:
        log.error('panel_storage: stop failed (%s)', _short_error(exc))


async def stop_async(timeout=None):
    """FastAPI shutdown hook: request the final flush at once and wait without the default executor.

    asyncio.to_thread(stop) would queue behind SSH calls that may hold every executor
    thread until SIGKILL; here the request is immediate and the wait is a poll.
    """
    try:
        if backend() == 'local':
            return
        st = _S
        if not st.bootstrapped or st.closed:
            return
        deadline = _request_flush(st, timeout)
        with _start_lock:
            if _flush_thread(st) is None and not st.closed:
                st.flusher = threading.Thread(target=_final_flush, args=(st,), name='s3-final-flush', daemon=True)
                st.flusher.start()
        while not st.flush_done.is_set() and _monotonic() < deadline:
            await asyncio.sleep(FLUSH_POLL)
    except Exception as exc:
        log.error('panel_storage: stop failed (%s)', _short_error(exc))


def _sync_loop(st):
    failures = 0
    while not st.closed and not st.fenced:
        delay = st.cfg.sync_interval if not failures else min(BACKOFF_CAP, st.cfg.sync_interval * 2 ** failures)
        if st.flush_request.wait(delay):
            break
        try:
            _commit_round(st, 'run')
            failures = 0
            _maybe_gc(st)
        except _Fenced:
            break
        except Exception as exc:
            failures = min(failures + 1, 16)
            _record_error(st, exc)
            log.warning('panel_storage: sync failed (%s); the panel keeps working locally, retrying',
                        _short_error(exc))
    _final_flush(st)


def _final_flush(st):
    try:
        with st.commit_mutex:
            _final_flush_locked(st)
    finally:
        st.flush_done.set()


def _final_flush_locked(st):
    if st.closed or st.fenced:
        st.closed = True
        return
    try:
        _commit_locked(st, 'final')
        log.info('panel_storage: final commit of generation %d; S3 lease released', st.generation)
    except _Fenced:
        pass
    except Exception as exc:
        _record_error(st, exc)
        log.error('panel_storage: final S3 commit failed (%s); the next panel waits until the lease is stale',
                  _short_error(exc))
    finally:
        st.closed = True


def _stamps(st):
    return {rel: stamp for rel, (_, stamp) in _scan(st).items()}


def _drain(st):
    """Wait until the mirrored files have not changed for DRAIN_QUIET s, at most DRAIN_LIMIT s."""
    log.info('panel_storage: SIGTERM: waiting up to %.0fs for running requests to finish writing', DRAIN_LIMIT)
    try:
        begin = quiet_since = _monotonic()
        last = _stamps(st)
        while _monotonic() - quiet_since < DRAIN_QUIET and _monotonic() - begin < DRAIN_LIMIT:
            _sleep(DRAIN_POLL)
            current = _stamps(st)
            if current != last:
                last, quiet_since = current, _monotonic()
    except Exception as exc:
        log.warning('panel_storage: waiting for running requests failed (%s)', _short_error(exc))


def _on_sigterm(signum, frame):
    st = _S
    if st.starting and not st.claimed:
        # Before the claim: only note it; bootstrap() exits at its next safe point,
        # or right here when it is sleeping at one.
        st.term_requested = True
        if st.pausing:
            _check_term(st)
        return
    if st.claimed and not st.closed:
        thread = st.thread
        if not st.flush_request.is_set() and thread is not None and thread.is_alive():
            # Nobody asked for the final flush yet, so uvicorn did not drain the requests:
            # PANEL_FRONT=1 runs it in a thread without signal handling. Let running requests
            # finish writing while the sync thread keeps committing; this handler blocks the
            # front's event loop meanwhile, so no new requests arrive.
            _drain(st)
        deadline = _request_flush(st)
        if _flush_thread(st) is not None:
            st.flush_done.wait(max(0.0, deadline - _monotonic()))
        elif st.commit_mutex.acquire(blocking=False):
            # Signal before the startup event: nobody else can commit, flush here.
            try:
                _final_flush_locked(st)
            finally:
                st.commit_mutex.release()
                st.flush_done.set()
        else:
            # No flush thread, yet the commit lock is taken: this main thread is inside the
            # final commit itself (stop() after a SIGTERM during startup, at exit, or an earlier
            # SIGTERM). A SystemExit here would abort that PUT and keep the lease held; let it
            # finish, the process exits right after it.
            log.warning('panel_storage: SIGTERM during the final commit; letting it finish')
            return
    previous = _previous_sigterm
    if callable(previous):
        previous(signum, frame)
        return
    raise SystemExit(0)


def _install_sigterm():
    global _previous_sigterm, _sigterm_installed
    if _sigterm_installed:
        return
    if threading.current_thread() is not threading.main_thread():
        log.warning('panel_storage: bootstrap() ran outside the main thread; SIGTERM will not trigger the final flush')
        return
    try:
        _previous_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _on_sigterm)
        _sigterm_installed = True
    except (AttributeError, OSError, ValueError) as exc:
        log.warning('panel_storage: cannot install the SIGTERM handler (%s)', type(exc).__name__)


def _reset():
    """Forget all module state (tests). Never flushes."""
    global _S, _previous_sigterm, _sigterm_installed, _atexit_registered
    st = _S
    st.closed = True
    st.flush_request.set()
    for thread in (st.thread, st.flusher):
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(5)
    if st.lock_fd is not None:
        try:
            os.close(st.lock_fd)
        except OSError:
            pass
    if _sigterm_installed:
        try:
            signal.signal(signal.SIGTERM, _previous_sigterm if _previous_sigterm is not None else signal.SIG_DFL)
        except (OSError, ValueError):
            pass
    if _atexit_registered:
        atexit.unregister(stop)
    _previous_sigterm = None
    _sigterm_installed = False
    _atexit_registered = False
    _S = _State()


def _local_dir():
    value = _env('DATA_FILE')
    if value is None:
        base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(
            os.path.abspath(__file__))
        value = os.path.join(base, 'data.json')
    return os.path.dirname(os.path.abspath(os.path.expanduser(value)))


def status():
    """JSON-safe summary for the settings page; never contains secrets."""
    try:
        kind = backend()
    except StorageConfigError:
        return {'backend': 'invalid'}
    if kind == 'local':
        return {'backend': 'local', 'path': _local_dir()}
    st = _S
    cfg = st.cfg
    meta = getattr(st.client, 'meta', None)
    endpoint = getattr(meta, 'endpoint_url', None) or (cfg.endpoint if cfg else _env('PANEL_S3_ENDPOINT_URL'))
    files = st.files or {}
    return {
        'backend': 's3',
        'bucket': cfg.bucket if cfg else _env('PANEL_S3_BUCKET'),
        'prefix': cfg.prefix if cfg else _normalize_prefix(os.environ.get('PANEL_S3_PREFIX')),
        'endpoint': _display_endpoint(endpoint),
        'region': getattr(meta, 'region_name', None) or (cfg.region if cfg else _env('PANEL_S3_REGION')),
        'fencing': st.fencing,
        'generation': st.generation if st.claimed else None,
        'files': len(files),
        'bytes': sum(entry['size'] for entry in files.values()),
        'last_commit_at': st.last_commit_at,
        'last_error': st.last_error if st.bootstrapped else (st.last_error or 'not_bootstrapped'),
        'last_error_at': st.last_error_at,
        'fenced': st.fenced,
        'pending': st.pending,
        'lease_owner': st.lease_owner,
    }


# ---------------------------------------------------------------- CLI

def _cli_state():
    if backend() != 's3':
        raise StorageConfigError('set PANEL_STORAGE=s3 and the PANEL_S3_* variables to use this command')
    st = _State()
    st.cfg = _load_config()
    st.keys = _Keys(st.cfg.master_key)
    st.cfg.master_key = None
    st.client = _make_client(st.cfg, 3)
    st.put_client = _make_client(st.cfg, 1)
    st.cfg.access_key_id = st.cfg.secret_access_key = None
    st.owner = 'cli-' + _owner_id()
    st.panel_version = 'cli'
    st.key_rels = _key_rels(st.cfg)
    return st


def _cli_status(st):
    cfg = st.cfg
    meta = getattr(st.client, 'meta', None)
    out = {'backend': 's3', 'bucket': cfg.bucket, 'prefix': cfg.prefix,
           'endpoint': _display_endpoint(getattr(meta, 'endpoint_url', None) or cfg.endpoint),
           'region': getattr(meta, 'region_name', None) or cfg.region, 'manifest': None}
    current = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
    if current is not None:
        manifest = current.manifest
        lease = _lease_of(manifest)
        out['manifest'] = {
            'generation': manifest['generation'], 'commit_id': manifest['commit_id'],
            'owner': manifest.get('owner'), 'committed_at': manifest.get('committed_at'),
            'panel_version': manifest.get('panel_version'),
            'lease': {'owner': lease.get('owner'), 'released': bool(lease.get('released')),
                      'interval': lease.get('interval'), 'age_seconds': round(_lease_age(current), 1)},
            'files': len(manifest['files']), 'bytes': sum(e['size'] for e in manifest['files'].values()),
        }
    print(json.dumps(out, indent=2, sort_keys=True))
    return out


def _history_manifest(st, generation):
    listed, _ = _retrying(st, 'listing history snapshots',
                          lambda: _list_all(st, _key(st, 'history/%012d-' % generation)))
    if not listed:
        raise StorageError('no history snapshot for generation %d (snapshots are hourly and kept '
                           'PANEL_S3_HISTORY_DAYS days)' % generation)
    key = listed[0]['Key']
    body = _retrying(st, 'reading a history snapshot',
                     lambda: _read_body(st.client.get_object(Bucket=st.cfg.bucket, Key=key)))
    return _decode_manifest(st, body, _history_aad(st.cfg.prefix, _history_name(st, key)))


def _cli_pull(st, target, generation=None):
    target = os.path.abspath(os.path.expanduser(target))
    if os.path.lexists(target):
        if not os.path.isdir(target) or os.listdir(target):
            raise StorageError('pull needs a new or empty directory')
    else:
        os.makedirs(target, 0o700)
    os.chmod(target, 0o700)
    current = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
    if current is None:
        raise StorageError('there is no manifest under this prefix')
    snapshot = current.manifest
    if generation is not None and generation != snapshot['generation']:
        snapshot = _history_manifest(st, generation)
    for rel, entry in sorted(snapshot['files'].items()):
        try:
            raw = _retrying(st, 'downloading %s' % rel, lambda entry=entry: _get_blob(st, entry))
        except _BlobMissing as exc:
            raise StorageError('blob %s of %s is missing' % (exc, rel)) from None
        path = os.path.join(target, *rel.split('/'))
        _make_private_dirs(target, os.path.dirname(path))
        _atomic_write(path, raw)
    info = {'commit_id': snapshot['commit_id'], 'generation': snapshot['generation'], 'etag': current.etag,
            'base_commit_id': current.manifest['commit_id'], 'base_generation': current.manifest['generation']}
    _atomic_write(os.path.join(target, PULL_NAME), json.dumps(info, indent=2, sort_keys=True).encode('utf-8'))
    print('pulled generation %d (%d files) into %s' % (snapshot['generation'], len(snapshot['files']), target))
    return info


def _cli_push(st, source, allow_shrink=False):
    source = os.path.abspath(os.path.expanduser(source))
    if not os.path.isdir(source):
        raise StorageError('%s is not a directory' % source)
    try:
        with open(os.path.join(source, PULL_NAME), 'rb') as handle:
            info = json.loads(handle.read().decode('utf-8'))
        base_commit = info.get('base_commit_id') or info['commit_id']
        pulled_etag = info['etag']
    except (OSError, ValueError, UnicodeError, KeyError, AttributeError, TypeError):
        raise StorageError('%s is missing or unreadable: run "pull" into this directory first' % PULL_NAME) from None
    st.root = source
    st.env_files = {}
    st.allow_shrink = bool(allow_shrink)
    st.fencing = _probe_fencing(st)
    current = _retrying(st, 'reading the S3 manifest', lambda: _get_manifest(st))
    if current is None:
        raise StorageError('there is no manifest under this prefix')
    if current.manifest['commit_id'] != base_commit:
        raise StorageError('the bucket changed since the pull (now generation %d); pull again'
                           % current.manifest['generation'])
    lease = _lease_of(current.manifest)
    try:
        interval = float(lease.get('interval') or st.cfg.lease_interval)
    except (TypeError, ValueError):
        interval = float(st.cfg.lease_interval)
    age = _lease_age(current)
    if not lease.get('released') and age < 3 * interval:
        raise StorageError('the panel %s still holds the lease (last heartbeat %.0fs ago); scale it to 0 first'
                           % (lease.get('owner'), age))
    _adopt(st, current)
    st.etag = pulled_etag
    st.committed_people = _remote_people(st, st.files)
    try:
        _retrying(st, 'pushing the snapshot', lambda: _commit_round(st, 'push'))
    except _Conflict as exc:
        raise StorageError('the bucket changed during the push (%s); nothing was overwritten' % exc) from None
    print('pushed %s as generation %d (%d files); the lease is released' % (source, st.generation, len(st.files)))
    return st.generation


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog='panel_storage.py',
                                     description='Inspect, pull or push the panel state kept in S3 '
                                                 '(PANEL_STORAGE=s3, PANEL_S3_* variables).')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status', help='show the configuration and the manifest (no secrets)')
    pull = commands.add_parser('pull', help='download a snapshot into a new or empty directory')
    pull.add_argument('dir')
    pull.add_argument('--generation', type=int, help='a generation kept in history/ instead of the current one')
    push = commands.add_parser('push', help='commit a pulled directory as a new generation (panel stopped)')
    push.add_argument('dir')
    push.add_argument('--allow-shrink', action='store_true',
                      help='allow removing data.json content, recovery records or the credential key')
    args = parser.parse_args(argv)
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    try:
        st = _cli_state()
        if args.command == 'status':
            _cli_status(st)
        elif args.command == 'pull':
            _cli_pull(st, args.dir, args.generation)
        else:
            _cli_push(st, args.dir, args.allow_shrink)
    except (StorageConfigError, StorageError) as exc:
        print('panel_storage: %s' % exc, file=sys.stderr)
        return 2
    except Exception as exc:
        print('panel_storage: %s failed: %s' % (args.command, _short_error(exc)), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
