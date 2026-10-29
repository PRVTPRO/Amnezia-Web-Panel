"""Explicit recovery, not a final-traffic receipt or an ordinary deletion bypass.

Snapshots contain secrets needed for rollback. They are owner-only local files;
only sanitized operation summaries may be returned by HTTP or written to logs.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import threading
import time
from datetime import datetime


STATE_FILE_LOCK = threading.RLock()
GENERATION = '_recovery_generation'
DISASTER_HOLD = '_disaster_recovery_hold'
MAX_BACKUP_BYTES = 32 * 1024 * 1024


class RecoveryError(RuntimeError):
    pass


def prepare_online_restore(current, backup):
    """Restore compatible settings without rewinding live accounting.

    An online restore is not a topology/policy migration. Keep this deliberately
    strict: changed servers, owners, peer configuration or user policy require
    offline recovery. Work on copies so rejected/replayed requests are inert.
    """
    result = copy.deepcopy(backup)
    if not (current.get('user_connections') or current.get('accounting_recoveries')):
        if DISASTER_HOLD in current:
            result[DISASTER_HOLD] = copy.deepcopy(current[DISASTER_HOLD])
        return result

    def incompatible():
        raise RecoveryError('online_restore_accounting_conflict')

    if current.get('servers', []) != backup.get('servers', []):
        incompatible()
    if current.get('accounting_recoveries', []) != backup.get('accounting_recoveries', []):
        incompatible()

    runtime_user = {'traffic_used', 'traffic_total', 'last_reset_at',
                    'access_revision', 'access_sync_pending'}
    runtime_connection = {'last_bytes', 'traffic_observed_at', 'traffic_counter_epoch',
                          'last_rx_bytes', 'last_tx_bytes', 'traffic_accounting_gap'}

    def indexed(rows, ignored):
        if not isinstance(rows, list):
            incompatible()
        indexed_rows = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('id'), (str, int)):
                incompatible()
            key = row['id']
            if key in indexed_rows:
                incompatible()
            indexed_rows[key] = {k: v for k, v in row.items() if k not in ignored}
        return indexed_rows

    users = indexed(current.get('users', []), runtime_user)
    if users != indexed(backup.get('users', []), runtime_user):
        incompatible()
    connections = indexed(current.get('user_connections', []), runtime_connection)
    if connections != indexed(backup.get('user_connections', []), runtime_connection):
        incompatible()
    for conn in current.get('user_connections', []):
        sid = conn.get('server_id')
        if (conn.get('user_id') not in users or type(sid) is not int
                or not 0 <= sid < len(current.get('servers', []))):
            incompatible()

    for key in ('users', 'user_connections', 'accounting_recoveries', GENERATION, DISASTER_HOLD):
        if key in current:
            result[key] = copy.deepcopy(current[key])
        else:
            result.pop(key, None)
    return result


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def file_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _fsync_directory(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_bytes(path, raw):
    path = Path(path)
    if path.is_symlink():
        raise RecoveryError('unsafe_recovery_path')
    fd, temp = tempfile.mkstemp(prefix='.recovery-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def atomic_json(path, data):
    atomic_bytes(path, json.dumps(data, indent=2, ensure_ascii=False,
                                allow_nan=False).encode())


def validate_backup(raw):
    if not raw or len(raw) > MAX_BACKUP_BYTES:
        raise RecoveryError('invalid_backup_size')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RecoveryError('duplicate_json_key')
            result[key] = value
        return result
    try:
        data = json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(RecoveryError('invalid_number')))
    except (ValueError, UnicodeError, RecursionError):
        raise RecoveryError('invalid_backup_json') from None
    if not isinstance(data, dict) or any(not isinstance(data.get(k), list) for k in ('servers', 'users')):
        raise RecoveryError('invalid_backup_structure')
    conns = data.get('user_connections', [])
    if not isinstance(conns, list) or not isinstance(data.get('settings', {}), dict):
        raise RecoveryError('invalid_backup_structure')
    def unique(items, field):
        ids = [item.get(field) for item in items if isinstance(item, dict)]
        if len(ids) != len(items) or any(not isinstance(v, str) or not v for v in ids) or len(set(ids)) != len(ids):
            raise RecoveryError('invalid_backup_identity')
        return set(ids)
    users = unique(data['users'], 'id')
    # Old backups may lack server UIDs; the caller backfills after validation.
    uids = [s.get('uid') for s in data['servers'] if isinstance(s, dict) and s.get('uid')]
    if any(not isinstance(s, dict) for s in data['servers']) or any(not isinstance(uid, str) for uid in uids) or len(set(uids)) != len(uids):
        raise RecoveryError('invalid_server_identity')
    unique(conns, 'id')
    scopes = set()
    from peer_accounting import _protocol_scope
    for conn in conns:
        sid = conn.get('server_id')
        if type(sid) is not int or not 0 <= sid < len(data['servers']) or conn.get('user_id') not in users:
            raise RecoveryError('invalid_connection_owner')
        if not isinstance(conn.get('client_id'), str) or not conn['client_id'] or not isinstance(conn.get('protocol'), str):
            raise RecoveryError('invalid_connection_identity')
        scope = (sid, _protocol_scope(conn['protocol']), conn['client_id'])
        if scope in scopes:
            raise RecoveryError('duplicate_peer_ownership')
        scopes.add(scope)
    for item in data['users'] + conns:
        for key in ('traffic_used', 'traffic_total', 'traffic_limit', 'last_bytes'):
            if key in item and (type(item[key]) is not int or item[key] < 0):
                raise RecoveryError('invalid_accounting_counter')
    return data


def process_alive(pid):
    if type(pid) is not int or pid <= 0:
        raise RecoveryError('invalid_runtime_process')
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    # os.kill(pid, 0) terminates processes on Windows; use a read-only handle.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: no such PID
            return False
        raise RecoveryError('runtime_process_state_unknown')
    try:
        result = kernel.WaitForSingleObject(handle, 0)
        if result not in (0, 258):
            raise RecoveryError('runtime_process_state_unknown')
        return result == 258
    finally:
        kernel.CloseHandle(handle)


class PanelLease:
    """One running panel OR one offline recovery process, never both.

    The panel takes this lease before starting background tasks. Recovery does
    not try to cancel SSH work by killing a running panel.
    """
    def __init__(self, data_file, *, runtime=False, recovery=False):
        self.path = Path(str(data_file) + '.runtime.lock')
        self.file = None
        self.runtime = runtime
        self.recovery = recovery

    def acquire(self):
        if self.path.is_symlink():
            raise RecoveryError('unsafe_lease_path')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        self.file = os.fdopen(fd, 'r+b')
        try:
            if os.name == 'nt':
                import msvcrt
                if not self.path.stat().st_size:
                    self.file.write(b'0')
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise RecoveryError('panel_or_recovery_running') from None
        if self.recovery:
            # ASGI shutdown can precede thread/task termination. Closing the
            # advisory handle is NOT proof that the old process has exited.
            self.file.seek(0)
            try:
                marker = json.loads(self.file.read() or b'0')
            except ValueError:
                self.close()
                raise RecoveryError('invalid_runtime_lease') from None
            if isinstance(marker, dict) and marker.get('runtime'):
                try:
                    alive = process_alive(marker['pid'])
                except (OSError, ValueError, KeyError, RecoveryError):
                    self.close()
                    raise RecoveryError('runtime_process_state_unknown') from None
                if alive:
                    self.close()
                    raise RecoveryError('panel_process_still_running')
        if self.runtime:
            try:
                self.file.seek(0)
                self.file.truncate()
                self.file.write(json.dumps({'runtime': True, 'pid': os.getpid()}).encode())
                self.file.flush()
                os.fsync(self.file.fileno())
                _fsync_directory(self.path.parent)
            except BaseException:
                self.close()
                raise
        return self

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *args):
        self.close()


class RecoveryStore:
    def __init__(self, data_file):
        self.data_file = Path(data_file)
        self.root = Path(str(data_file) + '.recovery')

    def _path(self, operation_id):
        if not re.fullmatch(r'[a-f0-9]{32}', operation_id):
            raise RecoveryError('invalid_operation_id')
        if self.root.is_symlink():
            raise RecoveryError('unsafe_recovery_path')
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=True)
            _fsync_directory(self.root.parent)
        if os.name != 'nt' and self.root.stat().st_mode & 0o077:
            raise RecoveryError('recovery_directory_not_private')
        path = self.root / (operation_id + '.json')
        if path.is_symlink():
            raise RecoveryError('unsafe_recovery_path')
        return path

    def replay(self, operation_id, actor, kind, intent):
        path = self._path(operation_id)
        if not path.exists():
            return None
        record = json.loads(path.read_bytes())
        if (record['actor'], record['kind'], record['intent']) != (actor, kind, intent):
            raise RecoveryError('operation_conflict')
        current = self.data_file.read_bytes() if self.data_file.exists() else b''
        try:
            committed_generation = json.loads(current).get(GENERATION) == operation_id
        except (ValueError, AttributeError):
            committed_generation = False
        if file_hash(current) == record['after_sha256'] or committed_generation:
            if record['phase'] != 'committed':
                record['phase'] = 'committed'
                record['audit'].append({'event': 'commit_recovered', 'at': int(time.time())})
                atomic_json(path, record)
            return {'status': 'success', 'operation_id': operation_id, 'replayed': True,
                    'counters_verified_final': False}
        if record['phase'] == 'committed':
            # A completed request must never restore its old "after" over later
            # legitimate writes. The durable journal is its idempotency record.
            return {'status': 'success', 'operation_id': operation_id, 'replayed': True,
                    'counters_verified_final': False}
        if file_hash(current) != record['before_sha256']:
            raise RecoveryError('recovery_state_changed')
        return None

    def commit(self, operation_id, actor, kind, intent, before, after):
        """Called under DATA_LOCK + STATE_FILE_LOCK online, or PanelLease offline."""
        replay = self.replay(operation_id, actor, kind, intent)
        if replay:
            return replay
        path = self._path(operation_id)
        after = copy.deepcopy(after)
        after[GENERATION] = operation_id
        output = json.dumps(after, indent=2, ensure_ascii=False, allow_nan=False).encode()
        record = {'version': 1, 'actor': actor, 'kind': kind, 'intent': intent,
                  'before_sha256': file_hash(before), 'before_base64': base64.b64encode(before).decode(),
                  'after_sha256': file_hash(output), 'phase': 'prepared',
                  'counters_verified_final': False,
                  'audit': [{'event': 'prepared', 'at': int(time.time())}]}
        companion = Path(str(self.data_file) + '.peer-creates.json')
        if companion.exists():
            if companion.is_symlink():
                raise RecoveryError('unsafe_recovery_path')
            raw = companion.read_bytes()
            record['peer_creates_snapshot'] = {'sha256': file_hash(raw),
                                              'base64': base64.b64encode(raw).decode()}
        # Snapshot and its audit are one fsynced atomic object, before data write.
        # Any error here forbids the destructive write.
        atomic_json(path, record)
        current = self.data_file.read_bytes() if self.data_file.exists() else b''
        if not hashlib.sha256(current).digest() == hashlib.sha256(before).digest():
            raise RecoveryError('recovery_state_changed')
        atomic_bytes(self.data_file, output)
        record['phase'] = 'committed'
        record['audit'].append({'event': 'committed', 'at': int(time.time())})
        atomic_json(path, record)  # Failure is NOT success; retry recovers by hash.
        return {'status': 'success', 'operation_id': operation_id, 'replayed': False,
                'counters_verified_final': False}


def orphan_scope(data, connection_id):
    matches = [c for c in data.get('user_connections', []) if c.get('id') == connection_id]
    if len(matches) != 1:
        raise RecoveryError('connection_not_unique')
    conn = matches[0]
    if any(u.get('id') == conn.get('user_id') for u in data.get('users', [])):
        raise RecoveryError('connection_has_existing_owner')
    sid = conn.get('server_id')
    if type(sid) is not int or not 0 <= sid < len(data.get('servers', [])):
        raise RecoveryError('server_identity_unavailable')
    server = data['servers'][sid]
    if not server.get('uid') or sum(s.get('uid') == server['uid'] for s in data['servers']) != 1:
        raise RecoveryError('server_identity_unavailable')
    from peer_accounting import _protocol_scope
    base, instance = _protocol_scope(conn.get('protocol'))
    if not isinstance(conn.get('client_id'), str) or not conn['client_id']:
        raise RecoveryError('client_identity_unavailable')
    return conn, server, {'connection_id': connection_id, 'server_uid': server['uid'],
                          'protocol': base, 'instance': instance, 'client_id': conn['client_id']}


def require_repair_target(data, user_id):
    user = next((u for u in data.get('users', []) if u.get('id') == user_id), None)
    if not user:
        raise RecoveryError('target_user_missing')
    # Binding must not give a pre-existing active orphan to a manually blocked,
    # expired or exhausted account. No toggle/enable is performed by recovery.
    try:
        if not user.get('enabled', True) or user.get('disable_reasons'):
            raise ValueError()
        limit = user.get('traffic_limit', 0)
        if limit and user.get('traffic_used', 0) >= limit:
            raise ValueError()
        if user.get('expiration_date'):
            expiry = datetime.fromisoformat(user['expiration_date'])
            if expiry <= datetime.now(expiry.tzinfo):
                raise ValueError()
    except (ValueError, TypeError):
        raise RecoveryError('target_access_blocked_or_unknown') from None


def verify_awg_peer_absent(ssh, protocol, client_id):
    """Strict read-only absence evidence, NOT final accounting/quiescence.

    Ordinary get_clients() may swallow SSH errors. Require successful reads of
    persistent metadata, every supported config candidate and native peers.
    This deliberately excludes unverified protocol backends.
    """
    from managers.awg_manager import AWGManager
    from peer_accounting import _protocol_scope
    base, instance = _protocol_scope(protocol)
    if base not in {'awg', 'awg2', 'awg3', 'awg_legacy'}:
        raise RecoveryError('absence_verification_not_supported')
    canonical = base if instance == 1 else base + '__' + str(instance)
    manager = AWGManager(ssh)
    container = manager._container_name(canonical)
    def command(inner, optional=False):
        out, err, code = ssh.run_sudo_command('docker exec ' + shlex.quote(container) +
                                             ' sh -c ' + shlex.quote(inner), timeout=15)
        if optional and code == 44:
            return None
        if code != 0 or not isinstance(out, str):
            raise RecoveryError('absence_verification_failed')
        return out
    table = json.loads(command('cat ' + shlex.quote(manager._clients_table_path())))
    if not isinstance(table, list) or any(not isinstance(c, dict) or not isinstance(c.get('clientId'), str) for c in table):
        raise RecoveryError('incomplete_peer_state')
    if any(c['clientId'] == client_id for c in table):
        raise RecoveryError('peer_still_present_restore_ownership_instead')
    found_config = False
    for path in manager._config_path_candidates(canonical):
        config = command('if [ -f ' + shlex.quote(path) + ' ]; then cat ' + shlex.quote(path) + '; else exit 44; fi', optional=True)
        if config is None:
            continue
        found_config = True
        if '[Interface]' not in config:
            raise RecoveryError('incomplete_peer_state')
        for line in config.splitlines():
            # wg config accepts inline comments; do not mistake a commented
            # PublicKey line for absence while the interface is stopped.
            line = line.split('#', 1)[0].strip()
            match = re.fullmatch(r'PublicKey\s*=\s*(\S+)', line, re.IGNORECASE)
            if line.lower().startswith('publickey') and match is None:
                raise RecoveryError('incomplete_peer_state')
            if match and match[1] == client_id:
                raise RecoveryError('peer_still_present_restore_ownership_instead')
    if not found_config:
        raise RecoveryError('incomplete_peer_state')
    native = command(shlex.quote(manager._wg_binary(canonical)) + ' show all peers')
    for line in native.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise RecoveryError('incomplete_peer_state')
        if fields[1] == client_id:
            raise RecoveryError('peer_still_present_restore_ownership_instead')
    return True


def check_create_journal(data_file, *, replacement=None, scope=None):
    """Compatibility with the independent disabled-first create journal (#242).

    Do not copy, clear or reinterpret unfinished intents as absent peers. Keep
    completed ownership matched when a full JSON backup is restored.
    """
    path = Path(str(data_file) + '.peer-creates.json')
    if not path.exists():
        return
    if path.is_symlink():
        raise RecoveryError('unsafe_recovery_path')
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_BACKUP_BYTES + 1)
        if len(raw) > MAX_BACKUP_BYTES:
            raise ValueError()
        operations = json.loads(raw)
        if not isinstance(operations, dict):
            raise ValueError()
        from peer_accounting import _protocol_scope
        for operation in operations.values():
            identity = operation['identity']
            if not isinstance(identity, list) or len(identity) != 4:
                raise ValueError()
            if scope is not None:
                if identity[1] == scope['server_uid'] and _protocol_scope(identity[2]) == (scope['protocol'], scope['instance']) and operation['public'] == scope['client_id']:
                    raise RecoveryError('peer_create_recovery_required')
                continue
            if operation['phase'] not in ('complete', 'blocked'):
                raise RecoveryError('peer_create_recovery_required')
            links = (replacement or {}).get('user_connections', [])
            match = next((c for c in links if c.get('id') == operation['id'] and c.get('user_id') == identity[0]
                          and c.get('client_id') == operation['public'] and _protocol_scope(c.get('protocol')) == _protocol_scope(identity[2])), None)
            servers = (replacement or {}).get('servers', [])
            if match is None or type(match.get('server_id')) is not int or not 0 <= match['server_id'] < len(servers):
                raise RecoveryError('peer_create_recovery_required')
            server = servers[match['server_id']]
            if server.get('uid') != identity[1] or [server.get('host'), server.get('ssh_port', 22), server.get('username')] != operation['endpoint']:
                raise RecoveryError('peer_create_recovery_required')
    except (ValueError, KeyError, TypeError):
        raise RecoveryError('invalid_peer_create_journal') from None
