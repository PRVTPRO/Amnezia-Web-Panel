"""Bounded panel-state archives. No SSH, live restore or arbitrary host trees."""
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import getpass
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import uuid
import zipfile
import zlib

from peer_recovery import STATE_FILE_LOCK, RecoveryStore, DISASTER_HOLD, digest

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FILES = 2048
PRIVATE_HEADERS = {'Cache-Control': 'no-store, private', 'Pragma': 'no-cache',
                   'X-Content-Type-Options': 'nosniff'}
FORMAT = 'amnezia-panel-state-v1'


class BackupError(RuntimeError):
    """Stable, non-sensitive code only; never include file contents or paths."""


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BackupError('duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BackupError('invalid_number')))
    except (ValueError, UnicodeError, RecursionError):
        raise BackupError('invalid_state_json') from None


def _path(path):
    path = Path(os.path.abspath(os.path.expanduser(path)))
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            raise BackupError('unsafe_state_path')
    return path


def _read(path, limit=MAX_FILE_BYTES):
    try:
        return _read_checked(path, limit)
    except OSError:
        raise BackupError('state_read_failed') from None


def _read_checked(path, limit):
    path = _path(path)
    first = path.stat()
    if not stat.S_ISREG(first.st_mode):
        raise BackupError('unsafe_state_file')
    # Reject unreadable modes before open() too: root can open mode 000,
    # whereas an unprivileged process raises EACCES first. Both must fail closed.
    if first.st_nlink != 1 or not first.st_mode & 0o444 or first.st_size > limit:
        raise BackupError('unreadable_or_oversized_state')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if (_stamp(first) != _stamp(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                not before.st_mode & 0o444 or before.st_size > limit):
            raise BackupError('unreadable_or_oversized_state')
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
        if len(raw) > limit or _stamp(before) != _stamp(after):
            raise BackupError('state_changed')
    return raw, _stamp(after)


def _stamp(value):
    # Windows stat/fstat expose different legacy ctime meanings on Python 3.12.
    # Identity, nanosecond mtime, size, mode and link count still agree. POSIX
    # additionally uses ctime (including metadata-only changes).
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns if os.name != 'nt' else None, value.st_mode, value.st_nlink)


def _recovery_files(root):
    # pathlib.rglob may suppress a permission error and silently omit a whole
    # recovery subtree. Enumerate explicitly; incomplete evidence is not a backup.
    pending, count = [root], 0
    while pending:
        directory = _path(pending.pop())
        mode = directory.stat().st_mode
        if not stat.S_ISDIR(mode):
            raise BackupError('invalid_recovery_directory')
        if os.name != 'nt':
            if mode & 0o077:
                raise BackupError('recovery_directory_not_private')
            if mode & 0o500 != 0o500:
                raise BackupError('unreadable_recovery_directory')
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_FILES * 2:
                        raise BackupError('too_many_state_files')
                    path = _path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    else:
                        yield path
        except OSError:
            raise BackupError('state_read_failed') from None


def _entries(data_file, trust_file, system_trust):
    data = _path(data_file)
    result = {'state/data.json': data}
    optional = {'state/data.json.peer-creates.json': Path(str(data) + '.peer-creates.json'),
                'state/data.json.lifecycle-uncertain.json': Path(str(data) + '.lifecycle-uncertain.json'),
                'trust/ssh_known_hosts': _path(trust_file)}
    if system_trust is not None:
        optional['trust/system_known_hosts'] = _path(system_trust)
    absent = []
    for name, path in optional.items():
        _path(path)
        if path.exists():
            result[name] = path
        else:
            absent.append(name)
    recovery = _path(str(data) + '.recovery')
    if recovery.exists():
        for path in _recovery_files(recovery):
            # Atomic-write scratch files are not durable records. Do not export
            # runtime PID leases or unrelated DATA_FILE siblings either.
            if path.name.startswith(('.recovery-', '.peer-create-', '.ssh-trust-')) or path.suffix in ('.tmp', '.temp'):
                continue
            result['state/data.json.recovery/' + path.relative_to(recovery).as_posix()] = path
            if len(result) > MAX_FILES:
                raise BackupError('too_many_state_files')
    else:
        absent.append('state/data.json.recovery/')
    return result, sorted(absent)


def _validate_content(name, raw):
    if name.startswith('trust/'):
        import paramiko
        try:
            for line in raw.decode('utf-8').splitlines():
                if line.strip() and not line.lstrip().startswith('#'):
                    if paramiko.hostkeys.HostKeyEntry.from_line(line) is None:
                        raise BackupError('invalid_trust_store')
        except Exception:
            raise BackupError('invalid_trust_store') from None
    elif name.endswith('.json'):
        obj = _json(raw)
        if not isinstance(obj, dict):
            raise BackupError('invalid_state_structure')
        if name == 'state/data.json' and any(not isinstance(obj.get(k), list) for k in ('users', 'servers')):
            raise BackupError('invalid_state_structure')


class ArchiveJob:
    """Anonymous private tempfile: OS closes/unlinks it even on process exit."""
    def __init__(self):
        self.file = None

    def close(self):
        if self.file is not None:
            self.file.close()

    def create(self, data_file, trust_file, version, *, journal_lock, trust_lock,
               system_trust=None):
        # Caller holds lifecycle admission then DATA_LOCK. No network is done
        # here. All synchronous writers use STATE_FILE_LOCK; journal and trust
        # writers have their own short locks, in this explicit order.
        try:
            with ExitStack() as stack:
                for lock in (STATE_FILE_LOCK, journal_lock, trust_lock):
                    if not lock.acquire(timeout=5):
                        raise BackupError('state_busy')
                    stack.callback(lock.release)
                entries, absent = _entries(data_file, trust_file, system_trust)
                self.file = tempfile.TemporaryFile(mode='w+b')
                if hasattr(os, 'fchmod'):
                    os.fchmod(self.file.fileno(), 0o600)
                records, stamps, total = [], {}, 0
                with zipfile.ZipFile(self.file, 'w', zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
                    for name, path in sorted(entries.items()):
                        _member(name)
                        raw, stamps[name] = _read(path)
                        total += len(raw)
                        if total > MAX_TOTAL_BYTES:
                            raise BackupError('state_too_large')
                        _validate_content(name, raw)
                        archive.writestr(name, raw)
                        records.append({'path': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                    # Also detect unmanaged replacements/creations during the read.
                    latest, missing = _entries(data_file, trust_file, system_trust)
                    if latest != entries or missing != absent or any(_stamp(p.stat()) != stamps[n] for n, p in latest.items()):
                        raise BackupError('state_changed')
                    manifest = {'format': FORMAT, 'panel_version': version,
                                'created_at': datetime.now(timezone.utc).isoformat(),
                                'files': records, 'absent': absent,
                                'source': {'data_file': str(_path(data_file)), 'ssh_known_hosts_file': str(_path(trust_file))},
                                'counters_verified_final': False, 'remote_nodes_included': False,
                                'restore': 'offline staging and independent node reconciliation only',
                                'external_requirements': ['deployment environment/SECRET_KEY', 'Compose/service configuration',
                                                          'reverse proxy and external TLS certificates']}
                    raw_manifest = json.dumps(manifest, ensure_ascii=False).encode()
                    if len(raw_manifest) > MAX_MANIFEST_BYTES:
                        raise BackupError('manifest_too_large')
                    archive.writestr('manifest.json', raw_manifest)
                self.file.flush()
                os.fsync(self.file.fileno())
                self.file.seek(0)
            return self
        except BaseException:
            self.close()
            raise

    def chunks(self):
        while True:
            chunk = self.file.read(256 * 1024)
            if not chunk:
                break
            yield chunk


def _member(name):
    p = PurePosixPath(name)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
    if (not name or len(name) > 1024 or len(p.parts) > 16 or '\\' in name or any(ord(c) < 32 for c in name) or ':' in name or p.is_absolute() or
            any(part.rstrip('. ') != part or part.split('.')[0].upper() in reserved for part in p.parts) or
            any(s in ('', '.', '..') for s in name.split('/')) or p.as_posix() != name):
        raise BackupError('unsafe_archive_path')
    fixed = {'state/data.json', 'state/data.json.peer-creates.json',
             'state/data.json.lifecycle-uncertain.json', 'trust/ssh_known_hosts', 'trust/system_known_hosts'}
    if name not in fixed and not name.startswith('state/data.json.recovery/'):
        raise BackupError('unexpected_archive_member')
    return p


def read_archive(path):
    """Validate everything before returning bytes; never extract source paths."""
    raw, _ = _read(path, MAX_TOTAL_BYTES + 4 * 1024 * 1024)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(infos) > MAX_FILES + 1 or len(set(names)) != len(names) or 'manifest.json' not in names:
                raise BackupError('invalid_archive_structure')
            total = 0
            for item in infos:
                limit = MAX_MANIFEST_BYTES if item.filename == 'manifest.json' else MAX_FILE_BYTES
                if (item.file_size > limit or item.flag_bits & 1 or
                        item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or
                        stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG) or item.is_dir()):
                    raise BackupError('unsafe_archive_member')
                total += item.file_size
            if total > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
                raise BackupError('archive_too_large')
            manifest = _json(archive.read('manifest.json'))
            if not isinstance(manifest, dict) or manifest.get('format') != FORMAT or not isinstance(manifest.get('files'), list):
                raise BackupError('unsupported_archive')
            files = {}
            for record in manifest['files']:
                name = record['path']; _member(name)
                if name in files or type(record['size']) is not int or record['size'] < 0 or not re.fullmatch('[a-f0-9]{64}', record['sha256']):
                    raise BackupError('invalid_manifest')
                value = archive.read(name)
                if len(value) != record['size'] or hashlib.sha256(value).hexdigest() != record['sha256']:
                    raise BackupError('archive_integrity_failed')
                _validate_content(name, value)
                files[name] = value
            if set(names) != set(files) | {'manifest.json'} or 'state/data.json' not in files:
                raise BackupError('incomplete_archive')
            return manifest, files, hashlib.sha256(raw).hexdigest()
    except (zipfile.BadZipFile, KeyError, TypeError, ValueError, RuntimeError, EOFError, zlib.error) as error:
        if isinstance(error, BackupError):
            raise
        raise BackupError('invalid_archive') from None


STAGE_CONFIRM = 'STAGE OFFLINE; NODES MUST BE RECONCILED; COUNTERS MAY REWIND'


def stage_restore(archive, destination, confirmation):
    """New private tree only. Never overwrite current state, trust or journals.

    The startup hold is durable before the tree is published. Existing offline
    recovery performs the separate, audited release after node reconciliation.
    """
    if confirmation != STAGE_CONFIRM:
        raise BackupError('explicit_confirmation_required')
    manifest, files, checksum = read_archive(archive)
    destination = _path(destination)
    parent = destination.parent
    if destination.exists() or not parent.is_dir():
        raise BackupError('new_private_destination_required')
    claim = parent / ('.' + destination.name + '.restore-claim')
    fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    stage = None
    try:
        stage = Path(tempfile.mkdtemp(prefix='.panel-restore-', dir=parent))
        for name, raw in files.items():
            parts = _member(name).parts
            target = stage.joinpath(*parts)
            # parents=True applies mode only to the leaf, leaving intermediate
            # recovery directories at the process umask's (often 0755) mode.
            for depth in range(1, len(parts)):
                stage.joinpath(*parts[:depth]).mkdir(mode=0o700, exist_ok=True)
            from peer_recovery import atomic_bytes
            atomic_bytes(target, raw)
        data_file = stage / 'state/data.json'
        before = data_file.read_bytes()
        data = _json(before)
        operation = uuid.uuid4().hex
        data[DISASTER_HOLD] = operation
        RecoveryStore(data_file).commit(operation, 'offline:' + getpass.getuser(), 'archive_stage',
                                        digest({'archive_sha256': checksum}), before, data)
        from peer_recovery import atomic_json, _fsync_directory
        atomic_json(stage / 'RESTORE.json', {'archive_sha256': checksum, 'restore_id': operation,
                                            'counters_verified_final': False, 'startup_held': True})
        if destination.exists():
            raise BackupError('destination_changed')
        os.rename(stage, destination)
        stage = None
        _fsync_directory(parent)
        return {'status': 'staged', 'restore_id': operation, 'archive_sha256': checksum,
                'startup_held': True, 'counters_verified_final': False}
    finally:
        os.close(fd)
        claim.unlink()
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
