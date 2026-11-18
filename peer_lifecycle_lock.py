"""Serialize peer/inventory mutations without holding the data lock over SSH."""
import asyncio
import contextvars
from contextlib import asynccontextmanager
import functools
import inspect
import json
import logging
import pathlib
import time
import traceback
import weakref


_mutation_locks = weakref.WeakKeyDictionary()
_active = contextvars.ContextVar('peer_lifecycle_active', default=False)
_uncertain = contextvars.ContextVar('peer_lifecycle_uncertain', default=None)
_operation = contextvars.ContextVar('peer_lifecycle_operation', default=None)
logger = logging.getLogger(__name__)
# Admission and HTTP response budgets, NOT cancellation deadlines for SSH.
QUEUE_WAIT_SECONDS = 10.0
RESPONSE_WAIT_SECONDS = 300.0
_fence_path = None
_fenced = False
# None with _fenced set means a global fence (legacy marker or unknown target).
_fenced_scope = None
# Resolvers configured by app.py: server_id -> identity dict, and
# fenced uid -> uids whose operations depend on that server (exit links).
_identity_resolver = None
_dependency_resolver = None
_marker_cache = {'key': None, 'value': None}
_running = weakref.WeakKeyDictionary()


class PeerLifecycleBusy(RuntimeError):
    code = 'peer_lifecycle_busy'


class PeerLifecycleUncertain(RuntimeError):
    code = 'peer_lifecycle_uncertain'


def configure(data_file):
    global _fence_path, _fenced, _fenced_scope
    _fence_path = pathlib.Path(str(data_file) + '.lifecycle-uncertain.json')
    _fenced = False
    _fenced_scope = None
    _invalidate_marker_cache()


def configure_resolvers(identity_for_server, dependent_uids):
    """Wire panel knowledge into the standalone interlock.

    ``identity_for_server(server_id)`` returns a dict with ``server_uid``,
    ``host``, ``ssh_port`` and ``username`` (or None for an unknown target).
    ``dependent_uids(server_uid)`` returns the uids of servers whose lifecycle
    operations touch that server (exit-link pairs).
    """
    global _identity_resolver, _dependency_resolver
    _identity_resolver = identity_for_server
    _dependency_resolver = dependent_uids


def read_marker():
    """Marked-fence contents for diagnostics, never for decisions.

    Returns None when there is no marker; ``{'unreadable': True}`` for a
    corrupt one (the fence stays closed: an unreadable marker is still a
    marker). Only non-secret fields are exposed: the marker never stores
    credentials, commands or tracebacks.
    """
    if not _fence_path:
        return None
    try:
        stat = _fence_path.stat()
        cache_key = (stat.st_mtime_ns, stat.st_size)
    except FileNotFoundError:
        _marker_cache.update(key=None, value=None)
        return None
    except Exception:
        return {'unreadable': True}
    if _marker_cache['key'] == cache_key:
        return _marker_cache['value']
    try:
        raw = _fence_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
    except Exception:
        return {'unreadable': True}
    try:
        marker = json.loads(raw)
    except Exception:
        marker = {'unreadable': True}
    if not isinstance(marker, dict):
        marker = {'unreadable': True}
    _marker_cache.update(key=cache_key, value=marker)
    return marker


def _invalidate_marker_cache():
    _marker_cache.update(key=None, value=None)


def diagnostics():
    marker = read_marker()
    details = {'blocked': _fenced or bool(marker),
               'running': [{'operation': item['operation'],
                            'elapsed_seconds': int(time.monotonic() - item['started'])}
                           for item in list(_running.values())]}
    if not marker:
        return details
    if marker.get('unreadable'):
        details.update({'reason': 'marker_unreadable', 'created_at': None,
                        'age_seconds': None, 'marker_version': None,
                        'scope': None, 'operation': None})
        return details
    created = marker.get('created_at')
    created = int(created) if isinstance(created, (int, float)) else None
    scope = marker.get('scope') if isinstance(marker.get('scope'), dict) else None
    operation = marker.get('operation') if isinstance(marker.get('operation'), dict) else None
    details.update({'reason': str(marker.get('reason') or 'unknown'),
                    'created_at': created,
                    'age_seconds': int(time.time() - created) if created else None,
                    'marker_version': marker.get('version'),
                    # No scope = legacy global marker; never guess a server.
                    'scope': scope,
                    'operation': operation})
    return details


def _is_scope(value):
    return isinstance(value, dict) and bool(value)


def fence_scope():
    """(blocked, scope). ``scope`` None means the fence is global."""
    if _fenced:
        return True, _fenced_scope
    marker = read_marker()
    if not marker:
        return False, None
    if marker.get('unreadable'):
        return True, None
    scope = marker.get('scope')
    return True, scope if _is_scope(scope) else None


def normalize_identity(identity):
    """Keep only the fields that identify a server for the fence."""
    if not isinstance(identity, dict) or not identity.get('host'):
        return None
    try:
        port = int(identity.get('ssh_port') or 22)
    except (TypeError, ValueError):
        port = 22
    uid = identity.get('server_uid')
    return {'server_uid': str(uid) if uid else None,
            'host': str(identity['host']),
            'ssh_port': port,
            'username': str(identity.get('username') or '')}


def identities_match(scope, identity):
    """True when a fence scope and a command target are the same server.

    The uid is the strong key, but a re-created inventory record can keep the
    same connection coordinates with a new uid (and a pooled manager can hold
    the previous one), so matching coordinates also count: over-blocking the
    same host is safe, under-blocking it is not.
    """
    scope = normalize_identity(scope)
    identity = normalize_identity(identity)
    if not scope or not identity:
        return False
    if scope['server_uid'] and identity['server_uid'] \
            and scope['server_uid'] == identity['server_uid']:
        return True
    return (scope['host'] == identity['host']
            and scope['ssh_port'] == identity['ssh_port']
            and scope['username'] == identity['username'])


def _depends_on_fenced(scope, identity):
    if not _dependency_resolver:
        return False
    scope = normalize_identity(scope)
    identity = normalize_identity(identity)
    if not scope or not identity or not scope['server_uid'] or not identity['server_uid']:
        return False
    try:
        dependents = _dependency_resolver(scope['server_uid']) or ()
    except Exception:
        # A broken resolver must not open the fence: treat the target as
        # dependent (see caller) by reporting True.
        logger.warning('Lifecycle dependency resolver failed; blocking the target',
                       exc_info=True)
        return True
    return identity['server_uid'] in {str(item) for item in dependents}


def check_remote_fence(identity=None):
    """Refuse a remote operation when the fence covers it.

    A global fence (legacy marker without identity, unreadable marker, or an
    operation that cannot name its server) refuses everything, as before. A
    scoped fence refuses the affected server and the servers whose lifecycle
    operations touch it, while unrelated healthy servers keep working.
    """
    blocked, scope = fence_scope()
    if not blocked:
        return
    if scope is None or identity is None:
        raise PeerLifecycleUncertain('peer_lifecycle_uncertain')
    if identities_match(scope, identity) or _depends_on_fenced(scope, identity):
        raise PeerLifecycleUncertain('peer_lifecycle_uncertain')


def lifecycle_active():
    """True while an admitted lifecycle operation owns the interlock.

    The SSH layer uses this to tell a plain read (where a single retry after a
    dead-transport exec failure is harmless) from a mutation under the
    interlock, where re-running a command with an unknown outcome would mean
    executing it twice.
    """
    return bool(_active.get())


@asynccontextmanager
async def snapshot_interlock():
    """Quiesce managed lifecycle writes for a local backup, including fences.

    A fence is archived as evidence, never cleared. This read-only operation
    does not claim remote quiescence or final counters. One panel process only.
    """
    loop = asyncio.get_running_loop()
    lock = _mutation_locks.setdefault(loop, asyncio.Lock())
    if _active.get():
        raise PeerLifecycleBusy('backup_during_lifecycle')
    try:
        async with asyncio.timeout(QUEUE_WAIT_SECONDS):
            await lock.acquire()
    except asyncio.TimeoutError:
        raise PeerLifecycleBusy('peer_lifecycle_busy') from None
    try:
        yield
    finally:
        lock.release()


def _merge_scope(scope):
    """Never narrow a fence; widen to global when identities conflict.

    The first recorded incident keeps its server identity. A legacy marker, an
    unreadable marker, an incident that cannot name its server, or a second
    incident on another server all end as a global fence: guessing which
    server is affected would be worse than blocking everything.
    """
    existing = read_marker() or {}
    if existing.get('unreadable'):
        return None
    existing_scope = existing.get('scope')
    existing_scope = existing_scope if _is_scope(existing_scope) else None
    if not existing:
        return scope
    if existing_scope is None or scope is None:
        return None
    if identities_match(existing_scope, scope):
        return existing_scope
    return None


def note_ssh_uncertainty(scope=None):
    """A lost SSH reply is not proof the remote command has stopped.

    Keep a durable logical interlock after the worker exits. No automatic retry
    or HTTP deadline may clear it. Only an offline, independently verified
    operator recovery may archive this fence. When the SSH layer knows which
    server it was talking to, that identity is recorded so the fence covers the
    affected server (and its exit-link partners) instead of the whole panel.
    """
    global _fenced, _fenced_scope
    if not _active.get():
        return
    _fenced = True
    marker_scope = _merge_scope(normalize_identity(scope))
    _fenced_scope = marker_scope
    marker = _uncertain.get()
    if marker is not None:
        marker['unknown'] = True
        marker['scope'] = marker_scope
    if _fence_path:
        from peer_recovery import atomic_json
        payload = {'version': 2, 'created_at': int(time.time()),
                   'reason': 'ssh_result_unknown'}
        if marker_scope is not None:
            payload['scope'] = marker_scope
        operation = _operation.get()
        if isinstance(operation, dict):
            payload['operation'] = operation
        try:
            atomic_json(_fence_path, payload)
            _invalidate_marker_cache()
        except Exception:
            # In-memory fence stays closed even when durable storage fails.
            logger.error('Cannot persist lifecycle fence; keep panel offline after shutdown')
    logger.error('SSH result unknown; lifecycle admission fenced pending independent verification')


def _admission_check(function, args, kwargs):
    """Refuse admission only when a fence exists (no inventory read otherwise)."""
    blocked, _scope = fence_scope()
    if not blocked:
        return
    check_remote_fence(_target_identity(function, args, kwargs))


def _target_identity(function, args, kwargs):
    """Identity of the server an endpoint targets, if it names one."""
    if not _identity_resolver:
        return None
    try:
        bound = inspect.signature(function).bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        return None
    server_id = bound.arguments.get('server_id')
    if not isinstance(server_id, int):
        return None
    try:
        return _identity_resolver(server_id)
    except Exception:
        logger.warning('Cannot resolve the lifecycle target server; fence stays global',
                       exc_info=True)
        return None


def serialize_peer_lifecycle(function):
    """Interlock ownership changes with destructive network operations.

    This is separate from DATA_LOCK: reads, traffic commits and access intent
    updates continue while SSH runs. As with DATA_LOCK, one panel process is
    required. A cancelled waiter never runs; an already-started worker keeps
    the interlock until its external effects and local commit have finished.
    """
    @functools.wraps(function)
    async def wrapped(*args, **kwargs):
        async def invoke():
            if inspect.iscoroutinefunction(function):
                return await function(*args, **kwargs)
            return await asyncio.to_thread(function, *args, **kwargs)
        if _active.get():
            return await invoke()
        loop = asyncio.get_running_loop()
        lock = _mutation_locks.setdefault(loop, asyncio.Lock())
        started = asyncio.Event()

        async def work():
            try:
                async with asyncio.timeout(QUEUE_WAIT_SECONDS):
                    await lock.acquire()
            except asyncio.TimeoutError:
                raise PeerLifecycleBusy('peer_lifecycle_busy') from None
            try:
                _admission_check(function, args, kwargs)
                started.set()
                token = _active.set(True)
                uncertain = _uncertain.set({'unknown': False})
                operation = _operation.set({'kind': 'lifecycle',
                                            'label': function.__name__})
                _running[loop] = {'operation': function.__name__, 'started': time.monotonic()}
                try:
                    result = await invoke()
                    if _uncertain.get()['unknown']:
                        raise PeerLifecycleUncertain('peer_lifecycle_uncertain')
                    return result
                except (TimeoutError, ConnectionError) as exc:
                    if getattr(exc, 'nothing_executed', False):
                        # Nothing was executed: the server refused to start the
                        # operation (busy lock, open breaker). That is a known
                        # outcome, not uncertainty, so it must not latch the
                        # durable fence.
                        raise
                    note_ssh_uncertainty()
                    raise PeerLifecycleUncertain('peer_lifecycle_uncertain') from None
                finally:
                    _running.pop(loop, None)
                    _operation.reset(operation)
                    _uncertain.reset(uncertain)
                    _active.reset(token)
            finally:
                lock.release()  # The durable logical fence still rejects new work.

        task = asyncio.create_task(work())
        def finished(done):
            if done.cancelled():
                logger.debug('Queued lifecycle worker cancelled before admission')
                return
            error = done.exception()
            if error is not None and not isinstance(error, (PeerLifecycleBusy, PeerLifecycleUncertain)) and not hasattr(error, 'status_code') and not hasattr(error, 'code'):
                # Traceback without exception text/locals: SSH exceptions can
                # carry credentials, commands or private configuration content.
                frames = ''.join('  File "%s", line %s, in %s\n' %
                                 (frame.f_code.co_filename, line, frame.f_code.co_name)
                                 for frame, line in traceback.walk_tb(error.__traceback__))
                logger.error('Lifecycle worker failed\nTraceback (most recent call last):\n%s%s: details redacted',
                             frames, type(error).__name__)
        task.add_done_callback(finished)
        try:
            return await asyncio.wait_for(asyncio.shield(task), RESPONSE_WAIT_SECONDS)
        except asyncio.TimeoutError:
            logger.warning('Lifecycle response deadline reached; worker retains interlock (%s)', function.__name__)
            raise PeerLifecycleBusy('peer_lifecycle_still_running') from None
        except asyncio.CancelledError:
            if not started.is_set():
                task.cancel()
            raise
    return wrapped
