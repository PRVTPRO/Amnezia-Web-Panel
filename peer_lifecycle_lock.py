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
logger = logging.getLogger(__name__)
# Admission and HTTP response budgets, NOT cancellation deadlines for SSH.
QUEUE_WAIT_SECONDS = 10.0
RESPONSE_WAIT_SECONDS = 300.0
_fence_path = None
_fenced = False
_running = weakref.WeakKeyDictionary()


class PeerLifecycleBusy(RuntimeError):
    code = 'peer_lifecycle_busy'


class PeerLifecycleUncertain(RuntimeError):
    code = 'peer_lifecycle_uncertain'


def configure(data_file):
    global _fence_path, _fenced
    _fence_path = pathlib.Path(str(data_file) + '.lifecycle-uncertain.json')
    _fenced = False


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
        raw = _fence_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return None
    except Exception:
        return {'unreadable': True}
    try:
        marker = json.loads(raw)
    except Exception:
        return {'unreadable': True}
    return marker if isinstance(marker, dict) else {'unreadable': True}


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


def check_remote_fence():
    if _fenced or (_fence_path and _fence_path.exists()):
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


def note_ssh_uncertainty():
    """A lost SSH reply is not proof the remote command has stopped.

    Keep a durable logical interlock after the worker exits. No automatic retry
    or HTTP deadline may clear it. Only an offline, independently verified
    operator recovery may archive this fence.
    """
    global _fenced
    if not _active.get():
        return
    _fenced = True
    marker = _uncertain.get()
    if marker is not None:
        marker['unknown'] = True
    if _fence_path:
        from peer_recovery import atomic_json
        try:
            atomic_json(_fence_path, {'version': 1, 'created_at': int(time.time()),
                                     'reason': 'ssh_result_unknown'})
        except Exception:
            # In-memory fence stays closed even when durable storage fails.
            logger.error('Cannot persist lifecycle fence; keep panel offline after shutdown')
    logger.error('SSH result unknown; lifecycle admission fenced pending independent verification')


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
                check_remote_fence()
                started.set()
                token = _active.set(True)
                uncertain = _uncertain.set({'unknown': False})
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
