"""Serialize peer/inventory mutations without holding the data lock over SSH."""
import asyncio
import contextvars
from contextlib import asynccontextmanager
import functools
import inspect
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
RESPONSE_WAIT_SECONDS = 120.0
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


def diagnostics():
    return {'blocked': _fenced or bool(_fence_path and _fence_path.exists()),
            'running': [{'operation': item['operation'],
                         'elapsed_seconds': int(time.monotonic() - item['started'])}
                        for item in list(_running.values())]}


def check_remote_fence():
    if _fenced or (_fence_path and _fence_path.exists()):
        raise PeerLifecycleUncertain('peer_lifecycle_uncertain')


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
                except (TimeoutError, ConnectionError):
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
