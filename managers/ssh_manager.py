"""
SSH Manager - manages SSH connections to VPN servers.
Replicates the ServerController logic from the AmneziaVPN client.
"""

import paramiko
import io
import time
import threading
import logging
import shlex
import os
from contextlib import contextmanager, nullcontext
from managers import ssh_trust

logger = logging.getLogger(__name__)

_DEFAULT_JUMP = object()
_JUMP_RESOLVER = None

# How long a worker may queue for the per-server exec lock on top of the
# command's own budget. Without a bound, a single stuck command parks every
# other request thread on this lock until uvicorn runs out of workers.
_EXEC_LOCK_SLACK = 15.0
# Ceiling for that wait. A legitimately long operation may hold the lock for
# minutes (docker build 600s, smartroute 420s, archive transfer 900s); an
# interactive request must not inherit that wait, or the panel stops serving
# again — it gets "busy" instead.
_EXEC_WAIT_MAX = 120.0

_SFTP_TIMEOUT = 120.0
# Extra time the kill switch gives the graceful timeout path before it closes
# the socket underneath a blocked paramiko call.
_KILL_SWITCH_GRACE = 15.0
# How long disconnect()/force_disconnect() wait for an in-flight operation.
_LOCK_WAIT_MAXIMUM = 5.0

# Jump hosts: opening the direct-tcpip channel through a jump transport uses
# paramiko's per-transport channel_timeout, which defaults to one hour.
_CHANNEL_OPEN_TIMEOUT = 30.0


class SSHBusy(ConnectionError):
    """The server is busy with another SSH operation; nothing was executed.

    Deliberately not a plain ConnectionError for the peer lifecycle interlock:
    a refusal to start must never fence the panel ("nothing ran" is a known
    outcome), while a lost reply is.
    """

    code = 'ssh_busy'
    nothing_executed = True


class SSHBackoff(SSHBusy):
    """The connect circuit breaker is open; nothing was executed either."""

    code = 'ssh_backoff'


def configure_jump_resolver(resolver):
    """Set the panel callback that resolves a jump manager for an endpoint."""
    global _JUMP_RESOLVER
    _JUMP_RESOLVER = resolver


def _conn_lock_of(obj):
    """_conn_lock, tolerating objects built without __init__ (tests)."""
    return getattr(obj, '_conn_lock', None) or nullcontext()


def _exec_lock_of(obj):
    """_exec_lock, or None for objects built without __init__ (tests)."""
    return getattr(obj, '_exec_lock', None)


class SSHManager:
    """Manages SSH connections and command execution on remote servers."""

    # Class-level default: tests build managers via __new__() without __init__,
    # and a missing identity must mean "unknown target" (the fence then behaves
    # globally) rather than an AttributeError on every command.
    server_scope = None

    def __init__(self, host, port, username, password=None, private_key=None,
                 connect_cooldown_base=30.0, jump_manager=_DEFAULT_JUMP,
                 server_scope=None):
        self.host = host
        self.port = int(port)
        self.username = username
        # Identity used by the lifecycle fence: a fence recorded for this
        # server must block its commands, while an unrelated server keeps
        # working. Refreshed by app.get_ssh() when a pooled manager is reused.
        self.server_scope = server_scope
        self.password = password
        self.private_key = private_key
        self.jump_manager = (_JUMP_RESOLVER(host, int(port), username)
                             if jump_manager is _DEFAULT_JUMP and _JUMP_RESOLVER
                             else (None if jump_manager is _DEFAULT_JUMP else jump_manager))
        self.client = None
        self._is_root = (username == 'root')
        # Serializes connect/disconnect so concurrent threads (UI request
        # handler + background monitor) cannot race a half-built transport.
        # RLock: run_command holds it for the whole command (see below) and
        # the reconnect-retry path re-enters connect() on the same thread.
        # Holding it during exec is what finally closes the race where
        # force_disconnect() nulled self.client between ensure_connected()
        # and exec_command(), surfacing as 'NoneType open_session'.
        self._conn_lock = threading.RLock()
        # Serializes command/SFTP execution on the shared transport. Pooled
        # managers are used concurrently by request handlers and background
        # threads (traffic sync, conn monitor); without this a failed
        # exec on one side triggers a reconnect that closes the client the
        # other side is mid-command on ('NoneType open_session', EOFError
        # in open_sftp, bursts of 500s followed by the connect cooldown).
        # RLock because run_command retries by calling itself.
        self._exec_lock = threading.RLock()
        # Serializes access to the AWG batched-status cache (_awg_batch),
        # which is shared across threads via the pooled SSH manager.
        self._awg_batch_lock = threading.RLock()
        # Circuit breaker: after a failed connect, do not hammer the dead
        # server on every request (each attempt costs up to `timeout` seconds
        # and can exhaust the web worker pool when several servers are down).
        # Consecutive failures grow the cooldown base -> 2x -> 4x -> ... up
        # to 300s; the first successful connect resets it back to base.
        # Base is configurable per server (data.json: ssh_cooldown_base).
        self._connect_cooldown_base = float(connect_cooldown_base or 30.0)
        self._last_connect_fail = 0.0
        self._connect_cooldown = self._connect_cooldown_base
        self._connect_fail_count = 0
        self._connect_cooldown_max = 300.0
        # Pooled managers (shared via app.get_ssh) must ignore the legacy
        # per-request disconnect() calls scattered across endpoints —
        # otherwise every API request kills the shared transport.
        self.pooled = False

    def connect(self):
        """Establish SSH connection to the server."""
        # Legacy endpoints still call connect() after get_ssh() has returned a
        # pooled manager.  Reconnecting there used to close the shared
        # transport underneath another request (stats/background checks),
        # producing "Unable to open channel" bursts and hanging service checks.
        # Use the same lock as command execution and make a live pooled
        # connection idempotent.
        with self._exec_slot(None) as slot:
            if not slot:
                raise SSHBusy(
                    f"SSH to {self.host} is still busy with another operation")
            with self._conn_lock:
                if self.pooled:
                    try:
                        transport = self.client.get_transport() if self.client else None
                        if transport and transport.is_active():
                            return True
                    except Exception:
                        pass

                self._disconnect_locked()
                # One retry on TCP connect timeout: links with random SYN loss
                # (e.g. transcontinental/DPI-filtered routes) drop ~half of the
                # first attempts while the retry succeeds in milliseconds.
                last_exc = None
                for attempt in (1, 2):
                    try:
                        self._connect_once()
                        last_exc = None
                        break
                    except (TimeoutError, OSError) as e:
                        last_exc = e
                        logger.warning(
                            f"SSH connect to {self.host} attempt {attempt} "
                            f"failed: {e}")
                        self._disconnect_locked()
                    except Exception:
                        # Host-key/authentication/configuration failures are
                        # not transient TCP failures: never retry or accept a
                        # different key, and do not leave a half-open client.
                        self._disconnect_locked()
                        self._record_connect_failure()
                        raise
                if last_exc is not None:
                    self._record_connect_failure()
                    raise last_exc
                self._reset_connect_failures()
        return True

    @contextmanager
    def _exec_slot(self, timeout):
        """Bounded wait for the per-server exec lock (yields True when held).

        A command that never returns used to leave every later request blocked
        on this lock *forever*: sync endpoints and `asyncio.to_thread` SSH calls
        share uvicorn's 40-thread pool, so those parked threads end up serving
        no HTTP request at all and the whole panel stops answering while the
        container still looks healthy.

        The wait is the caller's own budget, never the holder's: a long archive
        transfer or a docker build must not park every request to that server.
        The request gets an honest "busy" instead, and the panel stays alive.
        """
        lock = _exec_lock_of(self)
        if lock is None:
            yield True
            return
        budget = (float(timeout) if timeout else 60.0) + _EXEC_LOCK_SLACK
        acquired = lock.acquire(timeout=min(budget, _EXEC_WAIT_MAX))
        try:
            yield acquired
        finally:
            if acquired:
                lock.release()

    @contextmanager
    def _kill_switch(self, seconds, what='call'):
        """Close the transport when a single SSH call outlives its budget.

        paramiko has waits without a timeout of their own: `recv_exit_status()`
        blocks on an Event, channel reads and SFTP requests have none at all.
        When the route to a managed node changes, packets are blackholed — the
        TCP socket stays open, `is_active()` keeps returning True and every
        blocked call stays blocked for hours. The timer closes the socket so
        the blocked call raises instead of holding a worker thread forever.
        """
        client = self.client
        done = threading.Event()
        fired = []

        def _abort():
            # cancel() cannot stop a callback that already started, and by then
            # the command may have finished and a new transport may be in use.
            if done.is_set():
                return
            fired.append(True)
            logger.error(
                f"SSH {what} on {self.host} exceeded {seconds:g}s; "
                f"closing a transport that may be dead")
            # Close the transport this call started on *and* the current one:
            # ensure_connected() may have replaced it while the call was stuck.
            targets = []
            for candidate in (client, self.client):
                if candidate is not None and all(candidate is not t for t in targets):
                    targets.append(candidate)
            for target in targets:
                if done.is_set():
                    return
                try:
                    target.close()
                except Exception:
                    pass

        timer = threading.Timer(max(0.05, float(seconds)), _abort)
        timer.daemon = True
        timer.start()
        try:
            yield fired
        finally:
            done.set()
            timer.cancel()

    def _drop_transport(self):
        """Close a dead/suspect transport (caller holds _conn_lock)."""
        try:
            self._disconnect_locked()
        except Exception:
            self.client = None

    def _transport_alive(self):
        """True while paramiko still believes the transport works.

        For a blackholed route this stays True (nothing arrives to close it),
        but after the kill switch closes the socket it reports the truth.
        """
        try:
            transport = self.client.get_transport() if self.client else None
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def _record_connect_failure(self):
        """Feed the breaker from any failed connect path (caller holds
        _conn_lock): bump the streak and grow the cooldown exponentially."""
        self._connect_fail_count += 1
        self._last_connect_fail = time.time()
        self._connect_cooldown = min(
            self._connect_cooldown_base * (2 ** (self._connect_fail_count - 1)),
            self._connect_cooldown_max)

    def _reset_connect_failures(self):
        """First successful connect closes the breaker again."""
        self._connect_fail_count = 0
        self._connect_cooldown = self._connect_cooldown_base
        self._last_connect_fail = 0.0

    def _connect_once(self):
        """Single TCP+SSH handshake attempt (caller holds _conn_lock)."""
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        # Persist trust alongside DATA_FILE (the standard Docker data volume).
        # Explicitly configured files must exist and parse successfully; never
        # fall back to trust-on-first-use when trust configuration is broken.
        configured = os.environ.get('SSH_KNOWN_HOSTS_FILE')
        known_hosts = ssh_trust.trust_path()
        if configured or os.path.isfile(known_hosts):
            self.client.load_host_keys(known_hosts)
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs = {
            'hostname': self.host,
            'port': self.port,
            'username': self.username,
            'timeout': 15,
            'allow_agent': False,
            'look_for_keys': False,
        }

        if self.private_key:
            key_file = io.StringIO(self.private_key)
            try:
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except paramiko.ssh_exception.SSHException:
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except paramiko.ssh_exception.SSHException:
                    key_file.seek(0)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            kwargs['pkey'] = pkey
        elif self.password:
            kwargs['password'] = self.password

        if self.jump_manager is not None:
            self.jump_manager.ensure_connected()
            transport = (self.jump_manager.client.get_transport()
                         if self.jump_manager.client else None)
            if not transport or not transport.is_active():
                raise ConnectionError('SSH jump host transport is unavailable')
            kwargs['sock'] = transport.open_channel(
                'direct-tcpip', (self.host, self.port), ('127.0.0.1', 0),
                timeout=_CHANNEL_OPEN_TIMEOUT)

        self.client.connect(**kwargs)
        # paramiko's default channel_timeout is one hour: with a blackholed
        # route, open_session()/open_sftp() stay blocked that long with no
        # error. 30s is plenty for a channel open on a live transport.
        try:
            transport = self.client.get_transport()
            if transport is not None:
                transport.channel_timeout = 30.0
        except Exception:
            pass
        # Keep NAT/stateful firewalls from silently dropping the idle
        # long-lived transport between command bursts.
        try:
            self.client.get_transport().set_keepalive(15)
        except Exception:
            pass

    def _disconnect_locked(self):
        """Close SSH connection (caller must hold _conn_lock)."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def disconnect(self):
        """Close SSH connection.

        No-op for pooled managers: legacy endpoints call disconnect() in
        finally-blocks after every request, which would destroy the shared
        long-lived transport. Use force_disconnect() to really close it.
        """
        if self.pooled:
            return
        # Bounded: an archive transfer can hold this lock for minutes and a
        # legacy finally-block must not park a worker behind it.
        if not self._conn_lock.acquire(timeout=_LOCK_WAIT_MAXIMUM):
            logger.warning(f"SSH disconnect on {self.host} skipped: connection busy")
            return
        try:
            self._disconnect_locked()
        finally:
            self._conn_lock.release()

    def force_disconnect(self):
        """Unconditionally close SSH connection (pool eviction etc.)."""
        if not self._conn_lock.acquire(timeout=_LOCK_WAIT_MAXIMUM):
            logger.warning(f"SSH eviction on {self.host} skipped: connection busy")
            return
        try:
            self._disconnect_locked()
        finally:
            self._conn_lock.release()

    # ----- docker container state snapshot (batch status checks) -----

    # A full `docker ps -a` round trip answers every "container exists /
    # running" question at once. Status checks used to fire one SSH command
    # per protocol per question (~20-30 commands per /check), which is what
    # made server pages slow on high-latency links. The snapshot is cached
    # for a few seconds so a burst of checks costs a single command.
    DOCKER_PS_TTL = 10.0

    def docker_ps_snapshot(self):
        """Dict {container_name: state}, or None when the probe fails."""
        now = time.time()
        cached = getattr(self, '_docker_ps_cache', None)
        if cached and now - cached[0] < self.DOCKER_PS_TTL:
            return cached[1]
        out, err, code = self.run_sudo_command(
            "docker ps -a --format '{{.Names}}\t{{.State}}'", timeout=30)
        if code != 0:
            # A denied/timed-out probe is unknown, not a successful empty list.
            # Do not poison the shared cache or suppress per-container fallback.
            return None
        states = {}
        if code == 0:
            for line in (out or '').splitlines():
                parts = line.split('\t')
                if len(parts) == 2 and parts[0]:
                    states[parts[0]] = parts[1]
        self._docker_ps_cache = (now, states)
        return states

    def docker_container_state(self, name):
        """(exists, running) for one container from the snapshot.

        Returns None when the snapshot itself failed, so callers fall back
        to their direct per-container command."""
        try:
            states = self.docker_ps_snapshot()
        except Exception:
            return None
        if states is None:
            return None
        return (name in states, states.get(name) == 'running')

    def docker_ps_invalidate(self):
        """Drop the snapshot after a mutating docker operation."""
        self._docker_ps_cache = None

    def ensure_connected(self):
        """Connect only if there is no live transport.

        Lets the panel keep one long-lived connection per server and run
        commands as cheap channels on it instead of paying a full TCP+SSH
        handshake for every API request (a major source of UI timeouts on
        high-latency servers).
        """
        try:
            transport = self.client.get_transport() if self.client else None
            if transport and transport.is_active():
                return True
        except Exception:
            pass
        # Cooldown after a recent failed attempt: fail fast instead of
        # blocking the worker on another 15s connect to a dead server.
        if time.time() - self._last_connect_fail < self._connect_cooldown:
            raise SSHBackoff(
                f"SSH to {self.host} recently failed, backing off "
                f"{int(self._connect_cooldown)}s")
        # connect() itself feeds the breaker on failure and resets it on
        # success, so reconnect-and-retry paths are covered too.
        self.connect()
        return True

    def run_command(self, command, timeout=60, _retried=False, stdin_input=None):
        """Execute command on remote server.

        stdin_input, when given, is written to the channel's stdin right after
        exec and the write side is closed (same semantics as a shell pipe).
        Used to feed the sudo password without putting it on the command line.

        _conn_lock is held for the whole command so force_disconnect() (pool
        eviction) cannot tear down the transport mid-command.
        """
        from peer_lifecycle_lock import check_remote_fence
        check_remote_fence(self.server_scope)
        with self._exec_slot(timeout) as slot:
            if not slot:
                logger.error(
                    f"SSH to {self.host} is still busy with a previous command; "
                    f"refusing to queue another request thread")
                return "", (f"SSH to {self.host} is still busy with a previous "
                            f"command"), -1
            with _conn_lock_of(self):
                return self._run_command_locked(command, timeout, _retried, stdin_input)

    @staticmethod
    def _reason(exc):
        """Text for an exception that often carries none: paramiko raises bare
        EOFError/SSHException when the transport dies mid-command, and an empty
        string travels all the way to the UI as "... failed: "."""
        return str(exc).strip() or type(exc).__name__

    @staticmethod
    def _drain_streams(stdout, stderr, backstop):
        """Read stdout and stderr concurrently, bounded by the kill switch.

        Both streams share one channel window: reading stdout to EOF while a
        chatty command fills the window with stderr blocks the remote, so the
        stdout read never sees EOF. Threads keep both buffers moving.

        There is deliberately no wall-clock budget here: `timeout` on an SSH
        command bounds *inactivity* (the channel timeout), not the total
        runtime, so a command that keeps printing may legitimately run longer.
        The only cap is the caller's kill switch, which closes the transport
        when the whole command overruns.
        """
        results = {}

        def pull(name, stream):
            try:
                results[name] = stream.read()
            except Exception as exc:
                results[name + '_error'] = exc

        readers = [threading.Thread(target=pull, args=('out', stdout), daemon=True),
                   threading.Thread(target=pull, args=('err', stderr), daemon=True)]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + backstop
        for reader in readers:
            reader.join(timeout=max(0.05, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            raise TimeoutError(f'command still running after {backstop:g}s')
        for key in ('out_error', 'err_error'):
            if key in results:
                raise results[key]
        return results.get('out', b''), results.get('err', b'')

    def _run_command_locked(self, command, timeout, _retried, stdin_input=None):
        # One budget for the whole call: exec_command() bounds the channel open,
        # the reads below bound inactivity, and the status wait uses the rest.
        timeout = float(timeout) if timeout else 60.0
        self.ensure_connected()

        logger.info(f"Running command: {command[:100]}...")
        try:
            # Channel.exec_command() itself replies through _wait_for_event(),
            # which is a bare Event.wait() in paramiko: after a successful
            # channel open a blackholed link leaves it waiting forever. The
            # switch must cover the exec call, not just the reads.
            with self._kill_switch(timeout + _KILL_SWITCH_GRACE, 'command start'):
                stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        except Exception as e:
            # Transport can be dead while is_active() still claims otherwise
            # (silent NAT drop). Reconnect once and retry before giving up.
            from peer_lifecycle_lock import note_ssh_uncertainty, lifecycle_active
            note_ssh_uncertainty(self.server_scope)
            # Повтор разрешён только вне lifecycle-интерлока: там исход уже
            # неизвестен, и повторная отправка означала бы выполнить мутацию
            # дважды. Забор (fence) в этом случае ставится выше.
            if not _retried and not lifecycle_active():
                logger.warning(f"exec failed ({e}); reconnecting and retrying once")
                try:
                    self.connect()
                except Exception as ce:
                    logger.error(f"reconnect failed: {ce}")
                    return "", self._reason(ce), -1
                return self.run_command(command, timeout=timeout, _retried=True, stdin_input=stdin_input)
            logger.error(f"exec failed after retry: {e}")
            return "", self._reason(e), -1

        # Crucial: set timeout on the channel to prevent hanging indefinitely
        channel = stdout.channel
        channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)

        # The kill switch covers the stdin write as well as the reads: a full
        # send window could otherwise block for a long time.
        # A command that is slow but healthy may legitimately run longer than
        # one timeout, so the wall-clock guard is generous.
        with self._kill_switch(2 * timeout + _KILL_SWITCH_GRACE, 'command'):
            if stdin_input is not None:
                try:
                    stdin.write(stdin_input)
                    stdin.flush()
                    # Signal EOF so consumers of stdin (e.g. docker exec -i)
                    # behave exactly as with the old `echo ... |` pipe.
                    stdin.channel.shutdown_write()
                except Exception as e:
                    logger.warning(f"failed to write command stdin: {e}")
            try:
                # Drain both pipes before waiting for the exit status: paramiko
                # documents that recv_exit_status() deadlocks when the command
                # writes more than one channel window while nobody reads it.
                out_bytes, err_bytes = self._drain_streams(
                    stdout, stderr, 2 * timeout + _KILL_SWITCH_GRACE + 5)
                out = out_bytes.decode('utf-8', errors='replace').strip()
                err = err_bytes.decode('utf-8', errors='replace').strip()
                # recv_exit_status() itself waits on an Event with no timeout.
                # Wait for it explicitly so a lost route ends as an error, not
                # as a worker thread that never comes back.
                status_event = getattr(channel, 'status_event', None)
                if status_event is not None and not status_event.wait(timeout):
                    raise TimeoutError(
                        f'no exit status after {timeout:g}s')
                exit_code = channel.recv_exit_status()
                if exit_code < 0 and not self._transport_alive():
                    # paramiko uses -1 when the transport died before sending
                    # the exit status: the command outcome is unknown, not a
                    # normal failure, and the interlock must know that.
                    raise RuntimeError('remote exit status was not received')
            except Exception as e:
                from peer_lifecycle_lock import note_ssh_uncertainty
                note_ssh_uncertainty()
                logger.error(f"Command timed out or failed to read: {e}")
                dead = not self._transport_alive()
                try:
                    channel.close()
                except Exception:
                    pass
                # Drop the transport only when it is actually gone (or was
                # closed by the kill switch). A slow command on a healthy link
                # keeps the pooled connection for the next request.
                if dead:
                    self._drop_transport()
                if isinstance(e, TimeoutError):
                    err = (f"SSH command timed out after {timeout:g}s "
                           f"({self._reason(e)})")
                else:
                    err = ("SSH connection lost while running the command "
                           f"({self._reason(e)})")
                out, exit_code = "", -1
            else:
                # A signal-killed command (OOM killer, admin `kill`) makes sshd
                # send exit-signal, which paramiko does not decode: the status
                # stays -1 on a perfectly healthy transport. Keep the output.
                if exit_code < 0:
                    err = (err or 'remote command was killed before reporting '
                                   'an exit status')
                    logger.warning(
                        f"Command on {self.host} ended without an exit status: {err}")

        if exit_code != 0:
            logger.warning(f"Command exited with code {exit_code}: {err}")

        return out, err, exit_code

    def run_sudo_command(self, command, timeout=60):
        """
        Execute command with sudo, automatically handling password.
        Strips 'sudo ' from the beginning of command if present,
        and re-adds it with password piping.
        """
        # Remove existing sudo prefix if present
        clean_cmd = command
        if clean_cmd.strip().startswith('sudo '):
            clean_cmd = clean_cmd.strip()[5:]

        if self._is_root:
            return self.run_command(clean_cmd, timeout=timeout)

        if self.password:
            # Feed the password via channel stdin: keeping it out of the
            # command line hides it from both the panel log (logged above)
            # and the remote process list.
            return self.run_command(
                f"sudo -S -p '' {clean_cmd}", timeout=timeout,
                stdin_input=self.password + '\n')

        return self.run_command(f"sudo {clean_cmd}", timeout=timeout)

    def run_sudo_script(self, script, timeout=120):
        """
        Execute a multi-line script with sudo/root privileges.
        Writes script to /tmp via SFTP, then runs with sudo bash.
        """
        if self._is_root:
            return self.run_script(script, timeout=timeout)

        # Atomically allocate private staging; never follow a preplanted /tmp file.
        tmp_dir = self._make_private_temp_dir()
        try:
            tmp_script = tmp_dir + '/script.sh'
            self.upload_file(script, tmp_script)
            return self.run_sudo_command('bash ' + shlex.quote(tmp_script), timeout=timeout)
        finally:
            self.run_command('rm -rf -- ' + shlex.quote(tmp_dir))

    def _make_private_temp_dir(self):
        out, err, code = self.run_command('mktemp -d /tmp/amnezia-private.XXXXXXXXXX')
        path = out.strip()
        if code != 0 or not path.startswith('/tmp/amnezia-private.') or '/' in path[5:] or '\n' in path:
            raise RuntimeError(err or 'Failed to create private remote staging directory')
        return path

    def run_script(self, script, timeout=120):
        """Execute a multi-line script on remote server."""
        return self.run_command(script, timeout=timeout)

    def upload_file(self, content, remote_path):
        """Upload text content to a remote file via SFTP."""
        from peer_lifecycle_lock import check_remote_fence
        check_remote_fence(self.server_scope)
        return self._sftp_call(
            _SFTP_TIMEOUT, lambda: self._upload_file_locked(content, remote_path))

    def _sftp_call(self, budget, operation):
        """Run one SFTP operation under the exec lock and a hard deadline.

        SFTP has no timeout of its own and open_sftp() waits on a channel open,
        so a blackholed route parks the worker forever without the kill switch.
        """
        with self._exec_slot(budget) as slot:
            if not slot:
                raise RuntimeError(
                    f"SSH to {self.host} is still busy with a previous command")
            with _conn_lock_of(self), self._kill_switch(budget, 'sftp') as fired:
                try:
                    return operation()
                except Exception as e:
                    if fired:
                        raise TimeoutError(
                            f"SSH SFTP operation on {self.host} exceeded "
                            f"{budget:g}s") from e
                    raise

    # Archives (backups, instance copies) are far bigger than the config files
    # upload_file/download_file handle, so the whole operation gets a generous
    # wall-clock budget and a stalled read is caught much earlier by the
    # channel timeout.
    SFTP_TRANSFER_BUDGET = 900.0
    SFTP_INACTIVITY_TIMEOUT = 60.0

    @contextmanager
    def sftp_transfer(self, budget=None, inactivity=None):
        """SFTP session for archives: bounded inactivity and a hard deadline.

        `sftp.get()`/`sftp.put()` and `open_sftp()` have no timeout of their
        own, so on a blackholed route they block a worker thread forever — the
        issue #347 failure mode, reachable from the backup and copy endpoints
        just as from the command path.
        """
        budget = float(budget or self.SFTP_TRANSFER_BUDGET)
        inactivity = float(inactivity or self.SFTP_INACTIVITY_TIMEOUT)
        with self._exec_slot(budget) as slot:
            if not slot:
                raise RuntimeError(
                    f"SSH to {self.host} is still busy with a previous command")
            with _conn_lock_of(self), self._kill_switch(budget, 'sftp transfer') as fired:
                try:
                    self.ensure_connected()
                    sftp = self.client.open_sftp()
                    try:
                        sftp.get_channel().settimeout(inactivity)
                        yield sftp
                    finally:
                        try:
                            sftp.close()
                        except Exception:
                            pass
                except Exception as e:
                    if fired:
                        raise TimeoutError(
                            f"SSH transfer on {self.host} exceeded "
                            f"{budget:g}s") from e
                    raise

    def _upload_file_locked(self, content, remote_path):
        self.ensure_connected()

        # Normalize line endings (Windows CRLF -> Unix LF)
        content = content.replace('\r\n', '\n')

        sftp = self.client.open_sftp()
        try:
            sftp.get_channel().settimeout(self.SFTP_INACTIVITY_TIMEOUT)
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
        finally:
            sftp.close()

    def upload_file_sudo(self, content, remote_path):
        """
        Upload text content to a remote file that requires root access.
        Uses SFTP to write to /tmp, then sudo mv to the target path.
        Also normalizes line endings to Unix-style (LF).
        """
        self.ensure_connected()

        # Normalize line endings (Windows CRLF -> Unix LF)
        content = content.replace('\r\n', '\n')

        tmp_dir = self._make_private_temp_dir()
        try:
            tmp_path = tmp_dir + '/content'
            self.upload_file(content, tmp_path)
            out, err, code = self.run_sudo_command(
                'mv -- ' + shlex.quote(tmp_path) + ' ' + shlex.quote(remote_path))
            if code != 0:
                raise RuntimeError(err or out or 'Failed to install remote file')
        finally:
            self.run_command('rm -rf -- ' + shlex.quote(tmp_dir))
        self.run_sudo_command(f"chmod 644 {remote_path}")
        return True

    def download_file(self, remote_path):
        """Download text content from a remote file."""
        from peer_lifecycle_lock import check_remote_fence
        check_remote_fence(self.server_scope)
        return self._sftp_call(
            _SFTP_TIMEOUT, lambda: self._download_file_locked(remote_path))

    def _download_file_locked(self, remote_path):
        self.ensure_connected()

        sftp = self.client.open_sftp()
        try:
            sftp.get_channel().settimeout(self.SFTP_INACTIVITY_TIMEOUT)
            with sftp.file(remote_path, 'r') as f:
                return f.read().decode('utf-8', errors='replace')
        finally:
            sftp.close()

    def file_exists(self, remote_path):
        """Check if a remote file exists."""
        from peer_lifecycle_lock import check_remote_fence
        check_remote_fence(self.server_scope)
        return self._sftp_call(
            _SFTP_TIMEOUT, lambda: self._file_exists_locked(remote_path))

    def _file_exists_locked(self, remote_path):
        self.ensure_connected()

        sftp = self.client.open_sftp()
        try:
            sftp.get_channel().settimeout(self.SFTP_INACTIVITY_TIMEOUT)
            sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False
        finally:
            sftp.close()

    def test_connection(self):
        """Test SSH connection and return server info."""
        out, err, code = self.run_command("uname -sr && cat /etc/os-release 2>/dev/null | head -2")
        return out

    def write_file(self, remote_path, content):
        """Write content to a remote file with sudo."""
        return self.upload_file_sudo(content, remote_path)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
