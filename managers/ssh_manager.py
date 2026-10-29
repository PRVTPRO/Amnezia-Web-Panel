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
from contextlib import nullcontext
from managers import ssh_trust

logger = logging.getLogger(__name__)


def _conn_lock_of(obj):
    """_conn_lock, tolerating objects built without __init__ (tests)."""
    return getattr(obj, '_conn_lock', None) or nullcontext()


class SSHManager:
    """Manages SSH connections and command execution on remote servers."""

    def __init__(self, host, port, username, password=None, private_key=None,
                 connect_cooldown_base=30.0):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.private_key = private_key
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
        with self._exec_lock:
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

        self.client.connect(**kwargs)
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
        with self._conn_lock:
            self._disconnect_locked()

    def force_disconnect(self):
        """Unconditionally close SSH connection (pool eviction etc.)."""
        with self._conn_lock:
            self._disconnect_locked()

    # ----- docker container state snapshot (batch status checks) -----

    # A full `docker ps -a` round trip answers every "container exists /
    # running" question at once. Status checks used to fire one SSH command
    # per protocol per question (~20-30 commands per /check), which is what
    # made server pages slow on high-latency links. The snapshot is cached
    # for a few seconds so a burst of checks costs a single command.
    DOCKER_PS_TTL = 10.0

    def docker_ps_snapshot(self):
        """Dict {container_name: state} from one `docker ps -a` command."""
        now = time.time()
        cached = getattr(self, '_docker_ps_cache', None)
        if cached and now - cached[0] < self.DOCKER_PS_TTL:
            return cached[1]
        out, err, code = self.run_sudo_command(
            "docker ps -a --format '{{.Names}}\t{{.State}}'", timeout=30)
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
            raise ConnectionError(
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
        check_remote_fence()
        with self._exec_lock, _conn_lock_of(self):
            return self._run_command_locked(command, timeout, _retried, stdin_input)

    @staticmethod
    def _reason(exc):
        """Text for an exception that often carries none: paramiko raises bare
        EOFError/SSHException when the transport dies mid-command, and an empty
        string travels all the way to the UI as "... failed: "."""
        return str(exc).strip() or type(exc).__name__

    def _run_command_locked(self, command, timeout, _retried, stdin_input=None):
        self.ensure_connected()

        logger.info(f"Running command: {command[:100]}...")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        except Exception as e:
            # Transport can be dead while is_active() still claims otherwise
            # (silent NAT drop). Reconnect once and retry before giving up.
            from peer_lifecycle_lock import note_ssh_uncertainty
            note_ssh_uncertainty()
            if not _retried:
                logger.warning(f"exec failed ({e}); reconnecting and retrying once")
                try:
                    self.connect()
                except Exception as ce:
                    logger.error(f"reconnect failed: {ce}")
                    return "", self._reason(ce), -1
                return self.run_command(command, timeout=timeout, _retried=True, stdin_input=stdin_input)
            logger.error(f"exec failed after retry: {e}")
            return "", self._reason(e), -1

        if stdin_input is not None:
            try:
                stdin.write(stdin_input)
                stdin.flush()
                # Signal EOF so consumers of stdin (e.g. docker exec -i)
                # behave exactly as with the old `echo ... |` pipe.
                stdin.channel.shutdown_write()
            except Exception as e:
                logger.warning(f"failed to write command stdin: {e}")

        # Crucial: set timeout on the channel to prevent hanging indefinitely
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)

        try:
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
        except Exception as e:
            from peer_lifecycle_lock import note_ssh_uncertainty
            note_ssh_uncertainty()
            logger.error(f"Command timed out or failed to read: {e}")
            out, err, exit_code = "", f"SSH connection lost while running the command ({self._reason(e)})", -1

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
        with self._exec_lock, _conn_lock_of(self):
            return self._upload_file_locked(content, remote_path)

    def _upload_file_locked(self, content, remote_path):
        self.ensure_connected()

        # Normalize line endings (Windows CRLF -> Unix LF)
        content = content.replace('\r\n', '\n')

        sftp = self.client.open_sftp()
        try:
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
        with self._exec_lock, _conn_lock_of(self):
            return self._download_file_locked(remote_path)

    def _download_file_locked(self, remote_path):
        self.ensure_connected()

        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, 'r') as f:
                return f.read().decode('utf-8', errors='replace')
        finally:
            sftp.close()

    def file_exists(self, remote_path):
        """Check if a remote file exists."""
        with self._exec_lock, _conn_lock_of(self):
            return self._file_exists_locked(remote_path)

    def _file_exists_locked(self, remote_path):
        self.ensure_connected()

        sftp = self.client.open_sftp()
        try:
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
