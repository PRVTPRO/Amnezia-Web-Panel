"""
SSH Manager - manages SSH connections to VPN servers.
Replicates the ServerController logic from the AmneziaVPN client.
"""

import paramiko
import io
import time
import threading
import logging

logger = logging.getLogger(__name__)


class SSHManager:
    """Manages SSH connections and command execution on remote servers."""

    def __init__(self, host, port, username, password=None, private_key=None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.private_key = private_key
        self.client = None
        self._is_root = (username == 'root')
        # Serializes connect/disconnect so concurrent threads (UI request
        # handler + background monitor) cannot race a half-built transport.
        self._conn_lock = threading.Lock()
        # Serializes command/SFTP execution on the shared transport. Pooled
        # managers are used concurrently by request handlers and background
        # threads (traffic sync, conn monitor); without this a failed
        # exec on one side triggers a reconnect that closes the client the
        # other side is mid-command on ('NoneType open_session', EOFError
        # in open_sftp, bursts of 500s followed by the connect cooldown).
        # RLock because run_command retries by calling itself.
        self._exec_lock = threading.RLock()
        # Backoff: after a failed connect, do not hammer the dead server on
        # every request (each attempt costs up to `timeout` seconds and can
        # exhaust the web worker pool when several servers are down).
        self._last_connect_fail = 0.0
        self._connect_cooldown = 30.0
        # Pooled managers (shared via app.get_ssh) must ignore the legacy
        # per-request disconnect() calls scattered across endpoints —
        # otherwise every API request kills the shared transport.
        self.pooled = False

    def connect(self):
        """Establish SSH connection to the server."""
        with self._conn_lock:
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
            if last_exc is not None:
                raise last_exc
            self._last_connect_fail = 0.0
        return True

    def _connect_once(self):
        """Single TCP+SSH handshake attempt (caller holds _conn_lock)."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
            self.client.get_transport().set_keepalive(30)
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
        try:
            self.connect()
        except Exception:
            self._last_connect_fail = time.time()
            raise
        return True

    def run_command(self, command, timeout=60, _retried=False):
        """Execute command on remote server."""
        with self._exec_lock:
            return self._run_command_locked(command, timeout, _retried)

    def _run_command_locked(self, command, timeout, _retried):
        self.ensure_connected()

        logger.info(f"Running command: {command[:100]}...")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        except Exception as e:
            # Transport can be dead while is_active() still claims otherwise
            # (silent NAT drop). Reconnect once and retry before giving up.
            if not _retried:
                logger.warning(f"exec failed ({e}); reconnecting and retrying once")
                try:
                    self.connect()
                except Exception as ce:
                    logger.error(f"reconnect failed: {ce}")
                    return "", str(ce), -1
                return self.run_command(command, timeout=timeout, _retried=True)
            logger.error(f"exec failed after retry: {e}")
            return "", str(e), -1

        # Crucial: set timeout on the channel to prevent hanging indefinitely
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)

        try:
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
        except Exception as e:
            logger.error(f"Command timed out or failed to read: {e}")
            out, err, exit_code = "", str(e), -1

        if exit_code != 0:
            logger.warning(f"Command exited with code {exit_code}: {err}")

        return out, err, exit_code

    def _sudo_prefix(self):
        """Get the sudo command prefix with password handling."""
        if self._is_root:
            return ''
        if self.password:
            # Use sudo -S to read password from stdin
            escaped_pass = self.password.replace("'", "'\\''")
            return f"echo '{escaped_pass}' | sudo -S "
        return 'sudo '

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
            escaped_pass = self.password.replace("'", "'\\''")
            # Pipe password directly to sudo -S, preserving original command quoting
            # 2>/dev/null on echo suppresses '[sudo] password for...' prompt noise
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' {clean_cmd}"
        else:
            full_cmd = f"sudo {clean_cmd}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_sudo_script(self, script, timeout=120):
        """
        Execute a multi-line script with sudo/root privileges.
        Writes script to /tmp via SFTP, then runs with sudo bash.
        """
        if self._is_root:
            return self.run_script(script, timeout=timeout)

        # Write script to temp file via SFTP (avoids heredoc/pipe conflicts)
        import hashlib
        script_hash = hashlib.md5(script.encode()).hexdigest()[:8]
        tmp_script = f"/tmp/_amnz_script_{script_hash}.sh"
        self.upload_file(script, tmp_script)

        # Run with sudo
        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' bash {tmp_script}; rm -f {tmp_script}"
        else:
            full_cmd = f"sudo bash {tmp_script}; rm -f {tmp_script}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_script(self, script, timeout=120):
        """Execute a multi-line script on remote server."""
        return self.run_command(script, timeout=timeout)

    def upload_file(self, content, remote_path):
        """Upload text content to a remote file via SFTP."""
        with self._exec_lock:
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

        # Write to temp file via SFTP (no sudo needed for /tmp)
        import hashlib
        tmp_name = f"/tmp/_amnz_{hashlib.md5(remote_path.encode()).hexdigest()[:8]}"
        self.upload_file(content, tmp_name)

        # Move to target with sudo
        self.run_sudo_command(f"mv {tmp_name} {remote_path}")
        self.run_sudo_command(f"chmod 644 {remote_path}")
        return True

    def download_file(self, remote_path):
        """Download text content from a remote file."""
        with self._exec_lock:
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
        with self._exec_lock:
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
