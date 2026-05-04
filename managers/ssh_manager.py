"""
SSH Manager - manages SSH connections to VPN servers.
Replicates the ServerController logic from the AmneziaVPN client.
"""

import paramiko
import io
import time
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

    def connect(self):
        """Establish SSH connection to the server."""
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
        return True

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def run_command(self, command, timeout=60):
        """Execute command on remote server."""
        if not self.client:
            raise ConnectionError("Not connected to server")

        logger.info(f"Running command: {command[:100]}...")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        
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
        if not self.client:
            raise ConnectionError("Not connected to server")

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
        if not self.client:
            raise ConnectionError("Not connected to server")

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
        if not self.client:
            raise ConnectionError("Not connected to server")

        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, 'r') as f:
                return f.read().decode('utf-8', errors='replace')
        finally:
            sftp.close()

    def file_exists(self, remote_path):
        """Check if a remote file exists."""
        if not self.client:
            raise ConnectionError("Not connected to server")

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
