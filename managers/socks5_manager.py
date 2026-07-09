"""
SOCKS5 Proxy Manager — runs 3proxy in a Docker container, modelled after the
official Amnezia client install (client/server_scripts/socks5_proxy/). Holds a
single user (port + username + password); credentials can be edited later from
the panel via update_credentials().
"""

import logging
import secrets
import string
import re

logger = logging.getLogger(__name__)


def _generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class Socks5Manager:
    PROTOCOL = 'socks5'
    CONTAINER_NAME = 'amnezia-socks5proxy'
    IMAGE_NAME = '3proxy/3proxy:0.9.5'
    CONFIG_DIR = '/opt/amnezia/socks5proxy'
    CONFIG_PATH = '/etc/3proxy/3proxy.cfg'

    DEFAULT_PORT = 38080
    DEFAULT_USERNAME = 'proxy_user'

    def __init__(self, ssh, protocol='socks5'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.config_dir = self._config_dir(self.protocol)

    def _instance_index(self, protocol=None):
        parts = str(protocol or self.protocol or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.CONTAINER_NAME if idx <= 1 else f'{self.CONTAINER_NAME}-{idx}'

    def _config_dir(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.CONFIG_DIR if idx <= 1 else f'{self.CONFIG_DIR}-{idx}'

    # ===================== STATUS =====================

    def check_docker_installed(self):
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def check_protocol_installed(self, protocol_type='socks5'):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self._container_name(protocol_type)}$ --format '{{{{.Names}}}}'"
        )
        return self._container_name(protocol_type) in out.strip().split('\n')

    def check_container_running(self, protocol_type='socks5'):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self._container_name(protocol_type)}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def get_server_status(self, protocol_type='socks5'):
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type)
        creds = self.get_credentials() if exists else {}
        return {
            'container_exists': exists,
            'container_running': running,
            'port': creds.get('port'),
            'username': creds.get('username'),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': self._instance_index(protocol_type),
            'container_name': self._container_name(protocol_type),
        }

    # ===================== CONFIG I/O =====================

    def _build_config(self, username, password, port):
        # Mirrors client/server_scripts/socks5_proxy/configure_container.sh.
        # 'auth strong' enforces username/password on every connection;
        # 'allow {user}' restricts the ACL to our single user only.
        return (
            "#!/bin/3proxy\n"
            f"config {self.CONFIG_PATH}\n"
            "timeouts 1 5 30 60 180 1800 15 60\n"
            f"users {username}:CL:{password}\n"
            "log\n"
            "auth strong\n"
            f"allow {username}\n"
            f"socks -p{int(port)}\n"
        )

    def _read_config(self):
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {self.CONFIG_PATH} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            out, _, code = self.ssh.run_sudo_command(
                f"cat {self.config_dir}/3proxy.cfg 2>/dev/null"
            )
        if code != 0 or not out.strip():
            return ''
        return out

    def _write_config(self, config_text):
        # Write to host first (so we have a stable copy outside the container),
        # then docker cp into the running container at the path 3proxy expects.
        self.ssh.run_sudo_command(f"mkdir -p {self.config_dir}")
        self.ssh.upload_file_sudo(config_text, f"{self.config_dir}/3proxy.cfg")
        self.ssh.run_sudo_command(
            f"docker cp {self.config_dir}/3proxy.cfg {self.container_name}:{self.CONFIG_PATH} 2>/dev/null || true"
        )

    def _parse_credentials(self, config_text):
        creds = {'port': None, 'username': None, 'password': None}
        if not config_text:
            return creds
        m_user = re.search(r'^\s*users\s+([^:\s]+):CL:(\S+)', config_text, re.MULTILINE)
        if m_user:
            creds['username'] = m_user.group(1)
            creds['password'] = m_user.group(2)
        m_port = re.search(r'^\s*socks\s+-p(\d+)', config_text, re.MULTILINE)
        if m_port:
            creds['port'] = int(m_port.group(1))
        return creds

    def get_credentials(self):
        return self._parse_credentials(self._read_config())

    # ===================== INSTALL / UPDATE / REMOVE =====================

    def install_protocol(self, protocol_type='socks5', port=None, username=None, password=None):
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}

        port = int(port or self.DEFAULT_PORT)
        username = (username or self.DEFAULT_USERNAME).strip() or self.DEFAULT_USERNAME
        password = (password or _generate_password()).strip() or _generate_password()

        # Pull image (idempotent — fast no-op if cached)
        self.ssh.run_sudo_command(f"docker pull {self.IMAGE_NAME}")

        # Wipe any prior install, including the bind-mounted config dir, before
        # writing a fresh config — leftover state would leak old credentials.
        install_protocol = protocol_type or self.protocol
        container_name = self._container_name(install_protocol)
        config_dir = self._config_dir(install_protocol)

        if self.check_protocol_installed(install_protocol):
            self.remove_container(install_protocol)

        config_text = self._build_config(username, password, port)
        self.ssh.run_sudo_command(f"mkdir -p {config_dir}")
        self.ssh.upload_file_sudo(config_text, f"{config_dir}/3proxy.cfg")

        # The 3proxy image reads /etc/3proxy/3proxy.cfg by default.
        # Do not pass the config path as the container command: Docker would try
        # to execute the config file and fail with "permission denied".
        run_cmd = (
            f"docker run -d --restart always "
            f"--name {container_name} "
            f"-p {port}:{port}/tcp "
            f"-v {config_dir}:/etc/3proxy:ro "
            f"{self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            return {'status': 'error', 'message': f'Failed to start container: {err}'}

        return {
            'status': 'success',
            'protocol': install_protocol,
            'base_protocol': self.PROTOCOL,
            'instance': self._instance_index(install_protocol),
            'container_name': container_name,
            'port': port,
            'username': username,
            'password': password,
            'message': 'SOCKS5 proxy installed',
            'log': [
                f'SOCKS5 proxy listening on port {port}/TCP',
                f'Username: {username}',
                f'Password: {password}',
                'Save these credentials — the password can also be viewed later via "Change settings".',
            ],
        }

    def update_credentials(self, port=None, username=None, password=None):
        """Apply new connection settings: regenerates the config file and
        restarts the container so the new port mapping takes effect."""
        if not self.check_protocol_installed(self.protocol):
            return {'status': 'error', 'message': 'SOCKS5 not installed'}

        current = self.get_credentials()
        new_port = int(port if port is not None else (current.get('port') or self.DEFAULT_PORT))
        new_user = (username or current.get('username') or self.DEFAULT_USERNAME).strip()
        new_pass = (password or current.get('password') or _generate_password()).strip()

        old_port = current.get('port')

        # If the port changed we must recreate the container — `docker run -p`
        # mappings are immutable on existing containers.
        if old_port and new_port != old_port:
            return self.install_protocol(
                protocol_type=self.protocol, port=new_port, username=new_user, password=new_pass
            )

        config_text = self._build_config(new_user, new_pass, new_port)
        self._write_config(config_text)
        self.ssh.run_sudo_command(f"docker restart {self.container_name}")

        return {
            'status': 'success',
            'port': new_port,
            'username': new_user,
            'password': new_pass,
        }

    def remove_container(self, protocol_type='socks5'):
        self.ssh.run_sudo_command(f"docker stop {self._container_name(protocol_type)} || true")
        self.ssh.run_sudo_command(f"docker rm -fv {self._container_name(protocol_type)} || true")
        self.ssh.run_sudo_command(f"rm -rf {self._config_dir(protocol_type)}")
        return True
