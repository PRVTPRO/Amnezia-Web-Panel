"""
HAProxy load balancer manager.

Runs an HAProxy container with a single editable configuration file. The
panel owns haproxy.cfg: editable through the Config button, validated with
`haproxy -c` inside the container before it is applied, and applied with a
container restart (HAProxy has no hot reload signal in this setup).
"""

import json
import logging
import shlex

logger = logging.getLogger(__name__)


def _q(value):
    return shlex.quote(str(value))


class HaproxyManager:
    PROTOCOL = 'haproxy'
    CONTAINER_NAME = 'amnezia-haproxy'
    IMAGE_NAME = 'haproxy:lts-alpine'
    BASE_DIR = '/opt/amnezia/haproxy'
    CONF_DIR = f'{BASE_DIR}/conf'
    CONF_PATH = f'{CONF_DIR}/haproxy.cfg'
    # The path inside the official image where the config is mounted.
    CONTAINER_CONF_PATH = '/usr/local/etc/haproxy/haproxy.cfg'
    META_PATH = f'{BASE_DIR}/metadata.json'
    DEFAULT_PORT = 8080

    def __init__(self, ssh, protocol='haproxy'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL

    # ===================== STATUS =====================

    def check_docker_installed(self):
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def check_protocol_installed(self, protocol_type='haproxy'):
        _st_fn = getattr(self.ssh, 'docker_container_state', None)
        if _st_fn:
            _st = _st_fn(self.CONTAINER_NAME)
            if _st is not None:
                return _st[0]
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

    def check_container_running(self, protocol_type='haproxy'):
        _st_fn = getattr(self.ssh, 'docker_container_state', None)
        if _st_fn:
            _st = _st_fn(self.CONTAINER_NAME)
            if _st is not None:
                return _st[1]
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def get_server_status(self, protocol_type='haproxy'):
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type)
        meta = self._read_metadata() if exists else {}
        return {
            'container_exists': exists,
            'container_running': running,
            'port': int(meta.get('port') or self.DEFAULT_PORT),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.CONTAINER_NAME,
        }

    # ===================== CONFIG =====================

    def _default_config(self, port):
        return f"""global
    log stdout format raw local0 info

defaults
    mode http
    log global
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Stats and placeholder page on the chosen port.
# Replace this frontend/backend pair with your own load-balancing rules.
frontend http_{port}
    bind *:{port}
    default_backend placeholder

backend placeholder
    balance roundrobin
    # Add your real servers here, e.g.:
    # server app1 10.8.1.2:443 check
    http-request return status 200 content-type 'text/html' string "HAProxy is running"
"""

    def get_config(self, protocol_type='haproxy'):
        config = self._read_file(self.CONF_PATH)
        if config:
            return config
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.CONTAINER_NAME} cat {self.CONTAINER_CONF_PATH} 2>/dev/null"
        )
        return out if code == 0 else ''

    # Back-compat alias used by the generic server-config routes.
    def _get_server_config(self, protocol_type='haproxy'):
        return self.get_config(protocol_type)

    def save_server_config(self, protocol_type='haproxy', config_text=''):
        old_config = self.get_config(protocol_type)
        self._write_file(self.CONF_PATH, config_text or '')
        if self.check_container_running(protocol_type):
            _, err, code = self.ssh.run_sudo_command(
                f"docker exec {self.CONTAINER_NAME} haproxy -c -f {self.CONTAINER_CONF_PATH}",
                timeout=30,
            )
            if code != 0:
                self._write_file(self.CONF_PATH, old_config)
                raise RuntimeError(f'Invalid HAProxy config: {err}')
            self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}")
        return True

    # ===================== FILE I/O =====================

    def _read_file(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {_q(path)} 2>/dev/null")
        return out if code == 0 else ''

    def _write_file(self, path, content):
        parent = path.rsplit('/', 1)[0]
        self.ssh.run_sudo_command(f"mkdir -p {_q(parent)}")
        self.ssh.upload_file_sudo(content, path)

    def _read_metadata(self):
        raw = self._read_file(self.META_PATH)
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _write_metadata(self, meta):
        self._write_file(self.META_PATH, json.dumps(meta, indent=2, ensure_ascii=False))

    # ===================== INSTALL / REMOVE =====================

    def install_protocol(self, protocol_type='haproxy', port=None):
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}

        port = int(port or self.DEFAULT_PORT)

        self.ssh.run_sudo_command(f"docker pull {self.IMAGE_NAME}", timeout=180)

        if self.check_protocol_installed(protocol_type):
            self.remove_container(protocol_type)

        self._write_file(self.CONF_PATH, self._default_config(port))
        self._write_metadata({'port': port})

        run_cmd = (
            f"docker run -d --restart always "
            f"--name {self.CONTAINER_NAME} "
            f"-p {port}:{port}/tcp "
            f"-v {self.CONF_DIR}:{self.CONTAINER_CONF_PATH.rsplit('/', 1)[0]}:ro "
            f"{self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd, timeout=60)
        if code != 0:
            return {'status': 'error', 'message': f'Failed to start HAProxy container: {err}'}

        _, err, code = self.ssh.run_sudo_command(
            f"docker exec {self.CONTAINER_NAME} haproxy -c -f {self.CONTAINER_CONF_PATH}",
            timeout=30,
        )
        if code != 0:
            logs = self.ssh.run_sudo_command(
                f"docker logs --tail 60 {self.CONTAINER_NAME} 2>&1 || true")[0]
            self.remove_container(protocol_type)
            return {'status': 'error',
                    'message': f'The generated HAProxy config is invalid: {err} {logs}'}

        return {
            'status': 'success',
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.CONTAINER_NAME,
            'port': port,
            'message': 'HAProxy load balancer installed',
            'log': [
                f'HAProxy listens on {port}/TCP',
                f'Config file: {self.CONF_PATH} — edit it with the Config button',
            ],
        }

    def remove_container(self, protocol_type='haproxy'):
        self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"rm -rf {self.BASE_DIR}")
        return True
