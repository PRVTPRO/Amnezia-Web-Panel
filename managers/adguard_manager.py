"""
AdGuard Home Manager — runs adguard/adguardhome in a Docker container,
joined to the same internal `amnezia-dns-net` network the rest of the panel
uses. Two install modes:

  * 'replace'    — removes the AmneziaDNS container (if present) and takes
                   its static IP (172.29.172.254) so VPN clients keep using
                   the same upstream.
  * 'sidebyside' — runs alongside AmneziaDNS on a different static IP
                   (172.29.172.253). VPN users can hit it on demand
                   (e.g. via the web admin UI from inside the tunnel).

Initial setup of AdGuard itself runs through its built-in wizard on the web
UI port — we do not try to script it (the JSON setup API is unstable across
versions and trying to drive it programmatically tends to break on upgrade).
"""

import logging

logger = logging.getLogger(__name__)


class AdguardManager:
    PROTOCOL = 'adguard'
    CONTAINER_NAME = 'amnezia-adguard'
    IMAGE_NAME = 'adguard/adguardhome:latest'

    NETWORK_NAME = 'amnezia-dns-net'
    NETWORK_SUBNET = '172.29.172.0/24'
    REPLACE_IP = '172.29.172.254'      # AmneziaDNS's slot
    SIDEBYSIDE_IP = '172.29.172.253'   # parallel to AmneziaDNS

    HOST_DIR = '/opt/amnezia/adguard'
    DEFAULT_DNS_PORT = 53
    DEFAULT_WEB_PORT = 3000
    DEFAULT_DOT_PORT = 853
    DEFAULT_DOH_PORT = 443

    def __init__(self, ssh):
        self.ssh = ssh

    # ===================== STATUS =====================

    def check_docker_installed(self):
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def check_protocol_installed(self, protocol_type='adguard'):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

    def check_container_running(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def _container_ip(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}} {{{{end}}}}' {self.CONTAINER_NAME} 2>/dev/null"
        )
        ip = out.strip().split()[0] if out.strip() else ''
        return ip

    def _detect_mode(self):
        """Return 'replace' or 'sidebyside' based on the running container's IP.
        Returns None if not detectable (container not running)."""
        ip = self._container_ip()
        if ip == self.REPLACE_IP:
            return 'replace'
        if ip == self.SIDEBYSIDE_IP:
            return 'sidebyside'
        return None

    def _exposed_web_port(self):
        """Reads back the host->container port mapping for the web UI port,
        so the panel can show the correct admin URL after install."""
        out, _, _ = self.ssh.run_sudo_command(
            f"docker port {self.CONTAINER_NAME} 3000/tcp 2>/dev/null"
        )
        if not out.strip():
            return None
        # output like "0.0.0.0:3000" — take the last colon-separated chunk
        last = out.strip().split('\n')[0].split(':')[-1].strip()
        try:
            return int(last)
        except ValueError:
            return None

    def get_server_status(self, protocol_type='adguard'):
        exists = self.check_protocol_installed()
        running = self.check_container_running()
        mode = self._detect_mode() if running else None
        ip = self._container_ip() if running else ''
        exposed_port = self._exposed_web_port() if running else None
        # When the web UI is not bound to the host the user still needs an
        # admin URL (reachable via VPN) — fall back to the default :3000 the
        # container listens on inside the docker network.
        return {
            'container_exists': exists,
            'container_running': running,
            'mode': mode,
            'internal_ip': ip,
            'web_port': exposed_port or self.DEFAULT_WEB_PORT,
            'web_exposed': exposed_port is not None,
            'port': self.DEFAULT_DNS_PORT,
            'protocol': protocol_type,
        }

    # ===================== INSTALL / REMOVE =====================

    def _ensure_network(self):
        self.ssh.run_sudo_command(
            f"docker network ls | grep -q {self.NETWORK_NAME} || "
            f"docker network create --subnet {self.NETWORK_SUBNET} {self.NETWORK_NAME}"
        )

    def install_protocol(
        self,
        protocol_type='adguard',
        mode='sidebyside',
        web_port=None,
        expose_web=False,
        dns_port=None,
        dot_port=None,
        doh_port=None,
        expose_dns=False,
        expose_dot=False,
        expose_doh=False,
    ):
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}
        if mode not in ('replace', 'sidebyside'):
            return {'status': 'error', 'message': f"Invalid mode '{mode}'"}

        web_port = int(web_port or self.DEFAULT_WEB_PORT)
        dns_port = int(dns_port or self.DEFAULT_DNS_PORT)
        dot_port = int(dot_port or self.DEFAULT_DOT_PORT)
        doh_port = int(doh_port or self.DEFAULT_DOH_PORT)

        # Persistent volumes — without these the AdGuard setup wizard would have
        # to re-run on every container recreate.
        self.ssh.run_sudo_command(f"mkdir -p {self.HOST_DIR}/work {self.HOST_DIR}/conf")

        self._ensure_network()

        # Replace mode: detach + remove AmneziaDNS so we can claim its IP.
        if mode == 'replace':
            self.ssh.run_sudo_command(
                f"docker network disconnect {self.NETWORK_NAME} amnezia-dns 2>/dev/null || true"
            )
            self.ssh.run_sudo_command("docker stop amnezia-dns 2>/dev/null || true")
            self.ssh.run_sudo_command("docker rm -fv amnezia-dns 2>/dev/null || true")
            target_ip = self.REPLACE_IP
        else:
            target_ip = self.SIDEBYSIDE_IP

        if self.check_protocol_installed():
            self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} 2>/dev/null || true")
            self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} 2>/dev/null || true")

        self.ssh.run_sudo_command(f"docker pull {self.IMAGE_NAME}")

        # Build port mapping. By default ports are reachable only inside
        # `amnezia-dns-net` (so VPN clients hit them via the static IP).
        # Optional `expose_*` flags add host port mappings for direct access.
        ports = []
        if expose_web:
            ports.append(f"-p {web_port}:3000/tcp")
        if expose_dns:
            ports.append(f"-p {dns_port}:53/tcp")
            ports.append(f"-p {dns_port}:53/udp")
        if expose_dot:
            ports.append(f"-p {dot_port}:853/tcp")
        if expose_doh:
            ports.append(f"-p {doh_port}:443/tcp")
        ports_str = ' '.join(ports)

        run_cmd = (
            f"docker run -d --name {self.CONTAINER_NAME} --restart always "
            f"--network {self.NETWORK_NAME} --ip {target_ip} "
            f"-v {self.HOST_DIR}/work:/opt/adguardhome/work "
            f"-v {self.HOST_DIR}/conf:/opt/adguardhome/conf "
            f"{ports_str} "
            f"{self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            return {'status': 'error', 'message': f'Failed to start container: {err}'}

        # Re-attach known VPN containers to the DNS network so they can reach
        # AdGuard at target_ip (mirrors what dns_manager.py does on install).
        for c in ('amnezia-awg', 'amnezia-awg2', 'amnezia-awg-legacy', 'amnezia-xray', 'amnezia-wireguard', 'telemt'):
            self.ssh.run_sudo_command(
                f"docker ps --format '{{{{.Names}}}}' | grep -q '^{c}$' && "
                f"docker network connect {self.NETWORK_NAME} {c} 2>/dev/null || true"
            )

        url_host = self.ssh.host if expose_web else target_ip
        admin_url = f"http://{url_host}:{web_port}"
        return {
            'status': 'success',
            'protocol': 'adguard',
            'mode': mode,
            'internal_ip': target_ip,
            'web_port': web_port,
            'expose_web': bool(expose_web),
            'admin_url': admin_url,
            'message': 'AdGuard Home installed. Complete the setup wizard via the web UI.',
            'log': [
                f"AdGuard Home installed in '{mode}' mode",
                f"Internal IP: {target_ip}",
                f"Admin UI: {admin_url}" + ("" if expose_web else "  (VPN-only — connect via VPN to reach it)"),
                'Open the URL above to run the AdGuard setup wizard.',
            ],
        }

    def remove_container(self, protocol_type='adguard'):
        self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"rm -rf {self.HOST_DIR}")
        return True
