
import os
import logging
from managers import docker_image_cleanup

logger = logging.getLogger(__name__)

class DNSManager:
    def __init__(self, ssh):
        self.ssh = ssh

    def install_protocol(self, protocol_type='dns', port='53'):
        """Install AmneziaDNS service."""
        try:
            # 1. Check if docker is installed
            out, _, _ = self.ssh.run_command("docker --version")
            if "docker version" not in out.lower():
                return {"status": "error", "message": "Docker not installed"}

            # 2. Prepare directory
            self.ssh.run_sudo_command("mkdir -p /opt/amnezia/dns")

            # 3. Create Dockerfile matching official Amnezia implementation
            # We use Unbound (mvance/unbound) with DNS-over-TLS to Cloudflare
            forward_config = """forward-zone:
   name: "."
   forward-tls-upstream: yes
   forward-addr: 1.1.1.1@853
   forward-addr: 1.0.0.1@853
"""
            self.ssh.write_file("/opt/amnezia/dns/forward-records.conf", forward_config)
            
            dockerfile = """
FROM mvance/unbound:latest
LABEL maintainer="AmneziaVPN"
COPY forward-records.conf /opt/unbound/etc/unbound/forward-records.conf
"""
            self.ssh.write_file("/opt/amnezia/dns/Dockerfile", dockerfile)

            # 4. Build and run
            old_image_id = docker_image_cleanup.image_id(self.ssh, 'amnezia-dns')
            _out, _err, build_code = self.ssh.run_sudo_command(
                "docker build -t amnezia-dns /opt/amnezia/dns")
            if build_code == 0:
                docker_image_cleanup.drop_replaced_image(
                    self.ssh, 'amnezia-dns', old_image_id)
            self.ssh.run_sudo_command("docker stop amnezia-dns || true")
            self.ssh.run_sudo_command("docker rm amnezia-dns || true")
            
            # Create internal network for DNS (like original Amnezia client)
            # Both halves need root: `sudo <a> || <b>` would run the create unprivileged
            self.ssh.run_sudo_command(
                "sh -c 'docker network ls | grep -q amnezia-dns-net || "
                "docker network create --subnet 172.29.172.0/24 amnezia-dns-net'")
            
            # Use internal network with static IP. Do not expose 53 on host to avoid systemd-resolved conflict.
            cmd = "docker run -d --name amnezia-dns --restart always --network amnezia-dns-net --ip=172.29.172.254 amnezia-dns"
            self.ssh.run_sudo_command(cmd)

            # Connect existing VPN containers to the DNS network
            vpn_containers = ['amnezia-awg', 'amnezia-awg2', 'amnezia-awg-legacy', 'amnezia-xray', 'telemt', 'amnezia-exit']
            for c in vpn_containers:
                # `docker network connect` also needs root, so the whole chain
                # goes to one shell (see _fetch_remote_archive for the same trap)
                self.ssh.run_sudo_command(
                    f"sh -c 'docker ps | grep -q {c} && "
                    f"docker network connect amnezia-dns-net {c} || true'")

            return {"status": "success", "message": "AmneziaDNS installed successfully"}
        except Exception as e:
            logger.exception("Error installing DNS")
            return {"status": "error", "message": str(e)}
        finally:
            self._invalidate_snapshot()

    def _invalidate_snapshot(self):
        invalidate = getattr(self.ssh, 'docker_ps_invalidate', None)
        if invalidate:
            invalidate()

    def get_server_status(self, protocol_type='dns'):
        """Check if AmneziaDNS container is running."""
        try:
            snapshot = getattr(self.ssh, 'docker_container_state', None)
            try:
                state = snapshot('amnezia-dns') if snapshot else None
            except Exception:
                state = None
            if state is not None:
                return {
                    'container_exists': state[0], 'container_running': state[1],
                    'port': '53', 'protocol': protocol_type,
                }
            out, _, running_code = self.ssh.run_sudo_command("docker ps --filter name=^amnezia-dns$ --format '{{.Status}}'")
            is_running = 'Up' in out
            
            out_exists, _, exists_code = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
            if running_code != 0 or exists_code != 0:
                return {'error': 'Unable to inspect DNS container', 'protocol': protocol_type}
            container_exists = 'amnezia-dns' in out_exists.strip().split('\n')
            
            return {
                "container_exists": container_exists,
                "container_running": is_running,
                "port": "53",
                "protocol": protocol_type
            }
        except Exception as e:
            return {"error": str(e)}

    def remove_container(self, protocol_type='dns'):
        """Remove AmneziaDNS container."""
        try:
            self.ssh.run_sudo_command("docker stop amnezia-dns || true")
            self.ssh.run_sudo_command("docker rm amnezia-dns || true")
            self.ssh.run_sudo_command("rm -rf /opt/amnezia/dns")
        finally:
            self._invalidate_snapshot()
