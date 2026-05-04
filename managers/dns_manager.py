
import os
import logging

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
            self.ssh.run_sudo_command("docker build -t amnezia-dns /opt/amnezia/dns")
            self.ssh.run_sudo_command("docker stop amnezia-dns || true")
            self.ssh.run_sudo_command("docker rm amnezia-dns || true")
            
            # Create internal network for DNS (like original Amnezia client)
            self.ssh.run_sudo_command("docker network ls | grep -q amnezia-dns-net || docker network create --subnet 172.29.172.0/24 amnezia-dns-net")
            
            # Use internal network with static IP. Do not expose 53 on host to avoid systemd-resolved conflict.
            cmd = "docker run -d --name amnezia-dns --restart always --network amnezia-dns-net --ip=172.29.172.254 amnezia-dns"
            self.ssh.run_sudo_command(cmd)

            # Connect existing VPN containers to the DNS network
            vpn_containers = ['amnezia-awg', 'amnezia-awg2', 'amnezia-awg-legacy', 'amnezia-xray', 'telemt']
            for c in vpn_containers:
                self.ssh.run_sudo_command(f"docker ps | grep -q {c} && docker network connect amnezia-dns-net {c} || true")

            return {"status": "success", "message": "AmneziaDNS installed successfully"}
        except Exception as e:
            logger.exception("Error installing DNS")
            return {"status": "error", "message": str(e)}

    def get_server_status(self, protocol_type='dns'):
        """Check if AmneziaDNS container is running."""
        try:
            out, _, _ = self.ssh.run_sudo_command("docker ps --filter name=^amnezia-dns$ --format '{{.Status}}'")
            is_running = 'Up' in out
            
            out_exists, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
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
        self.ssh.run_sudo_command("docker stop amnezia-dns || true")
        self.ssh.run_sudo_command("docker rm amnezia-dns || true")
        self.ssh.run_sudo_command("rm -rf /opt/amnezia/dns")
