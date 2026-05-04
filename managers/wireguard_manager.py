"""
WireGuard Protocol Manager - handles standard WireGuard protocol
installation, configuration, and client management on remote servers.

Follows the same architecture as awg_manager.py, using:
- client/server_scripts/wireguard/ scripts as reference
- Docker container: amneziavpn/amnezia-wg (same as AWG Legacy)
- Standard wg/wg-quick tools
"""

import json
import re
import secrets
import logging
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

WG_DEFAULTS = {
    'port': '51820',
    'mtu': '1420',
    'subnet_address': '10.8.2.0',
    'subnet_cidr': '24',
    'subnet_ip': '10.8.2.1',
    'dns1': '1.1.1.1',
    'dns2': '1.0.0.1',
}


def generate_wg_keypair():
    """Generate a WireGuard X25519 keypair (private, public) as base64 strings."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(private_bytes).decode(), b64encode(public_bytes).decode()


def generate_psk():
    """Generate a WireGuard preshared key."""
    return b64encode(secrets.token_bytes(32)).decode()


class WireGuardManager:
    """Manages standard WireGuard protocol installation and client management."""

    PROTOCOL = 'wireguard'
    CONTAINER_NAME = 'amnezia-wireguard'
    DOCKER_IMAGE = 'amneziavpn/amnezia-wg:latest'
    CONFIG_PATH = '/opt/amnezia/wireguard/wg0.conf'
    KEY_DIR = '/opt/amnezia/wireguard'
    CLIENTS_TABLE_PATH = '/opt/amnezia/wireguard/clientsTable'
    INTERFACE = 'wg0'

    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        """Check if Docker is installed and running."""
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, code2 = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def install_docker(self):
        """Install Docker on the server."""
        script = r"""
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl enable --now docker; sleep 5;
fi;
if [ "$(systemctl is-active docker)" != "active" ]; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl start docker; sleep 5;
fi;
docker --version
"""
        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            raise RuntimeError(f"Failed to install Docker: {err}")
        return out

    def check_container_running(self):
        """Check if WireGuard container is running."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self):
        """Check if protocol is installed (container exists)."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

    def prepare_host(self):
        """Prepare host for container."""
        dockerfile_folder = f"/opt/amnezia/{self.CONTAINER_NAME}"
        script = f"""
mkdir -p {dockerfile_folder}
mkdir -p {self.KEY_DIR}
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            logger.warning(f"prepare_host warning: {err}")
        return True

    def setup_firewall(self):
        """Setup host firewall."""
        script = """
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
"""
        self.ssh.run_sudo_script(script)
        return True

    def install_protocol(self, port=None):
        """
        Full installation of WireGuard protocol.
        Steps: install docker -> prepare host -> build container ->
               configure container -> run container -> setup firewall
        """
        if port is None:
            port = WG_DEFAULTS['port']

        results = []

        # Step 1: Install Docker
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        # Step 2: Prepare host
        results.append("Preparing host...")
        self.prepare_host()
        results.append("Host prepared")

        # Step 3: Remove old container if exists
        if self.check_protocol_installed():
            results.append("Removing old container...")
            self.remove_container()
            results.append("Old container removed")

        # Step 4: Build container
        results.append("Building Docker image...")
        dockerfile_folder = f"/opt/amnezia/{self.CONTAINER_NAME}"

        dockerfile_content = (
            f"FROM {self.DOCKER_IMAGE}\n"
            f"\n"
            f'LABEL maintainer="AmneziaVPN"\n'
            f"\n"
            f"RUN apk add --no-cache curl wireguard-tools dumb-init iptables bash\n"
            f"RUN apk --update upgrade --no-cache\n"
            f"\n"
            f"RUN mkdir -p /opt/amnezia\n"
            f'RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && '
            f'echo "tail -f /dev/null" >> /opt/amnezia/start.sh\n'
            f"RUN chmod a+x /opt/amnezia/start.sh\n"
            f"\n"
            f'ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]\n'
        )
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {self.CONTAINER_NAME} {dockerfile_folder}",
            timeout=300
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        # Step 5: Run container
        results.append("Starting container...")
        run_cmd = f"""docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p {port}:{port}/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name {self.CONTAINER_NAME} \
{self.CONTAINER_NAME}"""

        out, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")

        # Connect to DNS network
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.CONTAINER_NAME}")

        # Wait for container
        results.append("Waiting for container to start...")
        self._wait_container_running()
        results.append("Container started")

        # Step 6: Configure container
        results.append("Configuring WireGuard...")
        self._configure_container(port)
        results.append("WireGuard configured")

        # Step 7: Upload start script
        results.append("Starting WireGuard service...")
        self._upload_start_script(port)
        results.append("WireGuard service started")

        # Step 8: Setup firewall
        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")

        return {
            'status': 'success',
            'protocol': self.PROTOCOL,
            'port': port,
            'log': results,
        }

    def _wait_container_running(self, timeout=30):
        """Wait for a container to be in 'running' state."""
        import time
        last_status = 'unknown'
        for i in range(timeout // 2):
            out, _, _ = self.ssh.run_sudo_command(
                f"docker inspect --format='{{{{.State.Status}}}}' {self.CONTAINER_NAME}"
            )
            last_status = out.strip().strip("'\"")
            if last_status == 'running':
                time.sleep(1)
                return True
            time.sleep(2)

        logs_out, _, _ = self.ssh.run_sudo_command(
            f"docker logs --tail 50 {self.CONTAINER_NAME} 2>&1"
        )
        raise RuntimeError(
            f"Container {self.CONTAINER_NAME} did not start within {timeout}s "
            f"(status: {last_status}). Logs:\n{logs_out}"
        )

    def _configure_container(self, port):
        """Configure the WireGuard container (generate keys and server config)."""
        subnet_ip = WG_DEFAULTS['subnet_ip']
        subnet_cidr = WG_DEFAULTS['subnet_cidr']

        config_script = f"""
mkdir -p {self.KEY_DIR}
cd {self.KEY_DIR}
WIREGUARD_SERVER_PRIVATE_KEY=$(wg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > {self.KEY_DIR}/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | wg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > {self.KEY_DIR}/wireguard_server_public_key.key

WIREGUARD_PSK=$(wg genpsk)
echo $WIREGUARD_PSK > {self.KEY_DIR}/wireguard_psk.key

cat > {self.CONFIG_PATH} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {subnet_ip}/{subnet_cidr}
ListenPort = {port}
EOF
"""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c '{config_script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure container: {err}")

    def _upload_start_script(self, port):
        """Upload and execute the start script inside the container."""
        subnet_ip = WG_DEFAULTS['subnet_ip']
        subnet_cidr = WG_DEFAULTS['subnet_cidr']

        start_script = f"""#!/bin/bash
echo "WireGuard container startup"

# Kill existing wg-quick if running
wg-quick down {self.CONFIG_PATH} 2>/dev/null

# Start WireGuard
if [ -f {self.CONFIG_PATH} ]; then wg-quick up {self.CONFIG_PATH}; fi

# Allow traffic on the TUN interface
iptables -A INPUT -i {self.INTERFACE} -j ACCEPT
iptables -A FORWARD -i {self.INTERFACE} -j ACCEPT
iptables -A OUTPUT -o {self.INTERFACE} -j ACCEPT

iptables -A FORWARD -i {self.INTERFACE} -o eth0 -s {subnet_ip}/{subnet_cidr} -j ACCEPT
iptables -A FORWARD -i {self.INTERFACE} -o eth1 -s {subnet_ip}/{subnet_cidr} -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s {subnet_ip}/{subnet_cidr} -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s {subnet_ip}/{subnet_cidr} -o eth1 -j MASQUERADE

tail -f /dev/null
"""
        self.ssh.upload_file(start_script, "/tmp/_wg_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_wg_start.sh {self.CONTAINER_NAME}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_wg_start.sh")

        self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}")
        import time
        time.sleep(5)

    def remove_container(self):
        """Remove WireGuard container."""
        self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rmi {self.CONTAINER_NAME}")
        return True

    # ===================== CLIENT MANAGEMENT =====================

    def _get_clients_table(self):
        """Get the clients table from the server."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.CLIENTS_TABLE_PATH} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            return []

    def _save_clients_table(self, clients_table):
        """Save the clients table to the server."""
        content = json.dumps(clients_table, indent=2)
        self.ssh.upload_file(content, "/tmp/_wg_clients.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_wg_clients.json {self.CONTAINER_NAME}:{self.CLIENTS_TABLE_PATH}"
        )
        self.ssh.run_command("rm -f /tmp/_wg_clients.json")

    def _get_server_config(self):
        """Get the server WireGuard config."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.CONFIG_PATH}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server config: {err}")
        return out

    def save_server_config(self, config_content):
        """Save the server WireGuard config and restart container."""
        self.ssh.upload_file(config_content.replace('\r\n', '\n'), "/tmp/_wg_edit_config.conf")
        self.ssh.run_sudo_command(f"docker cp /tmp/_wg_edit_config.conf {self.CONTAINER_NAME}:{self.CONFIG_PATH}")
        self.ssh.run_command("rm -f /tmp/_wg_edit_config.conf")
        self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}")

    def _get_server_public_key(self):
        """Get server public key."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.KEY_DIR}/wireguard_server_public_key.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server public key: {err}")
        return out.strip()

    def _get_server_psk(self):
        """Get server preshared key."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.KEY_DIR}/wireguard_psk.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get PSK: {err}")
        return out.strip()

    def _get_listen_port(self):
        """Extract ListenPort from server config."""
        config = self._get_server_config()
        for line in config.split('\n'):
            if line.strip().startswith('ListenPort'):
                return line.split('=', 1)[1].strip()
        return WG_DEFAULTS['port']

    def _get_used_ips(self):
        """Get list of IPs already assigned in the config."""
        config = self._get_server_config()
        ips = []
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('AllowedIPs'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
            elif line.startswith('Address'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
        return ips

    def _get_next_ip(self):
        """Calculate the next available IP for a new client."""
        used_ips = self._get_used_ips()
        if not used_ips:
            base = WG_DEFAULTS['subnet_address']
            parts = base.split('.')
            parts[3] = '2'
            return '.'.join(parts)

        last_ip = used_ips[-1]
        parts = last_ip.split('.')
        last_octet = int(parts[3])
        next_octet = last_octet + 1
        if next_octet > 254:
            next_octet = 2
        parts[3] = str(next_octet)
        return '.'.join(parts)

    def _parse_peers_from_config(self):
        """Parse [Peer] sections from WireGuard server config."""
        try:
            config = self._get_server_config()
        except Exception:
            return {}
        peers = {}
        current_key = None
        for line in config.split('\n'):
            line = line.strip()
            if line == '[Peer]':
                current_key = None
            elif current_key is None and line.startswith('PublicKey'):
                current_key = line.split('=', 1)[1].strip()
                peers[current_key] = {'allowedIps': ''}
            elif current_key and line.startswith('AllowedIPs'):
                peers[current_key]['allowedIps'] = line.split('=', 1)[1].strip()
        return peers

    def _parse_bytes(self, size_str):
        """Parse human readable size string into bytes."""
        try:
            parts = size_str.strip().split()
            if len(parts) != 2:
                return 0
            val, unit = float(parts[0]), parts[1]
            units = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}
            return int(val * units.get(unit, 1))
        except Exception:
            return 0

    def _wg_show(self):
        """Run 'wg show all' and parse output."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'wg show all'"
        )
        if code != 0 or not out.strip():
            return {}

        result = {}
        current_peer = None

        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result[current_peer] = {}
            elif current_peer and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == 'latest handshake':
                    result[current_peer]['latestHandshake'] = value
                elif key == 'transfer':
                    parts = value.split(',')
                    if len(parts) == 2:
                        received = parts[0].strip().replace(' received', '')
                        sent = parts[1].strip().replace(' sent', '')
                        result[current_peer]['dataReceived'] = received
                        result[current_peer]['dataSent'] = sent
                        result[current_peer]['dataReceivedBytes'] = self._parse_bytes(received)
                        result[current_peer]['dataSentBytes'] = self._parse_bytes(sent)
                elif key == 'allowed ips':
                    result[current_peer]['allowedIps'] = value
        return result

    def get_clients(self):
        """Get list of all clients with live traffic data."""
        clients_table = self._get_clients_table()

        try:
            wg_show_data = self._wg_show()
        except Exception:
            wg_show_data = {}

        known_ids = set()
        for client in clients_table:
            client_id = client.get('clientId', '')
            known_ids.add(client_id)
            if client_id in wg_show_data:
                show_data = wg_show_data[client_id]
                user_data = client.get('userData', {})
                user_data['latestHandshake'] = show_data.get('latestHandshake', '')
                user_data['dataReceived'] = show_data.get('dataReceived', '')
                user_data['dataSent'] = show_data.get('dataSent', '')
                user_data['dataReceivedBytes'] = show_data.get('dataReceivedBytes', 0)
                user_data['dataSentBytes'] = show_data.get('dataSentBytes', 0)
                user_data['allowedIps'] = show_data.get('allowedIps', '')
                client['userData'] = user_data

        # Pick up peers from conf not in clientsTable (native app clients)
        try:
            conf_peers = self._parse_peers_from_config()
            for pub_key, peer_info in conf_peers.items():
                if pub_key in known_ids:
                    continue
                show_data = wg_show_data.get(pub_key, {})
                allowed_ip = peer_info.get('allowedIps', '') or show_data.get('allowedIps', '')
                ip_part = ''
                if allowed_ip:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', allowed_ip)
                    if m:
                        ip_part = m.group(1)
                display_name = f'External ({ip_part})' if ip_part else 'External (native app)'
                clients_table.append({
                    'clientId': pub_key,
                    'userData': {
                        'clientName': display_name,
                        'clientPrivateKey': '',
                        'externalClient': True,
                        'clientIp': ip_part,
                        'latestHandshake': show_data.get('latestHandshake', ''),
                        'dataReceived': show_data.get('dataReceived', ''),
                        'dataSent': show_data.get('dataSent', ''),
                        'dataReceivedBytes': show_data.get('dataReceivedBytes', 0),
                        'dataSentBytes': show_data.get('dataSentBytes', 0),
                        'allowedIps': allowed_ip,
                    }
                })
        except Exception as e:
            logger.warning(f'get_clients: failed to parse conf peers: {e}')

        return clients_table

    def add_client(self, client_name, server_host):
        """
        Add a new client/peer to the WireGuard config.
        Returns the client config string.
        """
        # Generate client keys
        client_priv_key, client_pub_key = generate_wg_keypair()

        # Get server info
        server_pub_key = self._get_server_public_key()
        psk = self._get_server_psk()
        port = self._get_listen_port()

        # Get next available IP
        client_ip = self._get_next_ip()

        dns1 = WG_DEFAULTS['dns1']
        dns2 = WG_DEFAULTS['dns2']
        
        # Check if AmneziaDNS is installed
        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'
            
        mtu = WG_DEFAULTS['mtu']

        # Append peer to server config
        peer_section = f"""
[Peer]
PublicKey = {client_pub_key}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
        escaped_peer = peer_section.replace("'", "'\\''")
        self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'echo \"{escaped_peer}\" >> {self.CONFIG_PATH}'"
        )

        # Sync config without restart
        self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'wg syncconf {self.INTERFACE} <(wg-quick strip {self.CONFIG_PATH})'"
        )

        # Update clients table
        clients_table = self._get_clients_table()
        new_client = {
            'clientId': client_pub_key,
            'userData': {
                'clientName': client_name,
                'creationDate': __import__('datetime').datetime.now().isoformat(),
                'clientPrivateKey': client_priv_key,
                'clientIp': client_ip,
                'psk': psk,
                'enabled': True,
            }
        }
        clients_table.append(new_client)
        self._save_clients_table(clients_table)

        # Build client config
        client_config = f"""[Interface]
Address = {client_ip}/32
DNS = {dns1}, {dns2}
PrivateKey = {client_priv_key}
MTU = {mtu}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""
        return {
            'client_name': client_name,
            'client_id': client_pub_key,
            'client_ip': client_ip,
            'config': client_config,
        }

    def get_client_config(self, client_id, server_host):
        """Reconstruct client config from stored data."""
        clients_table = self._get_clients_table()
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        if not client:
            raise RuntimeError(f"Client {client_id} not found")

        ud = client.get('userData', {})
        client_priv_key = ud.get('clientPrivateKey', '')
        client_ip = ud.get('clientIp', '')
        psk = ud.get('psk', '')

        if not client_priv_key:
            raise RuntimeError("Client private key not stored. Config cannot be reconstructed.")

        server_pub_key = self._get_server_public_key()
        if not psk:
            psk = self._get_server_psk()

        port = self._get_listen_port()

        dns1 = WG_DEFAULTS['dns1']
        dns2 = WG_DEFAULTS['dns2']
        
        # Check if AmneziaDNS is installed
        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'
            
        mtu = WG_DEFAULTS['mtu']

        config = f"""[Interface]
Address = {client_ip}/32
DNS = {dns1}, {dns2}
PrivateKey = {client_priv_key}
MTU = {mtu}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""
        return config

    def toggle_client(self, client_id, enable):
        """Enable or disable a client by adding/removing their [Peer] from server config."""
        if enable:
            clients_table = self._get_clients_table()
            client = next((c for c in clients_table if c.get('clientId') == client_id), None)
            if not client:
                raise RuntimeError(f"Client {client_id} not found")

            ud = client.get('userData', {})
            psk = ud.get('psk', '') or self._get_server_psk()
            client_ip = ud.get('clientIp', '')

            peer_section = f"""
[Peer]
PublicKey = {client_id}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
            escaped_peer = peer_section.replace("'", "'\\''")
            self.ssh.run_sudo_command(
                f"docker exec -i {self.CONTAINER_NAME} bash -c 'echo \"{escaped_peer}\" >> {self.CONFIG_PATH}'"
            )
        else:
            # Remove peer from server config
            config = self._get_server_config()
            sections = config.split('[')
            new_sections = [s for s in sections if s.strip() and client_id not in s]
            new_config = '[' + '['.join(new_sections)

            self.ssh.upload_file(new_config, "/tmp/_wg_config.conf")
            self.ssh.run_sudo_command(
                f"docker cp /tmp/_wg_config.conf {self.CONTAINER_NAME}:{self.CONFIG_PATH}"
            )
            self.ssh.run_command("rm -f /tmp/_wg_config.conf")

        # Sync config
        self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'wg syncconf {self.INTERFACE} <(wg-quick strip {self.CONFIG_PATH})'"
        )

        # Update enabled status in clients table
        clients_table = self._get_clients_table()
        for c in clients_table:
            if c.get('clientId') == client_id:
                c.setdefault('userData', {})['enabled'] = enable
                break
        self._save_clients_table(clients_table)

    def remove_client(self, client_id):
        """Remove a client from WireGuard config."""
        config = self._get_server_config()
        sections = config.split('[')
        new_sections = [s for s in sections if s.strip() and client_id not in s]
        new_config = '[' + '['.join(new_sections)

        self.ssh.upload_file(new_config, "/tmp/_wg_config.conf")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_wg_config.conf {self.CONTAINER_NAME}:{self.CONFIG_PATH}"
        )
        self.ssh.run_command("rm -f /tmp/_wg_config.conf")

        # Sync config
        self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c 'wg syncconf {self.INTERFACE} <(wg-quick strip {self.CONFIG_PATH})'"
        )

        # Update clients table
        clients_table = self._get_clients_table()
        clients_table = [c for c in clients_table if c.get('clientId') != client_id]
        self._save_clients_table(clients_table)
        return True

    def get_server_status(self):
        """Get detailed status of the WireGuard server."""
        info = {
            'container_exists': self.check_protocol_installed(),
            'container_running': False,
            'protocol': self.PROTOCOL,
        }

        if info['container_exists']:
            info['container_running'] = self.check_container_running()
            if info['container_running']:
                try:
                    config = self._get_server_config()
                    for line in config.split('\n'):
                        if 'ListenPort' in line:
                            info['port'] = line.split('=')[1].strip()
                            break
                    info['clients_count'] = len(self._get_clients_table())
                except Exception as e:
                    info['error'] = str(e)

        return info

    def get_traffic_stats(self):
        """Get aggregate traffic stats for all clients."""
        try:
            wg_data = self._wg_show()
        except Exception:
            return {}

        total_rx = 0
        total_tx = 0
        active_peers = 0
        active_ips = []

        for peer_key, data in wg_data.items():
            rx = data.get('dataReceivedBytes', 0)
            tx = data.get('dataSentBytes', 0)
            total_rx += rx
            total_tx += tx
            if rx > 0 or tx > 0:
                active_peers += 1
            allowed = data.get('allowedIps', '')
            if allowed:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', allowed)
                if m:
                    active_ips.append(m.group(1))

        return {
            'total_rx_bytes': total_rx,
            'total_tx_bytes': total_tx,
            'active_connections': active_peers,
            'active_ips': active_ips,
        }
