"""Exit node: an AmneziaWG transit endpoint whose peers are other panel servers.

An entry node routes its clients through the exit and SNATs them into its own
transit address, so the exit sees exactly one /32 per entry, NATs the transit
subnet to the internet and never carries end-user peers. The container is the
same image and start script as an AWG server (see AWGManager builders) with its
own paths, one fixed instance and a peers table instead of a clients table.
"""

import ipaddress
import logging
from datetime import datetime

from managers.awg_manager import (
    AWG_QUICK_FORCE_USERSPACE_PATCH,
    AWGManager,
    generate_psk,
    generate_transit_params,
    is_awg31_params,
    transit_mtu,
    transit_param_lines,
)
import warp_service as warp_logic

logger = logging.getLogger(__name__)

EXIT_DEFAULTS = {
    'port': '55520',
    'subnet': '10.9.0.0/24',
    'mtu': '1420',
}


class ExitManager(AWGManager):
    """Install and manage the `amnezia-exit` transit container."""

    PROTOCOL = 'exit'
    CONTAINER_NAME = 'amnezia-exit'
    DOCKER_IMAGE = 'amneziavpn/amneziawg-go:latest'
    CONFIG_DIR = '/opt/amnezia/exit'
    CONFIG_PATH = '/opt/amnezia/exit/transit0.conf'
    INTERFACE = 'transit0'
    PEERS_TABLE = '/opt/amnezia/exit/peersTable'
    PRIVATE_KEY_PATH = '/opt/amnezia/exit/wireguard_server_private_key.key'
    PUBLIC_KEY_PATH = '/opt/amnezia/exit/wireguard_server_public_key.key'

    def __init__(self, ssh, protocol='exit'):
        super().__init__(ssh)
        self.protocol = self.PROTOCOL
        # telegram_bot falls back to these attributes for docker inspect
        self.container_name = self.CONTAINER_NAME

    # ----- single fixed instance: every AWGManager lookup resolves here -----

    def _base_protocol(self, protocol_type=None):
        return self.PROTOCOL

    def _instance_index(self, protocol_type=None):
        return 1

    def _container_name(self, protocol_type=None):
        return self.CONTAINER_NAME

    def _config_path(self, protocol_type=None):
        return self.CONFIG_PATH

    def _config_path_candidates(self, protocol_type=None):
        return [self.CONFIG_PATH]

    def _resolve_config_path(self, protocol_type=None):
        # One fixed location, nothing to probe over SSH.
        return self.CONFIG_PATH

    def _interface_name(self, protocol_type=None, config_path=None):
        return self.INTERFACE

    def _docker_image(self, protocol_type=None):
        return self.DOCKER_IMAGE

    def _wg_binary(self, protocol_type=None):
        return 'awg'

    def _quick_binary(self, protocol_type=None):
        return 'awg-quick'

    def _userspace_guard(self, protocol_type=None):
        # The transit link must run on the kernel module: a userspace
        # amneziawg-go fallback is refused at install/link time instead of
        # being silently used (see install_protocol / transit_backend).
        return ''

    def transit_backend(self):
        """'kernel' / 'userspace' / 'down' for the transit0 interface."""
        return self._tunnel_backend(self.PROTOCOL, self.INTERFACE)

    def _clients_table_path(self):
        return self.PEERS_TABLE

    def _bwlimits_path(self):
        return f'{self.CONFIG_DIR}/bwlimits'

    def _apply_bw_limits(self, protocol_type, clients_table):
        # No per-peer shaping on the transit link.
        return None

    def _get_server_public_key(self, protocol_type=None):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} cat {self.PUBLIC_KEY_PATH}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get exit public key: {err}")
        return out.strip()

    def _get_server_psk(self, protocol_type=None):
        raise RuntimeError('Exit node uses a per-peer preshared key')

    # ----- no end users on an exit node: every client path is closed -----

    def _no_clients(self, *args, **kwargs):
        raise RuntimeError('Exit node has no clients; manage its peers instead')

    add_client = _no_clients
    get_client_config = _no_clients
    toggle_client = _no_clients
    rename_client = _no_clients
    save_client_config = _no_clients
    set_speed_limit = _no_clients

    # ===================== INSTALLATION =====================

    @staticmethod
    def _subnet_gateway(net):
        """Address line of the exit itself: first host of the transit subnet."""
        return f"{net.network_address + 1}/{net.prefixlen}"

    def _render_start_script(self, protocol_type=None, config_path=None,
                             warp_ctx=None):
        net = ipaddress.ip_network(EXIT_DEFAULTS['subnet'])
        pre_blocks = ()
        extra_blocks = (self._mss_clamp_body(self.INTERFACE),)
        if warp_ctx and warp_ctx.get('active'):
            functions = self._warp_shell_functions(
                warp_ctx,
                'awg-quick',
                'awg',
                '$SUBNET',
                '$IFACE',
                '$SUBNET6',
                pref_c2c=warp_logic.WARP_PREF_B_TRANSIT,
                transit_cidr=warp_ctx.get('transit_cidr') or '',
                marker='/opt/amnezia/exit/warp-link',
                include_helpers=True,
                userspace='amneziawg-go' in self._docker_image(protocol_type),
            )
            pre_blocks = (functions + 'x_warp_killswitch_on\n',)
            extra_blocks = (
                self._mss_clamp_body(self.INTERFACE),
                '# ---- WARP egress: bring it up now that the transit link exists ----\n'
                'x_warp_up || echo "! warp link not applied, transit stays on the kill-switch"\n',
            )
        return self._start_script_body(
            self.CONFIG_PATH,
            'awg-quick',
            '',
            self._subnet_gateway(net),
            self._bwlimits_path(),
            pre_blocks=pre_blocks,
            extra_blocks=extra_blocks,
        )

    def _transit_config(self, port, net, awg_params):
        """transit0.conf. Panel metadata lives inside [Interface] as comments
        (remove_client() splits the file on `[` and would drop anything before
        the first section)."""
        return (
            "[Interface]\n"
            "# Managed by Amnezia Web Panel - exit node transit endpoint\n"
            f"# Subnet = {net}\n"
            f"# Obfuscation = {'on' if awg_params else 'off'}\n"
            f"# ProtocolVersion = {self._protocol_version(awg_params) or 'wireguard'}\n"
            "PrivateKey = $(cat wireguard_server_private_key.key)\n"
            f"Address = {self._subnet_gateway(net)}\n"
            f"ListenPort = {port}\n"
            f"MTU = {transit_mtu(awg_params)}\n"
            f"{transit_param_lines(awg_params) if awg_params else ''}"
        )

    @staticmethod
    def _protocol_version(awg_params):
        """'3.1' for a header-protected transit, '2.0' for the legacy set."""
        if not awg_params:
            return None
        return '3.1' if is_awg31_params(awg_params) else '2.0'

    def _configure_exit_container(self, port, net, awg_params):
        """Generate the key pair (kept if present) and write transit0.conf.

        The file is rewritten from scratch, but the [Peer] sections are carried
        over: they only exist in this file (the panel's peersTable has no PSKs),
        so dropping them would silently break every exit link on the next
        reinstall or settings change.

        The script body is embedded in ``bash -c '...'``, so it must not contain
        a single quote: only double quotes are safe in here.
        """
        script = f"""
set -e
mkdir -p {self.CONFIG_DIR} && cd {self.CONFIG_DIR} && umask 077
[ -s wireguard_server_private_key.key ] || awg genkey > wireguard_server_private_key.key
awg pubkey < wireguard_server_private_key.key > wireguard_server_public_key.key
PEERS=""
if [ -f {self.CONFIG_PATH} ]; then
  PEERS=$(awk "/^\\[Peer\\]/{{inside=1}} inside" {self.CONFIG_PATH})
fi
cat > {self.CONFIG_PATH} <<EOF
{self._transit_config(port, net, awg_params)}EOF
if [ -n "$PEERS" ]; then
  printf "%s\\n" "$PEERS" >> {self.CONFIG_PATH}
fi
"""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} bash -c '{script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure the transit endpoint: {err}")

    def install_protocol(self, protocol_type='exit', port=None, subnet=None,
                         obfuscation=False, awg3=False, warp_ctx=None, **_ignored):
        """Install the exit-node container.

        `subnet` is the transit subnet shared with the entry nodes (must be an
        IPv4 /24: the peer allocator hands out the last octet); `obfuscation`
        turns the transit link into AmneziaWG with junk/handshake obfuscation,
        otherwise it speaks plain WireGuard. `awg3` upgrades that obfuscation
        to the 3.1 key set (header protection, random trailers, content
        padding); entry nodes must speak 3.1 to link to such an exit.
        """
        port = str(port or EXIT_DEFAULTS['port']).strip()
        try:
            net = ipaddress.ip_network(subnet or EXIT_DEFAULTS['subnet'], strict=False)
        except ValueError:
            return {'status': 'error', 'message': f'Invalid transit subnet: {subnet}'}
        if net.version != 4 or net.prefixlen != 24:
            return {'status': 'error',
                    'message': 'Transit subnet must be an IPv4 /24 (peers get the last octet)'}

        if obfuscation and awg3:
            module = self._host_awg_module_version()
            if not self._module_supports_awg3(module):
                return {
                    'status': 'error',
                    'message': (
                        'AmneziaWG 3.1 needs the amneziawg kernel module 3.0+ '
                        f'(this host has {module or "no amneziawg module"}). '
                        'The link would fall back to userspace amneziawg-go.'),
                }

        results = []
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        results.append("Preparing host...")
        docker_ipv6 = self.prepare_host(self.PROTOCOL)
        results.append("Host prepared")
        if docker_ipv6 == 'pending':
            results.append(
                "! Docker IPv6 was enabled in /etc/docker/daemon.json, but Docker "
                "was NOT restarted because other containers are running. The transit "
                "stays IPv4-only until you run: systemctl restart docker"
            )
        elif docker_ipv6 == 'restarted':
            results.append("Docker restarted to apply IPv6 config")

        if self.check_protocol_installed(self.PROTOCOL):
            results.append("Removing old container...")
            self.remove_container(self.PROTOCOL)
            results.append("Old container removed")

        results.append("Pulling Docker image...")
        dockerfile_folder = f"/opt/amnezia/{self.CONTAINER_NAME}"
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(
            self._dockerfile_content(self.DOCKER_IMAGE, AWG_QUICK_FORCE_USERSPACE_PATCH),
            f"{dockerfile_folder}/Dockerfile",
        )
        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {self.CONTAINER_NAME} {dockerfile_folder}",
            timeout=300,
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        results.append("Starting container...")
        ipv6_enabled = self._detect_server_ipv6()
        out, err, code = self.ssh.run_sudo_command(
            self._docker_run_cmd(self.CONTAINER_NAME, self.CONTAINER_NAME, port, ipv6_enabled)
        )
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.CONTAINER_NAME}")
        results.append("Waiting for container to start...")
        self._wait_container_running(self.CONTAINER_NAME)
        results.append("Container started")

        awg_params = None
        if obfuscation:
            awg_params = generate_transit_params(awg3=bool(awg3))

        try:
            results.append("Configuring transit endpoint...")
            self._configure_exit_container(port, net, awg_params)
            if awg_params:
                label = ("AmneziaWG 3.1" if is_awg31_params(awg_params)
                         else "AmneziaWG 2.0")
            else:
                label = "plain WireGuard"
            results.append(f"Transit endpoint configured ({label} obfuscation on)")
            results.append("Starting transit service...")
            self._upload_start_script(self.PROTOCOL, warp_ctx=warp_ctx)
            self._verify_interface_up(self.PROTOCOL)
            backend = self.transit_backend()
            results.append(f"Transit backend: {backend}")
            if awg_params and is_awg31_params(awg_params) and backend != 'kernel':
                raise RuntimeError(
                    f'transit0 came up on the {backend} backend; AWG 3.1 requires '
                    'the amneziawg kernel module')
            results.append("Transit service started")
        except RuntimeError:
            # Do not leave a running container with no working interface behind.
            self.remove_container(self.PROTOCOL)
            raise

        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")
        results.append("Applying host network tuning (BBR)...")
        self.setup_host_tuning()
        results.append("Host network tuning applied")

        return {
            'status': 'success',
            'protocol': self.PROTOCOL,
            'port': port,
            'subnet': str(net),
            'public_key': self._get_server_public_key(),
            'obfuscation': bool(awg_params),
            'protocol_version': self._protocol_version(awg_params),
            'backend': backend,
            'awg_params': awg_params or {},
            'log': results,
        }

    # ===================== STATUS / INFO =====================

    def get_server_status(self, protocol_type='exit'):
        info = super().get_server_status(self.PROTOCOL)
        if info.get('container_running') and 'error' not in info:
            info['peers_count'] = info.pop('clients_count', 0)
            info['subnet'] = self._read_config_key(self.PROTOCOL, 'Subnet')
            info['obfuscation'] = (self._read_config_key(self.PROTOCOL, 'Obfuscation') or 'off') == 'on'
            try:
                info['public_key'] = self._get_server_public_key()
            except RuntimeError as err:
                info['error'] = str(err)
        info['base_protocol'] = self.PROTOCOL
        info['instance'] = 1
        info['container_name'] = self.CONTAINER_NAME
        return info

    def get_info(self):
        """What an entry node needs to build its side of the link."""
        params = self._get_awg_params_from_config(self.PROTOCOL)
        port = params.pop('port', None)
        return {
            'public_key': self._get_server_public_key(),
            'port': port,
            'subnet': self._read_config_key(self.PROTOCOL, 'Subnet'),
            'obfuscation': (self._read_config_key(self.PROTOCOL, 'Obfuscation') or 'off') == 'on',
            'protocol_version': self._protocol_version(params),
            'mtu': transit_mtu(params),
            'awg_params': params,
        }

    # ===================== PEERS =====================

    def list_peers(self):
        """Peers from the peers table enriched with live handshake/transfer
        data; blocks present only in transit0.conf are reported as external."""
        table = self._get_clients_table(self.PROTOCOL)
        try:
            live = self._wg_show(self.PROTOCOL)
        except Exception:
            live = {}
        conf_peers = self._parse_peers_from_config(self.PROTOCOL)

        peers = []
        seen = set()
        for entry in table:
            public_key = entry.get('clientId', '')
            user_data = entry.get('userData', {}) or {}
            show = live.get(public_key, {})
            seen.add(public_key)
            peers.append({
                'peer_id': user_data.get('peerId', ''),
                'name': user_data.get('clientName', ''),
                'transit_ip': user_data.get('clientIp', ''),
                'public_key': public_key,
                'created_at': user_data.get('creationDate', ''),
                'latest_handshake': show.get('latestHandshake', ''),
                'rx': show.get('dataReceived', ''),
                'tx': show.get('dataSent', ''),
                'rx_bytes': show.get('dataReceivedBytes', 0),
                'tx_bytes': show.get('dataSentBytes', 0),
                'external': False,
            })
        for public_key, peer in conf_peers.items():
            if public_key in seen:
                continue
            ip = self._extract_ipv4(peer.get('allowedIps', ''))
            show = live.get(public_key, {})
            peers.append({
                'peer_id': '',
                'name': f'External ({ip})' if ip else 'External',
                'transit_ip': ip or '',
                'public_key': public_key,
                'created_at': '',
                'latest_handshake': show.get('latestHandshake', ''),
                'rx': show.get('dataReceived', ''),
                'tx': show.get('dataSent', ''),
                'rx_bytes': show.get('dataReceivedBytes', 0),
                'tx_bytes': show.get('dataSentBytes', 0),
                'external': True,
            })
        return peers

    def _find_peer(self, peer_id):
        for entry in self._get_clients_table(self.PROTOCOL):
            if (entry.get('userData') or {}).get('peerId') == peer_id:
                return entry
        return None

    def add_peer(self, peer_id, name, public_key):
        """Register (or re-register) an entry node as a peer.

        Upsert by `peer_id`: an existing peer keeps its transit address and is
        rewritten with the new key. Returns what the entry side needs for its
        exit0.conf - the transit address, a fresh per-peer PSK and the exit's
        own endpoint data.
        """
        peer_id = (peer_id or '').strip()
        public_key = (public_key or '').strip()
        if not peer_id or not public_key:
            raise ValueError('peer_id and public_key are required')

        keep_ip = None
        existing = self._find_peer(peer_id)
        if existing:
            keep_ip = (existing.get('userData') or {}).get('clientIp')
            self.remove_client(self.PROTOCOL, existing.get('clientId', ''))
        if public_key in self._parse_peers_from_config(self.PROTOCOL):
            # Same key already present under another (or no) peer id.
            self.remove_client(self.PROTOCOL, public_key)

        transit_ip = keep_ip or self._get_next_ip(self.PROTOCOL)
        psk = generate_psk()
        peer_section = (
            f"\n[Peer]\n"
            f"# peerId = {peer_id}\n"
            f"PublicKey = {public_key}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {transit_ip}/32\n"
        )
        self._insert_peer_sorted(self.PROTOCOL, peer_section)
        self._sync_server_config(self.PROTOCOL)
        try:
            table = self._get_clients_table(self.PROTOCOL)
            table.append({
                'clientId': public_key,
                'userData': {
                    'clientName': name or peer_id,
                    'peerId': peer_id,
                    'clientIp': transit_ip,
                    'creationDate': datetime.now().isoformat(),
                    'enabled': True,
                },
            })
            self._save_clients_table(self.PROTOCOL, table)
        except Exception:
            self.remove_client(self.PROTOCOL, public_key)
            raise

        info = self.get_info()
        info.update({'transit_ip': transit_ip, 'psk': psk})
        return info

    def remove_peer(self, public_key=None, peer_id=None):
        """Drop a peer by key or by peer id; True when something was removed."""
        if not public_key and peer_id:
            existing = self._find_peer(peer_id)
            public_key = existing.get('clientId', '') if existing else ''
        if not public_key:
            return False
        known = public_key in self._parse_peers_from_config(self.PROTOCOL) or any(
            e.get('clientId') == public_key for e in self._get_clients_table(self.PROTOCOL)
        )
        if not known:
            return False
        self.remove_client(self.PROTOCOL, public_key)
        return True
