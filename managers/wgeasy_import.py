"""
wg-easy / amnezia-wg-easy importer.

Fetches clients from a running wg-easy (v14 API, also used by the
w0rng/amnezia-wg-easy fork) or wg-easy v15 panel through the target
server's SSH connection (the wg-easy web UI is reached via 127.0.0.1 on
the server itself, so it never has to be exposed to the network), then
recreates the setup as a panel-managed WireGuard instance, preserving
server identity (private key), listen port, subnet and all client keys,
so existing client configs keep working unchanged.
"""

import json
import logging
import re
from datetime import datetime

from managers.wireguard_manager import WireGuardManager

logger = logging.getLogger(__name__)

DEFAULT_WEB_PORT = 51821


class WgEasyError(Exception):
    pass


def _sh(s):
    """Shell-escape a string for bash single quotes."""
    return "'" + str(s).replace("'", "'\\''") + "'"


class WgEasyImporter:
    """Fetches data from a wg-easy instance reachable from the target server."""

    def __init__(self, ssh_manager, web_port=DEFAULT_WEB_PORT):
        self.ssh = ssh_manager
        self.web_port = int(web_port)
        self.base = f"http://127.0.0.1:{self.web_port}"

    # ---------- low-level ----------

    def _curl(self, args, timeout=20):
        out, err, code = self.ssh.run_command(
            f"curl -sS -m {timeout} {args}", timeout=timeout + 10
        )
        return out, err, code

    def _cleanup_tmp(self):
        self.ssh.run_command("rm -f /tmp/_wgeasy_auth.json /tmp/_wgeasy_cookies")

    # ---------- detection ----------

    def detect_release(self):
        """Return wg-easy API release number (14, 15, ...) or raise."""
        out, err, code = self._curl(f"{self.base}/api/release")
        if code != 0:
            raise WgEasyError(f"wg-easy web UI is not reachable on port {self.web_port}: {err.strip() or 'connection failed'}")
        try:
            return int(out.strip())
        except ValueError:
            raise WgEasyError(f"Unexpected response from {self.base}/api/release: {out[:100]!r}")

    def find_containers(self):
        """List wg-easy family containers: [{name, image, running, udp_port}]."""
        out, _, _ = self.ssh.run_sudo_command(
            "docker ps -a --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}'"
        )
        containers = []
        for line in out.splitlines():
            parts = line.split('|')
            if len(parts) < 4:
                continue
            name, image, state, ports = parts[0], parts[1], parts[2], parts[3]
            if 'wg-easy' not in image.lower():
                continue
            udp_port = None
            m = re.search(r':(\d+)->(\d+)/udp', ports)
            if m:
                udp_port = m.group(1)
            containers.append({
                'name': name,
                'image': image,
                'running': state.lower() == 'running',
                'udp_port': udp_port,
            })
        return containers

    # ---------- v14 (and w0rng fork) ----------

    def _v14_login(self, password):
        self.ssh.upload_file(json.dumps({"password": password}), "/tmp/_wgeasy_auth.json")
        self._curl(f"-c /tmp/_wgeasy_cookies -H 'Content-Type: application/json' "
                   f"-d @/tmp/_wgeasy_auth.json {self.base}/api/session")
        out, _, _ = self._curl(f"-b /tmp/_wgeasy_cookies {self.base}/api/session")
        try:
            sess = json.loads(out)
        except json.JSONDecodeError:
            self._cleanup_tmp()
            raise WgEasyError(f"Unexpected session response: {out[:100]!r}")
        if not sess.get('authenticated'):
            self._cleanup_tmp()
            raise WgEasyError("Authentication failed: wrong password")

    def _v14_backup(self):
        out, err, code = self._curl(f"-b /tmp/_wgeasy_cookies {self.base}/api/wireguard/backup")
        self._cleanup_tmp()
        if code != 0:
            raise WgEasyError(f"Failed to download backup: {err.strip()}")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise WgEasyError("Backup is not valid JSON — unsupported wg-easy version?")
        if not isinstance(data, dict) or 'clients' not in data or 'server' not in data:
            raise WgEasyError("Backup has unexpected structure (no server/clients)")
        return data

    # ---------- v15 ----------

    def _v15_backup(self, username, password):
        auth = f"-u {_sh(username + ':' + password)}"
        out, err, code = self._curl(f"{auth} {self.base}/api/client")
        if code != 0:
            raise WgEasyError(f"Failed to list clients: {err.strip()}")
        try:
            clients = json.loads(out)
        except json.JSONDecodeError:
            raise WgEasyError("Authentication failed or unsupported v15 API response")
        if not isinstance(clients, list):
            raise WgEasyError("Authentication failed: wrong username/password")

        result_clients = {}
        server_pub = ''
        server_addr_guess = ''
        for c in clients:
            cid = c.get('id')
            if not cid:
                continue
            cfg_out, _, cfg_code = self._curl(f"{auth} {self.base}/api/client/{cid}/configuration")
            if cfg_code != 0 or 'PrivateKey' not in cfg_out:
                continue
            priv = _conf_value(cfg_out, 'PrivateKey')
            psk = _conf_value(cfg_out, 'PresharedKey')
            addr = _conf_value(cfg_out, 'Address').split('/')[0].strip()
            spub = _conf_value(cfg_out, 'PublicKey', section='Peer')
            if spub:
                server_pub = spub
            if addr and not server_addr_guess:
                parts = addr.split('.')
                server_addr_guess = '.'.join(parts[:3] + ['1']) + '/24'
            result_clients[str(cid)] = {
                'name': c.get('name') or str(cid),
                'address': addr,
                'enabled': bool(c.get('enabled', True)),
                'privateKey': priv,
                'publicKey': '',  # derived below
                'preSharedKey': psk,
            }
        # v15 client config has no client public key; derive it from private key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from base64 import b64encode, b64decode
        for c in result_clients.values():
            try:
                pk = X25519PrivateKey.from_private_bytes(b64decode(c['privateKey']))
                c['publicKey'] = b64encode(pk.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
            except Exception:
                raise WgEasyError(f"Cannot derive public key for client {c.get('name')}")
        return {
            'server': {
                'privateKey': '',  # v15 API does not expose the server private key
                'publicKey': server_pub,
                'address': server_addr_guess,
            },
            'clients': result_clients,
        }

    def read_source_config(self, container_name):
        """Read the source wg0.conf from the wg-easy container."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {_sh(container_name)} cat /etc/wireguard/wg0.conf"
        )
        if code != 0 or '[Interface]' not in out:
            raise WgEasyError(f"Cannot read wg0.conf from container {container_name}: {err.strip()}")
        return out

    def detect_source(self):
        """Locate the source wg-easy container. Returns
        (container_name, listen_port, config_text, obfuscation_dict)."""
        containers = self.find_containers()
        for prefer_running in (True, False):
            for c in containers:
                if prefer_running and not c['running']:
                    continue
                if not c['udp_port']:
                    continue
                try:
                    conf = self.read_source_config(c['name'])
                except WgEasyError:
                    continue
                return c['name'], c['udp_port'], conf, parse_obfuscation(conf)
        raise WgEasyError("No wg-easy / amnezia-wg-easy container found on this server")

    # ---------- public ----------

    def fetch_backup(self, password, username='admin'):
        """Return normalized backup dict {server, clients} from any supported release."""
        release = self.detect_release()
        if release >= 15:
            backup = self._v15_backup(username, password)
        else:
            self._v14_login(password)
            backup = self._v14_backup()
        backup['_release'] = release
        return backup


def _conf_value(config_text, key, section=None):
    """Extract `key = value` from a wg-quick style config text."""
    current = None
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = line.strip('[]')
            continue
        if section and current != section:
            continue
        if line.startswith(key) and '=' in line:
            return line.split('=', 1)[1].strip()
    return ''


OBFUSCATION_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
                    'H1', 'H2', 'H3', 'H4')


def parse_obfuscation(config_text):
    """Extract AmneziaWG obfuscation params (Jc/../H4) from the [Interface]
    section of a source wg0.conf. Returns an ordered dict, empty for plain
    WireGuard sources."""
    result = {}
    in_interface = False
    for line in config_text.splitlines():
        s = line.strip()
        if s.startswith('['):
            in_interface = s.strip('[]').lower() == 'interface'
            continue
        if not in_interface or '=' not in s:
            continue
        key, _, value = s.partition('=')
        key, value = key.strip(), value.strip()
        if key in OBFUSCATION_KEYS and value:
            result[key] = value
    return result


def normalize_clients(backup):
    """Return a list of clients sorted by IPv4 address.

    Each item: {id, name, address, enabled, privateKey, publicKey, preSharedKey}
    """
    clients = []
    for cid, c in (backup.get('clients') or {}).items():
        addr = str(c.get('address') or '').split('/')[0].strip()
        clients.append({
            'id': str(cid),
            'name': c.get('name') or cid,
            'address': addr,
            'enabled': bool(c.get('enabled', True)),
            'privateKey': c.get('privateKey') or '',
            'publicKey': c.get('publicKey') or '',
            'preSharedKey': c.get('preSharedKey') or '',
        })

    def key(item):
        m = re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)$', item['address'])
        return tuple(int(m.group(i)) for i in range(1, 5)) if m else (255, 255, 255, 255)

    clients.sort(key=key)
    return clients


def build_server_config(server_info, clients, listen_port, obfuscation=None):
    """Build wg0.conf/awg0.conf content for the imported instance (enabled
    clients only). `obfuscation` carries Jc/../H4 lines for AWG targets."""
    address = server_info.get('address') or ''
    if '/' not in address:
        address += '/24'
    lines = [
        '[Interface]',
        f"PrivateKey = {server_info.get('privateKey', '')}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    for key in OBFUSCATION_KEYS:
        if obfuscation and obfuscation.get(key):
            lines.append(f"{key} = {obfuscation[key]}")
    lines.append('')
    for c in clients:
        if not c['enabled']:
            continue
        lines.append('[Peer]')
        lines.append(f"# {c['name']}")
        lines.append(f"PublicKey = {c['publicKey']}")
        if c['preSharedKey']:
            lines.append(f"PresharedKey = {c['preSharedKey']}")
        lines.append(f"AllowedIPs = {c['address']}/32")
        lines.append('')
    return '\n'.join(lines)


def build_clients_table(clients):
    """Build panel clientsTable entries for all imported clients."""
    table = []
    now = datetime.now().isoformat()
    for c in clients:
        table.append({
            'clientId': c['publicKey'],
            'userData': {
                'clientName': c['name'],
                'creationDate': now,
                'clientPrivateKey': c['privateKey'],
                'clientIp': c['address'],
                'psk': c['preSharedKey'],
                'enabled': c['enabled'],
                'importedFrom': 'wg-easy',
            },
        })
    return table


def run_import(ssh, backup, client_ids=None, target='auto'):
    """Replace wg-easy on this server with a panel-managed instance.

    target='auto': AWG 2.0 when the source config has obfuscation params
    (w0rng/amnezia-wg-easy), plain WireGuard otherwise.

    Steps: stop the old wg-easy container -> install the panel protocol on
    the same port -> overwrite identity (server key, subnet, obfuscation,
    peers, clientsTable) -> restart. Returns a summary dict.
    """
    importer = WgEasyImporter(ssh)
    clients = normalize_clients(backup)
    if client_ids:
        wanted = set(str(i) for i in client_ids)
        clients = [c for c in clients if c['id'] in wanted]
    if not clients:
        raise WgEasyError("No clients selected for import")

    server_info = backup.get('server') or {}
    if not server_info.get('privateKey'):
        raise WgEasyError(
            "Server private key is not available (wg-easy v15 API limitation) — "
            "transparent import without config reissue is impossible")

    address = server_info.get('address') or '10.8.0.1/24'
    subnet_ip = address.split('/')[0]
    subnet_cidr = address.split('/')[1] if '/' in address else '24'

    # Detect source container, listen port and obfuscation from its config
    source_container, listen_port, source_conf, obfuscation = importer.detect_source()
    if target == 'auto':
        target = 'awg2' if obfuscation else 'wireguard'
    if target == 'awg2' and not obfuscation:
        raise WgEasyError("Target AWG 2.0 requested, but the source has no "
                          "obfuscation params — plain WireGuard target fits better")

    # Keep a server-side backup copy before touching anything
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_path = f"/root/wg-easy-backup-{stamp}.json"
    ssh.upload_file(json.dumps(backup, indent=2, ensure_ascii=False), "/tmp/_wgeasy_backup_copy.json")
    ssh.run_sudo_command(f"cp /tmp/_wgeasy_backup_copy.json {backup_path}")
    ssh.run_command("rm -f /tmp/_wgeasy_backup_copy.json")

    # Stop the old wg-easy container (frees the UDP port)
    if source_container:
        ssh.run_sudo_command(f"docker stop {_sh(source_container)}")

    config = build_server_config(server_info, clients, listen_port,
                                 obfuscation if target == 'awg2' else None)
    table = build_clients_table(clients)

    try:
        if target == 'awg2':
            from managers.awg_manager import AWGManager
            mgr = AWGManager(ssh)
            mgr.install_protocol('awg2', port=int(listen_port))
            container = mgr._container_name('awg2')
            config_path = mgr._config_path('awg2')
            key_dir = '/opt/amnezia/awg'
            clients_table_path = mgr._clients_table_path()
        else:
            mgr = WireGuardManager(ssh)
            mgr.install_protocol(port=int(listen_port))
            container = mgr.CONTAINER_NAME
            config_path = mgr.CONFIG_PATH
            key_dir = mgr.KEY_DIR
            clients_table_path = mgr.CLIENTS_TABLE_PATH
            config = WireGuardManager._sanitize_server_config(config)

        # Overwrite server identity and peers
        ssh.upload_file(config, "/tmp/_wgeasy_wg0.conf")
        ssh.run_sudo_command(f"docker cp /tmp/_wgeasy_wg0.conf {container}:{config_path}")
        ssh.run_command("rm -f /tmp/_wgeasy_wg0.conf")

        ssh.upload_file(server_info['privateKey'] + '\n', "/tmp/_wgeasy_srvkey")
        ssh.run_sudo_command(
            f"docker cp /tmp/_wgeasy_srvkey {container}:{key_dir}/wireguard_server_private_key.key")
        if server_info.get('publicKey'):
            ssh.upload_file(server_info['publicKey'] + '\n', "/tmp/_wgeasy_srvpub")
            ssh.run_sudo_command(
                f"docker cp /tmp/_wgeasy_srvpub {container}:{key_dir}/wireguard_server_public_key.key")
        ssh.run_command("rm -f /tmp/_wgeasy_srvkey /tmp/_wgeasy_srvpub")

        # Clients table (all clients incl. disabled)
        ssh.upload_file(json.dumps(table, indent=2), "/tmp/_wgeasy_clients.json")
        ssh.run_sudo_command(
            f"docker cp /tmp/_wgeasy_clients.json {container}:{clients_table_path}")
        ssh.run_command("rm -f /tmp/_wgeasy_clients.json")

        if target == 'awg2':
            # The AWG start script reads the subnet from the config at
            # runtime, so a plain restart applies the imported identity.
            ssh.run_sudo_command(f"docker restart {container}")
            import time
            time.sleep(5)
        else:
            # Rewrite the start script so NAT rules match the imported subnet
            mgr._upload_start_script(int(listen_port), subnet_ip=subnet_ip, subnet_cidr=subnet_cidr)
    except Exception:
        # Best effort: bring the old container back up on failure
        if source_container:
            ssh.run_sudo_command(f"docker start {_sh(source_container)}")
        raise

    return {
        'status': 'success',
        'target': target,
        'obfuscation': bool(obfuscation),
        'imported': len([c for c in clients if c['enabled']]),
        'disabled': len([c for c in clients if not c['enabled']]),
        'port': int(listen_port),
        'subnet': f"{subnet_ip}/{subnet_cidr}",
        'stopped_container': source_container,
        'backup_path': backup_path,
    }
