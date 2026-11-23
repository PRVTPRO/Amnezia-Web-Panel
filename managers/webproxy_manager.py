"""Telegram WEB proxy (tproxy-server) manager.

The WEB proxy transport wraps ordinary MTProxy traffic in real HTTPS/WebSocket
requests to an operator-owned hostname, so an active probe sees a genuine
website with a genuine certificate rather than a fake-TLS imitation.

Layout deployed on the server (all in one host network namespace, because the
relay validates that its backend is a numeric loopback address):

    Internet 80/443 -> Caddy -> 127.0.0.1:8080 relay -> 127.0.0.1:2398 MTProxy

Client model: one profile per connection. The link secret IS the MTProxy
secret (PROTOCOL.md), so every client exists twice -- as a profile for the
relay and as a user on the MTProxy behind it. `clients.json` is the single
source of truth the panel owns; profiles.json and the backend's [access.users]
are rendered from it. The relay has no admin API and no hot reload, so any
membership change restarts it; the MTProxy backend only takes a SIGHUP.
"""

import base64
import binascii
import json
import logging
import os
import re
import secrets
import socket
import uuid
from datetime import datetime, timezone

from .docker_utils import compose_exec, compose_up, ensure_docker_compose
from .naming import transliterate
from .ssh_manager import SSHManager
from .webproxy_site import generate_site

logger = logging.getLogger(__name__)

CARRIER_MODES = ('https', 'https-lanes', 'websocket', 'websocket-lanes')

# Who owns what on the server. `upload_file_sudo` keeps the SSH user as owner
# (SFTP to /tmp, then `sudo mv`), so every uploaded file gets an explicit chown.
# The relay runs as root but with all capabilities dropped -- no CAP_DAC_OVERRIDE,
# so it can only read files it actually owns. ghcr.io/telemt/telemt runs as
# nonroot:nonroot (uid/gid 65532).
RELAY_OWNER = '0:0'
BACKEND_OWNER = '65532:65532'


class WebProxyManager:
    CONTAINER_NAME = "amnezia-webproxy"          # the relay; primary for status
    CADDY_CONTAINER = "amnezia-webproxy-caddy"
    BACKEND_CONTAINER = "amnezia-webproxy-mtp"
    REMOTE_DIR = "/opt/amnezia/webproxy"
    ADMIN_URL = "http://127.0.0.1:8081"
    BACKEND_ADDR = "127.0.0.1:2398"
    LOCAL_ASSETS = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'protocol_webproxy')

    def __init__(self, ssh_manager: SSHManager):
        self.ssh = ssh_manager

    # ------------------------------------------------------------------
    # validation (mirrors internal/config/config.go so we fail in the panel
    # rather than crash-looping the relay on the server)
    # ------------------------------------------------------------------

    @staticmethod
    def validate_hostname(host):
        host = (host or '').strip().lower()
        if not host or len(host) > 253 or host.endswith('.') or re.search(r'[:/@?#\[\]]', host):
            raise ValueError("Hostname must be a bare DNS name: no scheme, port, path or trailing dot")
        if '.' not in host or re.fullmatch(r'[0-9.]+', host):
            raise ValueError("An IP address or single-label name cannot be used; a real domain is required")
        for label in host.split('.'):
            if not label or len(label) > 63 or label[0] == '-' or label[-1] == '-':
                raise ValueError(f"Invalid DNS label in hostname: '{label}'")
            if not re.fullmatch(r'[a-z0-9-]+', label):
                raise ValueError("Hostname must be lowercase ASCII (use the IDNA A-label form for IDN)")
        return host

    @staticmethod
    def validate_secret(value):
        """Accept what DecodeSecret accepts: 16 bytes, optionally dd-prefixed."""
        value = (value or '').strip()
        decoded = None
        if len(value) in (32, 34):
            try:
                decoded = binascii.unhexlify(value)
            except (binascii.Error, ValueError):
                decoded = None
        if decoded is None:
            for pad in ('', '=' * (-len(value) % 4)):
                try:
                    decoded = base64.urlsafe_b64decode(value + pad)
                    break
                except (binascii.Error, ValueError):
                    decoded = None
        if decoded is None or len(decoded) not in (16, 17):
            raise ValueError("Secret must decode to 16 bytes (32 hex chars), optionally dd-prefixed")
        if len(decoded) == 17 and decoded[0] != 0xdd:
            raise ValueError("A 17-byte secret must use the dd prefix")
        return decoded.hex()

    @staticmethod
    def validate_carrier_mode(mode):
        mode = (mode or 'https').strip()
        if mode not in CARRIER_MODES:
            raise ValueError(f"carrier_mode must be one of: {', '.join(CARRIER_MODES)}")
        return mode

    @staticmethod
    def _sanitize_name(name):
        """Coerce a display name into a key usable on *both* sides.

        The relay allows any 1-64 character profile name, but the same name
        keys the MTProxy backend's [access.users], where TOML bare keys only
        allow [A-Za-z0-9_-]. Restricting to that subset here keeps one name
        for one client instead of two that can drift apart -- and
        transliterating first means "Иванов И.И." stays readable rather than
        collapsing to underscores and colliding with the next Russian name.
        """
        cleaned = transliterate((name or '').strip()).replace(' ', '_')
        cleaned = re.sub(r'[^A-Za-z0-9_-]+', '_', cleaned).strip('_')[:64].strip('_')
        return cleaned or ("user_" + uuid.uuid4().hex[:8])

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    # Every docker call goes through sudo on purpose: the panel may log in as an
    # ordinary user that is not in the `docker` group, and a plain `docker ps`
    # then fails with "permission denied ... /var/run/docker.sock" -- which
    # reads as "protocol not installed" and makes a reinstall re-run the
    # port pre-flight against our own Caddy.
    def check_docker_installed(self):
        out, _, _ = self.ssh.run_sudo_command("docker --version 2>/dev/null")
        return bool(out.strip())

    def check_protocol_installed(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'")
        return out.strip() == self.CONTAINER_NAME

    def _container_running(self, name):
        out, _, _ = self.ssh.run_sudo_command(f"docker inspect -f '{{{{.State.Running}}}}' {name} 2>/dev/null")
        return out.strip().lower() == 'true'

    def get_server_status(self, protocol_type='webproxy'):
        exists = self.check_protocol_installed()
        status = {
            'container_exists': exists,
            'container_running': self._container_running(self.CONTAINER_NAME),
        }
        if not exists:
            return status

        status['caddy_running'] = self._container_running(self.CADDY_CONTAINER)
        status['backend_running'] = self._container_running(self.BACKEND_CONTAINER)
        # The public surface is always 443; the WEB proxy type fixes it and the
        # client accepts no port at all.
        status['port'] = '443'

        config = self._read_json(f"{self.REMOTE_DIR}/config.json") or {}
        hostname = config.get('public_hostname', '')
        status['hostname'] = hostname
        status['awg_params'] = {
            'hostname': hostname,
            'site_mode': 'upstream' if config.get('public_upstream') else 'dir',
            'max_profiles': (config.get('limits') or {}).get('max_profiles'),
        }

        clients = self._load_clients()
        status['clients_count'] = len([c for c in clients if c.get('enabled', True)])
        status['metrics'] = self._get_metrics()
        return status

    def _get_metrics(self):
        """Relay metrics are process-wide only -- there is no per-profile
        breakdown in /metrics, so the panel can show totals but not per-user
        traffic the way telemt's API allows."""
        out, _, code = self.ssh.run_sudo_command(
            f"curl -fsS --max-time 5 {self.ADMIN_URL}/metrics 2>/dev/null")
        if code != 0 or not out.strip():
            return {}
        metrics = {}
        for line in out.strip().split('\n'):
            parts = line.split()
            if len(parts) == 2 and parts[0].startswith('tproxy_'):
                try:
                    metrics[parts[0][len('tproxy_'):]] = int(parts[1])
                except ValueError:
                    continue
        return metrics

    # ------------------------------------------------------------------
    # remote file helpers
    # ------------------------------------------------------------------

    def _read_remote(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {path} 2>/dev/null")
        return out if code == 0 else ""

    def _read_json(self, path):
        raw = self._read_remote(path)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Malformed JSON at %s on %s", path, getattr(self.ssh, 'host', '?'))
            return None

    def _upload_secret_file(self, content, path, owner=RELAY_OWNER):
        """Upload, then tighten perms: loadProfiles refuses a profiles file
        that is readable or writable by group or others.

        Ownership is always set explicitly, because `upload_file_sudo` writes
        the file over SFTP as the *SSH user* and then `sudo mv`s it, which
        keeps that user as the owner. On a panel that logs in as a non-root
        sudo user the result is a 0600 file owned by uid 1000 -- and neither
        container can read it: the relay runs as root but with `cap_drop: ALL`
        it has no CAP_DAC_OVERRIDE, and the MTProxy backend runs as nonroot.
        """
        self.ssh.upload_file_sudo(content, path)
        self.ssh.run_sudo_command(f"chown {owner} {path}")
        self.ssh.run_sudo_command(f"chmod 600 {path}")

    def _upload_public_file(self, content, path):
        """World-readable config the containers must read; same ownership
        caveat as `_upload_secret_file`, so set the owner explicitly."""
        self.ssh.upload_file_sudo(content, path)
        self.ssh.run_sudo_command(f"chown {RELAY_OWNER} {path}")

    def _ensure_token_key(self):
        """Provision the relay's 32-byte token-signing key, once per install.

        Session tokens carry an HMAC tag under this key, which is how the relay
        tells its own expired token from random probe input. Regenerating it
        loses that provenance, so we only create the file when it is absent.
        The relay refuses to start unless it is exactly 32 bytes and unreadable
        by group or others.
        """
        path = f"{self.REMOTE_DIR}/token.key"
        script = f"""set -e
umask 077
# A previous compose run with no key here leaves an empty directory behind.
if [ -e {path} ] && [ ! -f {path} ]; then
    rm -rf {path}
fi
if [ ! -s {path} ] || [ $(wc -c < {path}) -ne 32 ]; then
    head -c 32 /dev/urandom > {path}
fi
chmod 600 {path}
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            raise RuntimeError(f"Failed to provision the relay token key: {(err or out)[-500:]}")

    def _load_clients(self):
        data = self._read_json(f"{self.REMOTE_DIR}/clients.json") or {}
        clients = data.get('clients')
        return clients if isinstance(clients, list) else []

    # ------------------------------------------------------------------
    # rendering: clients.json -> profiles.json + backend [access.users]
    # ------------------------------------------------------------------

    def _render_profiles(self, clients):
        enabled = [c for c in clients if c.get('enabled', True)]
        if not enabled:
            # The relay refuses to start on an empty profiles file, exactly as
            # telemt refuses an empty [access.users]. Keep an unusable
            # placeholder so the container stays up until a real client exists.
            enabled = [{
                'name': '_webproxy_init',
                'secret': secrets.token_hex(16),
                'carrier_mode': 'https',
            }]
        profiles = [{
            'name': c['name'],
            'secret': c['secret'],
            'backend': self.BACKEND_ADDR,
            'carrier_mode': c.get('carrier_mode') or 'https',
        } for c in enabled]
        return json.dumps({'profiles': profiles}, indent=2) + '\n'

    def _render_backend_users(self, clients, backend_toml):
        """Rewrite the [access.users] table of the backend MTProxy config.

        Names there are TOML bare keys, so they get a stricter sanitize than
        relay profile names; we key on the same client name to keep the two
        sides aligned."""
        enabled = [c for c in clients if c.get('enabled', True)]
        lines, seen = [], set()
        for c in enabled:
            key = self._sanitize_name(c['name'])
            while key in seen:
                key = f"{key[:57]}_{uuid.uuid4().hex[:6]}"
            seen.add(key)
            lines.append(f'{key} = "{c["secret"]}"')
        if not lines:
            lines.append(f'_webproxy_init = "{secrets.token_hex(16)}"')
        head = re.split(r'^\[access\.users\]\s*$', backend_toml, maxsplit=1, flags=re.MULTILINE)[0]
        return head.rstrip('\n') + '\n\n[access.users]\n' + '\n'.join(lines) + '\n'

    def _apply_clients(self, clients, restart=True):
        """Persist clients and push both rendered configs to the server."""
        self._upload_secret_file(
            json.dumps({'clients': clients}, indent=2) + '\n',
            f"{self.REMOTE_DIR}/clients.json")
        self._upload_secret_file(
            self._render_profiles(clients),
            f"{self.REMOTE_DIR}/profiles.json")

        backend_path = f"{self.REMOTE_DIR}/backend/backend.toml"
        backend_toml = self._read_remote(backend_path)
        if backend_toml.strip():
            self._upload_secret_file(self._render_backend_users(clients, backend_toml), backend_path,
                                     owner=BACKEND_OWNER)

        if restart:
            self.restart()

    def restart(self):
        """The relay reads profiles once at start-up: no signal reloads them,
        so a membership change costs every live session a reconnect. The
        MTProxy backend keeps its sessions on a SIGHUP."""
        # separate calls: in `a || b` under sudo, b would run without root
        _, _, code = self.ssh.run_sudo_command(f"docker kill -s HUP {self.BACKEND_CONTAINER}")
        if code != 0:
            self.ssh.run_sudo_command(f"docker restart {self.BACKEND_CONTAINER}")
        self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}", timeout=120)

    # ------------------------------------------------------------------
    # install / uninstall
    # ------------------------------------------------------------------

    def _resolve_a_records(self, hostname):
        """Resolve the hostname's A records from the panel, not from the target.

        `getent` on the server consults /etc/hosts first, and Ubuntu keeps a
        `127.0.1.1 <fqdn>` line for the machine's own name. On a server whose
        hostname *is* the proxy domain that answers loopback, and a perfectly
        good A record looks like a mismatch. Falls back to the server's own
        resolver (minus loopback) if the panel itself cannot resolve.
        """
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            addresses = sorted({i[4][0] for i in infos})
        except socket.gaierror:
            addresses = []
        if not addresses:
            out, _, _ = self.ssh.run_command(
                f"getent ahostsv4 {hostname} 2>/dev/null | awk '{{print $1}}' | sort -u")
            addresses = sorted(set(out.split()))
        return [a for a in addresses if not a.startswith('127.')]

    def _preflight(self, hostname, skip_ports=False):
        """Fail in the panel rather than leave Caddy looping on a doomed ACME
        order or the stack fighting another service for 443."""
        problems = []

        addresses = self._resolve_a_records(hostname)
        public_ip, _, _ = self.ssh.run_command(
            "curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true")
        public_ip = public_ip.strip()
        expected = {a for a in (public_ip, self.ssh.host) if a}
        if not addresses:
            problems.append(f"{hostname} does not resolve; add an A record pointing at this server first")
        elif expected and not (set(addresses) & expected):
            problems.append(
                f"{hostname} resolves to {', '.join(addresses)} but this server is "
                f"{' / '.join(sorted(expected))}; ACME validation would fail")

        # Skipped on reinstall: our own Caddy is holding 80/443, and because the
        # stack runs in the host netns it publishes no ports, so there is no way
        # to tell "ours" from "someone else's" by the socket alone.
        for port in ([] if skip_ports else (80, 443)):
            busy, _, _ = self.ssh.run_command(
                f"ss -ltnH 'sport = :{port}' 2>/dev/null | head -1")
            if busy.strip():
                owner, _, _ = self.ssh.run_sudo_command(
                    f"docker ps --filter publish={port} --format '{{{{.Names}}}}' 2>/dev/null")
                owner = owner.strip()
                detail = f" (in use by container {owner})" if owner else ""
                problems.append(
                    f"TCP {port} is already in use{detail}; the WEB proxy needs both 80 and 443 "
                    f"on this host, and the client cannot be pointed at any other port")

        if problems:
            raise ValueError("Pre-flight checks failed:\n- " + "\n- ".join(problems))

    def install_protocol(self, protocol_type='webproxy', hostname='', acme_email='',
                         carrier_mode='https', site_mode='generated', site_name='',
                         site_tagline='', site_upstream='', max_profiles=128,
                         max_sessions=128, skip_preflight=False):
        hostname = self.validate_hostname(hostname)
        carrier_mode = self.validate_carrier_mode(carrier_mode)
        acme_email = (acme_email or '').strip()
        if '@' not in acme_email:
            raise ValueError("A contact e-mail is required for the Let's Encrypt account")
        if site_mode not in ('generated', 'upstream', 'keep'):
            raise ValueError("site_mode must be 'generated', 'upstream' or 'keep'")
        if site_mode == 'upstream' and not re.fullmatch(r'http://127\.\d+\.\d+\.\d+:\d+', site_upstream or ''):
            raise ValueError("site_upstream must be a numeric loopback URL, e.g. http://127.0.0.1:3000")

        results = []
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.ssh.run_sudo_command("curl -fsSL https://get.docker.com | sh", timeout=300)

        reinstall = self.check_protocol_installed()
        if not skip_preflight:
            results.append("Running pre-flight checks...")
            self._preflight(hostname, skip_ports=reinstall)

        results.append("Ensuring docker compose plugin...")
        ensure_docker_compose(self.ssh)

        existing_clients = self._load_clients() if reinstall else []
        if reinstall:
            results.append("Removing previous containers...")
            self._compose_down()

        results.append("Uploading WEB proxy files...")
        self.ssh.run_sudo_command(f"mkdir -p {self.REMOTE_DIR}/backend {self.REMOTE_DIR}/site")
        self.ssh.run_sudo_command(f"chmod 755 {self.REMOTE_DIR}")
        # The backend mounts this directory as its working dir and caches
        # proxy-secret and its state files there; as root it only gets
        # "Permission denied (non-fatal)" and re-downloads on every start.
        self.ssh.run_sudo_command(f"chown {BACKEND_OWNER} {self.REMOTE_DIR}/backend")

        for name in ('Dockerfile', 'docker-compose.yml', 'Caddyfile'):
            with open(os.path.join(self.LOCAL_ASSETS, name), encoding='utf-8') as fh:
                self._upload_public_file(fh.read(), f"{self.REMOTE_DIR}/{name}")

        with open(os.path.join(self.LOCAL_ASSETS, 'config.json'), encoding='utf-8') as fh:
            config = json.load(fh)
        config['public_hostname'] = hostname
        config['limits']['max_profiles'] = max(1, int(max_profiles or 128))
        config['limits']['max_sessions_global'] = max(1, int(max_sessions or 128))
        if site_mode == 'upstream':
            config['public_upstream'] = site_upstream
            config.pop('public_dir', None)
        else:
            config['public_dir'] = '/srv/tproxy-site'
            config.pop('public_upstream', None)
        self._upload_public_file(json.dumps(config, indent=2) + '\n', f"{self.REMOTE_DIR}/config.json")

        self._upload_public_file(
            f"TPROXY_HOSTNAME={hostname}\nACME_EMAIL={acme_email}\n", f"{self.REMOTE_DIR}/.env")

        # Must exist before compose runs, or Docker would create a directory
        # at the bind-mount path.
        self._ensure_token_key()

        with open(os.path.join(self.LOCAL_ASSETS, 'backend', 'backend.toml'), encoding='utf-8') as fh:
            backend_toml = fh.read()
        self._upload_secret_file(backend_toml, f"{self.REMOTE_DIR}/backend/backend.toml",
                                 owner=BACKEND_OWNER)

        if site_mode == 'generated':
            results.append("Generating cover site...")
            site = generate_site(site_name or hostname.split('.')[0], site_tagline,
                                 seed=secrets.randbits(64))
            for rel, content in site.items():
                self._upload_public_file(content, f"{self.REMOTE_DIR}/site/{rel}")

        # Carry existing clients across a reinstall; re-render on the new files.
        for client in existing_clients:
            client['carrier_mode'] = client.get('carrier_mode') or carrier_mode
        self._apply_clients(existing_clients, restart=False)

        results.append("Building relay...")
        out, err, code = compose_exec(self.ssh, self.REMOTE_DIR, "build webproxy-relay", timeout=1200)
        if code != 0:
            raise RuntimeError(f"docker compose build failed: {(err or out)[-2000:]}")

        # `-check` validates config, profiles, token key and the site tree, then
        # exits without binding anything. Cheaper than debugging a crash loop.
        results.append("Validating relay configuration...")
        out, err, code = compose_exec(
            self.ssh, self.REMOTE_DIR,
            "run --rm --no-deps webproxy-relay -config /etc/tproxy/config.json -check",
            timeout=120)
        if code != 0:
            raise RuntimeError(f"Relay rejected the configuration: {(err or out)[-2000:]}")

        results.append("Starting containers...")
        out, err, code = compose_up(self.ssh, self.REMOTE_DIR, timeout=1200)
        if code != 0:
            raise RuntimeError(f"docker compose up failed: {(err or out)[-2000:]}")

        return {
            "status": "success",
            "host": hostname,
            "port": "443",
            "log": results,
        }

    def _compose_down(self):
        self.ssh.run_sudo_command(
            f"sh -c 'cd {self.REMOTE_DIR} && (docker compose down || docker-compose down)'", timeout=180)
        for name in (self.CADDY_CONTAINER, self.CONTAINER_NAME, self.BACKEND_CONTAINER):
            self.ssh.run_sudo_command(f"docker rm -f {name} 2>/dev/null")

    def remove_container(self, protocol_type=None):
        self._compose_down()
        self.ssh.run_sudo_command(f"rm -rf {self.REMOTE_DIR}")

    # ------------------------------------------------------------------
    # raw config editing
    # ------------------------------------------------------------------

    def _get_server_config(self):
        return self._read_remote(f"{self.REMOTE_DIR}/config.json")

    def save_server_config(self, protocol_type, config_content):
        try:
            config = json.loads(config_content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Refusing to write an invalid relay config: {exc}") from exc
        hostname = self.validate_hostname(config.get('public_hostname', ''))
        config['public_hostname'] = hostname
        if bool(config.get('public_dir')) == bool(config.get('public_upstream')):
            raise ValueError("Exactly one of public_dir or public_upstream must be set")

        previous = (self._read_json(f"{self.REMOTE_DIR}/config.json") or {}).get('public_hostname', '')
        self._upload_public_file(json.dumps(config, indent=2) + '\n', f"{self.REMOTE_DIR}/config.json")
        if hostname != previous:
            # Caddy takes the domain from .env, not from config.json. Leaving it
            # behind means the relay expects one hostname while Caddy still holds
            # a certificate for the other, and every client sees a TLS mismatch.
            self._set_env_hostname(hostname)
            # Recreate, not restart: env_file values are injected when the
            # container is created, so a plain restart keeps the old domain.
            compose_exec(self.ssh, self.REMOTE_DIR,
                         "up -d --force-recreate webproxy-caddy", timeout=180)
        self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}", timeout=120)

    def _set_env_hostname(self, hostname):
        """Rewrite TPROXY_HOSTNAME in .env, keeping the ACME e-mail as it is."""
        acme_email = ''
        for line in self._read_remote(f"{self.REMOTE_DIR}/.env").splitlines():
            if line.startswith('ACME_EMAIL='):
                acme_email = line.split('=', 1)[1].strip()
        self._upload_public_file(
            f"TPROXY_HOSTNAME={hostname}\nACME_EMAIL={acme_email}\n", f"{self.REMOTE_DIR}/.env")

    # ------------------------------------------------------------------
    # clients
    # ------------------------------------------------------------------

    def get_clients(self, protocol_type='webproxy'):
        clients = []
        for c in self._load_clients():
            created = c.get('created', '')
            clients.append({
                'clientId': c['name'],
                'clientName': c['name'],
                'enabled': c.get('enabled', True),
                'creationDate': created,
                # Nested exactly like the other managers: the UI stores this
                # dict as `connectionsStore[clientId]` and reads the name,
                # the secret and the carrier mode straight out of it.
                'userData': {
                    'clientName': c['name'],
                    'token': c['secret'],
                    'carrier_mode': c.get('carrier_mode') or 'https',
                    'creationDate': created,
                },
            })
        return clients

    def add_client(self, protocol_type, name, host='', port='', **kwargs):
        clients = self._load_clients()
        client_name = self._sanitize_name(name)
        if any(c['name'] == client_name for c in clients):
            client_name = f"{client_name[:55]}_{uuid.uuid4().hex[:6]}"

        secret = kwargs.get('secret')
        secret = self.validate_secret(secret) if secret else secrets.token_hex(16)
        if any(c['secret'] == secret for c in clients):
            raise ValueError("That secret is already used by another connection")

        config = self._read_json(f"{self.REMOTE_DIR}/config.json") or {}
        limit = (config.get('limits') or {}).get('max_profiles') or 128
        if len([c for c in clients if c.get('enabled', True)]) >= limit:
            raise ValueError(
                f"The relay allows at most {limit} profiles; raise max_profiles in the server config first")

        clients.append({
            'name': client_name,
            'secret': secret,
            'carrier_mode': self.validate_carrier_mode(kwargs.get('carrier_mode')),
            'enabled': True,
            'created': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        })
        self._apply_clients(clients)
        # `client_id` (not `clientId`) is the key app.py looks for when linking
        # a fresh connection to a panel user -- match the other managers.
        return {
            'client_id': client_name,
            'secret': secret,
            'hostname': self._public_hostname(),
            'config': self._build_link(secret),
            'vpn_link': self._build_share_link(secret),
        }

    def edit_client(self, protocol_type, client_id, new_params):
        clients = self._load_clients()
        target = next((c for c in clients if c['name'] == client_id), None)
        if target is None:
            raise ValueError(f"Connection '{client_id}' not found")

        if new_params.get('secret'):
            secret = self.validate_secret(new_params['secret'])
            if any(c['secret'] == secret and c['name'] != client_id for c in clients):
                raise ValueError("That secret is already used by another connection")
            target['secret'] = secret
        if new_params.get('carrier_mode'):
            target['carrier_mode'] = self.validate_carrier_mode(new_params['carrier_mode'])
        new_name = new_params.get('name')
        if new_name:
            renamed = self._sanitize_name(new_name)
            if renamed != client_id and any(c['name'] == renamed for c in clients):
                raise ValueError(f"A connection named '{renamed}' already exists")
            target['name'] = renamed

        self._apply_clients(clients)
        return {'status': 'success', 'client_id': target['name'],
                'hostname': self._public_hostname(),
                'config': self._build_link(target['secret']),
                'vpn_link': self._build_share_link(target['secret'])}

    def remove_client(self, protocol_type, client_id):
        clients = self._load_clients()
        remaining = [c for c in clients if c['name'] != client_id]
        if len(remaining) == len(clients):
            raise ValueError(f"Connection '{client_id}' not found")
        self._apply_clients(remaining)
        return {'status': 'success'}

    def toggle_client(self, protocol_type, client_id, enable, restart=True):
        clients = self._load_clients()
        target = next((c for c in clients if c['name'] == client_id), None)
        if target is None:
            raise ValueError(f"Connection '{client_id}' not found")
        target['enabled'] = bool(enable)
        self._apply_clients(clients, restart=restart)
        return {'status': 'success'}

    def get_client_config(self, protocol_type, client_id, host='', port=''):
        # `host`/`port` are ignored on purpose: callers pass the server's SSH or
        # client IP, but the link must carry the relay's own public_hostname --
        # the client refuses an IP address and accepts no port at all.
        target = next((c for c in self._load_clients() if c['name'] == client_id), None)
        if target is None:
            return ""
        return self._build_link(target['secret'])

    def _build_link(self, secret):
        """Primary link: the `tg://` form the client resolves on its own.

        The documented `https://t.me/webproxy?...` wrapper is not usable yet --
        README says the public t.me frontend does not register that route, so it
        only works once Telegram ships it (and needs t.me to be reachable at
        all). The tg:// deep link never touches the network, and the values a
        client actually asks for are just hostname + secret.
        """
        hostname = self._public_hostname()
        if not hostname:
            return ""
        return f"tg://webproxy?server={hostname}&secret={secret}"

    def _build_share_link(self, secret):
        """The t.me wrapper, kept for when Telegram registers the route."""
        hostname = self._public_hostname()
        if not hostname:
            return ""
        return f"https://t.me/webproxy?server={hostname}&secret={secret}"

    def _public_hostname(self):
        return (self._read_json(f"{self.REMOTE_DIR}/config.json") or {}).get('public_hostname', '')
