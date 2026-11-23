import json
import logging
import uuid
import re
import os
import secrets
from datetime import datetime
from .docker_utils import ensure_docker_compose
from .naming import is_safe_key, transliterate
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

class TelemtManager:
    CONTAINER_NAME = "telemt"
    API_URL = "http://127.0.0.1:9091"
    CONFIG_PATH = "/opt/amnezia/telemt/config.toml"
    # Sections whose keys are usernames (and therefore must be safe TOML bare keys).
    USER_KEYED_SECTIONS = (
        "access.users",
        "access.user_data_quota",
        "access.user_max_unique_ips",
        "access.user_expirations",
        "access.user_ad_tags",
        "access.user_max_tcp_conns",
    )

    def __init__(self, ssh_manager: SSHManager):
        self.ssh = ssh_manager

    def _api_request(self, method, path, data=None):
        """Execute a curl request inside the docker container."""
        cmd = f"docker exec {self.CONTAINER_NAME} curl -s -X {method} {self.API_URL}{path}"
        if data:
            js_data = json.dumps(data).replace('"', '\\"')
            cmd += f" -H 'Content-Type: application/json' -d \"{js_data}\""
        
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0:
            return None
        
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def check_docker_installed(self):
        out, _, _ = self.ssh.run_command("docker --version 2>/dev/null")
        return bool(out.strip())

    def check_protocol_installed(self):
        out, _, _ = self.ssh.run_command(f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'")
        return out.strip() == self.CONTAINER_NAME

    def get_server_status(self, protocol_type):
        exists = self.check_protocol_installed()
        out, _, _ = self.ssh.run_command(f"docker inspect -f '{{{{.State.Running}}}}' {self.CONTAINER_NAME} 2>/dev/null")
        is_running = out.strip().lower() == 'true'
        
        status = {
            'container_exists': exists,
            'container_running': is_running,
        }
        
        if is_running:
            # get external docker port mapping for 443
            out, _, _ = self.ssh.run_command(f"docker port {self.CONTAINER_NAME} 443 2>/dev/null")
            if out:
                port = out.split(':')[-1].strip()
                status['port'] = port
            else:
                status['port'] = None
                
            config = self._get_server_config()
            status['awg_params'] = self._parse_telemt_params(config)
            
            # Count connections from API
            clients = self.get_clients(protocol_type)
            status['clients_count'] = len(clients)
            
        return status

    def _ensure_docker_compose(self):
        # Shared with the WEB proxy manager; see managers/docker_utils.py.
        ensure_docker_compose(self.ssh)

    def install_protocol(self, protocol_type='telemt', port='443', tls_emulation=True, tls_domain="", max_connections=0):
        results = []
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.ssh.run_sudo_command("curl -fsSL https://get.docker.com | sh", timeout=300)

        if self.check_protocol_installed():
            self.ssh.run_sudo_command(f"docker rm -f {self.CONTAINER_NAME}")

        results.append("Ensuring docker compose plugin...")
        self._ensure_docker_compose()
            
        results.append("Uploading Telemt files...")
        # protocol_telemt/ lives at the repo root, not under managers/ — the
        # upstream join was looking at /app/managers/protocol_telemt which
        # doesn't exist. Step up one level from this file's directory.
        local_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'protocol_telemt')
        remote_dir = "/opt/amnezia/telemt"
        self.ssh.run_sudo_command(f"mkdir -p {remote_dir}")
        self.ssh.run_sudo_command(f"chmod 755 {remote_dir}")
        
        # Read and patch config.toml
        with open(os.path.join(local_dir, 'config.toml'), 'r', encoding='utf-8') as f:
            config_content = f.read()
            
        tls_emul_str = "true" if tls_emulation else "false"
        config_content = re.sub(r'tls_emulation\s*=\s*(true|false|True|False)', f'tls_emulation = {tls_emul_str}', config_content)
        
        if tls_emulation and tls_domain:
            config_content = re.sub(r'tls_domain\s*=\s*".*?"', f'tls_domain = "{tls_domain}"', config_content)
            
        if max_connections is not None and max_connections > 0:
            config_content = re.sub(r'max_connections\s*=\s*\d+', f'max_connections = {max_connections}', config_content)

        # Patch public_host and public_port for links
        if "public_host =" in config_content or "# public_host =" in config_content:
            config_content = re.sub(r'#?\s*public_host\s*=\s*".*?"', f'public_host = "{self.ssh.host}"', config_content)
        else:
            config_content = config_content.replace('[general.links]', f'[general.links]\npublic_host = "{self.ssh.host}"')
            
        config_content = re.sub(r'public_port\s*=\s*\d+', f'public_port = {port}', config_content)
        
        # Replace the bundled `hello = "00000000..."` placeholder with a
        # service entry that has a fresh random secret.  Telemt refuses to
        # start when `[access.users]` is empty ("No users configured"), so if
        # we stripped the default outright the container would crash-loop
        # until the first real add_client. Keeping a service-named placeholder
        # with an unguessable secret lets the proxy come up immediately:
        #   - admin can't (and shouldn't) hand out the `_telemt_init` link;
        #   - admin sees it in the UI client list and can delete it manually
        #     once a real user has been added.
        _placeholder_secret = secrets.token_hex(16)
        config_content = re.sub(
            r'^hello\s*=\s*".*?"\s*$',
            f'_telemt_init = "{_placeholder_secret}"',
            config_content,
            flags=re.MULTILINE,
        )
            
        self.ssh.upload_file_sudo(config_content, f"{remote_dir}/config.toml")
        
        # Patch docker-compose.yml with proper port
        with open(os.path.join(local_dir, 'docker-compose.yml'), 'r', encoding='utf-8') as f:
            compose_content = f.read()
            
        compose_content = re.sub(r'"443:443"', f'"{port}:443"', compose_content)
        self.ssh.upload_file_sudo(compose_content, f"{remote_dir}/docker-compose.yml")
        
        # Upload Dockerfile
        with open(os.path.join(local_dir, 'Dockerfile'), 'r', encoding='utf-8') as f:
            dockerfile = f.read()
            self.ssh.upload_file_sudo(dockerfile, f"{remote_dir}/Dockerfile")
            
        results.append("Starting Telemt container...")
        out, err, code = self.ssh.run_sudo_command(f"sh -c 'cd {remote_dir} && docker compose up -d --build'", timeout=600)
        if code != 0:
            self.ssh.run_sudo_command(f"sh -c 'cd {remote_dir} && docker-compose up -d --build'", timeout=600)
                
        return {
            "status": "success",
            "host": "",
            "port": port,
            "log": results
        }

    # Cyrillic -> Latin so that a Russian display name survives as something
    # readable instead of collapsing into underscores ("Иванов И.И." used to
    # sanitize down to an empty key and get a random uuid name).
    # Table shared with the WEB proxy manager; see managers/naming.py.
    @classmethod
    def _transliterate(cls, text):
        return transliterate(text)

    @staticmethod
    def _is_safe_key(key):
        """True if `key` is a TOML bare key Telemt will read as a plain name."""
        return is_safe_key(key)

    @classmethod
    def _sanitize_username(cls, name):
        """Coerce an arbitrary display name into a safe TOML bare key.

        TOML bare keys only allow [A-Za-z0-9_-]; a literal dot is the
        nested-table separator, so `foo.bar = "x"` parses as the table `[foo]`
        with member `bar` rather than a scalar named `foo.bar`.  Telemt then
        dies at startup with "invalid type: map, expected a string" and stays
        in a restart loop -- i.e. one bad name takes down the proxy for every
        user on the server.  Replace (rather than strip) unsafe runs so that
        an all-non-ASCII name doesn't collapse into an empty key.
        """
        username = cls._transliterate((name or '').strip())
        username = re.sub(r'[^A-Za-z0-9_-]+', '_', username.replace(' ', '_')).strip('_')
        return username or ("user_" + uuid.uuid4().hex[:8])

    @classmethod
    def _repair_key(cls, key):
        """Minimal fix for an existing config key: only touch unsafe ones.

        Deliberately NOT _sanitize_username(): that one falls back to a random
        uuid name, which would rename a live user (e.g. the legacy `_` key on
        anubis) and desync them from the panel on every single write.
        """
        repaired = re.sub(r'[^A-Za-z0-9_-]+', '_', cls._transliterate(key)).strip('_')
        return repaired or 'user_' + re.sub(r'[^a-f0-9]', '', uuid.uuid5(uuid.NAMESPACE_DNS, key).hex)[:8]

    @classmethod
    def _normalize_config_keys(cls, config_text):
        """Rewrite unsafe usernames already present in a config.

        Guards against configs written by an older panel build (whose regex
        kept dots) and against hand edits made through the raw-config editor.
        Returns (config_text, renames) where renames maps old -> new.
        """
        lines = config_text.split('\n')
        section = None
        renames = {}
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if stripped.startswith('[') and stripped.endswith(']'):
                section = stripped[1:-1].strip()
                continue
            if section not in cls.USER_KEYED_SECTIONS:
                continue
            # Disabled users are stored commented out; keep that marker intact.
            m = re.match(r'^(\s*)(#\s*)?([^#\s=\[\]"\']+)(\s*=\s*)(.*)$', raw)
            if not m:
                continue
            indent, comment, key, eq, value = m.groups()
            if cls._is_safe_key(key):
                continue
            safe = cls._repair_key(key)
            if safe == key:
                continue
            renames[key] = safe
            lines[i] = f"{indent}{comment or ''}{safe}{eq}{value}"
        return '\n'.join(lines), renames

    @staticmethod
    def _validate_config(config_text):
        """Return a list of fatal problems; empty means Telemt should accept it."""
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python < 3.11
            return []
        try:
            data = tomllib.loads(config_text)
        except Exception as exc:
            return [f"TOML syntax error: {exc}"]
        users = (data.get('access') or {}).get('users') or {}
        if not isinstance(users, dict):
            return ["[access.users] is not a table"]
        problems = [
            f"user '{name}' has a {type(secret).__name__} value, expected a string"
            for name, secret in users.items() if not isinstance(secret, str)
        ]
        if not users:
            problems.append("no users configured - Telemt refuses to start with an empty [access.users]")
        return problems

    def _upload_config(self, config_text):
        """Normalize, validate and only then push config.toml to the server.

        Every write to config.toml goes through here so a malformed config
        can never reach the server and crash-loop the container.
        """
        config_text = config_text.replace('\r\n', '\n')
        config_text, renames = self._normalize_config_keys(config_text)
        if renames:
            logger.warning(
                "Telemt config on %s contained unsafe usernames, normalized: %s",
                getattr(self.ssh, 'host', '?'),
                ', '.join(f"{old} -> {new}" for old, new in renames.items()),
            )
        problems = self._validate_config(config_text)
        if problems:
            raise ValueError("Refusing to write an invalid Telemt config: " + "; ".join(problems))
        self.ssh.upload_file_sudo(config_text, self.CONFIG_PATH)
        return renames

    def _get_server_config(self):
        out, _, code = self.ssh.run_sudo_command(f"cat {self.CONFIG_PATH}")
        if code != 0: return ""
        return out

    def _reload(self):
        """SIGHUP keeps traffic counters; restart only if HUP failed.
        Two commands: in `a || b` under sudo, b would run without root."""
        _, _, code = self.ssh.run_sudo_command(f"docker kill -s HUP {self.CONTAINER_NAME}")
        if code != 0:
            self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}")

    def save_server_config(self, protocol_type, config_content):
        self._upload_config(config_content)
        # Use SIGHUP (HUP) to reload MTProxy config without restarting the process/container.
        # This keeps the traffic statistics (octets) in memory.
        self._reload()

    def _parse_telemt_params(self, config_text):
        params = {}
        m = re.search(r'tls_emulation\s*=\s*(true|false)', config_text, re.IGNORECASE)
        if m: params['tls_emulation'] = m.group(1).lower() == 'true'
        
        m = re.search(r'tls_domain\s*=\s*"([^"]+)"', config_text)
        if m: params['tls_domain'] = m.group(1)
        
        m = re.search(r'max_connections\s*=\s*(\d+)', config_text)
        if m: params['max_connections'] = int(m.group(1))
        
        return params

    @staticmethod
    def _is_tls_mode(config_text: str) -> bool:
        """Detect whether the active config has only Fake-TLS mode enabled
        (`[general.modes]` tls=true, classic=false, secure=false)."""
        # Pull out just the [general.modes] section, so we don't accidentally
        # match a `tls = true` line that belongs to some other table.
        m = re.search(r'\[general\.modes\](.*?)(?=\n\[|\Z)', config_text, re.S)
        if not m:
            return False
        section = m.group(1)
        tls_match = re.search(r'^\s*tls\s*=\s*(true|false)', section, re.I | re.M)
        return bool(tls_match and tls_match.group(1).lower() == 'true')

    @staticmethod
    def _build_fake_tls_secret(secret_hex: str, tls_domain: str) -> str:
        """Wrap a 32-hex-char (16-byte) MTProxy secret into the Fake-TLS
        on-wire format that the official Telegram client recognises:

            ee + <16 random bytes hex> + <utf8(tls_domain) hex>

        Returns the new hex secret. If inputs are malformed, returns the
        secret unchanged so we never produce a worse link than before."""
        if not secret_hex or not tls_domain:
            return secret_hex
        try:
            # Reject anything that isn't exactly 16 bytes of hex — Fake-TLS
            # requires that fixed length for the random suffix.
            if len(secret_hex) != 32 or not all(c in '0123456789abcdefABCDEF' for c in secret_hex):
                return secret_hex
            return 'ee' + secret_hex.lower() + tls_domain.encode('utf-8').hex()
        except Exception:
            return secret_hex

    def remove_container(self, protocol_type=None):
        self.ssh.run_sudo_command(f"docker rm -f {self.CONTAINER_NAME}")
        self.ssh.run_sudo_command("rm -rf /opt/amnezia/telemt")

    def get_clients(self, protocol_type):
        api_data = {}
        resp = self._api_request("GET", "/v1/users")
        if resp and resp.get('ok'):
            for u in resp.get('data', []):
                api_data[u.get('username')] = u

        config_text = self._get_server_config()
        users = self._parse_users_from_config(config_text)
        
        clients = []
        needs_update = False
        for username, secret in users.items():
            user_stats = api_data.get(username.lstrip('#').strip(), {})
            links = user_stats.get('links', {})
            tg_link = ""
            if links.get('tls'): tg_link = links['tls'][0]
            elif links.get('secure'): tg_link = links['secure'][0]
            elif links.get('classic'): tg_link = links['classic'][0]
            
            enabled = not username.startswith('#')
            clean_name = username.lstrip('#').strip()
            
            total_octets = user_stats.get('total_octets', 0)
            quota = user_stats.get('data_quota_bytes')
            
            # AUTO-DISABLE IF QUOTA REACHED
            if enabled and quota and total_octets >= quota:
                logger.info(f"Auto-disabling client {clean_name} - quota reached: {total_octets} >= {quota}")
                # We will trigger a toggle after we finish this loop to avoid re-reading config inside loop
                enabled = False
                needs_update = True
            
            clients.append({
                "clientId": clean_name,
                "clientName": clean_name,
                "enabled": enabled,
                "creationDate": "",
                "userData": { 
                    "clientName": clean_name,
                    "token": secret,
                    "tg_link": tg_link,
                    "total_octets": total_octets,
                    "current_connections": user_stats.get('current_connections', 0),
                    "active_ips": user_stats.get('active_unique_ips', 0),
                    "quota": quota,
                    "expiry": user_stats.get('expiration_rfc3339')
                }
            })
            
        if needs_update:
            # Re-read and update config strictly at the end
            for c in clients:
                if not c['enabled']:
                     self.toggle_client(protocol_type, c['clientId'], False, restart=False)
            self._reload()

        return clients

    def _parse_users_from_config(self, config_text):
        users = {}
        lines = config_text.split('\n')
        in_section = False
        for line in lines:
            stripped = line.strip()
            if stripped == '[access.users]':
                in_section = True
                continue
            if in_section and stripped.startswith('['):
                break
            if in_section and stripped:
                commented = stripped.startswith('#')
                content = stripped.lstrip('#').strip()
                if '=' in content:
                    if content.lower().startswith('format:'): continue
                    name, secret = content.split('=', 1)
                    name = name.strip().strip('"').strip()
                    secret = secret.strip().strip('"').strip()
                    full_name = ("# " + name) if commented else name
                    users[full_name] = secret
        return users

    def add_client(self, protocol_type, name, host='', port='', **kwargs):
        username = self._sanitize_username(name)

        config_text = self._get_server_config()
        current_users = self._parse_users_from_config(config_text)
        idx = 1
        base_username = username
        while any(u.lstrip('#').strip() == username for u in current_users):
            username = f"{base_username}_{idx}"
            idx += 1
            
        secret = kwargs.get('secret') or secrets.token_hex(16)
        
        # 1. Update config file for persistence (but don't restart yet)
        config_text = self._insert_into_section(config_text, "access.users", f'{username} = "{secret}"')
        
        api_payload = {
            "username": username,
            "secret": secret
        }
        
        if kwargs.get('telemt_quota'): 
            val = int(kwargs['telemt_quota'])
            config_text = self._insert_into_section(config_text, "access.user_data_quota", f'{username} = {val}')
            api_payload['data_quota_bytes'] = val
            
        if kwargs.get('telemt_max_ips'): 
            val = int(kwargs['telemt_max_ips'])
            config_text = self._insert_into_section(config_text, "access.user_max_unique_ips", f'{username} = {val}')
            api_payload['max_unique_ips'] = val
            
        if kwargs.get('telemt_expiry'): 
            val = kwargs['telemt_expiry']
            config_text = self._insert_into_section(config_text, "access.user_expirations", f'{username} = "{val}"')
            api_payload['expiration_rfc3339'] = val

        if kwargs.get('user_ad_tag'):
            val = kwargs['user_ad_tag']
            config_text = self._insert_into_section(config_text, "access.user_ad_tags", f'{username} = "{val}"')
            api_payload['user_ad_tag'] = val
            
        if kwargs.get('max_tcp_conns'):
            val = int(kwargs['max_tcp_conns'])
            config_text = self._insert_into_section(config_text, "access.user_max_tcp_conns", f'{username} = {val}')
            api_payload['max_tcp_conns'] = val

        # Save config to host
        self._upload_config(config_text)
        
        # 2. Call API for immediate effect
        self._api_request("POST", "/v1/users", data=api_payload)
        
        # Fetch the official link from API (it includes TLS emulation padding like 'ee...' if enabled)
        link = self.get_client_config(protocol_type, username, host, port)

        # Extreme fallback if API is slow or 404 (e.g. container in restart loop
        # right after install). Without this, admins get a flat secret that
        # Telemt refuses in Fake-TLS-only mode. Reconstruct the proper format
        # from what we already know locally.
        if link == "Not found":
            params = self._parse_telemt_params(config_text)
            wire_secret = secret
            if self._is_tls_mode(config_text) and params.get('tls_domain'):
                wire_secret = self._build_fake_tls_secret(secret, params['tls_domain'])
            link = f"tg://proxy?server={host}&port={port}&secret={wire_secret}"
        
        return {
            "client_id": username,
            "config": link,
            "vpn_link": link
        }

    def edit_client(self, protocol_type, client_id, new_params):
        """Update existing client parameters via API and in config."""
        config_text = self._get_server_config()
        api_payload = {}
        
        if 'telemt_quota' in new_params:
            val = int(new_params['telemt_quota']) if new_params['telemt_quota'] else None
            config_text = self._update_line_in_section(config_text, "access.user_data_quota", client_id, val)
            api_payload['data_quota_bytes'] = val
            
        if 'telemt_max_ips' in new_params:
            val = int(new_params['telemt_max_ips']) if new_params['telemt_max_ips'] else None
            config_text = self._update_line_in_section(config_text, "access.user_max_unique_ips", client_id, val)
            api_payload['max_unique_ips'] = val
            
        if 'telemt_expiry' in new_params:
            val = new_params['telemt_expiry']
            quoted_val = f'"{val}"' if val else None
            config_text = self._update_line_in_section(config_text, "access.user_expirations", client_id, quoted_val)
            api_payload['expiration_rfc3339'] = val
            
        if 'secret' in new_params:
            val = new_params['secret']
            quoted_val = f'"{val}"' if val else None
            config_text = self._update_line_in_section(config_text, "access.users", client_id, quoted_val)
            api_payload['secret'] = val

        if 'user_ad_tag' in new_params:
            val = new_params['user_ad_tag']
            quoted_val = f'"{val}"' if val else None
            config_text = self._update_line_in_section(config_text, "access.user_ad_tags", client_id, quoted_val)
            api_payload['user_ad_tag'] = val
            
        if 'max_tcp_conns' in new_params:
            val = int(new_params['max_tcp_conns']) if new_params['max_tcp_conns'] else None
            config_text = self._update_line_in_section(config_text, "access.user_max_tcp_conns", client_id, val)
            api_payload['max_tcp_conns'] = val

        # Save config to host
        self._upload_config(config_text)
        
        # API call
        self._api_request("PATCH", f"/v1/users/{client_id}", data=api_payload)
        return {"status": "success"}

    def _update_line_in_section(self, config_text, section_name, client_id, value):
        lines = config_text.split('\n')
        section_start = -1
        section_end = -1
        for i, line in enumerate(lines):
            if line.strip() == f"[{section_name}]":
                section_start = i
            elif section_start != -1 and line.strip().startswith('['):
                section_end = i
                break
        
        if section_end == -1: section_end = len(lines)
        if section_start == -1:
            if value is not None:
                lines.append(f"[{section_name}]")
                lines.append(f'{client_id} = {value}')
                lines.append("")
            return '\n'.join(lines)

        found = False
        for i in range(section_start + 1, section_end):
            line = lines[i].strip().lstrip('#').strip()
            if line.startswith(f"{client_id} ") or line.startswith(f"{client_id}="):
                if value is None: lines.pop(i)
                else: lines[i] = f'{client_id} = {value}'
                found = True
                break
        
        if not found and value is not None:
            lines.insert(section_start + 1, f'{client_id} = {value}')
            
        return '\n'.join(lines)

    def _insert_into_section(self, config_text, section_name, line_to_insert):
        lines = config_text.split('\n')
        section_start = -1
        for i, line in enumerate(lines):
            if line.strip() == f"[{section_name}]":
                section_start = i
                break
        if section_start == -1:
            lines.append(f"[{section_name}]")
            lines.append(line_to_insert)
            lines.append("")
        else:
            lines.insert(section_start + 1, line_to_insert)
        return '\n'.join(lines)

    PLACEHOLDER_USER = '_telemt_init'

    def _keep_users_nonempty(self, config_text):
        """Telemt won't start with no active users: put back the init placeholder."""
        active = [u for u in self._parse_users_from_config(config_text) if not u.startswith('#')]
        if active:
            return config_text
        line = f'{self.PLACEHOLDER_USER} = "{secrets.token_hex(16)}"'
        return self._insert_into_section(config_text, 'access.users', line)

    def remove_client(self, protocol_type, client_id):
        # 1. API
        self._api_request("DELETE", f"/v1/users/{client_id}")
        
        # 2. Config
        config_text = self._get_server_config()
        users = {u.lstrip('#').strip() for u in self._parse_users_from_config(config_text)}
        if client_id not in users:
            # Protocol removed/reinstalled or user already gone: nothing to write.
            logger.info("Telemt user %s not in config on %s, skip config write",
                        client_id, getattr(self.ssh, 'host', '?'))
            return
        lines = config_text.split('\n')
        new_lines = []
        for line in lines:
            stripped = line.strip().lstrip('#').strip()
            if stripped.startswith(f"{client_id} ") or stripped.startswith(f"{client_id}="):
                continue
            new_lines.append(line)
        self._upload_config(self._keep_users_nonempty('\n'.join(new_lines)))

    def toggle_client(self, protocol_type, client_id, enable, restart=True):
        # API doesn't have a direct "toggle", so we either set a huge quota or remove/re-add
        # But for Telemt, commenting out in config is the persistent way.
        # We'll use HUP after toggling in config.
        
        config_text = self._get_server_config()
        lines = config_text.split('\n')
        new_lines = []
        in_access_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('[access.'): in_access_section = True
            elif stripped.startswith('['): in_access_section = False
            
            if in_access_section:
                base_line = line.lstrip('#').strip()
                if base_line.startswith(f"{client_id} ") or base_line.startswith(f"{client_id}="):
                    line = base_line if enable else f"# {base_line}"
            new_lines.append(line)
        
        self._upload_config(self._keep_users_nonempty('\n'.join(new_lines)))
        
        if enable:
            # If enabling, we re-add via API since it might have been deleted from memory
            secret = ""
            users = self._parse_users_from_config('\n'.join(new_lines))
            secret = users.get(client_id, "")
            if secret:
                self._api_request("POST", "/v1/users", data={"username": client_id, "secret": secret})
        else:
            # If disabling, we just delete from memory
            self._api_request("DELETE", f"/v1/users/{client_id}")

        if restart:
            self._reload()

    def get_client_config(self, protocol_type, client_id, host='', port=''):
        resp = self._api_request("GET", f"/v1/users/{client_id}")
        if resp and resp.get('ok'):
            user = resp.get('data', {})
            links = user.get('links', {})
            if links.get('tls'): return links['tls'][0]
            if links.get('secure'): return links['secure'][0]
            if links.get('classic'): return links['classic'][0]

        # API unreachable — try to assemble the link from the config we have
        # on disk (matches the Fake-TLS format Telemt would generate itself).
        clients = self.get_clients(protocol_type)
        c = next((c for c in clients if c['clientId'] == client_id), None)
        if c:
            secret = c.get('userData', {}).get('token', '')
            if secret:
                config_text = self._get_server_config()
                wire_secret = secret
                if config_text and self._is_tls_mode(config_text):
                    params = self._parse_telemt_params(config_text)
                    if params.get('tls_domain'):
                        wire_secret = self._build_fake_tls_secret(secret, params['tls_domain'])
                return f"tg://proxy?server={host}&port={port}&secret={wire_secret}"
        return "Not found"