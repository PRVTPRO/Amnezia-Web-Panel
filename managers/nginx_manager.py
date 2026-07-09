"""
NGINX Web Server Manager.

Runs an NGINX container with a single editable site (index.html) and a
Let's Encrypt certificate issued through the webroot HTTP-01 challenge.
The panel owns:
  - nginx.conf: editable through the Config button
  - index.html: editable through the Site button
"""

import json
import logging
import re
import shlex

logger = logging.getLogger(__name__)


def _q(value):
    return shlex.quote(str(value))


class NginxManager:
    PROTOCOL = 'nginx'
    CONTAINER_NAME = 'amnezia-nginx'
    IMAGE_NAME = 'nginx:alpine'
    CERTBOT_IMAGE = 'certbot/certbot:latest'
    CERTBOT_CONTAINER_NAME = 'amnezia-nginx-certbot'
    BASE_DIR = '/opt/amnezia/nginx'
    CONF_DIR = f'{BASE_DIR}/conf'
    HTML_DIR = f'{BASE_DIR}/html'
    CERTBOT_WWW_DIR = f'{BASE_DIR}/certbot/www'
    LETSENCRYPT_DIR = f'{BASE_DIR}/letsencrypt'
    META_PATH = f'{BASE_DIR}/metadata.json'
    NGINX_CONF_PATH = f'{CONF_DIR}/default.conf'
    INDEX_PATH = f'{HTML_DIR}/index.html'
    DEFAULT_PORT = 443

    def __init__(self, ssh, protocol='nginx'):
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

    def check_protocol_installed(self, protocol_type='nginx'):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

    def check_container_running(self, protocol_type='nginx'):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_certbot_running(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CERTBOT_CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def get_server_status(self, protocol_type='nginx'):
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type)
        meta = self._read_metadata() if exists else {}
        config = self._get_server_config(protocol_type) if exists else ''
        domain = meta.get('domain') or self._parse_domain(config)
        port = int(meta.get('port') or self.DEFAULT_PORT)
        return {
            'container_exists': exists,
            'container_running': running,
            'port': port,
            'domain': domain,
            'email': meta.get('email'),
            'site_url': self._site_url(domain, port) if domain else None,
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.CONTAINER_NAME,
            'certbot_container_name': self.CERTBOT_CONTAINER_NAME,
            'certbot_running': self.check_certbot_running() if exists else False,
        }

    # ===================== CONFIG BUILDERS =====================

    def _validate_domain(self, domain):
        domain = (domain or '').strip().lower()
        if not domain or len(domain) > 253:
            raise ValueError('Domain is required')
        if not re.match(r'^(?!-)[a-z0-9.-]+(?<!-)$', domain) or '.' not in domain:
            raise ValueError('Invalid domain name')
        return domain

    def _validate_email(self, email):
        email = (email or '').strip()
        if not email or '@' not in email:
            raise ValueError('Valid Let\'s Encrypt email is required')
        return email

    def _site_url(self, domain, port):
        if not domain:
            return None
        port = int(port or self.DEFAULT_PORT)
        return f'https://{domain}' if port == 443 else f'https://{domain}:{port}'

    def _build_initial_config(self, domain):
        return f"""server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        root /usr/share/nginx/html;
        index index.html;
        try_files $uri $uri/ /index.html;
    }}
}}
"""

    def _build_ssl_config(self, domain, port):
        redirect_target = 'https://$host$request_uri' if int(port) == 443 else f'https://$host:{int(port)}$request_uri'
        return f"""server {{
    listen 80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 {redirect_target};
    }}
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    root /usr/share/nginx/html;
    index index.html;

    location / {{
        try_files $uri $uri/ /index.html;
    }}
}}
"""

    def _default_index(self, domain):
        return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{domain}</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: #0f172a; color: #e2e8f0; }}
    main {{ text-align: center; padding: 32px; }}
    h1 {{ font-size: clamp(2rem, 6vw, 4rem); margin: 0 0 12px; }}
    p {{ color: #94a3b8; font-size: 1.1rem; }}
  </style>
</head>
<body>
  <main>
    <h1>NGINX is running</h1>
    <p>{domain}</p>
  </main>
</body>
</html>
"""

    def _parse_domain(self, config_text):
        m = re.search(r'^\s*server_name\s+([^;\s]+)', config_text or '', re.MULTILINE)
        return m.group(1) if m else None

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

    def _get_server_config(self, protocol_type='nginx'):
        config = self._read_file(self.NGINX_CONF_PATH)
        if config:
            return config
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.CONTAINER_NAME} cat /etc/nginx/conf.d/default.conf 2>/dev/null"
        )
        return out if code == 0 else ''

    def save_server_config(self, protocol_type='nginx', config_text=''):
        old_config = self._get_server_config(protocol_type)
        self._write_file(self.NGINX_CONF_PATH, config_text or '')
        if self.check_container_running(protocol_type):
            _, err, code = self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} nginx -t", timeout=30)
            if code != 0:
                self._write_file(self.NGINX_CONF_PATH, old_config)
                self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} nginx -s reload 2>/dev/null || true")
                raise RuntimeError(f'Invalid NGINX config: {err}')
            self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} nginx -s reload")
        return True

    def get_site_index(self, protocol_type='nginx'):
        return self._read_file(self.INDEX_PATH)

    def save_site_index(self, protocol_type='nginx', html=''):
        self._write_file(self.INDEX_PATH, html or '')
        return True

    # ===================== INSTALL / REMOVE =====================

    def _run_nginx_container(self, port):
        run_cmd = (
            f"docker run -d --restart always "
            f"--name {self.CONTAINER_NAME} "
            f"-p 80:80/tcp "
            f"-p {int(port)}:443/tcp "
            f"-v {self.CONF_DIR}:/etc/nginx/conf.d:ro "
            f"-v {self.HTML_DIR}:/usr/share/nginx/html:ro "
            f"-v {self.CERTBOT_WWW_DIR}:/var/www/certbot:ro "
            f"-v {self.LETSENCRYPT_DIR}:/etc/letsencrypt:ro "
            f"{self.IMAGE_NAME}"
        )
        return self.ssh.run_sudo_command(run_cmd, timeout=60)

    def _run_certbot_renewer(self, domain, email):
        loop_script = f"""
set -eu
if [ ! -f /etc/letsencrypt/live/{domain}/fullchain.pem ]; then
  certbot certonly --webroot --webroot-path /var/www/certbot --email {_q(email)} --agree-tos --no-eff-email -d {_q(domain)}
fi
kill -HUP 1 2>/dev/null || true
while :; do
  certbot renew --webroot --webroot-path /var/www/certbot --quiet --deploy-hook 'kill -HUP 1 2>/dev/null || true'
  sleep 12h & wait $!
done
"""
        self.ssh.run_sudo_command(f"docker rm -fv {self.CERTBOT_CONTAINER_NAME} || true")
        run_cmd = (
            f"docker run -d --restart always "
            f"--name {self.CERTBOT_CONTAINER_NAME} "
            f"--pid=container:{self.CONTAINER_NAME} "
            f"-v {self.CERTBOT_WWW_DIR}:/var/www/certbot "
            f"-v {self.LETSENCRYPT_DIR}:/etc/letsencrypt "
            f"--entrypoint /bin/sh "
            f"{self.CERTBOT_IMAGE} -c {_q(loop_script)}"
        )
        return self.ssh.run_sudo_command(run_cmd, timeout=60)

    def _wait_for_certificate(self, domain):
        wait_script = f"""
for i in $(seq 1 60); do
  if [ -s {self.LETSENCRYPT_DIR}/live/{domain}/fullchain.pem ] && [ -s {self.LETSENCRYPT_DIR}/live/{domain}/privkey.pem ]; then
    exit 0
  fi
  if ! docker ps --filter name=^{self.CERTBOT_CONTAINER_NAME}$ --format '{{{{.Names}}}}' | grep -qx {self.CERTBOT_CONTAINER_NAME}; then
    docker logs --tail 120 {self.CERTBOT_CONTAINER_NAME} 2>&1 || true
    exit 1
  fi
  sleep 5
done
docker logs --tail 120 {self.CERTBOT_CONTAINER_NAME} 2>&1 || true
exit 1
"""
        return self.ssh.run_sudo_command(f"sh -c {_q(wait_script)}", timeout=330)

    def install_protocol(self, protocol_type='nginx', port=None, email=None, domain=None):
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}

        port = int(port or self.DEFAULT_PORT)
        if port == 80:
            return {'status': 'error', 'message': 'Port 80 is reserved for Let\'s Encrypt validation'}
        domain = self._validate_domain(domain)
        email = self._validate_email(email)

        self.ssh.run_sudo_command(f"docker pull {self.IMAGE_NAME}", timeout=180)
        self.ssh.run_sudo_command(f"docker pull {self.CERTBOT_IMAGE}", timeout=180)

        if self.check_protocol_installed(protocol_type):
            self.remove_container(protocol_type)

        self.ssh.run_sudo_command(
            f"mkdir -p {self.CONF_DIR} {self.HTML_DIR} {self.CERTBOT_WWW_DIR} {self.LETSENCRYPT_DIR}"
        )
        self._write_file(self.NGINX_CONF_PATH, self._build_initial_config(domain))
        self._write_file(self.INDEX_PATH, self._default_index(domain))
        self._write_metadata({'domain': domain, 'email': email, 'port': port})

        _, err, code = self._run_nginx_container(port)
        if code != 0:
            return {'status': 'error', 'message': f'Failed to start NGINX container: {err}'}

        _, err, code = self._run_certbot_renewer(domain, email)
        if code != 0:
            self.ssh.run_sudo_command(f"docker logs --tail 100 {self.CONTAINER_NAME} 2>/dev/null || true")
            self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} || true")
            self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} || true")
            return {'status': 'error', 'message': f'Failed to start certbot renewer container: {err}'}

        out, err, code = self._wait_for_certificate(domain)
        if code != 0:
            self.ssh.run_sudo_command(f"docker logs --tail 120 {self.CERTBOT_CONTAINER_NAME} 2>/dev/null || true")
            self.ssh.run_sudo_command(f"docker rm -fv {self.CERTBOT_CONTAINER_NAME} || true")
            self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} || true")
            self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} || true")
            return {
                'status': 'error',
                'message': f"Let's Encrypt certificate issue failed. Make sure {domain} points to this server and port 80 is reachable. {err or out}",
            }

        self._write_file(self.NGINX_CONF_PATH, self._build_ssl_config(domain, port))
        _, err, code = self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} nginx -t", timeout=30)
        if code != 0:
            return {'status': 'error', 'message': f'Generated NGINX config is invalid: {err}'}
        self.ssh.run_sudo_command(f"docker exec {self.CONTAINER_NAME} nginx -s reload")

        url = self._site_url(domain, port)
        return {
            'status': 'success',
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.CONTAINER_NAME,
            'certbot_container_name': self.CERTBOT_CONTAINER_NAME,
            'certbot_running': self.check_certbot_running(),
            'port': port,
            'domain': domain,
            'email': email,
            'site_url': url,
            'message': 'NGINX web server installed',
            'log': [
                f'NGINX HTTPS port: {port}/TCP',
                'Port 80/TCP is used for Let\'s Encrypt HTTP-01 validation',
                f'Certificate issued for {domain}',
                f'Auto-renewal container: {self.CERTBOT_CONTAINER_NAME}',
                f'Site URL: {url}',
            ],
        }

    def remove_container(self, protocol_type='nginx'):
        self.ssh.run_sudo_command(f"docker stop {self.CERTBOT_CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CERTBOT_CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} || true")
        self.ssh.run_sudo_command(f"rm -rf {self.BASE_DIR}")
        return True
