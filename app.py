import os
import sys
import json
import logging
import base64
import hashlib
import secrets
import uuid
import asyncio
import math
import platform
import re
import shutil
import shlex
import tempfile
import subprocess
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
import signal
import socket
import struct
import zlib
import ipaddress
from datetime import datetime, timedelta, timezone
import io
from fastapi.responses import (JSONResponse, RedirectResponse, HTMLResponse, StreamingResponse,
                               FileResponse, PlainTextResponse)
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Request, Query, UploadFile, File, Form
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field, StrictBool, constr, conint
from typing import Optional, List, Dict
import uvicorn
import httpx

try:
    from multicolorcaptcha import CaptchaGenerator
except ImportError:
    CaptchaGenerator = None

from managers.ssh_manager import SSHManager
from managers import ssh_trust
from managers.awg_manager import AWGManager, normalize_special_junk
from managers.xray_manager import XrayManager
from managers.wireguard_manager import WireGuardManager
from managers.backup_manager import BackupManager
import telegram_bot as tg_bot

from exit_link_service import ExitLinkError, ExitLinkService
from smartroute_service import SmartRouteError, SmartRouteService
from mail_service import (
    DEFAULT_MAIL_SETTINGS,
    MailError,
    MailOptions,
    MailService,
    merge_mail_settings,
)
from pwa import build_manifest
from captcha_challenges import captcha_challenges
from user_state import reconcile_user_state, apply_traffic_samples, traffic_server_identity
from connection_service import (
    ConnectionService,
    DEFAULT_SELF_SERVICE_SETTINGS,
    RateLimitError,
    SelfServiceError,
    sanitize_allowed_protocols,
    self_service_protocol_choices,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ordered list of OpenAPI tag groups — the order here drives the section order in /docs and /redoc.
OPENAPI_TAGS = [
    {"name": "System Templates", "description": "HTML pages served to browsers. These return Jinja-rendered templates rather than a JSON contract — they are not part of the public API and are listed here only for completeness."},
    {"name": "Authentication", "description": "Login, captcha, and session lifecycle."},
    {"name": "Servers", "description": "Server inventory, lifecycle and host-level operations (add, edit, delete, ping, reorder, reboot, clear, stats, status check)."},
    {"name": "Protocols", "description": "Install, uninstall, container start/stop and raw config editing for the protocols/services on a server (AWG, Xray, WireGuard, Telemt, AmneziaDNS, AdGuard Home, SOCKS5, Exit node)."},
    {"name": "Connections", "description": "Per-protocol VPN client connections on a server (CRUD plus enable/disable and config retrieval)."},
    {"name": "Users", "description": "Panel user accounts and the connections assigned to them."},
    {"name": "Self-service", "description": "Endpoints called by a regular user for their own data (the /my surface)."},
    {"name": "Sharing", "description": "Public, token-protected configuration sharing for end users — no panel session required."},
    {"name": "Settings", "description": "Panel-wide settings, Telegram bot, Remnawave sync, JSON backup/restore."},
    {"name": "Email", "description": "SMTP delivery of configs and proxy links — to one user or to every user with an address."},
    {"name": "API Tokens", "description": "Bearer tokens for external integrations. Send the token in `Authorization: Bearer <token>`; tokens have admin-equivalent rights and are tied to the admin user that created them."},
]

app = FastAPI(
    title="Amnezia Web Panel",
    openapi_tags=OPENAPI_TAGS,
    # FastAPI's stock /redoc loads the JS bundle from `redoc@next` on jsdelivr —
    # an unstable rolling tag that breaks unpredictably. Disable the default and
    # serve our own /redoc just below, pinned to the stable v2 bundle.
    redoc_url=None,
)


@app.exception_handler(Exception)
async def api_json_error_handler(request: Request, exc: Exception):
    """Answer /api/* with JSON even when a handler blew up.

    Without this Starlette returns a plain-text "Internal Server Error", and
    every caller that does `await res.json()` fails with a parse error that
    says nothing about what went wrong ("JSON.parse: unexpected character at
    line 1 column 1"). Pages keep the plain-text response - a browser showing
    an error page is fine.
    """
    logger.exception(f"Unhandled error on {request.method} {request.url.path}")
    if request.url.path.startswith('/api/'):
        return JSONResponse({'error': 'Internal server error'}, status_code=500)
    return PlainTextResponse('Internal Server Error', status_code=500)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    """Self-curated ReDoc page. Differs from FastAPI's default in two ways:
    pinned bundle (`redoc@2` instead of `@next`) and Google Fonts disabled
    (the Montserrat/Roboto stylesheet is blocked on a lot of networks and made
    the page hang for some users)."""
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} — ReDoc",
        redoc_js_url="/static/vendor/redoc/redoc.standalone.js",
        with_google_fonts=False,
    )


@app.middleware("http")
async def noindex_middleware(request, call_next):
    """Keep every panel page out of search indexes.

    The panel is an admin tool, often exposed on a public domain (e.g. a
    DuckDNS name). Without this header a reachable instance can end up in
    search results, advertising its login page to scanners. noindex/nofollow
    via X-Robots-Tag covers HTML pages, API responses and error pages alike.
    """
    response = await call_next(request)
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    """Politely ask crawlers to stay away (X-Robots-Tag above is the real lock;
    robots.txt is only a hint and gets ignored by some bots)."""
    return PlainTextResponse("User-agent: *\nDisallow: /\n")

DOCS_PATHS = ('/docs', '/redoc', '/openapi.json')


@app.middleware("http")
async def docs_auth_middleware(request, call_next):
    """Serve the API schema only to authenticated admins.

    The OpenAPI document is a ready-made map of every endpoint and
    parameter of the panel; leaving it open to anonymous visitors hands
    scanners the feature list for free. Session cookie or admin Bearer
    token both count.
    """
    if request.url.path in DOCS_PATHS and not _check_admin(request):
        if request.url.path == '/openapi.json':
            return JSONResponse({'error': 'Forbidden'}, status_code=403)
        return RedirectResponse('/login')
    return await call_next(request)

# Sessions must wrap every other middleware: docs_auth_middleware above
# reads request.session, so SessionMiddleware has to sit outside it.
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)))

class CachedStaticFiles(StaticFiles):
    """Static assets that carry ?v=<static mtime> (see static_version()) change
    their URL on every redeploy, so they can be cached for 180 days. Assets
    referenced without that query - the favicon, the icons, qrcode.min.js,
    searchable-select.js, the vendored CodeMirror and ReDoc bundles - keep the
    same URL forever, so an immutable lifetime would freeze them in the
    browser until it expires. Those get an hour and a revalidation instead."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            query = urllib.parse.parse_qsl(scope.get('query_string', b'').decode('latin-1'))
            fingerprinted = any(key == 'v' for key, _value in query)
            response.headers['Cache-Control'] = (
                'public, max-age=15552000, immutable' if fingerprinted
                else 'public, max-age=3600, must-revalidate')
        return response

# Bundled resources live beside __file__, not beside the PyInstaller executable.
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", CachedStaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(__file__)

DATA_FILE = os.path.abspath(os.path.expanduser(
    os.environ.get('DATA_FILE') or os.path.join(application_path, 'data.json')
))
ssh_trust.configure(DATA_FILE)
CURRENT_VERSION = "v1.8.3"

# Custom protocol instance names: the rename modal caps input at 64 chars.
CUSTOM_PROTOCOL_NAME_MAX = 64
BIN_DIR = os.environ.get('TUNNEL_BIN_DIR', os.path.join(application_path, 'bin'))
TUNNEL_STATE_FILE = os.environ.get('TUNNEL_STATE_FILE', os.path.join(application_path, 'tunnels_state.json'))


class TunnelRuntime:
    def __init__(self):
        self.process = None
        self.pid = None
        self.public_url = ''
        self.last_error = ''
        self.started_at = None
        self.output = []


TUNNEL_RUNTIMES = {
    'cloudflare': TunnelRuntime(),
    'ngrok': TunnelRuntime(),
}
TUNNEL_LOCK = threading.Lock()
TUNNEL_URL_RE = re.compile(r'https://[^\s"\']+')
WARP_CLI_COMMAND = 'warp-cli.exe' if os.name == 'nt' else 'warp-cli'



# ======================== Translations ========================
TRANSLATIONS = {}

def load_translations():
    global TRANSLATIONS
    trans_dir = os.path.join(os.path.dirname(__file__), 'translations')
    if os.path.exists(trans_dir):
        for f in os.listdir(trans_dir):
            if f.endswith('.json'):
                lang = f.split('.')[0]
                try:
                    with open(os.path.join(trans_dir, f), 'r', encoding='utf-8') as tf:
                        TRANSLATIONS[lang] = json.load(tf)
                except Exception as e:
                    logger.error(f"Error loading translation {f}: {e}")
    logger.info(f"Loaded translations: {list(TRANSLATIONS.keys())}")

def _t(text_id, lang='en'):
    lang_batch = TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))
    return lang_batch.get(text_id, text_id)

load_translations()


# ======================== Helpers ========================

# Global lock for data.json access to prevent race conditions during async operations
from peer_lifecycle_lock import serialize_peer_lifecycle
import peer_lifecycle_lock
from peer_accounting import guard_user_deletions
from peer_recovery import (RecoveryStore, RecoveryError, PanelLease, STATE_FILE_LOCK,
                           GENERATION, digest as recovery_digest, orphan_scope, validate_backup)
from peer_recovery import verify_awg_peer_absent, check_create_journal, require_repair_target, DISASTER_HOLD
from peer_finalization import (
    FinalizationError,
    connection_scope,
    find_connection,
    read_peer_state,
    finalize_connection_record,
    commit_finalize,
    make_intent,
)

peer_lifecycle_lock.configure(DATA_FILE)
_panel_lease = None

DATA_LOCK = asyncio.Lock()
# Serialize overlapping traffic collection/commit cycles.
_TRAFFIC_SYNC_LOCK = asyncio.Lock()
# Inventory/identity operations may await SSH; unrelated JSON updates stay free.
SERVER_MUTATION_LOCK = asyncio.Lock()


@app.on_event('shutdown')
async def close_panel_lease():
    if _panel_lease is not None:
        _panel_lease.close()


@app.exception_handler(peer_lifecycle_lock.PeerLifecycleBusy)
async def lifecycle_busy_response(request, error):
    return JSONResponse({'error': 'A lifecycle operation is still running. Retry later.',
                         'code': str(error)}, status_code=503, headers={'Retry-After': '10'})


@app.exception_handler(peer_lifecycle_lock.PeerLifecycleUncertain)
async def lifecycle_uncertain_response(request, error):
    return JSONResponse({'error': 'An SSH result is unknown. Administrator recovery is required.',
                         'code': error.code}, status_code=503)


def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = {}
    data.setdefault('servers', [])
    data.setdefault('users', [])
    data.setdefault('user_connections', [])
    data.setdefault('api_tokens', [])
    settings = data.setdefault('settings', {})
    settings.setdefault('appearance', {
        'title': 'Amnezia',
        'logo': '❤️',
        'subtitle': 'Web Panel'
    })
    settings.setdefault('sync', {
        'remnawave_url': '',
        'remnawave_api_key': '',
        'remnawave_sync': False,
        'remnawave_sync_users': False,
        'remnawave_create_conns': False,
        'remnawave_server_id': 0,
        'remnawave_protocol': 'awg'
    })
    settings.setdefault('captcha', {'enabled': False})
    settings.setdefault('exit_nodes', {'default_exit_uid': ''})
    settings.setdefault('telegram', {'token': '', 'enabled': False})
    mail = settings.setdefault('mail', dict(DEFAULT_MAIL_SETTINGS))
    for key, value in DEFAULT_MAIL_SETTINGS.items():
        mail.setdefault(key, value)
    settings.setdefault('ssl', {
        'enabled': False,
        'domain': '',
        'cert_path': '',
        'key_path': '',
        'cert_text': '',
        'key_text': '',
        'panel_port': 5000
    })
    settings.setdefault('auto_backup', {
        'enabled': False,
        'interval_hours': 24,
        'last_run_at': None,
        'last_status': None,
        'last_created_count': 0,
        'last_error': None
    })
    self_service = data['settings'].setdefault('self_service', dict(DEFAULT_SELF_SERVICE_SETTINGS))
    for key, value in DEFAULT_SELF_SERVICE_SETTINGS.items():
        self_service.setdefault(key, value)
    for server in data.get('servers', []):
        server.setdefault('self_service_enabled', False)
        # Legacy RKN toggle: the blocking contour is now a marketplace app
        # (server['rknblock']). The old flag is dropped so every server shows
        # "not installed" until the app is installed from the store.
        server.pop('rkn_block_enabled', None)
    return data


def save_data(data):
    # Keep this writer self-contained for isolated handler/AST tests as well.
    from peer_recovery import STATE_FILE_LOCK, GENERATION, RecoveryError, atomic_json
    with STATE_FILE_LOCK:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r', encoding='utf-8') as source:
                generation = json.load(source).get(GENERATION)
            if generation and data.get(GENERATION) != generation:
                raise RecoveryError('stale_snapshot_after_recovery')
        os.makedirs(os.path.dirname(DATA_FILE) or '.', exist_ok=True)
        atomic_json(DATA_FILE, data)


async def save_data_async(data):
    """Saves data to file in a thread-safe way."""
    async with DATA_LOCK:
        await asyncio.to_thread(save_data, data)


# Long-lived SSH connections, keyed by (host, port, username). Each command
# becomes a cheap channel on an existing transport instead of a full TCP+SSH
# handshake per API call — the main fix for UI timeouts on distant servers.
_SSH_POOL = {}
_SSH_POOL_LOCK = threading.Lock()


def get_ssh(server):
    key = (server['host'], int(server.get('ssh_port', 22)), server['username'])
    cooldown_base = float(server.get('ssh_cooldown_base') or 30)
    with _SSH_POOL_LOCK:
        ssh = _SSH_POOL.get(key)
        if ssh is None:
            ssh = SSHManager(
                host=server['host'],
                port=server.get('ssh_port', 22),
                username=server['username'],
                password=server.get('password'),
                private_key=server.get('private_key'),
                connect_cooldown_base=cooldown_base,
            )
            _SSH_POOL[key] = ssh
        # Apply edits without dropping the pooled connection.
        ssh._connect_cooldown_base = cooldown_base
        ssh.pooled = True
    ssh.ensure_connected()
    return ssh


def drop_ssh(server):
    """Remove a server's pooled connection (on edit/delete) and close it."""
    key = (server['host'], int(server.get('ssh_port', 22)), server['username'])
    with _SSH_POOL_LOCK:
        ssh = _SSH_POOL.pop(key, None)
    if ssh is not None:
        try:
            ssh.force_disconnect()
        except Exception:
            pass


def get_panel_local_url(request: Optional[Request] = None):
    data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {})
    scheme = 'https' if ssl_conf.get('enabled') else 'http'
    host = '127.0.0.1'
    port = ssl_conf.get('panel_port', 5000) or 5000
    if request:
        scheme = request.url.scheme or scheme
        host = request.url.hostname or host
        port = request.url.port or port
    return f"{scheme}://{host}:{port}"


def get_panel_tunnel_target_url():
    data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {})
    scheme = 'https' if ssl_conf.get('enabled') else 'http'
    port = ssl_conf.get('panel_port', 5000) or 5000
    return f"{scheme}://127.0.0.1:{port}"


def get_warp_cli_binary():
    found = shutil.which(WARP_CLI_COMMAND)
    if found:
        return found
    if os.name == 'nt':
        for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')):
            if not base:
                continue
            candidate = os.path.join(base, 'Cloudflare', 'Cloudflare WARP', 'warp-cli.exe')
            if os.path.exists(candidate):
                return candidate
    return None


def is_warp_cli_installed():
    return bool(get_warp_cli_binary())


def _warp_install_hint():
    system = platform.system().lower()
    if system == 'windows':
        return 'Install Cloudflare WARP from https://1.1.1.1/ or winget install Cloudflare.Warp, then restart this panel.'
    if system == 'darwin':
        return 'Install Cloudflare WARP from https://1.1.1.1/ or brew install --cask cloudflare-warp, then restart this panel.'
    return 'Install the official cloudflare-warp package for your Linux distribution, start warp-svc, then restart this panel.'


def run_warp_cli(*args, timeout: int = 12):
    binary = get_warp_cli_binary()
    if not binary:
        raise RuntimeError(_warp_install_hint())
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    command = [binary]
    if '--accept-tos' not in args:
        command.append('--accept-tos')
    command.extend(args)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=timeout,
        creationflags=creationflags,
    )
    output = '\n'.join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    if result.returncode != 0:
        raise RuntimeError(output or f'warp-cli exited with code {result.returncode}')
    return output


def _parse_warp_status(output: str):
    lowered = (output or '').lower()
    if 'registration missing' in lowered or 'not registered' in lowered or 'not enrolled' in lowered:
        return 'not_registered'
    if 'disconnect' in lowered or 'disabled' in lowered:
        return 'disconnected'
    if 'connecting' in lowered:
        return 'connecting'
    if 'connected' in lowered:
        return 'connected'
    return 'unknown'


def get_warp_status():
    installed = is_warp_cli_installed()
    status = {
        'installed': installed,
        'running': False,
        'connected': False,
        'status': 'not_installed' if not installed else 'unknown',
        'raw': '',
        'last_error': '' if installed else _warp_install_hint(),
        'install_hint': _warp_install_hint(),
    }
    if not installed:
        return status
    try:
        output = run_warp_cli('status')
        parsed = _parse_warp_status(output)
        status.update({
            'running': parsed in ('connected', 'connecting'),
            'connected': parsed == 'connected',
            'status': parsed,
            'raw': output,
            'last_error': '',
        })
    except Exception as e:
        status['last_error'] = str(e)
        lowered = str(e).lower()
        if 'registration missing' in lowered or 'not registered' in lowered or 'not enrolled' in lowered:
            status['status'] = 'not_registered'
        elif 'service' in lowered or 'daemon' in lowered or 'warp-svc' in lowered:
            status['status'] = 'service_unavailable'
        else:
            status['status'] = 'error'
    return status


def enable_warp():
    current = get_warp_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _warp_install_hint())
    try:
        if current.get('status') == 'not_registered':
            run_warp_cli('registration', 'new', timeout=30)
        run_warp_cli('mode', 'warp', timeout=15)
        run_warp_cli('connect', timeout=30)
    except Exception as e:
        message = str(e)
        if 'registration' in message.lower() or 'not registered' in message.lower() or 'not enrolled' in message.lower():
            run_warp_cli('registration', 'new', timeout=30)
            run_warp_cli('mode', 'warp', timeout=15)
            run_warp_cli('connect', timeout=30)
        else:
            raise
    time.sleep(1)
    return get_warp_status()


def disable_warp():
    current = get_warp_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _warp_install_hint())
    run_warp_cli('disconnect', timeout=20)
    time.sleep(0.5)
    return get_warp_status()


def get_tunnel_command_name(provider: str):
    if provider == 'cloudflare':
        return 'cloudflared.exe' if os.name == 'nt' else 'cloudflared'
    if provider == 'ngrok':
        return 'ngrok.exe' if os.name == 'nt' else 'ngrok'
    raise ValueError('Unsupported tunnel provider')


def get_tunnel_binary_path(provider: str):
    return os.path.join(BIN_DIR, get_tunnel_command_name(provider))


def find_tunnel_binary(provider: str):
    bundled = get_tunnel_binary_path(provider)
    if os.path.exists(bundled):
        return bundled
    return shutil.which(get_tunnel_command_name(provider))


def is_tunnel_installed(provider: str):
    return bool(find_tunnel_binary(provider))


def load_tunnel_state():
    if not os.path.exists(TUNNEL_STATE_FILE):
        return {}
    try:
        with open(TUNNEL_STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load tunnel state: {e}")
        return {}


def save_tunnel_state(state):
    with open(TUNNEL_STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def update_tunnel_state(provider: str, **updates):
    state = load_tunnel_state()
    provider_state = state.get(provider, {})
    provider_state.update(updates)
    state[provider] = provider_state
    save_tunnel_state(state)


def clear_tunnel_state(provider: str):
    state = load_tunnel_state()
    if provider in state:
        state.pop(provider)
        save_tunnel_state(state)


def pid_is_running(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False
    except Exception:
        return False


def kill_pid(pid):
    if not pid:
        return
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not pid_is_running(pid):
                return
            time.sleep(0.2)
    else:
        try:
            os.kill(int(pid), signal.SIGTERM)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not pid_is_running(pid):
                    return
                time.sleep(0.2)
            if pid_is_running(pid):
                os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            return


def wait_for_path_release(path, seconds: int = 5):
    if os.name != 'nt':
        return
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if not os.path.exists(path):
                return
            with open(path, 'ab'):
                return
        except PermissionError:
            time.sleep(0.25)


def find_running_tunnel_pids_in_proc(provider: str, binary_path: str = ''):
    proc_dir = '/proc'
    if os.name == 'nt' or not os.path.isdir(proc_dir):
        return []
    command_name = get_tunnel_command_name(provider).lower()
    command_base = command_name.replace('.exe', '')
    markers = ['tunnel', '--url'] if provider == 'cloudflare' else ['http']
    expected_binary = os.path.abspath(binary_path).lower() if binary_path else ''
    pids = []
    try:
        for entry in os.listdir(proc_dir):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == os.getpid():
                continue
            cmdline_path = os.path.join(proc_dir, entry, 'cmdline')
            try:
                with open(cmdline_path, 'rb') as f:
                    cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            except Exception:
                continue
            lowered = cmdline.lower()
            exe_path = ''
            try:
                exe_path = os.path.abspath(os.readlink(os.path.join(proc_dir, entry, 'exe'))).lower()
            except Exception:
                pass
            path_matches = bool(expected_binary and exe_path == expected_binary)
            command_matches = (command_name in lowered or command_base in lowered) and all(marker in lowered for marker in markers)
            if path_matches or command_matches:
                if pid_is_running(pid):
                    pids.append(pid)
    except Exception as e:
        logger.debug(f"Failed to scan /proc for running {provider} tunnel process: {e}")
    return pids


def find_running_tunnel_pids(provider: str, binary_path: str = ''):
    command_name = get_tunnel_command_name(provider).lower()
    process_name = command_name[:-4] if command_name.endswith('.exe') else command_name
    markers = ['tunnel', '--url'] if provider == 'cloudflare' else ['http']
    expected_binary = os.path.normcase(os.path.abspath(binary_path or get_tunnel_binary_path(provider)))
    pids = []
    try:
        if os.name == 'nt':
            ps_script = f"Get-CimInstance Win32_Process -Filter \"name='{command_name}'\" | Select-Object ProcessId,CommandLine,ExecutablePath | ConvertTo-Json -Compress"
            result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            rows = []
            if result.returncode == 0 and result.stdout.strip():
                payload = json.loads(result.stdout)
                if payload:
                    rows = payload if isinstance(payload, list) else [payload]
            if not rows:
                ps_script = f"Get-Process -Name '{process_name}' -ErrorAction SilentlyContinue | Select-Object Id,Path | ConvertTo-Json -Compress"
                result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    payload = json.loads(result.stdout)
                    proc_rows = payload if isinstance(payload, list) else ([payload] if payload else [])
                    rows = [{'ProcessId': r.get('Id'), 'ExecutablePath': r.get('Path'), 'CommandLine': ''} for r in proc_rows]
            for row in rows:
                if not row:
                    continue
                pid = int(row.get('ProcessId') or 0)
                command_line = str(row.get('CommandLine') or '').lower()
                executable = os.path.normcase(os.path.abspath(str(row.get('ExecutablePath') or ''))) if row.get('ExecutablePath') else ''
                path_matches = bool(expected_binary and executable == expected_binary)
                command_matches = command_name in command_line and all(marker in command_line for marker in markers)
                if pid and pid != os.getpid() and (path_matches or command_matches) and pid_is_running(pid):
                    pids.append(pid)
            if not pids and os.path.exists(expected_binary):
                result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {command_name}', '/FO', 'CSV', '/NH'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
                for line in result.stdout.splitlines():
                    match = re.match(r'"[^"]+","(\d+)"', line.strip())
                    if match:
                        pid = int(match.group(1))
                        if pid != os.getpid() and pid_is_running(pid):
                            pids.append(pid)
            return list(dict.fromkeys(pids))
        else:
            result = subprocess.run(
                ['ps', '-eo', 'pid=,args='],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=5,
            )
            lines = result.stdout.splitlines()

        for line in lines:
            text = line.strip()
            lowered = text.lower()
            if command_name not in lowered or not all(marker in lowered for marker in markers):
                continue
            pid_match = re.match(r'\s*(\d+)\s+', text)
            if pid_match:
                pid = int(pid_match.group(1))
                if pid != os.getpid() and pid_is_running(pid):
                    pids.append(pid)
    except Exception as e:
        logger.debug(f"Failed to scan running {provider} tunnel process: {e}")
    pids.extend(find_running_tunnel_pids_in_proc(provider, expected_binary))
    return list(dict.fromkeys(pids))


def find_running_tunnel_pid(provider: str):
    pids = find_running_tunnel_pids(provider)
    return pids[0] if pids else None


def kill_tunnel_processes(provider: str, binary_path: str = '', include_all_by_name: bool = False):
    pids = find_running_tunnel_pids(provider, binary_path)
    for pid in pids:
        kill_pid(pid)
    if os.name == 'nt' and include_all_by_name:
        subprocess.run(['taskkill', '/IM', get_tunnel_command_name(provider), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return pids


def get_tunnel_download(provider: str):
    system = platform.system().lower()
    machine = platform.machine().lower()

    if provider == 'cloudflare':
        if system == 'windows':
            arch = 'amd64' if machine in ('amd64', 'x86_64') else '386'
            return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-{arch}.exe', 'exe'
        if system == 'darwin':
            arch = 'arm64' if 'arm' in machine else 'amd64'
            return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-{arch}.tgz', 'tgz'
        arch = 'arm64' if 'aarch64' in machine or 'arm64' in machine else 'amd64'
        return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}', 'bin'

    if provider == 'ngrok':
        if system == 'windows':
            os_part = 'windows'
            ext = 'zip'
        elif system == 'darwin':
            os_part = 'darwin'
            ext = 'zip'
        else:
            os_part = 'linux'
            ext = 'tgz'
        arch = 'arm64' if 'aarch64' in machine or 'arm64' in machine else 'amd64'
        return f'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-{os_part}-{arch}.{ext}', ext

    raise ValueError('Unsupported tunnel provider')


def install_tunnel_binary(provider: str):
    if is_tunnel_installed(provider):
        return find_tunnel_binary(provider)

    os.makedirs(BIN_DIR, exist_ok=True)
    url, archive_type = get_tunnel_download(provider)
    target = get_tunnel_binary_path(provider)
    tmp_path = os.path.join(BIN_DIR, f'{provider}.download')
    logger.info(f"Downloading {provider} tunnel binary from {url}")
    urllib.request.urlretrieve(url, tmp_path)

    if archive_type in ('bin', 'exe'):
        shutil.move(tmp_path, target)
    elif archive_type == 'zip':
        with zipfile.ZipFile(tmp_path) as zf:
            member = next((m for m in zf.namelist() if os.path.basename(m).lower() == get_tunnel_command_name(provider).lower()), None)
            if not member:
                raise RuntimeError(f'{provider} binary not found in downloaded archive')
            with zf.open(member) as src, open(target, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        os.remove(tmp_path)
    elif archive_type == 'tgz':
        with tarfile.open(tmp_path, 'r:gz') as tf:
            member = next((m for m in tf.getmembers() if os.path.basename(m.name).lower() == get_tunnel_command_name(provider).lower()), None)
            if not member:
                raise RuntimeError(f'{provider} binary not found in downloaded archive')
            extracted = tf.extractfile(member)
            if not extracted:
                raise RuntimeError(f'Cannot extract {provider} binary')
            with extracted as src, open(target, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        os.remove(tmp_path)
    else:
        raise RuntimeError(f'Unsupported download format: {archive_type}')

    if os.name != 'nt':
        os.chmod(target, 0o755)
    return target


def get_tunnel_public_urls(provider: str, runtime: TunnelRuntime):
    urls = []
    if runtime.public_url:
        urls.append(runtime.public_url)
    state_url = load_tunnel_state().get(provider, {}).get('public_url')
    if state_url:
        urls.append(state_url)
    if provider == 'ngrok' and runtime.process and runtime.process.poll() is None:
        try:
            with urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=1) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
            for item in payload.get('tunnels', []):
                public_url = item.get('public_url')
                if public_url and public_url.startswith('https://'):
                    urls.append(public_url)
        except Exception:
            pass
    return list(dict.fromkeys(urls))


def watch_tunnel_output(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    process = runtime.process
    if not process or not process.stdout:
        return
    try:
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            text = line.strip()
            with TUNNEL_LOCK:
                runtime.output.append(text)
                runtime.output = runtime.output[-60:]
                match = TUNNEL_URL_RE.search(text)
                if match:
                    runtime.public_url = match.group(0).rstrip('.,')
                    update_tunnel_state(provider, public_url=runtime.public_url)
    except Exception as e:
        with TUNNEL_LOCK:
            runtime.last_error = str(e)


def build_tunnel_command(provider: str, binary: str, local_url: str, authtoken: str = ''):
    if provider == 'cloudflare':
        return [binary, 'tunnel', '--url', local_url, '--no-autoupdate']
    if provider == 'ngrok':
        cmd = [binary, 'http', local_url, '--log=stdout']
        return cmd
    raise ValueError('Unsupported tunnel provider')


def start_tunnel(provider: str, local_url: str, authtoken: str = ''):
    binary = find_tunnel_binary(provider)
    if not binary:
        raise RuntimeError(f'{provider} is not installed')

    runtime = TUNNEL_RUNTIMES[provider]
    with TUNNEL_LOCK:
        if runtime.process and runtime.process.poll() is None:
            return runtime
        runtime.public_url = ''
        runtime.last_error = ''
        runtime.output = []
        runtime.started_at = datetime.now().isoformat()

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        env = os.environ.copy()
        if provider == 'ngrok' and authtoken:
            env['NGROK_AUTHTOKEN'] = authtoken

        runtime.process = subprocess.Popen(
            build_tunnel_command(provider, binary, local_url, authtoken),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=application_path,
            env=env,
            creationflags=creationflags,
        )
        runtime.pid = runtime.process.pid
        update_tunnel_state(
            provider,
            pid=runtime.pid,
            public_url='',
            started_at=runtime.started_at,
            binary=os.path.abspath(binary),
        )

    threading.Thread(target=watch_tunnel_output, args=(provider,), daemon=True).start()
    return runtime


def stop_tunnel(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    process = runtime.process
    state = load_tunnel_state().get(provider, {})
    pids_to_stop = []
    if process and process.poll() is None:
        pids_to_stop.append(process.pid)
        try:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        except Exception as e:
            with TUNNEL_LOCK:
                runtime.last_error = str(e)
            raise
    if state.get('pid') and pid_is_running(state.get('pid')):
        pids_to_stop.append(state.get('pid'))
    pids_to_stop.extend(find_running_tunnel_pids(provider, state.get('binary') or get_tunnel_binary_path(provider)))
    for pid in dict.fromkeys(pids_to_stop):
        if pid_is_running(pid):
            kill_pid(pid)

    with TUNNEL_LOCK:
        runtime.process = None
        runtime.pid = None
        runtime.public_url = ''
        runtime.started_at = None
        runtime.last_error = ''
    clear_tunnel_state(provider)
    return runtime


def delete_tunnel_binary(provider: str):
    stop_tunnel(provider)
    bundled = get_tunnel_binary_path(provider)
    if os.path.exists(bundled):
        wait_for_path_release(bundled, seconds=8)
        try:
            os.remove(bundled)
        except PermissionError:
            killed = kill_tunnel_processes(provider, bundled, include_all_by_name=True)
            if killed:
                wait_for_path_release(bundled, seconds=8)
            try:
                os.remove(bundled)
            except PermissionError:
                raise RuntimeError('Cannot delete tunnel binary because Windows still keeps it locked. All detected cloudflared/ngrok processes were stopped; close any antivirus scan, terminal, or external process using the file and try again.')
    elif shutil.which(get_tunnel_command_name(provider)):
        raise RuntimeError('This tunnel binary is installed system-wide. Remove it from PATH manually or use the panel-managed installation.')

    tmp_path = os.path.join(BIN_DIR, f'{provider}.download')
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    runtime = TUNNEL_RUNTIMES[provider]
    with TUNNEL_LOCK:
        runtime.output = []
    clear_tunnel_state(provider)
    return runtime


def get_tunnel_status(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    state = load_tunnel_state().get(provider, {})
    running = bool(runtime.process and runtime.process.poll() is None)
    if not running and state.get('pid'):
        running = pid_is_running(state.get('pid'))
        if running:
            runtime.pid = state.get('pid')
            runtime.started_at = runtime.started_at or state.get('started_at')
            runtime.public_url = runtime.public_url or state.get('public_url', '')
        else:
            clear_tunnel_state(provider)
            state = {}
    if not running and is_tunnel_installed(provider):
        found_pid = find_running_tunnel_pid(provider)
        if found_pid:
            running = True
            runtime.pid = found_pid
            runtime.started_at = runtime.started_at or datetime.now().isoformat()
            update_tunnel_state(
                provider,
                pid=found_pid,
                public_url=runtime.public_url,
                started_at=runtime.started_at,
                binary=os.path.abspath(find_tunnel_binary(provider) or ''),
            )
            state = load_tunnel_state().get(provider, {})
    if runtime.process and not running and not runtime.last_error and runtime.output:
        runtime.last_error = runtime.output[-1]
    urls = get_tunnel_public_urls(provider, runtime)
    return {
        'installed': is_tunnel_installed(provider),
        'running': running,
        'public_url': urls[0] if urls else '',
        'public_urls': urls,
        'last_error': runtime.last_error,
        'started_at': runtime.started_at or state.get('started_at'),
    }


async def wait_for_tunnel_url(provider: str, seconds: int = 20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = get_tunnel_status(provider)
        if status.get('public_url') or not status.get('running'):
            return status
        await asyncio.sleep(0.5)
    return get_tunnel_status(provider)


BASE_PROTOCOLS = ['awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'dns', 'wireguard', 'socks5', 'adguard', 'nginx', 'exit']
MULTI_INSTANCE_PROTOCOLS = {'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'socks5'}


def backfill_server_uids(servers) -> bool:
    """Give every server record without a stable `uid` one; return True when
    something changed. Only write paths call this (startup migration,
    add-server, backup restore): minting ids inside load_data() would let two
    concurrent readers hand out different uids for the same record."""
    changed = False
    for server in servers or []:
        if not server.get('uid'):
            server['uid'] = uuid.uuid4().hex
            changed = True
    return changed


def should_link_default_exit(default_uid, server_uid, is_awg, reinstall, previous_link):
    """Whether a just-installed instance should join the default exit node:
    only a newly added AWG instance on another server, and only when nothing
    (a link of its own, or an earlier deliberate unlink) already speaks for it."""
    return bool(default_uid) and is_awg and not reinstall and not previous_link \
        and default_uid != server_uid


def find_server_by_uid(data, uid):
    """Return (index, server) for a stable server uid, or (None, None) when the
    uid is empty or unknown. Index-based server_id values shift on reorder and
    delete, so cross-server references must resolve through this instead."""
    if not uid:
        return None, None
    for idx, server in enumerate(data.get('servers', []) or []):
        if server.get('uid') == uid:
            return idx, server
    return None, None


def protocol_base(protocol: str) -> str:
    return str(protocol or 'awg').split('__', 1)[0]


def protocol_instance(protocol: str) -> int:
    parts = str(protocol or '').split('__', 1)
    if len(parts) == 2:
        try:
            return max(1, int(parts[1]))
        except ValueError:
            return 1
    return 1


def protocol_key(base: str, instance: int = 1) -> str:
    base = protocol_base(base)
    return base if int(instance or 1) <= 1 else f'{base}__{int(instance)}'


def next_protocol_key(protocols: dict, base: str) -> str:
    base = protocol_base(base)
    used = {protocol_instance(k) for k in (protocols or {}).keys() if protocol_base(k) == base}
    idx = 1
    while idx in used:
        idx += 1
    return protocol_key(base, idx)


# The official Amnezia client has no separate AWG 3 container: it installs
# AWG 3.x into amnezia-awg2 and only the config (HeaderProtectionKey) differs.
AWG3_IN_AWG2_NAME = 'AmneziaWG 3 (amnezia-awg2)'


def is_awg3_in_awg2(protocol: str, header_protection=False) -> bool:
    return protocol_base(protocol) == 'awg2' and bool(header_protection)


def protocol_display_name(protocol: str, header_protection=False) -> str:
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    if is_awg3_in_awg2(protocol, header_protection):
        return AWG3_IN_AWG2_NAME if idx <= 1 else f'{AWG3_IN_AWG2_NAME} #{idx}'
    names = {
        'awg': 'AmneziaWG',
        'awg2': 'AmneziaWG 2.0',
        'awg3': 'AmneziaWG 3.1',
        'awg_legacy': 'AmneziaWG Legacy',
        'xray': 'Xray',
        'telemt': 'Telemt',
        'dns': 'AmneziaDNS',
        'wireguard': 'WireGuard',
        'socks5': 'SOCKS5',
        'adguard': 'AdGuard Home',
        'nginx': 'NGINX',
        'exit': 'Exit Node',
    }
    name = names.get(base, base)
    return name if idx <= 1 else f'{name} #{idx}'


def protocol_container_name(protocol: str) -> Optional[str]:
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    base_names = {
        'awg': 'amnezia-awg',
        'awg2': 'amnezia-awg2',
        'awg3': 'amnezia-awg3',
        'awg_legacy': 'amnezia-awg-legacy',
        'xray': 'amnezia-xray',
        'telemt': 'telemt',
        'dns': 'amnezia-dns',
        'wireguard': 'amnezia-wireguard',
        'socks5': 'amnezia-socks5proxy',
        'adguard': 'amnezia-adguard',
        'nginx': 'amnezia-nginx',
        'exit': 'amnezia-exit',
    }
    name = base_names.get(base)
    if not name:
        return None
    return name if idx <= 1 else f'{name}-{idx}'


def is_valid_protocol(protocol: str) -> bool:
    return protocol_base(protocol) in BASE_PROTOCOLS


def get_protocol_manager(ssh, protocol: str):
    base = protocol_base(protocol)
    if base == 'xray':
        from managers.xray_manager import XrayManager
        return XrayManager(ssh, protocol)
    elif base == 'telemt':
        from managers.telemt_manager import TelemtManager
        return TelemtManager(ssh, protocol)
    elif base == 'dns':
        from managers.dns_manager import DNSManager
        return DNSManager(ssh)
    elif base == 'wireguard':
        from managers.wireguard_manager import WireGuardManager
        return WireGuardManager(ssh)
    elif base == 'socks5':
        from managers.socks5_manager import Socks5Manager
        return Socks5Manager(ssh, protocol)
    elif base == 'adguard':
        from managers.adguard_manager import AdguardManager
        return AdguardManager(ssh)
    elif base == 'nginx':
        from managers.nginx_manager import NginxManager
        return NginxManager(ssh, protocol)
    elif base == 'exit':
        from managers.exit_manager import ExitManager
        return ExitManager(ssh, protocol)
    from managers.awg_manager import AWGManager
    return AWGManager(ssh)



def ensure_docker_installed(ssh):
    """Ensure Docker is installed and running before installing any protocol/service."""
    out, _, code = ssh.run_command("docker --version 2>/dev/null")
    if code == 0 and out.strip():
        status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        if 'active' in status or 'running' in status.lower():
            return 'Docker already installed'
        ssh.run_sudo_command("systemctl enable --now docker 2>/dev/null || service docker start 2>/dev/null || true", timeout=60)
        status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        if 'active' in status or 'running' in status.lower():
            return 'Docker service started'

    script = r"""
set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y docker.io
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker
elif command -v yum >/dev/null 2>&1; then
  yum install -y docker
elif command -v zypper >/dev/null 2>&1; then
  zypper --non-interactive refresh
  zypper --non-interactive install docker
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm --noprogressbar docker
else
  echo "Packet manager not found" >&2
  exit 1
fi
(systemctl enable --now docker || service docker start || true)
sleep 3
docker --version
"""
    out, err, code = ssh.run_sudo_script(script, timeout=300)
    if code != 0:
        raise RuntimeError(f"Failed to install Docker: {err or out}")
    status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
    if 'active' not in status and 'running' not in status.lower():
        raise RuntimeError("Docker installed but service is not running")
    return 'Docker installed successfully'


def _manager_call(manager, method, protocol, *args, **kwargs):
    """Unified call: WireGuard manager methods don't take protocol_type argument."""
    fn = getattr(manager, method)
    if isinstance(manager, WireGuardManager):
        return fn(*args, **kwargs)
    return fn(protocol, *args, **kwargs)


AWG_PROTOCOLS = ('awg', 'awg2', 'awg3', 'awg_legacy')


# A public host is an IP (v4, or v6 in the brackets an endpoint needs to stay
# readable next to the port) or a DNS name. Anything else -- a scheme, a path,
# a space, a bare IPv6 -- would be copied verbatim into client configs, where
# it reads as a valid endpoint and simply never connects.
PUBLIC_HOST_MAX = 253
PUBLIC_HOST_RE = re.compile(r'^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9._-]*)$')


def normalize_public_host(value):
    """Validated public host, or '' when the field is left empty."""
    host = str(value or '').strip()
    if not host:
        return ''
    if len(host) > PUBLIC_HOST_MAX or not PUBLIC_HOST_RE.match(host):
        raise ValueError('Public host must be an IP address or a host name')
    return host


def normalize_public_port(value):
    """Validated public port as a string, or '' when the field is left empty."""
    port = str(value or '').strip()
    if not port:
        return ''
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Public port must be a number between 1 and 65535')
    return port


def protocol_public_endpoint(server, protocol):
    """The address clients must dial for one protocol instance: (host, port).

    Both default to what the panel itself uses -- the server address it opens
    SSH to, and the instance's own listen port (the returned port is None then,
    so managers keep using it). An instance can live somewhere else: a second
    IP on the same box, a port forward, a domain name. `public_host` and
    `public_port` on the instance record carry that, and every config and link
    handed to a client follows them.
    """
    info = (server.get('protocols') or {}).get(protocol) or {}
    host = str(info.get('public_host') or '').strip() or server.get('host', '')
    public_port = str(info.get('public_port') or '').strip() or None
    return host, public_port


def join_dns(dns1, dns2):
    """Join the two DNS fields into the `a, b` form used in configs."""
    parts = [str(value).strip() for value in (dns1, dns2) if value and str(value).strip()]
    return ', '.join(parts) or None


def split_dns(dns):
    """Split a stored `a, b` DNS string back into two form fields."""
    parts = [part.strip() for part in str(dns or '').split(',') if part.strip()]
    parts += [''] * (2 - len(parts))
    return parts[0], parts[1]


def awg_special_junk_from(req):
    """Collect I1-I5 from a request, or None when the form sent none of them."""
    values = {key: getattr(req, f'awg_{key}', None) for key in ('i1', 'i2', 'i3', 'i4', 'i5')}
    if all(value is None for value in values.values()):
        return None
    return values


# Keys the desktop client treats as AmneziaWG-specific -- configKey::awgProtocolKeys()
# in client/core/utils/constants/configKeys.h. One of them in a config is what makes
# the client pick the awg container over the plain wireguard one.
AWG_CONFIG_KEYS = (
    'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
    'I1', 'I2', 'I3', 'I4', 'I5',
    'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout',
    'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts', 'RandomTrailers',
    'DisableCookies',
)


def protocol_short_name(protocol: str, header_protection=False) -> str:
    """Short protocol tag for the server name, e.g. `AWG3`."""
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    if is_awg3_in_awg2(protocol, header_protection):
        base = 'awg3'
    names = {
        'awg': 'AWG',
        'awg2': 'AWG2',
        'awg3': 'AWG3',
        'awg_legacy': 'AWG-Legacy',
        'wireguard': 'WG',
        'xray': 'Xray',
        'telemt': 'Telemt',
        'socks5': 'SOCKS5',
        'dns': 'DNS',
        'adguard': 'AdGuard',
        'nginx': 'NGINX',
        'exit': 'Exit',
    }
    name = names.get(base, base.upper())
    return name if idx <= 1 else f'{name}#{idx}'


def connection_display_name(server=None, protocol=None) -> str:
    """`<node> <container>`, e.g. `nl-01 AWG3` -- the name the client will show."""
    node = str((server or {}).get('name') or (server or {}).get('host') or '').strip()
    record = ((server or {}).get('protocols') or {}).get(protocol) or {} if protocol else {}
    tag = protocol_short_name(protocol, record.get('header_protection')) if protocol else ''
    return ' '.join(part for part in (node, tag) if part)


def parse_wg_config(config_text):
    """Read a WireGuard/AmneziaWG config the way the client's importer does:
    section headers ignored, every `key = value` line collected into one map."""
    values = {}
    for line in str(config_text or '').split('\n'):
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            continue
        sep = line.find('=')
        if sep > 0:
            values[line[:sep].strip()] = line[sep + 1:].strip()
    return values


# amnezia-awg only knows one link shape from this panel, and only that shape
# can carry a name in its fragment.
NAMED_LINK_SCHEMES = ('vless://',)

# serialization::inbounds::GenerateInboundEntry(): the local SOCKS listener the
# client patches with a free port and credentials when it connects.
XRAY_INBOUND = {
    'listen': '127.0.0.1',
    'port': 10808,
    'protocol': 'socks',
    'settings': {'udp': True},
}


def apply_link_name(config_text, name):
    """Put the connection's display name in a vless link's fragment.

    AmneziaVPN reads that fragment as the server name (vless::Deserialize hands
    it to extractXrayConfig as the description), so the panel's per-connection
    label used to end up as the server's name in the client.
    """
    text = str(config_text or '').strip()
    if not name or not text.startswith(NAMED_LINK_SCHEMES):
        return config_text
    return f"{text.split('#', 1)[0]}#{urllib.parse.quote(name)}"


def build_xray_client_config(link):
    """Turn a vless link into the xray client config the desktop client builds.

    A port of serialization::vless::Deserialize -- the client only reaches that
    code path for a bare `vless://` string, so anything wrapped (a `vpn://` key,
    a QR code) has to arrive already deserialised.
    """
    if not str(link or '').strip().startswith('vless://'):
        return None
    parts = urllib.parse.urlsplit(link.strip())
    host = (parts.hostname or '').strip('[]')
    uuid_value = urllib.parse.unquote(parts.netloc.rpartition('@')[0])
    try:
        port = parts.port
    except ValueError:
        return None
    if not host or not port or not uuid_value:
        return None

    query = {}
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        query.setdefault(key, value)

    user = {'id': uuid_value, 'encryption': query.get('encryption', 'none')}
    stream = {}

    network = query.get('type', 'tcp')
    if network != 'tcp':
        stream['network'] = network
    if network == 'kcp':
        if query.get('seed'):
            stream.setdefault('kcpSettings', {})['seed'] = query['seed']
        if query.get('headerType', 'none') != 'none':
            stream.setdefault('kcpSettings', {}).setdefault('header', {})['type'] = query['headerType']
    elif network == 'http':
        if query.get('path', '/') != '/':
            stream.setdefault('httpSettings', {})['path'] = query['path']
        if 'host' in query:
            stream.setdefault('httpSettings', {})['host'] = query['host'].split(',')
    elif network == 'ws':
        if query.get('path', '/') != '/':
            stream.setdefault('wsSettings', {})['path'] = query['path']
        if 'host' in query:
            stream.setdefault('wsSettings', {}).setdefault('headers', {})['Host'] = query['host']
    elif network == 'quic':
        if 'quicSecurity' in query:
            quic = stream.setdefault('quicSettings', {})
            quic['security'] = query['quicSecurity']
            if query['quicSecurity'] != 'none':
                quic['key'] = query.get('key', '')
            if query.get('headerType', 'none') != 'none':
                quic.setdefault('header', {})['type'] = query['headerType']
    elif network == 'grpc':
        if 'serviceName' in query:
            stream.setdefault('grpcSettings', {})['serviceName'] = query['serviceName']
        if 'mode' in query:
            stream.setdefault('grpcSettings', {})['multiMode'] = query['mode'] == 'multi'

    security = query.get('security', 'none')
    tls_key = 'xtlsSettings' if security == 'xtls' else ('tlsSettings' if security == 'tls' else 'realitySettings')
    if security != 'none':
        stream['security'] = security
    if 'sni' in query:
        stream.setdefault(tls_key, {})['serverName'] = query['sni']
    if 'alpn' in query:
        # xray does not speak h2 here, and the client drops it
        alpn = [item for item in query['alpn'].split(',') if item and item != 'h2']
        if alpn:
            stream.setdefault(tls_key, {})['alpn'] = alpn
    if security in ('xtls', 'reality'):
        user['flow'] = query.get('flow', '')
    if security == 'reality':
        reality = stream.setdefault('realitySettings', {})
        for param, field in (('fp', 'fingerprint'), ('pbk', 'publicKey'), ('sid', 'shortId')):
            if param in query:
                reality[field] = query[param]
        # the client only reads the long spelling, the panel emits the short one
        spider = query.get('spiderX') or query.get('spx')
        if spider:
            reality['spiderX'] = spider

    outbound = {
        'protocol': 'vless',
        'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]},
        'streamSettings': stream,
    }
    return {'inbounds': [dict(XRAY_INBOUND)], 'outbounds': [outbound]}


def build_amnezia_xray_config(config_text, description):
    """Wrap a vless link the way ImportController::extractXrayConfig would."""
    client_config = build_xray_client_config(config_text)
    if not client_config:
        return None
    serialized = json.dumps(client_config, indent=4, sort_keys=True) + '\n'
    return {
        'containers': [{
            'container': 'amnezia-xray',
            'xray': {'last_config': serialized, 'isThirdPartyConfig': True},
        }],
        'defaultContainer': 'amnezia-xray',
        'description': description,
        'hostName': client_config['outbounds'][0]['settings']['vnext'][0]['address'],
    }


def build_amnezia_config(config_text, description):
    """Wrap a WireGuard/AmneziaWG config into Amnezia's own server config format.

    A plain `.conf` cannot carry a name: extractWireGuardConfig() overwrites
    description with nextAvailableServerName(), which is why every imported key
    lands as "Server 1". This JSON goes down the ConfigTypes::Amnezia branch
    instead, which keeps whatever description it is given. Field for field it is
    what the client itself builds from the same config.
    """
    if str(config_text or '').strip().startswith(NAMED_LINK_SCHEMES):
        return build_amnezia_xray_config(config_text, description)
    values = parse_wg_config(config_text)
    host, _, port = values.get('Endpoint', '').rpartition(':')
    host = host.strip('[]')
    if not host or not port.isdigit():
        return None
    if not (values.get('PrivateKey') and values.get('Address') and values.get('PublicKey')):
        return None

    last_config = {
        'config': str(config_text),
        'hostName': host,
        'port': int(port),
        'client_priv_key': values['PrivateKey'],
        'client_ip': values['Address'],
        'server_pub_key': values['PublicKey'],
    }
    psk = values.get('PresharedKey') or values.get('PreSharedKey')
    if psk:
        last_config['psk_key'] = psk
    if values.get('PersistentKeepalive'):
        last_config['persistent_keep_alive'] = values['PersistentKeepalive']
    last_config['allowed_ips'] = [
        part.strip() for part in values.get('AllowedIPs', '').split(',') if part.strip()
    ]

    protocol_name = 'wireguard'
    for key in AWG_CONFIG_KEYS:
        if values.get(key):
            last_config[key] = values[key]
            protocol_name = 'awg'
    # processAmneziaConfig() replaces this with the client's own default on
    # import, so a custom MTU only survives in the raw config below.
    last_config['mtu'] = values.get('MTU') or ('1376' if protocol_name == 'awg' else '1420')

    container = 'amnezia-awg' if protocol_name == 'awg' else 'amnezia-wireguard'
    config = {
        'containers': [{
            'container': container,
            protocol_name: {
                'last_config': json.dumps(last_config, indent=4) + '\n',
                'isThirdPartyConfig': True,
                'port': str(port),
                'transport_proto': 'udp',
            },
        }],
        'defaultContainer': container,
        'description': description,
        'hostName': host,
    }
    dns = [part.strip() for part in values.get('DNS', '').split(',') if part.strip()]
    if len(dns) >= 2:
        config['dns1'], config['dns2'] = dns[0], dns[1]
    return config


def amnezia_config_bytes(config_text, description):
    """qCompress(json) -- what an Amnezia `vpn://` key and QR series both carry.

    qCompress prepends the uncompressed size as a big-endian uint32 and
    qUncompress refuses anything without it. Empty when the config is not a
    WireGuard/AmneziaWG one, so callers fall back to the plain key.
    """
    if not description:
        return b''
    config = build_amnezia_config(config_text, description)
    if not config:
        return b''
    raw = json.dumps(config, indent=4).encode('utf-8')
    return struct.pack('>I', len(raw)) + zlib.compress(raw, 8)


def amnezia_vpn_key(config_text, description):
    """The payload half of an Amnezia `vpn://` key."""
    payload = amnezia_config_bytes(config_text, description)
    if not payload:
        return ''
    return base64.urlsafe_b64encode(payload).decode('utf-8').rstrip('=')


# ImportController::parseQrCodeChunk reassembles a scanned config from a series
# of framed chunks: a QDataStream carrying qint16 magic, quint8 total, quint8
# index and the payload slice as a QByteArray (quint32 length + bytes), the
# whole frame base64url'd into one QR code.
QR_MAGIC = 1984

# The Android scanner (CameraActivity.kt) builds `ImageAnalysis.Builder().build()`
# with no ResolutionSelector, so CameraX hands ML Kit 640x480 frames -- which is
# why a whole config in one code never scanned: it lands at version 19 raw or 26
# wrapped, around 2-3 px per module in such a frame. 144 bytes keeps every frame
# at version 8-9, under 55x55 modules, which survived a simulated VGA capture
# down to a QR filling only 40% of the frame height.
QR_CHUNK_SIZE = 144

# quint8 chunk counter on the reading side.
QR_MAX_CHUNKS = 255


def amnezia_qr_chunks(config_text, description):
    """Split the config into QR frames the client can reassemble."""
    payload = amnezia_config_bytes(config_text, description)
    if not payload:
        return []
    total = (len(payload) + QR_CHUNK_SIZE - 1) // QR_CHUNK_SIZE
    if total > QR_MAX_CHUNKS:
        return []
    # spread the bytes evenly rather than leaving a stub last frame
    size = (len(payload) + total - 1) // total
    chunks = []
    for index in range(total):
        part = payload[index * size:(index + 1) * size]
        frame = struct.pack('>hBBI', QR_MAGIC, total, index, len(part)) + part
        chunks.append(base64.urlsafe_b64encode(frame).decode('utf-8').rstrip('='))
    return chunks


def generate_vpn_link(config_text, server=None, protocol=None):
    """Encode a config as a vpn:// key.

    Amnezia decodes with QByteArray::Base64UrlEncoding|OmitTrailingEquals,
    and Qt silently *skips* characters outside that alphabet instead of
    failing. Standard base64 therefore corrupts the payload as soon as it
    emits '+' or '/' -- which a config containing '>' or '?' does, the
    default I1 packet among them.
    """
    key = amnezia_vpn_key(config_text, connection_display_name(server, protocol))
    if key:
        return f"vpn://{key}"
    b64 = base64.urlsafe_b64encode(config_text.strip().encode('utf-8')).decode('utf-8')
    return f"vpn://{b64.rstrip('=')}"


def config_payloads(config_text, server=None, protocol=None):
    """What every config view needs: the config, the key, the QR frames, the name.

    The frames carry no `vpn://` prefix -- extractConfigFromQr() hands the
    scanned text straight to QByteArray::fromBase64, which drops ':' and '/'
    but keeps 'v', 'p' and 'n', shifting the whole payload by three characters.
    The list is empty when the config is not a WireGuard/AmneziaWG one; the QR
    then stays on the raw config, which is all such clients understand anyway.
    """
    name = connection_display_name(server, protocol)
    if not str(config_text or '').strip():
        return {'config': config_text, 'vpn_link': '', 'vpn_qr_chunks': [], 'vpn_name': name}
    config_text = apply_link_name(config_text, name)
    key = amnezia_vpn_key(config_text, name)
    return {
        'config': config_text,
        'vpn_link': f"vpn://{key}" if key else generate_vpn_link(config_text),
        'vpn_qr_chunks': amnezia_qr_chunks(config_text, name),
        'vpn_name': name,
    }


from peer_create import PeerCreateService, PeerCreateError
from panel_backup import ArchiveJob, PRIVATE_HEADERS

peer_creates = PeerCreateService(
    path=lambda: DATA_FILE + '.peer-creates.json',
    load_data=lambda: load_data(), save_data=lambda data: save_data(data),
    data_lock=DATA_LOCK, get_ssh=lambda server: get_ssh(server),
    get_manager=lambda ssh, protocol: get_protocol_manager(ssh, protocol),
    public_endpoint=lambda server, protocol: protocol_public_endpoint(server, protocol),
)


self_service_connections = ConnectionService(
    load_data=load_data,
    save_data=save_data,
    data_lock=DATA_LOCK,
    get_ssh=get_ssh,
    get_protocol_manager=get_protocol_manager,
    manager_call=_manager_call,
    generate_vpn_link=generate_vpn_link,
    protocol_public_endpoint=protocol_public_endpoint,
)


mail_svc = MailService(
    load_data=load_data,
    get_ssh=get_ssh,
    get_protocol_manager=get_protocol_manager,
    manager_call=_manager_call,
    config_payloads=config_payloads,
    protocol_display_name=protocol_display_name,
    protocol_base=protocol_base,
    translate=_t,
)


def _mail_error_response(exc: MailError, lang: str):
    """MailError carries a translation key, so the browser gets the message in
    the admin's language and the machine-readable key next to it."""
    return JSONResponse({'error': _t(str(exc), lang), 'code': str(exc)},
                        status_code=exc.status_code)


def _exit_manager_factory(ssh):
    from managers.exit_manager import ExitManager
    return ExitManager(ssh)


exit_link_svc = ExitLinkService(
    load_data=load_data,
    save_data=save_data,
    data_lock=DATA_LOCK,
    get_ssh=get_ssh,
    awg_manager_factory=lambda ssh: AWGManager(ssh),
    exit_manager_factory=_exit_manager_factory,
    protocol_base=protocol_base,
    awg_protocols=AWG_PROTOCOLS,
    protocol_display_name=protocol_display_name,
    find_server_by_uid=find_server_by_uid,
)

smartroute_svc = SmartRouteService(
    load_data=load_data,
    save_data=save_data,
    data_lock=DATA_LOCK,
    get_ssh=get_ssh,
    awg_manager_factory=lambda ssh: AWGManager(ssh),
    protocol_base=protocol_base,
    awg_protocols=AWG_PROTOCOLS,
    apply_dns_via_exit=lambda sid, proto, en: exit_link_svc.set_dns_via_exit(sid, proto, en),
)


def _self_service_error_response(exc):
    if isinstance(exc, RateLimitError):
        return JSONResponse({'error': str(exc)}, status_code=429)
    if isinstance(exc, SelfServiceError):
        body = {'error': str(exc)}
        if getattr(exc, 'code', None):
            body['code'] = exc.code
        return JSONResponse(body, status_code=exc.status_code)
    logger.exception("Unexpected self-service error")
    return JSONResponse({'error': 'Internal server error'}, status_code=500)


# ===================== API tokens =====================

API_TOKEN_PREFIX = 'awp_'  # "Amnezia Web Panel" — makes tokens visually distinct in logs / configs
API_TOKEN_TOUCH_INTERVAL = 300  # don't re-write data.json more than once per 5 min per token


def _hash_api_token(raw: str) -> str:
    """One-way hash of a raw token. We never store the original token — only the
    SHA-256 digest, plus a short prefix for the UI to identify rotations."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _generate_api_token() -> str:
    """Generate a fresh bearer token. ~256 bits of entropy with a recognizable
    'awp_' prefix so leaked tokens are obvious in source control / pastes."""
    return f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def _resolve_api_token(data: dict, raw_token: str):
    """Match a raw bearer token against stored hashes. Returns the user record
    that owns the token, or None if the token is unknown / its owner is gone /
    its owner is no longer admin-or-support."""
    if not raw_token:
        return None
    token_hash = _hash_api_token(raw_token)
    entry = next(
        (t for t in data.get('api_tokens', []) if t.get('token_hash') == token_hash),
        None,
    )
    if not entry:
        return None
    user = next((u for u in data.get('users', []) if u['id'] == entry.get('user_id')), None)
    if not user:
        return None
    # Disabled or downgraded admins should not have a working token any more.
    if not user.get('enabled', True):
        return None
    if user.get('role') not in ('admin', 'support'):
        return None
    return (entry, user)


def _touch_api_token(token_entry: dict) -> bool:
    """Update last_used_at on a token entry, but only if enough time has passed
    since the previous touch — avoids hot-write loops under load. Returns True
    if the entry was updated and the caller should persist data."""
    now = datetime.now()
    last = token_entry.get('last_used_at')
    if last:
        try:
            prev = datetime.fromisoformat(last)
            if (now - prev).total_seconds() < API_TOKEN_TOUCH_INTERVAL:
                return False
        except Exception:
            pass
    token_entry['last_used_at'] = now.isoformat()
    return True


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, h = password_hash.split('$', 1)
        new_h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return new_h.hex() == h
    except Exception:
        return False


def _traffic_removal_guard(data, **scope):
    from peer_accounting import TrafficFinalizationRequired, require_unowned
    try:
        require_unowned(data, **scope)
    except TrafficFinalizationRequired as error:
        return JSONResponse({'error': str(error), 'code': error.code}, status_code=409)
    return None


def perform_delete_user(data: dict, user_id: str):
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False
    from peer_accounting import require_unowned
    require_unowned(data, user_ids={user_id})
    data['users'] = [u for u in data['users'] if u['id'] != user_id]
    return True


def _user_connection_identity(data, user_id):
    result = []
    for conn in data.get('user_connections', []):
        if conn['user_id'] != user_id:
            continue
        sid = conn['server_id']
        identity = traffic_server_identity(data['servers'][sid]) if 0 <= sid < len(data['servers']) else None
        result.append((conn['id'], conn['protocol'], conn['client_id'], identity))
    return sorted(result)


async def _propagate_user_state(user_id):
    # One worker per user, including when an HTTP waiter is cancelled. A newer
    # committed intent is applied after any already-running SSH command.
    for _ in range(8):
        async with DATA_LOCK:
            data = load_data()
            user = next((u for u in data['users'] if u['id'] == user_id), None)
            if user is None:
                return False
            revision = user.get('access_revision', 0)
            enabled = user.get('enabled', True)
            connections = _user_connection_identity(data, user_id)
        failed = False
        for connection_id, protocol, client_id, server_identity in connections:
            ssh = None
            try:
                async with DATA_LOCK:
                    current = load_data()
                    user = next((u for u in current['users'] if u['id'] == user_id), None)
                    if user is None:
                        return False
                    if user.get('access_revision', 0) != revision:
                        break
                    conn = next((c for c in current['user_connections'] if c['id'] == connection_id), None)
                    if conn is None or not 0 <= conn['server_id'] < len(current['servers']):
                        failed = True
                        break
                    server = current['servers'][conn['server_id']]
                    if (traffic_server_identity(server) != server_identity or conn['client_id'] != client_id
                            or conn['protocol'] != protocol or conn['user_id'] != user_id):
                        failed = True
                        break
                ssh = await asyncio.to_thread(get_ssh, server)
                await asyncio.to_thread(ssh.connect)
                # Do not execute an obsolete decision after a slow connect.
                async with DATA_LOCK:
                    latest = load_data()
                    user = next((u for u in latest['users'] if u['id'] == user_id), None)
                    if user is None:
                        return False
                    if user.get('access_revision', 0) != revision:
                        break
                    if _user_connection_identity(latest, user_id) != connections:
                        break
                manager = get_protocol_manager(ssh, protocol)
                clients = await asyncio.to_thread(_manager_call, manager, 'get_clients', protocol)
                peer = next((c for c in clients if str(c.get('clientId')) == str(client_id)), None)
                actual = peer.get('enabled', peer.get('userData', {}).get('enabled')) if peer else None
                if not isinstance(actual, bool):
                    raise RuntimeError('Peer state could not be verified')
                if actual != enabled:
                    async with DATA_LOCK:
                        latest = load_data()
                        user = next((u for u in latest['users'] if u['id'] == user_id), None)
                        if user is None:
                            return False
                        if (user.get('access_revision', 0) != revision
                                or _user_connection_identity(latest, user_id) != connections):
                            break
                    await asyncio.to_thread(_manager_call, manager, 'toggle_client', protocol, client_id, enabled)
                    clients = await asyncio.to_thread(_manager_call, manager, 'get_clients', protocol)
                    peer = next((c for c in clients if str(c.get('clientId')) == str(client_id)), None)
                    if peer is None or peer.get('enabled', peer.get('userData', {}).get('enabled')) is not enabled:
                        raise RuntimeError('Peer state was not applied')
            except Exception:
                failed = True
                logger.warning("User access SSH application pending: user=%s connection=%s", user_id, connection_id)
            finally:
                if ssh is not None:
                    try:
                        await asyncio.to_thread(ssh.disconnect)
                    except Exception:
                        failed = True
        async with DATA_LOCK:
            current = load_data()
            user = next((u for u in current['users'] if u['id'] == user_id), None)
            if user is None:
                return False
            if user.get('access_revision', 0) != revision or _user_connection_identity(current, user_id) != connections:
                continue
            if failed:
                return False
            user['access_sync_pending'] = False
            save_data(current)
            return True
    return False


async def perform_toggle_user(data: dict, user_id: str, enable: bool) -> bool:
    # The old snapshot/enable arguments are deliberately not authoritative.
    task = _USER_STATE_TASKS.get(user_id)
    if task is None or task.done():
        task = asyncio.create_task(_propagate_user_state(user_id))
        _USER_STATE_TASKS[user_id] = task
        def finished(done):
            if _USER_STATE_TASKS.get(user_id) is done:
                _USER_STATE_TASKS.pop(user_id, None)
        task.add_done_callback(finished)
    return await asyncio.shield(task)


@serialize_peer_lifecycle
@guard_user_deletions(lambda: load_data())
async def perform_mass_operations(delete_uids: List[str] = None, toggle_uids: List[tuple] = None, create_conns: List[dict] = None):
    """
    Executes multiple SSH operations efficiently.
    Reloads data inside to ensure we don't overwrite other changes.
    """
    toggle_results = []
    if toggle_uids:
        async with DATA_LOCK:
            current = load_data()
            for uid, enabled in toggle_uids:
                user = next((u for u in current['users'] if u['id'] == uid), None)
                if user:
                    reconcile_user_state(user, datetime.now(), external=enabled)
            save_data(current)
        toggle_results = await asyncio.gather(*(perform_toggle_user({}, uid, enabled) for uid, enabled in toggle_uids))
    data = load_data()
    server_ops = {}

    def get_ops(sid):
        if sid not in server_ops:
            server_ops[sid] = {'delete': [], 'create': []}
        return server_ops[sid]

    if delete_uids:
        for uid in delete_uids:
            conns = [c for c in data.get('user_connections', []) if c['user_id'] == uid]
            for c in conns: get_ops(c['server_id'])['delete'].append(c)
    
    if create_conns:
        for req in create_conns: get_ops(req['server_id'])['create'].append(req)

    async def run_server_ops(srv_id, ops):
        # We re-load data inside to be absolutely sure about current state
        # but for performance we'll use the passed srv_id
        current_data = load_data()
        if srv_id >= len(current_data['servers']): return
        srv = current_data['servers'][srv_id]
        
        try:
            ssh = await asyncio.to_thread(get_ssh, srv)
            await asyncio.to_thread(ssh.connect)
            
            # 1. Deletes
            for c in ops['delete']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'remove_client', c['protocol'], c['client_id'])
                # Incremental delete from data
                async with DATA_LOCK:
                    current_data = load_data()
                    current_data['user_connections'] = [conn for conn in current_data['user_connections'] if conn['id'] != c['id']]
                    save_data(current_data)
            
            # 3. Creates
            for c_req in ops['create']:
                proto_info = srv.get('protocols', {}).get(c_req['protocol'], {})
                port = proto_info.get('port', '55424')
                pub_host, pub_port = protocol_public_endpoint(srv, c_req['protocol'])
                manager = get_protocol_manager(ssh, c_req['protocol'])
                
                if c_req['protocol'] == 'wireguard':
                    res = await asyncio.to_thread(manager.add_client, c_req['name'], pub_host, public_port=pub_port)
                else:
                    res = await asyncio.to_thread(_manager_call, manager, 'add_client', c_req['protocol'], c_req['name'], pub_host, port, public_port=pub_port)
                
                if res.get('client_id'):
                    new_conn = {
                        'id': str(uuid.uuid4()),
                        'user_id': c_req['user_id'],
                        'server_id': srv_id,
                        'protocol': c_req['protocol'],
                        'client_id': res['client_id'],
                        'name': c_req['name'],
                        'created_at': datetime.now().isoformat(),
                    }
                    async with DATA_LOCK:
                        current_data = load_data()
                        current_data['user_connections'].append(new_conn)
                        save_data(current_data)
            
            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.error(f"Mass ops failed for server {srv_id}: {e}")

    # Run all servers in parallel
    tasks = [run_server_ops(sid, ops) for sid, ops in server_ops.items()]
    if tasks:
        await asyncio.gather(*tasks)

    # 4. Final user-level cleanup (delete/toggle users metadata)
    async with DATA_LOCK:
        current_data = load_data()
        if delete_uids:
            from peer_accounting import require_unowned
            require_unowned(current_data, user_ids=set(delete_uids))
            current_data['users'] = [u for u in current_data['users'] if u['id'] not in delete_uids]
            current_data['user_connections'] = [c for c in current_data.get('user_connections', []) if c['user_id'] not in delete_uids]
        save_data(current_data)

    return all(toggle_results)


async def sync_users_with_remnawave(data: dict):
    settings = data.get('settings', {}).get('sync', {})
    if not settings.get('remnawave_sync_users'):
        return 0, "Synchronization is disabled in settings"
    
    url = settings.get('remnawave_url')
    api_key = settings.get('remnawave_api_key')
    if not url or not api_key:
        return 0, "Remnawave URL or API Key not configured"
    
    api_url = url.rstrip('/') + '/api/users'
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        rw_users = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            page_size = 50  # Use a smaller page size that is more likely to be accepted
            current_start = 0
            while True:
                resp = await client.get(f"{api_url}?size={page_size}&start={current_start}", headers=headers)
                if resp.status_code != 200:
                    return 0, f"Remnawave API error: {resp.status_code} {resp.text}"
                
                page_data = resp.json()
                response_obj = page_data.get('response', {})
                page_users = response_obj.get('users', [])
                total_count = response_obj.get('total', 0)
                
                if not page_users:
                    break
                
                rw_users.extend(page_users)
                logger.info(f"Fetched {len(rw_users)} / {total_count} users from Remnawave...")
                
                if len(rw_users) >= total_count or len(page_users) == 0:
                    break
                    
                current_start += len(page_users)

            rw_uuids = {u['uuid'] for u in rw_users}
            
            # 1. Handle deletion (users that have remnawave_uuid but are no longer in Remnawave)
            to_delete_ids = []
            for u in data['users']:
                if u.get('remnawave_uuid') and u['remnawave_uuid'] not in rw_uuids:
                    to_delete_ids.append(u['id'])
            
            if to_delete_ids:
                logger.info(f"Removing {len(to_delete_ids)} users deleted in Remnawave")
                await perform_mass_operations(delete_uids=to_delete_ids)

            # 2. Sync / Create users
            synced_count = 0
            to_toggle = [] # list of (user_id, enabled)
            to_create_conns = [] # list of dicts
            
            for rw_u in rw_users:
                # We reload data in each loop step to handle concurrency
                data = load_data()
                local_u = next((u for u in data['users'] if u.get('remnawave_uuid') == rw_u['uuid']), None)
                if not local_u:
                    local_u = next((u for u in data['users'] if u['username'] == rw_u['username']), None)

                is_active = (rw_u.get('status') == 'ACTIVE')
                
                if local_u:
                    local_u['username'] = rw_u['username']
                    local_u['telegramId'] = rw_u.get('telegramId')
                    local_u['email'] = rw_u.get('email')
                    local_u['description'] = rw_u.get('description')
                    local_u['remnawave_uuid'] = rw_u['uuid']
                    
                    if local_u.get('enabled', True) != is_active:
                        to_toggle.append((local_u['id'], is_active))
                    
                    # Save metadata immediately
                    async with DATA_LOCK:
                        current = load_data()
                        # Update index
                        idx = next((i for i, u in enumerate(current['users']) if u['id'] == local_u['id']), -1)
                        if idx != -1:
                            current['users'][idx].update({key: local_u[key] for key in
                                ('username', 'telegramId', 'email', 'description', 'remnawave_uuid')})
                            save_data(current)
                    
                    synced_count += 1
                else:
                    new_id = str(uuid.uuid4())
                    new_user = {
                        'id': new_id,
                        'username': rw_u['username'],
                        'password_hash': '', 
                        'role': 'user',
                        'telegramId': rw_u.get('telegramId'),
                        'email': rw_u.get('email'),
                        'description': rw_u.get('description'),
                        'enabled': is_active,
                        'disable_reasons': [] if is_active else ['external'],
                        'created_at': datetime.now().isoformat(),
                        'remnawave_uuid': rw_u['uuid'],
                        'share_enabled': False,
                        'share_token': secrets.token_urlsafe(16),
                        'share_password_hash': None,
                    }
                    async with DATA_LOCK:
                        current = load_data()
                        current['users'].append(new_user)
                        save_data(current)
                    
                    if settings.get('remnawave_create_conns'):
                        sid = settings.get('remnawave_server_id')
                        if sid is not None:
                            to_create_conns.append({
                                'user_id': new_id,
                                'server_id': sid,
                                'protocol': settings.get('remnawave_protocol', 'awg'),
                                'name': f"{rw_u['username']}_vpn"
                            })
                    synced_count += 1
            
            # Execute all collected mass operations
            if to_toggle or to_create_conns:
                logger.info(f"Executing mass ops for Remnawave sync: toggle={len(to_toggle)}, create={len(to_create_conns)}")
                applied = await perform_mass_operations(toggle_uids=to_toggle, create_conns=to_create_conns)
                if not applied:
                    return synced_count, "Metadata synchronized; access SSH application pending"
            
            return synced_count, "Successfully synchronized with Remnawave"
            
    except Exception as e:
        logger.exception("Synchronization error")
        return 0, f"Error: {str(e)}"


def get_current_user(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    data = load_data()
    for u in data.get('users', []):
        if u['id'] == user_id:
            if not u.get('enabled', True) or u.get('role') == 'none':
                return None
            return u
    return None


def static_version():
    """Cache buster for /static: the newest mtime under it.

    Browsers hold on to style.css across a redeploy -- it is served with an
    ETag but no Cache-Control, so heuristic caching keeps a stale copy and the
    page renders new markup against old rules.
    """
    newest = 0.0
    for root, _dirs, files in os.walk(STATIC_DIR):
        for name in files:
            try:
                newest = max(newest, os.path.getmtime(os.path.join(root, name)))
            except OSError:
                continue
    return str(int(newest))


def tpl(request, template, **kwargs):
    data = load_data()
    lang = request.cookies.get('lang', 'en')
    ctx = {
        'request': request,
        'static_v': static_version(),
        'current_user': get_current_user(request),
        'site_settings': data.get('settings', {}).get('appearance', {}),
        'captcha_settings': data.get('settings', {}).get('captcha', {}),
        'telegram_settings': data.get('settings', {}).get('telegram', {}),
        'bot_running': tg_bot.is_running(),
        'lang': lang,
        '_': lambda text_id: _t(text_id, lang),
        'translations_json': json.dumps(TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))),
        # The login page is the only public page; it must not dump the whole
        # UI dictionary (a feature showcase of the panel) into view-source.
        'login_translations_json': json.dumps({
            k: _t(k, lang) for k in ('login', 'logging_in', 'login_error')
        }),
        'all_translations_json': json.dumps(TRANSLATIONS)
    }
    ctx.update(kwargs)
    return templates.TemplateResponse(template, ctx)


@app.get('/manifest.webmanifest')
def web_manifest(request: Request):
    """Installable PWA manifest — public, no auth (browsers fetch without credentials)."""
    data = load_data()
    lang = request.cookies.get('lang', 'en')
    appearance = data.get('settings', {}).get('appearance', {})
    return JSONResponse(
        build_manifest(appearance, lang),
        media_type='application/manifest+json',
    )


@app.get('/sw.js')
def service_worker():
    """Root-scoped service worker. Must not live under /static/ or scope is confined."""
    path = os.path.join(STATIC_DIR, 'sw.js')
    return FileResponse(
        path,
        media_type='text/javascript',
        headers={
            'Cache-Control': 'no-cache',
            'Service-Worker-Allowed': '/',
        },
    )


# ======================== Pydantic Models ========================

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha: Optional[str] = None


class AddServerRequest(BaseModel):
    host: str = ''
    ssh_port: conint(strict=True, ge=1, le=65535) = 22
    username: str = ''
    password: str = ''
    private_key: str = ''
    name: str = ''


class EditServerRequest(BaseModel):
    name: str = ''
    host: str = ''
    ssh_port: Optional[conint(strict=True, ge=1, le=65535)] = None
    username: str = ''
    # Optional[str] = None lets the client distinguish "leave field as is"
    # (omit / null) from "explicitly clear" (empty string). Both credential
    # fields can be omitted to keep current auth unchanged.
    password: Optional[str] = None
    private_key: Optional[str] = None
    self_service_enabled: Optional[bool] = None


class ReorderServersRequest(BaseModel):
    # `order[i]` is the *old* server index now at position `i` in the new layout.
    order: List[int]
    server_uids: Optional[List[str]] = None


class InstallProtocolRequest(BaseModel):
    protocol: str = 'awg'
    port: str = '55424'
    install_another: Optional[bool] = False
    tls_emulation: Optional[bool] = None
    tls_domain: Optional[str] = None
    max_connections: Optional[int] = None
    # SOCKS5
    socks5_username: Optional[str] = None
    socks5_password: Optional[str] = None
    # AdGuard Home
    adguard_mode: Optional[str] = None  # 'replace' or 'sidebyside'
    adguard_web_port: Optional[int] = None
    adguard_expose_web: Optional[bool] = None
    adguard_dot_port: Optional[int] = None
    adguard_doh_port: Optional[int] = None
    adguard_expose_dns: Optional[bool] = None
    adguard_expose_dot: Optional[bool] = None
    adguard_expose_doh: Optional[bool] = None
    # NGINX
    nginx_domain: Optional[str] = None
    nginx_email: Optional[str] = None
    # Exit node
    exit_subnet: Optional[str] = None       # transit subnet, default 10.9.0.0/24
    exit_obfuscation: Optional[bool] = None  # AmneziaWG obfuscation on the transit link
    # AmneziaWG: values that end up in the generated client configs
    awg_mtu: Optional[str] = None
    awg_dns1: Optional[str] = None
    awg_dns2: Optional[str] = None
    awg_dns6: Optional[str] = None
    awg_i1: Optional[str] = None
    awg_i2: Optional[str] = None
    awg_i3: Optional[str] = None
    awg_i4: Optional[str] = None
    awg_i5: Optional[str] = None


class AwgSettingsRequest(BaseModel):
    protocol: str = 'awg2'
    mtu: Optional[str] = None
    dns1: Optional[str] = None
    dns2: Optional[str] = None
    dns6: Optional[str] = None
    i1: Optional[str] = None
    i2: Optional[str] = None
    i3: Optional[str] = None
    i4: Optional[str] = None
    i5: Optional[str] = None


class ExitPeerAddRequest(BaseModel):
    protocol: str = 'exit'
    peer_id: str = ''
    name: str = ''
    public_key: str = ''


class ExitPeerRemoveRequest(BaseModel):
    protocol: str = 'exit'
    public_key: str = ''
    peer_id: str = ''


class ExitLinkRequest(BaseModel):
    protocol: str = 'awg'
    exit_uid: str = ''
    force: Optional[bool] = False


class ExitDnsRequest(BaseModel):
    protocol: str = 'awg'
    enabled: bool = False


class SmartRouteOwnSubnetsRequest(BaseModel):
    cidrs: list = []


class SmartRouteSplitRequest(BaseModel):
    protocol: str = 'awg'
    enabled: bool = False


class SmartRouteDnsRequest(BaseModel):
    enabled: bool = False


class SmartRouteEnableRequest(BaseModel):
    enabled: bool = True


class SmartRouteDnsServersRequest(BaseModel):
    direct: str = '77.88.8.8'
    exit: str = '1.1.1.1'


class Socks5SettingsRequest(BaseModel):
    protocol: str = 'socks5'
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ProtocolRequest(BaseModel):
    protocol: str = 'awg'


class ContainerToggleRequest(ProtocolRequest):
    # Stopping an exit node that entries route through needs an explicit yes
    force: Optional[bool] = False


class WgEasyPreviewRequest(BaseModel):
    web_port: int = 51821
    password: str = ''
    username: Optional[str] = 'admin'


class WgEasyImportRequest(BaseModel):
    web_port: int = 51821
    password: str = ''
    username: Optional[str] = 'admin'
    client_ids: Optional[list] = None  # None = import all
    target: str = 'auto'  # auto | wireguard | awg2
      
class RenameProtocolRequest(BaseModel):
    protocol: str = ''
    name: str = ''  # empty = reset to default


class PublicEndpointRequest(BaseModel):
    protocol: str = ''
    public_host: str = ''  # empty = the server's own address
    public_port: str = ''  # empty = the instance's listen port


class AddConnectionRequest(BaseModel):
    protocol: str = 'awg'
    name: str = 'Connection'
    user_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class EditConnectionRequest(BaseModel):
    protocol: str = 'telemt'
    client_id: str = ''
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class ConnectionActionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    allow_unverified: bool = False


class RenameConnectionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    new_name: str = ''
    max_speed: float = -1  # Mbit/s; -1 = don't touch, 0 = unlimited


class ConnectionSpeedRequest(BaseModel):
    protocol: str = Field(default='awg', min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=256)
    # Validate numeric bounds in the handler so non-standard JSON NaN/Infinity
    # also receive a JSON error without serializing the invalid number back.
    max_speed: float = Field(strict=True, description='Finite Mbit/s, 0..1000000 in steps of 0.1; 0 = unlimited')

class SaveConnectionConfigRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    config: str = ''


class ToggleConnectionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    enable: bool = True


class AddUserRequest(BaseModel):
    username: str
    # Password is optional: role 'none' (the default) is a record-only user
    # who cannot log in, so no password is needed. Any real role requires one.
    password: Optional[str] = None
    role: str = 'none'
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = 'never'
    server_id: Optional[int] = None
    protocol: Optional[str] = None
    connection_name: Optional[str] = None
    expiration_date: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None



class ServerConfigSaveRequest(BaseModel):
    protocol: str
    config: str


class NginxSiteSaveRequest(BaseModel):
    protocol: str = 'nginx'
    html: str = ''


class BackupDownloadRequest(BaseModel):
    protocol: str
    filename: str


class AppearanceSettings(BaseModel):
    title: str = 'Amnezia'
    logo: str = '🛡'
    subtitle: str = 'Web Panel'


class SyncSettings(BaseModel):
    remnawave_url: str = ''
    remnawave_api_key: str = ''
    remnawave_sync: bool = False
    remnawave_sync_users: bool = False
    remnawave_create_conns: bool = False
    remnawave_server_id: int = 0
    remnawave_protocol: str = 'awg'

class CaptchaSettings(BaseModel):
    enabled: bool = False


class SSLSettings(BaseModel):
    enabled: bool = False
    domain: str = ''
    cert_path: str = ''
    key_path: str = ''
    cert_text: str = ''
    key_text: str = ''
    panel_port: int = 5000

class DuckDNSApplyRequest(BaseModel):
    enabled: bool = False
    domain: str = ''
    # Empty keeps the stored token: the settings page never echoes it back.
    token: str = ''

class TelegramSettings(BaseModel):
    token: str = ''
    enabled: bool = False


class MailSettings(BaseModel):
    enabled: bool = False
    host: str = ''
    port: int = Field(587, ge=1, le=65535)
    security: str = 'starttls'      # none | starttls | ssl
    username: str = ''
    # Empty keeps the stored password: the settings page never echoes it back.
    password: str = ''
    from_email: str = ''
    from_name: str = ''
    reply_to: str = ''
    timeout_seconds: int = Field(30, ge=5, le=300)


class AutoBackupSettings(BaseModel):
    enabled: bool = False
    interval_hours: int = 24


class SelfServiceSettings(BaseModel):
    enabled: bool = False
    web_enabled: bool = True
    telegram_enabled: bool = True
    max_connections_per_user: int = Field(5, ge=1, le=100)
    rate_limit_count: int = Field(3, ge=1, le=100)
    rate_limit_window_seconds: int = Field(60, ge=1, le=86400)
    allowed_protocols: List[str] = Field(default_factory=lambda: ['awg', 'awg2'])


class SelfServiceConnectionRequest(BaseModel):
    server_id: int
    protocol: str = 'awg'
    name: str = 'VPN Connection'




class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = None
    traffic_reset_strategy: Optional[str] = None
    expiration_date: Optional[str] = None
    password: Optional[str] = None



class ExitNodesSettings(BaseModel):
    default_exit_uid: str = ''


class SaveSettingsRequest(BaseModel):
    appearance: AppearanceSettings
    sync: SyncSettings
    captcha: CaptchaSettings
    telegram: TelegramSettings
    ssl: SSLSettings
    auto_backup: AutoBackupSettings = AutoBackupSettings()
    self_service: SelfServiceSettings = SelfServiceSettings()
    exit_nodes: ExitNodesSettings = ExitNodesSettings()
    mail: MailSettings = MailSettings()


class ToggleUserRequest(BaseModel):
    enabled: bool


def _normalize_telegram_id(value):
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    if not normalized.isdigit():
        raise ValueError('Telegram ID must be numeric')
    return normalized


class AddUserConnectionRequest(BaseModel):
    server_id: int
    protocol: str = 'awg'
    name: str = 'VPN Connection'
    client_id: Optional[str] = None
    operation_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class MailSendRequest(BaseModel):
    include_configs: bool = True
    include_links: bool = True
    subject: str = ''
    message: str = ''
    # Overrides the address on the user record for this one send.
    recipient: Optional[str] = None


class MailBulkRequest(BaseModel):
    include_configs: bool = True
    include_links: bool = True
    subject: str = ''
    message: str = ''
    # None means "every user that has an address".
    user_ids: Optional[List[str]] = None
    only_enabled: bool = True
    skip_without_connections: bool = True


class MailTestRequest(BaseModel):
    recipient: str = ''


class CreateApiTokenRequest(BaseModel):
    name: str


class ShareSetupRequest(BaseModel):
    enabled: bool
    password: Optional[str] = None


class ShareAuthRequest(BaseModel):
    password: str


class TunnelStartRequest(BaseModel):
    authtoken: Optional[str] = None


# ======================== Startup ========================

# Interval (seconds) between background connection-flood collection rounds.
# Each round is one cheap SSH roundtrip per AWG instance (a compact per-IP
# conntrack summary), so detection works 24/7 without anyone watching the UI
# and the 6s UI refresh only reads the small snapshot files.
CONN_MONITOR_INTERVAL = 600


def _conn_monitor_loop():
    from managers.awg_manager import AWGManager
    while True:
        try:
            data = load_data()
            for server in data.get('servers', []):
                protocols = server.get('protocols', {}) or {}
                for proto in list(protocols):
                    if protocol_base(proto) not in ('awg', 'awg2', 'awg3'):
                        continue
                    try:
                        AWGManager(get_ssh(server)).collect_conn_stats(proto)
                    except Exception as e:
                        logger.warning(
                            f"conn monitor: {server.get('host')} {proto}: {e}")
        except Exception as e:
            logger.warning(f"conn monitor loop: {e}")
        time.sleep(CONN_MONITOR_INTERVAL)


_conn_monitor_started = False


def _start_conn_monitor():
    global _conn_monitor_started
    if _conn_monitor_started:
        return
    _conn_monitor_started = True
    threading.Thread(target=_conn_monitor_loop, daemon=True,
                     name='conn-monitor').start()
    logger.info(f"Connection-flood monitor started (every {CONN_MONITOR_INTERVAL}s)")


@app.on_event("startup")
async def startup():
    global _panel_lease
    _panel_lease = PanelLease(DATA_FILE, runtime=True)
    _panel_lease.acquire()
    data = load_data()
    if data.get(DISASTER_HOLD):
        raise RuntimeError('Disaster recovery requires independent node reconciliation before startup')
    _start_conn_monitor()
    _start_duckdns_monitor()
    changed = False
    if not data.get('users'):
        data['users'] = [{
            'id': str(uuid.uuid4()),
            'username': 'admin',
            'password_hash': hash_password('admin'),
            'role': 'admin',
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }]
        changed = True
        logger.info("Default admin created (admin / admin)")
    
    # Migration for sharing fields and traffic reset strategy
    for u in data['users']:
        migrated = False
        if 'share_enabled' not in u:
            u['share_enabled'] = False
            migrated = True
        if not u.get('share_token'):
            u['share_token'] = secrets.token_urlsafe(16)
            migrated = True
        if 'share_password_hash' not in u:
            u['share_password_hash'] = None
            migrated = True
        
        # Traffic reset strategy and total traffic
        if 'traffic_reset_strategy' not in u:
            u['traffic_reset_strategy'] = 'never'
            migrated = True
        if 'traffic_total' not in u:
            u['traffic_total'] = u.get('traffic_used', 0)
            migrated = True
        if 'last_reset_at' not in u:
            u['last_reset_at'] = datetime.now().isoformat()
            migrated = True
        if 'expiration_date' not in u:
            u['expiration_date'] = None
            migrated = True
            
        if migrated:
            changed = True
            logger.info(f"Migrated user {u.get('username', u.get('id', '?'))} to new traffic/sharing fields")
    
    # API tokens collection — initialise lazily on first run.
    if 'api_tokens' not in data:
        data['api_tokens'] = []
        changed = True
        logger.info("Initialised empty api_tokens collection")

    # Stable server identity: list indices shift on reorder/delete, uids don't.
    if backfill_server_uids(data.get('servers')):
        changed = True
        logger.info("Assigned uids to servers that had none")

    # Auto backup settings migration
    auto_backup = data.setdefault('settings', {}).setdefault('auto_backup', {})
    if 'enabled' not in auto_backup:
        auto_backup['enabled'] = False
        changed = True
    if 'interval_hours' not in auto_backup:
        auto_backup['interval_hours'] = 24
        changed = True
    if 'last_run_at' not in auto_backup:
        auto_backup['last_run_at'] = None
        changed = True
    if 'last_status' not in auto_backup:
        auto_backup['last_status'] = None
        changed = True
    if 'last_created_count' not in auto_backup:
        auto_backup['last_created_count'] = 0
        changed = True
    if 'last_error' not in auto_backup:
        auto_backup['last_error'] = None
        changed = True

    if changed:
        save_data(data)

    # Start periodic background tasks
    asyncio.create_task(periodic_background_tasks())

    # Re-apply public-port forwards on the fleet: hand-made iptables rules do
    # not survive reboots on their own, and only some hosts persist them.
    asyncio.create_task(restore_public_port_forwards())
    # ... and keep re-applying: a VPS can reboot while the panel keeps running.
    asyncio.create_task(restore_public_port_forwards_loop())

    # Start Telegram bot if enabled
    tg_cfg = data.get('settings', {}).get('telegram', {})
    if tg_cfg.get('enabled') and tg_cfg.get('token'):
        logger.info("Starting Telegram bot from saved settings...")
        tg_bot.launch_bot(tg_cfg['token'], load_data, generate_vpn_link, save_data, self_service_svc=self_service_connections)


def _auto_backup_due(auto_backup: dict, now: Optional[datetime] = None) -> bool:
    if not auto_backup.get('enabled'):
        return False
    try:
        interval_hours = max(1, min(24, int(auto_backup.get('interval_hours') or 24)))
    except (TypeError, ValueError):
        interval_hours = 24
    last_run_at = auto_backup.get('last_run_at')
    if not last_run_at:
        return True
    try:
        last_run = datetime.fromisoformat(str(last_run_at))
    except ValueError:
        return True
    now = now or datetime.now()
    return now - last_run >= timedelta(hours=interval_hours)


def _create_auto_backups_once(data: dict) -> dict:
    started_at = datetime.now()
    created = []
    errors = []

    for server_id, server in enumerate(data.get('servers', [])):
        protocols = server.get('protocols', {}) or {}
        installed_protocols = [
            proto for proto, info in protocols.items()
            if isinstance(info, dict) and info.get('installed') and is_valid_protocol(proto) and protocol_container_name(proto)
        ]
        if not installed_protocols:
            continue

        ssh = None
        try:
            ssh = get_ssh(server)
            ssh.connect()
            backup_manager = BackupManager(ssh)
            for proto in installed_protocols:
                try:
                    result = backup_manager.create_backup(proto, protocol_container_name(proto))
                    if result.get('status') == 'success':
                        created.append({
                            'server_id': server_id,
                            'protocol': proto,
                            'name': result.get('backup', {}).get('name')
                        })
                    else:
                        errors.append({
                            'server_id': server_id,
                            'protocol': proto,
                            'error': result.get('message', 'Failed to create backup')
                        })
                except Exception as e:
                    errors.append({'server_id': server_id, 'protocol': proto, 'error': str(e)})
        except Exception as e:
            for proto in installed_protocols:
                errors.append({'server_id': server_id, 'protocol': proto, 'error': str(e)})
        finally:
            if ssh:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

    status = 'success' if not errors else ('partial' if created else 'error')
    return {
        'status': status,
        'started_at': started_at.isoformat(),
        'finished_at': datetime.now().isoformat(),
        'created_count': len(created),
        'created': created,
        'errors': errors,
        'error': '; '.join(f"server {e['server_id']} {e['protocol']}: {e['error']}" for e in errors[:5]) if errors else None
    }


async def run_auto_backups_if_due():
    data = load_data()
    auto_backup = data.get('settings', {}).get('auto_backup', {})
    if not _auto_backup_due(auto_backup):
        return None

    logger.info("Starting scheduled auto backups...")
    result = await asyncio.to_thread(_create_auto_backups_once, data)

    async with DATA_LOCK:
        curr_data = load_data()
        curr_auto = curr_data.setdefault('settings', {}).setdefault('auto_backup', {})
        curr_auto['enabled'] = bool(curr_auto.get('enabled', auto_backup.get('enabled', False)))
        try:
            curr_auto['interval_hours'] = max(1, min(24, int(curr_auto.get('interval_hours') or auto_backup.get('interval_hours') or 24)))
        except (TypeError, ValueError):
            curr_auto['interval_hours'] = 24
        curr_auto['last_run_at'] = result['finished_at']
        curr_auto['last_status'] = result['status']
        curr_auto['last_created_count'] = result['created_count']
        curr_auto['last_error'] = result.get('error')
        save_data(curr_data)

    logger.info(
        "Auto backups finished: status=%s created=%s errors=%s",
        result['status'], result['created_count'], len(result.get('errors', []))
    )
    return result


def _scrape_server_traffic(server, sid, my_conns):
    from collections import Counter
    from managers.traffic_counters import counter
    from peer_accounting import _protocol_scope

    server_updates = []
    ssh = None
    try:
        ssh = get_ssh(server)
        ssh.connect()
        # The manager resolves first-instance aliases to the same container.
        # Query each physical scope once, retaining each link's full protocol.
        scopes = {}
        for proto, record in server.get('protocols', {}).items():
            if (str(proto).split('__', 1)[0] in ('awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'wireguard')
                    and isinstance(record, dict) and record.get('installed', True)):
                scopes.setdefault(_protocol_scope(proto), proto)
        owners = Counter((_protocol_scope(c['protocol']), c['client_id']) for c in my_conns)
        for scope, proto in scopes.items():
            try:
                manager = get_protocol_manager(ssh, proto)
                observed_at = time.time()
                epoch = None
                if scope[0] in ('awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard'):
                    snapshot = _manager_call(manager, 'get_traffic_snapshot', proto)
                    epoch, peer_counters = snapshot['epoch'], snapshot['peers']
                    if not isinstance(epoch, str) or not epoch:
                        raise ValueError('Counter epoch missing')
                else:
                    # Other protocols keep their adapters, but missing, bool,
                    # malformed or cached counters must not become zero either.
                    peer_counters = {}
                    for client in _manager_call(manager, 'get_clients', proto):
                        ud = client.get('userData', {})
                        if ud.get('traffic_valid', True):
                            peer_counters[client.get('clientId')] = {
                                'rx_bytes': ud.get('dataReceivedBytes'),
                                'tx_bytes': ud.get('dataSentBytes'),
                            }
                for uc in my_conns:
                    if _protocol_scope(uc['protocol']) != scope:
                        continue
                    if owners[(scope, uc['client_id'])] != 1:
                        logger.warning('Traffic ownership ambiguous on server %s; sample skipped', sid)
                        continue
                    values = peer_counters.get(uc['client_id'], {})
                    rx, tx = values.get('rx_bytes'), values.get('tx_bytes')
                    if not counter(rx) or not counter(tx):
                        continue
                    sample = {
                        'id': uc['id'], 'user_id': uc['user_id'],
                        'protocol': uc['protocol'], 'client_id': uc['client_id'],
                        'server_identity': traffic_server_identity(server),
                        'bytes': rx + tx, 'observed_at': observed_at,
                    }
                    if epoch is not None:
                        sample.update(rx_bytes=rx, tx_bytes=tx, counter_epoch=epoch)
                    server_updates.append(sample)
            except Exception:
                # One unavailable instance must not starve the other instances.
                # Never include arbitrary remote stderr or configurations.
                logger.warning('Traffic snapshot unavailable on server %s protocol %s; baselines retained', sid, proto)
    except Exception:
        logger.warning('Traffic SSH unavailable on server %s; baselines retained', sid)
    finally:
        if ssh is not None:
            try:
                ssh.disconnect()
            except Exception:
                logger.warning('Traffic SSH disconnect failed on server %s', sid)
    return server_updates


async def sync_user_traffic_and_state():
    # Serialize collection AND commit across overlapping cycles, not DATA_LOCK
    # across SSH. Normal admin writes continue while counters are collected.
    async with _TRAFFIC_SYNC_LOCK:
        async with DATA_LOCK:
            data = load_data()
        updates = []
        for sid, server in enumerate(data.get('servers', [])):
            conns = [c for c in data.get('user_connections', []) if c['server_id'] == sid]
            if conns:
                updates.extend(await asyncio.to_thread(_scrape_server_traffic, server, sid, conns))
        async with DATA_LOCK:
            current = load_data()
            apply_traffic_samples(current, updates, datetime.now())
            pending = [u['id'] for u in current['users'] if u.get('access_sync_pending')]
            save_data(current)
        if pending:
            await asyncio.gather(*(perform_toggle_user({}, uid, False) for uid in pending))


async def periodic_background_tasks():
    """Background task to sync traffic limits and Remnawave every 10 minutes"""
    while True:
        try:
            peer_creates.schedule_recovery()
            # We wait before the first sync to let the app settle
            await asyncio.sleep(60) 
            
            # --- 1. TRAFFIC SYNC & LIMITS ---
            logger.info("Starting background traffic sync...")
            await sync_user_traffic_and_state()

            # --- 2. AUTO BACKUP ---
            await run_auto_backups_if_due()

            # --- 3. REMNAWAVE SYNC ---
            logger.info("Starting background Remnawave sync...")
            data = load_data()
            if data.get('settings', {}).get('sync', {}).get('remnawave_sync_users'):
                count, msg = await sync_users_with_remnawave(data)
                logger.info(f"Background Remnawave sync finished: {count} users updated. {msg}")
            else:
                logger.info("Background Remnawave sync skipped (disabled in settings)")
                
        except Exception as e:
            logger.error(f"Error in periodic_background_tasks: {e}")
            
        # Wait 10 minutes before next sync
        await asyncio.sleep(600)


# ======================== PAGE ROUTES ========================

@app.get('/login', response_class=HTMLResponse, tags=["System Templates"])
def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse(url='/', status_code=302)
    return tpl(request, 'login.html')


@app.get("/set_lang/{lang}", tags=["System Templates"])
def set_lang(lang: str, request: Request):
    if lang not in TRANSLATIONS:
        return JSONResponse({'error': 'Unsupported language'}, status_code=400)
    # Referer is untrusted: keep only a same-origin path, never an external URL.
    ref = request.headers.get("referer", "/")
    target = '/'
    try:
        parsed = urllib.parse.urlsplit(ref)
        origin = urllib.parse.urlsplit(str(request.base_url))
        same_origin = (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)
        relative = not parsed.scheme and not parsed.netloc
        if (same_origin or relative) and not any(c in ref for c in (chr(92), chr(13), chr(10))):
            path = parsed.path or '/'
            if path.startswith('/') and not path.startswith('//'):
                target = urllib.parse.urlunsplit(('', '', path, parsed.query, ''))
    except ValueError:
        pass
    response = RedirectResponse(url=target)
    response.set_cookie(key="lang", value=lang, max_age=31536000,
                        httponly=True, secure=request.url.scheme == 'https', samesite='lax')
    return response


@app.get('/logout', tags=["System Templates"])
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/login', status_code=302)


@app.get('/', response_class=HTMLResponse, tags=["System Templates"])
def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    return tpl(request, 'index.html', servers=data['servers'])


@app.get('/servers/new', response_class=HTMLResponse, tags=["System Templates"])
def server_new_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user.get('role') != 'admin':
        # Support operators can manage servers but cannot enroll new SSH hosts.
        return HTMLResponse('<h1>403 Forbidden</h1>', status_code=403)
    return tpl(request, 'server_new.html')


@app.get('/server/{server_id}', response_class=HTMLResponse, tags=["System Templates"])
async def server_detail(request: Request, server_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    async with DATA_LOCK:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return RedirectResponse(url='/')
        # Startup normally migrates these. Also cover legacy state restored
        # while running, before stamping an actionable UID into the page.
        if backfill_server_uids(data['servers']):
            save_data(data)
    server = data['servers'][server_id]
    users_list = data.get('users', [])
    return tpl(request, 'server.html', server=server, server_id=server_id, users=users_list)


@app.get('/users', response_class=HTMLResponse, tags=["System Templates"])
def users_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    users_list = data.get('users', [])
    # Count connections per user
    conns = data.get('user_connections', [])
    for u in users_list:
        u['connections_count'] = sum(1 for c in conns if c['user_id'] == u['id'])
    servers = data['servers']
    return tpl(request, 'users.html', users=users_list, servers=servers)


@app.get('/my', response_class=HTMLResponse, tags=["System Templates"])
def my_connections_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    # Enrich with server names
    for c in conns:
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', data['servers'][sid].get('host', ''))
        else:
            c['server_name'] = 'Unknown'
    return tpl(request, 'my_connections.html', connections=conns)


# ======================== AUTH API ========================

@app.get('/api/auth/captcha', tags=["Authentication"])
def api_captcha(request: Request):
    if not CaptchaGenerator:
        return JSONResponse({"error": "multicolorcaptcha is not installed"}, status_code=500)
    
    # 2 is a multiplier for the image resolution size
    generator = CaptchaGenerator(2)
    captcha = generator.gen_captcha_image(difficult_level=2)
    request.session.pop('captcha_answer', None)  # Remove legacy disclosed answers.
    captcha_challenges.discard(request.session.pop('captcha_challenge_id', None))
    request.session['captcha_challenge_id'] = captcha_challenges.issue(captcha.characters)
    
    img_bytes = io.BytesIO()
    captcha.image.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return StreamingResponse(img_bytes, media_type="image/png")


@app.post('/api/auth/login', tags=["Authentication"])
def api_login(request: Request, req: LoginRequest):
    data = load_data()
    captcha_settings = data.get('settings', {}).get('captcha', {})
    request.session.pop('captcha_answer', None)  # Never accept legacy cookie answers.
    if captcha_settings.get('enabled') is True:
        challenge_id = request.session.pop('captcha_challenge_id', None)
        lang = request.cookies.get('lang', 'ru')
        if not captcha_challenges.consume(challenge_id, req.captcha):
            return JSONResponse({'error': _t('invalid_captcha', lang)}, status_code=400)

    for u in data.get('users', []):
        # Users without a password (role 'none', record-only) can never log in.
        if u.get('username') == req.username and u.get('password_hash') and verify_password(req.password, u['password_hash']):
            lang = request.cookies.get('lang', 'ru')
            if u.get('role') == 'none':
                # Record-only account: even a password set later does not
                # grant access until a real role is assigned.
                return JSONResponse({'error': _t('invalid_login', lang)}, status_code=401)
            if not u.get('enabled', True):
                return JSONResponse({'error': _t('account_disabled', lang)}, status_code=403)
            request.session['user_id'] = u['id']
            return {'status': 'success', 'role': u['role']}
    lang = request.cookies.get('lang', 'ru')
    return JSONResponse({'error': _t('invalid_login', lang)}, status_code=401)


# ======================== SERVER API (admin/support) ========================

def _check_admin(request):
    """Authorize an admin/support action via session cookie OR Bearer token.

    Tokens are admin-equivalent and inherit the role of the user who created
    them — if that user is later disabled or demoted, the token stops working.
    """
    user = get_current_user(request)
    if user and user['role'] in ('admin', 'support'):
        return user

    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        raw_token = auth_header[7:].strip()
        data = load_data()
        resolved = _resolve_api_token(data, raw_token)
        if resolved:
            entry, token_user = resolved
            # Best-effort last-used tracking; swallow write errors so a flaky
            # disk never blocks an API call from succeeding.
            try:
                if _touch_api_token(entry):
                    save_data(data)
            except Exception as e:
                logger.warning(f"Failed to touch API token last_used_at: {e}")
            return token_user

    return None


class SSHTrustConfirmation(BaseModel):
    token: constr(min_length=1, max_length=4096)
    confirmed: StrictBool


class SSHOnboardingEndpoint(BaseModel):
    host: constr(min_length=1, max_length=253)
    ssh_port: conint(strict=True, ge=1, le=65535) = 22
    server_uid: Optional[constr(min_length=1, max_length=128)] = None

    class Config:
        # Inspect/confirm must never receive SSH authentication material.
        extra = 'forbid'


class SSHOnboardingConfirmation(SSHOnboardingEndpoint, SSHTrustConfirmation):
    pass


def _ssh_onboarding_endpoint(req):
    endpoint = {'host': req.host, 'ssh_port': req.ssh_port,
                'uid': req.server_uid, 'enrollment_context': 'new-server'}
    ssh_trust.identity(endpoint)
    if req.server_uid:
        current = next((s for s in load_data()['servers'] if s.get('uid') == req.server_uid), None)
        if current is None:
            raise ValueError('Server no longer exists; refresh inventory')
        endpoint['enrollment_context'] = ssh_trust.inventory_binding(current)
    return endpoint


@app.post('/api/ssh-trust/onboarding/inspect', tags=["Servers"])
async def api_ssh_onboarding_inspect(request: Request, req: SSHOnboardingEndpoint):
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        async with DATA_LOCK:
            endpoint = _ssh_onboarding_endpoint(req)
        result = await asyncio.to_thread(ssh_trust.inspect, endpoint)
        async with DATA_LOCK:
            if endpoint != _ssh_onboarding_endpoint(req):
                raise ValueError('Server endpoint changed; inspect again')
        return result
    except Exception as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)


@app.post('/api/ssh-trust/onboarding/confirm', tags=["Servers"])
async def api_ssh_onboarding_confirm(request: Request, req: SSHOnboardingConfirmation):
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not req.confirmed:
        return JSONResponse({'error': 'Explicit confirmation required'}, status_code=400)
    try:
        async with DATA_LOCK:
            endpoint = _ssh_onboarding_endpoint(req)
            reset_server = next((dict(s) for s in load_data()['servers']
                                 if s.get('uid') == req.server_uid), None) if req.server_uid else None
        key = await asyncio.to_thread(ssh_trust.prepare_enrollment, endpoint, req.token)
        result = await _save_ssh_confirmation(endpoint, req.token, key,
            lambda: endpoint == _ssh_onboarding_endpoint(req), reset_server)
        return dict(result, ssh_authenticated=False)
    except Exception as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)


def _ssh_trust_admin(request):
    # Keep session/Bearer authorization; reject cross-origin browser writes.
    origin = request.headers.get('origin')
    fetch_site = request.headers.get('sec-fetch-site')
    # Modern browsers supply unforgeable-by-JS same-origin metadata even
    # behind TLS-terminating proxies. Do not trust arbitrary Forwarded headers.
    if origin and fetch_site != 'same-origin' and origin.rstrip('/') != str(request.base_url).rstrip('/'):
        return False
    if fetch_site in ('cross-site', 'same-site'):
        return False
    user = _check_admin(request)
    return bool(user and user['role'] == 'admin')


@app.post('/api/servers/{server_id}/ssh-trust/inspect', tags=["Servers"])
def api_ssh_trust_inspect(request: Request, server_id: int, server_uid: Optional[str] = None):
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    servers = load_data()['servers']
    if not 0 <= server_id < len(servers):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    if server_uid is not None and servers[server_id].get('uid') != server_uid:
        return JSONResponse({'error': 'Inventory changed; refresh and retry'}, status_code=409)
    try:
        return ssh_trust.inspect(servers[server_id])
    except Exception as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)


@app.get('/api/servers/{server_id}/ssh-trust/status', tags=["Servers"])
def api_ssh_trust_status(request: Request, server_id: int, server_uid: Optional[str] = None):
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    servers = load_data()['servers']
    if not 0 <= server_id < len(servers):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    if server_uid is not None and servers[server_id].get('uid') != server_uid:
        return JSONResponse({'error': 'Inventory changed; refresh and retry'}, status_code=409)
    try:
        return {'status': ssh_trust.saved_status(servers[server_id])}
    except Exception as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)


async def _finish_locked_worker(function):
    """Do not release a caller's lock while its worker can still mutate state."""
    worker = asyncio.create_task(asyncio.to_thread(function))
    cancelled = False
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    if cancelled:
        # Retrieve any worker exception, but preserve the request cancellation.
        if not worker.cancelled():
            worker.exception()
        raise asyncio.CancelledError
    return worker.result()


async def _save_ssh_confirmation(endpoint, token, key, unchanged, reset_server):
    committed = []
    def commit():
        result = ssh_trust.commit_enrollment(endpoint, token, key, validate_endpoint=unchanged)
        committed.append(True)
        return result
    try:
        async with DATA_LOCK:
            return await _finish_locked_worker(commit)
    finally:
        # A pooled transport can be busy with a handshake/command. Wait outside
        # DATA_LOCK, including if the HTTP request was cancelled during commit.
        if committed and reset_server is not None:
            await _finish_locked_worker(lambda: drop_ssh(reset_server))


@app.post('/api/servers/{server_id}/ssh-trust/confirm', tags=["Servers"])
async def api_ssh_trust_confirm(request: Request, server_id: int, req: SSHTrustConfirmation,
                                server_uid: Optional[str] = None):
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not req.confirmed:
        return JSONResponse({'error': 'Explicit confirmation required'}, status_code=400)
    servers = load_data()['servers']
    if not 0 <= server_id < len(servers):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = servers[server_id]
    if server_uid is not None and server.get('uid') != server_uid:
        return JSONResponse({'error': 'Inventory changed; refresh and retry'}, status_code=409)
    try:
        key = await asyncio.to_thread(ssh_trust.prepare_enrollment, server, req.token)
        def unchanged():
            current = load_data()['servers']
            return any(all(s.get(k) == server.get(k) for k in ('uid', 'host', 'ssh_port'))
                       for s in current)
        return await _save_ssh_confirmation(server, req.token, key, unchanged, server)
    except Exception as exc:
        return JSONResponse({'error': str(exc)}, status_code=409)


def _server_identity(server_id, server_uid=None):
    servers = load_data()['servers']
    if not 0 <= server_id < len(servers):
        return None, JSONResponse({'error': 'Server not found'}, status_code=404)
    server = servers[server_id]
    if not server.get('uid') or (server_uid is not None and server_uid != server['uid']):
        return None, JSONResponse({'error': 'Server identity changed; refresh the inventory'}, status_code=409)
    return server, None


async def _finish_server_operation(operation):
    """A disconnected HTTP caller must not abandon in-flight SSH mutations.

    The worker owns SERVER_MUTATION_LOCK until cleanup and persistence finish;
    cancellation is then propagated to the caller, including repeated cancels.
    """
    worker = asyncio.create_task(operation)
    cancelled = False
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    if cancelled:
        if not worker.cancelled():
            worker.exception()
        raise asyncio.CancelledError
    return worker.result()


def _classify_ssh_error(exc):
    """Map SSH/save failures to a stable machine-readable code.

    The typed checks come first; the message fallback only distinguishes
    the two host-key states Paramiko reports as generic SSHException.
    """
    import paramiko as _paramiko

    if isinstance(exc, _paramiko.AuthenticationException):
        return 'authentication_failed'
    if isinstance(exc, _paramiko.BadHostKeyException):
        return 'host_key_changed'
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return 'network_error'
    if isinstance(exc, _paramiko.SSHException):
        message = str(exc).lower()
        if 'not found in known_hosts' in message:
            return 'host_key_unknown'
        if 'host key' in message and any(
                marker in message for marker in ('does not match', 'mismatch', 'changed')):
            return 'host_key_changed'
        if any(marker in message for marker in (
                'authentication', 'auth failed', 'private key', 'password')):
            return 'authentication_failed'
        # Remaining Paramiko handshake/transport failures are reachability
        # problems: banner errors, refused/invalid connections, closed peers.
        return 'network_error'
    return 'internal_error'


def _exception_text(exc):
    try:
        return str(exc)
    except Exception:
        return type(exc).__name__


def _enrollment_payload(req):
    """Validate an add/test request and return the normalized fields."""
    host = req.host.strip()
    username = req.username.strip()
    if not host or not username:
        raise ValueError('Host and username are required')
    if not req.password and not req.private_key:
        raise ValueError('Password or SSH key is required')
    return host, username


@app.post('/api/servers/test', tags=["Servers"])
async def api_test_server(request: Request, req: AddServerRequest):
    """Test host-key trust, authentication and connectivity without saving.

    First enrollment is trust-on-first-use: an unknown key is pinned after a
    key-only probe, then credentials are tested. A changed key is never
    overridden here; the UI must confirm it through the onboarding endpoint.
    """
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden', 'error_code': 'forbidden'}, status_code=403)
    try:
        host, username = _enrollment_payload(req)
    except ValueError as exc:
        return JSONResponse({'error': str(exc), 'error_code': 'validation_error'},
                            status_code=400)

    endpoint = {'host': host, 'ssh_port': req.ssh_port, 'uid': None,
                'enrollment_context': 'new-server'}
    try:
        inspection = await asyncio.to_thread(ssh_trust.inspect, endpoint)
    except Exception as exc:
        error_code = _classify_ssh_error(exc)
        logger.warning("Server test host-key inspection failed: %s (%s)",
                       error_code, type(exc).__name__)
        return JSONResponse({'error': f'Host key check failed: {_exception_text(exc)}',
                             'error_code': error_code}, status_code=400)

    if inspection.get('status') == 'changed':
        # Do not authenticate and do not overwrite the pin. The client must
        # show the old/new fingerprints and explicitly confirm the new key.
        return JSONResponse({
            'error': 'Host key changed; verify and accept the new key',
            'error_code': 'host_key_changed',
            'host_key': inspection,
        }, status_code=409)

    try:
        if inspection.get('status') == 'unknown':
            await asyncio.to_thread(ssh_trust.enroll, endpoint, inspection['token'])
    except Exception as exc:
        error_code = _classify_ssh_error(exc)
        logger.warning("Server test host-key pin failed: %s (%s)",
                       error_code, type(exc).__name__)
        return JSONResponse({'error': f'Host key pin failed: {_exception_text(exc)}',
                             'error_code': error_code}, status_code=400)

    def verify():
        ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)
        try:
            ssh.connect()
            return ssh.test_connection()
        finally:
            ssh.disconnect()

    try:
        server_info = await asyncio.to_thread(verify)
    except Exception as exc:
        error_code = _classify_ssh_error(exc)
        # Never log credentials or raw connection detail.
        logger.warning("Server test authentication failed: %s (%s)",
                       error_code, type(exc).__name__)
        return JSONResponse({'error': f'Connection failed: {_exception_text(exc)}',
                             'error_code': error_code}, status_code=400)

    return {
        'status': 'success',
        'server_info': server_info,
        'host_key': {
            'host': host, 'port': req.ssh_port,
            'algorithm': inspection['algorithm'],
            'fingerprint': inspection['fingerprint'],
            'status': 'pinned' if inspection.get('status') == 'unknown' else 'trusted',
        },
    }


@app.post('/api/servers/add', tags=["Servers"])
@serialize_peer_lifecycle
async def api_add_server(request: Request, req: AddServerRequest):
    actor = _check_admin(request)
    # Enrolling a new SSH host is an administrator-only action. Keep the
    # isinstance guard because some callers/tests inject a truthy sentinel.
    if not actor or (isinstance(actor, dict) and actor.get('role') != 'admin'):
        return JSONResponse({'error': 'Forbidden', 'error_code': 'forbidden'}, status_code=403)
    try:
        host = req.host.strip()
        username = req.username.strip()
        name = req.name.strip() or host
        if not host or not username:
            return JSONResponse({'error': 'Host and username are required',
                                 'error_code': 'validation_error'}, status_code=400)
        if not req.password and not req.private_key:
            return JSONResponse({'error': 'Password or SSH key is required',
                                 'error_code': 'validation_error'}, status_code=400)

        def verify():
            ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)
            try:
                ssh.connect()
                return ssh.test_connection()
            finally:
                ssh.disconnect()
        try:
            server_info = await asyncio.to_thread(verify)
        except Exception as e:
            error_code = _classify_ssh_error(e)
            # Log only the classification and exception type; credentials and
            # raw Paramiko/OS detail must never reach the panel log here.
            logger.warning("Server add verification failed: %s (%s)",
                           error_code, type(e).__name__)
            return JSONResponse({'error': f'Connection failed: {_exception_text(e)}',
                                 'error_code': error_code}, status_code=400)

        server = {
            'uid': uuid.uuid4().hex,
            'name': name, 'host': host, 'ssh_port': req.ssh_port,
            'username': username, 'password': req.password,
            'private_key': req.private_key, 'server_info': server_info,
            'protocols': {},
        }
        async with SERVER_MUTATION_LOCK:
            async with DATA_LOCK:
                data = load_data()
                data['servers'].append(server)
                save_data(data)
                server_id = len(data['servers']) - 1
        return {'status': 'success', 'server_id': server_id, 'server_info': server_info}
    except Exception as e:
        logger.exception("Error adding server")
        return JSONResponse({'error': _exception_text(e), 'error_code': 'internal_error'}, status_code=500)


@app.post('/api/servers/{server_id}/edit', tags=["Servers"])
@serialize_peer_lifecycle
async def api_edit_server(request: Request, server_id: int, req: EditServerRequest,
                          server_uid: Optional[str] = None):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    selected, error = _server_identity(server_id, server_uid)
    if error is not None:
        return error
    uid = selected['uid']

    async def edit():
        async with SERVER_MUTATION_LOCK:
            try:
                async with DATA_LOCK:
                    _, server = find_server_by_uid(load_data(), uid)
                    if server is None:
                        return JSONResponse({'error': 'Server not found'}, status_code=404)
                    server = dict(server)
                new_host = (req.host or '').strip() or server['host']
                new_user = (req.username or '').strip() or server['username']
                new_port = int(req.ssh_port or server.get('ssh_port', 22))
                new_name = (req.name or '').strip() or server.get('name') or new_host
                if req.private_key:
                    new_pass, new_key = '', req.private_key
                elif req.password:
                    new_pass, new_key = req.password, ''
                else:
                    new_pass, new_key = server.get('password', ''), server.get('private_key', '')
                if not new_pass and not new_key:
                    return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

                def verify():
                    ssh = SSHManager(new_host, new_port, new_user, new_pass, new_key)
                    try:
                        ssh.connect()
                        return ssh.test_connection()
                    finally:
                        ssh.disconnect()
                try:
                    server_info = await asyncio.to_thread(verify)
                except Exception as e:
                    return JSONResponse({'error': f'Connection failed: {e}'}, status_code=400)

                async with DATA_LOCK:
                    data = load_data()
                    _, current = find_server_by_uid(data, uid)
                    if current is None or any(current.get(k) != server.get(k) for k in
                                              ('host', 'ssh_port', 'username', 'password', 'private_key')):
                        return JSONResponse({'error': 'Server changed during verification'}, status_code=409)
                    current.update(name=new_name, host=new_host, ssh_port=new_port,
                                   username=new_user, password=new_pass, private_key=new_key,
                                   server_info=server_info)
                    if req.self_service_enabled is not None:
                        current['self_service_enabled'] = bool(req.self_service_enabled)
                    save_data(data)
                # Invalidate the OLD endpoint, not the just-written new address.
                await _finish_locked_worker(lambda: drop_ssh(server))
                return {'status': 'success', 'server_info': server_info}
            except Exception as e:
                logger.exception("Error editing server")
                return JSONResponse({'error': str(e)}, status_code=500)
    return await _finish_server_operation(edit())


@app.get('/api/servers/{server_id}/ping', tags=["Servers"])
async def api_server_ping(request: Request, server_id: int):
    """Cheap reachability check: opens a TCP connection to the SSH port,
    measures RTT, immediately closes. Runs on the asyncio loop so the page
    can issue many pings in parallel without blocking each other.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    host = server['host']
    port = int(server.get('ssh_port', 22))

    import time as _time
    t0 = _time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2.0
        )
        ms = round((_time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        try:
            # A live key-only probe (no credentials) detects a changed host key
            # before the admin opens the server page. Cached saved status alone
            # cannot distinguish "trusted" from "changed".
            inspection = await asyncio.wait_for(
                asyncio.to_thread(ssh_trust.inspect, server), timeout=5.0)
            return {'alive': True, 'ms': ms,
                    'ssh_trust': inspection.get('status', 'error'),
                    'ssh_trust_detail': inspection,
                    'ssh_verified': inspection.get('status') == 'trusted'}
        except Exception:
            return {'alive': True, 'ms': ms, 'ssh_trust': 'error'}
    except asyncio.TimeoutError:
        return {'alive': False, 'error': 'timeout', 'ms': None}
    except Exception as e:
        return {'alive': False, 'error': str(e), 'ms': None}


@app.post('/api/servers/reorder', tags=["Servers"])
@serialize_peer_lifecycle
async def api_reorder_servers(request: Request, req: ReorderServersRequest):
    """Remap the latest connections by stable UID, rejecting stale inventories."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    servers = load_data()['servers']
    n = len(servers)
    order = req.order or []
    if len(order) != n or sorted(order) != list(range(n)):
        return JSONResponse({'error': f'Order must be a permutation of indices 0..{n - 1}'}, status_code=400)
    requested = [servers[i].get('uid') for i in order]
    if (any(not uid for uid in requested) or len(set(requested)) != n or
            (req.server_uids is not None and req.server_uids != requested)):
        return JSONResponse({'error': 'Server identity changed; refresh the inventory'}, status_code=409)
    async with SERVER_MUTATION_LOCK:
        async with DATA_LOCK:
            data = load_data()
            current = data['servers']
            if len(current) != n or {s.get('uid') for s in current} != set(requested):
                return JSONResponse({'error': 'Server inventory changed; refresh before reordering'}, status_code=409)
            by_uid = {s['uid']: s for s in current}
            new_index = {uid: i for i, uid in enumerate(requested)}
            remap = {i: new_index[s['uid']] for i, s in enumerate(current)}
            for c in data.get('user_connections', []):
                old_id = c.get('server_id')
                if isinstance(old_id, int) and old_id in remap:
                    c['server_id'] = remap[old_id]
            sync_cfg = data.get('settings', {}).get('sync', {})
            rsid = sync_cfg.get('remnawave_server_id')
            if isinstance(rsid, int) and rsid in remap:
                sync_cfg['remnawave_server_id'] = remap[rsid]
            data['servers'] = [by_uid[uid] for uid in requested]
            save_data(data)
    return {'status': 'success'}


@app.post('/api/servers/{server_id}/delete', tags=["Servers"])
@serialize_peer_lifecycle
async def api_delete_server(request: Request, server_id: int, server_uid: Optional[str] = None):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    selected, error = _server_identity(server_id, server_uid)
    if error is not None:
        return error
    uid = selected['uid']
    data = load_data()
    guard = _traffic_removal_guard(data, server_id=server_id)
    if guard is not None:
        return guard

    async def delete():
        async with SERVER_MUTATION_LOCK:
            cleanup_completed = False
            deletion_committed = False
            try:
                async with DATA_LOCK:
                    _, server = find_server_by_uid(load_data(), uid)
                    if server is None:
                        return {'status': 'success', 'already_deleted': True}
                results = []
                if (server.get('protocols') or {}).get('exit'):
                    results.extend(await exit_link_svc.detach_entries_for_exit(uid, 'exit_server_deleted'))
                results.extend(await exit_link_svc.forget_entry_peers(server))
                if any(item.get('status') != 'success' for item in results):
                    return JSONResponse({'error': 'Exit-link cleanup incomplete; server retained',
                                         'cleanup_results': results, 'deletion_committed': False}, status_code=409)
                cleanup_completed = True
                async with DATA_LOCK:
                    data = load_data()
                    index, current = find_server_by_uid(data, uid)
                    if current is None:
                        return {'status': 'success', 'already_deleted': True}
                    data['servers'].pop(index)
                    data['user_connections'] = [c for c in data.get('user_connections', [])
                                                if c.get('server_id') != index]
                    for c in data['user_connections']:
                        if c.get('server_id', 0) > index:
                            c['server_id'] -= 1
                    save_data(data)
                    deletion_committed = True
                await _finish_locked_worker(lambda: drop_ssh(server))
                return {'status': 'success'}
            except Exception as e:
                # Remote cleanup is not transactional. Keep the server on a failed
                # local commit, report the partial result, and allow a safe retry.
                logger.exception("Error deleting server uid=%s; cleanup_completed=%s deletion_committed=%s",
                                 uid, cleanup_completed, deletion_committed)
                return JSONResponse({'error': str(e), 'cleanup_completed': cleanup_completed,
                                     'deletion_committed': deletion_committed}, status_code=500)
    return await _finish_server_operation(delete())


@app.post('/api/servers/{server_id}/reboot', tags=["Servers"])
def api_reboot_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        try:
            ssh.run_sudo_command("nohup reboot > /dev/null 2>&1 &")
        except Exception:
            pass            
        try:
            ssh.disconnect()
        except:
            pass
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error rebooting server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/clear', tags=["Servers"])
@serialize_peer_lifecycle
async def api_clear_server(request: Request, server_id: int, server_uid: Optional[str] = None):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    if not 0 <= server_id < len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    guard = _traffic_removal_guard(data, server_id=server_id)
    if guard is not None:
        return guard
    selected = data['servers'][server_id]
    uid = selected.get('uid')
    if not uid or (server_uid is not None and server_uid != uid):
        return JSONResponse({'error': 'Server identity changed; refresh before clearing'}, status_code=409)

    def unchanged(current):
        return current is not None and all(current.get(k) == selected.get(k)
                                          for k in ('host', 'ssh_port', 'username', 'protocols'))

    async def clear():
        remote_completed = False
        local_committed = False
        try:
            async with DATA_LOCK:
                _, server = find_server_by_uid(load_data(), uid)
                if not unchanged(server):
                    return JSONResponse({'error': 'Server changed before cleanup'}, status_code=409)
            results = []
            if (server.get('protocols') or {}).get('exit'):
                results.extend(await exit_link_svc.detach_entries_for_exit(uid, 'exit_cleared'))
            results.extend(await exit_link_svc.forget_entry_peers(server))
            if any(item.get('status') != 'success' for item in results):
                return JSONResponse({'error': 'Exit-link cleanup incomplete; clear aborted',
                                     'cleanup_results': results}, status_code=409)
            async with DATA_LOCK:
                _, server = find_server_by_uid(load_data(), uid)
                if not unchanged(server):
                    return JSONResponse({'error': 'Server changed during exit cleanup'}, status_code=409)

            def run_remote():
                ssh = get_ssh(server)
                try:
                    ssh.connect()
                    cleanup_script = r"""
for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^(amnezia-|telemt$)'); do
    docker stop "$c" >/dev/null 2>&1 || true
    docker rm -fv "$c" >/dev/null 2>&1 || true
done

# Drop locally-built and pulled Amnezia images so reinstall starts from a clean slate
for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '^(amnezia-|amneziavpn/|telemt:)'); do
    docker rmi -f "$img" >/dev/null 2>&1 || true
done

docker network rm amnezia-dns-net >/dev/null 2>&1 || true
rm -rf /opt/amnezia
"""
                    return ssh.run_sudo_script(cleanup_script, timeout=120)
                finally:
                    ssh.disconnect()
            result = await asyncio.to_thread(run_remote)
            if not isinstance(result, (tuple, list)) or len(result) != 3 or result[2] != 0:
                return JSONResponse({'error': 'Remote cleanup failed; protocol metadata retained',
                                     'remote_cleanup_completed': False, 'local_commit_completed': False}, status_code=502)
            remote_completed = True
            async with DATA_LOCK:
                data = load_data()
                _, current = find_server_by_uid(data, uid)
                if not unchanged(current):
                    return JSONResponse({'error': 'Server changed after remote cleanup; refresh and reconcile',
                                         'remote_cleanup_completed': True, 'local_commit_completed': False}, status_code=409)
                current['protocols'] = {}
                save_data(data)
                local_committed = True
            return {'status': 'success'}
        except Exception as e:
            logger.exception("Error clearing server uid=%s; remote_completed=%s local_committed=%s",
                             uid, remote_completed, local_committed)
            return JSONResponse({'error': str(e), 'remote_cleanup_completed': remote_completed,
                                 'local_commit_completed': local_committed}, status_code=500)

    # Do not abandon a destructive worker on HTTP disconnect. Finish its local
    # reconciliation before propagating cancellation; DATA_LOCK is free during SSH.
    worker = asyncio.create_task(clear())
    cancelled = False
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    if cancelled:
        if not worker.cancelled():
            worker.exception()
        raise asyncio.CancelledError
    return worker.result()


@app.post('/api/servers/{server_id}/stats', tags=["Servers"])
def api_server_stats(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        stats = {}
        out, _, _ = ssh.run_command(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || "
            "awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' "
            "<(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null"
        )
        try:
            stats['cpu'] = round(float(out.strip().split('\n')[0]), 1)
        except (ValueError, IndexError):
            stats['cpu'] = 0
        out, _, _ = ssh.run_command("free -b | awk 'NR==2{printf \"%d %d\", $3, $2}'")
        try:
            parts = out.strip().split()
            used, total = int(parts[0]), int(parts[1])
            stats.update(ram_used=used, ram_total=total, ram_percent=round(used / total * 100, 1) if total > 0 else 0)
        except (ValueError, IndexError):
            stats.update(ram_used=0, ram_total=0, ram_percent=0)
        out, _, _ = ssh.run_command("df -B1 / | awk 'NR==2{printf \"%d %d\", $3, $2}'")
        try:
            parts = out.strip().split()
            used, total = int(parts[0]), int(parts[1])
            stats.update(disk_used=used, disk_total=total, disk_percent=round(used / total * 100, 1) if total > 0 else 0)
        except (ValueError, IndexError):
            stats.update(disk_used=0, disk_total=0, disk_percent=0)
        out, _, _ = ssh.run_command(
            "DEV=$(ip route | awk '/default/ {print $5}' | head -1); "
            "cat /proc/net/dev | awk -v dev=\"$DEV:\" '$1==dev{printf \"%d %d\", $2, $10}'"
        )
        try:
            parts = out.strip().split()
            stats['net_rx'], stats['net_tx'] = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            stats['net_rx'] = stats['net_tx'] = 0
        out, _, _ = ssh.run_command("uptime -p 2>/dev/null || uptime")
        stats['uptime'] = out.strip()
        # Global IPv6 addresses for the page header. Some providers mark ULA
        # (fd00::/8) addresses as scope global, so filter them out explicitly.
        # Small point-to-point transit prefixes (/126 etc. between the box and
        # the provider's router) are infrastructure, not a public address.
        out, _, _ = ssh.run_command(
            "ip -6 addr show scope global 2>/dev/null | "
            "awk '/inet6/ && $2 !~ /^fd[0-9a-fA-F]{2}:/ {"
            "split($2, a, \"/\"); if (a[2] <= 64) print a[1]}'"
        )
        stats['ipv6'] = [a for a in (line.strip() for line in out.splitlines()) if a]
        ssh.disconnect()
        return stats
    except Exception as e:
        logger.exception("Error getting server stats")
        return JSONResponse({'error': str(e)}, status_code=500)


RKN_RAW_BASE = ('https://raw.githubusercontent.com/PRVTPRO/Amnezia-Web-Panel/'
                'main/scripts/rknblock')

RKN_INSTALL_CMD = (
    f'curl -fsSL {RKN_RAW_BASE}/install-rkn-extra.sh '
    '-o /tmp/rkn-install.sh && bash /tmp/rkn-install.sh'
)

RKN_SCRIPT_URL = f'{RKN_RAW_BASE}/rkn-extra-block.sh'


def _rkn_run_cmd(subcommand):
    """Fetch the current script to /tmp, refresh the host copy, run a subcommand.

    Server-side copies may predate newer subcommands (`uninstall`, `set`);
    always driving a fresh copy keeps every server able to run every
    subcommand regardless of the version it was installed with.
    """
    return (f'curl -fsSL {RKN_SCRIPT_URL} -o /tmp/rkn-extra-block-run.sh '
            f'&& install -m 0755 /tmp/rkn-extra-block-run.sh /usr/local/sbin/rkn-extra-block '
            f'&& bash /tmp/rkn-extra-block-run.sh {subcommand}; '
            f'rc=$?; rm -f /tmp/rkn-extra-block-run.sh; exit $rc')


def _rkn_record(server):
    return server.get('rknblock') or {}


def _rkn_server_index(data, server_id, server_uid, expected=None):
    """Resolve a server after a long SSH call: uid survives reorder/delete,
    legacy index-only callers still need one persisted, unambiguous UID."""
    servers = data.get('servers', [])
    if server_uid is None and isinstance(server_id, int) and 0 <= server_id < len(servers):
        server_uid = servers[server_id].get('uid')
    matches = [idx for idx, srv in enumerate(servers) if server_uid and srv.get('uid') == server_uid]
    if len(matches) != 1:
        return None
    idx = matches[0]
    if expected is not None and any(servers[idx].get(k) != expected.get(k)
                                   for k in ('uid', 'host', 'ssh_port', 'username', 'password', 'private_key')):
        return None
    return idx


async def _rkn_store_record(server_id, server_uid, mutate, expected=None):
    """Reload under DATA_LOCK after SSH and persist only the RKN record.

    RKN install/enable/options take seconds and the old code saved a whole
    data.json snapshot loaded before the SSH call. A background traffic save
    or another admin action could then overwrite the new record with a stale
    snapshot, leaving the card at "not installed" right after a successful
    install.
    """
    async with DATA_LOCK:
        data = load_data()
        idx = _rkn_server_index(data, server_id, server_uid, expected)
        if idx is None:
            return None
        rec = dict(data['servers'][idx].get('rknblock') or {})
        mutate(rec)
        data['servers'][idx]['rknblock'] = rec
        save_data(data)
        return rec


async def _rkn_drop_record(server_id, server_uid, expected=None):
    async with DATA_LOCK:
        data = load_data()
        idx = _rkn_server_index(data, server_id, server_uid, expected)
        if idx is None:
            return False
        data['servers'][idx].pop('rknblock', None)
        save_data(data)
        return True


async def _rkn_ssh_run(server, cmd, timeout):
    ssh = await asyncio.to_thread(get_ssh, server)
    try:
        await asyncio.to_thread(ssh.connect)
        if _rkn_server_index(load_data(), None, server.get('uid'), server) is None:
            return JSONResponse({'error': 'Server identity changed; refresh the inventory'}, status_code=409)
        out, err, code = await asyncio.to_thread(ssh.run_sudo_command, cmd, timeout)
    finally:
        try:
            ssh.disconnect()
        except Exception:
            pass
    if _rkn_server_index(load_data(), None, server.get('uid'), server) is None:
        return JSONResponse({'error': 'Server identity changed; refresh the inventory'}, status_code=409)
    if code != 0:
        return JSONResponse({'error': f'command failed: {(err or out or "").strip()[-500:]}'},
                            status_code=500)
    return None


@app.post('/api/servers/{server_id}/rknblock/install', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rknblock_install(request: Request, server_id: int, server_uid: str | None = None):
    """Install the RKN/VK network blocking app (rkn-extra-block contour)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    if _rkn_record(server).get('installed'):
        return JSONResponse({'error': 'App is already installed; refresh its status'}, status_code=409)
    server_uid = server.get('uid')
    err = await _rkn_ssh_run(server, RKN_INSTALL_CMD, 420)
    if err is not None:
        return err

    def mark(rec):
        rec['installed'] = True
        rec['enabled'] = True
        rec['last_error'] = None

    rec = await _rkn_store_record(server_id, server_uid, mark, server)
    if rec is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    RKN_FLAG_CACHE.clear()
    return {'status': 'success', 'installed': True, 'enabled': True}


@app.post('/api/servers/{server_id}/rknblock/uninstall', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rknblock_uninstall(request: Request, server_id: int, server_uid: str | None = None):
    """Fully remove the blocking contour: rules, sets, units, scripts, logs."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    server_uid = server.get('uid')
    err = await _rkn_ssh_run(server, _rkn_run_cmd('uninstall'), 180)
    if err is not None:
        return err
    if not await _rkn_drop_record(server_id, server_uid, server):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    RKN_FLAG_CACHE.clear()
    return {'status': 'success', 'installed': False}


class RknBlockEnableRequest(BaseModel):
    enabled: bool = True


@app.post('/api/servers/{server_id}/rknblock/enable', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rknblock_enable(request: Request, server_id: int, req: RknBlockEnableRequest, server_uid: str | None = None):
    """Start or stop the blocking contour (rules jump in/out; lists stay)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    if not _rkn_record(server).get('installed'):
        return JSONResponse({'error': 'App is not installed'}, status_code=409)
    server_uid = server.get('uid')
    err = await _rkn_ssh_run(server, _rkn_run_cmd('on' if req.enabled else 'off'), 180)
    if err is not None:
        return err

    def mark(rec):
        rec['installed'] = True
        rec['enabled'] = bool(req.enabled)
        rec['last_error'] = None

    rec = await _rkn_store_record(server_id, server_uid, mark, server)
    if rec is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    RKN_FLAG_CACHE.clear()
    return {'status': 'success', 'enabled': bool(req.enabled)}


@app.post('/api/servers/{server_id}/rknblock/update', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rknblock_update(request: Request, server_id: int, server_uid: str | None = None):
    """Re-download the C24Be lists and atomically reload the ipset sets."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    if not _rkn_record(server).get('installed'):
        return JSONResponse({'error': 'App is not installed'}, status_code=409)
    err = await _rkn_ssh_run(server, _rkn_run_cmd('update'), 300)
    if err is not None:
        return err
    RKN_FLAG_CACHE.pop(server_id, None)
    return {'status': 'success', 'updated': True}


RKN_OPTION_FLAGS = ('block_in', 'block_out', 'log_in', 'log_out')


class RknBlockOptionsRequest(BaseModel):
    block_in: bool = True
    block_out: bool = True
    log_in: bool = True
    log_out: bool = True


@app.post('/api/servers/{server_id}/rknblock/options', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rknblock_options(request: Request, server_id: int, req: RknBlockOptionsRequest, server_uid: str | None = None):
    """Set per-direction block/log flags on the host contour (chains rebuilt only)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    if not _rkn_record(server).get('installed'):
        return JSONResponse({'error': 'App is not installed'}, status_code=409)
    values = req.model_dump()
    pairs = ' '.join(f'{k}={"on" if values[k] else "off"}' for k in RKN_OPTION_FLAGS)
    server_uid = server.get('uid')
    err = await _rkn_ssh_run(server, _rkn_run_cmd(f'set {pairs}'), 120)
    if err is not None:
        return err

    def mark(rec):
        rec['installed'] = True
        rec['flags'] = values
        rec['last_error'] = None

    rec = await _rkn_store_record(server_id, server_uid, mark, server)
    if rec is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    RKN_FLAG_CACHE.clear()
    return {'status': 'success', 'flags': values}


RKN_SCAN_SSH_CMD = ("rkn-extra-block status 2>/dev/null | head -10; "
                      "echo '===LOG==='; tail -n 2000 /var/log/rkn-scans.json 2>/dev/null")


def _parse_rkn_scan_output(out, flag_enabled):
    """Parse `rkn-extra-block status` + rkn-scans.json tail into a summary dict."""
    agent_state = 'unknown'
    log_part = ''
    status_part = ''
    if '===LOG===' in (out or ''):
        status_part, log_part = out.split('===LOG===', 1)
        first_line = status_part.strip().splitlines()[0] if status_part.strip() else ''
        if ':' in first_line:
            agent_state = first_line.split(':', 1)[1].strip()
    # Наполненность наборов из cmd_status: "входящие...: v4=N сетей v6=M сетей"
    sets = {'in4': 0, 'in6': 0, 'out4': 0, 'out6': 0}
    counts = re.findall(r'v[46]=(\d+)', status_part)
    if len(counts) >= 4:
        sets = dict(zip(('in4', 'in6', 'out4', 'out6'), (int(c) for c in counts[:4])))
    # Флаги направлений из строки "flags: block_in=on block_out=on log_in=on log_out=on"
    flags = {}
    m = re.search(r'flags:\s*([^\n]+)', status_part)
    if m:
        for kv in m.group(1).split():
            if '=' in kv:
                k, v = kv.split('=', 1)
                flags[k.strip()] = v.strip()
    # Дата последнего обновления баз из строки "last_update: 2026-10-16T12:00:00Z"
    last_update = None
    m = re.search(r'last_update:\s*(\S+)', status_part)
    if m and m.group(1) != '—':
        last_update = m.group(1)
    # Новый статус печатает health: ok|failed после проверки наборов и правил.
    # Старые версии строку не печатают; тогда здоровье определяется по sets.
    health = None
    m = re.search(r'health:\s*(\w+)', status_part)
    if m:
        health = m.group(1).lower()
    events = []
    for line in (log_part or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            ev = json.loads(line)
            if isinstance(ev, dict) and 't' in ev:
                events.append(ev)
        except ValueError:
            continue

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    by_org, by_dpt, by_dir = {}, {}, {}
    last_24h = 0
    last_ts = None
    for ev in events:
        org = str(ev.get('org') or '?')
        by_org[org] = by_org.get(org, 0) + 1
        dpt = ev.get('dpt', 0)
        by_dpt[dpt] = by_dpt.get(dpt, 0) + 1
        direction = ev.get('dir', '?')
        by_dir[direction] = by_dir.get(direction, 0) + 1
        try:
            ts = datetime.fromisoformat(str(ev['t']).replace('Z', '+00:00'))
            if ts >= day_ago:
                last_24h += 1
            if last_ts is None or ts > last_ts:
                last_ts = ts
        except ValueError:
            pass

    sets_ok = sets.get('in4', 0) > 0 and sets.get('out4', 0) > 0
    problems = []
    if agent_state != 'on':
        problems.append('not_running')
    if not sets_ok:
        problems.append('lists_empty')
    if health == 'failed':
        problems.append('health_failed')

    return {
        'flag_enabled': bool(flag_enabled),
        'agent_state': agent_state,
        'health': health,
        'sets_ok': sets_ok,
        'problems': problems,
        'sets': sets,
        'flags': flags,
        'last_update': last_update,
        'total_events': len(events),
        'last_24h': last_24h,
        'last_event': last_ts.isoformat() if last_ts else None,
        'by_org': sorted(by_org.items(), key=lambda kv: -kv[1])[:10],
        'by_dpt': sorted(by_dpt.items(), key=lambda kv: -kv[1])[:10],
        'by_dir': by_dir,
        'recent': events[-5:][::-1],
    }


async def _fetch_rkn_scan_output(server):
    """SSH to a server and fetch the rkn-extra-block status line + scan log tail."""
    ssh = await asyncio.to_thread(get_ssh, server)
    try:
        await asyncio.to_thread(ssh.connect)
        if _rkn_server_index(load_data(), None, server.get('uid'), server) is None:
            raise ValueError('Server identity changed')
        out, _, _ = await asyncio.to_thread(ssh.run_sudo_command, RKN_SCAN_SSH_CMD, 60)
    finally:
        try:
            ssh.disconnect()
        except Exception:
            pass
    return out


@app.get('/api/servers/{server_id}/rkn_scans', tags=["Servers"])
async def api_rkn_scans(request: Request, server_id: int, server_uid: str | None = None):
    """Compact scan statistics collected hourly by rkn-agent on the server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    identity = [server.get(k) for k in ('uid', 'host', 'ssh_port', 'username')]
    previous_record = dict(server.get('rknblock') or {})
    available = True
    try:
        out = await _fetch_rkn_scan_output(server)
        available = '===LOG===' in (out or '')
    except Exception:
        out, available = '', False
    current = load_data()
    idx = _rkn_server_index(current, server_id, identity[0])
    if idx is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = current['servers'][idx]
    if [server.get(k) for k in ('uid', 'host', 'ssh_port', 'username')] != identity:
        return JSONResponse({'error': 'Server identity changed; refresh the inventory'}, status_code=409)
    if (server.get('rknblock') or {}) != previous_record:
        out, available = '', False  # A mutation committed while the probe was running.
    record = server.get('rknblock') or {}
    installed = bool(record.get('installed'))
    parsed = _parse_rkn_scan_output(out, installed)
    installed = installed or parsed.get('agent_state') in ('on', 'off')
    live_on = available and parsed.get('agent_state') == 'on'
    parsed['installed'] = installed
    parsed['available'] = available and (not installed or parsed.get('agent_state') != 'unknown')
    parsed['server_uid'] = server.get('uid')
    parsed['enabled'] = bool(record.get('enabled', True)) if installed else False
    parsed['running'] = bool(installed and live_on)
    parsed['healthy'] = bool(installed and live_on
                             and parsed.get('sets_ok')
                             and parsed.get('health') != 'failed')
    parsed['last_error'] = record.get('last_error')
    return parsed


@app.post('/api/servers/{server_id}/rkn_scans/clear', tags=["Servers"])
@serialize_peer_lifecycle
async def api_rkn_scans_clear(request: Request, server_id: int, server_uid: str | None = None):
    """Truncate the remote rkn-scans.json so the admin can acknowledge sightings."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    server_id = _rkn_server_index(data, server_id, server_uid)
    if server_id is None:
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = dict(data['servers'][server_id])
    error = await _rkn_ssh_run(server,
        'rkn-extra-block clearscans 2>/dev/null || : > /var/log/rkn-scans.json', 30)
    if error is not None:
        return error
    RKN_FLAG_CACHE.pop(server_id, None)
    return {'status': 'cleared'}


RKN_FLAG_CACHE = {}
RKN_FLAG_CACHE_TTL = 900  # seconds; scan flags on the overview page


@app.get('/api/servers/rkn_scan_flags', tags=["Servers"])
async def api_rkn_scan_flags(request: Request):
    """Lightweight per-server scan flags for the servers overview page.

    Returns {server_id: {agent_state, events24, last, flag}} for servers whose
    rkn-agent responded. Results are cached for RKN_FLAG_CACHE_TTL seconds so
    the overview page doesn't SSH into every server on each load.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    now = time.time()

    async def collect(idx, srv):
        cached = RKN_FLAG_CACHE.get(idx)
        if cached and now - cached['ts'] < RKN_FLAG_CACHE_TTL:
            return idx, cached['data']
        try:
            out = await _fetch_rkn_scan_output(srv)
            installed = bool((srv.get('rknblock') or {}).get('installed'))
            parsed = _parse_rkn_scan_output(out, installed)
            live_on = parsed.get('agent_state') == 'on'
            summary = {'agent_state': parsed['agent_state'],
                       'running': bool(installed and live_on),
                       'healthy': bool(installed and live_on
                                       and parsed.get('sets_ok')
                                       and parsed.get('health') != 'failed'),
                       'problems': parsed.get('problems', []),
                       'events24': parsed['last_24h'],
                       'last': parsed['last_event'],
                       'flag': bool(installed),
                       'installed': bool(installed),
                       'sets': parsed['sets']}
        except Exception:
            summary = None
        RKN_FLAG_CACHE[idx] = {'ts': now, 'data': summary}
        return idx, summary

    results = await asyncio.gather(
        *[collect(i, s) for i, s in enumerate(data['servers'])])
    return {str(i): s for i, s in results if s}


@app.post('/api/servers/{server_id}/check', tags=["Servers"])
def api_check_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        # Just use awg's docker checker since it uses the same command
        manager = get_protocol_manager(ssh, 'awg')
        status = {'connection': 'ok', 'docker_installed': manager.check_docker_installed(), 'protocols': {}}
        
        changed = False
        if 'protocols' not in server:
            server['protocols'] = {}

        def merge_saved_protocol_status(proto, result=None, error=None):
            """Merge live status with saved protocol metadata.

            Multi-instance protocols are source-of-truth in data.json because
            they cannot be discovered from BASE_PROTOCOLS alone. A transient
            check failure must not delete awg2__2/awg2__3 from the panel.
            """
            db_proto = server.get('protocols', {}).get(proto, {}) or {}
            merged = dict(result or {})
            merged.setdefault('protocol', proto)
            if error:
                merged['error'] = error
            if not merged.get('port') and db_proto.get('port'):
                merged['port'] = db_proto['port']
            if db_proto.get('awg_params') and not merged.get('awg_params'):
                merged['awg_params'] = db_proto.get('awg_params')
            merged['base_protocol'] = db_proto.get('base_protocol') or protocol_base(proto)
            merged['instance'] = db_proto.get('instance') or protocol_instance(proto)
            merged['display_name'] = db_proto.get('display_name') or protocol_display_name(proto)
            if protocol_base(proto) == 'awg2' and 'header_protection' in merged:
                merged['display_name'] = protocol_display_name(proto, merged['header_protection'])
            merged['container_name'] = db_proto.get('container_name') or protocol_container_name(proto)
            if protocol_base(proto) == 'adguard':
                for key in ('web_port', 'mode', 'internal_ip', 'expose_web'):
                    if db_proto.get(key) not in (None, ''):
                        if key == 'web_port' and merged.get('web_exposed'):
                            continue
                        merged[key] = db_proto[key]
                if 'expose_web' in db_proto and 'web_exposed' not in merged:
                    merged['web_exposed'] = bool(db_proto.get('expose_web'))
            if protocol_base(proto) == 'nginx':
                for key in ('domain', 'email', 'site_url'):
                    if db_proto.get(key) not in (None, ''):
                        merged[key] = db_proto[key]
            if protocol_base(proto) == 'exit':
                for key in ('subnet', 'public_key', 'obfuscation'):
                    if db_proto.get(key) not in (None, ''):
                        merged.setdefault(key, db_proto[key])
            if protocol_base(proto) in AWG_PROTOCOLS and db_proto.get('exit_link'):
                merged['exit_link'] = db_proto['exit_link']
            return merged

        def should_preserve_saved_protocol(proto, result=None, err=None):
            """Return True when check must not remove a saved protocol record."""
            db_proto = server.get('protocols', {}).get(proto)
            if not db_proto:
                return False
            # An instance routed through an exit node keeps its record: the
            # exit still holds its peer and the admin needs Unlink/Repair.
            if db_proto.get('exit_link'):
                return True
            # Additional AWG-family instances are only known by their saved
            # dynamic keys (awg__2/awg2__2/awg_legacy__2). Keep them unless
            # the user explicitly uninstalls them.
            if protocol_base(proto) in MULTI_INSTANCE_PROTOCOLS and protocol_instance(proto) > 1:
                return True
            # Do not delete any saved protocol on command/check errors; only a
            # clean live result with container_exists=False may prune base apps.
            if err or (result and result.get('error')):
                return True
            return False

        def check_proto(proto):
            try:
                p_manager = get_protocol_manager(ssh, proto)
                result = _manager_call(p_manager, 'get_server_status', proto)
                db_proto = server.get('protocols', {}).get(proto, {}) or {}
                if db_proto.get('exit_link') and result.get('container_running'):
                    try:
                        result['exit_link_status'] = AWGManager(ssh).exit_link_status(proto)
                    except Exception as e:
                        result['exit_link_status'] = {'up': False, 'error': str(e)}
                return proto, merge_saved_protocol_status(proto, result), None
            except Exception as e:
                return proto, merge_saved_protocol_status(proto, {}, str(e)), str(e)

        protocols_to_check = list(dict.fromkeys(BASE_PROTOCOLS + list(server.get('protocols', {}).keys())))
        # One batched round trip for all AWG containers (ps snapshot + configs
        # + clientsTables) instead of 3-5 SSH commands per instance - this is
        # what made /check take seconds on high-latency servers.
        try:
            awg_protos = [p for p in protocols_to_check if protocol_base(p) in AWG_PROTOCOLS]
            if awg_protos:
                AWGManager(ssh).prefetch_awg_state(awg_protos)
        except Exception as e:
            logger.warning(f"AWG status prefetch failed, falling back to per-instance checks: {e}")
        # Run checks sequentially. Several managers use the same SSH connection;
        # checking them in parallel through one SSH object can produce false
        # negatives and previously caused dynamic AWG instances to be removed.
        for proto in protocols_to_check:
            proto, result, err = check_proto(proto)
            status['protocols'][proto] = result
            if err:
                continue
            if result.get('container_exists'):
                if proto not in server['protocols']:
                    server['protocols'][proto] = {
                        'installed': True,
                        'port': result.get('port', '55424'),
                        'awg_params': result.get('awg_params', {}),
                        'base_protocol': protocol_base(proto),
                        'instance': protocol_instance(proto),
                        'display_name': protocol_display_name(proto, result.get('header_protection')),
                        'container_name': protocol_container_name(proto),
                    }
                    if protocol_base(proto) == 'adguard':
                        server['protocols'][proto].update({
                            'mode': result.get('mode'),
                            'internal_ip': result.get('internal_ip'),
                            'web_port': result.get('web_port'),
                            'expose_web': result.get('web_exposed'),
                        })
                    if protocol_base(proto) == 'nginx':
                        server['protocols'][proto].update({
                            'domain': result.get('domain'),
                            'email': result.get('email'),
                            'site_url': result.get('site_url'),
                        })
                    if protocol_base(proto) == 'exit':
                        server['protocols'][proto].update({
                            'subnet': result.get('subnet'),
                            'public_key': result.get('public_key'),
                            'obfuscation': result.get('obfuscation'),
                        })
                    changed = True
                record = server['protocols'][proto]
                if protocol_base(proto) == 'awg2' and 'header_protection' in result:
                    header_protection = bool(result['header_protection'])
                    if bool(record.get('header_protection')) != header_protection:
                        record['header_protection'] = header_protection
                        record['display_name'] = protocol_display_name(proto, header_protection)
                        changed = True
            else:
                if proto in server['protocols']:
                    if should_preserve_saved_protocol(proto, result, err):
                        # Keep saved dynamic instances visible as installed but stopped/unchecked.
                        status['protocols'][proto]['container_exists'] = True
                        status['protocols'][proto].setdefault('container_running', False)
                        status['protocols'][proto]['status_preserved'] = True
                        link = (server['protocols'][proto] or {}).get('exit_link')
                        if link and not err and not link.get('stale') and result and not result.get('container_exists'):
                            # Container gone but the exit still has our peer
                            link['stale'] = 'entry_container_missing'
                            changed = True
                    else:
                        del server['protocols'][proto]
                        changed = True
                
        if changed:
            save_data(data)
            
        ssh.disconnect()
        return status
    except Exception as e:
        logger.exception("Error checking server")
        return JSONResponse({'error': str(e), 'connection': 'failed'}, status_code=500)


def get_used_ports(ssh):
    """Return {'udp': {port: proc}, 'tcp': {port: proc}} for listening sockets.

    Used to suggest a free port before protocol installation and to validate
    the chosen port, instead of letting 'docker run' fail with a half-created
    container on 'port is already allocated'.
    """
    out, _, code = ssh.run_sudo_command("ss -H -l -n -p -u; echo ---TCP---; ss -H -l -n -p -t")
    used = {'udp': {}, 'tcp': {}}
    if code != 0 or not out:
        return used
    section = 'udp'
    for line in out.split('\n'):
        line = line.strip()
        if line == '---TCP---':
            section = 'tcp'
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        port = local.rsplit(':', 1)[-1]
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        used[section][port] = m.group(1) if m else '?'
    return used


# Protocols whose install port must be validated against used ports,
# mapped to their transport. dns/adguard are skipped (internal bindings).
INSTALL_PORT_TRANSPORT = {
    'awg': 'udp', 'awg2': 'udp', 'awg3': 'udp', 'awg_legacy': 'udp',
    'wireguard': 'udp', 'exit': 'udp',
    'xray': 'tcp', 'telemt': 'tcp', 'socks5': 'tcp', 'nginx': 'tcp',
}


@app.get('/api/servers/{server_id}/used-ports', tags=["Servers"])
def api_used_ports(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(data['servers'][server_id])
        ssh.connect()
        return get_used_ports(ssh)
    except Exception as e:
        logger.exception("Error getting used ports")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/install', tags=["Protocols"])
@serialize_peer_lifecycle
async def api_install_protocol(request: Request, server_id: int, req: InstallProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not is_valid_protocol(req.protocol):
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)

        server = data['servers'][server_id]
        if 'protocols' not in server:
            server['protocols'] = {}
        base_protocol = protocol_base(req.protocol)
        if req.install_another:
            if base_protocol not in MULTI_INSTANCE_PROTOCOLS:
                return JSONResponse({'error': 'Multiple instances are not supported for this protocol yet'}, status_code=400)
            install_protocol = next_protocol_key(server.get('protocols', {}), base_protocol)
        else:
            install_protocol = req.protocol
        install_base = protocol_base(install_protocol)
        # A reinstalled entry keeps its exit link and is re-linked below
        previous_link = None
        # Where an instance is published is a property of the network, not
        # of this install: reinstalling must not move clients back to the
        # address the panel happens to manage the box through.
        previous_record = (server.get('protocols') or {}).get(install_protocol) or {}
        previous_public = {key: previous_record[key]
                           for key in ('public_host', 'public_port')
                           if previous_record.get(key)}
        # Reinstalling an instance is not the same as adding one: an instance a
        # user deliberately left unlinked must not be linked behind their back.
        reinstall = install_protocol in (server.get('protocols') or {})
        if install_base in AWG_PROTOCOLS:
            previous_link = ((server.get('protocols') or {}).get(install_protocol) or {}).get('exit_link')

        awg_special_junk = awg_special_junk_from(req) if install_base in AWG_PROTOCOLS else None
        if awg_special_junk is not None:
            # Reject a malformed packet before touching the server.
            try:
                normalize_special_junk(awg_special_junk)
            except ValueError as e:
                return JSONResponse({'error': str(e)}, status_code=400)

        ssh = await asyncio.to_thread(get_ssh, server)
        await asyncio.to_thread(ssh.connect)

        # Validate the requested port before touching Docker: a busy port
        # otherwise fails mid-install with a half-created broken container.
        transport = INSTALL_PORT_TRANSPORT.get(install_base)
        if transport and req.port and str(req.port).isdigit():
            used = await asyncio.to_thread(get_used_ports, ssh)
            owner = used.get(transport, {}).get(str(req.port))
            if owner:
                return JSONResponse(
                    {'error': f'Port {req.port}/{transport} is already used by {owner}. '
                              f'Choose another port.'},
                    status_code=400)

        docker_install_log = await asyncio.to_thread(ensure_docker_installed, ssh)
        manager = get_protocol_manager(ssh, install_protocol)

        # Pass parameters to installer
        install_kwargs = None
        if install_base == 'telemt':
            install_args = ()
            install_kwargs = dict(
                protocol_type=install_protocol,
                port=req.port,
                tls_emulation=req.tls_emulation if req.tls_emulation is not None else True,
                tls_domain=req.tls_domain,
                max_connections=req.max_connections if req.max_connections is not None else 0,
                public_host=previous_public.get('public_host'),
                public_port=previous_public.get('public_port'),
            )
        elif install_base == 'xray':
            install_args = ()
            install_kwargs = dict(port=req.port)
        elif install_base == 'wireguard':
            install_args = ()
            install_kwargs = dict(port=req.port)
        elif install_base == 'socks5':
            install_args = ()
            install_kwargs = dict(
                protocol_type=install_protocol,
                port=req.port,
                username=req.socks5_username,
                password=req.socks5_password,
            )
        elif install_base == 'adguard':
            install_args = ()
            install_kwargs = dict(
                protocol_type='adguard',
                mode=req.adguard_mode or 'sidebyside',
                web_port=req.adguard_web_port,
                expose_web=bool(req.adguard_expose_web),
                dns_port=req.port,
                dot_port=req.adguard_dot_port,
                doh_port=req.adguard_doh_port,
                expose_dns=bool(req.adguard_expose_dns),
                expose_dot=bool(req.adguard_expose_dot),
                expose_doh=bool(req.adguard_expose_doh),
            )
        elif install_base == 'nginx':
            install_args = ()
            install_kwargs = dict(
                protocol_type='nginx',
                port=req.port,
                domain=req.nginx_domain,
                email=req.nginx_email,
            )
        elif install_base == 'exit':
            install_args = ()
            install_kwargs = dict(
                protocol_type='exit',
                port=req.port,
                subnet=req.exit_subnet,
                obfuscation=bool(req.exit_obfuscation),
            )
        elif install_base in AWG_PROTOCOLS:
            install_args = (install_protocol,)
            install_kwargs = dict(
                port=req.port,
                mtu=req.awg_mtu,
                dns=join_dns(req.awg_dns1, req.awg_dns2),
                special_junk=awg_special_junk,
                dns6=req.awg_dns6,
            )
        else:
            install_args = (install_protocol,)
            install_kwargs = dict(port=req.port)
        result = await asyncio.to_thread(manager.install_protocol, *install_args, **install_kwargs)

        if not isinstance(result, dict):
            result = {'status': 'success', 'message': str(result)}
        if docker_install_log:
            result.setdefault('log', [])
            result['log'].insert(0, docker_install_log)
        if result.get('status') == 'error' or result.get('error'):
            ssh.disconnect()
            return JSONResponse({'error': result.get('message') or result.get('error') or 'Installation failed'}, status_code=400)

        proto_record = {
            'installed': True,
            'port': req.port,
            'awg_params': result.get('awg_params', {}),
        }
        if result.get('mtu'):
            proto_record['mtu'] = result['mtu']
        if result.get('dns'):
            proto_record['dns'] = result['dns']
        if install_base == 'adguard':
            proto_record['mode'] = result.get('mode')
            proto_record['internal_ip'] = result.get('internal_ip')
            proto_record['web_port'] = result.get('web_port')
            proto_record['expose_web'] = result.get('expose_web')
        if install_base == 'nginx':
            proto_record['domain'] = result.get('domain')
            proto_record['email'] = result.get('email')
            proto_record['site_url'] = result.get('site_url')
        if install_base == 'exit':
            # req.port may be empty: the manager applied the default
            proto_record['port'] = result.get('port') or req.port
            proto_record['subnet'] = result.get('subnet')
            proto_record['public_key'] = result.get('public_key')
            proto_record['obfuscation'] = result.get('obfuscation')
        proto_record['base_protocol'] = install_base
        proto_record['instance'] = protocol_instance(install_protocol)
        proto_record['display_name'] = protocol_display_name(install_protocol)
        proto_record['container_name'] = protocol_container_name(install_protocol)
        if previous_link:
            proto_record['exit_link'] = previous_link
        proto_record.update(previous_public)
        server['protocols'][install_protocol] = proto_record
        result['protocol'] = install_protocol
        result['base_protocol'] = install_base
        result['display_name'] = proto_record['display_name']
        result['container_name'] = proto_record['container_name']
        save_data(data)
        ssh.disconnect()

        # A new AWG instance joins the default exit node, when one is set.
        default_uid = ((data.get('settings', {}).get('exit_nodes') or {}).get('default_exit_uid') or '').strip()
        if should_link_default_exit(default_uid, server.get('uid'), install_base in AWG_PROTOCOLS,
                                    reinstall, previous_link):
            try:
                linked = await exit_link_svc.link(server_id, install_protocol, default_uid)
                result.setdefault('log', []).append(
                    f"Linked to the default exit node {linked['exit_link']['exit_name']}")
            except Exception as e:
                # the instance is installed either way; the link is an extra
                logger.warning(f"default exit link after install failed: {e}")
                result.setdefault('log', []).append(f"! Could not link to the default exit node: {e}")

        # Exit-node links survive reinstalls: bring them back now.
        if install_base == 'exit':
            for item in await exit_link_svc.relink_entries_for_exit(server.get('uid')):
                result.setdefault('log', []).append(
                    f"Re-linked {item['name']}/{item['protocol']}" if item['status'] == 'success'
                    else f"! Failed to re-link {item['name']}/{item['protocol']}: {item['error']}")
        elif previous_link:
            try:
                await exit_link_svc.relink_entry(server_id, install_protocol)
                result.setdefault('log', []).append(f"Re-linked to exit node {previous_link.get('exit_name')}")
            except Exception as e:
                logger.warning(f"re-link after reinstall failed: {e}")
                fresh = load_data()
                rec = (fresh['servers'][server_id].get('protocols') or {}).get(install_protocol) if server_id < len(fresh['servers']) else None
                if rec and rec.get('exit_link'):
                    rec['exit_link']['stale'] = 'relink_failed'
                    save_data(fresh)
                result.setdefault('log', []).append(
                    f"! Could not re-link to exit node {previous_link.get('exit_name')}: {e}")
        return result
    except Exception as e:
        logger.exception("Error installing protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
def api_socks5_get_credentials(request: Request, server_id: int, protocol: str = 'socks5'):
    """Return the current SOCKS5 port/username/password for the panel UI."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        protocol = protocol if is_valid_protocol(protocol) and protocol_base(protocol) == 'socks5' else 'socks5'
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        creds = manager.get_credentials()
        ssh.disconnect()
        return {'status': 'success', **creds}
    except Exception as e:
        logger.exception("Error reading SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
def api_socks5_update_credentials(request: Request, server_id: int, req: Socks5SettingsRequest):
    """Apply new SOCKS5 connection settings — regenerates the 3proxy config and
    reconciles the container (recreating it if the listening port changed)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        protocol = req.protocol if is_valid_protocol(req.protocol) and protocol_base(req.protocol) == 'socks5' else 'socks5'
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        result = manager.update_credentials(
            port=req.port, username=req.username, password=req.password
        )
        ssh.disconnect()
        # Persist the new port in the saved server record so the dashboard
        # shows the right value on next check without an SSH round-trip.
        if result.get('status') == 'success' and result.get('port'):
            srv_proto = server.setdefault('protocols', {}).setdefault(protocol, {})
            srv_proto['port'] = str(result['port'])
            srv_proto['installed'] = True
            srv_proto['base_protocol'] = protocol_base(protocol)
            srv_proto['instance'] = protocol_instance(protocol)
            srv_proto['display_name'] = protocol_display_name(protocol)
            srv_proto['container_name'] = protocol_container_name(protocol)
            save_data(data)
        return result
    except Exception as e:
        logger.exception("Error updating SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


def _exit_manager_for(ssh):
    from managers.exit_manager import ExitManager
    return ExitManager(ssh)


@app.post('/api/servers/{server_id}/exit/peers', tags=["Protocols"])
def api_exit_peers(request: Request, server_id: int, req: ProtocolRequest):
    """Exit node endpoint data (public key, port, transit subnet, obfuscation)
    and its peers - the entry nodes linked to it - with live handshake and
    transfer counters."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(data['servers'][server_id])
        ssh.connect()
        try:
            manager = _exit_manager_for(ssh)
            info = manager.get_info()
            peers = manager.list_peers()
        finally:
            ssh.disconnect()
        return {'status': 'success', 'info': info, 'peers': peers}
    except Exception as e:
        logger.exception("Error listing exit peers")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit/peers/add', tags=["Protocols"])
def api_exit_peer_add(request: Request, server_id: int, req: ExitPeerAddRequest):
    """Register a peer on the exit node by hand (a node not managed by this
    panel). Upserts by `peer_id`; returns the transit address, a fresh PSK and
    the exit's endpoint data for the peer's own WireGuard config."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not req.peer_id.strip() or not req.public_key.strip():
        return JSONResponse({'error': 'peer_id and public_key are required'}, status_code=400)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(data['servers'][server_id])
        ssh.connect()
        try:
            manager = _exit_manager_for(ssh)
            peer = manager.add_peer(req.peer_id.strip(), req.name.strip() or req.peer_id.strip(),
                                    req.public_key.strip())
        finally:
            ssh.disconnect()
        return {'status': 'success', 'peer': peer}
    except ValueError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:
        logger.exception("Error adding exit peer")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit/peers/remove', tags=["Protocols"])
def api_exit_peer_remove(request: Request, server_id: int, req: ExitPeerRemoveRequest):
    """Drop a peer from the exit node by public key or by peer id."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not req.public_key.strip() and not req.peer_id.strip():
        return JSONResponse({'error': 'public_key or peer_id is required'}, status_code=400)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(data['servers'][server_id])
        ssh.connect()
        try:
            manager = _exit_manager_for(ssh)
            removed = manager.remove_peer(public_key=req.public_key.strip() or None,
                                          peer_id=req.peer_id.strip() or None)
        finally:
            ssh.disconnect()
        return {'status': 'success', 'removed': removed}
    except Exception as e:
        logger.exception("Error removing exit peer")
        return JSONResponse({'error': str(e)}, status_code=500)


def _exit_link_error(e: ExitLinkError):
    return JSONResponse({'error': e.code, 'message': str(e)}, status_code=e.status_code)


def _smartroute_error(e: SmartRouteError):
    return JSONResponse({'error': e.code, 'message': str(e)}, status_code=e.status_code)


@app.get('/api/exit-nodes', tags=["Servers"])
def api_exit_nodes(request: Request):
    """Servers with an installed exit node, from data.json (no SSH)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return {'status': 'success', 'exit_nodes': exit_link_svc.list_exit_nodes(load_data())}


@app.post('/api/servers/{server_id}/exit-link', tags=["Protocols"])
async def api_exit_link(request: Request, server_id: int, req: ExitLinkRequest):
    """Route all clients of an AWG instance through an exit node (by its
    server uid). Rolled back unless the exit answers within 15 s; `force`
    keeps the link anyway."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await exit_link_svc.link(server_id, req.protocol, req.exit_uid.strip(), force=bool(req.force))
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error linking to exit node")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit-link/remove', tags=["Protocols"])
async def api_exit_unlink(request: Request, server_id: int, req: ProtocolRequest):
    """Restore direct egress for an AWG instance and drop its peer on the exit."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await exit_link_svc.unlink(server_id, req.protocol)
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error unlinking from exit node")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit-link/relink', tags=["Protocols"])
async def api_exit_relink(request: Request, server_id: int, req: ProtocolRequest):
    """Re-establish an existing link (after a reinstall or a stale state)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await exit_link_svc.relink_entry(server_id, req.protocol)
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error re-linking to exit node")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit-link/dns', tags=["Protocols"])
async def api_exit_link_dns(request: Request, server_id: int, req: ExitDnsRequest):
    """Resolve client DNS at the exit node instead of this one (requires
    AmneziaDNS on the exit)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await exit_link_svc.set_dns_via_exit(server_id, req.protocol, req.enabled)
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error switching the DNS route of an exit link")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/exit-link/status', tags=["Protocols"])
async def api_exit_link_status(request: Request, server_id: int, req: ProtocolRequest):
    """Saved link plus live handshake/transfer, client MTU and IPv6 flags."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        payload = await exit_link_svc.status(server_id, req.protocol)
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error reading exit link status")
        return JSONResponse({'error': str(e)}, status_code=500)
    # Smart Route counters ride along best-effort: a probe failure must not
    # hide the whole link status.
    try:
        payload['smartroute'] = await smartroute_svc.counters(server_id, req.protocol)
    except Exception:
        logger.debug("smartroute counters unavailable for server %s %s",
                     server_id, req.protocol)
        payload['smartroute'] = None
    return payload


@app.post('/api/servers/{server_id}/exit-link/check-egress', tags=["Protocols"])
async def api_exit_link_check_egress(request: Request, server_id: int, req: ProtocolRequest):
    """Public IP the clients of this instance leave from, compared with the
    exit node address (two HTTP probes from inside the container)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await exit_link_svc.check_egress(server_id, req.protocol)
    except ExitLinkError as e:
        return _exit_link_error(e)
    except Exception as e:
        logger.exception("Error checking exit egress")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/install', tags=["Protocols"])
async def api_smartroute_install(request: Request, server_id: int):
    """Install the host-side Smart Route updater (lists + systemd timer)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.install(server_id)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error installing Smart Route")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/uninstall', tags=["Protocols"])
async def api_smartroute_uninstall(request: Request, server_id: int):
    """Remove Smart Route: every split instance is rolled back to full
    tunnel through the exit node first."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.uninstall(server_id)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error uninstalling Smart Route")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/update', tags=["Protocols"])
async def api_smartroute_update(request: Request, server_id: int):
    """Re-download the RU prefix lists and re-apply them now."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.run_update(server_id)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error updating Smart Route lists")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/own-subnets', tags=["Protocols"])
async def api_smartroute_own_subnets(request: Request, server_id: int,
                                     req: SmartRouteOwnSubnetsRequest):
    """Own subnets routed directly (merged into every split instance)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.set_own_subnets(server_id, req.cidrs)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error saving Smart Route own subnets")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/split', tags=["Protocols"])
async def api_smartroute_split(request: Request, server_id: int,
                               req: SmartRouteSplitRequest):
    """Toggle RU-direct split routing for one exit-linked instance."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.set_split(server_id, req.protocol, req.enabled)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error toggling Smart Route split")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/dns', tags=["Protocols"])
async def api_smartroute_dns(request: Request, server_id: int,
                             req: SmartRouteDnsRequest):
    """Resolve DNS at the exit node for all split instances of the server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.set_dns_via_exit(server_id, req.enabled)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error switching Smart Route DNS")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/enable', tags=["Protocols"])
async def api_smartroute_enable(request: Request, server_id: int,
                                req: SmartRouteEnableRequest):
    """Global pause/resume of Smart Route on the server (card toggle).

    Pausing rolls the split routing out of every split instance (traffic
    returns to the exit node); resuming re-applies it. Lists, timer and
    per-instance preferences are preserved."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.set_enabled(server_id, req.enabled)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error toggling Smart Route globally")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/smartroute/dns-servers', tags=["Protocols"])
async def api_smartroute_dns_servers(request: Request, server_id: int,
                                     req: SmartRouteDnsServersRequest):
    """Resolver pair for split instances: the direct resolver is expected to
    be a RU IP (routed directly), the exit resolver a foreign one (routed
    through the exit node). Stored server-wide and pushed into every split
    instance's client-config DNS line."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.set_dns_servers(server_id, req.direct, req.exit)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error saving Smart Route DNS pair")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/smartroute/status', tags=["Protocols"])
async def api_smartroute_status(request: Request, server_id: int):
    """App state: host lists, timer, own subnets, DNS choice, split instances."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await smartroute_svc.status(server_id)
    except SmartRouteError as e:
        return _smartroute_error(e)
    except Exception as e:
        logger.exception("Error reading Smart Route status")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/awg/settings', tags=["Protocols"])
def api_awg_settings_get(request: Request, server_id: int, req: ProtocolRequest):
    """Return MTU, DNS and the special junk packets I1-I5 of an AWG server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if protocol_base(req.protocol) not in AWG_PROTOCOLS:
        return JSONResponse({'error': 'Not an AmneziaWG protocol'}, status_code=400)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        ssh = get_ssh(data['servers'][server_id])
        ssh.connect()
        try:
            settings = AWGManager(ssh).get_awg_settings(req.protocol)
        finally:
            ssh.disconnect()
        settings['dns1'], settings['dns2'] = split_dns(settings.get('dns'))
        return settings
    except Exception as e:
        logger.exception("Error getting AWG settings")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/awg/settings/save', tags=["Protocols"])
def api_awg_settings_save(request: Request, server_id: int, req: AwgSettingsRequest):
    """Update MTU, DNS and I1-I5 and apply them to the running interface."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if protocol_base(req.protocol) not in AWG_PROTOCOLS:
        return JSONResponse({'error': 'Not an AmneziaWG protocol'}, status_code=400)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        special_junk = {key: getattr(req, key) for key in ('i1', 'i2', 'i3', 'i4', 'i5')}
        if all(value is None for value in special_junk.values()):
            special_junk = None
        else:
            # Reject a malformed packet before opening an SSH connection.
            normalize_special_junk(special_junk)
        ssh = get_ssh(server)
        ssh.connect()
        try:
            # An empty string means "clear it", None means "leave it alone";
            # join_dns() collapses two blank fields to None, so restore the
            # distinction here or the DNS could never be reset from the UI.
            dns = None
            if req.dns1 is not None or req.dns2 is not None:
                dns = join_dns(req.dns1, req.dns2) or ''
            settings = AWGManager(ssh).update_awg_settings(
                req.protocol,
                mtu=req.mtu,
                dns=dns,
                special_junk=special_junk,
                dns6=req.dns6,
            )
        finally:
            ssh.disconnect()
        proto_record = server.setdefault('protocols', {}).get(req.protocol)
        if proto_record is not None:
            proto_record['mtu'] = settings.get('mtu')
            proto_record['dns'] = settings.get('dns')
            proto_record['dns6'] = settings.get('dns6')
            save_data(data)
        settings['dns1'], settings['dns2'] = split_dns(settings.get('dns'))
        settings['status'] = 'success'
        return settings
    except ValueError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:
        logger.exception("Error saving AWG settings")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/uninstall', tags=["Protocols"])
@serialize_peer_lifecycle
async def api_uninstall_protocol(request: Request, server_id: int, req: ProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        guard = _traffic_removal_guard(data, server_id=server_id, protocol=req.protocol)
        if guard is not None:
            return guard
        server = data['servers'][server_id]
        base = protocol_base(req.protocol)
        if base in AWG_PROTOCOLS and ((server.get('protocols') or {}).get(req.protocol) or {}).get('exit_link'):
            # Drop our peer on the exit while the container still exists
            try:
                await exit_link_svc.unlink(server_id, req.protocol)
            except Exception as e:
                logger.warning(f"unlink before uninstall failed: {e}")
            data = load_data()
            server = data['servers'][server_id]
        ssh = await asyncio.to_thread(get_ssh, server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)
        if base in ('xray', 'wireguard'):
            await asyncio.to_thread(manager.remove_container)
        else:
            await asyncio.to_thread(manager.remove_container, req.protocol)
        if req.protocol in server.get('protocols', {}):
            del server['protocols'][req.protocol]
            save_data(data)
        # The instance is gone: its peers are gone with it, so connections
        # pointing at this (server, protocol) would dangle forever — the
        # modal would list a phantom that errors with 'Client not found'
        # on every action. Purge them like server/user deletion does.
        data['user_connections'] = [
            c for c in data.get('user_connections', [])
            if not (c.get('server_id') == server_id
                    and c.get('protocol') == req.protocol)
        ]
        save_data(data)
        ssh.disconnect()
        if base == 'exit':
            detached = await exit_link_svc.detach_entries_for_exit(server.get('uid'), 'exit_uninstalled')
            return {'status': 'success', 'detached': detached}
        if base == 'dns':
            # queries sent here through a link would go nowhere now
            restored = await exit_link_svc.disable_dns_via_exit_for_exit(server.get('uid'))
            if restored:
                return {'status': 'success', 'dns_restored': restored}
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error uninstalling protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


CONTAINER_NAMES = {
    'awg': 'amnezia-awg',
    'awg2': 'amnezia-awg2',
    'awg3': 'amnezia-awg3',
    'awg_legacy': 'amnezia-awg-legacy',
    'xray': 'amnezia-xray',
    'telemt': 'telemt',
    'dns': 'amnezia-dns',
    'wireguard': 'amnezia-wireguard',
    'socks5': 'amnezia-socks5proxy',
    'adguard': 'amnezia-adguard',
    'nginx': 'amnezia-nginx',
}



@app.post('/api/servers/{server_id}/backups', tags=["Protocols"])
def api_protocol_backups_list(request: Request, server_id: int, req: ProtocolRequest):
    """List backups created on the remote server for one protocol."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    ssh = None
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        result = BackupManager(ssh).list_backups(req.protocol)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to list backups')}, status_code=500)
        return result
    except Exception as e:
        logger.exception("Error listing protocol backups")
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/create', tags=["Protocols"])
def api_protocol_backup_create(request: Request, server_id: int, req: ProtocolRequest):
    """Create a protocol backup archive on the remote server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    ssh = None
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        result = BackupManager(ssh).create_backup(req.protocol, container)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to create backup')}, status_code=500)
        return result
    except Exception as e:
        logger.exception("Error creating protocol backup")
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/download', tags=["Protocols"])
def api_protocol_backup_download(request: Request, server_id: int, req: BackupDownloadRequest):
    """Download one remote protocol backup archive through the panel."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    manager = BackupManager(None)
    safe_proto = manager.safe_protocol(req.protocol)
    filename = manager.safe_filename(req.filename)
    if not filename:
        return JSONResponse({'error': 'Invalid backup filename'}, status_code=400)
    ssh = None
    tmp_path = None
    remote_temp_dir = None
    remote_path = f'{manager.BACKUP_ROOT}/{safe_proto}/{filename}'
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        # mktemp creates a mode-0700 directory owned by the SSH/SFTP user.
        # The root-owned readable copy stays inaccessible to other local users.
        remote_temp_dir = ssh._make_private_temp_dir()
        tmp_remote = remote_temp_dir + '/' + filename
        quoted_remote = shlex.quote(remote_path)
        quoted_tmp = shlex.quote(tmp_remote)
        # `sudo <a> && <b>` elevates only `<a>`; the whole chain needs one shell
        _, err, code = ssh.run_sudo_command(
            f"sh -c {shlex.quote(f'test -f {quoted_remote} && cp {quoted_remote} {quoted_tmp} && chmod 0644 {quoted_tmp}')}"
        )
        if code != 0:
            return JSONResponse({'error': err or 'Backup not found'}, status_code=404)
        fd, tmp_path = tempfile.mkstemp(prefix='amnezia-backup-', suffix='.tar.gz')
        os.close(fd)
        sftp = ssh.client.open_sftp()
        try:
            sftp.get(tmp_remote, tmp_path)
        finally:
            sftp.close()
        return FileResponse(
            tmp_path,
            media_type='application/gzip',
            filename=filename,
            background=BackgroundTask(lambda p=tmp_path: os.path.exists(p) and os.remove(p)),
        )
    except Exception as e:
        logger.exception("Error downloading protocol backup")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            try:
                if remote_temp_dir:
                    _, cleanup_error, cleanup_code = ssh.run_sudo_command(
                        'rm -rf -- ' + shlex.quote(remote_temp_dir))
                    if cleanup_code != 0:
                        logger.warning('Remote backup staging cleanup failed: %s', cleanup_error)
            except Exception:
                logger.warning('Remote backup staging cleanup failed', exc_info=True)
            finally:
                ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/upload', tags=["Protocols"])
async def api_protocol_backup_upload(
    request: Request,
    server_id: int,
    protocol: str = Form(...),
    file: UploadFile = File(...),
):
    """Upload a protocol backup archive onto the remote server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    ssh = None
    tmp_path = None
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        content = await file.read(BackupManager.MAX_UPLOAD_BYTES + 1)
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)
        if len(content) > BackupManager.MAX_UPLOAD_BYTES:
            return JSONResponse({'error': 'Backup file is too large'}, status_code=413)
        fd, tmp_path = tempfile.mkstemp(prefix='amnezia-backup-upload-', suffix='.tar.gz')
        os.write(fd, content)
        os.close(fd)
        fd = None
        server = data['servers'][server_id]
        ssh = await asyncio.to_thread(get_ssh, server)
        await asyncio.to_thread(ssh.connect)
        result = await asyncio.to_thread(BackupManager(ssh).upload_backup, protocol, file.filename, tmp_path)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to upload backup')}, status_code=400)
        return result
    except Exception as e:
        logger.exception("Error uploading protocol backup")
        return JSONResponse({'error': 'Internal server error'}, status_code=500)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/restore', tags=["Protocols"])
@serialize_peer_lifecycle
async def api_protocol_backup_restore(request: Request, server_id: int, req: BackupDownloadRequest):
    """Restore a protocol from a backup archive on the remote server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    filename = BackupManager.safe_filename(req.filename)
    if not filename:
        return JSONResponse({'error': 'Invalid backup filename'}, status_code=400)
    ssh = None
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        guard = _traffic_removal_guard(data, server_id=server_id, protocol=req.protocol, include_archived=True)
        if guard is not None:
            return guard
        server = data['servers'][server_id]
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        ssh = await asyncio.to_thread(get_ssh, server)
        await asyncio.to_thread(ssh.connect)
        result = await asyncio.to_thread(BackupManager(ssh).restore_backup, req.protocol, container, filename)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to restore backup')}, status_code=500)
        ssh.disconnect()
        ssh = None
        # The archive owns the files an exit link lives in, so the restored
        # container and data.json can now disagree. Never fails the restore.
        try:
            result.update(await exit_link_svc.reconcile_after_restore(server_id, req.protocol))
        except Exception as e:
            logger.warning(f"exit-link reconcile after restore failed: {e}")
        return result
    except Exception as e:
        logger.exception("Error restoring protocol backup")
        return JSONResponse({'error': 'Internal server error'}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/delete', tags=["Protocols"])
def api_protocol_backup_delete(request: Request, server_id: int, req: BackupDownloadRequest):
    """Delete one protocol backup archive on the remote server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    filename = BackupManager.safe_filename(req.filename)
    if not filename:
        return JSONResponse({'error': 'Invalid backup filename'}, status_code=400)
    ssh = None
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        result = BackupManager(ssh).delete_backup(req.protocol, filename)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to delete backup')}, status_code=404)
        return result
    except Exception as e:
        logger.exception("Error deleting protocol backup")
        return JSONResponse({'error': 'Internal server error'}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/container/toggle', tags=["Protocols"])
def api_container_toggle(request: Request, server_id: int, req: ContainerToggleRequest):
    """Start or stop a protocol Docker container. Stopping an exit node that
    entries route through is refused (409 `exit_in_use`) unless `force` is
    set - their clients would silently land on the kill-switch."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        # Check current state
        out, _, _ = ssh.run_sudo_command(
            f"docker inspect -f '{{{{.State.Running}}}}' {container} 2>/dev/null"
        )
        is_running = out.strip().lower() == 'true'
        if is_running and protocol_base(req.protocol) == 'exit' and not req.force:
            entries = exit_link_svc.linked_entries(data, server.get('uid'))
            if entries:
                ssh.disconnect()
                return JSONResponse({'error': 'exit_in_use', 'entries': entries}, status_code=409)
        if is_running:
            ssh.run_sudo_command(f"docker stop {container}")
            action = 'stopped'
        else:
            ssh.run_sudo_command(f"docker start {container}")
            action = 'started'
        if hasattr(ssh, 'docker_ps_invalidate'):
            ssh.docker_ps_invalidate()
        ssh.disconnect()
        return {'status': 'success', 'action': action, 'container': container}
    except Exception as e:
        logger.exception("Error toggling container")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config', tags=["Protocols"])
def api_server_config(request: Request, server_id: int, req: ProtocolRequest):
    """Get the raw server-side WireGuard/Xray configuration."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        if protocol_base(req.protocol) == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh, req.protocol)
            data_json = mgr._get_server_json()
            import json as _json
            config = _json.dumps(data_json, indent=2, ensure_ascii=False) if data_json else ''
        elif protocol_base(req.protocol) == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh, req.protocol)
            config = mgr._get_server_config()
        elif protocol_base(req.protocol) == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            config = mgr._get_server_config()
        elif protocol_base(req.protocol) == 'nginx':
            from managers.nginx_manager import NginxManager
            mgr = NginxManager(ssh, req.protocol)
            config = mgr._get_server_config(req.protocol)
        else:
            mgr = AWGManager(ssh)
            config = mgr._get_server_config(req.protocol)
        ssh.disconnect()
        return {'config': config}
    except Exception as e:
        logger.exception("Error getting server config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/ssh_cooldown', tags=["Servers"])
async def api_ssh_cooldown(request: Request, server_id: int):
    """Set the per-server SSH circuit-breaker base cooldown (seconds)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        body = await request.json()
        seconds = float(body.get('seconds', 30))
    except Exception:
        return JSONResponse({'error': 'Invalid value'}, status_code=400)
    if not (5 <= seconds <= 300):
        return JSONResponse({'error': 'Value must be between 5 and 300 seconds'}, status_code=400)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    data['servers'][server_id]['ssh_cooldown_base'] = seconds
    save_data(data)
    return {'ok': True, 'ssh_cooldown_base': seconds}


# Allowed live peer-list refresh intervals (seconds); 0 disables polling.
PEER_POLL_INTERVALS = (0, 5, 10, 15, 20, 45, 120, 300, 600)


@app.post('/api/servers/{server_id}/peer_poll_interval', tags=["Servers"])
async def api_peer_poll_interval(request: Request, server_id: int):
    """Set the per-server live peer-list refresh interval (0 = off).

    Polling is opt-in: every poll is a full connections read over SSH, which
    is cheap on fast servers but painful on slow/flaky ones."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        body = await request.json()
        seconds = int(body.get('seconds', 0))
    except Exception:
        return JSONResponse({'error': 'Invalid value'}, status_code=400)
    if seconds not in PEER_POLL_INTERVALS:
        return JSONResponse(
            {'error': 'Value must be one of ' + ','.join(map(str, PEER_POLL_INTERVALS))},
            status_code=400)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    data['servers'][server_id]['peer_poll_interval'] = seconds
    save_data(data)
    return {'ok': True, 'peer_poll_interval': seconds}


@app.post('/api/servers/{server_id}/host_tuning', tags=["Protocols"])
def api_host_tuning(request: Request, server_id: int):
    """Server-level network tuning summary (host sysctls + AWG containers)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        mgr = AWGManager(ssh)
        info = mgr.get_host_tuning()
        ssh.disconnect()
        info['panel'] = {'ssh_cooldown_base': float(server.get('ssh_cooldown_base') or 30)}
        return info
    except Exception as e:
        logger.exception("Error getting host tuning info")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/wgeasy/preview', tags=["Protocols"])
def api_wgeasy_preview(request: Request, server_id: int, req: WgEasyPreviewRequest):
    """Fetch the client list from a wg-easy / amnezia-wg-easy panel running on
    this server (via its local web API over SSH). No secrets are returned."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    from managers.wgeasy_import import WgEasyError
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        try:
            from managers.wgeasy_import import WgEasyImporter, normalize_clients
            importer = WgEasyImporter(ssh, web_port=req.web_port)
            backup = importer.fetch_backup(req.password, req.username or 'admin')
            clients = normalize_clients(backup)
            _, listen_port, _, obfuscation = importer.detect_source()
        finally:
            ssh.disconnect()
        return {
            'status': 'success',
            'release': backup.get('_release'),
            'server_address': (backup.get('server') or {}).get('address', ''),
            'listen_port': int(listen_port),
            'obfuscation': bool(obfuscation),
            'recommended_target': 'awg2' if obfuscation else 'wireguard',
            'clients': [{
                'id': c['id'],
                'name': c['name'],
                'address': c['address'],
                'enabled': c['enabled'],
            } for c in clients],
            'has_server_private_key': bool((backup.get('server') or {}).get('privateKey')),
        }
    except WgEasyError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:
        logger.exception("Error previewing wg-easy import")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/protocol/rename', tags=["Protocols"])
def api_rename_protocol(request: Request, server_id: int, req: RenameProtocolRequest):
    """Set or clear a custom display name for an installed protocol instance."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto = req.protocol.strip()
        if proto not in server.get('protocols', {}):
            return JSONResponse({'error': 'Protocol not found'}, status_code=404)
        # The modal caps input at 64 chars; the API has to cap it too, or a
        # direct call parks an unbounded string in data.json forever.
        name = req.name.strip()[:CUSTOM_PROTOCOL_NAME_MAX]
        if name:
            server['protocols'][proto]['custom_name'] = name
        else:
            server['protocols'][proto].pop('custom_name', None)
        save_data(data)
        return {'status': 'success', 'protocol': proto, 'name': name}
    except Exception as e:
        logger.exception("Error renaming protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/protocol/public-endpoint', tags=["Protocols"])
async def api_set_protocol_public_endpoint(request: Request, server_id: int, req: PublicEndpointRequest):
    """Set or clear the address clients dial for one protocol instance.

    Both fields are optional and empty means "as before": the server's own
    address, the instance's listen port. Useful when an instance answers on a
    second IP of the same box, behind a port forward, or under a domain name.
    A custom public port on this same box is published automatically: REDIRECT
    rules in iptables/ip6tables send it to the instance's listen port.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto = req.protocol.strip()
        if proto not in server.get('protocols', {}):
            return JSONResponse({'error': 'Protocol not found'}, status_code=404)
        try:
            host = normalize_public_host(req.public_host)
            port = normalize_public_port(req.public_port)
        except ValueError as e:
            return JSONResponse({'error': str(e)}, status_code=400)

        record = server['protocols'][proto]
        old_public_port = str(record.get('public_port') or '').strip()
        listen_port = str(record.get('port') or '').strip()
        for key, value in (('public_host', host), ('public_port', port)):
            if value:
                record[key] = value
            else:
                record.pop(key, None)
        save_data(data)

        # The override reaches the server in two ways: telemt composes its own
        # tg:// links from config.toml, and a custom public port on this same
        # box needs an iptables REDIRECT to the listen port. The record is
        # saved either way: a box that is down right now must not lose the
        # setting, and the next save re-applies it.
        warning = ''
        ssh = None
        try:
            base = protocol_base(proto)
            if base == 'telemt':
                pub_host, pub_port = protocol_public_endpoint(server, proto)
                ssh = await asyncio.to_thread(get_ssh, server)
                await asyncio.to_thread(ssh.connect)
                manager = get_protocol_manager(ssh, proto)
                await asyncio.to_thread(
                    manager.set_public_endpoint, pub_host, pub_port or record.get('port', '443'))
            fwd_host, _ = protocol_public_endpoint(server, proto)
            fwd, fwd_warning = public_port_forward_commands(
                proto, port, listen_port, old_public_port, fwd_host)
            if fwd_warning and not warning:
                warning = fwd_warning
            if fwd is not None:
                if ssh is None:
                    ssh = await asyncio.to_thread(get_ssh, server)
                    await asyncio.to_thread(ssh.connect)
                for cmd in fwd:
                    out, err, code = await asyncio.to_thread(ssh.run_sudo_command, cmd)
                    if code != 0 and not warning:
                        logger.warning(f"Public port forward command failed on {proto}: {cmd}: {err}")
                        warning = f"forward command failed: {cmd}: {err}"
                # Verify the rule exists for each address family when adding,
                # scoped exactly like the rule that was installed.
                if not warning and port and str(port) != str(listen_port):
                    l4 = next((k for k, v in PUBLIC_FORWARD_L4.items() if base in v), None)
                    if l4:
                        fam, _ = _forward_family_dests(fwd_host)
                        for ipt, fkey in (('iptables', 4), ('ip6tables', 6)):
                            addrs = fam[fkey]
                            if addrs == []:
                                continue
                            for addr in (addrs if addrs is not None else ['']):
                                dest = f' -d {addr}' if addr else ''
                                verify = (f'{ipt} -t nat -C PREROUTING -p {l4}{dest} --dport {port} '
                                          f'-j REDIRECT --to-ports {listen_port}')
                                vout, verr, vcode = await asyncio.to_thread(ssh.run_sudo_command, verify)
                                if vcode != 0 and not warning:
                                    logger.warning(f"Public port forward verification failed on {proto}: {ipt}: {verr}")
                                    warning = f"forward verification failed: {ipt} REDIRECT to :{listen_port} not present"
        except Exception as e:
            logger.warning(f"Could not apply the public endpoint to {proto}: {e}")
            warning = str(e)
        finally:
            if ssh is not None:
                ssh.disconnect()

        return {'status': 'success', 'protocol': proto,
                'public_host': host, 'public_port': port, 'warning': warning}
    except Exception as e:
        logger.exception("Error setting protocol public endpoint")
        return JSONResponse({'error': str(e)}, status_code=500)


# Public ports are published on the box itself: UDP for the WireGuard family,
# TCP for the rest. DNS resolvers and the exit node have nothing to publish.
PUBLIC_FORWARD_L4 = {
    'udp': ('awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard'),
    'tcp': ('xray', 'telemt', 'socks5', 'nginx'),
}

# Seconds before the startup re-apply touches SSH, so the panel is serving
# first. Patched to 0 in tests.
RESTORE_FORWARD_DELAY = 10

# Seconds between periodic re-applies of the public-port forwards. A VPS can
# reboot on its own while the panel keeps running, and hand-made iptables
# rules do not come back - the panel owns putting them back, again and again.
# Idempotency makes every round safe: -C-guarded additions never duplicate.
RESTORE_FORWARD_INTERVAL = 6 * 3600


async def restore_public_port_forwards():
    """Re-apply public-port REDIRECT rules on every server at panel startup.

    Hosts have no uniform persistence for hand-made iptables rules (netfilter
    -persistent exists on some boxes only, docker restores only its own), so
    after a server or panel restart the panel's own forwards were gone. The
    panel owns these rules -- it puts them back. Idempotent: additions are
    guarded by -C, so a double run never duplicates anything.
    """
    await asyncio.sleep(RESTORE_FORWARD_DELAY)  # let the panel finish booting
    data = load_data()
    for server in data.get('servers', []):
        commands = []
        for proto, record in (server.get('protocols') or {}).items():
            if not isinstance(record, dict):
                continue
            public_port = str(record.get('public_port') or '').strip()
            listen_port = str(record.get('port') or '').strip()
            if not public_port or not listen_port:
                continue
            pub_host, _ = protocol_public_endpoint(server, proto)
            cmds, fwd_warning = public_port_forward_commands(
                proto, public_port, listen_port, public_ip=pub_host)
            if fwd_warning:
                logger.warning(f"Public port forward on "
                               f"{server.get('name') or server.get('host')} {proto}: {fwd_warning}")
            if cmds:
                commands.extend(cmds)
        if not commands:
            continue
        ssh = None
        try:
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            failed = False
            for cmd in commands:
                out, err, code = await asyncio.to_thread(ssh.run_sudo_command, cmd)
                if code != 0:
                    logger.error(f"Failed to re-apply public port forward on "
                                 f"{server.get('name') or server.get('host')}: {cmd}: {err}")
                    failed = True
            if not failed:
                logger.info(f"Public port forwards re-applied on {server.get('name') or server.get('host')}")
        except Exception as e:
            logger.warning(f"Could not re-apply public port forwards on "
                           f"{server.get('name') or server.get('host')}: {e}")
        finally:
            if ssh is not None:
                ssh.disconnect()


async def restore_public_port_forwards_loop():
    """Re-apply the forwards periodically, not only at panel startup: a VPS
    rebooted independently leaves its REDIRECT rules gone until someone
    restarts the panel. Never raises - the next round retries."""
    while True:
        await asyncio.sleep(RESTORE_FORWARD_INTERVAL)
        try:
            await restore_public_port_forwards()
        except Exception as e:
            logger.warning(f"Periodic public port forward re-apply failed: {e}")


def _forward_family_dests(public_ip):
    """Per-address-family -d scoping for the REDIRECT rules.

    Returns ({4: addrs|None, 6: addrs|None}, warning): None means the family
    stays unrestricted, [] means the family is skipped entirely (a resolved
    host with no addresses of that family publishes nothing there), a list
    scopes every rule of that family to those addresses. An IP literal
    restricts its own family only; a domain resolves on the panel machine.
    An unresolvable domain falls back to unrestricted rules plus a warning
    the API surfaces.
    """
    if not public_ip:
        return {4: None, 6: None}, ''
    host = str(public_ip).strip()
    try:
        addr = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        addr = None
    if addr is not None:
        fam = {4: [], 6: []}
        fam[addr.version] = [str(addr)]
        return fam, ''
    v4, v6 = [], []
    try:
        for info in socket.getaddrinfo(host, None):
            if info[0] == socket.AF_INET:
                v4.append(info[4][0])
            elif info[0] == socket.AF_INET6:
                v6.append(info[4][0])
    except OSError:
        pass
    v4, v6 = sorted(set(v4)), sorted(set(v6))
    if not v4 and not v6:
        return {4: None, 6: None}, (f'could not restrict the forward rule to the public IP: '
                                    f'{host} does not resolve')
    return {4: v4, 6: v6}, ''


def public_port_forward_commands(protocol, public_port, listen_port, old_public_port='',
                                 public_ip=''):
    """iptables/ip6tables commands publishing a custom public port.

    Returns (commands, warning); commands is None when nothing is needed.
    A public port equal to the listen port (or empty) means "no rule"; any
    previous rule for the same instance is removed. Idempotent: additions are
    guarded by -C, removals loop -D until the rule is gone. Rules are scoped
    to the public address (-d public_ip) so they redirect only the traffic
    actually meant for this instance, not every packet hitting the port.
    """
    base = protocol_base(protocol)
    l4 = next((k for k, v in PUBLIC_FORWARD_L4.items() if base in v), None)
    if l4 is None:
        return None, ''
    fam, warning = _forward_family_dests(public_ip)
    commands = []

    def drop(port):
        for ipt, fkey in (('iptables', 4), ('ip6tables', 6)):
            addrs = fam[fkey]
            if addrs == []:
                continue  # nothing was ever published in this family
            for addr in (addrs if addrs is not None else ['']):
                dest = f' -d {addr}' if addr else ''
                rule = (f'-t nat -D PREROUTING -p {l4}{dest} --dport {port} '
                        f'-j REDIRECT --to-ports {listen_port}')
                commands.append(f'for i in 1 2 3; do {ipt} {rule} 2>/dev/null || break; done')

    for stale in {p for p in (old_public_port,) if p and p != public_port}:
        drop(stale)
    if public_port and public_port != listen_port:
        for ipt, fkey in (('iptables', 4), ('ip6tables', 6)):
            addrs = fam[fkey]
            if addrs == []:
                continue
            for addr in (addrs if addrs is not None else ['']):
                dest = f' -d {addr}' if addr else ''
                rule = (f'-t nat -A PREROUTING -p {l4}{dest} --dport {public_port} '
                        f'-j REDIRECT --to-ports {listen_port}')
                commands.append(f'{ipt} {rule.replace("-A ", "-C ", 1)} 2>/dev/null || {ipt} {rule}')
    return (commands or None), warning


def _parse_ss_listeners(output):
    """Turn `ss -tulpnH` output into [{proto, address, process, pid}]."""
    listeners = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split(None, 5)
        if len(fields) < 5 or fields[0] not in ('tcp', 'udp'):
            continue
        process, pid = '', ''
        if len(fields) > 5:
            m = re.search(r'\("([^"]+)",pid=(\d+)', fields[5])
            if m:
                process, pid = m.group(1), m.group(2)
        listeners.append({'proto': fields[0], 'address': fields[4],
                          'process': process, 'pid': pid})
    return listeners


@app.get('/api/servers/{server_id}/protocol/port-check', tags=["Protocols"])
async def api_check_protocol_port(request: Request, server_id: int, port: str = ''):
    """Who is listening on a candidate port on the server.

    For the public-endpoint modal: before a custom port is published in
    client configs the admin should see whether (and by what) it is taken.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        port = normalize_public_port(port)
    except ValueError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    if not port:
        return JSONResponse({'error': 'Port is required'}, status_code=400)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    ssh = None
    try:
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        out, _, _ = await asyncio.to_thread(
            ssh.run_command, "ss -tulpnH '( sport = :%d )'" % int(port))
        listeners = _parse_ss_listeners(out)
        resp = {'port': int(port), 'in_use': bool(listeners), 'listeners': listeners}
        if listeners:
            foreign = [l for l in listeners
                       if not re.match(r'^(docker-proxy|dockerd)$', l.get('process', ''))]
            if not foreign:
                resp['warning'] = (f'Port {port} is held by Docker; the REDIRECT rule may '
                                   f'conflict unless the container publish is removed.')
        return resp
    except Exception as e:
        logger.warning(f"Port check on server {server_id} failed: {e}")
        return JSONResponse({'error': str(e)}, status_code=502)
    finally:
        if ssh is not None:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/wgeasy/import', tags=["Protocols"])
def api_wgeasy_import(request: Request, server_id: int, req: WgEasyImportRequest):
    """Migrate clients from a wg-easy panel on this server into a panel-managed
    WireGuard instance, preserving keys/IPs/port so client configs keep working."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    from managers.wgeasy_import import WgEasyError  # noqa: needed in except below
    log = []
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        if 'protocols' not in server:
            server['protocols'] = {}
        ssh = get_ssh(server)
        ssh.connect()
        try:
            from managers.wgeasy_import import WgEasyImporter, WgEasyError, run_import
            importer = WgEasyImporter(ssh, web_port=req.web_port)
            backup = importer.fetch_backup(req.password, req.username or 'admin')
            _, _, _, obfuscation = importer.detect_source()
            target = req.target if req.target in ('wireguard', 'awg2') else (
                'awg2' if obfuscation else 'wireguard')
            # Additional instances are supported for AWG 2.0: when the first
            # slot is taken, import as the next free instance key (awg2__2,
            # awg2__3, ...). WireGuard is single-instance for now.
            if target in server['protocols'] and target != 'awg2':
                return JSONResponse(
                    {'error': f'Protocol {target} is already installed on this server. '
                              'Remove it first if you want to re-import.'}, status_code=400)
            if target == 'awg2' and any(k.split('__', 1)[0] == 'awg2'
                                        for k in server['protocols']):
                target = next_protocol_key(server['protocols'], 'awg2')
            result = run_import(ssh, backup, client_ids=req.client_ids,
                                target=target, log=log)
            result['log'] = log
        finally:
            ssh.disconnect()

        server['protocols'][target] = {
            'installed': True,
            'port': result['port'],
            'awg_params': {},
            'base_protocol': protocol_base(target),
            'instance': protocol_instance(target),
            'display_name': protocol_display_name(target),
            'container_name': protocol_container_name(target),
        }
        save_data(data)
        return result
    except WgEasyError as e:
        return JSONResponse({'error': str(e), 'log': log}, status_code=400)
    except Exception as e:
        logger.exception("Error importing from wg-easy")
        return JSONResponse({'error': str(e), 'log': log}, status_code=500)


@app.post('/api/servers/{server_id}/server_config/save', tags=["Protocols"])
@serialize_peer_lifecycle
def api_server_config_save(request: Request, server_id: int, req: ServerConfigSaveRequest):
    """Save the raw server-side WireGuard/Xray configuration and apply changes."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        guard = _traffic_removal_guard(data, server_id=server_id, protocol=req.protocol, include_archived=True)
        if guard is not None:
            return guard
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        if protocol_base(req.protocol) == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh, req.protocol)
            import json as _json
            try:
                data_json = _json.loads(req.config)
            except Exception as e:
                ssh.disconnect()
                return JSONResponse({'error': f'Invalid JSON format: {str(e)}'}, status_code=400)
            mgr._save_server_json(data_json)
        elif protocol_base(req.protocol) == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        elif protocol_base(req.protocol) == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            mgr.save_server_config(req.config)
        elif protocol_base(req.protocol) == 'nginx':
            from managers.nginx_manager import NginxManager
            mgr = NginxManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        else:
            mgr = AWGManager(ssh)
            mgr.save_server_config(req.protocol, req.config)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving server config")
        return JSONResponse({'error': str(e)}, status_code=500)





@app.post('/api/servers/{server_id}/nginx/site', tags=["Protocols"])
def api_nginx_site_get(request: Request, server_id: int, req: ProtocolRequest):
    """Return editable NGINX site index.html."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if protocol_base(req.protocol) != 'nginx':
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        from managers.nginx_manager import NginxManager
        mgr = NginxManager(ssh, req.protocol)
        html = mgr.get_site_index(req.protocol)
        ssh.disconnect()
        return {'status': 'success', 'html': html}
    except Exception as e:
        logger.exception("Error getting NGINX site")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/nginx/site/save', tags=["Protocols"])
def api_nginx_site_save(request: Request, server_id: int, req: NginxSiteSaveRequest):
    """Save editable NGINX site index.html."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if protocol_base(req.protocol) != 'nginx':
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        from managers.nginx_manager import NginxManager
        mgr = NginxManager(ssh, req.protocol)
        mgr.save_site_index(req.protocol, req.html)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving NGINX site")
        return JSONResponse({'error': str(e)}, status_code=500)

@app.get('/api/servers/{server_id}/connections', tags=["Connections"])
def api_get_connections(request: Request, server_id: int, protocol: str = Query(default='awg')):
    if not protocol:
        protocol = 'awg'
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        clients = _manager_call(manager, 'get_clients', protocol)
        ssh.disconnect()

        # Enrich with user info from user_connections
        user_conns = data.get('user_connections', [])
        users = data.get('users', [])
        users_map = {u['id']: u for u in users}
        for client in clients:
            cid = client.get('clientId', '')
            for uc in user_conns:
                if uc.get('client_id') == cid and uc.get('server_id') == server_id and uc.get('protocol') == protocol:
                    uid = uc.get('user_id')
                    u = users_map.get(uid)
                    if u:
                        client['assigned_user'] = u['username']
                        client['assigned_user_id'] = uid
                    break
        return {'clients': clients}
    except Exception as e:
        logger.exception("Error getting connections")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/add', tags=["Connections"])
@serialize_peer_lifecycle
def api_add_connection(request: Request, server_id: int, req: AddConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        pub_host, pub_port = protocol_public_endpoint(server, req.protocol)
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        
        if protocol_base(req.protocol) == 'telemt':
            result = manager.add_client(
                req.protocol, req.name, pub_host, pub_port or port,
                telemt_quota=req.telemt_quota,
                telemt_max_ips=req.telemt_max_ips,
                telemt_expiry=req.telemt_expiry,
                secret=req.telemt_secret,
                user_ad_tag=req.telemt_ad_tag,
                max_tcp_conns=req.telemt_max_conns
            )
        elif protocol_base(req.protocol) == 'wireguard':
            result = manager.add_client(req.name, pub_host, public_port=pub_port)
        else:
            result = manager.add_client(req.protocol, req.name, pub_host, port, public_port=pub_port)
        ssh.disconnect()

        if result.get('config'):
            result.update(config_payloads(result['config'], server, req.protocol))

        # Link connection to user if specified
        if req.user_id and result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': req.user_id,
                'server_id': server_id,
                'protocol': req.protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            data['user_connections'].append(conn)
            save_data(data)

        return result
    except Exception as e:
        logger.exception("Error adding connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/remove', tags=["Connections"])
@serialize_peer_lifecycle
async def api_remove_connection(request: Request, server_id: int, req: ConnectionActionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)

        try:
            actor = str(get_current_user(request)['id'])
        except Exception:
            actor = 'admin'
        operation_id = uuid.uuid4().hex

        # An owned peer must be finalized; an unowned peer can be removed raw.
        conn = find_connection(data, server_id, req.protocol, req.client_id)
        if conn is None:
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            manager = get_protocol_manager(ssh, req.protocol)
            await asyncio.to_thread(_manager_call, manager, 'remove_client',
                                    req.protocol, req.client_id)
            ssh.disconnect()
            return {'status': 'success', 'finalized': False}

        scope = connection_scope(conn, server)
        kind = 'peer_remove'
        intent = make_intent(scope, 'remove')

        observed_bytes = None
        quiescent = False
        ssh = None
        try:
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            manager = get_protocol_manager(ssh, req.protocol)
            observed_bytes, quiescent = await asyncio.to_thread(
                read_peer_state, manager, req.protocol, req.client_id)

            if observed_bytes is None and not quiescent and not req.allow_unverified:
                return JSONResponse({
                    'error': 'Could not read the final traffic counter.',
                    'code': 'final_counter_read_failed',
                    'can_force': True,
                }, status_code=409)

            await asyncio.to_thread(_manager_call, manager, 'remove_client',
                                    req.protocol, req.client_id)
        except FinalizationError as exc:
            return JSONResponse({'error': str(exc), 'code': exc.code,
                                 'can_force': exc.can_force}, status_code=409)
        except Exception as exc:
            logger.exception("Error during peer removal SSH")
            return JSONResponse({'error': str(exc), 'code': 'removal_ssh_failed'},
                                status_code=502)
        finally:
            if ssh:
                try:
                    ssh.disconnect()
                except Exception:
                    pass

        async with DATA_LOCK:
            before = pathlib_read_data_bytes() if os.path.exists(DATA_FILE) else b''
            data = load_data()
            conn = find_connection(data, server_id, req.protocol, req.client_id)
            if conn is None:
                return JSONResponse({'error': 'Connection link disappeared during removal'},
                                    status_code=409)
            mode = 'delete_unverified' if observed_bytes is None else 'delete_finalized'
            accounting = finalize_connection_record(
                data, conn, server, observed_bytes, time.time(), mode,
                operation_id, quiescent)
            result = await asyncio.to_thread(
                commit_finalize, DATA_FILE, operation_id, actor, kind, intent,
                before, data)
            result['accounting'] = accounting
            result['finalized'] = True
            return result
    except Exception as e:
        logger.exception("Error removing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/edit', tags=["Connections"])
@serialize_peer_lifecycle
def api_edit_connection(request: Request, server_id: int, req: EditConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        
        edit_params = {}
        if protocol_base(req.protocol) == 'telemt':
            edit_params['telemt_quota'] = req.telemt_quota
            edit_params['telemt_max_ips'] = req.telemt_max_ips
            edit_params['telemt_expiry'] = req.telemt_expiry
            edit_params['secret'] = req.telemt_secret
            edit_params['user_ad_tag'] = req.telemt_ad_tag
            edit_params['max_tcp_conns'] = req.telemt_max_conns
            
        result = manager.edit_client(req.protocol, req.client_id, edit_params)
        ssh.disconnect()
        return result
    except Exception as e:
        logger.exception("Error editing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/clear_warnings', tags=["Connections"])
def api_clear_conn_warnings(request: Request, server_id: int, req: ConnectionActionRequest):
    """Clear recorded connection-flood (torrent) warnings for one peer."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        result = _manager_call(manager, 'clear_conn_warnings', req.protocol, req.client_id) or {}
        ssh.disconnect()
        return result
    except Exception as e:
        logger.exception("Error clearing connection warnings")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/rename', tags=["Connections"])
@serialize_peer_lifecycle
async def api_rename_connection(request: Request, server_id: int, req: RenameConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        async with DATA_LOCK:
            data = load_data()
        if server_id < 0 or server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        new_name = (req.new_name or '').strip()
        if not new_name:
            return JSONResponse({'error': 'New name is required'}, status_code=400)
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        connection_ids = {
            conn['id'] for conn in data.get('user_connections', [])
            if conn.get('id') and conn.get('client_id') == req.client_id
            and conn.get('server_id') == server_id and conn.get('protocol') == req.protocol
        }

        def rename_peer():
            ssh = get_ssh(server)
            try:
                ssh.connect()
                manager = get_protocol_manager(ssh, req.protocol)
                result = _manager_call(manager, 'rename_client', req.protocol, req.client_id, new_name) or {}
                speed_warning = None
                if req.max_speed >= 0 and hasattr(manager, 'set_speed_limit'):
                    try:
                        _manager_call(manager, 'set_speed_limit', req.protocol, req.client_id, req.max_speed)
                    except Exception as se:
                        logger.warning(f"set_speed_limit failed: {se}")
                        speed_warning = str(se)
                return result, speed_warning
            finally:
                ssh.disconnect()

        # Blocking SSH stays outside DATA_LOCK and off the event loop.
        result, speed_warning = await asyncio.to_thread(rename_peer)
        # Telemt rename may also change client_id (username is the identity there)
        new_client_id = result.get('client_id', req.client_id)
        stored_name = result.get('name', new_name)
        async with DATA_LOCK:
            current = load_data()
            changed = False
            for conn in current.get('user_connections', []):
                if (conn.get('id') in connection_ids and conn.get('client_id') == req.client_id
                        and conn.get('server_id') == server_id and conn.get('protocol') == req.protocol):
                    conn['name'] = stored_name
                    conn['client_id'] = new_client_id
                    changed = True
            if changed:
                save_data(current)
        resp = {'status': 'success', 'name': stored_name, 'client_id': new_client_id}
        if speed_warning:
            resp['speed_warning'] = speed_warning
        return resp
    except Exception as e:
        logger.exception("Error renaming connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/speed', tags=["Connections"])
async def api_set_connection_speed(request: Request, server_id: int, req: ConnectionSpeedRequest):
    actor = _check_admin(request)
    if not actor or actor.get('role') != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if (not math.isfinite(req.max_speed) or not 0 <= req.max_speed <= 1000000
            or round(req.max_speed, 1) != req.max_speed):
        return JSONResponse({'error': 'max_speed must be finite, 0..1000000 Mbit/s, in steps of 0.1'}, status_code=400)
    data = load_data()
    if server_id < 0 or server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    if req.protocol not in (server.get('protocols') or {}):
        return JSONResponse({'error': 'Protocol not installed'}, status_code=404)

    def set_peer_speed():
        ssh = get_ssh(server)
        try:
            ssh.connect()
            manager = get_protocol_manager(ssh, req.protocol)
            if not callable(getattr(manager, 'set_speed_limit', None)):
                return JSONResponse({'error': 'Speed limits are not supported by this protocol'}, status_code=501)
            clients = _manager_call(manager, 'get_clients', req.protocol)
            if not any(c.get('clientId') == req.client_id for c in clients):
                return JSONResponse({'error': 'Client not found'}, status_code=404)
            result = _manager_call(manager, 'set_speed_limit', req.protocol, req.client_id, req.max_speed)
            if not isinstance(result, dict) or result.get('status') != 'success' or result.get('speed_warning'):
                raise RuntimeError('Speed limit application was not confirmed')
            clients = _manager_call(manager, 'get_clients', req.protocol)
            peer = next((c for c in clients if c.get('clientId') == req.client_id), None)
            if peer is None or float((peer.get('userData') or {}).get('maxSpeed') or 0) != req.max_speed:
                raise RuntimeError('Speed limit read-back mismatch')
            return {'status': 'success', 'server_id': server_id, 'protocol': req.protocol,
                    'client_id': req.client_id, 'max_speed': req.max_speed}
        finally:
            ssh.disconnect()

    try:
        # No rename, local JSON write, or DATA_LOCK held across SSH.
        return await asyncio.to_thread(set_peer_speed)
    except Exception:
        logger.exception('Error applying connection speed limit')
        return JSONResponse({'error': 'Speed limit could not be applied or verified'}, status_code=502)


@app.post('/api/servers/{server_id}/connections/config/save', tags=["Connections"])
@serialize_peer_lifecycle
def api_save_connection_config(request: Request, server_id: int, req: SaveConnectionConfigRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        config_text = (req.config or '').strip()
        if not config_text:
            return JSONResponse({'error': 'Config is required'}, status_code=400)
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        _manager_call(manager, 'save_client_config', req.protocol, req.client_id, config_text)
        ssh.disconnect()
        return {'status': 'success', **config_payloads(config_text, server, req.protocol)}
    except Exception as e:
        logger.exception("Error saving connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/config', tags=["Connections"])
def api_get_connection_config(request: Request, server_id: int, req: ConnectionActionRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        # Only explicit privileged roles may view unowned connections.
        if user.get('role') not in ('admin', 'support'):
            owned = any(
                c for c in data.get('user_connections', [])
                if c.get('client_id') == req.client_id
                and c.get('server_id') == server_id
                and c.get('user_id') == user['id']
                and c.get('protocol')
                # Preserve manager aliases such as awg and awg__1.
                and protocol_base(c['protocol']) == protocol_base(req.protocol)
                and protocol_instance(c['protocol']) == protocol_instance(req.protocol)
            )
            if not owned:
                return JSONResponse({'error': 'Forbidden'}, status_code=403)
        server = data['servers'][server_id]
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        pub_host, pub_port = protocol_public_endpoint(server, req.protocol)
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        config = _manager_call(manager, 'get_client_config', req.protocol, req.client_id, pub_host, port, public_port=pub_port)
        ssh.disconnect()
        return {'config': config, **config_payloads(config, server, req.protocol)}
    except Exception as e:
        logger.exception("Error getting connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/toggle', tags=["Connections"])
@serialize_peer_lifecycle
def api_toggle_connection(request: Request, server_id: int, req: ToggleConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        _manager_call(manager, 'toggle_client', req.protocol, req.client_id, req.enable)
        ssh.disconnect()
        status = 'enabled' if req.enable else 'disabled'
        return {'status': 'success', 'enabled': req.enable, 'message': f'Connection {status}'}
    except Exception as e:
        logger.exception("Error toggling connection")
        return JSONResponse({'error': str(e)}, status_code=500)


# ======================== USER API (admin only) ========================

@app.get('/api/users', tags=["Users"])
def api_list_users(request: Request, search: str = '', page: int = 1, size: int = 10):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    all_users = data.get('users', [])
    conns = data.get('user_connections', [])
    
    # Filter
    filtered = []
    search = search.lower()
    for u in all_users:
        if search:
            match = (search in u['username'].lower() or 
                     (u.get('email') and search in u['email'].lower()) or 
                     (u.get('telegramId') and search in str(u['telegramId']).lower()))
            if not match:
                continue
        filtered.append(u)
        
    total = len(filtered)
    start = (page - 1) * size
    end = start + size
    page_items = filtered[start:end]
    
    users = []
    for u in page_items:
        users.append({
            'id': u['id'], 'username': u['username'], 'role': u['role'],
            'enabled': u.get('enabled', True),
            'disable_reasons': u.get('disable_reasons', [] if u.get('enabled', True) else ['legacy']),
            'access_revision': u.get('access_revision', 0),
            'access_sync_pending': u.get('access_sync_pending', False),
            'created_at': u.get('created_at', ''),
            'telegramId': u.get('telegramId'),
            'email': u.get('email'),
            'description': u.get('description'),
            'connections_count': sum(1 for c in conns if c['user_id'] == u['id']),
            'traffic_used': u.get('traffic_used', 0),
            'traffic_total': u.get('traffic_total', 0),
            'traffic_limit': u.get('traffic_limit', 0),
            'traffic_reset_strategy': u.get('traffic_reset_strategy', 'never'),
            'last_reset_at': u.get('last_reset_at'),
            "expiration_date": u.get("expiration_date"),
            'share_enabled': u.get('share_enabled', False),
            'share_token': u.get('share_token'),
            'has_share_password': bool(u.get('share_password_hash')),
            'source': 'Remnawave' if u.get('remnawave_uuid') else 'Local'
        })
    return {
        'users': users,
        'total': total,
        'page': page,
        'size': size,
        'pages': (total + size - 1) // size
    }


@app.post('/api/users/add', tags=["Users"])
@serialize_peer_lifecycle
def api_add_user(request: Request, req: AddUserRequest):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        lang = request.cookies.get('lang', 'ru')
        try:
            telegram_id = _normalize_telegram_id(req.telegramId)
        except ValueError as exc:
            return JSONResponse({'error': str(exc)}, status_code=400)
        # Check duplicate
        if any(u['username'] == req.username for u in data.get('users', [])):
            return JSONResponse({'error': _t('user_exists', lang)}, status_code=400)
        if req.role not in ('admin', 'support', 'user', 'none'):
            return JSONResponse({'error': _t('invalid_role', lang)}, status_code=400)
        if req.role != 'none' and not req.password:
            return JSONResponse({'error': _t('password_required_for_role', lang)}, status_code=400)
        new_user = {
            'id': str(uuid.uuid4()),
            'username': req.username,
            'password_hash': hash_password(req.password) if req.password else None,
            'role': req.role,
            'telegramId': telegram_id,
            'email': req.email,
            'description': req.description,
            'traffic_limit': int(req.traffic_limit * 1024**3) if req.traffic_limit else 0,
            'traffic_reset_strategy': req.traffic_reset_strategy or 'never',
            'traffic_used': 0,
            'traffic_total': 0,
            'last_reset_at': datetime.now().isoformat(),
            'expiration_date': req.expiration_date,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
            'remnawave_uuid': None,
            'share_enabled': False,
            'share_token': secrets.token_urlsafe(16),
            'share_password_hash': None,
        }
        data['users'].append(new_user)
        save_data(data)

        result = {'status': 'success', 'user_id': new_user['id']}

        # Auto-create connection if server & protocol specified
        if req.server_id is not None and req.protocol:
            if req.server_id < len(data['servers']):
                server = data['servers'][req.server_id]
                proto_info = server.get('protocols', {}).get(req.protocol, {})
                port = proto_info.get('port', '55424')
                pub_host, pub_port = protocol_public_endpoint(server, req.protocol)
                conn_name = req.connection_name or f"{req.username}_vpn"
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, req.protocol)
                if protocol_base(req.protocol) == 'telemt':
                    conn_result = manager.add_client(
                        req.protocol, conn_name, pub_host, pub_port or port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns
                    )
                else:
                    conn_result = manager.add_client(req.protocol, conn_name, pub_host, port, public_port=pub_port)
                ssh.disconnect()

                if conn_result.get('client_id'):
                    conn = {
                        'id': str(uuid.uuid4()),
                        'user_id': new_user['id'],
                        'server_id': req.server_id,
                        'protocol': req.protocol,
                        'client_id': conn_result['client_id'],
                        'name': conn_name,
                        'created_at': datetime.now().isoformat(),
                    }
                    data = load_data()  # reload
                    data['user_connections'].append(conn)
                    save_data(data)
                    result['connection_created'] = True
                    if conn_result.get('config'):
                        result['config'] = conn_result['config']
                        result.update(config_payloads(conn_result['config'], server, req.protocol))
        return result
    except Exception as e:
        logger.exception("Error adding user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/update', tags=["Users"])
async def api_update_user(request: Request, user_id: str, req: UpdateUserRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        async with DATA_LOCK:
            data = load_data()
            user = next((u for u in data['users'] if u['id'] == user_id), None)
            if not user:
                return JSONResponse({'error': 'User not found'}, status_code=404)

            if req.username is not None:
                new_name = req.username.strip()
                lang = request.cookies.get('lang', 'ru')
                if not new_name:
                    return JSONResponse({'error': _t('username_empty', lang)}, status_code=400)
                if any(u['username'] == new_name and u['id'] != user_id for u in data.get('users', [])):
                    return JSONResponse({'error': _t('user_exists', lang)}, status_code=400)
                user['username'] = new_name
            if req.telegramId is not None:
                try:
                    user['telegramId'] = _normalize_telegram_id(req.telegramId)
                except ValueError as exc:
                    return JSONResponse({'error': str(exc)}, status_code=400)
            if req.email is not None: user['email'] = req.email
            if req.description is not None: user['description'] = req.description
            if req.traffic_limit is not None:
                new_limit = int(req.traffic_limit * 1024**3)
                user['traffic_limit'] = new_limit

            if req.traffic_reset_strategy is not None:
                user['traffic_reset_strategy'] = req.traffic_reset_strategy
                user['last_reset_at'] = datetime.now().isoformat()

            req_fields = getattr(req, 'model_fields_set', getattr(req, '__fields_set__', set()))
            if 'expiration_date' in req_fields:
                user['expiration_date'] = req.expiration_date or None

            if req.password:
                user['password_hash'] = hash_password(req.password)

            old_enabled = user.get('enabled', True)
            if (req.traffic_limit is not None or req.traffic_reset_strategy is not None
                    or 'expiration_date' in req_fields):
                reconcile_user_state(user, datetime.now())
            pending = user.get('access_sync_pending', False)
            wait_for_ssh = pending and (old_enabled != user['enabled'] or user_id not in _USER_STATE_TASKS)
            save_data(data)

        if wait_for_ssh and not await perform_toggle_user(data, user_id, user['enabled']):
            return JSONResponse({'error': 'Access intent saved; SSH application pending'}, status_code=503)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error updating user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/delete', tags=["Users"])
@serialize_peer_lifecycle
async def api_delete_user(request: Request, user_id: str):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'ru')
    if cur['id'] == user_id:
        return JSONResponse({'error': _t('cannot_delete_self', lang)}, status_code=400)
    try:
        # A linked user is rejected without SSH; deleting an empty user is a
        # short local mutation. Resolve it under the lock so concurrent linking
        # cannot disappear through the previous stale snapshot save.
        async with DATA_LOCK:
            data = load_data()
            guard = _traffic_removal_guard(data, user_ids={user_id})
            if guard is not None:
                return guard
            if not perform_delete_user(data, user_id):
                return JSONResponse({'error': 'User not found'}, status_code=404)
            save_data(data)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error deleting user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/toggle', tags=["Users"])
async def api_toggle_user(request: Request, user_id: str, req: ToggleUserRequest):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        async with DATA_LOCK:
            data = load_data()
            user = next((u for u in data['users'] if u['id'] == user_id), None)
            if not user:
                return JSONResponse({'error': 'User not found'}, status_code=404)
            reconcile_user_state(user, datetime.now(), manual=req.enabled)
            save_data(data)
        # SSH only propagates the committed intent; it must not save an old
        # full-data snapshot when it completes.
        if not await perform_toggle_user(data, user_id, user['enabled']):
            return JSONResponse({'error': 'Access intent saved; SSH application pending'}, status_code=503)
        current = load_data()
        user = next((u for u in current['users'] if u['id'] == user_id), None)
        return {'status': 'success', 'enabled': user['enabled'] if user else False}
    except Exception as e:
        logger.exception("Error toggling user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/traffic/reset', tags=["Users"])
async def api_reset_user_traffic(request: Request, user_id: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        async with DATA_LOCK:
            data = load_data()
            user = next((u for u in data.get('users', []) if u.get('id') == user_id), None)
            if not user:
                return JSONResponse({'error': 'User not found'}, status_code=404)
            user['traffic_used'] = 0
            user['last_reset_at'] = datetime.now().isoformat()
            reconcile_user_state(user, datetime.now())
            save_data(data)
        if user.get('access_sync_pending') and not await perform_toggle_user(data, user_id, user['enabled']):
            return JSONResponse({'error': 'Traffic reset saved; SSH application pending'}, status_code=503)
        return {
            'status': 'success',
            'traffic_used': user['traffic_used'],
            'last_reset_at': user['last_reset_at']
        }
    except Exception as e:
        logger.exception("Error resetting user traffic")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/connections/add', tags=["Users"])
@serialize_peer_lifecycle
async def api_add_user_connection(request: Request, user_id: str, req: AddUserConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        if not req.client_id and protocol_base(req.protocol) in ('awg', 'awg2', 'awg3', 'awg_legacy'):
            result = await peer_creates.create(user_id, req.server_id, req.protocol,
                                               req.name, req.operation_id)
            data = load_data()
            operation = peer_creates.journal.read()[result['operation_id']]
            server = next(server for server in data['servers']
                          if server.get('uid') == operation['identity'][1])
            response = {'status': 'success', 'operation_id': result['operation_id']}
            if result.get('config'):
                response['config'] = result['config']
                response.update(config_payloads(result['config'], server, req.protocol))
            return response
        data = load_data()
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        if req.server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][req.server_id]

        if req.client_id:
            # A peer is a single on/off entity on the server: linking it to a
            # second panel user would make both cards control the same peer.
            # Reject any double-link, even to the same user.
            clash = next(
                (c for c in data.get('user_connections', [])
                 if c.get('client_id') == req.client_id
                 and c.get('server_id') == req.server_id
                 and c.get('protocol') == req.protocol),
                None,
            )
            if clash:
                lang = request.cookies.get('lang', 'ru')
                if clash.get('user_id') == user_id:
                    return JSONResponse({'error': _t('peer_already_linked_self', lang)}, status_code=400)
                owner = next((u for u in data['users'] if u['id'] == clash.get('user_id')), None)
                owner_name = owner['username'] if owner else '?'
                return JSONResponse({'error': _t('peer_already_linked', lang).replace('{}', owner_name)}, status_code=400)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        pub_host, pub_port = protocol_public_endpoint(server, req.protocol)
        ssh = await asyncio.to_thread(get_ssh, server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)
        
        if req.client_id:
            # Use existing client
            target_client_id = req.client_id
            # Retrieve config for existing client
            config = await asyncio.to_thread(_manager_call, manager, 'get_client_config', req.protocol, req.client_id, pub_host, port, public_port=pub_port)
            result = {'client_id': target_client_id, 'config': config}
        else:
            # Create new client
            if protocol_base(req.protocol) == 'telemt':
                result = await asyncio.to_thread(
                    manager.add_client, req.protocol, req.name, pub_host, pub_port or port,
                    telemt_quota=req.telemt_quota,
                    telemt_max_ips=req.telemt_max_ips,
                    telemt_expiry=req.telemt_expiry,
                    secret=req.telemt_secret,
                    user_ad_tag=req.telemt_ad_tag,
                    max_tcp_conns=req.telemt_max_conns
                )
            else:
                result = await asyncio.to_thread(manager.add_client, req.protocol, req.name, pub_host, port, public_port=pub_port)
        
        await asyncio.to_thread(ssh.disconnect)

        if result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'server_id': req.server_id,
                'protocol': req.protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            data = load_data()
            data['user_connections'].append(conn)
            save_data(data)

        resp = {'status': 'success'}
        if result.get('config'):
            resp['config'] = result['config']
            resp.update(config_payloads(result['config'], server, req.protocol))
        return resp
    except PeerCreateError as error:
        return JSONResponse({'error': str(error), 'operation_id': error.operation_id},
                            status_code=error.status_code)
    except Exception as e:
        logger.exception("Error adding user connection")
        return JSONResponse({'error': str(e)}, status_code=500)


class UnlinkConnectionRequest(BaseModel):
    server_id: int
    protocol: str = 'awg'
    client_id: str = ''
    stop: bool = False
    allow_unverified: bool = False


@app.post('/api/users/{user_id}/connections/unlink', tags=["Users"])
@serialize_peer_lifecycle
async def api_unlink_user_connection(request: Request, user_id: str, req: UnlinkConnectionRequest):
    """Unlink a peer from its owner, finalizing accounting first.

    * Disabled/absent peers can be unlinked directly (no traffic is possible).
    * Active peers require ``stop=True``; the endpoint disables the peer first.
    * A failed final counter read returns 409 with ``can_force=True`` so the
      UI can ask for explicit confirmation before ``allow_unverified=True``.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)

    try:
        actor = str(get_current_user(request)['id'])
    except Exception:
        actor = 'admin'
    operation_id = uuid.uuid4().hex

    async with DATA_LOCK:
        data = load_data()
        if req.server_id < 0 or req.server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][req.server_id]
        conn = find_connection(data, req.server_id, req.protocol, req.client_id,
                               user_id=user_id)
        if conn is None:
            return JSONResponse({'error': 'Connection link not found'}, status_code=404)
        scope = connection_scope(conn, server)
        kind = 'peer_unlink'
        intent = make_intent(scope, 'unlink')

    observed_bytes = None
    quiescent = False
    ssh = None
    try:
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)
        observed_bytes, quiescent = await asyncio.to_thread(
            read_peer_state, manager, req.protocol, req.client_id)

        if not quiescent and not req.stop:
            return JSONResponse({
                'error': 'Peer is active. Stop it first or use stop-and-unlink.',
                'code': 'peer_active_stop_required',
                'can_stop': True,
            }, status_code=409)

        if not quiescent and req.stop:
            await asyncio.to_thread(_manager_call, manager, 'toggle_client',
                                    req.protocol, req.client_id, False)
            observed_bytes, quiescent = await asyncio.to_thread(
                read_peer_state, manager, req.protocol, req.client_id)
            if not quiescent:
                return JSONResponse({
                    'error': 'Peer could not be stopped; unlink aborted.',
                    'code': 'peer_stop_failed',
                }, status_code=409)

        if observed_bytes is None and not quiescent and not req.allow_unverified:
            return JSONResponse({
                'error': 'Could not read the final traffic counter.',
                'code': 'final_counter_read_failed',
                'can_force': True,
            }, status_code=409)
    except FinalizationError as exc:
        return JSONResponse({'error': str(exc), 'code': exc.code,
                             'can_force': exc.can_force}, status_code=409)
    except Exception as exc:
        logger.exception("Error during unlink finalization SSH")
        return JSONResponse({'error': str(exc), 'code': 'finalization_ssh_failed'},
                            status_code=502)
    finally:
        if ssh:
            try:
                ssh.disconnect()
            except Exception:
                pass

    async with DATA_LOCK:
        before = pathlib_read_data_bytes() if os.path.exists(DATA_FILE) else b''
        data = load_data()
        conn = find_connection(data, req.server_id, req.protocol, req.client_id,
                               user_id=user_id)
        if conn is None:
            return JSONResponse({'error': 'Connection link not found'},
                                status_code=404)
        mode = 'unlink_stopped' if req.stop else 'unlink_finalized'
        accounting = finalize_connection_record(
            data, conn, server, observed_bytes, time.time(), mode,
            operation_id, quiescent)
        result = await asyncio.to_thread(
            commit_finalize, DATA_FILE, operation_id, actor, kind, intent,
            before, data)
        result['accounting'] = accounting
        return result


@app.get('/api/users/{user_id}/connections', tags=["Users"])
def api_get_user_connections(request: Request, user_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    # Users can only see their own, admin/support can see all
    if user['role'] in ('user', 'none') and user['id'] != user_id:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    conns = []
    for c in data.get('user_connections', []):
        if c['user_id'] != user_id:
            continue
        sid = c.get('server_id', 0)
        # Skip links to uninstalled instances: the peer is gone with the
        # container, and every action on such a phantom ends in
        # 'Client not found'. (Uninstall purges them; this is the belt.)
        if sid < len(data['servers']):
            srv = data['servers'][sid]
            if c.get('protocol') not in (srv.get('protocols') or {}):
                continue
        conns.append(c)
    for c in conns:
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', '')

    # Enrich with live peer data (IP, enabled, handshake, transfer, speed
    # limit) from each server the user has connections on. One SSH session
    # per (server, protocol) group; unreachable servers degrade gracefully —
    # the DB fields above are still returned.
    from collections import defaultdict
    groups = defaultdict(list)
    for c in conns:
        groups[(c.get('server_id', 0), c.get('protocol', 'awg'))].append(c)
    for (sid, proto), items in groups.items():
        try:
            if sid >= len(data['servers']):
                continue
            server = data['servers'][sid]
            ssh = get_ssh(server)
            ssh.connect()
            try:
                manager = get_protocol_manager(ssh, proto)
                clients = _manager_call(manager, 'get_clients', proto)
            finally:
                ssh.disconnect()
        except Exception as e:
            logger.warning(f"Could not enrich connections from server {sid}/{proto}: {e}")
            continue
        by_id = {cl.get('clientId'): cl for cl in clients}
        for c in items:
            cl = by_id.get(c.get('client_id'))
            if not cl:
                continue
            ud = cl.get('userData', {}) or {}
            # Peer names live in userData.clientName (same place the server
            # page reads them); fall back to a top-level key just in case.
            c['peer_name'] = ud.get('clientName') or cl.get('name', '')
            # Managers store the flag in userData.enabled; fall back to the
            # top-level key just in case another manager sets it there.
            enabled = cl.get('enabled', ud.get('enabled', True))
            c['enabled'] = enabled if enabled is not None else True
            c['allowed_ips'] = ud.get('allowedIps', '')
            c['latest_handshake'] = ud.get('latestHandshake', '')
            c['data_received'] = ud.get('dataReceived', '')
            c['data_sent'] = ud.get('dataSent', '')
            c['max_speed'] = ud.get('maxSpeed', 0) or 0
    return {'connections': conns}


# ======================== MY CONNECTIONS API (for user role) ========================

@app.get('/api/my/connections', tags=["Self-service"])
def api_my_connections(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    for c in conns:
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', '')
        else:
            c['server_name'] = 'Unknown'
        c['protocol_name'] = protocol_display_name(c.get('protocol', ''))
    return {'connections': conns}


@app.get('/api/my/connections/options', tags=["Self-service"])
async def api_my_connection_options(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await self_service_connections.get_self_service_options(user['id'], 'web')
    except Exception as exc:
        return _self_service_error_response(exc)


@app.post('/api/my/connections/add', tags=["Self-service"])
async def api_my_connection_add(request: Request, payload: SelfServiceConnectionRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await self_service_connections.create_user_connection(
            user['id'], payload.server_id, payload.protocol, payload.name, 'web'
        )
    except Exception as exc:
        return _self_service_error_response(exc)


@app.post('/api/my/connections/{connection_id}/delete', tags=["Self-service"])
async def api_my_connection_delete(request: Request, connection_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await self_service_connections.delete_user_connection(user['id'], connection_id, 'web')
    except Exception as exc:
        return _self_service_error_response(exc)


@app.post('/api/users/{user_id}/share/setup', tags=["Users"])
def api_user_share_setup(user_id: str, req: ShareSetupRequest, request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return JSONResponse({'error': 'User not found'}, status_code=404)
    
    # Revoke signed cookies without changing the public URL. Missing revisions
    # on existing records start at zero; legacy boolean cookies are rejected.
    if not req.enabled or req.password is not None:
        user['share_auth_revision'] = user.get('share_auth_revision', 0) + 1
    user['share_enabled'] = req.enabled
    if not user.get('share_token'):
        user['share_token'] = secrets.token_urlsafe(16)
    if req.password:
        user['share_password_hash'] = hash_password(req.password)
    elif req.password == "": # Clear
        user['share_password_hash'] = None
        
    save_data(data)
    return {'status': 'success', 'share_token': user.get('share_token')}


def _share_session_authorized(user, request):
    if not user.get('share_password_hash'):
        return True
    revision = request.session.get(f"share_auth_{user['share_token']}")
    # bool is an int subclass: require the exact type to reject old True cookies.
    return type(revision) is int and revision == user.get('share_auth_revision', 0)


@app.get('/share/{token}', response_class=HTMLResponse, tags=["System Templates"])
def share_page(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        lang = request.cookies.get('lang', 'ru')
        return HTMLResponse(f"<h1>{_t('share_not_found', lang)}</h1><p>{_t('share_not_found_desc', lang)}</p>", status_code=404)
    
    need_password = not _share_session_authorized(user, request)
    
    return tpl(request, 'user_share.html', 
               share_user=user, 
               need_password=need_password, 
               token=token)


@app.post('/api/share/{token}/auth', tags=["Sharing"])
def api_share_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    
    if verify_password(req.password, user.get('share_password_hash', '')):
        request.session[f'share_auth_{token}'] = user.get('share_auth_revision', 0)
        return {'status': 'success'}
    else:
        lang = request.cookies.get('lang', 'ru')
        return JSONResponse({'error': _t('wrong_share_password', lang)}, status_code=401)


@app.get('/api/share/{token}/connections', tags=["Sharing"])
def api_share_connections(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if not _share_session_authorized(user, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conns = [dict(c) for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    for c in conns:
        sid = c['server_id']
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name') or data['servers'][sid]['host']
        else:
            c['server_name'] = 'Unknown'
            
    return {'connections': conns, 'username': user['username']}


@app.post('/api/share/{token}/config/{connection_id}', tags=["Sharing"])
def api_share_config(token: str, connection_id: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if not _share_session_authorized(user, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conn = next((c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == user['id']), None)
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
        
    try:
        sid = conn['server_id']
        server = data['servers'][sid]
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        pub_host, pub_port = protocol_public_endpoint(server, conn['protocol'])
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = _manager_call(manager, 'get_client_config', conn['protocol'], conn['client_id'], pub_host, port, public_port=pub_port)
        ssh.disconnect()
        return {'config': config, **config_payloads(config, server, conn['protocol'])}
    except Exception as e:
        logger.exception("Error getting shared config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/my/connections/{connection_id}/config', tags=["Self-service"])
def api_my_connection_config(request: Request, connection_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        conn = next(
            (c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == user['id']),
            None
        )
        if not conn:
            return JSONResponse({'error': 'Connection not found'}, status_code=404)
        sid = conn['server_id']
        if sid >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][sid]
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        pub_host, pub_port = protocol_public_endpoint(server, conn['protocol'])
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol (fixes Telemt/Xray not working for users)
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = _manager_call(manager, 'get_client_config', conn['protocol'], conn['client_id'], pub_host, port, public_port=pub_port)
        ssh.disconnect()
        return {'config': config, **config_payloads(config, server, conn['protocol'])}
    except Exception as e:
        logger.exception("Error getting my connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


# ======================== EMAIL DELIVERY (admin) ========================

@app.post('/api/settings/mail/test', tags=["Email"])
async def api_mail_test(request: Request, req: MailTestRequest):
    """Send a one-liner through the stored SMTP settings to prove they work."""
    admin = _check_admin(request)
    if not admin:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'en')
    recipient = (req.recipient or '').strip() or str(admin.get('email') or '').strip()
    try:
        return await asyncio.to_thread(mail_svc.send_test, recipient, lang)
    except MailError as exc:
        return _mail_error_response(exc, lang)
    except Exception as exc:
        logger.exception("Mail: test send failed")
        return JSONResponse({'error': str(exc)}, status_code=502)


@app.post('/api/users/mail/bulk', tags=["Email"])
def api_mail_send_bulk(request: Request, req: MailBulkRequest):
    """Start a mass send. Returns immediately with the initial job state --
    reading a few hundred configs over SSH takes minutes, far longer than a
    browser waits, so the run continues in a worker thread and the page polls
    /api/users/mail/bulk/status."""
    admin = _check_admin(request)
    if not admin:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'en')
    try:
        options = MailOptions.from_dict(req.dict())
        return mail_svc.start_bulk(options, lang=lang, user_ids=req.user_ids,
                                   started_by=admin.get('username', ''))
    except MailError as exc:
        return _mail_error_response(exc, lang)
    except Exception as exc:
        logger.exception("Mail: bulk send failed to start")
        return JSONResponse({'error': str(exc)}, status_code=500)


@app.get('/api/users/mail/bulk/status', tags=["Email"])
def api_mail_bulk_status(request: Request):
    """Progress of the current (or last) mass send."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return mail_svc.bulk_status()


@app.post('/api/users/{user_id}/mail/send', tags=["Email"])
async def api_mail_send_user(request: Request, user_id: str, req: MailSendRequest):
    """Email one user their configs and/or proxy links."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'en')
    try:
        options = MailOptions.from_dict(req.dict())
        return await asyncio.to_thread(mail_svc.send_to_user, user_id, options, lang)
    except MailError as exc:
        return _mail_error_response(exc, lang)
    except Exception as exc:
        logger.exception("Mail: send to user failed")
        return JSONResponse({'error': str(exc)}, status_code=502)


@app.get('/settings', tags=["System Templates"])
def settings_page(request: Request):
    user = _check_admin(request)
    if not user:
        return RedirectResponse('/login')
    data = load_data()
    backup_csrf = request.session.setdefault('backup_csrf', secrets.token_urlsafe(32)) if user['role'] == 'admin' else ''
    return tpl(
        request,
        'settings.html',
        settings=data.get('settings', {}),
        servers=data.get('servers', []),
        current_version=CURRENT_VERSION,
        backup_csrf=backup_csrf,
        self_service_protocol_choices=self_service_protocol_choices(),
    )


@app.get('/api/settings', tags=["Settings"])
def api_get_settings(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    return data.get('settings', {})


@app.get('/api/settings/tunnels/status', tags=["Settings"])
def api_tunnels_status(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return {
        'local_server': get_panel_local_url(request),
        'cloudflare': get_tunnel_status('cloudflare'),
        'ngrok': get_tunnel_status('ngrok'),
        'warp': get_warp_status(),
    }


@app.post('/api/settings/tunnels/{provider}/install', tags=["Settings"])
async def api_tunnel_install(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(install_tunnel_binary, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error installing {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/tunnels/{provider}/start', tags=["Settings"])
async def api_tunnel_start(request: Request, provider: str, payload: TunnelStartRequest = TunnelStartRequest()):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        local_url = get_panel_tunnel_target_url()
        await asyncio.to_thread(start_tunnel, provider, local_url, payload.authtoken or '')
        status = await wait_for_tunnel_url(provider)
        if not status.get('running'):
            return JSONResponse({'error': status.get('last_error') or 'Tunnel process stopped'}, status_code=500)
        return status
    except Exception as e:
        logger.exception(f"Error starting {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/tunnels/{provider}/stop', tags=["Settings"])
async def api_tunnel_stop(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(stop_tunnel, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error stopping {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.delete('/api/settings/tunnels/{provider}', tags=["Settings"])
async def api_tunnel_delete(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(delete_tunnel_binary, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error deleting {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/warp/connect', tags=["Settings"])
async def api_warp_connect(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(enable_warp)
    except Exception as e:
        logger.exception("Error connecting Cloudflare WARP")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/warp/disconnect', tags=["Settings"])
async def api_warp_disconnect(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(disable_warp)
    except Exception as e:
        logger.exception("Error disconnecting Cloudflare WARP")
        return JSONResponse({'error': str(e)}, status_code=500)


# @app.post('/api/settings/save')
# async def api_save_settings(request: Request, body: SaveSettingsRequest):
#     _check_admin(request)
#     data = load_data()
#     data['settings'] = body.dict()
#     save_data(data)
    
#     # Trigger sync if enabled
#     if body.sync.remnawave_sync_users:
#         await sync_users_with_remnawave(data)
#         save_data(data)
        
#     return {'status': 'success'}

@app.post('/api/settings/save', tags=["Settings"])
def save_settings(request: Request, payload: SaveSettingsRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    settings = data.setdefault('settings', {})
    settings['appearance'] = payload.appearance.dict()
    settings['sync'] = payload.sync.dict()
    settings['captcha'] = payload.captcha.dict()
    settings['telegram'] = payload.telegram.dict()
    settings['ssl'] = payload.ssl.dict()
    settings['mail'] = merge_mail_settings(settings.get('mail'), payload.mail.dict())

    old_auto_backup = settings.get('auto_backup', {}) or {}
    interval_hours = max(1, min(24, int(payload.auto_backup.interval_hours or 24)))
    settings['auto_backup'] = {
        'enabled': bool(payload.auto_backup.enabled),
        'interval_hours': interval_hours,
        'last_run_at': old_auto_backup.get('last_run_at'),
        'last_status': old_auto_backup.get('last_status'),
        'last_created_count': old_auto_backup.get('last_created_count', 0),
        'last_error': old_auto_backup.get('last_error')
    }
    self_service = payload.self_service.dict()
    self_service['allowed_protocols'] = sanitize_allowed_protocols(self_service.get('allowed_protocols'))
    settings['self_service'] = self_service

    warnings = []
    default_exit_uid = (payload.exit_nodes.default_exit_uid or '').strip()
    if default_exit_uid and not any(n['uid'] == default_exit_uid
                                    for n in exit_link_svc.list_exit_nodes(data)):
        # the node was uninstalled or deleted between opening and saving
        default_exit_uid = ''
        warnings.append('exit_default_cleared')
    settings['exit_nodes'] = {'default_exit_uid': default_exit_uid}
    save_data(data)
    logger.info("Settings saved (including captcha, telegram and auto backup)")

    # Handle bot start/stop based on new telegram settings
    tg_cfg = payload.telegram
    if tg_cfg.enabled and tg_cfg.token:
        if not tg_bot.is_running():
            logger.info("Starting Telegram bot (settings save)...")
            tg_bot.launch_bot(tg_cfg.token, load_data, generate_vpn_link, save_data, self_service_svc=self_service_connections)
    else:
        if tg_bot.is_running():
            logger.info("Stopping Telegram bot (settings save)...")
            asyncio.create_task(tg_bot.stop_bot())

    return {"status": "success", "bot_running": tg_bot.is_running(), "warnings": warnings}


# ----- DuckDNS: free domain + one-click auto-renewed Let's Encrypt cert -----

DUCKDNS_CERT_DIR = '/etc/amnezia'
DUCKDNS_UPDATE_INTERVAL = 600


def _duckdns_normalize_domain(domain):
    """Accept 'example' or 'example.duckdns.org', return the full domain."""
    d = (domain or '').strip().lower().rstrip('.')
    if d.endswith('.duckdns.org'):
        d = d[:-len('.duckdns.org')]
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z0-9]', d or ''):
        return ''
    return f"{d}.duckdns.org"


def _duckdns_update_ip(domain, token):
    """Point the duckdns domain at this server's public IP.

    An empty ip= makes duckdns use the caller's address, which is exactly
    the panel server. Returns (ok, detail)."""
    subdomain = domain[:-len('.duckdns.org')]
    url = ('https://www.duckdns.org/update?domains=%s&token=%s&ip='
           % (urllib.parse.quote(subdomain), urllib.parse.quote(token)))
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            body = resp.read().decode('utf-8', 'replace').strip()
    except Exception as e:
        return False, str(e)
    return (body.upper().startswith('OK'), body)


def _duckdns_issue_cert(domain, token):
    """Issue a Let's Encrypt cert via acme.sh DNS-01 (duckdns plugin) and
    install it where the panel ssl settings expect. acme.sh drops its own
    cron entry, so renewal (and the panel restart via --reloadcmd under
    systemd) is automatic from then on. Returns (ok, log_tail)."""
    if os.name == 'nt':
        return False, 'DuckDNS auto-cert is supported on Linux panel hosts only'
    acme = os.path.expanduser('~/.acme.sh/acme.sh')
    logs = []
    if not os.path.exists(acme):
        inst = subprocess.run(
            'curl -s https://get.acme.sh | sh -s email=admin@%s' % domain,
            shell=True, capture_output=True, text=True, timeout=300)
        logs.append(((inst.stdout or '') + (inst.stderr or ''))[-2000:])
        if not os.path.exists(acme):
            return False, 'acme.sh install failed:\n' + '\n'.join(logs)
    env = dict(os.environ, DuckDNS_Token=token)
    issue = subprocess.run(
        [acme, '--issue', '--dns', 'dns_duckdns', '-d', domain,
         '--server', 'letsencrypt'],
        capture_output=True, text=True, timeout=300, env=env)
    logs.append(((issue.stdout or '') + (issue.stderr or ''))[-4000:])
    # rc 2 = "Skip, next renewal time" (a valid cert already exists) — fine,
    # --install-cert below will still export it to the panel paths.
    if issue.returncode not in (0, 2):
        return False, 'certificate issue failed:\n' + '\n'.join(logs)
    os.makedirs(DUCKDNS_CERT_DIR, exist_ok=True)
    key_file = os.path.join(DUCKDNS_CERT_DIR, 'duckdns.key.pem')
    cert_file = os.path.join(DUCKDNS_CERT_DIR, 'duckdns.cert.pem')
    cmd = [acme, '--install-cert', '-d', domain,
           '--key-file', key_file, '--fullchain-file', cert_file]
    if os.environ.get('INVOCATION_ID'):
        # renewed/installed cert -> restart the panel so uvicorn picks it up.
        # Delayed AND detached: a plain 'systemctl restart' here would kill
        # the very HTTP request that is running this install-cert (observed
        # on the first apply: files installed, child SIGTERMed, 502).
        cmd += ['--reloadcmd',
                "sh -c '(sleep 5 && systemctl restart amnezia-panel) >/dev/null 2>&1 &'"]
    install = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    logs.append(((install.stdout or '') + (install.stderr or ''))[-2000:])
    if install.returncode != 0 or not (os.path.exists(key_file) and os.path.exists(cert_file)):
        return False, 'certificate install failed:\n' + '\n'.join(logs)
    return True, '\n'.join(logs)


@app.post('/api/settings/duckdns/apply', tags=["Settings"])
def api_duckdns_apply(request: Request, payload: DuckDNSApplyRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    settings = data.setdefault('settings', {})
    stored = settings.get('duckdns', {}) or {}
    domain = _duckdns_normalize_domain(payload.domain) or stored.get('domain', '')
    token = payload.token.strip() or stored.get('token', '')
    if payload.enabled and (not domain or not token):
        return JSONResponse({'error': 'duckdns_domain_token_required'}, status_code=400)
    settings['duckdns'] = {
        'enabled': bool(payload.enabled),
        'domain': domain,
        'token': token,
    }
    result = {'status': 'success', 'domain': domain}
    if payload.enabled:
        ok, detail = _duckdns_update_ip(domain, token)
        result['ip_update'] = {'ok': ok, 'detail': detail}
        if not ok:
            save_data(data)
            return JSONResponse(
                {'error': 'duckdns_ip_update_failed', 'detail': detail},
                status_code=502)
        ok, log = _duckdns_issue_cert(domain, token)
        if not ok:
            save_data(data)
            return JSONResponse(
                {'error': 'duckdns_cert_failed', 'detail': log[-3000:]},
                status_code=502)
        # The duckdns card drives the SAME ssl config as the manual card:
        # issued paths are written into settings['ssl'].
        ssl_conf = settings.setdefault('ssl', {})
        ssl_conf.update({
            'enabled': True,
            'domain': domain,
            'cert_path': os.path.join(DUCKDNS_CERT_DIR, 'duckdns.cert.pem'),
            'key_path': os.path.join(DUCKDNS_CERT_DIR, 'duckdns.key.pem'),
            'cert_text': '',
            'key_text': '',
        })
        if os.environ.get('INVOCATION_ID'):
            # install-cert's detached reloadcmd restarts the panel in ~5s,
            # switching it to HTTPS on its own
            result['restarting'] = True
        else:
            result['restart_required'] = True
    save_data(data)
    logger.info(f"DuckDNS settings applied: enabled={payload.enabled} domain={domain}")
    return result


_duckdns_monitor_started = False


def _duckdns_monitor_loop():
    """Keep the duckdns record pointed at this server's current public IP."""
    while True:
        try:
            d = load_data().get('settings', {}).get('duckdns', {}) or {}
            if d.get('enabled') and d.get('domain') and d.get('token'):
                ok, detail = _duckdns_update_ip(d['domain'], d['token'])
                if not ok:
                    logger.warning(f"duckdns monitor: ip update failed: {detail}")
        except Exception as e:
            logger.warning(f"duckdns monitor loop: {e}")
        time.sleep(DUCKDNS_UPDATE_INTERVAL)


def _start_duckdns_monitor():
    global _duckdns_monitor_started
    if _duckdns_monitor_started:
        return
    _duckdns_monitor_started = True
    threading.Thread(target=_duckdns_monitor_loop, daemon=True,
                     name='duckdns-monitor').start()
    logger.info(f"DuckDNS monitor started (every {DUCKDNS_UPDATE_INTERVAL}s)")


@app.post('/api/settings/telegram/toggle', tags=["Settings"])
async def api_telegram_toggle(request: Request):
    """Quick enable/disable of the bot without a full settings save."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    tg_cfg = data.get('settings', {}).get('telegram', {})
    token = tg_cfg.get('token', '')
    if not token:
        return JSONResponse({'error': 'Telegram token not set in settings'}, status_code=400)

    if tg_bot.is_running():
        await tg_bot.stop_bot()
        tg_cfg['enabled'] = False
        data['settings']['telegram'] = tg_cfg
        save_data(data)
        return {'status': 'stopped', 'bot_running': False}
    else:
        tg_bot.launch_bot(token, load_data, generate_vpn_link, save_data, self_service_svc=self_service_connections)
        tg_cfg['enabled'] = True
        data['settings']['telegram'] = tg_cfg
        save_data(data)
        return {'status': 'started', 'bot_running': True}

@app.post('/api/settings/sync_now', tags=["Settings"])
async def api_sync_now(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    count, msg = await sync_users_with_remnawave(data)
    return {'status': 'success', 'count': count, 'message': msg}


@app.post('/api/settings/sync_delete', tags=["Settings"])
async def api_sync_delete(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    to_delete_ids = [u['id'] for u in data['users'] if u.get('remnawave_uuid')]
    guard = _traffic_removal_guard(data, user_ids=set(to_delete_ids))
    if guard is not None:
        return guard
    if to_delete_ids:
        await perform_mass_operations(delete_uids=to_delete_ids)
    return {'status': 'success', 'count': len(to_delete_ids)}


@app.get('/api/servers/{server_id}/{protocol}/clients', tags=["Connections"])
def api_get_server_clients(request: Request, server_id: int, protocol: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        clients = _manager_call(manager, 'get_clients', protocol)
        ssh.disconnect()
        
        # Filter: only show clients that are not assigned to anyone in the panel
        assigned_ids = {c['client_id'] for c in data.get('user_connections', []) if c['server_id'] == server_id and c['protocol'] == protocol}
        
        filtered = []
        for c in clients:
            if c['clientId'] not in assigned_ids:
                filtered.append({
                    'id': c['clientId'],
                    'name': c.get('userData', {}).get('clientName', 'Unnamed')
                })
        
        return {'clients': filtered}
    except Exception as e:
        logger.exception("Error getting server clients")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/settings/tokens', tags=["API Tokens"])
def api_list_tokens(request: Request):
    """List metadata for every API token. The raw token value is never
    returned by this endpoint — only its prefix and timestamps are visible
    after creation, by design."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    users_by_id = {u['id']: u for u in data.get('users', [])}
    tokens = []
    for t in data.get('api_tokens', []):
        owner = users_by_id.get(t.get('user_id'))
        tokens.append({
            'id': t.get('id'),
            'name': t.get('name', ''),
            'token_prefix': t.get('token_prefix', ''),
            'created_at': t.get('created_at'),
            'last_used_at': t.get('last_used_at'),
            'owner': owner['username'] if owner else None,
            'owner_id': t.get('user_id'),
        })
    return {'tokens': tokens}


@app.post('/api/settings/tokens', tags=["API Tokens"])
async def api_create_token(request: Request, req: CreateApiTokenRequest):
    """Issue a new bearer token. The full token value is returned **once** in
    the response and never persisted in plaintext — only its SHA-256 hash is
    stored, so a leaked data.json file alone cannot be used to authenticate.
    Save the value at creation time; if it's lost the token must be recreated.
    """
    cur = _check_admin(request)
    if not cur:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    name = (req.name or '').strip()
    if not name:
        return JSONResponse({'error': 'Token name is required'}, status_code=400)

    raw = _generate_api_token()
    token_id = str(uuid.uuid4())
    # Show enough of the token in the UI to identify it later, but not enough
    # to reconstruct it: the prefix + first 4 chars of the secret part.
    token_prefix = raw[:len(API_TOKEN_PREFIX) + 4]

    entry = {
        'id': token_id,
        'name': name,
        'token_hash': _hash_api_token(raw),
        'token_prefix': token_prefix,
        'user_id': cur['id'],
        'created_at': datetime.now().isoformat(),
        'last_used_at': None,
    }
    async with DATA_LOCK:
        data = load_data()
        data.setdefault('api_tokens', []).append(entry)
        save_data(data)

    # `token` is returned only here — subsequent reads will not see it.
    return {
        'status': 'success',
        'id': token_id,
        'name': name,
        'token': raw,
        'token_prefix': token_prefix,
        'created_at': entry['created_at'],
    }


@app.delete('/api/settings/tokens/{token_id}', tags=["API Tokens"])
async def api_revoke_token(request: Request, token_id: str):
    """Permanently revoke a token. The associated bearer value can never be
    used again, even if the same name is reissued — every token has its own hash."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    async with DATA_LOCK:
        data = load_data()
        before = len(data.get('api_tokens', []))
        data['api_tokens'] = [t for t in data.get('api_tokens', []) if t.get('id') != token_id]
        if len(data['api_tokens']) == before:
            return JSONResponse({'error': 'Token not found'}, status_code=404)
        save_data(data)
    return {'status': 'success'}


def _backup_admin(request):
    """Panel backups contain secrets and can inject accounts/inventory.

    Keep backup download/restore admin-only without changing the wider
    admin/support policy used by the rest of the panel.
    """
    actor = _check_admin(request)
    if not actor:
        return None
    if isinstance(actor, dict) and actor.get('role') != 'admin':
        return None
    return actor


@app.get('/api/settings/backup/download', tags=["Settings"])
def api_backup_download(request: Request):
    if not _backup_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not os.path.exists(DATA_FILE):
        return JSONResponse({'error': 'Data file not found'}, status_code=404)
    return FileResponse(DATA_FILE, media_type='application/json', filename='data.json')


class PrivateBackupResponse(StreamingResponse):
    def __init__(self, job):
        self.job = job
        job.file.seek(0, os.SEEK_END)
        size = job.file.tell()
        job.file.seek(0)
        name = 'amnezia-panel-backup-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '.zip'
        super().__init__(job.chunks(), media_type='application/zip', headers={
            **PRIVATE_HEADERS, 'Content-Disposition': 'attachment; filename="' + name + '"',
            'Content-Length': str(size)})

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.job.close()


@app.post('/api/settings/backup/archive', tags=['Settings'])
async def api_backup_archive(request: Request):
    # Unlike the legacy JSON endpoint, a complete archive is admin-only.
    if not _ssh_trust_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403, headers=PRIVATE_HEADERS)
    bearer = not get_current_user(request) and request.headers.get('authorization', '').lower().startswith('bearer ')
    expected = request.session.get('backup_csrf', '')
    if not bearer and (not expected or not secrets.compare_digest(expected.encode(), request.headers.get('x-backup-csrf', '').encode())):
        return JSONResponse({'error': 'CSRF check failed'}, status_code=403, headers=PRIVATE_HEADERS)
    if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        return JSONResponse({'error': 'JSON request required'}, status_code=415, headers=PRIVATE_HEADERS)
    job = ArchiveJob()
    try:
        # Bounded queue admission. No DATA_LOCK is held over an SSH operation.
        async with peer_lifecycle_lock.snapshot_interlock():
            async with DATA_LOCK:
                if not _ssh_trust_admin(request):
                    return JSONResponse({'error': 'Forbidden'}, status_code=403, headers=PRIVATE_HEADERS)
                await _finish_locked_worker(lambda: job.create(
                    DATA_FILE, ssh_trust.trust_path(), CURRENT_VERSION,
                    journal_lock=peer_creates.journal.lock, trust_lock=ssh_trust.LOCK,
                    system_trust=os.path.expanduser('~/.ssh/known_hosts')))
        return PrivateBackupResponse(job)
    except peer_lifecycle_lock.PeerLifecycleBusy:
        job.close()
        return JSONResponse({'error': 'State is busy; retry after pending operations finish.',
                             'code': 'panel_backup_busy'}, status_code=503, headers=PRIVATE_HEADERS)
    except asyncio.CancelledError:
        job.close()
        raise
    except Exception:
        job.close()
        logger.warning('Complete panel backup unavailable; inspect private storage permissions/state')
        return JSONResponse({'error': 'Complete backup could not be created. No partial archive was returned.',
                             'code': 'panel_backup_unavailable'}, status_code=503, headers=PRIVATE_HEADERS)


@app.post('/api/settings/backup/restore', tags=["Settings"])
@serialize_peer_lifecycle
async def api_backup_restore(request: Request, file: UploadFile = File(...),
                             operation_id: Optional[str] = Form(None)):
    backup_actor = _backup_admin(request)
    if not backup_actor:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        # Limit the in-memory JSON read; enforce request-body limits at the
        # reverse proxy too, since multipart parsing happens before this handler.
        max_backup_bytes = 32 * 1024 * 1024
        content = await file.read(max_backup_bytes + 1)
        if len(content) > max_backup_bytes:
            return JSONResponse({'error': 'Backup exceeds the 32 MiB limit'}, status_code=413)
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)
        
        try:
            backup_data = validate_backup(content)
        except (json.JSONDecodeError, UnicodeDecodeError, RecoveryError):
            return JSONResponse({'error': 'Invalid JSON format'}, status_code=400)

        # Basic structure validation
        if not isinstance(backup_data, dict):
            return JSONResponse({'error': 'Invalid structure: expected a JSON object'}, status_code=400)
        required_keys = ['servers', 'users']
        missing = [k for k in required_keys if k not in backup_data]
        if missing:
            return JSONResponse({'error': f'Invalid structure. Missing keys: {", ".join(missing)}'}, status_code=400)

        # Ensure types are correct
        if not isinstance(backup_data['servers'], list) or not isinstance(backup_data['users'], list):
            return JSONResponse({'error': 'Invalid structure: servers and users must be lists'}, status_code=400)

        # Save the new data; older backups predate server uids, mint them now
        # so the file on disk is complete without waiting for the next restart.
        backfill_server_uids(backup_data['servers'])
        async with DATA_LOCK:
            # Even identical-looking old backups can rewind traffic baselines.
            current = load_data()
            # Bearer-admin restores have no session, so the resolved token
            # owner is the audit actor; session restores keep the same id.
            actor = str(backup_actor.get('id') if isinstance(backup_actor, dict)
                        else get_current_user(request)['id'])
            store = RecoveryStore(DATA_FILE)
            op = operation_id if isinstance(operation_id, str) else secrets.token_hex(16)
            intent = recovery_digest({'backup_sha256': hashlib.sha256(content).hexdigest()})
            replay = store.replay(op, actor, 'ordinary_restore', intent)
            if replay:
                return replay
            from peer_recovery import prepare_online_restore
            try:
                backup_data = prepare_online_restore(current, backup_data)
            except RecoveryError:
                return JSONResponse({
                    'error': 'Online restore requires unchanged servers, connections and user policy; current traffic accounting is retained. Use the offline administrator disaster-recovery workflow for incompatible backups.',
                    'code': 'traffic_finalization_required',
                    'recovery': 'scripts/panel_recovery.py'}, status_code=409)
            with STATE_FILE_LOCK:
                check_create_journal(DATA_FILE, replacement=backup_data)
                before = pathlib_read_data_bytes() if os.path.exists(DATA_FILE) else b''
                result = store.commit(op, actor, 'ordinary_restore', intent, before, backup_data)
        
        # Full disaster recovery is deliberately separate and offline; see
        # scripts/panel_recovery.py. Never use a force flag on this endpoint.
        return result if isinstance(operation_id, str) else {'status': 'success'}
    except Exception as e:
        logger.exception("Error during restore")
        return JSONResponse({'error': str(e)}, status_code=500)


class OrphanRecoveryRequest(BaseModel):
    operation_id: str
    connection_id: str
    expected_digest: str
    expected_peer_digest: str
    mode: str
    target_user_id: Optional[str] = None
    confirmation: str


@app.get('/api/recovery/status', tags=['Settings'])
def api_recovery_status(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return peer_lifecycle_lock.diagnostics()


def _read_orphan_peers(server, conn, strict_absence=False):
    ssh = get_ssh(server)
    try:
        ssh.connect()
        manager = get_protocol_manager(ssh, conn['protocol'])
        clients = _manager_call(manager, 'get_clients', conn['protocol'])
        if not isinstance(clients, list) or any(not isinstance(c, dict) or not isinstance(c.get('clientId'), str) for c in clients):
            raise RecoveryError('incomplete_peer_state')
        peers = [c for c in clients if c['clientId'] == conn['client_id']]
        if len(peers) > 1:
            raise RecoveryError('peer_identity_ambiguous')
        if strict_absence:
            verify_awg_peer_absent(ssh, conn['protocol'], conn['client_id'])
        return peers
    finally:
        ssh.disconnect()


@app.get('/api/recovery/orphans/{connection_id}', tags=['Settings'])
def api_orphan_recovery_preview(request: Request, connection_id: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        conn, server, scope = orphan_scope(data, connection_id)
        peers = _read_orphan_peers(server, conn)
        return {'scope': scope, 'expected_digest': recovery_digest(data),
                'expected_peer_digest': recovery_digest(peers),
                'peer_status': 'present' if peers else 'absence_not_yet_verified',
                'last_observed_bytes': conn.get('last_bytes'),
                'counters_verified_final': False,
                'warning': 'Restore ownership first. Emergency archival requires a verified absent peer; available counters are NOT a final receipt.'}
    except RecoveryError as error:
        return JSONResponse({'error': str(error)}, status_code=409)


@app.post('/api/recovery/orphans', tags=['Settings'])
@serialize_peer_lifecycle
async def api_orphan_recovery(request: Request, req: OrphanRecoveryRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    # A cross-origin browser must not turn confirmation strings into a CSRF bypass.
    origin = request.headers.get('origin')
    if origin and origin.rstrip('/') != str(request.base_url).rstrip('/'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        actor = str(get_current_user(request)['id'])
        phrases = {'repair': 'RESTORE OWNERSHIP; USAGE IS UNVERIFIED',
                   'archive_absent': 'ARCHIVE ABSENT PEER; FINAL USAGE IS UNKNOWN'}
        if req.mode not in phrases or req.confirmation != phrases[req.mode]:
            raise RecoveryError('explicit_confirmation_required')
        intent = recovery_digest(req.model_dump())
        store = RecoveryStore(DATA_FILE)
        async with DATA_LOCK:
            with STATE_FILE_LOCK:
                replay = store.replay(req.operation_id, actor, req.mode, intent)
                if replay:
                    return replay
                data = load_data()
                if recovery_digest(data) != req.expected_digest:
                    raise RecoveryError('recovery_state_changed')
                conn, server, scope = orphan_scope(data, req.connection_id)
                check_create_journal(DATA_FILE, scope=scope)
                if req.mode == 'repair':
                    require_repair_target(data, req.target_user_id)
        # Probe the exact physical protocol instance; no keys/config are returned
        # to the caller and no DATA_LOCK is held over SSH.
        peers = await asyncio.to_thread(_read_orphan_peers, server, conn, req.mode == 'archive_absent')
        if recovery_digest(peers) != req.expected_peer_digest:
            raise RecoveryError('peer_state_changed')
        if req.mode == 'repair' and not peers:
            raise RecoveryError('peer_state_unknown')
        if req.mode == 'archive_absent' and peers:
            raise RecoveryError('peer_still_present_restore_ownership_instead')
        async with DATA_LOCK:
            with STATE_FILE_LOCK:
                current = load_data()
                if recovery_digest(current) != req.expected_digest:
                    raise RecoveryError('recovery_state_changed')
                latest, latest_server, latest_scope = orphan_scope(current, req.connection_id)
                if latest_scope != scope:
                    raise RecoveryError('peer_identity_changed')
                before = pathlib_read_data_bytes()
                # Include the complete original row and last live observation in
                # the protected snapshot/tombstone, never the public audit summary.
                observed = (peers[0].get('userData') or {}) if peers else {}
                counters = {k: observed[k] for k in ('dataReceivedBytes', 'dataSentBytes') if type(observed.get(k)) is int and observed[k] >= 0}
                evidence = {'operation_id': req.operation_id, 'scope': scope,
                            'connection': dict(latest), 'observed_counters': counters,
                            'counters_verified_final': False}
                current.setdefault('accounting_recoveries', []).append(evidence)
                if req.mode == 'repair':
                    latest['user_id'] = req.target_user_id
                    latest['accounting_recovery_id'] = req.operation_id
                else:
                    current['user_connections'] = [c for c in current['user_connections'] if c['id'] != req.connection_id]
                return store.commit(req.operation_id, actor, req.mode, intent, before, current)
    except RecoveryError as error:
        return JSONResponse({'error': str(error), 'code': 'recovery_not_completed'}, status_code=409)
    except Exception:
        logger.error('Orphan recovery failed; inspect owner-only recovery journal')
        return JSONResponse({'error': 'Recovery did not complete. Retry the same operation ID.',
                             'code': 'recovery_not_completed'}, status_code=503)


def pathlib_read_data_bytes():
    # Kept separate so failure injection can prove there is no destructive write.
    with open(DATA_FILE, 'rb') as source:
        return source.read()


if __name__ == '__main__':
    data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {})
    
    cert_file = ssl_conf.get('cert_path')
    key_file = ssl_conf.get('key_path')
    
    # If text is provided, create temporary files
    temp_dir = os.path.join(os.getcwd(), 'ssl_temp')
    if ssl_conf.get('enabled'):
        if ssl_conf.get('cert_text') or ssl_conf.get('key_text'):
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            if ssl_conf.get('cert_text'):
                cert_file = os.path.join(temp_dir, 'cert.pem')
                with open(cert_file, 'w') as f:
                    f.write(ssl_conf['cert_text'].strip() + '\n')
            
            if ssl_conf.get('key_text'):
                key_file = os.path.join(temp_dir, 'key.pem')
                with open(key_file, 'w') as f:
                    f.write(ssl_conf['key_text'].strip() + '\n')

    uvicorn_kwargs = {
        "app": app,
        "host": "0.0.0.0",
        "port": ssl_conf.get('panel_port', 5000)
    }
    
    if ssl_conf.get('enabled') and cert_file and key_file:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info(f"Starting panel with HTTPS enabled on domain: {ssl_conf.get('domain')} at port {uvicorn_kwargs['port']}")
            uvicorn_kwargs["ssl_certfile"] = cert_file
            uvicorn_kwargs["ssl_keyfile"] = key_file
        else:
            logger.error("SSL certificates not found at specified paths. Starting with HTTP.")

    uvicorn.run(**uvicorn_kwargs)
