import os
import sys
import json
import logging
import base64
import hashlib
import secrets
import uuid
import asyncio
from datetime import datetime
import io
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Request, Query, UploadFile, File
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import uvicorn
import httpx

try:
    from multicolorcaptcha import CaptchaGenerator
except ImportError:
    CaptchaGenerator = None

from managers.ssh_manager import SSHManager
from managers.awg_manager import AWGManager
from managers.xray_manager import XrayManager
from managers.wireguard_manager import WireGuardManager
import telegram_bot as tg_bot

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ordered list of OpenAPI tag groups — the order here drives the section order in /docs and /redoc.
OPENAPI_TAGS = [
    {"name": "System Templates", "description": "HTML pages served to browsers. These return Jinja-rendered templates rather than a JSON contract — they are not part of the public API and are listed here only for completeness."},
    {"name": "Authentication", "description": "Login, captcha, and session lifecycle."},
    {"name": "Servers", "description": "Server inventory, lifecycle and host-level operations (add, edit, delete, ping, reorder, reboot, clear, stats, status check)."},
    {"name": "Protocols", "description": "Install, uninstall, container start/stop and raw config editing for the protocols/services on a server (AWG, Xray, WireGuard, Telemt, AmneziaDNS, AdGuard Home, SOCKS5)."},
    {"name": "Connections", "description": "Per-protocol VPN client connections on a server (CRUD plus enable/disable and config retrieval)."},
    {"name": "Users", "description": "Panel user accounts and the connections assigned to them."},
    {"name": "Self-service", "description": "Endpoints called by a regular user for their own data (the /my surface)."},
    {"name": "Sharing", "description": "Public, token-protected configuration sharing for end users — no panel session required."},
    {"name": "Settings", "description": "Panel-wide settings, Telegram bot, Remnawave sync, JSON backup/restore."},
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
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
        with_google_fonts=False,
    )
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)))

# Mount static files & templates
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(__file__)

DATA_FILE = os.path.join(application_path, 'data.json')
CURRENT_VERSION = "v1.4.3"


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
DATA_LOCK = asyncio.Lock()


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
    data.setdefault('settings', {
        'appearance': {
            'title': 'Amnezia',
            'logo': '❤️',
            'subtitle': 'Web Panel'
        },
        'sync': {
            'remnawave_url': '',
            'remnawave_api_key': '',
            'remnawave_sync': False,
            'remnawave_sync_users': False,
            'remnawave_create_conns': False,
            'remnawave_server_id': 0,
            'remnawave_protocol': 'awg'
        }
    })
    return data


def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


async def save_data_async(data):
    """Saves data to file in a thread-safe way."""
    async with DATA_LOCK:
        await asyncio.to_thread(save_data, data)


def get_ssh(server):
    return SSHManager(
        host=server['host'],
        port=server.get('ssh_port', 22),
        username=server['username'],
        password=server.get('password'),
        private_key=server.get('private_key'),
    )


def get_protocol_manager(ssh, protocol: str):
    if protocol == 'xray':
        from managers.xray_manager import XrayManager
        return XrayManager(ssh)
    elif protocol == 'telemt':
        from managers.telemt_manager import TelemtManager
        return TelemtManager(ssh)
    elif protocol == 'dns':
        from managers.dns_manager import DNSManager
        return DNSManager(ssh)
    elif protocol == 'wireguard':
        from managers.wireguard_manager import WireGuardManager
        return WireGuardManager(ssh)
    elif protocol == 'socks5':
        from managers.socks5_manager import Socks5Manager
        return Socks5Manager(ssh)
    elif protocol == 'adguard':
        from managers.adguard_manager import AdguardManager
        return AdguardManager(ssh)
    from managers.awg_manager import AWGManager
    return AWGManager(ssh)


def _manager_call(manager, method, protocol, *args, **kwargs):
    """Unified call: WireGuard manager methods don't take protocol_type argument."""
    fn = getattr(manager, method)
    if isinstance(manager, WireGuardManager):
        return fn(*args, **kwargs)
    return fn(protocol, *args, **kwargs)


def generate_vpn_link(config_text):
    b64 = base64.b64encode(config_text.strip().encode('utf-8')).decode('utf-8')
    return f"vpn://{b64}"


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


async def perform_delete_user(data: dict, user_id: str):
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False
    # Remove user's connections from servers
    user_conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for uc in user_conns:
        try:
            sid = uc['server_id']
            if sid < len(data['servers']):
                server = data['servers'][sid]
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, uc['protocol'])
                _manager_call(manager, 'remove_client', uc['protocol'], uc['client_id'])
                ssh.disconnect()
        except Exception as e:
            logger.warning(f"Failed to remove connection {uc['client_id']} during user delete: {e}")
    data['user_connections'] = [c for c in data.get('user_connections', []) if c['user_id'] != user_id]
    data['users'] = [u for u in data['users'] if u['id'] != user_id]
    return True


async def perform_toggle_user(data: dict, user_id: str, enable: bool) -> bool:
    """Enable or disable a user and propagate the change to all their VPN connections."""
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False

    user['enabled'] = enable

    user_conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for uc in user_conns:
        try:
            sid = uc['server_id']
            if sid >= len(data['servers']):
                continue
            server = data['servers'][sid]
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            manager = get_protocol_manager(ssh, uc['protocol'])
            await asyncio.to_thread(
                _manager_call, manager, 'toggle_client', uc['protocol'], uc['client_id'], enable
            )
            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.warning(f"Failed to toggle connection {uc['client_id']} during user toggle: {e}")

    return True


async def perform_mass_operations(delete_uids: List[str] = None, toggle_uids: List[tuple] = None, create_conns: List[dict] = None):
    """
    Executes multiple SSH operations efficiently.
    Reloads data inside to ensure we don't overwrite other changes.
    """
    data = load_data()
    server_ops = {}

    def get_ops(sid):
        if sid not in server_ops:
            server_ops[sid] = {'delete': [], 'toggle': [], 'create': []}
        return server_ops[sid]

    if delete_uids:
        for uid in delete_uids:
            conns = [c for c in data.get('user_connections', []) if c['user_id'] == uid]
            for c in conns: get_ops(c['server_id'])['delete'].append(c)
    
    if toggle_uids:
        for uid, enabled in toggle_uids:
            conns = [c for c in data.get('user_connections', []) if c['user_id'] == uid]
            for c in conns: get_ops(c['server_id'])['toggle'].append((c, enabled))

    if create_conns:
        for req in create_conns: get_ops(req['server_id'])['create'].append(req)

    async def run_server_ops(srv_id, ops):
        # We re-load data inside to be absolutely sure about current state
        # but for performance we'll use the passed srv_id
        current_data = load_data()
        if srv_id >= len(current_data['servers']): return
        srv = current_data['servers'][srv_id]
        
        try:
            ssh = get_ssh(srv)
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
            
            # 2. Toggles
            for c, enabled in ops['toggle']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'toggle_client', c['protocol'], c['client_id'], enabled)
                # Incremental toggle in data
                async with DATA_LOCK:
                    current_data = load_data()
                    # We also need to update user status if it was a user toggle
                    # Wait, mass ops caller usually handles user enabled status. 
                    # Here we just toggle the actual wireguard peer.
                    save_data(current_data)
            
            # 3. Creates
            for c_req in ops['create']:
                proto_info = srv.get('protocols', {}).get(c_req['protocol'], {})
                port = proto_info.get('port', '55424')
                manager = get_protocol_manager(ssh, c_req['protocol'])
                
                if c_req['protocol'] == 'wireguard':
                    res = await asyncio.to_thread(manager.add_client, c_req['name'], srv['host'])
                else:
                    res = await asyncio.to_thread(_manager_call, manager, 'add_client', c_req['protocol'], c_req['name'], srv['host'], port)
                
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
            current_data['users'] = [u for u in current_data['users'] if u['id'] not in delete_uids]
            current_data['user_connections'] = [c for c in current_data.get('user_connections', []) if c['user_id'] not in delete_uids]
        if toggle_uids:
            for uid, enabled in toggle_uids:
                user = next((u for u in current_data['users'] if u['id'] == uid), None)
                if user: user['enabled'] = enabled
        save_data(current_data)

    return True


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
                            current['users'][idx] = local_u
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
                await perform_mass_operations(toggle_uids=to_toggle, create_conns=to_create_conns)
            
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
            return u
    return None


def tpl(request, template, **kwargs):
    data = load_data()
    lang = request.cookies.get('lang', 'en')
    ctx = {
        'request': request,
        'current_user': get_current_user(request),
        'site_settings': data.get('settings', {}).get('appearance', {}),
        'captcha_settings': data.get('settings', {}).get('captcha', {}),
        'telegram_settings': data.get('settings', {}).get('telegram', {}),
        'bot_running': tg_bot.is_running(),
        'lang': lang,
        '_': lambda text_id: _t(text_id, lang),
        'translations_json': json.dumps(TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))),
        'all_translations_json': json.dumps(TRANSLATIONS)
    }
    ctx.update(kwargs)
    return templates.TemplateResponse(template, ctx)


# ======================== Pydantic Models ========================

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha: Optional[str] = None


class AddServerRequest(BaseModel):
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    password: str = ''
    private_key: str = ''
    name: str = ''


class EditServerRequest(BaseModel):
    name: str = ''
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    # Optional[str] = None lets the client distinguish "leave field as is"
    # (omit / null) from "explicitly clear" (empty string). Both credential
    # fields can be omitted to keep current auth unchanged.
    password: Optional[str] = None
    private_key: Optional[str] = None


class ReorderServersRequest(BaseModel):
    # `order[i]` is the *old* server index now at position `i` in the new layout.
    order: List[int]


class InstallProtocolRequest(BaseModel):
    protocol: str = 'awg'
    port: str = '55424'
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


class Socks5SettingsRequest(BaseModel):
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ProtocolRequest(BaseModel):
    protocol: str = 'awg'


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


class ToggleConnectionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    enable: bool = True


class AddUserRequest(BaseModel):
    username: str
    password: str
    role: str = 'user'
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

class TelegramSettings(BaseModel):
    token: str = ''
    enabled: bool = False




class UpdateUserRequest(BaseModel):
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = None
    expiration_date: Optional[str] = None
    password: Optional[str] = None



class SaveSettingsRequest(BaseModel):
    appearance: AppearanceSettings
    sync: SyncSettings
    captcha: CaptchaSettings
    telegram: TelegramSettings
    ssl: SSLSettings


class ToggleUserRequest(BaseModel):
    enabled: bool


class AddUserConnectionRequest(BaseModel):
    server_id: int
    protocol: str = 'awg'
    name: str = 'VPN Connection'
    client_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class CreateApiTokenRequest(BaseModel):
    name: str


class ShareSetupRequest(BaseModel):
    enabled: bool
    password: Optional[str] = None


class ShareAuthRequest(BaseModel):
    password: str


# ======================== Startup ========================

@app.on_event("startup")
async def startup():
    data = load_data()
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
            logger.info(f"Migrated user {u['username']} to new traffic/sharing fields")
    
    # API tokens collection — initialise lazily on first run.
    if 'api_tokens' not in data:
        data['api_tokens'] = []
        changed = True
        logger.info("Initialised empty api_tokens collection")

    # SSL settings migration
    if 'ssl' not in data.get('settings', {}):
        if 'settings' not in data: data['settings'] = {}
        data['settings']['ssl'] = {
            'enabled': False,
            'domain': '',
            'cert_path': '',
            'key_path': '',
            'cert_text': '',
            'key_text': '',
            'panel_port': 5000
        }
        changed = True
        logger.info("Migrated SSL settings")

    if changed:
        save_data(data)

    # Start periodic background tasks
    asyncio.create_task(periodic_background_tasks())

    # Start Telegram bot if enabled
    tg_cfg = data.get('settings', {}).get('telegram', {})
    if tg_cfg.get('enabled') and tg_cfg.get('token'):
        logger.info("Starting Telegram bot from saved settings...")
        tg_bot.launch_bot(tg_cfg['token'], load_data, generate_vpn_link)


def _scrape_server_traffic(server, sid, my_conns):
    server_updates = []
    try:
        ssh = get_ssh(server)
        ssh.connect()
        for proto in ['awg', 'awg2', 'awg_legacy', 'xray', 'telemt', 'wireguard']:
            if proto in server.get('protocols', {}):
                manager = get_protocol_manager(ssh, proto)
                clients = _manager_call(manager, 'get_clients', proto)
                client_bytes = {}
                for c in clients:
                    rx = c.get('userData', {}).get('dataReceivedBytes', 0)
                    tx = c.get('userData', {}).get('dataSentBytes', 0)
                    client_bytes[c.get('clientId')] = rx + tx
                    
                for uc in my_conns:
                    if uc['protocol'] == proto and uc['client_id'] in client_bytes:
                        curr_bytes = client_bytes[uc['client_id']]
                        last_bytes = uc.get('last_bytes', 0)
                        delta = curr_bytes - last_bytes if curr_bytes >= last_bytes else curr_bytes
                        server_updates.append((uc['id'], delta, curr_bytes))
        ssh.disconnect()
    except Exception as e:
        logger.error(f"Traffic sync err server {sid}: {e}")
    return server_updates


async def periodic_background_tasks():
    """Background task to sync traffic limits and Remnawave every 10 minutes"""
    while True:
        try:
            # We wait before the first sync to let the app settle
            await asyncio.sleep(60) 
            
            # --- 1. TRAFFIC SYNC & LIMITS ---
            logger.info("Starting background traffic sync...")
            data = load_data()
            
            conns_by_server = {}
            for uc in data.get('user_connections', []):
                sid = uc['server_id']
                conns_by_server.setdefault(sid, []).append(uc)
                
            updates = []
            
            for sid, server in enumerate(data.get('servers', [])):
                if sid not in conns_by_server: continue
                
                # Run the blocking SSH traffic scraping in a background thread!
                server_updates = await asyncio.to_thread(_scrape_server_traffic, server, sid, conns_by_server[sid])
                if server_updates:
                    updates.extend(server_updates)

            to_disable_uids = []
            if updates:
                async with DATA_LOCK:
                    curr_data = load_data()
                    users_map = {u['id']: u for u in curr_data.get('users', [])}
                    uc_list = curr_data.get('user_connections', [])
                    uc_map = {uc['id']: uc for uc in uc_list}
                    
                    # Current date/time for reset checking
                    now = datetime.now()
                    
                    for uc_id, delta, curr_bytes in updates:
                        if uc_id in uc_map:
                            uc_map[uc_id]['last_bytes'] = curr_bytes
                            uid = uc_map[uc_id]['user_id']
                            if uid in users_map:
                                u = users_map[uid]
                                # Check if reset is needed BEFORE adding new consumption
                                strategy = u.get('traffic_reset_strategy', 'never')
                                last_reset_iso = u.get('last_reset_at')
                                
                                reset_needed = False
                                if strategy != 'never' and last_reset_iso:
                                    try:
                                        last = datetime.fromisoformat(last_reset_iso)
                                        if strategy == 'daily':
                                            reset_needed = now.date() > last.date()
                                        elif strategy == 'weekly':
                                            reset_needed = now.isocalendar()[1] != last.isocalendar()[1] or now.year != last.year
                                        elif strategy == 'monthly':
                                            reset_needed = now.month != last.month or now.year != last.year
                                    except:
                                        pass
                                
                                if reset_needed:
                                    logger.info(f"Resetting traffic for user {u['username']} (strategy: {strategy})")
                                    u['traffic_used'] = 0
                                    u['last_reset_at'] = now.isoformat()
                                
                                # Update both resettable and total traffic
                                u['traffic_used'] = u.get('traffic_used', 0) + delta
                                u['traffic_total'] = u.get('traffic_total', 0) + delta
                                
                                limit = u.get('traffic_limit', 0)
                                if limit > 0 and u['traffic_used'] >= limit and u.get('enabled', True):
                                    if uid not in to_disable_uids:
                                        to_disable_uids.append(uid)
                                
                                # Check expiration date
                                exp_str = u.get('expiration_date')
                                if exp_str and u.get('enabled', True):
                                    try:
                                        exp_date = datetime.fromisoformat(exp_str)
                                        if now > exp_date:
                                            logger.info(f"Subscription expired for user {u['username']} (expired at {exp_str})")
                                            if uid not in to_disable_uids:
                                                to_disable_uids.append(uid)
                                    except:
                                        pass
                    save_data(curr_data)
                    
            if to_disable_uids:
                logger.info(f"Traffic limit reached, disabling users: {to_disable_uids}")
                await perform_mass_operations(toggle_uids=[(uid, False) for uid in to_disable_uids])

            # --- 2. REMNAWAVE SYNC ---
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
async def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse(url='/', status_code=302)
    return tpl(request, 'login.html')


@app.get("/set_lang/{lang}", tags=["System Templates"])
async def set_lang(lang: str, request: Request):
    ref = request.headers.get("referer", "/")
    response = RedirectResponse(url=ref)
    response.set_cookie(key="lang", value=lang, max_age=31536000)
    return response


@app.get('/logout', tags=["System Templates"])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/login', status_code=302)


@app.get('/', response_class=HTMLResponse, tags=["System Templates"])
async def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] == 'user':
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    return tpl(request, 'index.html', servers=data['servers'])


@app.get('/server/{server_id}', response_class=HTMLResponse, tags=["System Templates"])
async def server_detail(request: Request, server_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    if server_id >= len(data['servers']):
        return RedirectResponse(url='/')
    server = data['servers'][server_id]
    users_list = data.get('users', [])
    return tpl(request, 'server.html', server=server, server_id=server_id, users=users_list)


@app.get('/users', response_class=HTMLResponse, tags=["System Templates"])
async def users_page(request: Request):
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
async def my_connections_page(request: Request):
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
async def api_captcha(request: Request):
    if not CaptchaGenerator:
        return JSONResponse({"error": "multicolorcaptcha is not installed"}, status_code=500)
    
    # 2 is a multiplier for the image resolution size
    generator = CaptchaGenerator(2)
    captcha = generator.gen_captcha_image(difficult_level=2)
    request.session['captcha_answer'] = captcha.characters
    
    img_bytes = io.BytesIO()
    captcha.image.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return StreamingResponse(img_bytes, media_type="image/png")


@app.post('/api/auth/login', tags=["Authentication"])
async def api_login(request: Request, req: LoginRequest):
    data = load_data()
    captcha_settings = data.get('settings', {}).get('captcha', {})
    if captcha_settings.get('enabled') is True:
        answer = request.session.get('captcha_answer')
        lang = request.cookies.get('lang', 'ru')
        if not answer or not req.captcha or answer.lower() != req.captcha.lower():
            request.session.pop('captcha_answer', None)
            return JSONResponse({'error': _t('invalid_captcha', lang)}, status_code=400)
        request.session.pop('captcha_answer', None)

    for u in data.get('users', []):
        if u['username'] == req.username and verify_password(req.password, u['password_hash']):
            lang = request.cookies.get('lang', 'ru')
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


@app.post('/api/servers/add', tags=["Servers"])
async def api_add_server(request: Request, req: AddServerRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        host = req.host.strip()
        username = req.username.strip()
        name = req.name.strip() or host
        if not host or not username:
            return JSONResponse({'error': 'Host and username are required'}, status_code=400)
        if not req.password and not req.private_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)
        try:
            ssh.connect()
            server_info = ssh.test_connection()
            ssh.disconnect()
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {str(e)}'}, status_code=400)

        server = {
            'name': name, 'host': host, 'ssh_port': req.ssh_port,
            'username': username, 'password': req.password,
            'private_key': req.private_key, 'server_info': server_info,
            'protocols': {},
        }
        data = load_data()
        data['servers'].append(server)
        save_data(data)
        return {'status': 'success', 'server_id': len(data['servers']) - 1, 'server_info': server_info}
    except Exception as e:
        logger.exception("Error adding server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/edit', tags=["Servers"])
async def api_edit_server(request: Request, server_id: int, req: EditServerRequest):
    """Update connection details for an existing server entry. Verifies the new
    credentials by SSH-connecting before persisting, so a typo can't lock us out.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]

        new_host = (req.host or '').strip() or server['host']
        new_user = (req.username or '').strip() or server['username']
        new_port = int(req.ssh_port or server.get('ssh_port', 22))
        new_name = (req.name or '').strip() or server.get('name') or new_host

        # Credential resolution: a non-empty value in either field switches to
        # that auth method (and clears the other). Both omitted => keep current.
        if req.private_key:
            new_pass, new_key = '', req.private_key
        elif req.password:
            new_pass, new_key = req.password, ''
        else:
            new_pass = server.get('password', '')
            new_key = server.get('private_key', '')

        if not new_pass and not new_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        # Verify the new connection details before committing the change.
        ssh = SSHManager(new_host, new_port, new_user, new_pass, new_key)
        try:
            ssh.connect()
            server_info = ssh.test_connection()
            ssh.disconnect()
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {e}'}, status_code=400)

        server['name'] = new_name
        server['host'] = new_host
        server['ssh_port'] = new_port
        server['username'] = new_user
        server['password'] = new_pass
        server['private_key'] = new_key
        server['server_info'] = server_info
        save_data(data)
        return {'status': 'success', 'server_info': server_info}
    except Exception as e:
        logger.exception("Error editing server")
        return JSONResponse({'error': str(e)}, status_code=500)


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
        return {'alive': True, 'ms': ms}
    except asyncio.TimeoutError:
        return {'alive': False, 'error': 'timeout', 'ms': None}
    except Exception as e:
        return {'alive': False, 'error': str(e), 'ms': None}


@app.post('/api/servers/reorder', tags=["Servers"])
async def api_reorder_servers(request: Request, req: ReorderServersRequest):
    """Persist a user-defined ordering of servers. Also remaps `server_id`
    references in user_connections so existing assignments survive the move.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    async with DATA_LOCK:
        data = load_data()
        n = len(data['servers'])
        order = req.order or []
        if len(order) != n or sorted(order) != list(range(n)):
            return JSONResponse(
                {'error': f'Order must be a permutation of indices 0..{n - 1}'},
                status_code=400,
            )
        new_servers = [data['servers'][i] for i in order]
        # Map old index -> new index for user_connections remap
        remap = {old: new for new, old in enumerate(order)}
        for c in data.get('user_connections', []):
            old_id = c.get('server_id')
            if isinstance(old_id, int) and old_id in remap:
                c['server_id'] = remap[old_id]
        # Sync settings.sync.remnawave_server_id if it points at a moved server
        sync_cfg = data.get('settings', {}).get('sync', {})
        rsid = sync_cfg.get('remnawave_server_id')
        if isinstance(rsid, int) and rsid in remap:
            sync_cfg['remnawave_server_id'] = remap[rsid]
        data['servers'] = new_servers
        save_data(data)
    return {'status': 'success'}


@app.post('/api/servers/{server_id}/delete', tags=["Servers"])
async def api_delete_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        data['servers'].pop(server_id)
        # Clean up connections for this server
        data['user_connections'] = [c for c in data.get('user_connections', []) if c.get('server_id') != server_id]
        # Adjust server_ids for connections pointing to higher indices
        for c in data.get('user_connections', []):
            if c.get('server_id', 0) > server_id:
                c['server_id'] -= 1
        save_data(data)
        return {'status': 'success'}
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/reboot', tags=["Servers"])
async def api_reboot_server(request: Request, server_id: int):
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
async def api_clear_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        # Match every Amnezia container by name prefix (catches awg/awg2/awg-legacy,
        # wireguard, xray/ssxray, openvpn, dns, and any future amnezia-* protocol)
        # plus the telemt container which doesn't share that prefix.
        # Using a single script avoids one SSH round-trip per command.
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
        ssh.run_sudo_script(cleanup_script, timeout=120)

        server['protocols'] = {}
        save_data(data)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error clearing server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/stats', tags=["Servers"])
async def api_server_stats(request: Request, server_id: int):
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
        ssh.disconnect()
        return stats
    except Exception as e:
        logger.exception("Error getting server stats")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/check', tags=["Servers"])
async def api_check_server(request: Request, server_id: int):
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

        import concurrent.futures

        def check_proto(proto):
            try:
                p_manager = get_protocol_manager(ssh, proto)
                result = _manager_call(p_manager, 'get_server_status', proto)
                db_proto = server.get('protocols', {}).get(proto, {})
                if not result.get('port') and db_proto.get('port'):
                    result['port'] = db_proto['port']
                return proto, result, None
            except Exception as e:
                return proto, None, str(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
            futures = [executor.submit(check_proto, p) for p in ['awg', 'awg2', 'awg_legacy', 'xray', 'telemt', 'dns', 'wireguard', 'socks5', 'adguard']]
            for future in concurrent.futures.as_completed(futures):
                proto, result, err = future.result()
                if err:
                    status['protocols'][proto] = {'error': err}
                else:
                    status['protocols'][proto] = result
                    if result.get('container_exists'):
                        if proto not in server['protocols']:
                            server['protocols'][proto] = {
                                'installed': True,
                                'port': result.get('port', '55424'),
                                'awg_params': result.get('awg_params', {})
                            }
                            changed = True
                    else:
                        if proto in server['protocols']:
                            del server['protocols'][proto]
                            changed = True
                
        if changed:
            save_data(data)
            
        ssh.disconnect()
        return status
    except Exception as e:
        logger.exception("Error checking server")
        return JSONResponse({'error': str(e), 'connection': 'failed'}, status_code=500)


@app.post('/api/servers/{server_id}/install', tags=["Protocols"])
async def api_install_protocol(request: Request, server_id: int, req: InstallProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if req.protocol not in ['awg', 'awg2', 'awg_legacy', 'xray', 'telemt', 'dns', 'wireguard', 'socks5', 'adguard']:
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)

        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)

        # Pass parameters to installer
        if req.protocol == 'telemt':
            result = manager.install_protocol(
                protocol_type=req.protocol,
                port=req.port,
                tls_emulation=req.tls_emulation if req.tls_emulation is not None else True,
                tls_domain=req.tls_domain,
                max_connections=req.max_connections if req.max_connections is not None else 0
            )
        elif req.protocol == 'xray':
            result = manager.install_protocol(port=req.port)
        elif req.protocol == 'wireguard':
            result = manager.install_protocol(port=req.port)
        elif req.protocol == 'socks5':
            result = manager.install_protocol(
                protocol_type='socks5',
                port=req.port,
                username=req.socks5_username,
                password=req.socks5_password,
            )
        elif req.protocol == 'adguard':
            result = manager.install_protocol(
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
        else:
            result = manager.install_protocol(req.protocol, port=req.port)

        proto_record = {
            'installed': True,
            'port': req.port,
            'awg_params': result.get('awg_params', {}),
        }
        if req.protocol == 'adguard':
            proto_record['mode'] = result.get('mode')
            proto_record['internal_ip'] = result.get('internal_ip')
            proto_record['web_port'] = result.get('web_port')
            proto_record['expose_web'] = result.get('expose_web')
        server['protocols'][req.protocol] = proto_record
        save_data(data)
        ssh.disconnect()
        return result
    except Exception as e:
        logger.exception("Error installing protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_get_credentials(request: Request, server_id: int):
    """Return the current SOCKS5 port/username/password for the panel UI."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, 'socks5')
        creds = manager.get_credentials()
        ssh.disconnect()
        return {'status': 'success', **creds}
    except Exception as e:
        logger.exception("Error reading SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_update_credentials(request: Request, server_id: int, req: Socks5SettingsRequest):
    """Apply new SOCKS5 connection settings — regenerates the 3proxy config and
    reconciles the container (recreating it if the listening port changed)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, 'socks5')
        result = manager.update_credentials(
            port=req.port, username=req.username, password=req.password
        )
        ssh.disconnect()
        # Persist the new port in the saved server record so the dashboard
        # shows the right value on next check without an SSH round-trip.
        if result.get('status') == 'success' and result.get('port'):
            srv_proto = server.setdefault('protocols', {}).setdefault('socks5', {})
            srv_proto['port'] = str(result['port'])
            srv_proto['installed'] = True
            save_data(data)
        return result
    except Exception as e:
        logger.exception("Error updating SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/uninstall', tags=["Protocols"])
async def api_uninstall_protocol(request: Request, server_id: int, req: ProtocolRequest):
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
        if req.protocol in ('xray', 'wireguard'):
            manager.remove_container()
        else:
            manager.remove_container(req.protocol)
        if req.protocol in server.get('protocols', {}):
            del server['protocols'][req.protocol]
            save_data(data)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error uninstalling protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


CONTAINER_NAMES = {
    'awg': 'amnezia-awg',
    'awg2': 'amnezia-awg2',
    'awg_legacy': 'amnezia-awg-legacy',
    'xray': 'amnezia-xray',
    'telemt': 'telemt',
    'dns': 'amnezia-dns',
    'wireguard': 'amnezia-wireguard',
    'socks5': 'amnezia-socks5proxy',
    'adguard': 'amnezia-adguard',
}


@app.post('/api/servers/{server_id}/container/toggle', tags=["Protocols"])
async def api_container_toggle(request: Request, server_id: int, req: ProtocolRequest):
    """Start or stop a protocol Docker container."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = CONTAINER_NAMES.get(req.protocol)
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
        if is_running:
            ssh.run_sudo_command(f"docker stop {container}")
            action = 'stopped'
        else:
            ssh.run_sudo_command(f"docker start {container}")
            action = 'started'
        ssh.disconnect()
        return {'status': 'success', 'action': action, 'container': container}
    except Exception as e:
        logger.exception("Error toggling container")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config', tags=["Protocols"])
async def api_server_config(request: Request, server_id: int, req: ProtocolRequest):
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
        if req.protocol == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh)
            data_json = mgr._get_server_json()
            import json as _json
            config = _json.dumps(data_json, indent=2, ensure_ascii=False) if data_json else ''
        elif req.protocol == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh)
            config = mgr._get_server_config()
        elif req.protocol == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            config = mgr._get_server_config()
        else:
            mgr = AWGManager(ssh)
            config = mgr._get_server_config(req.protocol)
        ssh.disconnect()
        return {'config': config}
    except Exception as e:
        logger.exception("Error getting server config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config/save', tags=["Protocols"])
async def api_server_config_save(request: Request, server_id: int, req: ServerConfigSaveRequest):
    """Save the raw server-side WireGuard/Xray configuration and apply changes."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        if req.protocol == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh)
            import json as _json
            try:
                data_json = _json.loads(req.config)
            except Exception as e:
                ssh.disconnect()
                return JSONResponse({'error': f'Invalid JSON format: {str(e)}'}, status_code=400)
            mgr._save_server_json(data_json)
        elif req.protocol == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh)
            mgr.save_server_config(req.protocol, req.config)
        elif req.protocol == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            mgr.save_server_config(req.config)
        else:
            mgr = AWGManager(ssh)
            mgr.save_server_config(req.protocol, req.config)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving server config")
        return JSONResponse({'error': str(e)}, status_code=500)




@app.get('/api/servers/{server_id}/connections', tags=["Connections"])
async def api_get_connections(request: Request, server_id: int, protocol: str = Query(default='awg')):
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
async def api_add_connection(request: Request, server_id: int, req: AddConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        
        if req.protocol == 'telemt':
            result = manager.add_client(
                req.protocol, req.name, server['host'], port,
                telemt_quota=req.telemt_quota,
                telemt_max_ips=req.telemt_max_ips,
                telemt_expiry=req.telemt_expiry,
                secret=req.telemt_secret,
                user_ad_tag=req.telemt_ad_tag,
                max_tcp_conns=req.telemt_max_conns
            )
        elif req.protocol == 'wireguard':
            result = manager.add_client(req.name, server['host'])
        else:
            result = manager.add_client(req.protocol, req.name, server['host'], port)
        ssh.disconnect()

        if result.get('config'):
            result['vpn_link'] = generate_vpn_link(result['config'])

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
async def api_remove_connection(request: Request, server_id: int, req: ConnectionActionRequest):
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
        _manager_call(manager, 'remove_client', req.protocol, req.client_id)
        ssh.disconnect()
        # Remove from user_connections
        data['user_connections'] = [
            c for c in data.get('user_connections', [])
            if not (c.get('client_id') == req.client_id and c.get('server_id') == server_id)
        ]
        save_data(data)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error removing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/edit', tags=["Connections"])
async def api_edit_connection(request: Request, server_id: int, req: EditConnectionRequest):
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
        if req.protocol == 'telemt':
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


@app.post('/api/servers/{server_id}/connections/config', tags=["Connections"])
async def api_get_connection_config(request: Request, server_id: int, req: ConnectionActionRequest):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        # Users can only view their own connections
        if user['role'] == 'user':
            owned = any(
                c for c in data.get('user_connections', [])
                if c.get('client_id') == req.client_id and c.get('server_id') == server_id and c.get('user_id') == user['id']
            )
            if not owned:
                return JSONResponse({'error': 'Forbidden'}, status_code=403)
        server = data['servers'][server_id]
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        if req.protocol == 'wireguard':
            config = manager.get_client_config(req.client_id, server['host'])
        else:
            config = manager.get_client_config(req.protocol, req.client_id, server['host'], port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/toggle', tags=["Connections"])
async def api_toggle_connection(request: Request, server_id: int, req: ToggleConnectionRequest):
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
async def api_list_users(request: Request, search: str = '', page: int = 1, size: int = 10):
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
async def api_add_user(request: Request, req: AddUserRequest):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        lang = request.cookies.get('lang', 'ru')
        # Check duplicate
        if any(u['username'] == req.username for u in data.get('users', [])):
            return JSONResponse({'error': _t('user_exists', lang)}, status_code=400)
        if req.role not in ('admin', 'support', 'user'):
            return JSONResponse({'error': 'Invalid role'}, status_code=400)
        new_user = {
            'id': str(uuid.uuid4()),
            'username': req.username,
            'password_hash': hash_password(req.password),
            'role': req.role,
            'telegramId': req.telegramId,
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
                conn_name = req.connection_name or f"{req.username}_vpn"
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, req.protocol)
                if req.protocol == 'telemt':
                    conn_result = manager.add_client(
                        req.protocol, conn_name, server['host'], port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns
                    )
                else:
                    conn_result = manager.add_client(req.protocol, conn_name, server['host'], port)
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
                        result['vpn_link'] = generate_vpn_link(conn_result['config'])
        return result
    except Exception as e:
        logger.exception("Error adding user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/update', tags=["Users"])
async def api_update_user(request: Request, user_id: str, req: UpdateUserRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
            
        if req.telegramId is not None: user['telegramId'] = req.telegramId
        if req.email is not None: user['email'] = req.email
        if req.description is not None: user['description'] = req.description
        if req.traffic_limit is not None: 
            new_limit = int(req.traffic_limit * 1024**3)
            user['traffic_limit'] = new_limit
        
        if req.traffic_reset_strategy is not None:
            user['traffic_reset_strategy'] = req.traffic_reset_strategy
            user['last_reset_at'] = datetime.now().isoformat()
            
        if req.expiration_date is not None:
            user['expiration_date'] = req.expiration_date or None

        if req.password:
            user['password_hash'] = hash_password(req.password)
            
        save_data(data)
        
        # Auto re-enable if traffic limit increased beyond usage
        if req.traffic_limit is not None:
            if new_limit > 0 and user.get('traffic_used', 0) < new_limit and not user.get('enabled', True):
                await perform_toggle_user(data, user_id, True)
                save_data(data)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error updating user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/delete', tags=["Users"])
async def api_delete_user(request: Request, user_id: str):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'ru')
    if cur['id'] == user_id:
        return JSONResponse({'error': _t('cannot_delete_self', lang)}, status_code=400)
    try:
        data = load_data()
        success = await perform_delete_user(data, user_id)
        if not success:
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
        data = load_data()
        success = await perform_toggle_user(data, user_id, req.enabled)
        if not success:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        save_data(data)
        return {'status': 'success', 'enabled': req.enabled}
    except Exception as e:
        logger.exception("Error toggling user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/connections/add', tags=["Users"])
async def api_add_user_connection(request: Request, user_id: str, req: AddUserConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        if req.server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][req.server_id]
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        manager = get_protocol_manager(ssh, req.protocol)
        
        if req.client_id:
            # Use existing client
            target_client_id = req.client_id
            # Retrieve config for existing client
            config = await asyncio.to_thread(manager.get_client_config, req.protocol, req.client_id, server['host'], port)
            result = {'client_id': target_client_id, 'config': config}
        else:
            # Create new client
            if req.protocol == 'telemt':
                result = await asyncio.to_thread(
                    manager.add_client, req.protocol, req.name, server['host'], port,
                    telemt_quota=req.telemt_quota,
                    telemt_max_ips=req.telemt_max_ips,
                    telemt_expiry=req.telemt_expiry,
                    secret=req.telemt_secret,
                    user_ad_tag=req.telemt_ad_tag,
                    max_tcp_conns=req.telemt_max_conns
                )
            else:
                result = await asyncio.to_thread(manager.add_client, req.protocol, req.name, server['host'], port)
        
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
            resp['vpn_link'] = generate_vpn_link(result['config'])
        return resp
    except Exception as e:
        logger.exception("Error adding user connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/users/{user_id}/connections', tags=["Users"])
async def api_get_user_connections(request: Request, user_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    # Users can only see their own, admin/support can see all
    if user['role'] == 'user' and user['id'] != user_id:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for c in conns:
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', '')
    return {'connections': conns}


# ======================== MY CONNECTIONS API (for user role) ========================

@app.get('/api/my/connections', tags=["Self-service"])
async def api_my_connections(request: Request):
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
    return {'connections': conns}


@app.post('/api/users/{user_id}/share/setup', tags=["Users"])
async def api_user_share_setup(user_id: str, req: ShareSetupRequest, request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return JSONResponse({'error': 'User not found'}, status_code=404)
    
    user['share_enabled'] = req.enabled
    if not user.get('share_token'):
        user['share_token'] = secrets.token_urlsafe(16)
    if req.password:
        user['share_password_hash'] = hash_password(req.password)
    elif req.password == "": # Clear
        user['share_password_hash'] = None
        
    save_data(data)
    return {'status': 'success', 'share_token': user.get('share_token')}


@app.get('/share/{token}', response_class=HTMLResponse, tags=["System Templates"])
async def share_page(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        lang = request.cookies.get('lang', 'ru')
        return HTMLResponse(f"<h1>{_t('share_not_found', lang)}</h1><p>{_t('share_not_found_desc', lang)}</p>", status_code=404)
    
    auth_session_key = f'share_auth_{token}'
    need_password = bool(user.get('share_password_hash')) and not request.session.get(auth_session_key)
    
    return tpl(request, 'user_share.html', 
               share_user=user, 
               need_password=need_password, 
               token=token)


@app.post('/api/share/{token}/auth', tags=["Sharing"])
async def api_share_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    
    if verify_password(req.password, user.get('share_password_hash', '')):
        request.session[f'share_auth_{token}'] = True
        return {'status': 'success'}
    else:
        lang = request.cookies.get('lang', 'ru')
        return JSONResponse({'error': _t('wrong_share_password', lang)}, status_code=401)


@app.get('/api/share/{token}/connections', tags=["Sharing"])
async def api_share_connections(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
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
async def api_share_config(token: str, connection_id: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conn = next((c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == user['id']), None)
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
        
    try:
        sid = conn['server_id']
        server = data['servers'][sid]
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = manager.get_client_config(conn['protocol'], conn['client_id'], server['host'], port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting shared config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/my/connections/{connection_id}/config', tags=["Self-service"])
async def api_my_connection_config(request: Request, connection_id: str):
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
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol (fixes Telemt/Xray not working for users)
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = manager.get_client_config(conn['protocol'], conn['client_id'], server['host'], port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting my connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/settings', tags=["System Templates"])
async def settings_page(request: Request):
    user = _check_admin(request)
    if not user:
        return RedirectResponse('/login')
    data = load_data()
    return tpl(request, 'settings.html', settings=data.get('settings', {}), servers=data.get('servers', []), current_version=CURRENT_VERSION)


@app.get('/api/settings', tags=["Settings"])
async def api_get_settings(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    return data.get('settings', {})


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
async def save_settings(request: Request, payload: SaveSettingsRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    data['settings']['appearance'] = payload.appearance.dict()
    data['settings']['sync'] = payload.sync.dict()
    data['settings']['captcha'] = payload.captcha.dict()
    data['settings']['telegram'] = payload.telegram.dict()
    data['settings']['ssl'] = payload.ssl.dict()
    save_data(data)
    logger.info("Settings saved (including captcha and telegram)")

    # Handle bot start/stop based on new telegram settings
    tg_cfg = payload.telegram
    if tg_cfg.enabled and tg_cfg.token:
        if not tg_bot.is_running():
            logger.info("Starting Telegram bot (settings save)...")
            tg_bot.launch_bot(tg_cfg.token, load_data, generate_vpn_link)
    else:
        if tg_bot.is_running():
            logger.info("Stopping Telegram bot (settings save)...")
            asyncio.create_task(tg_bot.stop_bot())

    return {"status": "success", "bot_running": tg_bot.is_running()}


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
        tg_bot.launch_bot(token, load_data, generate_vpn_link)
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
    if to_delete_ids:
        await perform_mass_operations(delete_uids=to_delete_ids)
    return {'status': 'success', 'count': len(to_delete_ids)}


@app.get('/api/servers/{server_id}/{protocol}/clients', tags=["Connections"])
async def api_get_server_clients(request: Request, server_id: int, protocol: str):
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
        clients = manager.get_clients(protocol)
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
async def api_list_tokens(request: Request):
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


@app.get('/api/settings/backup/download', tags=["Settings"])
async def api_backup_download(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not os.path.exists(DATA_FILE):
        return JSONResponse({'error': 'Data file not found'}, status_code=404)
    return FileResponse(DATA_FILE, media_type='application/json', filename='data.json')


@app.post('/api/settings/backup/restore', tags=["Settings"])
async def api_backup_restore(request: Request, file: UploadFile = File(...)):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        content = await file.read()
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)
        
        try:
            backup_data = json.loads(content)
        except json.JSONDecodeError:
            return JSONResponse({'error': 'Invalid JSON format'}, status_code=400)

        # Basic structure validation
        required_keys = ['servers', 'users']
        missing = [k for k in required_keys if k not in backup_data]
        if missing:
            return JSONResponse({'error': f'Invalid structure. Missing keys: {", ".join(missing)}'}, status_code=400)

        # Ensure types are correct
        if not isinstance(backup_data['servers'], list) or not isinstance(backup_data['users'], list):
            return JSONResponse({'error': 'Invalid structure: servers and users must be lists'}, status_code=400)

        # Save the new data
        async with DATA_LOCK:
            save_data(backup_data)
        
        # In a real app we might want to restart or re-init background tasks
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error during restore")
        return JSONResponse({'error': str(e)}, status_code=500)


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
