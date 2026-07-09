"""
Telegram bot for Amnezia Web Panel.
Uses raw Telegram Bot API via httpx — no library version conflicts.
Runs as a background asyncio task alongside the FastAPI app.
"""
import asyncio
import html
import logging
import os
import shlex
import sys
import time
import uuid
from typing import Optional, Callable

import httpx

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------- #
#  Global state
# ----------------------------------------------------------------------- #
_bot_task: Optional[asyncio.Task] = None
_callback_refs = {}
_pending_inputs = {}

CLIENT_PROTOCOLS = {"awg", "awg2", "awg_legacy", "xray", "telemt", "wireguard"}
SERVICE_PROTOCOLS = {"dns", "adguard", "socks5", "nginx"}


# ----------------------------------------------------------------------- #
#  Public lifecycle
# ----------------------------------------------------------------------- #
def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


def launch_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None):
    global _bot_task
    _bot_task = asyncio.create_task(
        _run_bot(token, load_data_fn, generate_vpn_link_fn, save_data_fn),
        name="telegram_bot",
    )
    return _bot_task


async def stop_bot():
    global _bot_task
    if _bot_task and not _bot_task.done():
        _bot_task.cancel()
        try:
            await _bot_task
        except asyncio.CancelledError:
            pass
        _bot_task = None
        logger.info("Telegram bot stopped.")


# ----------------------------------------------------------------------- #
#  Low-level Telegram API helpers
# ----------------------------------------------------------------------- #
class TelegramAPI:
    def __init__(self, token: str, client: httpx.AsyncClient):
        self.base = f"https://api.telegram.org/bot{token}"
        self.client = client

    async def call(self, method: str, **params) -> dict:
        r = await self.client.post(f"{self.base}/{method}", json=params, timeout=30)
        return r.json()

    async def get_updates(self, offset: int = 0, timeout: int = 25) -> list:
        r = await self.client.post(
            f"{self.base}/getUpdates",
            json={"offset": offset, "timeout": timeout, "allowed_updates": ["message", "callback_query"]},
            timeout=timeout + 10,
        )
        data = r.json()
        if data.get("ok"):
            return data["result"]
        return []

    async def send_message(self, chat_id, text: str, reply_markup=None, parse_mode="HTML") -> dict:
        import json
        params = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        return await self.call("sendMessage", **params)

    async def edit_message(self, chat_id, message_id, text: str, reply_markup=None, parse_mode="HTML"):
        import json
        params = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        await self.call("editMessageText", **params)

    async def answer_callback(self, callback_query_id: str, text: str = ""):
        await self.call("answerCallbackQuery", callback_query_id=callback_query_id, text=text)

    async def send_document(self, chat_id, filename: str, content: bytes, caption: str = ""):
        files = {"document": (filename, content, "text/plain")}
        data = {"chat_id": str(chat_id), "caption": caption}
        r = await self.client.post(f"{self.base}/sendDocument", data=data, files=files, timeout=30)
        return r.json()


# ----------------------------------------------------------------------- #
#  Generic helpers
# ----------------------------------------------------------------------- #
def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _format_bytes(value) -> str:
    try:
        value = float(value or 0)
    except Exception:
        value = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


def _proto_base(protocol: str) -> str:
    return str(protocol or "awg").split("__", 1)[0]


def _protocol_display_name(protocol: str) -> str:
    base = _proto_base(protocol)
    names = {
        "awg": "AmneziaWG",
        "awg2": "AmneziaWG 2.0",
        "awg_legacy": "AmneziaWG Legacy",
        "xray": "Xray",
        "telemt": "Telemt",
        "dns": "AmneziaDNS",
        "wireguard": "WireGuard",
        "socks5": "SOCKS5",
        "adguard": "AdGuard Home",
        "nginx": "NGINX",
    }
    name = names.get(base, base)
    if "__" in str(protocol):
        try:
            return f"{name} #{int(str(protocol).split('__', 1)[1])}"
        except Exception:
            return name
    return name


def _find_user(load_data_fn: Callable, tg_id: str):
    data = load_data_fn()
    tg_id_clean = str(tg_id).lstrip("@")
    for u in data.get("users", []):
        stored = str(u.get("telegramId", "") or "").lstrip("@")
        if stored and stored == tg_id_clean:
            return u
    return None


def _is_admin(panel_user: dict) -> bool:
    return str((panel_user or {}).get("role", "")).lower() == "admin"


def _ref(action: str, payload: dict) -> str:
    """Short callback_data indirection; Telegram callback_data is limited to 64 bytes."""
    key = uuid.uuid4().hex[:12]
    _callback_refs[key] = {"action": action, "payload": payload, "ts": time.time()}
    # Opportunistic cleanup.
    if len(_callback_refs) > 500:
        cutoff = time.time() - 6 * 3600
        for k in [k for k, v in _callback_refs.items() if v.get("ts", 0) < cutoff]:
            _callback_refs.pop(k, None)
    return f"r:{key}"


def _resolve_ref(data_str: str):
    if not data_str.startswith("r:"):
        return None
    return _callback_refs.get(data_str[2:])


def _build_connections_keyboard(conns: list, data: dict) -> dict:
    """Build inline keyboard where each button = one connection."""
    rows = []
    servers = data.get("servers", [])
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = "Unknown"
        if isinstance(sid, int) and sid < len(servers):
            srv = servers[sid]
            server_name = srv.get("name") or srv.get("host", "Unknown")[:20]
        proto = c.get("protocol", "").upper()
        name = c.get("name", "Connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        rows.append([{"text": label, "callback_data": f"cfg:{c['id']}"}])
    rows.append([{"text": "🔄 Refresh list", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


def _connection_lookup(data: dict, server_id: int, proto: str) -> dict:
    return {
        c.get("client_id"): c
        for c in data.get("user_connections", [])
        if c.get("server_id") == server_id and c.get("protocol") == proto and c.get("client_id")
    }


def _client_display_name(client: dict, conn: Optional[dict] = None) -> str:
    if conn and conn.get("name"):
        return conn.get("name")
    user_data = client.get("userData") or {}
    return (
        client.get("name")
        or client.get("username")
        or user_data.get("clientName")
        or user_data.get("name")
        or str(client.get("clientId") or client.get("client_id") or client.get("id") or "Connection")[:12]
    )


def _user_label(user: dict) -> str:
    label = user.get("username") or user.get("id", "user")
    role = user.get("role") or "user"
    suffix = f" · {role}"
    if user.get("telegramId"):
        suffix += f" · tg:{user.get('telegramId')}"
    if user.get("enabled") is False:
        suffix += " · disabled"
    return f"{label}{suffix}"


def _users_keyboard(data: dict, back_callback: str = "adm:menu") -> dict:
    rows = []
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f"👤 {_user_label(user)}", "callback_data": _ref("user", {"uid": user.get("id")})}])
    rows.append([{"text": "⬅️ Back", "callback_data": back_callback}])
    return {"inline_keyboard": rows}


def _assign_user_keyboard(data: dict, server_id: int, proto: str, name: str) -> dict:
    rows = [[{"text": "🚫 Do not assign", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": None})}]]
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f"👤 {_user_label(user)}", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": user.get("id")})}])
    rows.append([{"text": "❌ Cancel", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}])
    return {"inline_keyboard": rows}


def _admin_main_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "🖥 Servers", "callback_data": "adm:servers"}],
            [{"text": "👤 Users", "callback_data": "adm:users"}],
            [{"text": "🔐 My connections", "callback_data": "adm:myconns"}],
            [{"text": "➕ How to add a server", "callback_data": "adm:addserver_help"}],
        ]
    }


def _server_keyboard(data: dict) -> dict:
    rows = []
    for sid, srv in enumerate(data.get("servers", [])):
        name = srv.get("name") or srv.get("host") or f"Server {sid + 1}"
        rows.append([{"text": f"🖥 {name}", "callback_data": f"srv:{sid}"}])
    rows.append([{"text": "⬅️ Admin menu", "callback_data": "adm:menu"}])
    return {"inline_keyboard": rows}


def _protocol_status_icon(info: dict) -> str:
    if info.get("status_error"):
        return "⚪"
    running = info.get("container_running")
    if running is True:
        return "🟢"
    if running is False:
        return "🔴"
    return "⚪"


def _protocol_status_text(info: dict) -> str:
    if info.get("status_error"):
        return "unknown ⚪"
    running = info.get("container_running")
    if running is True:
        return "running 🟢"
    if running is False:
        return "stopped 🔴"
    return "unknown ⚪"


def _protocols_keyboard(server_id: int, server: dict) -> dict:
    rows = []
    protocols = server.get("protocols", {}) or {}
    for proto, info in protocols.items():
        installed = "✅" if info.get("installed", True) else "⚪"
        rows.append([{"text": f"{installed}{_protocol_status_icon(info)} {_protocol_display_name(proto)}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}])
    if not rows:
        rows.append([{"text": "No installed protocols", "callback_data": f"noop"}])
    rows.append([{"text": "⬅️ Servers", "callback_data": "adm:servers"}])
    return {"inline_keyboard": rows}


def _protocol_keyboard(server_id: int, proto: str, proto_info: dict) -> dict:
    base = _proto_base(proto)
    rows = []
    if base in CLIENT_PROTOCOLS:
        rows.append([{"text": "👥 Connections", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}])
        rows.append([{"text": "➕ Create connection", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}])
    is_running = proto_info.get("container_running") is True
    rows.append([{"text": "⏹ Stop" if is_running else "▶️ Start", "callback_data": _ref("toggle_proto", {"sid": server_id, "proto": proto, "start": not is_running})}])
    rows.append([{"text": "⬅️ Protocols", "callback_data": f"srv:{server_id}"}])
    return {"inline_keyboard": rows}


def _client_keyboard(server_id: int, proto: str, client: dict) -> dict:
    client_id = client.get("clientId") or client.get("client_id") or client.get("id") or ""
    enabled = client.get("enabled")
    if enabled is None:
        enabled = client.get("isEnabled")
    enabled = bool(enabled) if enabled is not None else True
    return {
        "inline_keyboard": [
            [{"text": "📄 Config", "callback_data": _ref("client_cfg", {"sid": server_id, "proto": proto, "client_id": client_id, "name": client.get("name") or client.get("username") or "Connection"})}],
            [{"text": "🚫 Disable" if enabled else "✅ Enable", "callback_data": _ref("toggle_client", {"sid": server_id, "proto": proto, "client_id": client_id, "enable": not enabled})}],
            [{"text": "🗑 Delete", "callback_data": _ref("remove_client", {"sid": server_id, "proto": proto, "client_id": client_id})}],
            [{"text": "⬅️ Connections", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}],
        ]
    }


def _get_ssh_and_manager(server: dict, proto: str):
    sys.path.insert(0, os.path.dirname(__file__))
    from managers.ssh_manager import SSHManager
    from managers.awg_manager import AWGManager
    from managers.xray_manager import XrayManager
    from managers.telemt_manager import TelemtManager
    from managers.wireguard_manager import WireGuardManager
    from managers.dns_manager import DNSManager
    from managers.socks5_manager import Socks5Manager
    from managers.adguard_manager import AdguardManager
    from managers.nginx_manager import NginxManager

    ssh = SSHManager(
        server["host"],
        server.get("ssh_port", 22),
        server["username"],
        server.get("password", ""),
        server.get("private_key", ""),
    )
    base = _proto_base(proto)
    if base == "xray":
        manager = XrayManager(ssh, proto)
    elif base == "telemt":
        manager = TelemtManager(ssh, proto)
    elif base == "wireguard":
        manager = WireGuardManager(ssh)
    elif base == "dns":
        manager = DNSManager(ssh)
    elif base == "socks5":
        manager = Socks5Manager(ssh, proto)
    elif base == "adguard":
        manager = AdguardManager(ssh)
    elif base == "nginx":
        manager = NginxManager(ssh, proto)
    else:
        manager = AWGManager(ssh)
    return ssh, manager


def _manager_call(manager, method_name: str, proto: str, *args, **kwargs):
    method = getattr(manager, method_name)
    try:
        return method(proto, *args, **kwargs)
    except TypeError:
        return method(*args, **kwargs)


def _refresh_server_protocol_statuses(server: dict) -> dict:
    """Refresh saved protocol metadata with live Docker status for Telegram admin views."""
    protocols = server.get("protocols", {}) or {}
    if not protocols:
        return server

    ssh = None
    try:
        ssh, _ = _get_ssh_and_manager(server, "awg")
        ssh.connect()
        for proto, info in protocols.items():
            container = info.get("container_name")
            if not container:
                try:
                    _, manager = _get_ssh_and_manager(server, proto)
                    container = getattr(manager, "container_name", None) or getattr(manager, "CONTAINER_NAME", None)
                except Exception:
                    container = None
            if not container:
                info["status_error"] = "Container name is unknown"
                continue
            out, err, code = ssh.run_sudo_command(
                f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(str(container))} 2>/dev/null"
            )
            if code == 0:
                info["container_running"] = out.strip().lower() == "true"
                info["container_exists"] = True
                info.pop("status_error", None)
            else:
                info["container_running"] = False
                info["container_exists"] = False
                info["status_error"] = (err or out or "container not found").strip()
    except Exception as e:
        logger.warning("Telegram bot: failed to refresh protocol statuses for %s: %s", server.get("name") or server.get("host"), e)
        for info in protocols.values():
            info["status_error"] = str(e)
    finally:
        if ssh:
            try:
                ssh.disconnect()
            except Exception:
                pass
    return server


async def _refresh_server_protocol_statuses_async(server: dict) -> dict:
    return await asyncio.to_thread(_refresh_server_protocol_statuses, server)


# ----------------------------------------------------------------------- #
#  /start and user connection handlers
# ----------------------------------------------------------------------- #
async def _handle_start(api: TelegramAPI, msg: dict, load_data_fn: Callable):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    first_name = msg["from"].get("first_name", "")

    panel_user = _find_user(load_data_fn, tg_id)

    if not panel_user:
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{_e(first_name)}</b>!\n\n"
            "Your Telegram account is not linked to any panel user.\n"
            "Please contact your administrator — they need to add your Telegram ID to your profile.\n\n"
            f"Your Telegram ID: <code>{_e(tg_id)}</code>",
        )
        return

    if _is_admin(panel_user):
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{_e(first_name)}</b>!\n\n"
            f"You are registered as <b>{_e(panel_user.get('username'))}</b> with <b>Admin</b> role.\n"
            "Choose an action:",
            reply_markup=_admin_main_keyboard(),
        )
        return

    await _send_user_connections(api, chat_id, panel_user, load_data_fn, first_name=first_name)


async def _send_user_connections(api: TelegramAPI, chat_id: int, panel_user: dict, load_data_fn: Callable, first_name: str = ""):
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]

    if not conns:
        greeting = f"👋 Hi, <b>{_e(first_name)}</b>!\n\n" if first_name else ""
        await api.send_message(
            chat_id,
            greeting + f"You are registered as <b>{_e(panel_user.get('username'))}</b>.\n\n"
            "You have no connections yet. Please contact your administrator.",
        )
        return

    kb = _build_connections_keyboard(conns, data)
    greeting = f"👋 Hi, <b>{_e(first_name)}</b>!\n\n" if first_name else ""
    await api.send_message(
        chat_id,
        greeting + f"You are registered as <b>{_e(panel_user.get('username'))}</b>.\n\n"
        f"<b>Your connections</b> ({len(conns)}) — tap to get config:",
        reply_markup=kb,
    )


async def _handle_refresh(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, load_data_fn: Callable):
    await api.answer_callback(callback_id, "Updated!")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]
    if not conns:
        await api.edit_message(chat_id, message_id, "You have no connections.")
        return
    kb = _build_connections_keyboard(conns, data)
    await api.edit_message(chat_id, message_id, f"<b>Your connections</b> ({len(conns)}) — tap to get config:", reply_markup=kb)


async def _handle_get_config(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, conn_id: str, tg_id: str, load_data_fn: Callable, generate_vpn_link_fn: Callable):
    await api.answer_callback(callback_id, "Fetching config...")

    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.send_message(chat_id, "❌ Access denied.")
        return

    data = load_data_fn()
    conn = next((c for c in data.get("user_connections", []) if c.get("id") == conn_id and (_is_admin(panel_user) or c.get("user_id") == panel_user.get("id"))), None)
    if not conn:
        await api.send_message(chat_id, "❌ Connection not found.")
        return

    servers = data.get("servers", [])
    sid = conn.get("server_id")
    if not isinstance(sid, int) or sid >= len(servers):
        await api.send_message(chat_id, "❌ Server not found.")
        return

    await _send_config_by_client(api, chat_id, servers[sid], conn.get("protocol", "awg"), conn.get("client_id"), conn.get("name", "Connection"), generate_vpn_link_fn)


async def _send_config_by_client(api: TelegramAPI, chat_id: int, server: dict, proto: str, client_id: str, conn_name: str, generate_vpn_link_fn: Callable):
    loading_result = await api.send_message(chat_id, f"⏳ Fetching config for <b>{_e(conn_name)}</b>...")
    loading_msg_id = loading_result.get("result", {}).get("message_id")
    try:
        proto_info = server.get("protocols", {}).get(proto, {})
        port = proto_info.get("port", "55424")

        def _get_cfg():
            ssh, manager = _get_ssh_and_manager(server, proto)
            try:
                ssh.connect()
                return _manager_call(manager, "get_client_config", proto, client_id, server["host"], port)
            finally:
                ssh.disconnect()

        config = await asyncio.to_thread(_get_cfg)
        if not config:
            if loading_msg_id:
                await api.edit_message(chat_id, loading_msg_id, "❌ Failed to retrieve configuration.")
            return

        if loading_msg_id:
            await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)

        server_name = server.get("name") or server.get("host", "Unknown")
        await api.send_message(chat_id, f"✅ <b>{_e(conn_name)}</b>\n🌐 Server: <b>{_e(server_name)}</b>\n🔌 Protocol: <b>{_e(proto.upper())}</b>")

        is_link_proto = _proto_base(proto) in ("xray", "telemt")
        if is_link_proto:
            await api.send_message(chat_id, f"🔗 <b>Connection link</b> (tap to copy):\n<code>{_e(config)}</code>")
        else:
            MAX_LEN = 4000
            if len(config) <= MAX_LEN:
                await api.send_message(chat_id, f"<b>📄 Configuration:</b>\n<pre>{_e(config)}</pre>")
            else:
                chunks = [config[i:i + MAX_LEN] for i in range(0, len(config), MAX_LEN)]
                for i, chunk in enumerate(chunks, 1):
                    await api.send_message(chat_id, f"<b>📄 Configuration (part {i}/{len(chunks)}):</b>\n<pre>{_e(chunk)}</pre>")

            vpn_link = generate_vpn_link_fn(config) if config else ""
            if vpn_link:
                await api.send_message(chat_id, f"🔗 <b>VPN Link</b> (tap to copy):\n<code>{_e(vpn_link)}</code>")
            filename = f"{str(conn_name).replace(' ', '_')}.conf"
            await api.send_document(chat_id, filename=filename, content=config.encode("utf-8"), caption=f"📁 Config file: {conn_name}")
    except Exception as e:
        logger.exception("Bot: error getting config")
        if loading_msg_id:
            await api.edit_message(chat_id, loading_msg_id, f"❌ Error: {_e(e)}")
        else:
            await api.send_message(chat_id, f"❌ Error: {_e(e)}")


# ----------------------------------------------------------------------- #
#  Admin handlers
# ----------------------------------------------------------------------- #
def _require_admin(load_data_fn: Callable, tg_id: str):
    user = _find_user(load_data_fn, tg_id)
    if not user or not _is_admin(user):
        return None
    return user


async def _handle_add_server_command(api: TelegramAPI, msg: dict, load_data_fn: Callable, save_data_fn: Optional[Callable]):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    if not _require_admin(load_data_fn, tg_id):
        await api.send_message(chat_id, "❌ Access denied.")
        return
    if not save_data_fn:
        await api.send_message(chat_id, "❌ Saving is not available for this bot instance.")
        return

    text = msg.get("text", "")
    parts = text.split(maxsplit=5)
    if len(parts) < 4:
        await api.send_message(
            chat_id,
            "Usage:\n"
            "<code>/addserver host username password [ssh_port] [name]</code>\n\n"
            "Example:\n"
            "<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n"
            "⚠️ Telegram messages are not a secrets manager. Prefer adding servers in the web panel if possible.",
        )
        return

    host = parts[1]
    username = parts[2]
    password = parts[3]
    ssh_port = 22
    name = host
    if len(parts) >= 5:
        try:
            ssh_port = int(parts[4])
        except Exception:
            name = parts[4]
    if len(parts) >= 6:
        name = parts[5] or host

    data = load_data_fn()
    data.setdefault("servers", []).append({
        "name": name,
        "host": host,
        "ssh_port": ssh_port,
        "username": username,
        "password": password,
        "private_key": "",
        "protocols": {},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })
    save_data_fn(data)
    await api.send_message(chat_id, f"✅ Server added: <b>{_e(name)}</b>\nHost: <code>{_e(host)}</code>")


async def _admin_servers(api: TelegramAPI, chat_id: int, message_id: Optional[int], load_data_fn: Callable):
    data = load_data_fn()
    servers = data.get("servers", [])
    text = f"🖥 <b>Servers</b> ({len(servers)})\n\nChoose a server:"
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=_server_keyboard(data))
    else:
        await api.send_message(chat_id, text, reply_markup=_server_keyboard(data))


async def _admin_users(api: TelegramAPI, chat_id: int, message_id: int, load_data_fn: Callable):
    data = load_data_fn()
    users = data.get("users", [])
    await api.edit_message(chat_id, message_id, f"👤 <b>Users</b> ({len(users)})\n\nChoose a user:", reply_markup=_users_keyboard(data))


async def _admin_user_detail(api: TelegramAPI, chat_id: int, message_id: int, user_id: str, load_data_fn: Callable):
    data = load_data_fn()
    user = next((u for u in data.get("users", []) if u.get("id") == user_id), None)
    if not user:
        await api.edit_message(chat_id, message_id, "❌ User not found.", reply_markup={"inline_keyboard": [[{"text": "⬅️ Users", "callback_data": "adm:users"}]]})
        return
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == user_id]
    lines = [
        f"👤 <b>{_e(user.get('username'))}</b>",
        f"Role: <b>{_e(user.get('role', 'user'))}</b>",
        f"Enabled: <b>{'yes ✅' if user.get('enabled', True) else 'no 🚫'}</b>",
        f"Telegram ID: <code>{_e(user.get('telegramId') or '-')}</code>",
        f"Email: <code>{_e(user.get('email') or '-')}</code>",
        f"Connections: <b>{len(conns)}</b>",
    ]
    if user.get("description"):
        lines.append(f"Description: {_e(user.get('description'))}")
    rows = []
    servers = data.get("servers", [])
    for c in conns[:20]:
        sid = c.get("server_id")
        server_name = "Unknown"
        if isinstance(sid, int) and sid < len(servers):
            server_name = servers[sid].get("name") or servers[sid].get("host") or "Unknown"
        rows.append([{"text": f"🔐 {c.get('name', 'Connection')} · {c.get('protocol', '').upper()} · {server_name}", "callback_data": f"cfg:{c.get('id')}"}])
    rows.append([{"text": "⬅️ Users", "callback_data": "adm:users"}])
    rows.append([{"text": "⬅️ Admin menu", "callback_data": "adm:menu"}])
    await api.edit_message(chat_id, message_id, "\n".join(lines), reply_markup={"inline_keyboard": rows})


async def _admin_server_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, load_data_fn: Callable):
    data = load_data_fn()
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        await api.edit_message(chat_id, message_id, "❌ Server not found.")
        return
    server = await _refresh_server_protocol_statuses_async(servers[server_id])
    protocols = server.get("protocols", {}) or {}
    text = (
        f"🖥 <b>{_e(server.get('name') or server.get('host'))}</b>\n"
        f"Host: <code>{_e(server.get('host'))}</code>\n"
        f"SSH: <code>{_e(server.get('username'))}@{_e(server.get('host'))}:{_e(server.get('ssh_port', 22))}</code>\n\n"
        f"<b>Protocols</b> ({len(protocols)}):"
    )
    await api.edit_message(chat_id, message_id, text, reply_markup=_protocols_keyboard(server_id, server))


async def _admin_protocol_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, load_data_fn: Callable):
    data = load_data_fn()
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        await api.edit_message(chat_id, message_id, "❌ Server not found.")
        return
    server = await _refresh_server_protocol_statuses_async(servers[server_id])
    info = (server.get("protocols", {}) or {}).get(proto)
    if not info:
        await api.edit_message(chat_id, message_id, "❌ Protocol not found.")
        return
    lines = [
        f"🔌 <b>{_e(_protocol_display_name(proto))}</b>",
        f"Server: <b>{_e(server.get('name') or server.get('host'))}</b>",
        f"Status: <b>{_protocol_status_text(info)}</b>",
    ]
    for key in ("port", "container_name", "domain", "site_url", "web_port", "mode"):
        if info.get(key) not in (None, ""):
            lines.append(f"{_e(key)}: <code>{_e(info.get(key))}</code>")
    if info.get("status_error"):
        lines.append(f"status_error: <code>{_e(info.get('status_error'))}</code>")
    await api.edit_message(chat_id, message_id, "\n".join(lines), reply_markup=_protocol_keyboard(server_id, proto, info))


async def _admin_toggle_protocol(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, start: bool, load_data_fn: Callable):
    await api.edit_message(chat_id, message_id, "⏳ Updating protocol container...")

    def _toggle():
        data = load_data_fn()
        server = data["servers"][server_id]
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            container = (server.get("protocols", {}).get(proto, {}) or {}).get("container_name")
            if not container:
                # fallback: most managers expose CONTAINER_NAME for base/first instances
                container = getattr(manager, "CONTAINER_NAME", None)
            if not container:
                raise RuntimeError("Container name is unknown")
            action = "start" if start else "stop"
            out, err, code = ssh.run_sudo_command(f"docker {action} {container}")
            if code != 0:
                raise RuntimeError(err or out or f"docker {action} failed")
            return data
        finally:
            ssh.disconnect()

    try:
        await asyncio.to_thread(_toggle)
        await _admin_protocol_detail(api, chat_id, message_id, server_id, proto, load_data_fn)
    except Exception as e:
        logger.exception("Bot admin: protocol toggle failed")
        await api.edit_message(chat_id, message_id, f"❌ Error: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": "⬅️ Protocol", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _admin_clients(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, load_data_fn: Callable):
    await api.edit_message(chat_id, message_id, "⏳ Loading connections...")

    def _load_clients():
        data = load_data_fn()
        server = data["servers"][server_id]
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            return data, _manager_call(manager, "get_clients", proto)
        finally:
            ssh.disconnect()

    try:
        data, clients = await asyncio.to_thread(_load_clients)
        if not clients:
            await api.edit_message(chat_id, message_id, "👥 No connections.", reply_markup={"inline_keyboard": [[{"text": "➕ Create connection", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}], [{"text": "⬅️ Protocol", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})
            return
        rows = []
        conn_by_client = _connection_lookup(data, server_id, proto)
        users_by_id = {u.get("id"): u for u in data.get("users", [])}
        for c in clients[:40]:
            client_id = c.get("clientId") or c.get("client_id") or c.get("id") or ""
            conn = conn_by_client.get(client_id)
            name = _client_display_name(c, conn)
            traffic = ""
            user_data = c.get("userData") or {}
            if user_data:
                total = (user_data.get("dataReceivedBytes") or 0) + (user_data.get("dataSentBytes") or 0)
                traffic = f" · {_format_bytes(total)}"
            assigned = ""
            if conn and conn.get("user_id") in users_by_id:
                assigned = f" · @{users_by_id[conn.get('user_id')].get('username')}"
            c["name"] = name
            c["assigned_user_id"] = conn.get("user_id") if conn else None
            rows.append([{"text": f"👤 {name}{assigned}{traffic}", "callback_data": _ref("client", {"sid": server_id, "proto": proto, "client_id": client_id, "name": name, "client": c})}])
        rows.append([{"text": "➕ Create connection", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}])
        rows.append([{"text": "⬅️ Protocol", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}])
        await api.edit_message(chat_id, message_id, f"👥 <b>{_e(_protocol_display_name(proto))} connections</b> ({len(clients)})", reply_markup={"inline_keyboard": rows})
    except Exception as e:
        logger.exception("Bot admin: load clients failed")
        await api.edit_message(chat_id, message_id, f"❌ Error: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": "⬅️ Protocol", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _admin_client_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client: dict):
    client_id = client.get("clientId") or client.get("client_id") or client.get("id") or ""
    name = _client_display_name(client)
    user_data = client.get("userData") or {}
    rx = user_data.get("dataReceivedBytes") or 0
    tx = user_data.get("dataSentBytes") or 0
    enabled = client.get("enabled")
    if enabled is None:
        enabled = client.get("isEnabled")
    enabled_text = "enabled ✅" if (enabled is None or enabled) else "disabled 🚫"
    text = (
        f"👤 <b>{_e(name)}</b>\n"
        f"Protocol: <b>{_e(_protocol_display_name(proto))}</b>\n"
        f"Client ID: <code>{_e(client_id)}</code>\n"
        f"Status: <b>{enabled_text}</b>"
    )
    if user_data:
        text += f"\nTraffic: <b>{_format_bytes(rx + tx)}</b>\nRX: {_format_bytes(rx)} · TX: {_format_bytes(tx)}"
    await api.edit_message(chat_id, message_id, text, reply_markup=_client_keyboard(server_id, proto, client))


async def _admin_add_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, panel_user: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, "❌ Saving is not available for this bot instance.")
        return
    _pending_inputs[str(chat_id)] = {
        "kind": "add_client_name",
        "sid": server_id,
        "proto": proto,
        "admin_user_id": panel_user.get("id"),
        "ts": time.time(),
    }
    await api.edit_message(
        chat_id,
        message_id,
        "➕ <b>Create connection</b>\n\n"
        f"Server/protocol: <b>{_e(_protocol_display_name(proto))}</b>\n\n"
        "Send the connection name in the next message.\n"
        "Example: <code>Ivan iPhone</code>\n\n"
        "Send <code>/cancel</code> to cancel.",
        reply_markup={"inline_keyboard": [[{"text": "❌ Cancel", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]},
    )


async def _admin_choose_client_user(api: TelegramAPI, chat_id: int, name: str, server_id: int, proto: str, load_data_fn: Callable):
    data = load_data_fn()
    await api.send_message(
        chat_id,
        "✅ Connection name: <b>{}</b>\n\n"
        "Assign this connection to a panel user?".format(_e(name)),
        reply_markup=_assign_user_keyboard(data, server_id, proto, name),
    )


async def _admin_create_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, name: str, user_id: Optional[str], load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, "❌ Saving is not available for this bot instance.")
        return
    await api.edit_message(chat_id, message_id, "⏳ Creating connection...")

    def _create():
        data = load_data_fn()
        server = data["servers"][server_id]
        proto_info = (server.get("protocols", {}) or {}).get(proto, {})
        port = proto_info.get("port", "55424")
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            if _proto_base(proto) == "telemt":
                result = manager.add_client(proto, name, server["host"], port)
            elif _proto_base(proto) == "wireguard":
                result = manager.add_client(name, server["host"])
            else:
                result = manager.add_client(proto, name, server["host"], port)
        finally:
            ssh.disconnect()
        client_id = result.get("client_id") or result.get("clientId")
        assigned_user = None
        if user_id:
            assigned_user = next((u for u in data.get("users", []) if u.get("id") == user_id), None)
        if user_id and client_id:
            data.setdefault("user_connections", []).append({
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "server_id": server_id,
                "protocol": proto,
                "client_id": client_id,
                "name": name,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
            save_data_fn(data)
        return server, result, client_id, assigned_user

    try:
        server, result, client_id, assigned_user = await asyncio.to_thread(_create)
        assigned_text = f"\nAssigned to: <b>{_e(assigned_user.get('username'))}</b>" if assigned_user else "\nAssigned: <b>not linked</b>"
        await api.edit_message(chat_id, message_id, f"✅ Connection created: <b>{_e(name)}</b>{assigned_text}")
        config = result.get("config")
        if config:
            await _send_config_text(api, chat_id, server, proto, name, config, generate_vpn_link_fn)
        elif client_id:
            await _send_config_by_client(api, chat_id, server, proto, client_id, name, generate_vpn_link_fn)
    except Exception as e:
        logger.exception("Bot admin: add client failed")
        await api.edit_message(chat_id, message_id, f"❌ Error: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": "⬅️ Protocol", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _send_config_text(api: TelegramAPI, chat_id: int, server: dict, proto: str, conn_name: str, config: str, generate_vpn_link_fn: Callable):
    await api.send_message(chat_id, f"✅ <b>{_e(conn_name)}</b>\n🌐 Server: <b>{_e(server.get('name') or server.get('host'))}</b>\n🔌 Protocol: <b>{_e(proto.upper())}</b>")
    if _proto_base(proto) in ("xray", "telemt"):
        await api.send_message(chat_id, f"🔗 <b>Connection link</b>:\n<code>{_e(config)}</code>")
    else:
        await api.send_message(chat_id, f"<b>📄 Configuration:</b>\n<pre>{_e(config)}</pre>")
        vpn_link = generate_vpn_link_fn(config) if config else ""
        if vpn_link:
            await api.send_message(chat_id, f"🔗 <b>VPN Link</b>:\n<code>{_e(vpn_link)}</code>")
        await api.send_document(chat_id, filename=f"{conn_name}.conf", content=config.encode("utf-8"), caption=f"📁 Config file: {conn_name}")


async def _admin_toggle_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client_id: str, enable: bool, load_data_fn: Callable):
    await api.edit_message(chat_id, message_id, "⏳ Updating connection...")

    def _toggle():
        data = load_data_fn()
        server = data["servers"][server_id]
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            return _manager_call(manager, "toggle_client", proto, client_id, enable)
        finally:
            ssh.disconnect()

    try:
        await asyncio.to_thread(_toggle)
        await api.edit_message(chat_id, message_id, "✅ Updated.", reply_markup={"inline_keyboard": [[{"text": "⬅️ Connections", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]})
    except Exception as e:
        logger.exception("Bot admin: toggle client failed")
        await api.edit_message(chat_id, message_id, f"❌ Error: {_e(e)}")


async def _admin_remove_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client_id: str, load_data_fn: Callable, save_data_fn: Optional[Callable]):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, "❌ Saving is not available for this bot instance.")
        return
    await api.edit_message(chat_id, message_id, "⏳ Removing connection...")

    def _remove():
        data = load_data_fn()
        server = data["servers"][server_id]
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            _manager_call(manager, "remove_client", proto, client_id)
        finally:
            ssh.disconnect()
        data["user_connections"] = [
            c for c in data.get("user_connections", [])
            if not (c.get("server_id") == server_id and c.get("protocol") == proto and c.get("client_id") == client_id)
        ]
        save_data_fn(data)

    try:
        await asyncio.to_thread(_remove)
        await api.edit_message(chat_id, message_id, "✅ Connection removed.", reply_markup={"inline_keyboard": [[{"text": "⬅️ Connections", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]})
    except Exception as e:
        logger.exception("Bot admin: remove client failed")
        await api.edit_message(chat_id, message_id, f"❌ Error: {_e(e)}")


async def _handle_pending_input(api: TelegramAPI, msg: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable) -> bool:
    chat_id = msg["chat"]["id"]
    state = _pending_inputs.get(str(chat_id))
    if not state:
        return False

    text = (msg.get("text") or "").strip()
    if text.lower() in ("/cancel", "cancel"):
        _pending_inputs.pop(str(chat_id), None)
        await api.send_message(chat_id, "❌ Action cancelled.", reply_markup=_admin_main_keyboard())
        return True
    if text.startswith("/"):
        _pending_inputs.pop(str(chat_id), None)
        return False

    if state.get("kind") == "add_client_name":
        panel_user = _require_admin(load_data_fn, str(msg["from"]["id"]))
        if not panel_user:
            _pending_inputs.pop(str(chat_id), None)
            await api.send_message(chat_id, "❌ Access denied.")
            return True
        name = text[:80].strip()
        if not name:
            await api.send_message(chat_id, "Name cannot be empty. Send a connection name or /cancel.")
            return True
        _pending_inputs.pop(str(chat_id), None)
        await _admin_choose_client_user(api, chat_id, name, int(state.get("sid", 0)), state.get("proto", "awg"), load_data_fn)
        return True

    return False


# ----------------------------------------------------------------------- #
#  Main polling loop and dispatcher
# ----------------------------------------------------------------------- #
async def _run_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None):
    offset = 0
    logger.info("Telegram bot started (raw httpx polling).")

    async with httpx.AsyncClient() as client:
        api = TelegramAPI(token, client)

        me = await api.call("getMe")
        if not me.get("ok"):
            logger.error(f"Telegram bot: invalid token or API error: {me}")
            return
        logger.info(f"Telegram bot logged in as @{me['result']['username']}")

        while True:
            try:
                updates = await api.get_updates(offset=offset, timeout=25)
            except asyncio.CancelledError:
                logger.info("Telegram bot polling cancelled.")
                return
            except Exception as e:
                logger.warning(f"Telegram bot polling error: {e}")
                await asyncio.sleep(5)
                continue

            for update in updates:
                offset = update["update_id"] + 1
                try:
                    await _dispatch(api, update, load_data_fn, generate_vpn_link_fn, save_data_fn)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.exception(f"Telegram bot: error handling update {update['update_id']}: {e}")


async def _dispatch(api: TelegramAPI, update: dict, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None):
    if "message" in update:
        msg = update["message"]
        text = msg.get("text", "")
        if await _handle_pending_input(api, msg, load_data_fn, save_data_fn, generate_vpn_link_fn):
            return
        if text.startswith("/start") or text.startswith("/admin"):
            await _handle_start(api, msg, load_data_fn)
        elif text.startswith("/connections"):
            panel_user = _find_user(load_data_fn, str(msg["from"]["id"]))
            if not panel_user:
                await api.send_message(msg["chat"]["id"], "❌ Access denied.")
            else:
                await _send_user_connections(api, msg["chat"]["id"], panel_user, load_data_fn)
        elif text.startswith("/servers"):
            if _require_admin(load_data_fn, str(msg["from"]["id"])):
                await _admin_servers(api, msg["chat"]["id"], None, load_data_fn)
            else:
                await api.send_message(msg["chat"]["id"], "❌ Access denied.")
        elif text.startswith("/addserver"):
            await _handle_add_server_command(api, msg, load_data_fn, save_data_fn)

    elif "callback_query" in update:
        cq = update["callback_query"]
        callback_id = cq["id"]
        data_str = cq.get("data", "")
        chat_id = cq["message"]["chat"]["id"]
        message_id = cq["message"]["message_id"]
        tg_id = str(cq["from"]["id"])

        if data_str == "noop":
            await api.answer_callback(callback_id)
            return
        if data_str == "refresh":
            await _handle_refresh(api, chat_id, message_id, callback_id, tg_id, load_data_fn)
            return
        if data_str.startswith("cfg:"):
            await _handle_get_config(api, chat_id, message_id, callback_id, data_str[4:], tg_id, load_data_fn, generate_vpn_link_fn)
            return

        panel_user = _require_admin(load_data_fn, tg_id)
        if not panel_user:
            await api.answer_callback(callback_id, "Access denied")
            return

        await api.answer_callback(callback_id)

        if data_str == "adm:menu":
            await api.edit_message(chat_id, message_id, "<b>Admin menu</b>", reply_markup=_admin_main_keyboard())
        elif data_str == "adm:servers":
            await _admin_servers(api, chat_id, message_id, load_data_fn)
        elif data_str == "adm:users":
            await _admin_users(api, chat_id, message_id, load_data_fn)
        elif data_str == "adm:myconns":
            await _send_user_connections(api, chat_id, panel_user, load_data_fn)
        elif data_str == "adm:addserver_help":
            await api.edit_message(
                chat_id,
                message_id,
                "➕ <b>Add server</b>\n\n"
                "Use command:\n"
                "<code>/addserver host username password [ssh_port] [name]</code>\n\n"
                "Example:\n"
                "<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n"
                "⚠️ Prefer the web panel for real credentials if possible.",
                reply_markup={"inline_keyboard": [[{"text": "⬅️ Admin menu", "callback_data": "adm:menu"}]]},
            )
        elif data_str.startswith("srv:"):
            await _admin_server_detail(api, chat_id, message_id, int(data_str.split(":", 1)[1]), load_data_fn)
        else:
            ref = _resolve_ref(data_str)
            if not ref:
                await api.edit_message(chat_id, message_id, "❌ Action expired. Use /start again.")
                return
            action = ref.get("action")
            payload = ref.get("payload", {})
            sid = int(payload.get("sid", 0) or 0)
            proto = payload.get("proto", "awg")
            if action == "user":
                await _admin_user_detail(api, chat_id, message_id, payload.get("uid"), load_data_fn)
            elif action == "proto":
                await _admin_protocol_detail(api, chat_id, message_id, sid, proto, load_data_fn)
            elif action == "toggle_proto":
                await _admin_toggle_protocol(api, chat_id, message_id, sid, proto, bool(payload.get("start")), load_data_fn)
            elif action == "clients":
                await _admin_clients(api, chat_id, message_id, sid, proto, load_data_fn)
            elif action == "client":
                await _admin_client_detail(api, chat_id, message_id, sid, proto, payload.get("client", {}))
            elif action == "client_cfg":
                data = load_data_fn()
                server = data["servers"][sid]
                await _send_config_by_client(api, chat_id, server, proto, payload.get("client_id"), payload.get("name", "Connection"), generate_vpn_link_fn)
            elif action == "add_client":
                await _admin_add_client(api, chat_id, message_id, sid, proto, panel_user, load_data_fn, save_data_fn, generate_vpn_link_fn)
            elif action == "create_client":
                await _admin_create_client(api, chat_id, message_id, sid, proto, payload.get("name", "Connection"), payload.get("user_id"), load_data_fn, save_data_fn, generate_vpn_link_fn)
            elif action == "toggle_client":
                await _admin_toggle_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), bool(payload.get("enable")), load_data_fn)
            elif action == "remove_client":
                await _admin_remove_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), load_data_fn, save_data_fn)
