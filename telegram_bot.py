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

from connection_service import (
    SELF_SERVICE_PROTOCOLS,
    protocol_base,
    protocol_instance,
    sanitize_allowed_protocols,
    self_service_protocol_display_name,
    server_self_service_protocols,
)

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------- #
#  Global state
# ----------------------------------------------------------------------- #
_bot_task: Optional[asyncio.Task] = None
_callback_refs = {}
_pending_inputs = {}

_EXTRA_PROTOCOL_DISPLAY_NAMES = {
    "dns": "AmneziaDNS",
    "socks5": "SOCKS5",
    "exit": "Exit Node",
    "adguard": "AdGuard Home",
    "nginx": "NGINX",
}
SERVICE_PROTOCOLS = {"dns", "adguard", "socks5", "nginx", "exit"}

TG_TRANSLATIONS = {
    "en": {
        "hi": "Hi",
        "account_not_linked": "Your Telegram account is not linked to any panel user.",
        "contact_admin_to_link": "Please contact your administrator — they need to add your Telegram ID to your profile.",
        "your_telegram_id": "Your Telegram ID",
        "registered_admin": "You are registered as <b>{username}</b> with <b>Admin</b> role.",
        "choose_action": "Choose an action:",
        "registered_as": "You are registered as <b>{username}</b>.",
        "no_connections_create": "You have no connections yet. Tap the button below to create one!",
        "no_connections_contact_admin": "You have no connections yet. Please contact your administrator.",
        "your_connections": "<b>Your connections</b> ({count}) — tap to get config:",
        "updated": "Updated!",
        "access_denied": "Access denied.",
        "no_connections_create_short": "You have no connections. Tap the button below to create one!",
        "no_connections": "You have no connections.",
        "fetching_config": "Fetching config...",
        "connection_not_found": "Connection not found.",
        "server_not_found": "Server not found.",
        "fetching_config_for": "Fetching config for <b>{name}</b>...",
        "failed_retrieve_config": "Failed to retrieve configuration.",
        "admin_menu": "Admin menu",
        "action_expired": "Action expired. Use /start again.",
        "btn_create_connection": "Create connection",
        "btn_refresh_list": "Refresh list",
        "btn_back": "Back",
        "btn_do_not_assign": "Do not assign",
        "btn_cancel": "Cancel",
        "btn_servers": "Servers",
        "btn_users": "Users",
        "btn_my_connections": "My connections",
        "btn_how_add_server": "How to add a server",
        "btn_admin_menu": "Admin menu",
        "btn_no_installed_protocols": "No installed protocols",
        "btn_connections": "Connections",
        "btn_stop": "Stop",
        "btn_start": "Start",
        "btn_protocols": "Protocols",
        "btn_config": "Config",
        "btn_disable": "Disable",
        "btn_enable": "Enable",
        "btn_delete": "Delete",
        "btn_protocol": "Protocol",
        "choose_server": "Choose a server:",
        "choose_protocol": "Choose a protocol:",
        "protocol_label": "Protocol",
        "send_device_name": "Send the device name in the next message.",
        "cancel_instruction": "Send <code>/cancel</code> to cancel.",
        "example_label": "Example",
        "delete_connection_confirm": "Delete connection <b>{name}</b>?",
        "cannot_be_undone": "This cannot be undone.",
        "connection_deleted": "Connection deleted.",
        "connection_deleted_no_connections": "Connection deleted. You have no connections.",
        "connection_created_no_config": "Connection created, but no config is available.",
        "creating_connection_named": "Creating connection <b>{name}</b>...",
        "self_service_creation_disabled": "Self-service connection creation is currently disabled.\nPlease contact your administrator.",
        "self_service_no_servers": "No servers are available for self-service connection creation.\nPlease contact your administrator.",
        "self_service_disabled_contact": "Self-service is disabled. Contact your administrator.",
        "self_service_unavailable": "Self-service is not available.",
        "server_not_self_service": "This server is not available for self-service.",
        "no_protocols_available": "No protocols available on this server.",
        "name_empty": "Name cannot be empty. Send a connection name or /cancel.",
        "error": "Error",
        "saving_not_available": "Saving is not available for this bot instance.",
        "servers_title": "Servers",
        "choose_a_server": "Choose a server:",
        "users_title": "Users",
        "choose_a_user": "Choose a user:",
        "user_not_found": "User not found.",
        "protocol_not_found": "Protocol not found.",
        "updating_protocol": "Updating protocol container...",
        "loading_connections": "Loading connections...",
        "no_connections_short": "No connections.",
        "creating_connection": "Creating connection...",
        "updating_connection": "Updating connection...",
        "removing_connection": "Removing connection...",
        "connection_removed": "Connection removed.",
        "action_cancelled": "Action cancelled.",
        "add_server_label": "Add server",
        "add_server_command": "Use command:\n<code>/addserver host username password [ssh_port] [name]</code>\n\nExample:\n<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n⚠️ Telegram messages are not a secrets manager. Prefer adding servers in the web panel if possible.",
        "server_added": "Server added: <b>{name}</b>\nHost: <code>{host}</code>",
        "server_config": "Config",
        "send_connection_name": "Send the connection name in the next message.\nExample: <code>Ivan iPhone</code>\n\nSend <code>/cancel</code> to cancel.",
        "connection_name_label": "Connection name",
        "assign_to_user": "Assign this connection to a panel user?",
        "connection_created": "Connection created: <b>{name}</b>",
        "assigned_to": "Assigned to: <b>{username}</b>",
        "assigned_not_linked": "Assigned: <b>not linked</b>",
        "config_label": "Configuration",
        "connection_link_label": "Connection link",
        "config_part": "Configuration (part {part}/{total}):",
        "vpn_link_label": "VPN Link",
        "config_file_label": "Config file",
        "protocol_status": "Status",
        "protocol_port": "Port",
        "client_status": "Status",
        "enabled_label": "enabled",
        "disabled_label": "disabled",
        "traffic_label": "Traffic",
        "rx_label": "RX",
        "tx_label": "TX",
        "connections_count": "Connections",
        "create_new_connection": "Create connection",
        "connection_created_success": "Connection created successfully.",
        "role_label": "Role",
        "enabled_status": "Enabled",
        "email_label": "Email",
        "tg_id_label": "Telegram ID",
        "description_label": "Description",
        "protocol_display": "Protocol",
    },
    "ru": {
        "hi": "Привет",
        "account_not_linked": "Ваш аккаунт Telegram не привязан ни к одному пользователю панели.",
        "contact_admin_to_link": "Обратитесь к администратору — он должен добавить ваш Telegram ID в профиль.",
        "your_telegram_id": "Ваш Telegram ID",
        "registered_admin": "Вы зарегистрированы как <b>{username}</b> с ролью <b>Admin</b>.",
        "choose_action": "Выберите действие:",
        "registered_as": "Вы зарегистрированы как <b>{username}</b>.",
        "no_connections_create": "У вас пока нет подключений. Нажмите кнопку ниже, чтобы создать первое.",
        "no_connections_contact_admin": "У вас пока нет подключений. Обратитесь к администратору.",
        "your_connections": "<b>Ваши подключения</b> ({count}) — нажмите, чтобы получить конфигурацию:",
        "updated": "Обновлено!",
        "access_denied": "Доступ запрещён.",
        "no_connections_create_short": "У вас нет подключений. Нажмите кнопку ниже, чтобы создать первое.",
        "no_connections": "У вас нет подключений.",
        "fetching_config": "Получаю конфигурацию...",
        "connection_not_found": "Подключение не найдено.",
        "server_not_found": "Сервер не найден.",
        "fetching_config_for": "Получаю конфигурацию для <b>{name}</b>...",
        "failed_retrieve_config": "Не удалось получить конфигурацию.",
        "admin_menu": "Меню администратора",
        "action_expired": "Действие устарело. Используйте /start снова.",
        "btn_create_connection": "Создать подключение",
        "btn_refresh_list": "Обновить список",
        "btn_back": "Назад",
        "btn_do_not_assign": "Не назначать",
        "btn_cancel": "Отмена",
        "btn_servers": "Серверы",
        "btn_users": "Пользователи",
        "btn_my_connections": "Мои подключения",
        "btn_how_add_server": "Как добавить сервер",
        "btn_admin_menu": "Меню администратора",
        "btn_no_installed_protocols": "Нет установленных протоколов",
        "btn_connections": "Подключения",
        "btn_stop": "Остановить",
        "btn_start": "Запустить",
        "btn_protocols": "Протоколы",
        "btn_config": "Конфигурация",
        "btn_disable": "Отключить",
        "btn_enable": "Включить",
        "btn_delete": "Удалить",
        "btn_protocol": "Протокол",
        "choose_server": "Выберите сервер:",
        "choose_protocol": "Выберите протокол:",
        "protocol_label": "Протокол",
        "send_device_name": "Отправьте имя устройства следующим сообщением.",
        "cancel_instruction": "Отправьте <code>/cancel</code> для отмены.",
        "example_label": "Пример",
        "delete_connection_confirm": "Удалить подключение <b>{name}</b>?",
        "cannot_be_undone": "Это действие нельзя отменить.",
        "connection_deleted": "Подключение удалено.",
        "connection_deleted_no_connections": "Подключение удалено. У вас нет подключений.",
        "connection_created_no_config": "Подключение создано, но конфигурация недоступна.",
        "creating_connection_named": "Создаю подключение <b>{name}</b>...",
        "self_service_creation_disabled": "Создание подключений через self-service сейчас отключено.\nОбратитесь к администратору.",
        "self_service_no_servers": "Нет серверов, доступных для создания подключений через self-service.\nОбратитесь к администратору.",
        "self_service_disabled_contact": "Self-service отключён. Обратитесь к администратору.",
        "self_service_unavailable": "Self-service недоступен.",
        "server_not_self_service": "Этот сервер недоступен для self-service.",
        "no_protocols_available": "На этом сервере нет доступных протоколов.",
        "name_empty": "Имя не может быть пустым. Отправьте имя подключения или /cancel.",
        "error": "Ошибка",
        "saving_not_available": "Сохранение недоступно для этой версии бота.",
        "servers_title": "Серверы",
        "choose_a_server": "Выберите сервер:",
        "users_title": "Пользователи",
        "choose_a_user": "Выберите пользователя:",
        "user_not_found": "Пользователь не найден.",
        "protocol_not_found": "Протокол не найден.",
        "updating_protocol": "Обновляю контейнер протокола...",
        "loading_connections": "Загружаю подключения...",
        "no_connections_short": "Нет подключений.",
        "creating_connection": "Создаю подключение...",
        "updating_connection": "Обновляю подключение...",
        "removing_connection": "Удаляю подключение...",
        "connection_removed": "Подключение удалено.",
        "action_cancelled": "Действие отменено.",
        "add_server_label": "Добавить сервер",
        "add_server_command": "Используйте команду:\n<code>/addserver хост имя_пользователя пароль [ssh_порт] [имя]</code>\n\nПример:\n<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n⚠️ Сообщения Telegram — не менеджер секретов. Лучше добавлять серверы через веб-панель.",
        "server_added": "Сервер добавлен: <b>{name}</b>\nХост: <code>{host}</code>",
        "server_config": "Конфигурация",
        "send_connection_name": "Отправьте имя подключения следующим сообщением.\nПример: <code>Ivan iPhone</code>\n\nОтправьте <code>/cancel</code> для отмены.",
        "connection_name_label": "Имя подключения",
        "assign_to_user": "Назначить это подключение пользователю панели?",
        "connection_created": "Подключение создано: <b>{name}</b>",
        "assigned_to": "Назначено: <b>{username}</b>",
        "assigned_not_linked": "Назначено: <b>не привязано</b>",
        "config_label": "Конфигурация",
        "connection_link_label": "Ссылка подключения",
        "config_part": "Конфигурация (часть {part}/{total}):",
        "vpn_link_label": "VPN ссылка",
        "config_file_label": "Файл конфигурации",
        "protocol_status": "Статус",
        "protocol_port": "Порт",
        "client_status": "Статус",
        "enabled_label": "включён",
        "disabled_label": "отключён",
        "traffic_label": "Трафик",
        "rx_label": "Входящий",
        "tx_label": "Исходящий",
        "connections_count": "Подключения",
        "create_new_connection": "Создать подключение",
        "connection_created_success": "Подключение успешно создано.",
        "role_label": "Роль",
        "enabled_status": "Включён",
        "email_label": "Email",
        "tg_id_label": "Telegram ID",
        "description_label": "Описание",
        "protocol_display": "Протокол",
    },
}


# ----------------------------------------------------------------------- #
#  Public lifecycle
# ----------------------------------------------------------------------- #
def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


def launch_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None, self_service_svc=None):
    global _bot_task
    _bot_task = asyncio.create_task(
        _run_bot(token, load_data_fn, generate_vpn_link_fn, save_data_fn, self_service_svc),
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


async def _set_default_commands(api: TelegramAPI):
    await api.call(
        "setMyCommands",
        commands=[
            {"command": "start", "description": "Open bot menu"},
            {"command": "connections", "description": "Show my connections"},
            {"command": "connect", "description": "Create a new connection"},
            {"command": "disconnect", "description": "Delete a connection"},
        ],
    )


# ----------------------------------------------------------------------- #
#  Generic helpers
# ----------------------------------------------------------------------- #
def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))




def _tg_lang(from_user: Optional[dict]) -> str:
    code = str((from_user or {}).get("language_code") or "").lower()
    if code.startswith("ru"):
        return "ru"
    return "en"


def _tt(lang: str, key: str, **kwargs) -> str:
    text = TG_TRANSLATIONS.get(lang, TG_TRANSLATIONS["en"]).get(key, TG_TRANSLATIONS["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text


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


def _protocol_display_name(protocol: str) -> str:
    base = protocol_base(protocol)
    if base in SELF_SERVICE_PROTOCOLS:
        return self_service_protocol_display_name(protocol)
    name = _EXTRA_PROTOCOL_DISPLAY_NAMES.get(base, base)
    idx = protocol_instance(protocol)
    return name if idx <= 1 else f"{name} #{idx}"


def _find_user(load_data_fn: Callable, tg_id: str, username: Optional[str] = None):
    data = load_data_fn()
    tg_id_clean = str(tg_id).lstrip("@")
    for u in data.get("users", []):
        stored = str(u.get("telegramId", "") or "").lstrip("@")
        if stored and stored == tg_id_clean:
            return u
    return None


def _pending_key(chat_id, from_id) -> str:
    return f"{chat_id}:{from_id}"


def _is_private_chat(chat: Optional[dict]) -> bool:
    return (chat or {}).get("type", "private") == "private"


async def _reject_non_private(api: TelegramAPI, chat_id, lang: str = "en", callback_id: Optional[str] = None):
    if callback_id:
        await api.answer_callback(callback_id, "Use a private chat")
    await api.send_message(chat_id, "For security, use this command in a private chat with the bot.")


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


# ----------------------------------------------------------------------- #
#  Self-service helpers
# ----------------------------------------------------------------------- #
def _self_service_settings(data: dict) -> dict:
    return (data.get("settings") or {}).get("self_service") or {}


def _self_service_is_enabled(data: dict) -> bool:
    """Returns True if self-service is enabled globally in panel settings."""
    return bool(_self_service_settings(data).get("enabled", False))


def _self_service_telegram_enabled(data: dict) -> bool:
    """Returns True if self-service is enabled and Telegram channel is active."""
    ss = _self_service_settings(data)
    return bool(ss.get("enabled", False) and ss.get("telegram_enabled", False))


def _get_eligible_servers(data: dict, allowed_protocols=None) -> list:
    """Returns list of (server_id, server, available_protos) tuples for self-service."""
    if allowed_protocols is None:
        allowed_protocols = _self_service_settings(data).get("allowed_protocols", [])
    allowed_bases = sanitize_allowed_protocols(allowed_protocols)
    servers = data.get("servers", [])
    eligible = []
    for sid, server in enumerate(servers):
        if not server.get("self_service_enabled", False):
            continue
        available = server_self_service_protocols(server, allowed_bases)
        if available:
            eligible.append((sid, server, available))
    return eligible


def _user_create_server_keyboard(eligible, lang: str = "en") -> dict:
    rows = []
    for sid, server, protos in eligible:
        name = server.get("name") or server.get("host") or f"Server {sid + 1}"
        proto_text = ", ".join(self_service_protocol_display_name(p) for p in protos)
        rows.append([{"text": f"🖥 {name} ({proto_text})", "callback_data": _ref("user_create_server", {"sid": sid})}])
    rows.append([{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": "user_create_cancel"}])
    return {"inline_keyboard": rows}


def _build_connections_keyboard(conns: list, data: dict, lang: str = "en") -> dict:
    """Build inline keyboard where each button = one connection.
    When self-service is enabled, adds delete buttons for self-service connections
    and a 'Create connection' button."""
    rows = []
    servers = data.get("servers", [])
    ss_enabled = _self_service_telegram_enabled(data)
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = "Unknown"
        if isinstance(sid, int) and sid < len(servers):
            srv = servers[sid]
            server_name = srv.get("name") or srv.get("host", "Unknown")[:20]
        proto = c.get("protocol", "").upper()
        name = c.get("name", "Connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        row = [{"text": label, "callback_data": f"cfg:{c['id']}"}]
        if ss_enabled and c.get("created_by") == "self_service":
            row.append({"text": "🗑", "callback_data": _ref("user_delete", {"conn_id": c["id"], "name": name})})
        rows.append(row)
    if ss_enabled:
        rows.append([{"text": f"➕ {_tt(lang, 'btn_create_connection')}", "callback_data": "user_create"}])
    rows.append([{"text": f"🔄 {_tt(lang, 'btn_refresh_list')}", "callback_data": "refresh"}])
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


def _users_keyboard(data: dict, back_callback: str = "adm:menu", lang: str = "en") -> dict:
    rows = []
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f" {_user_label(user)}", "callback_data": _ref("user", {"uid": user.get("id")})}])
    rows.append([{"text": f"⬅️ {_tt(lang, 'btn_back')}", "callback_data": back_callback}])
    return {"inline_keyboard": rows}


def _assign_user_keyboard(data: dict, server_id: int, proto: str, name: str, lang: str = "en") -> dict:
    rows = [[{"text": f"🚫 {_tt(lang, 'btn_do_not_assign')}", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": None})}]]
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f" {_user_label(user)}", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": user.get("id")})}])
    rows.append([{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}])
    return {"inline_keyboard": rows}


def _admin_main_keyboard(lang: str = "en") -> dict:
    return {
        "inline_keyboard": [
            [{"text": f"🖥 {_tt(lang, 'btn_servers')}", "callback_data": "adm:servers"}],
            [{"text": f"👤 {_tt(lang, 'btn_users')}", "callback_data": "adm:users"}],
            [{"text": f"🔐 {_tt(lang, 'btn_my_connections')}", "callback_data": "adm:myconns"}],
            [{"text": f"➕ {_tt(lang, 'btn_how_add_server')}", "callback_data": "adm:addserver_help"}],
        ]
    }


def _server_keyboard(data: dict, lang: str = "en") -> dict:
    rows = []
    for sid, srv in enumerate(data.get("servers", [])):
        name = srv.get("name") or srv.get("host") or f"Server {sid + 1}"
        rows.append([{"text": f"🖥 {name}", "callback_data": f"srv:{sid}"}])
    rows.append([{"text": f"⬅️ {_tt(lang, 'btn_admin_menu')}", "callback_data": "adm:menu"}])
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


def _protocol_status_text(info: dict, lang: str = "en") -> str:
    if info.get("status_error"):
        return "unknown ⚪"
    running = info.get("container_running")
    if running is True:
        return "running 🟢"
    if running is False:
        return "stopped 🔴"
    return "unknown ⚪"


def _protocols_keyboard(server_id: int, server: dict, lang: str = "en") -> dict:
    rows = []
    protocols = server.get("protocols", {}) or {}
    for proto, info in protocols.items():
        installed = "✅" if info.get("installed", True) else ""
        rows.append([{"text": f"{installed}{_protocol_status_icon(info)} {_protocol_display_name(proto)}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}])
    if not rows:
        rows.append([{"text": _tt(lang, "btn_no_installed_protocols"), "callback_data": f"noop"}])
    rows.append([{"text": f"️ {_tt(lang, 'btn_servers')}", "callback_data": "adm:servers"}])
    return {"inline_keyboard": rows}


def _protocol_keyboard(server_id: int, proto: str, proto_info: dict, lang: str = "en") -> dict:
    base = protocol_base(proto)
    rows = []
    if base in SELF_SERVICE_PROTOCOLS:
        rows.append([{"text": f" {_tt(lang, 'btn_connections')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}])
        rows.append([{"text": f" {_tt(lang, 'btn_create_connection')}", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}])
    is_running = proto_info.get("container_running") is True
    rows.append([{"text": f"Stop" if is_running else f"Start", "callback_data": _ref("toggle_proto", {"sid": server_id, "proto": proto, "start": not is_running})}])
    rows.append([{"text": f" {_tt(lang, 'btn_protocols')}", "callback_data": f"srv:{server_id}"}])
    return {"inline_keyboard": rows}


def _client_keyboard(server_id: int, proto: str, client: dict, lang: str = "en") -> dict:
    client_id = client.get("clientId") or client.get("client_id") or client.get("id") or ""
    enabled = client.get("enabled")
    if enabled is None:
        enabled = client.get("isEnabled")
    enabled = bool(enabled) if enabled is not None else True
    return {
        "inline_keyboard": [
            [{"text": f" {_tt(lang, 'btn_config')}", "callback_data": _ref("client_cfg", {"sid": server_id, "proto": proto, "client_id": client_id, "name": client.get("name") or client.get("username") or "Connection"})}],
            [{"text": f"Disable" if enabled else f"Enable", "callback_data": _ref("toggle_client", {"sid": server_id, "proto": proto, "client_id": client_id, "enable": not enabled})}],
            [{"text": f" {_tt(lang, 'btn_delete')}", "callback_data": _ref("remove_client", {"sid": server_id, "proto": proto, "client_id": client_id})}],
            [{"text": f" {_tt(lang, 'btn_connections')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}],
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
    from managers.exit_manager import ExitManager

    ssh = SSHManager(
        server["host"],
        server.get("ssh_port", 22),
        server["username"],
        server.get("password", ""),
        server.get("private_key", ""),
    )
    base = protocol_base(proto)
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
    elif base == "exit":
        manager = ExitManager(ssh, proto)
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
    tg_username = msg["from"].get("username")
    first_name = msg["from"].get("first_name", "")
    lang = _tg_lang(msg["from"])

    panel_user = _find_user(load_data_fn, tg_id, tg_username)

    if not panel_user:
        await api.send_message(
            chat_id,
            f"👋 {_tt(lang, 'hi')}, <b>{_e(first_name)}</b>!\n\n"
            f"{_tt(lang, 'account_not_linked')}\n"
            f"{_tt(lang, 'contact_admin_to_link')}\n\n"
            f"{_tt(lang, 'your_telegram_id')}: <code>{_e(tg_id)}</code>",
        )
        return

    if _is_admin(panel_user):
        await api.send_message(
            chat_id,
            f"👋 {_tt(lang, 'hi')}, <b>{_e(first_name)}</b>!\n\n"
            f"{_tt(lang, 'registered_admin', username=_e(panel_user.get('username')))}\n"
            f"{_tt(lang, 'choose_action')}",
            reply_markup=_admin_main_keyboard(lang),
        )
        return

    await _send_user_connections(api, chat_id, panel_user, load_data_fn, first_name=first_name, lang=lang)


async def _send_user_connections(api: TelegramAPI, chat_id: int, panel_user: dict, load_data_fn: Callable, first_name: str = "", lang: str = "en"):
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]

    if not conns:
        greeting = f"👋 {_tt(lang, 'hi')}, <b>{_e(first_name)}</b>!\n\n" if first_name else ""
        if _self_service_telegram_enabled(data):
            kb = _build_connections_keyboard(conns, data, lang)
            await api.send_message(
                chat_id,
                greeting + f"{_tt(lang, 'registered_as', username=_e(panel_user.get('username')))}.\n\n"
                f"{_tt(lang, 'no_connections_create')}",
                reply_markup=kb,
            )
        else:
            await api.send_message(
                chat_id,
                greeting + f"{_tt(lang, 'registered_as', username=_e(panel_user.get('username')))}.\n\n"
                f"{_tt(lang, 'no_connections_contact_admin')}",
            )
        return

    kb = _build_connections_keyboard(conns, data, lang)
    greeting = f"👋 {_tt(lang, 'hi')}, <b>{_e(first_name)}</b>!\n\n" if first_name else ""
    await api.send_message(
        chat_id,
        greeting + f"{_tt(lang, 'registered_as', username=_e(panel_user.get('username')))}.\n\n"
        f"{_tt(lang, 'your_connections', count=len(conns))}",
        reply_markup=kb,
    )


async def _handle_refresh(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, lang: str = "en"):
    await api.answer_callback(callback_id, _tt(lang, "updated"))
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]
    if not conns:
        if _self_service_telegram_enabled(data):
            kb = _build_connections_keyboard(conns, data, lang)
            await api.edit_message(chat_id, message_id, _tt(lang, "no_connections_create_short"), reply_markup=kb)
        else:
            await api.edit_message(chat_id, message_id, _tt(lang, "no_connections"))
        return
    kb = _build_connections_keyboard(conns, data, lang)
    await api.edit_message(chat_id, message_id, _tt(lang, "your_connections", count=len(conns)), reply_markup=kb)


async def _handle_get_config(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, conn_id: str, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, generate_vpn_link_fn: Callable, lang: str = "en"):
    await api.answer_callback(callback_id, _tt(lang, "fetching_config"))

    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.send_message(chat_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    data = load_data_fn()
    conn = next((c for c in data.get("user_connections", []) if c.get("id") == conn_id and (_is_admin(panel_user) or c.get("user_id") == panel_user.get("id"))), None)
    if not conn:
        await api.send_message(chat_id, f"❌ {_tt(lang, 'connection_not_found')}")
        return

    servers = data.get("servers", [])
    sid = conn.get("server_id")
    if not isinstance(sid, int) or sid >= len(servers):
        await api.send_message(chat_id, f"❌ {_tt(lang, 'server_not_found')}")
        return

    await _send_config_by_client(api, chat_id, servers[sid], conn.get("protocol", "awg"), conn.get("client_id"), conn.get("name", "Connection"), generate_vpn_link_fn, lang)


async def _send_config_by_client(api: TelegramAPI, chat_id: int, server: dict, proto: str, client_id: str, conn_name: str, generate_vpn_link_fn: Callable, lang: str = "en"):
    loading_result = await api.send_message(chat_id, _tt(lang, "fetching_config_for", name=_e(conn_name)))
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
                await api.edit_message(chat_id, loading_msg_id, f"❌ {_tt(lang, 'failed_retrieve_config')}")
            return

        if loading_msg_id:
            await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)

        server_name = server.get("name") or server.get("host", "Unknown")
        await api.send_message(chat_id, f"✅ <b>{_e(conn_name)}</b>\n🌐 {_tt(lang, 'servers_title')}: <b>{_e(server_name)}</b>\n🔌 {_tt(lang, 'protocol_label')}: <b>{_e(proto.upper())}</b>")

        is_link_proto = protocol_base(proto) in ("xray", "telemt")
        if is_link_proto:
            await api.send_message(chat_id, f"🔗 <b>{_tt(lang, 'connection_link_label')}</b> (tap to copy):\n<code>{_e(config)}</code>")
        else:
            MAX_LEN = 4000
            if len(config) <= MAX_LEN:
                await api.send_message(chat_id, f"<b>📄 {_tt(lang, 'config_label')}:</b>\n<pre>{_e(config)}</pre>")
            else:
                chunks = [config[i:i + MAX_LEN] for i in range(0, len(config), MAX_LEN)]
                for i, chunk in enumerate(chunks, 1):
                    await api.send_message(chat_id, f"<b>📄 {_tt(lang, 'config_part', part=i, total=len(chunks))}:</b>\n<pre>{_e(chunk)}</pre>")

            vpn_link = generate_vpn_link_fn(config, server, proto) if config else ""
            if vpn_link:
                await api.send_message(chat_id, f"🔗 <b>{_tt(lang, 'vpn_link_label')}</b> (tap to copy):\n<code>{_e(vpn_link)}</code>")
            filename = f"{str(conn_name).replace(' ', '_')}.conf"
            await api.send_document(chat_id, filename=filename, content=config.encode("utf-8"), caption=f"📁 {_tt(lang, 'config_file_label')}: {conn_name}")
    except Exception as e:
        logger.exception("Bot: error getting config")
        if loading_msg_id:
            await api.edit_message(chat_id, loading_msg_id, f"❌ {_tt(lang, 'error')}: {_e(e)}")
        else:
            await api.send_message(chat_id, f"❌ {_tt(lang, 'error')}: {_e(e)}")


# ----------------------------------------------------------------------- #
#  Admin handlers
# ----------------------------------------------------------------------- #
def _require_admin(load_data_fn: Callable, tg_id: str, tg_username: Optional[str] = None):
    user = _find_user(load_data_fn, tg_id, tg_username)
    if not user or not _is_admin(user):
        return None
    return user


async def _handle_add_server_command(api: TelegramAPI, msg: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], lang: str = "en"):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    if not _require_admin(load_data_fn, tg_id):
        await api.send_message(chat_id, f"❌ {_tt(lang, 'access_denied')}")
        return
    if not save_data_fn:
        await api.send_message(chat_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return

    text = msg.get("text", "")
    parts = text.split(maxsplit=5)
    if len(parts) < 4:
        await api.send_message(
            chat_id,
            _tt(lang, "add_server_command"),
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
    await api.send_message(chat_id, _tt(lang, "server_added", name=_e(name), host=_e(host)))


async def _admin_servers(api: TelegramAPI, chat_id: int, message_id: Optional[int], load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    servers = data.get("servers", [])
    text = f"🖥 <b>{_tt(lang, 'servers_title')}</b> ({len(servers)})\n\n{_tt(lang, 'choose_a_server')}"
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=_server_keyboard(data, lang))
    else:
        await api.send_message(chat_id, text, reply_markup=_server_keyboard(data, lang))


async def _admin_users(api: TelegramAPI, chat_id: int, message_id: int, load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    users = data.get("users", [])
    await api.edit_message(chat_id, message_id, f"👤 <b>{_tt(lang, 'users_title')}</b> ({len(users)})\n\n{_tt(lang, 'choose_a_user')}", reply_markup=_users_keyboard(data, lang))


async def _admin_user_detail(api: TelegramAPI, chat_id: int, message_id: int, user_id: str, load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    user = next((u for u in data.get("users", []) if u.get("id") == user_id), None)
    if not user:
        await api.edit_message(chat_id, message_id, "❌ User not found.", reply_markup={"inline_keyboard": [[{"text": "⬅️ Users", "callback_data": "adm:users"}]]})
        return
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == user_id]
    lines = [
        f"👤 <b>{_e(user.get('username'))}</b>",
        f"{_tt(lang, 'role_label')}: <b>{_e(user.get('role', 'user'))}</b>",
        f"{_tt(lang, 'enabled_status')}: <b>{'yes ✅' if user.get('enabled', True) else 'no 🚫'}</b>",
        f"{_tt(lang, 'tg_id_label')}: <code>{_e(user.get('telegramId') or '-')}</code>",
        f"{_tt(lang, 'email_label')}: <code>{_e(user.get('email') or '-')}</code>",
        f"{_tt(lang, 'connections_count')}: <b>{len(conns)}</b>",
    ]
    if user.get("description"):
        lines.append(f"{_tt(lang, 'description_label')}: {_e(user.get('description'))}")
    rows = []
    servers = data.get("servers", [])
    for c in conns[:20]:
        sid = c.get("server_id")
        server_name = "Unknown"
        if isinstance(sid, int) and sid < len(servers):
            server_name = servers[sid].get("name") or servers[sid].get("host") or "Unknown"
        rows.append([{"text": f"🔐 {c.get('name', 'Connection')} · {c.get('protocol', '').upper()} · {server_name}", "callback_data": f"cfg:{c.get('id')}"}])
    rows.append([{"text": f"⬅️ {_tt(lang, 'btn_users')}", "callback_data": "adm:users"}])
    rows.append([{"text": f"⬅️ {_tt(lang, 'btn_admin_menu')}", "callback_data": "adm:menu"}])
    await api.edit_message(chat_id, message_id, "\n".join(lines), reply_markup={"inline_keyboard": rows})


async def _admin_server_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'server_not_found')}")
        return
    server = await _refresh_server_protocol_statuses_async(servers[server_id])
    protocols = server.get("protocols", {}) or {}
    text = (
        f"🖥 <b>{_e(server.get('name') or server.get('host'))}</b>\n"
        f"Host: <code>{_e(server.get('host'))}</code>\n"
        f"SSH: <code>{_e(server.get('username'))}@{_e(server.get('host'))}:{_e(server.get('ssh_port', 22))}</code>\n\n"
        f"<b>{_tt(lang, 'btn_protocols')}</b> ({len(protocols)}):"
    )
    await api.edit_message(chat_id, message_id, text, reply_markup=_protocols_keyboard(server_id, server, lang))


async def _admin_protocol_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'server_not_found')}")
        return
    server = await _refresh_server_protocol_statuses_async(servers[server_id])
    info = (server.get("protocols", {}) or {}).get(proto)
    if not info:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'protocol_not_found')}")
        return
    lines = [
        f" <b>{_e(_protocol_display_name(proto))}</b>",
        f"{_tt(lang, 'servers_title')}: <b>{_e(server.get('name') or server.get('host'))}</b>",
        f"{_tt(lang, 'protocol_status')}: <b>{_protocol_status_text(info, lang)}</b>",
    ]
    exit_link = info.get("exit_link") or {}
    if exit_link:
        lines.append(f"exit: <code>{_e(exit_link.get('exit_name'))}</code>"
                     + (f" ({_e(exit_link.get('stale'))})" if exit_link.get("stale") else ""))
    for key in ("port", "container_name", "domain", "site_url", "web_port", "mode", "subnet", "peers_count"):
        if info.get(key) not in (None, ""):
            lines.append(f"{_e(key)}: <code>{_e(info.get(key))}</code>")
    if info.get("status_error"):
        lines.append(f"status_error: <code>{_e(info.get('status_error'))}</code>")
    await api.edit_message(chat_id, message_id, "\n".join(lines), reply_markup=_protocol_keyboard(server_id, proto, info, lang))


async def _admin_toggle_protocol(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, start: bool, load_data_fn: Callable, lang: str = "en"):
    await api.edit_message(chat_id, message_id, f"⏳ {_tt(lang, 'updating_protocol')}")

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
        await _admin_protocol_detail(api, chat_id, message_id, server_id, proto, load_data_fn, lang)
    except Exception as e:
        logger.exception("Bot admin: protocol toggle failed")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'error')}: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _admin_clients(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, load_data_fn: Callable, lang: str = "en"):
    await api.edit_message(chat_id, message_id, f"⏳ {_tt(lang, 'loading_connections')}")

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
            await api.edit_message(chat_id, message_id, f"👥 {_tt(lang, 'no_connections_short')}", reply_markup={"inline_keyboard": [[{"text": f"➕ {_tt(lang, 'btn_create_connection')}", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}], [{"text": f"⬅️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})
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
            rows.append([{"text": f" {name}{assigned}{traffic}", "callback_data": _ref("client", {"sid": server_id, "proto": proto, "client_id": client_id, "name": name, "client": c})}])
        rows.append([{"text": f"➕ {_tt(lang, 'btn_create_connection')}", "callback_data": _ref("add_client", {"sid": server_id, "proto": proto})}])
        rows.append([{"text": f"⬅️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}])
        await api.edit_message(chat_id, message_id, f"👥 <b>{_e(_protocol_display_name(proto))} {_tt(lang, 'connections_count')}</b> ({len(clients)})", reply_markup={"inline_keyboard": rows})
    except Exception as e:
        logger.exception("Bot admin: load clients failed")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'error')}: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": f"️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _admin_client_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client: dict, lang: str = "en"):
    client_id = client.get("clientId") or client.get("client_id") or client.get("id") or ""
    name = _client_display_name(client)
    user_data = client.get("userData") or {}
    rx = user_data.get("dataReceivedBytes") or 0
    tx = user_data.get("dataSentBytes") or 0
    enabled = client.get("enabled")
    if enabled is None:
        enabled = client.get("isEnabled")
    enabled_text = f"{_tt(lang, 'enabled_label')} ✅" if (enabled is None or enabled) else f"{_tt(lang, 'disabled_label')} 🚫"
    text = (
        f"👤 <b>{_e(name)}</b>\n"
        f"{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto))}</b>\n"
        f"Client ID: <code>{_e(client_id)}</code>\n"
        f"{_tt(lang, 'client_status')}: <b>{enabled_text}</b>"
    )
    if user_data:
        text += f"\n{_tt(lang, 'traffic_label')}: <b>{_format_bytes(rx + tx)}</b>\n{_tt(lang, 'rx_label')}: {_format_bytes(rx)} · {_tt(lang, 'tx_label')}: {_format_bytes(tx)}"
    await api.edit_message(chat_id, message_id, text, reply_markup=_client_keyboard(server_id, proto, client, lang))


async def _admin_add_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, panel_user: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, lang: str = "en", tg_id: Optional[str] = None):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return
    _pending_inputs[_pending_key(chat_id, tg_id or panel_user.get('telegramId') or panel_user.get('id'))] = {
        "kind": "add_client_name",
        "sid": server_id,
        "proto": proto,
        "admin_user_id": panel_user.get("id"),
        "ts": time.time(),
    }
    await api.edit_message(
        chat_id,
        message_id,
        f"➕ <b>{_tt(lang, 'create_new_connection')}</b>\n\n"
        f"{_tt(lang, 'servers_title')}/{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto))}</b>\n\n"
        f"{_tt(lang, 'send_connection_name')}",
        reply_markup={"inline_keyboard": [[{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]},
    )


async def _admin_choose_client_user(api: TelegramAPI, chat_id: int, name: str, server_id: int, proto: str, load_data_fn: Callable, lang: str = "en"):
    data = load_data_fn()
    await api.send_message(
        chat_id,
        f"✅ {_tt(lang, 'connection_name_label')}: <b>{_e(name)}</b>\n\n"
        f"{_tt(lang, 'assign_to_user')}",
        reply_markup=_assign_user_keyboard(data, server_id, proto, name, lang),
    )


async def _admin_create_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, name: str, user_id: Optional[str], load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, lang: str = "en"):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return
    await api.edit_message(chat_id, message_id, f"⏳ {_tt(lang, 'creating_connection')}")

    def _create():
        data = load_data_fn()
        server = data["servers"][server_id]
        proto_info = (server.get("protocols", {}) or {}).get(proto, {})
        port = proto_info.get("port", "55424")
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            if protocol_base(proto) == "telemt":
                result = manager.add_client(proto, name, server["host"], port)
            elif protocol_base(proto) == "wireguard":
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
        assigned_text = f"\n{_tt(lang, 'assigned_to', username=_e(assigned_user.get('username')))}" if assigned_user else f"\n{_tt(lang, 'assigned_not_linked')}"
        await api.edit_message(chat_id, message_id, _tt(lang, "connection_created", name=_e(name)) + assigned_text)
        config = result.get("config")
        if config:
            await _send_config_text(api, chat_id, server, proto, name, config, generate_vpn_link_fn, lang)
        elif client_id:
            await _send_config_by_client(api, chat_id, server, proto, client_id, name, generate_vpn_link_fn, lang)
    except Exception as e:
        logger.exception("Bot admin: add client failed")
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'error')}: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _send_config_text(api: TelegramAPI, chat_id: int, server: dict, proto: str, conn_name: str, config: str, generate_vpn_link_fn: Callable, lang: str = "en"):
    await api.send_message(chat_id, f"✅ <b>{_e(conn_name)}</b>\n🌐 {_tt(lang, 'servers_title')}: <b>{_e(server.get('name') or server.get('host'))}</b>\n {_tt(lang, 'protocol_label')}: <b>{_e(proto.upper())}</b>")
    if protocol_base(proto) in ("xray", "telemt"):
        await api.send_message(chat_id, f"🔗 <b>{_tt(lang, 'connection_link_label')}</b>:\n<code>{_e(config)}</code>")
    else:
        await api.send_message(chat_id, f"<b>📄 Configuration:</b>\n<pre>{_e(config)}</pre>")
        vpn_link = generate_vpn_link_fn(config, server, proto) if config else ""
        if vpn_link:
            await api.send_message(chat_id, f" <b>{_tt(lang, 'vpn_link_label')}</b>:\n<code>{_e(vpn_link)}</code>")
        await api.send_document(chat_id, filename=f"{conn_name}.conf", content=config.encode("utf-8"), caption=f" {_tt(lang, 'config_file_label')}: {conn_name}")


async def _admin_toggle_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client_id: str, enable: bool, load_data_fn: Callable, lang: str = "en"):
    await api.edit_message(chat_id, message_id, f" {_tt(lang, 'updating_connection')}")

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
        await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'updated')}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_connections')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]})
    except Exception as e:
        logger.exception("Bot admin: toggle client failed")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'error')}: {_e(e)}")


async def _admin_remove_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client_id: str, load_data_fn: Callable, save_data_fn: Optional[Callable], lang: str = "en"):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return
    await api.edit_message(chat_id, message_id, f" {_tt(lang, 'removing_connection')}")

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
        await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'connection_removed')}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_connections')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]})
    except Exception as e:
        logger.exception("Bot admin: remove client failed")
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'error')}: {_e(e)}")


async def _handle_pending_input(api: TelegramAPI, msg: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, self_service_svc=None) -> bool:
    chat_id = msg["chat"]["id"]
    from_id = msg["from"]["id"]
    lang = _tg_lang(msg.get("from"))
    key = _pending_key(chat_id, from_id)
    state = _pending_inputs.get(key)
    if not state:
        return False

    text = (msg.get("text") or "").strip()
    if text.lower() in ("/cancel", "cancel"):
        _pending_inputs.pop(key, None)
        await api.send_message(chat_id, f"❌ {_tt(lang, 'action_cancelled')}", reply_markup=_admin_main_keyboard(lang))
        return True
    if text.startswith("/"):
        _pending_inputs.pop(key, None)
        return False

    if state.get("kind") == "add_client_name":
        panel_user = _require_admin(load_data_fn, str(msg["from"]["id"]), msg["from"].get("username"))
        if not panel_user:
            _pending_inputs.pop(key, None)
            await api.send_message(chat_id, f"❌ {_tt(lang, 'access_denied')}")
            return True
        name = text[:80].strip()
        if not name:
            await api.send_message(chat_id, _tt(lang, "name_empty"))
            return True
        _pending_inputs.pop(key, None)
        await _admin_choose_client_user(api, chat_id, name, int(state.get("sid", 0)), state.get("proto", "awg"), load_data_fn, lang)
        return True

    if state.get("kind") == "user_add_client_name":
        panel_user = _find_user(load_data_fn, str(msg["from"]["id"]), msg["from"].get("username"))
        if not panel_user:
            _pending_inputs.pop(key, None)
            await api.send_message(chat_id, f"❌ {_tt(lang, 'access_denied')}")
            return True
        name = text[:80].strip()
        if not name:
            await api.send_message(chat_id, _tt(lang, "name_empty"))
            return True
        _pending_inputs.pop(key, None)
        if not self_service_svc:
            await api.send_message(chat_id, f"❌ {_tt(lang, 'self_service_unavailable')}")
            return True
        data = load_data_fn()
        if not _self_service_telegram_enabled(data):
            await api.send_message(chat_id, _tt(lang, "self_service_creation_disabled"))
            return True
        sid = int(state.get("sid", 0))
        proto = state.get("proto", "awg")
        await _user_create_connection(api, chat_id, panel_user, sid, proto, name, load_data_fn, generate_vpn_link_fn, self_service_svc, lang)
        return True

    return False


# ----------------------------------------------------------------------- #
#  Self-service user create wizard
# ----------------------------------------------------------------------- #
async def _user_create_start(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, self_service_svc, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.answer_callback(callback_id)
        await api.edit_message(
            chat_id,
            message_id,
            _tt(lang, "self_service_disabled_contact"),
        )
        return

    eligible = _get_eligible_servers(data)
    if not eligible:
        await api.answer_callback(callback_id)
        await api.edit_message(
            chat_id,
            message_id,
            _tt(lang, "self_service_no_servers"),
        )
        return

    await api.answer_callback(callback_id)
    await api.edit_message(
        chat_id,
        message_id,
        f"➕ <b>{_tt(lang, 'btn_create_connection')}</b>\n\n{_tt(lang, 'choose_server')}",
        reply_markup=_user_create_server_keyboard(eligible, lang),
    )


async def _user_create_start_message(api: TelegramAPI, chat_id: int, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.send_message(chat_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.send_message(chat_id, _tt(lang, "self_service_disabled_contact"))
        return

    eligible = _get_eligible_servers(data)
    if not eligible:
        await api.send_message(chat_id, _tt(lang, "self_service_no_servers"))
        return

    await api.send_message(
        chat_id,
        f"➕ <b>{_tt(lang, 'btn_create_connection')}</b>\n\n{_tt(lang, 'choose_server')}",
        reply_markup=_user_create_server_keyboard(eligible, lang),
    )


async def _user_create_server(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], server_id: int, load_data_fn: Callable, self_service_svc, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    await api.answer_callback(callback_id)

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_disabled_contact"))
        return

    servers = data.get("servers", [])
    if server_id < 0 or server_id >= len(servers):
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'server_not_found')}")
        return

    server = servers[server_id]
    if not server.get("self_service_enabled", False):
        await api.edit_message(chat_id, message_id, _tt(lang, "server_not_self_service"))
        return

    allowed_bases = sanitize_allowed_protocols(_self_service_settings(data).get("allowed_protocols", []))
    available_protos = server_self_service_protocols(server, allowed_bases)
    if not available_protos:
        await api.edit_message(chat_id, message_id, _tt(lang, "no_protocols_available"))
        return

    server_name = server.get("name") or server.get("host") or f"Server {server_id + 1}"
    rows = []
    for proto in available_protos:
        rows.append([{"text": _protocol_display_name(proto), "callback_data": _ref("user_create_protocol", {"sid": server_id, "proto": proto})}])
    rows.append([{"text": f" {_tt(lang, 'btn_back')}", "callback_data": "user_create"}])

    await api.edit_message(
        chat_id,
        message_id,
        f" {_tt(lang, 'servers_title')}: <b>{_e(server_name)}</b>\n\n{_tt(lang, 'choose_protocol')}",
        reply_markup={"inline_keyboard": rows},
    )


async def _user_create_protocol(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], server_id: int, proto: str, load_data_fn: Callable, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    await api.answer_callback(callback_id)

    _pending_inputs[_pending_key(chat_id, tg_id)] = {
        "kind": "user_add_client_name",
        "sid": server_id,
        "proto": proto,
        "ts": time.time(),
    }

    await api.edit_message(
        chat_id,
        message_id,
        f"➕ <b>{_tt(lang, 'btn_create_connection')}</b>\n\n"
        f"{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto))}</b>\n\n"
        f"{_tt(lang, 'send_device_name')}\n"
        f"{_tt(lang, 'example_label')}: <code>Ivan iPhone</code>\n\n"
        f"{_tt(lang, 'cancel_instruction')}",
        reply_markup={"inline_keyboard": [[{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": "user_create_cancel"}]]},
    )


async def _user_create_cancel(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, lang: str = "en"):
    _pending_inputs.pop(_pending_key(chat_id, tg_id), None)
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'access_denied')}")
        return
    await api.answer_callback(callback_id)
    await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)


async def _user_delete(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], conn_id: str, name: str, load_data_fn: Callable, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    await api.answer_callback(callback_id)

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_disabled_contact"))
        return

    conn = next((c for c in data.get("user_connections", []) if c.get("id") == conn_id and c.get("user_id") == panel_user.get("id")), None)
    if not conn:
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'connection_not_found')}")
        return

    conn_name = conn.get("name") or name or "Connection"
    rows = [
        [{"text": f"🗑 {_tt(lang, 'btn_delete')}", "callback_data": _ref("user_delete_confirm", {"conn_id": conn_id})}],
        [{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": "refresh"}],
    ]
    await api.edit_message(
        chat_id,
        message_id,
        _tt(lang, "delete_connection_confirm", name=_e(conn_name)) + f"\n\n{_tt(lang, 'cannot_be_undone')}",
        reply_markup={"inline_keyboard": rows},
    )


async def _user_delete_confirm(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], conn_id: str, load_data_fn: Callable, self_service_svc, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    if not self_service_svc:
        await api.answer_callback(callback_id, text="Self-service not available")
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_unavailable"))
        return

    await api.answer_callback(callback_id)

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_disabled_contact"))
        return

    try:
        await self_service_svc.delete_user_connection(panel_user["id"], conn_id, "telegram")
    except Exception as e:
        logger.exception("Bot: self-service delete failed")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'error')}: {_tt(lang, 'self_service_unavailable')}")
        return

    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]
    if not conns:
        if _self_service_telegram_enabled(data):
            kb = _build_connections_keyboard(conns, data, lang)
            await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'connection_deleted')}\n\n{_tt(lang, 'no_connections_create_short')}", reply_markup=kb)
        else:
            await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'connection_deleted_no_connections')}")
        return
    kb = _build_connections_keyboard(conns, data, lang)
    await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'connection_deleted')}\n\n{_tt(lang, 'your_connections', count=len(conns))}", reply_markup=kb)


async def _user_add_client_final(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], server_id: int, proto: str, name: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, self_service_svc, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text="Access denied")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    if not self_service_svc:
        await api.answer_callback(callback_id, text="Self-service not available")
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_unavailable"))
        return

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.answer_callback(callback_id)
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_disabled_contact"))
        return

    await api.answer_callback(callback_id)

    clean_name = (name or "Connection").strip()[:80]
    await _user_create_connection(api, chat_id, panel_user, server_id, proto, clean_name, load_data_fn, generate_vpn_link_fn, self_service_svc, lang)


async def _user_create_connection(api: TelegramAPI, chat_id: int, panel_user: dict, server_id: int, proto: str, name: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, self_service_svc, lang: str = "en"):
    try:
        result = await self_service_svc.create_user_connection(panel_user["id"], server_id, proto, name, "telegram")

        loading_msg = await api.send_message(chat_id, _tt(lang, "creating_connection_named", name=_e(name)))
        loading_msg_id = loading_msg.get("result", {}).get("message_id")

        data = load_data_fn()
        servers = data.get("servers", [])
        if server_id < 0 or server_id >= len(servers):
            await api.edit_message(chat_id, loading_msg_id, f"❌ {_tt(lang, 'server_not_found')}")
            return
        server = servers[server_id]

        config = result.get("config", "")
        if config:
            if loading_msg_id:
                await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)
            await _send_config_text(api, chat_id, server, proto, name, config, generate_vpn_link_fn, lang)
        else:
            conn = result.get("connection", {})
            client_id = conn.get("client_id")
            if client_id:
                if loading_msg_id:
                    await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)
                await _send_config_by_client(api, chat_id, server, proto, client_id, name, generate_vpn_link_fn, lang)
            else:
                if loading_msg_id:
                    await api.edit_message(chat_id, loading_msg_id, f"✅ {_tt(lang, 'connection_created_success')}")
    except Exception as e:
        logger.exception("Bot: self-service create failed")
        await api.send_message(chat_id, f"❌ {_tt(lang, 'error')}: {_tt(lang, 'self_service_unavailable')}")


# ----------------------------------------------------------------------- #
#  Main polling loop and dispatcher
# ----------------------------------------------------------------------- #
async def _run_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None, self_service_svc=None):
    offset = 0
    logger.info("Telegram bot started (raw httpx polling).")

    async with httpx.AsyncClient() as client:
        api = TelegramAPI(token, client)

        me = await api.call("getMe")
        if not me.get("ok"):
            logger.error(f"Telegram bot: invalid token or API error: {me}")
            return
        logger.info(f"Telegram bot logged in as @{me['result']['username']}")
        await _set_default_commands(api)

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
                    await _dispatch(api, update, load_data_fn, generate_vpn_link_fn, save_data_fn, self_service_svc)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.exception(f"Telegram bot: error handling update {update['update_id']}: {e}")


async def _dispatch(api: TelegramAPI, update: dict, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None, self_service_svc=None):
    if "message" in update:
        msg = update["message"]
        text = msg.get("text", "")
        tg_username = msg["from"].get("username")
        lang = _tg_lang(msg["from"])
        chat_id = msg["chat"]["id"]
        if text.startswith(("/connections", "/connect", "/disconnect")) and not _is_private_chat(msg.get("chat")):
            await _reject_non_private(api, chat_id, lang)
            return
        if await _handle_pending_input(api, msg, load_data_fn, save_data_fn, generate_vpn_link_fn, self_service_svc):
            return
        if text.startswith("/start") or text.startswith("/admin"):
            await _handle_start(api, msg, load_data_fn)
        elif text.startswith("/connections"):
            panel_user = _find_user(load_data_fn, str(msg["from"]["id"]), tg_username)
            if not panel_user:
                await api.send_message(chat_id, f" {_tt(lang, 'access_denied')}")
            else:
                await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)
        elif text.startswith("/connect"):
            await _user_create_start_message(api, chat_id, str(msg["from"]["id"]), tg_username, load_data_fn, lang)
        elif text.startswith("/disconnect"):
            panel_user = _find_user(load_data_fn, str(msg["from"]["id"]), tg_username)
            if not panel_user:
                await api.send_message(chat_id, f" {_tt(lang, 'access_denied')}")
            else:
                await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)
        elif text.startswith("/servers"):
            if _require_admin(load_data_fn, str(msg["from"]["id"]), tg_username):
                await _admin_servers(api, msg["chat"]["id"], None, load_data_fn, lang)
            else:
                await api.send_message(msg["chat"]["id"], f" {_tt(lang, 'access_denied')}")
        elif text.startswith("/addserver"):
            await _handle_add_server_command(api, msg, load_data_fn, save_data_fn, lang)

    elif "callback_query" in update:
        cq = update["callback_query"]
        callback_id = cq["id"]
        data_str = cq.get("data", "")
        chat_id = cq["message"]["chat"]["id"]
        chat = cq["message"].get("chat", {})
        message_id = cq["message"]["message_id"]
        tg_id = str(cq["from"]["id"])
        tg_username = cq["from"].get("username")
        lang = _tg_lang(cq["from"])

        if data_str == "noop":
            await api.answer_callback(callback_id)
            return
        if data_str == "refresh":
            await _handle_refresh(api, chat_id, message_id, callback_id, tg_id, tg_username, load_data_fn, lang)
            return
        if data_str.startswith("cfg:"):
            if not _is_private_chat(chat):
                await _reject_non_private(api, chat_id, lang, callback_id)
                return
            await _handle_get_config(api, chat_id, message_id, callback_id, data_str[4:], tg_id, tg_username, load_data_fn, generate_vpn_link_fn, lang)
            return

        # Self-service user callbacks (before admin gate).
        if data_str == "user_create":
            if not _is_private_chat(chat):
                await _reject_non_private(api, chat_id, lang, callback_id)
                return
            await _user_create_start(api, chat_id, message_id, callback_id, tg_id, tg_username, load_data_fn, self_service_svc, lang)
            return
        if data_str == "user_create_cancel":
            await _user_create_cancel(api, chat_id, message_id, callback_id, tg_id, tg_username, load_data_fn, lang)
            return

        ref = _resolve_ref(data_str)
        if ref:
            action = ref.get("action")
            payload = ref.get("payload", {})
            if action == "user_create_server":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                await _user_create_server(api, chat_id, message_id, callback_id, tg_id, tg_username, int(payload.get("sid", 0)), load_data_fn, self_service_svc, lang)
                return
            if action == "user_create_protocol":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                await _user_create_protocol(api, chat_id, message_id, callback_id, tg_id, tg_username, int(payload.get("sid", 0)), payload.get("proto", "awg"), load_data_fn, lang)
                return
            if action == "user_add_client":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                await _user_add_client_final(api, chat_id, message_id, callback_id, tg_id, tg_username, int(payload.get("sid", 0)), payload.get("proto", "awg"), payload.get("name", ""), load_data_fn, generate_vpn_link_fn, self_service_svc, lang)
                return
            if action == "user_delete":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                await _user_delete(api, chat_id, message_id, callback_id, tg_id, tg_username, payload.get("conn_id", ""), payload.get("name", ""), load_data_fn, lang)
                return
            if action == "user_delete_confirm":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                await _user_delete_confirm(api, chat_id, message_id, callback_id, tg_id, tg_username, payload.get("conn_id", ""), load_data_fn, self_service_svc, lang)
                return

        panel_user = _require_admin(load_data_fn, tg_id, tg_username)
        if not panel_user:
            await api.answer_callback(callback_id, "Access denied")
            return

        await api.answer_callback(callback_id)

        if data_str == "adm:menu":
            await api.edit_message(chat_id, message_id, f"<b>{_tt(lang, 'admin_menu')}</b>", reply_markup=_admin_main_keyboard(lang))
        elif data_str == "adm:servers":
            await _admin_servers(api, chat_id, message_id, load_data_fn, lang)
        elif data_str == "adm:users":
            await _admin_users(api, chat_id, message_id, load_data_fn, lang)
        elif data_str == "adm:myconns":
            await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)
        elif data_str == "adm:addserver_help":
            await api.edit_message(
                chat_id,
                message_id,
                f"➕ <b>{_tt(lang, 'add_server_label')}</b>\n\n"
                f"{_tt(lang, 'add_server_command')}\n",
                reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_admin_menu')}", "callback_data": "adm:menu"}]]},
            )
        elif data_str.startswith("srv:"):
            await _admin_server_detail(api, chat_id, message_id, int(data_str.split(":", 1)[1]), load_data_fn, lang)
        else:
            ref = _resolve_ref(data_str)
            if not ref:
                await api.edit_message(chat_id, message_id, f" {_tt(lang, 'action_expired')}")
                return
            action = ref.get("action")
            payload = ref.get("payload", {})
            sid = int(payload.get("sid", 0) or 0)
            proto = payload.get("proto", "awg")
            if action == "user":
                await _admin_user_detail(api, chat_id, message_id, payload.get("uid"), load_data_fn, lang)
            elif action == "proto":
                await _admin_protocol_detail(api, chat_id, message_id, sid, proto, load_data_fn, lang)
            elif action == "toggle_proto":
                await _admin_toggle_protocol(api, chat_id, message_id, sid, proto, bool(payload.get("start")), load_data_fn, lang)
            elif action == "clients":
                await _admin_clients(api, chat_id, message_id, sid, proto, load_data_fn, lang)
            elif action == "client":
                await _admin_client_detail(api, chat_id, message_id, sid, proto, payload.get("client", {}), lang)
            elif action == "client_cfg":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                data = load_data_fn()
                server = data["servers"][sid]
                await _send_config_by_client(api, chat_id, server, proto, payload.get("client_id"), payload.get("name", "Connection"), generate_vpn_link_fn, lang)
            elif action == "add_client":
                await _admin_add_client(api, chat_id, message_id, sid, proto, panel_user, load_data_fn, save_data_fn, generate_vpn_link_fn, lang, tg_id)
            elif action == "create_client":
                await _admin_create_client(api, chat_id, message_id, sid, proto, payload.get("name", "Connection"), payload.get("user_id"), load_data_fn, save_data_fn, generate_vpn_link_fn, lang)
            elif action == "toggle_client":
                await _admin_toggle_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), bool(payload.get("enable")), load_data_fn, lang)
            elif action == "remove_client":
                await _admin_remove_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), load_data_fn, save_data_fn, lang)
