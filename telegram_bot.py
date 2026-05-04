"""
Telegram bot for Amnezia Web Panel.
Uses raw Telegram Bot API via httpx — no library version conflicts.
Runs as a background asyncio task alongside the FastAPI app.
"""
import asyncio
import logging
from typing import Optional, Callable

import httpx

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------- #
#  Global state
# ----------------------------------------------------------------------- #
_bot_task: Optional[asyncio.Task] = None


def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


def launch_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable):
    global _bot_task
    _bot_task = asyncio.create_task(
        _run_bot(token, load_data_fn, generate_vpn_link_fn),
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
        return (await self.call("sendMessage", **params))

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
#  Helpers
# ----------------------------------------------------------------------- #
def _find_user(load_data_fn: Callable, tg_id: str):
    data = load_data_fn()
    tg_id_clean = str(tg_id).lstrip("@")
    for u in data.get("users", []):
        stored = str(u.get("telegramId", "") or "").lstrip("@")
        if stored and stored == tg_id_clean:
            return u
    return None


def _build_connections_keyboard(conns: list, data: dict) -> dict:
    """Build inline keyboard where each button = one connection."""
    rows = []
    servers = data.get("servers", [])
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = "Unknown"
        if sid < len(servers):
            srv = servers[sid]
            server_name = srv.get("name") or srv.get("host", "Unknown")[:20]
        proto = c.get("protocol", "").upper()
        name = c.get("name", "Connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        # callback_data must be ≤ 64 bytes — use short prefix
        rows.append([{"text": label, "callback_data": f"cfg:{c['id']}"}])
    rows.append([{"text": "🔄 Обновить список", "callback_data": "refresh"}])
    return {"inline_keyboard": rows}


# ----------------------------------------------------------------------- #
#  /start handler — shows connections list immediately
# ----------------------------------------------------------------------- #
async def _handle_start(api: TelegramAPI, msg: dict, load_data_fn: Callable):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    first_name = msg["from"].get("first_name", "")

    panel_user = _find_user(load_data_fn, tg_id)

    if not panel_user:
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{first_name}</b>!\n\n"
            "Your Telegram account is not linked to any panel user.\n"
            "Please contact your administrator — they need to add your Telegram ID to your profile.\n\n"
            f"Your Telegram ID: <code>{tg_id}</code>",
        )
        return

    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == panel_user["id"]]

    if not conns:
        await api.send_message(
            chat_id,
            f"👋 Hi, <b>{first_name}</b>!\n\n"
            f"You are registered as <b>{panel_user['username']}</b>.\n\n"
            "You have no connections yet. Please contact your administrator.",
        )
        return

    kb = _build_connections_keyboard(conns, data)
    await api.send_message(
        chat_id,
        f"👋 Hi, <b>{first_name}</b>!\n\n"
        f"You are registered as <b>{panel_user['username']}</b>.\n\n"
        f"<b>Your connections</b> ({len(conns)}) — tap to get config:",
        reply_markup=kb,
    )


# ----------------------------------------------------------------------- #
#  Refresh — edit existing message with updated list
# ----------------------------------------------------------------------- #
async def _handle_refresh(
    api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, load_data_fn: Callable
):
    await api.answer_callback(callback_id, "Updated!")
    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.edit_message(chat_id, message_id, "❌ Access denied.")
        return
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == panel_user["id"]]
    if not conns:
        await api.edit_message(chat_id, message_id, "You have no connections.")
        return
    kb = _build_connections_keyboard(conns, data)
    await api.edit_message(
        chat_id, message_id,
        f"<b>Your connections</b> ({len(conns)}) — tap to get config:",
        reply_markup=kb,
    )


# ----------------------------------------------------------------------- #
#  Get config — send multiple messages with different formats
# ----------------------------------------------------------------------- #
async def _handle_get_config(
    api: TelegramAPI,
    chat_id: int,
    message_id: int,
    callback_id: str,
    conn_id: str,
    tg_id: str,
    load_data_fn: Callable,
    generate_vpn_link_fn: Callable,
):
    await api.answer_callback(callback_id, "Fetching config...")

    panel_user = _find_user(load_data_fn, tg_id)
    if not panel_user:
        await api.send_message(chat_id, "❌ Access denied.")
        return

    data = load_data_fn()
    conn = next(
        (c for c in data.get("user_connections", [])
         if c["id"] == conn_id and c["user_id"] == panel_user["id"]),
        None,
    )
    if not conn:
        await api.send_message(chat_id, "❌ Connection not found.")
        return

    sid = conn["server_id"]
    servers = data.get("servers", [])
    if sid >= len(servers):
        await api.send_message(chat_id, "❌ Server not found.")
        return

    server = servers[sid]
    proto = conn.get("protocol", "awg")
    conn_name = conn.get("name", "Connection")

    # Send "Loading..." as new message
    loading_result = await api.send_message(chat_id, f"⏳ Fetching config for <b>{conn_name}</b>...")
    loading_msg_id = loading_result.get("result", {}).get("message_id")

    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from managers.ssh_manager import SSHManager
        from managers.awg_manager import AWGManager
        from managers.xray_manager import XrayManager

        ssh = SSHManager(
            server["host"],
            server.get("ssh_port", 22),
            server["username"],
            server.get("password", ""),
            server.get("private_key", ""),
        )

        proto_info = server.get("protocols", {}).get(proto, {})
        port = proto_info.get("port", "55424")

        def _get_cfg():
            ssh.connect()
            from managers.wireguard_manager import WireGuardManager
            from managers.telemt_manager import TelemtManager

            if proto == "xray":
                mgr = XrayManager(ssh)
                cfg = mgr.get_client_config(proto, conn["client_id"], server["host"], port)
            elif proto == "wireguard":
                mgr = WireGuardManager(ssh)
                cfg = mgr.get_client_config(conn["client_id"], server["host"])
            elif proto == "telemt":
                mgr = TelemtManager(ssh)
                cfg = mgr.get_client_config(proto, conn["client_id"], server["host"], port)
            else:
                # awg, awg2, awg_legacy
                mgr = AWGManager(ssh)
                cfg = mgr.get_client_config(proto, conn["client_id"], server["host"], port)
            ssh.disconnect()
            return cfg

        config = await asyncio.to_thread(_get_cfg)

        if not config:
            if loading_msg_id:
                await api.edit_message(chat_id, loading_msg_id, "❌ Failed to retrieve configuration.")
            return

        vpn_link = generate_vpn_link_fn(config) if config else ""

        # Delete loading message
        if loading_msg_id:
            await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)

        # ------- 1. Header -------
        server_name = server.get("name") or server.get("host", "Unknown")
        await api.send_message(
            chat_id,
            f"✅ <b>{conn_name}</b>\n"
            f"🌐 Server: <b>{server_name}</b>\n"
            f"🔌 Protocol: <b>{proto.upper()}</b>",
        )

        # ------- 2. Send config (format depends on protocol) -------
        # Protocols that return a link/URI rather than an INI-style config file
        is_link_proto = proto in ("xray", "telemt")

        if is_link_proto:
            # Show as a tappable link — no .conf file needed
            await api.send_message(
                chat_id,
                f"🔗 <b>Connection link</b> (tap to copy):\n<code>{config}</code>",
            )
        else:
            # AWG / WireGuard — INI config text
            MAX_LEN = 4000
            if len(config) <= MAX_LEN:
                await api.send_message(chat_id, f"<b>📄 Configuration:</b>\n<pre>{config}</pre>")
            else:
                chunks = [config[i:i+MAX_LEN] for i in range(0, len(config), MAX_LEN)]
                for i, chunk in enumerate(chunks, 1):
                    await api.send_message(chat_id, f"<b>📄 Configuration (part {i}/{len(chunks)}):</b>\n<pre>{chunk}</pre>")

            # VPN deep-link (vpn:// base64 URI for the Amnezia app)
            vpn_link = generate_vpn_link_fn(config)
            if vpn_link:
                await api.send_message(
                    chat_id,
                    f"🔗 <b>VPN Link</b> (tap to copy):\n<code>{vpn_link}</code>",
                )

            # .conf file attachment
            filename = f"{conn_name.replace(' ', '_')}.conf"
            await api.send_document(
                chat_id,
                filename=filename,
                content=config.encode("utf-8"),
                caption=f"📁 Config file: {conn_name}",
            )

    except Exception as e:
        logger.exception("Bot: error getting config")
        if loading_msg_id:
            await api.edit_message(chat_id, loading_msg_id, f"❌ Error: {e}")
        else:
            await api.send_message(chat_id, f"❌ Error: {e}")


# ----------------------------------------------------------------------- #
#  Main polling loop
# ----------------------------------------------------------------------- #
async def _run_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable):
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
                    await _dispatch(api, update, load_data_fn, generate_vpn_link_fn)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.exception(f"Telegram bot: error handling update {update['update_id']}: {e}")


async def _dispatch(api: TelegramAPI, update: dict, load_data_fn: Callable, generate_vpn_link_fn: Callable):
    # --- Text messages ---
    if "message" in update:
        msg = update["message"]
        text = msg.get("text", "")
        if text.startswith("/start"):
            await _handle_start(api, msg, load_data_fn)
        elif text.startswith("/connections"):
            # Alias for /start
            await _handle_start(api, msg, load_data_fn)

    # --- Inline button callbacks ---
    elif "callback_query" in update:
        cq = update["callback_query"]
        callback_id = cq["id"]
        data_str = cq.get("data", "")
        chat_id = cq["message"]["chat"]["id"]
        message_id = cq["message"]["message_id"]
        tg_id = str(cq["from"]["id"])

        if data_str == "refresh":
            await _handle_refresh(api, chat_id, message_id, callback_id, tg_id, load_data_fn)
        elif data_str.startswith("cfg:"):
            conn_id = data_str[4:]
            await _handle_get_config(
                api, chat_id, message_id, callback_id,
                conn_id, tg_id, load_data_fn, generate_vpn_link_fn
            )
