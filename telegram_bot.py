"""
Telegram bot for Amnezia Web Panel.
Uses raw Telegram Bot API via httpx — no library version conflicts.
Runs as a background asyncio task alongside the FastAPI app.
"""
from peer_accounting import serialize_peer_lifecycle
from protocol_names import server_protocol_names
import asyncio
import hashlib
import html
import logging
import os
import shlex
import sys
import secrets
import time
import urllib.parse
import uuid
from datetime import datetime
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
        "account_disabled": "Account disabled",
        "account_not_linked": "Your Telegram account is not linked to any panel user.",
        "contact_admin_to_link": "Please contact your administrator — they need to add your Telegram ID to your profile.",
        "your_telegram_id": "Your Telegram ID",
        "registered_admin": "You are registered as <b>{username}</b> with <b>Admin</b> role.",
        "choose_action": "Choose an action:",
        "registered_as": "You are registered as <b>{username}</b>.",
        "credentials_title": "Your panel account has been created.",
        "credentials_login": "Login",
        "credentials_password": "Password",
        "credentials_instructions": "To sign in, open {panel_url} in a browser and enter these credentials on the login page.",
        "credentials_no_url": "The panel address is not configured. Contact the administrator to get the correct login address.",
        "credentials_disabled": "Your account was created disabled. Contact the administrator to enable it before signing in.",
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
        "max_connections_reached": "You have reached your connection limit. Delete an existing connection or contact your administrator.",
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
        "cmd_start": "Open bot menu",
        "btn_open_panel": "Open Panel",
        "cmd_connections": "Show my connections",
        "cmd_connect": "Create a new connection",
        "cmd_disconnect": "Delete a connection",
        "private_chat_short": "Use a private chat",
        "private_chat_required": "For security, use this command in a private chat with the bot.",
        "status_unknown": "unknown",
        "status_running": "running",
        "status_stopped": "stopped",
        "default_server": "Server {number}",
        "default_unknown": "Unknown",
        "default_connection": "Connection",
        "default_user": "user",
        "disabled_suffix": "disabled",
        "yes_label": "yes",
        "no_label": "no",
        "tap_to_copy": "tap to copy",
        "host_label": "Host",
        "ssh_label": "SSH",
        "client_id_label": "Client ID",
        "exit_label": "Exit",
        "field_port": "Port",
        "field_container_name": "Container",
        "field_domain": "Domain",
        "field_site_url": "Site URL",
        "field_web_port": "Web port",
        "field_mode": "Mode",
        "field_subnet": "Subnet",
        "field_peers_count": "Peers",
        "status_error_label": "Status error",
        "container_name_unknown": "Container name is unknown",
        "container_not_found": "Container not found",
        "protocol_action_failed": "Failed to {action} the protocol container.",
        "language_prompt": "Choose language",
        "btn_language": "Language",
        "language_saved": "Language saved."
    },
    "fa": {
        "hi": "سلام",
        "account_disabled": "حساب کاربری غیرفعال است",
        "account_not_linked": "حساب تلگرام شما به هیچ‌یک از کاربران پنل پیوند داده نشده است.",
        "contact_admin_to_link": "لطفاً با مدیر تماس بگیرید؛ او باید شناسه تلگرام شما را به پروفایلتان اضافه کند.",
        "your_telegram_id": "شناسه تلگرام شما",
        "registered_admin": "شما با نام <b>{username}</b> و نقش <b>مدیر</b> ثبت شده‌اید.",
        "choose_action": "یک گزینه را انتخاب کنید:",
        "registered_as": "شما با نام <b>{username}</b> ثبت شده‌اید.",
        "credentials_title": "حساب پنل شما ایجاد شد.",
        "credentials_login": "نام کاربری",
        "credentials_password": "گذرواژه",
        "credentials_instructions": "برای ورود، {panel_url} را در مرورگر باز کنید و این اطلاعات را در صفحه ورود وارد کنید.",
        "credentials_no_url": "نشانی پنل تنظیم نشده است. برای دریافت نشانی صحیح ورود با مدیر تماس بگیرید.",
        "credentials_disabled": "حساب شما غیرفعال ایجاد شده است. پیش از ورود، برای فعال‌سازی با مدیر تماس بگیرید.",
        "no_connections_create": "هنوز اتصالی ندارید. برای ساخت اولین اتصال، دکمه زیر را بزنید!",
        "no_connections_contact_admin": "هنوز اتصالی ندارید. لطفاً با مدیر تماس بگیرید.",
        "your_connections": "<b>اتصال‌های شما</b> ({count}) — برای دریافت پیکربندی بزنید:",
        "updated": "به‌روزرسانی شد!",
        "access_denied": "دسترسی مجاز نیست.",
        "no_connections_create_short": "اتصالی ندارید. برای ساخت اولین اتصال، دکمه زیر را بزنید!",
        "no_connections": "اتصالی ندارید.",
        "fetching_config": "در حال دریافت پیکربندی...",
        "connection_not_found": "اتصال پیدا نشد.",
        "server_not_found": "سرور پیدا نشد.",
        "fetching_config_for": "در حال دریافت پیکربندی برای <b>{name}</b>...",
        "failed_retrieve_config": "دریافت پیکربندی ناموفق بود.",
        "admin_menu": "منوی مدیریت",
        "action_expired": "این عملیات منقضی شده است. دوباره /start را اجرا کنید.",
        "btn_create_connection": "ساخت اتصال",
        "btn_refresh_list": "به‌روزرسانی فهرست",
        "btn_back": "بازگشت",
        "btn_do_not_assign": "اختصاص نده",
        "btn_cancel": "لغو",
        "btn_servers": "سرورها",
        "btn_users": "کاربران",
        "btn_my_connections": "اتصال‌های من",
        "btn_how_add_server": "روش افزودن سرور",
        "btn_admin_menu": "منوی مدیریت",
        "btn_no_installed_protocols": "هیچ پروتکلی نصب نیست",
        "btn_connections": "اتصال‌ها",
        "btn_stop": "توقف",
        "btn_start": "راه‌اندازی",
        "btn_protocols": "پروتکل‌ها",
        "btn_config": "پیکربندی",
        "btn_disable": "غیرفعال‌سازی",
        "btn_enable": "فعال‌سازی",
        "btn_delete": "حذف",
        "btn_protocol": "پروتکل",
        "choose_server": "یک سرور انتخاب کنید:",
        "choose_protocol": "یک پروتکل انتخاب کنید:",
        "protocol_label": "پروتکل",
        "send_device_name": "نام دستگاه را در پیام بعدی بفرستید.",
        "cancel_instruction": "برای لغو، <code>/cancel</code> را بفرستید.",
        "example_label": "نمونه",
        "delete_connection_confirm": "اتصال <b>{name}</b> حذف شود؟",
        "cannot_be_undone": "این عملیات قابل بازگشت نیست.",
        "connection_deleted": "اتصال حذف شد.",
        "connection_deleted_no_connections": "اتصال حذف شد. دیگر اتصالی ندارید.",
        "connection_created_no_config": "اتصال ساخته شد، اما پیکربندی در دسترس نیست.",
        "creating_connection_named": "در حال ساخت اتصال <b>{name}</b>...",
        "self_service_creation_disabled": "ساخت اتصال به‌صورت سلف‌سرویس در حال حاضر غیرفعال است.\nلطفاً با مدیر تماس بگیرید.",
        "self_service_no_servers": "هیچ سروری برای ساخت اتصال به‌صورت سلف‌سرویس در دسترس نیست.\nلطفاً با مدیر تماس بگیرید.",
        "self_service_disabled_contact": "سلف‌سرویس غیرفعال است. با مدیر تماس بگیرید.",
        "self_service_unavailable": "سلف‌سرویس در دسترس نیست.",
        "max_connections_reached": "به سقف تعداد اتصال‌ها رسیده‌اید. برای ادامه یک اتصال قبلی را حذف کنید یا با مدیر تماس بگیرید.",
        "server_not_self_service": "این سرور برای سلف‌سرویس در دسترس نیست.",
        "no_protocols_available": "هیچ پروتکلی روی این سرور در دسترس نیست.",
        "name_empty": "نام نمی‌تواند خالی باشد. نام اتصال یا /cancel را بفرستید.",
        "error": "خطا",
        "saving_not_available": "ذخیره‌سازی در این نمونه ربات در دسترس نیست.",
        "servers_title": "سرورها",
        "choose_a_server": "یک سرور انتخاب کنید:",
        "users_title": "کاربران",
        "choose_a_user": "یک کاربر انتخاب کنید:",
        "user_not_found": "کاربر پیدا نشد.",
        "protocol_not_found": "پروتکل پیدا نشد.",
        "updating_protocol": "در حال به‌روزرسانی کانتینر پروتکل...",
        "loading_connections": "در حال بارگیری اتصال‌ها...",
        "no_connections_short": "اتصالی وجود ندارد.",
        "creating_connection": "در حال ساخت اتصال...",
        "updating_connection": "در حال به‌روزرسانی اتصال...",
        "removing_connection": "در حال حذف اتصال...",
        "connection_removed": "اتصال حذف شد.",
        "action_cancelled": "عملیات لغو شد.",
        "add_server_label": "افزودن سرور",
        "add_server_command": "از این دستور استفاده کنید:\n<code>/addserver host username password [ssh_port] [name]</code>\n\nنمونه:\n<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n⚠️ پیام‌های تلگرام ابزار مدیریت اسرار نیستند. در صورت امکان، سرورها را از طریق پنل وب اضافه کنید.",
        "server_added": "سرور اضافه شد: <b>{name}</b>\nمیزبان: <code>{host}</code>",
        "server_config": "پیکربندی",
        "send_connection_name": "نام اتصال را در پیام بعدی بفرستید.\nنمونه: <code>Ivan iPhone</code>\n\nبرای لغو، <code>/cancel</code> را بفرستید.",
        "connection_name_label": "نام اتصال",
        "assign_to_user": "این اتصال به یک کاربر پنل اختصاص داده شود؟",
        "connection_created": "اتصال ساخته شد: <b>{name}</b>",
        "assigned_to": "اختصاص داده شد به: <b>{username}</b>",
        "assigned_not_linked": "اختصاص: <b>پیوند داده نشده</b>",
        "config_label": "پیکربندی",
        "connection_link_label": "لینک اتصال",
        "config_part": "پیکربندی (بخش {part}/{total}):",
        "vpn_link_label": "لینک VPN",
        "config_file_label": "فایل پیکربندی",
        "protocol_status": "وضعیت",
        "protocol_port": "پورت",
        "client_status": "وضعیت",
        "enabled_label": "فعال",
        "disabled_label": "غیرفعال",
        "traffic_label": "ترافیک",
        "rx_label": "RX",
        "tx_label": "TX",
        "connections_count": "اتصال‌ها",
        "create_new_connection": "ساخت اتصال",
        "connection_created_success": "اتصال با موفقیت ساخته شد.",
        "role_label": "نقش",
        "enabled_status": "فعال",
        "email_label": "ایمیل",
        "tg_id_label": "شناسه تلگرام",
        "description_label": "توضیحات",
        "protocol_display": "پروتکل",
        "cmd_start": "باز کردن منوی ربات",
        "btn_open_panel": "باز کردن پنل",
        "cmd_connections": "نمایش اتصال‌های من",
        "cmd_connect": "ساخت اتصال جدید",
        "cmd_disconnect": "حذف یک اتصال",
        "private_chat_short": "از گفت‌وگوی خصوصی استفاده کنید",
        "private_chat_required": "برای امنیت، این دستور را در گفت‌وگوی خصوصی با ربات اجرا کنید.",
        "status_unknown": "نامشخص",
        "status_running": "در حال اجرا",
        "status_stopped": "متوقف",
        "default_server": "سرور {number}",
        "default_unknown": "نامشخص",
        "default_connection": "اتصال",
        "default_user": "کاربر",
        "disabled_suffix": "غیرفعال",
        "yes_label": "بله",
        "no_label": "خیر",
        "tap_to_copy": "برای کپی بزنید",
        "host_label": "میزبان",
        "ssh_label": "SSH",
        "client_id_label": "شناسه کلاینت",
        "exit_label": "خروج",
        "field_port": "پورت",
        "field_container_name": "کانتینر",
        "field_domain": "دامنه",
        "field_site_url": "نشانی سایت",
        "field_web_port": "پورت وب",
        "field_mode": "حالت",
        "field_subnet": "زیرشبکه",
        "field_peers_count": "همتاها",
        "status_error_label": "خطای وضعیت",
        "container_name_unknown": "نام کانتینر نامشخص است",
        "container_not_found": "کانتینر پیدا نشد",
        "protocol_action_failed": "{action} کانتینر پروتکل ناموفق بود.",
        "language_prompt": "زبان را انتخاب کنید",
        "btn_language": "زبان",
        "language_saved": "زبان ذخیره شد."
    },
    "fr": {
        "hi": "Bonjour",
        "account_disabled": "Compte désactivé",
        "account_not_linked": "Votre compte Telegram n’est associé à aucun utilisateur du panneau.",
        "contact_admin_to_link": "Contactez votre administrateur : il doit ajouter votre identifiant Telegram à votre profil.",
        "your_telegram_id": "Votre identifiant Telegram",
        "registered_admin": "Vous êtes enregistré sous <b>{username}</b> avec le rôle <b>Admin</b>.",
        "choose_action": "Choisissez une action :",
        "registered_as": "Vous êtes enregistré sous <b>{username}</b>.",
        "credentials_title": "Votre compte du panneau a été créé.",
        "credentials_login": "Identifiant",
        "credentials_password": "Mot de passe",
        "credentials_instructions": "Pour vous connecter, ouvrez {panel_url} dans un navigateur et saisissez ces identifiants sur la page de connexion.",
        "credentials_no_url": "L’adresse du panneau n’est pas configurée. Contactez l’administrateur pour obtenir l’adresse de connexion correcte.",
        "credentials_disabled": "Votre compte a été créé désactivé. Contactez l’administrateur pour l’activer avant de vous connecter.",
        "no_connections_create": "Vous n’avez pas encore de connexion. Appuyez sur le bouton ci-dessous pour en créer une !",
        "no_connections_contact_admin": "Vous n’avez pas encore de connexion. Contactez votre administrateur.",
        "your_connections": "<b>Vos connexions</b> ({count}) — appuyez pour obtenir la configuration :",
        "updated": "Mis à jour !",
        "access_denied": "Accès refusé.",
        "no_connections_create_short": "Vous n’avez aucune connexion. Appuyez sur le bouton ci-dessous pour en créer une !",
        "no_connections": "Vous n’avez aucune connexion.",
        "fetching_config": "Récupération de la configuration...",
        "connection_not_found": "Connexion introuvable.",
        "server_not_found": "Serveur introuvable.",
        "fetching_config_for": "Récupération de la configuration pour <b>{name}</b>...",
        "failed_retrieve_config": "Impossible de récupérer la configuration.",
        "admin_menu": "Menu d’administration",
        "action_expired": "Action expirée. Utilisez de nouveau /start.",
        "btn_create_connection": "Créer une connexion",
        "btn_refresh_list": "Actualiser la liste",
        "btn_back": "Retour",
        "btn_do_not_assign": "Ne pas attribuer",
        "btn_cancel": "Annuler",
        "btn_servers": "Serveurs",
        "btn_users": "Utilisateurs",
        "btn_my_connections": "Mes connexions",
        "btn_how_add_server": "Comment ajouter un serveur",
        "btn_admin_menu": "Menu d’administration",
        "btn_no_installed_protocols": "Aucun protocole installé",
        "btn_connections": "Connexions",
        "btn_stop": "Arrêter",
        "btn_start": "Démarrer",
        "btn_protocols": "Protocoles",
        "btn_config": "Configuration",
        "btn_disable": "Désactiver",
        "btn_enable": "Activer",
        "btn_delete": "Supprimer",
        "btn_protocol": "Protocole",
        "choose_server": "Choisissez un serveur :",
        "choose_protocol": "Choisissez un protocole :",
        "protocol_label": "Protocole",
        "send_device_name": "Envoyez le nom de l’appareil dans le prochain message.",
        "cancel_instruction": "Envoyez <code>/cancel</code> pour annuler.",
        "example_label": "Exemple",
        "delete_connection_confirm": "Supprimer la connexion <b>{name}</b> ?",
        "cannot_be_undone": "Cette action est irréversible.",
        "connection_deleted": "Connexion supprimée.",
        "connection_deleted_no_connections": "Connexion supprimée. Vous n’avez plus de connexion.",
        "connection_created_no_config": "Connexion créée, mais aucune configuration n’est disponible.",
        "creating_connection_named": "Création de la connexion <b>{name}</b>...",
        "self_service_creation_disabled": "La création de connexions en libre-service est actuellement désactivée.\nContactez votre administrateur.",
        "self_service_no_servers": "Aucun serveur n’est disponible pour créer une connexion en libre-service.\nContactez votre administrateur.",
        "self_service_disabled_contact": "Le libre-service est désactivé. Contactez votre administrateur.",
        "self_service_unavailable": "Le libre-service n’est pas disponible.",
        "max_connections_reached": "Vous avez atteint la limite de connexions. Supprimez une connexion existante ou contactez votre administrateur.",
        "server_not_self_service": "Ce serveur n’est pas disponible en libre-service.",
        "no_protocols_available": "Aucun protocole disponible sur ce serveur.",
        "name_empty": "Le nom ne peut pas être vide. Envoyez un nom de connexion ou /cancel.",
        "error": "Erreur",
        "saving_not_available": "L’enregistrement n’est pas disponible pour cette instance du bot.",
        "servers_title": "Serveurs",
        "choose_a_server": "Choisissez un serveur :",
        "users_title": "Utilisateurs",
        "choose_a_user": "Choisissez un utilisateur :",
        "user_not_found": "Utilisateur introuvable.",
        "protocol_not_found": "Protocole introuvable.",
        "updating_protocol": "Mise à jour du conteneur du protocole...",
        "loading_connections": "Chargement des connexions...",
        "no_connections_short": "Aucune connexion.",
        "creating_connection": "Création de la connexion...",
        "updating_connection": "Mise à jour de la connexion...",
        "removing_connection": "Suppression de la connexion...",
        "connection_removed": "Connexion supprimée.",
        "action_cancelled": "Action annulée.",
        "add_server_label": "Ajouter un serveur",
        "add_server_command": "Utilisez la commande :\n<code>/addserver host username password [ssh_port] [name]</code>\n\nExemple :\n<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n⚠️ Les messages Telegram ne sont pas un gestionnaire de secrets. Ajoutez de préférence les serveurs depuis le panneau web.",
        "server_added": "Serveur ajouté : <b>{name}</b>\nHôte : <code>{host}</code>",
        "server_config": "Configuration",
        "send_connection_name": "Envoyez le nom de la connexion dans le prochain message.\nExemple : <code>Ivan iPhone</code>\n\nEnvoyez <code>/cancel</code> pour annuler.",
        "connection_name_label": "Nom de la connexion",
        "assign_to_user": "Attribuer cette connexion à un utilisateur du panneau ?",
        "connection_created": "Connexion créée : <b>{name}</b>",
        "assigned_to": "Attribuée à : <b>{username}</b>",
        "assigned_not_linked": "Attribution : <b>aucune</b>",
        "config_label": "Configuration",
        "connection_link_label": "Lien de connexion",
        "config_part": "Configuration (partie {part}/{total}) :",
        "vpn_link_label": "Lien VPN",
        "config_file_label": "Fichier de configuration",
        "protocol_status": "État",
        "protocol_port": "Port",
        "client_status": "État",
        "enabled_label": "activé",
        "disabled_label": "désactivé",
        "traffic_label": "Trafic",
        "rx_label": "RX",
        "tx_label": "TX",
        "connections_count": "Connexions",
        "create_new_connection": "Créer une connexion",
        "connection_created_success": "Connexion créée.",
        "role_label": "Rôle",
        "enabled_status": "Activé",
        "email_label": "E-mail",
        "tg_id_label": "Identifiant Telegram",
        "description_label": "Description",
        "protocol_display": "Protocole",
        "cmd_start": "Ouvrir le menu du bot",
        "btn_open_panel": "Ouvrir le panneau",
        "cmd_connections": "Afficher mes connexions",
        "cmd_connect": "Créer une connexion",
        "cmd_disconnect": "Supprimer une connexion",
        "private_chat_short": "Utiliser une discussion privée",
        "private_chat_required": "Pour votre sécurité, utilisez cette commande dans une discussion privée avec le bot.",
        "status_unknown": "inconnu",
        "status_running": "en cours d’exécution",
        "status_stopped": "arrêté",
        "default_server": "Serveur {number}",
        "default_unknown": "Inconnu",
        "default_connection": "Connexion",
        "default_user": "utilisateur",
        "disabled_suffix": "désactivé",
        "yes_label": "oui",
        "no_label": "non",
        "tap_to_copy": "appuyez pour copier",
        "host_label": "Hôte",
        "ssh_label": "SSH",
        "client_id_label": "ID client",
        "exit_label": "Sortie",
        "field_port": "Port",
        "field_container_name": "Conteneur",
        "field_domain": "Domaine",
        "field_site_url": "URL du site",
        "field_web_port": "Port web",
        "field_mode": "Mode",
        "field_subnet": "Sous-réseau",
        "field_peers_count": "Pairs",
        "status_error_label": "Erreur d’état",
        "container_name_unknown": "Le nom du conteneur est inconnu",
        "container_not_found": "Conteneur introuvable",
        "protocol_action_failed": "Impossible de {action} le conteneur du protocole.",
        "language_prompt": "Choisissez la langue",
        "btn_language": "Langue",
        "language_saved": "Langue enregistrée."
    },
    "ru": {
        "hi": "Привет",
        "account_disabled": "Аккаунт отключён",
        "account_not_linked": "Ваш аккаунт Telegram не привязан ни к одному пользователю панели.",
        "contact_admin_to_link": "Обратитесь к администратору — он должен добавить ваш Telegram ID в профиль.",
        "your_telegram_id": "Ваш Telegram ID",
        "registered_admin": "Вы зарегистрированы как <b>{username}</b> с ролью <b>Admin</b>.",
        "choose_action": "Выберите действие:",
        "registered_as": "Вы зарегистрированы как <b>{username}</b>.",
        "credentials_title": "Ваш аккаунт панели создан.",
        "credentials_login": "Логин",
        "credentials_password": "Пароль",
        "credentials_instructions": "Для входа откройте {panel_url} в браузере и введите эти данные на странице авторизации.",
        "credentials_no_url": "Адрес панели не настроен. Обратитесь к администратору, чтобы получить правильную ссылку для входа.",
        "credentials_disabled": "Аккаунт создан отключённым. Перед входом обратитесь к администратору для его активации.",
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
        "max_connections_reached": "Достигнут лимит подключений. Удалите одно из существующих подключений или обратитесь к администратору.",
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
        "cmd_start": "Открыть меню бота",
        "btn_open_panel": "Открыть панель",
        "cmd_connections": "Показать мои подключения",
        "cmd_connect": "Создать новое подключение",
        "cmd_disconnect": "Удалить подключение",
        "private_chat_short": "Используйте личный чат",
        "private_chat_required": "В целях безопасности используйте эту команду в личном чате с ботом.",
        "status_unknown": "неизвестно",
        "status_running": "запущен",
        "status_stopped": "остановлен",
        "default_server": "Сервер {number}",
        "default_unknown": "Неизвестно",
        "default_connection": "Подключение",
        "default_user": "пользователь",
        "disabled_suffix": "отключён",
        "yes_label": "да",
        "no_label": "нет",
        "tap_to_copy": "нажмите, чтобы скопировать",
        "host_label": "Хост",
        "ssh_label": "SSH",
        "client_id_label": "ID клиента",
        "exit_label": "Выходной узел",
        "field_port": "Порт",
        "field_container_name": "Контейнер",
        "field_domain": "Домен",
        "field_site_url": "URL сайта",
        "field_web_port": "Веб-порт",
        "field_mode": "Режим",
        "field_subnet": "Подсеть",
        "field_peers_count": "Пиры",
        "status_error_label": "Ошибка статуса",
        "container_name_unknown": "Имя контейнера неизвестно",
        "container_not_found": "Контейнер не найден",
        "protocol_action_failed": "Не удалось выполнить действие «{action}» для контейнера протокола.",
        "language_prompt": "Выберите язык",
        "btn_language": "Язык",
        "language_saved": "Язык сохранён."
    },
    "zh": {
        "hi": "你好",
        "account_disabled": "账户已被禁用",
        "account_not_linked": "你的 Telegram 账号尚未关联任何面板用户。",
        "contact_admin_to_link": "请联系管理员，将你的 Telegram ID 添加到个人资料中。",
        "your_telegram_id": "你的 Telegram ID",
        "registered_admin": "你已注册为 <b>{username}</b>，角色为 <b>Admin</b>。",
        "choose_action": "请选择操作：",
        "registered_as": "你已注册为 <b>{username}</b>。",
        "credentials_title": "你的面板账户已创建。",
        "credentials_login": "用户名",
        "credentials_password": "密码",
        "credentials_instructions": "登录时，请在浏览器中打开 {panel_url}，并在登录页面输入这些凭据。",
        "credentials_no_url": "尚未配置面板地址。请联系管理员获取正确的登录地址。",
        "credentials_disabled": "你的账户已创建但处于禁用状态。请联系管理员启用账户后再登录。",
        "no_connections_create": "你还没有连接。点击下方按钮创建一个吧！",
        "no_connections_contact_admin": "你还没有连接。请联系管理员。",
        "your_connections": "<b>你的连接</b>（{count}）— 点击获取配置：",
        "updated": "已更新！",
        "access_denied": "访问被拒绝。",
        "no_connections_create_short": "你还没有连接。点击下方按钮创建一个吧！",
        "no_connections": "你还没有连接。",
        "fetching_config": "正在获取配置...",
        "connection_not_found": "未找到连接。",
        "server_not_found": "未找到服务器。",
        "fetching_config_for": "正在获取 <b>{name}</b> 的配置...",
        "failed_retrieve_config": "无法获取配置。",
        "admin_menu": "管理员菜单",
        "action_expired": "操作已过期。请重新使用 /start。",
        "btn_create_connection": "创建连接",
        "btn_refresh_list": "刷新列表",
        "btn_back": "返回",
        "btn_do_not_assign": "不分配",
        "btn_cancel": "取消",
        "btn_servers": "服务器",
        "btn_users": "用户",
        "btn_my_connections": "我的连接",
        "btn_how_add_server": "如何添加服务器",
        "btn_admin_menu": "管理员菜单",
        "btn_no_installed_protocols": "没有已安装的协议",
        "btn_connections": "连接",
        "btn_stop": "停止",
        "btn_start": "启动",
        "btn_protocols": "协议",
        "btn_config": "配置",
        "btn_disable": "禁用",
        "btn_enable": "启用",
        "btn_delete": "删除",
        "btn_protocol": "协议",
        "choose_server": "请选择服务器：",
        "choose_protocol": "请选择协议：",
        "protocol_label": "协议",
        "send_device_name": "请在下一条消息中发送设备名称。",
        "cancel_instruction": "发送 <code>/cancel</code> 可取消。",
        "example_label": "示例",
        "delete_connection_confirm": "要删除连接 <b>{name}</b> 吗？",
        "cannot_be_undone": "此操作无法撤销。",
        "connection_deleted": "连接已删除。",
        "connection_deleted_no_connections": "连接已删除。你已没有其他连接。",
        "connection_created_no_config": "连接已创建，但没有可用配置。",
        "creating_connection_named": "正在创建连接 <b>{name}</b>...",
        "self_service_creation_disabled": "当前已禁用自助创建连接。\n请联系管理员。",
        "self_service_no_servers": "目前没有可用于自助创建连接的服务器。\n请联系管理员。",
        "self_service_disabled_contact": "自助服务已禁用。请联系管理员。",
        "self_service_unavailable": "自助服务不可用。",
        "max_connections_reached": "已达到连接数量上限。请删除一个现有连接，或联系管理员。",
        "server_not_self_service": "此服务器不支持自助服务。",
        "no_protocols_available": "此服务器没有可用协议。",
        "name_empty": "名称不能为空。请发送连接名称或 /cancel。",
        "error": "错误",
        "saving_not_available": "此机器人实例不支持保存。",
        "servers_title": "服务器",
        "choose_a_server": "请选择服务器：",
        "users_title": "用户",
        "choose_a_user": "请选择用户：",
        "user_not_found": "未找到用户。",
        "protocol_not_found": "未找到协议。",
        "updating_protocol": "正在更新协议容器...",
        "loading_connections": "正在加载连接...",
        "no_connections_short": "没有连接。",
        "creating_connection": "正在创建连接...",
        "updating_connection": "正在更新连接...",
        "removing_connection": "正在移除连接...",
        "connection_removed": "连接已移除。",
        "action_cancelled": "操作已取消。",
        "add_server_label": "添加服务器",
        "add_server_command": "使用命令：\n<code>/addserver host username password [ssh_port] [name]</code>\n\n示例：\n<code>/addserver 203.0.113.10 root myPassword 22 Prod VPS</code>\n\n⚠️ Telegram 消息并非密码管理器。请尽量通过网页面板添加服务器。",
        "server_added": "已添加服务器：<b>{name}</b>\n主机：<code>{host}</code>",
        "server_config": "配置",
        "send_connection_name": "请在下一条消息中发送连接名称。\n示例：<code>Ivan iPhone</code>\n\n发送 <code>/cancel</code> 可取消。",
        "connection_name_label": "连接名称",
        "assign_to_user": "要将此连接分配给面板用户吗？",
        "connection_created": "已创建连接：<b>{name}</b>",
        "assigned_to": "已分配给：<b>{username}</b>",
        "assigned_not_linked": "分配状态：<b>未关联</b>",
        "config_label": "配置",
        "connection_link_label": "连接链接",
        "config_part": "配置（第 {part}/{total} 部分）：",
        "vpn_link_label": "VPN 链接",
        "config_file_label": "配置文件",
        "protocol_status": "状态",
        "protocol_port": "端口",
        "client_status": "状态",
        "enabled_label": "已启用",
        "disabled_label": "已禁用",
        "traffic_label": "流量",
        "rx_label": "接收",
        "tx_label": "发送",
        "connections_count": "连接",
        "create_new_connection": "创建连接",
        "connection_created_success": "连接创建成功。",
        "role_label": "角色",
        "enabled_status": "已启用",
        "email_label": "电子邮箱",
        "tg_id_label": "Telegram ID",
        "description_label": "描述",
        "protocol_display": "协议",
        "cmd_start": "打开机器人菜单",
        "btn_open_panel": "打开面板",
        "cmd_connections": "查看我的连接",
        "cmd_connect": "创建新连接",
        "cmd_disconnect": "删除连接",
        "private_chat_short": "请使用私聊",
        "private_chat_required": "为确保安全，请在与机器人的私聊中使用此命令。",
        "status_unknown": "未知",
        "status_running": "运行中",
        "status_stopped": "已停止",
        "default_server": "服务器 {number}",
        "default_unknown": "未知",
        "default_connection": "连接",
        "default_user": "用户",
        "disabled_suffix": "已禁用",
        "yes_label": "是",
        "no_label": "否",
        "tap_to_copy": "点击复制",
        "host_label": "主机",
        "ssh_label": "SSH",
        "client_id_label": "客户端 ID",
        "exit_label": "出口",
        "field_port": "端口",
        "field_container_name": "容器",
        "field_domain": "域名",
        "field_site_url": "站点 URL",
        "field_web_port": "Web 端口",
        "field_mode": "模式",
        "field_subnet": "子网",
        "field_peers_count": "对等节点",
        "status_error_label": "状态错误",
        "container_name_unknown": "容器名称未知",
        "container_not_found": "未找到容器",
        "protocol_action_failed": "无法对协议容器执行{action}操作。",
        "language_prompt": "选择语言",
        "btn_language": "语言",
        "language_saved": "语言已保存。"
    }
}


# ----------------------------------------------------------------------- #
#  Public lifecycle
# ----------------------------------------------------------------------- #
def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


_ssh_credential_resolver = None


def launch_bot(token: str, load_data_fn: Callable, generate_vpn_link_fn: Callable, save_data_fn: Optional[Callable] = None, self_service_svc=None, credential_resolver=None):
    global _bot_task, _ssh_credential_resolver
    _ssh_credential_resolver = credential_resolver
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


def _command_menu(lang: str) -> list:
    return [
        {"command": "start", "description": _tt(lang, "cmd_start")},
        {"command": "connections", "description": _tt(lang, "cmd_connections")},
        {"command": "connect", "description": _tt(lang, "cmd_connect")},
        {"command": "disconnect", "description": _tt(lang, "cmd_disconnect")},
    ]


async def _set_default_commands(api: TelegramAPI):
    await api.call("setMyCommands", commands=_command_menu("en"))
    for lang in sorted(set(TG_TRANSLATIONS) - {"en"}):
        await api.call("setMyCommands", commands=_command_menu(lang), language_code=lang)

async def _set_webapp_menu_button(
    api: TelegramAPI, load_data_fn: Callable,
    chat_id: Optional[int] = None, lang: str = "en",
):
    """Expose the existing panel as the Telegram Mini App menu button."""
    panel_url = _panel_public_url(load_data_fn())
    params = {}
    if chat_id is not None:
        params["chat_id"] = chat_id
    if not panel_url.startswith("https://"):
        params["menu_button"] = {"type": "default"}
        await api.call("setChatMenuButton", **params)
        return
    params["menu_button"] = {
        "type": "web_app",
        "text": _tt(lang, "btn_open_panel"),
        "web_app": {"url": panel_url},
    }
    result = await api.call("setChatMenuButton", **params)
    if not result.get("ok"):
        logger.warning("Telegram WebApp menu button could not be configured: %s", result)



# ----------------------------------------------------------------------- #
#  Generic helpers
# ----------------------------------------------------------------------- #
def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))




def _tg_lang(from_user: Optional[dict]) -> str:
    code = str((from_user or {}).get("language_code") or "").strip().lower().replace("_", "-")
    primary = code.split("-", 1)[0]
    return primary if primary in TG_TRANSLATIONS else "en"


def _tt(lang: str, key: str, **kwargs) -> str:
    text = TG_TRANSLATIONS.get(lang, TG_TRANSLATIONS["en"]).get(key, TG_TRANSLATIONS["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text


_LANGUAGE_LABELS = {
    "en": "🇬🇧 English",
    "fa": "🇮🇷 فارسی",
    "fr": "🇫🇷 Français",
    "ru": "🇷🇺 Русский",
    "zh": "🇨🇳 中文",
}


def _language_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": label, "callback_data": f"lang:{lang}"}]
            for lang, label in _LANGUAGE_LABELS.items()
        ]
    }


def _language_button(lang: str) -> dict:
    return {"text": f"🌐 {_tt(lang, 'btn_language')}", "callback_data": "language_menu"}


def _telegram_language(data: dict, tg_id: str) -> Optional[str]:
    lang = ((data.get("telegram_preferences") or {}).get(str(tg_id)) or {}).get("language")
    return lang if lang in TG_TRANSLATIONS else None


def _selected_lang(load_data_fn: Callable, tg_id: str, from_user: Optional[dict] = None) -> str:
    return _telegram_language(load_data_fn(), tg_id) or _tg_lang(from_user)


def _save_telegram_language(load_data_fn: Callable, save_data_fn: Optional[Callable],
                            tg_id: str, lang: str) -> bool:
    if not save_data_fn or lang not in TG_TRANSLATIONS:
        return False
    data = load_data_fn()
    preferences = data.setdefault("telegram_preferences", {})
    current = preferences.setdefault(str(tg_id), {})
    current["language"] = lang
    save_data_fn(data)
    return True


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


def _protocol_display_name(protocol: str, server=None) -> str:
    if server is not None:
        return server_protocol_names(server).get(protocol, self_service_protocol_display_name(protocol))
    base = protocol_base(protocol)
    if base in SELF_SERVICE_PROTOCOLS:
        return self_service_protocol_display_name(protocol)
    name = _EXTRA_PROTOCOL_DISPLAY_NAMES.get(base, base)
    idx = protocol_instance(protocol)
    return name if idx <= 1 else f"{name} #{idx}"


def _resolve_public_endpoint(server: dict, protocol: str):
    """Return the client-facing endpoint for one protocol instance."""
    info = (server.get("protocols") or {}).get(protocol) or {}
    host = str(info.get("public_host") or "").strip() or server.get("host", "")
    public_port = str(info.get("public_port") or "").strip() or None
    return host, public_port


def _auto_create_telegram_user(data: dict, from_user: dict, save_data_fn: Optional[Callable]):
    """Create a panel account for a first-time Telegram user when enabled."""
    telegram_settings = (data.get("settings") or {}).get("telegram") or {}
    if telegram_settings.get("auto_create_users") is not True or not save_data_fn:
        return None

    tg_id = str((from_user or {}).get("id") or "").strip()
    if not tg_id:
        return None
    users = data.setdefault("users", [])
    existing = next((u for u in users
                     if str(u.get("telegramId") or "").strip() == tg_id), None)
    if existing:
        return existing, None

    parts = [
        str((from_user or {}).get("first_name") or "").strip(),
        str((from_user or {}).get("last_name") or "").strip(),
    ]
    display_name = " ".join(part for part in parts if part).strip()
    if not display_name:
        display_name = str((from_user or {}).get("username") or "").strip()
    if not display_name:
        display_name = f"Telegram {tg_id}"

    username = display_name[:80]
    if any(str(user.get("username") or "").casefold() == username.casefold()
           for user in users):
        suffix = f" ({tg_id})"
        username = username[:max(1, 80 - len(suffix))] + suffix

    now = datetime.now()
    random_password = secrets.token_urlsafe(48)
    salt = secrets.token_hex(16)
    password_digest = hashlib.pbkdf2_hmac(
        "sha256", random_password.encode(), salt.encode(), 100000
    )
    create_disabled = bool(telegram_settings.get("create_users_disabled", False))
    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "password_hash": f"{salt}${password_digest.hex()}",
        "role": "user",
        "telegramId": tg_id,
        "email": None,
        "description": "Created automatically from Telegram",
        "traffic_limit": 0,
        "max_connections": 0,
        "traffic_reset_strategy": "never",
        "traffic_used": 0,
        "traffic_total": 0,
        "last_reset_at": now.isoformat(),
        "expiration_date": None,
        "enabled": not create_disabled,
        "disable_reasons": ["manual"] if create_disabled else [],
        "access_revision": 0,
        "access_sync_pending": False,
        "created_at": now.isoformat(),
        "remnawave_uuid": None,
        "share_enabled": False,
        "share_token": secrets.token_urlsafe(16),
        "share_password_hash": None,
        "share_auth_revision": 0,
    }
    users.append(user)
    save_data_fn(data)
    logger.info("Created panel user from Telegram account %s", tg_id)
    return user, random_password


def _panel_public_url(data: dict) -> str:
    """Build the browser-facing panel URL from the saved public host settings."""
    settings = (data or {}).get("settings", {}) or {}
    ssl = settings.get("ssl", {}) or {}
    duckdns = settings.get("duckdns", {}) or {}
    panel_access = settings.get("panel_access", {}) or {}

    configured_host = (
        ssl.get("domain")
        or (duckdns.get("domain") if duckdns.get("enabled") else "")
        or panel_access.get("allowed_domain")
        or ""
    )
    configured_host = str(configured_host).strip()
    if not configured_host:
        return ""

    # Accept a hostname (normal settings format) or a full URL (legacy/manual).
    parsed = urllib.parse.urlsplit(
        configured_host if "://" in configured_host else f"//{configured_host}"
    )
    scheme = parsed.scheme.lower() if parsed.scheme else (
        "https" if ssl.get("enabled") else "http"
    )
    if (
        scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return ""

    try:
        configured_port = parsed.port
        panel_port = int(ssl.get("panel_port", 5000) or 5000)
    except (TypeError, ValueError):
        return ""
    port = configured_port if configured_port is not None else panel_port
    if not 1 <= port <= 65535:
        return ""

    hostname = parsed.hostname
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 443 if scheme == "https" else 80
    authority = hostname if port == default_port else f"{hostname}:{port}"
    return f"{scheme}://{authority}"


def _telegram_credentials_message(
    user: dict, password: str, lang: str, panel_url: str = ""
) -> str:
    lines = [
        f"<b>{_tt(lang, 'credentials_title')}</b>",
        f"{_tt(lang, 'credentials_login')}: <code>{_e(user.get('username'))}</code>",
        f"{_tt(lang, 'credentials_password')}: <code>{_e(password)}</code>",
        "",
    ]
    if not user.get("enabled", True):
        lines.append(_tt(lang, "credentials_disabled"))
    elif panel_url:
        safe_url = _e(panel_url)
        lines.append(_tt(
            lang, "credentials_instructions",
            panel_url=f'<a href="{safe_url}">{safe_url}</a>',
        ))
    else:
        lines.append(_tt(lang, "credentials_no_url"))
    return "\n".join(lines)


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
        await api.answer_callback(callback_id, _tt(lang, "private_chat_short"))
    await api.send_message(chat_id, _tt(lang, "private_chat_required"))


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
        name = server.get("name") or server.get("host") or _tt(lang, "default_server", number=sid + 1)
        proto_text = ", ".join(self_service_protocol_display_name(p, server.get("protocols", {}).get(p)) for p in protos)
        rows.append([{"text": f"🖥 {name} ({proto_text})", "callback_data": _ref("user_create_server", {"sid": sid})}])
    rows.append([{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": "user_create_cancel"}])
    return {"inline_keyboard": rows}


def _build_connections_keyboard(conns: list, data: dict, lang: str = "en",
                                include_language: bool = False) -> dict:
    """Build inline keyboard where each button = one connection.
    When self-service is enabled, adds delete buttons for self-service connections
    and a 'Create connection' button."""
    rows = []
    servers = data.get("servers", [])
    ss_enabled = _self_service_telegram_enabled(data)
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = _tt(lang, "default_unknown")
        if isinstance(sid, int) and sid < len(servers):
            srv = servers[sid]
            server_name = srv.get("name") or srv.get("host", _tt(lang, "default_unknown"))[:20]
        proto = c.get("protocol", "").upper()
        name = c.get("name") or _tt(lang, "default_connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        row = [{"text": label, "callback_data": f"cfg:{c['id']}"}]
        if ss_enabled and c.get("created_by") == "self_service":
            row.append({"text": "🗑", "callback_data": _ref("user_delete", {"conn_id": c["id"], "name": name})})
        rows.append(row)
    if ss_enabled:
        rows.append([{"text": f"➕ {_tt(lang, 'btn_create_connection')}", "callback_data": "user_create"}])
    rows.append([{"text": f"🔄 {_tt(lang, 'btn_refresh_list')}", "callback_data": "refresh"}])
    if include_language:
        rows.append([_language_button(lang)])
    return {"inline_keyboard": rows}


def _connection_lookup(data: dict, server_id: int, proto: str) -> dict:
    return {
        c.get("client_id"): c
        for c in data.get("user_connections", [])
        if c.get("server_id") == server_id and c.get("protocol") == proto and c.get("client_id")
    }


def _client_display_name(client: dict, conn: Optional[dict] = None, lang: str = "en") -> str:
    if conn and conn.get("name"):
        return conn.get("name")
    user_data = client.get("userData") or {}
    return (
        client.get("name")
        or client.get("username")
        or user_data.get("clientName")
        or user_data.get("name")
        or str(client.get("clientId") or client.get("client_id") or client.get("id") or _tt(lang, "default_connection"))[:12]
    )


def _user_label(user: dict, lang: str = "en") -> str:
    label = user.get("username") or user.get("id") or _tt(lang, "default_user")
    role = user.get("role") or _tt(lang, "default_user")
    suffix = f" · {role}"
    if user.get("telegramId"):
        suffix += f" · tg:{user.get('telegramId')}"
    if user.get("enabled") is False:
        suffix += f" · {_tt(lang, 'disabled_suffix')}"
    return f"{label}{suffix}"


def _users_keyboard(data: dict, back_callback: str = "adm:menu", lang: str = "en") -> dict:
    rows = []
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f" {_user_label(user, lang)}", "callback_data": _ref("user", {"uid": user.get("id")})}])
    rows.append([{"text": f"⬅️ {_tt(lang, 'btn_back')}", "callback_data": back_callback}])
    return {"inline_keyboard": rows}


def _assign_user_keyboard(data: dict, server_id: int, proto: str, name: str, lang: str = "en") -> dict:
    rows = [[{"text": f"🚫 {_tt(lang, 'btn_do_not_assign')}", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": None})}]]
    for user in data.get("users", [])[:40]:
        rows.append([{"text": f" {_user_label(user, lang)}", "callback_data": _ref("create_client", {"sid": server_id, "proto": proto, "name": name, "user_id": user.get("id")})}])
    rows.append([{"text": f"❌ {_tt(lang, 'btn_cancel')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}])
    return {"inline_keyboard": rows}


def _admin_main_keyboard(lang: str = "en", include_language: bool = False) -> dict:
    rows = [
        [{"text": f"🖥 {_tt(lang, 'btn_servers')}", "callback_data": "adm:servers"}],
        [{"text": f"👤 {_tt(lang, 'btn_users')}", "callback_data": "adm:users"}],
        [{"text": f"🔐 {_tt(lang, 'btn_my_connections')}", "callback_data": "adm:myconns"}],
        [{"text": f"➕ {_tt(lang, 'btn_how_add_server')}", "callback_data": "adm:addserver_help"}],
    ]
    if include_language:
        rows.append([_language_button(lang)])
    return {"inline_keyboard": rows}


def _server_keyboard(data: dict, lang: str = "en") -> dict:
    rows = []
    for sid, srv in enumerate(data.get("servers", [])):
        name = srv.get("name") or srv.get("host") or _tt(lang, "default_server", number=sid + 1)
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
        return f"{_tt(lang, 'status_unknown')} ⚪"
    running = info.get("container_running")
    if running is True:
        return f"{_tt(lang, 'status_running')} 🟢"
    if running is False:
        return f"{_tt(lang, 'status_stopped')} 🔴"
    return f"{_tt(lang, 'status_unknown')} ⚪"


def _protocols_keyboard(server_id: int, server: dict, lang: str = "en") -> dict:
    rows = []
    protocols = server.get("protocols", {}) or {}
    for proto, info in protocols.items():
        installed = "✅" if info.get("installed", True) else ""
        rows.append([{"text": f"{installed}{_protocol_status_icon(info)} {_protocol_display_name(proto, server)}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}])
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
    rows.append([{"text": _tt(lang, "btn_stop") if is_running else _tt(lang, "btn_start"), "callback_data": _ref("toggle_proto", {"sid": server_id, "proto": proto, "start": not is_running})}])
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
            [{"text": f" {_tt(lang, 'btn_config')}", "callback_data": _ref("client_cfg", {"sid": server_id, "proto": proto, "client_id": client_id, "name": client.get("name") or client.get("username") or _tt(lang, "default_connection")})}],
            [{"text": _tt(lang, "btn_disable") if enabled else _tt(lang, "btn_enable"), "callback_data": _ref("toggle_client", {"sid": server_id, "proto": proto, "client_id": client_id, "enable": not enabled})}],
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

    if _ssh_credential_resolver:
        password, private_key = _ssh_credential_resolver(server)
    else:
        password, private_key = server.get("password", ""), server.get("private_key", "")
    ssh = SSHManager(
        server["host"],
        server.get("ssh_port", 22),
        server["username"],
        password,
        private_key,
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
async def _handle_start(api: TelegramAPI, msg: dict, load_data_fn: Callable,
                        save_data_fn: Optional[Callable] = None):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    tg_username = msg["from"].get("username")
    first_name = msg["from"].get("first_name", "")
    data = load_data_fn()
    lang = _telegram_language(data, tg_id)
    if not lang:
        lang = _tg_lang(msg.get("from") or {})
    try:
        if _is_private_chat(msg.get("chat")):
            await _set_webapp_menu_button(api, load_data_fn, chat_id=chat_id, lang=lang)
    except Exception as exc:
        logger.warning("Telegram WebApp menu button refresh failed: %s", exc)
    if not _telegram_language(data, tg_id):
        await api.send_message(chat_id, _tt(lang, "language_prompt"),
                               reply_markup=_language_keyboard())
        return

    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    created_password = None
    if not panel_user and _is_private_chat(msg.get("chat")):
        created = _auto_create_telegram_user(data, msg.get("from") or {}, save_data_fn)
        if created:
            panel_user, created_password = created
    if created_password:
        await api.send_message(chat_id, _telegram_credentials_message(panel_user, created_password, lang, _panel_public_url(load_data_fn())))

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
            reply_markup=_admin_main_keyboard(lang, include_language=True),
        )
        return

    await _send_user_connections(api, chat_id, panel_user, load_data_fn, first_name=first_name,
                                 lang=lang, include_language=True)


async def _send_user_connections(api: TelegramAPI, chat_id: int, panel_user: dict,
                                 load_data_fn: Callable, first_name: str = "",
                                 lang: str = "en", include_language: bool = False):
    data = load_data_fn()
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == panel_user.get("id")]

    if not conns:
        greeting = f"👋 {_tt(lang, 'hi')}, <b>{_e(first_name)}</b>!\n\n" if first_name else ""
        if _self_service_telegram_enabled(data):
            kb = _build_connections_keyboard(conns, data, lang, include_language)
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

    kb = _build_connections_keyboard(conns, data, lang, include_language)
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

    await _send_config_by_client(api, chat_id, servers[sid], conn.get("protocol", "awg"), conn.get("client_id"), conn.get("name") or _tt(lang, "default_connection"), generate_vpn_link_fn, lang)


async def _send_config_by_client(api: TelegramAPI, chat_id: int, server: dict, proto: str, client_id: str, conn_name: str, generate_vpn_link_fn: Callable, lang: str = "en", public_endpoint_fn: Optional[Callable] = None):
    loading_result = await api.send_message(chat_id, _tt(lang, "fetching_config_for", name=_e(conn_name)))
    loading_msg_id = loading_result.get("result", {}).get("message_id")
    try:
        proto_info = server.get("protocols", {}).get(proto, {})
        port = proto_info.get("port", "55424")
        public_host, public_port = (public_endpoint_fn or _resolve_public_endpoint)(server, proto)

        def _get_cfg():
            ssh, manager = _get_ssh_and_manager(server, proto)
            try:
                ssh.connect()
                return _manager_call(
                    manager, "get_client_config", proto, client_id,
                    public_host, port, public_port=public_port,
                )
            finally:
                ssh.disconnect()

        config = await asyncio.to_thread(_get_cfg)
        if not config:
            if loading_msg_id:
                await api.edit_message(chat_id, loading_msg_id, f"❌ {_tt(lang, 'failed_retrieve_config')}")
            return

        if loading_msg_id:
            await api.call("deleteMessage", chat_id=chat_id, message_id=loading_msg_id)

        server_name = server.get("name") or server.get("host", _tt(lang, "default_unknown"))
        await api.send_message(chat_id, f"✅ <b>{_e(conn_name)}</b>\n🌐 {_tt(lang, 'servers_title')}: <b>{_e(server_name)}</b>\n🔌 {_tt(lang, 'protocol_label')}: <b>{_e(proto.upper())}</b>")

        is_link_proto = protocol_base(proto) in ("xray", "telemt")
        if is_link_proto:
            await api.send_message(chat_id, f"🔗 <b>{_tt(lang, 'connection_link_label')}</b> ({_tt(lang, 'tap_to_copy')}):\n<code>{_e(config)}</code>")
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
                await api.send_message(chat_id, f"🔗 <b>{_tt(lang, 'vpn_link_label')}</b> ({_tt(lang, 'tap_to_copy')}):\n<code>{_e(vpn_link)}</code>")
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
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'user_not_found')}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_users')}", "callback_data": "adm:users"}]]})
        return
    conns = [c for c in data.get("user_connections", []) if c.get("user_id") == user_id]
    lines = [
        f"👤 <b>{_e(user.get('username'))}</b>",
        f"{_tt(lang, 'role_label')}: <b>{_e(user.get('role') or _tt(lang, 'default_user'))}</b>",
        f"{_tt(lang, 'enabled_status')}: <b>{_tt(lang, 'yes_label') + ' ✅' if user.get('enabled', True) else _tt(lang, 'no_label') + ' 🚫'}</b>",
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
        server_name = _tt(lang, "default_unknown")
        if isinstance(sid, int) and sid < len(servers):
            server_name = servers[sid].get("name") or servers[sid].get("host") or _tt(lang, "default_unknown")
        rows.append([{"text": f"🔐 {c.get('name') or _tt(lang, 'default_connection')} · {c.get('protocol', '').upper()} · {server_name}", "callback_data": f"cfg:{c.get('id')}"}])
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
        f"{_tt(lang, 'host_label')}: <code>{_e(server.get('host'))}</code>\n"
        f"{_tt(lang, 'ssh_label')}: <code>{_e(server.get('username'))}@{_e(server.get('host'))}:{_e(server.get('ssh_port', 22))}</code>\n\n"
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
        f" <b>{_e(_protocol_display_name(proto, server))}</b>",
        f"{_tt(lang, 'servers_title')}: <b>{_e(server.get('name') or server.get('host'))}</b>",
        f"{_tt(lang, 'protocol_status')}: <b>{_protocol_status_text(info, lang)}</b>",
    ]
    exit_link = info.get("exit_link") or {}
    if exit_link:
        lines.append(f"{_tt(lang, 'exit_label')}: <code>{_e(exit_link.get('exit_name'))}</code>"
                     + (f" ({_e(exit_link.get('stale'))})" if exit_link.get("stale") else ""))
    field_keys = {
        "port": "field_port",
        "container_name": "field_container_name",
        "domain": "field_domain",
        "site_url": "field_site_url",
        "web_port": "field_web_port",
        "mode": "field_mode",
        "subnet": "field_subnet",
        "peers_count": "field_peers_count",
    }
    for key, label_key in field_keys.items():
        if info.get(key) not in (None, ""):
            lines.append(f"{_tt(lang, label_key)}: <code>{_e(info.get(key))}</code>")
    if info.get("status_error"):
        lines.append(f"{_tt(lang, 'status_error_label')}: <code>{_e(info.get('status_error'))}</code>")
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
            name = _client_display_name(c, conn, lang)
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
        await api.edit_message(chat_id, message_id, f"👥 <b>{_e(_protocol_display_name(proto, server))} {_tt(lang, 'connections_count')}</b> ({len(clients)})", reply_markup={"inline_keyboard": rows})
    except Exception as e:
        logger.exception("Bot admin: load clients failed")
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'error')}: {_e(e)}", reply_markup={"inline_keyboard": [[{"text": f"️ {_tt(lang, 'btn_protocol')}", "callback_data": _ref("proto", {"sid": server_id, "proto": proto})}]]})


async def _admin_client_detail(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client: dict, lang: str = "en", server=None):
    client_id = client.get("clientId") or client.get("client_id") or client.get("id") or ""
    name = _client_display_name(client, lang=lang)
    user_data = client.get("userData") or {}
    rx = user_data.get("dataReceivedBytes") or 0
    tx = user_data.get("dataSentBytes") or 0
    enabled = client.get("enabled")
    if enabled is None:
        enabled = client.get("isEnabled")
    enabled_text = f"{_tt(lang, 'enabled_label')} ✅" if (enabled is None or enabled) else f"{_tt(lang, 'disabled_label')} 🚫"
    text = (
        f"👤 <b>{_e(name)}</b>\n"
        f"{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto, server))}</b>\n"
        f"{_tt(lang, 'client_id_label')}: <code>{_e(client_id)}</code>\n"
        f"{_tt(lang, 'client_status')}: <b>{enabled_text}</b>"
    )
    if user_data:
        text += f"\n{_tt(lang, 'traffic_label')}: <b>{_format_bytes(rx + tx)}</b>\n{_tt(lang, 'rx_label')}: {_format_bytes(rx)} · {_tt(lang, 'tx_label')}: {_format_bytes(tx)}"
    await api.edit_message(chat_id, message_id, text, reply_markup=_client_keyboard(server_id, proto, client, lang))


async def _admin_add_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, panel_user: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, lang: str = "en", tg_id: Optional[str] = None):
    servers = load_data_fn().get("servers", [])
    server = servers[server_id] if 0 <= server_id < len(servers) else {}
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
        f"{_tt(lang, 'servers_title')}/{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto, server))}</b>\n\n"
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


@serialize_peer_lifecycle
async def _admin_create_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, name: str, user_id: Optional[str], load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, lang: str = "en", public_endpoint_fn: Optional[Callable] = None):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return
    await api.edit_message(chat_id, message_id, f"⏳ {_tt(lang, 'creating_connection')}")

    def _create():
        data = load_data_fn()
        server = data["servers"][server_id]
        proto_info = (server.get("protocols", {}) or {}).get(proto, {})
        port = proto_info.get("port", "55424")
        public_host, public_port = (public_endpoint_fn or _resolve_public_endpoint)(server, proto)
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            if protocol_base(proto) == "telemt":
                result = manager.add_client(proto, name, public_host, public_port or port)
            elif protocol_base(proto) == "wireguard":
                result = manager.add_client(name, public_host, public_port=public_port)
            else:
                result = manager.add_client(
                    proto, name, public_host, port, public_port=public_port,
                )
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
        await api.send_message(chat_id, f"<b>📄 {_tt(lang, 'config_label')}:</b>\n<pre>{_e(config)}</pre>")
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


@serialize_peer_lifecycle
async def _admin_remove_client(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, proto: str, client_id: str, load_data_fn: Callable, save_data_fn: Optional[Callable], lang: str = "en"):
    if not save_data_fn:
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'saving_not_available')}")
        return
    await api.edit_message(chat_id, message_id, f" {_tt(lang, 'removing_connection')}")

    def _remove():
        data = load_data_fn()
        from peer_accounting import require_unowned
        require_unowned(data, server_id=server_id, protocol=proto, client_id=client_id)
        server = data["servers"][server_id]
        ssh, manager = _get_ssh_and_manager(server, proto)
        try:
            ssh.connect()
            _manager_call(manager, "remove_client", proto, client_id)
        finally:
            ssh.disconnect()
        # Unlinked removal has no local mutation; never overwrite concurrent
        # accounting/access commits with the earlier snapshot.


    try:
        await asyncio.to_thread(_remove)
        await api.edit_message(chat_id, message_id, f"✅ {_tt(lang, 'connection_removed')}", reply_markup={"inline_keyboard": [[{"text": f"⬅️ {_tt(lang, 'btn_connections')}", "callback_data": _ref("clients", {"sid": server_id, "proto": proto})}]]})
    except Exception as e:
        logger.exception("Bot admin: remove client failed")
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'error')}: {_e(e)}")


async def _handle_pending_input(api: TelegramAPI, msg: dict, load_data_fn: Callable, save_data_fn: Optional[Callable], generate_vpn_link_fn: Callable, self_service_svc=None) -> bool:
    chat_id = msg["chat"]["id"]
    from_id = msg["from"]["id"]
    lang = _selected_lang(load_data_fn, str(from_id), msg.get("from"))
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
        if not panel_user.get("enabled", True):
            _pending_inputs.pop(key, None)
            await api.send_message(chat_id, f"❌ {_tt(lang, 'account_disabled')}")
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


async def _user_create_access(api: TelegramAPI, chat_id: int, panel_user: dict,
                               load_data_fn: Callable, self_service_svc, lang: str,
                               message_id: Optional[int] = None):
    """Validate all account/channel quotas before asking the user for wizard input."""
    async def show(message):
        if message_id is None:
            await api.send_message(chat_id, message)
        else:
            await api.edit_message(chat_id, message_id, message)

    data = load_data_fn()
    if not panel_user.get("enabled", True):
        await show(f"❌ {_tt(lang, 'account_disabled')}")
        return None
    if not _self_service_telegram_enabled(data):
        await show(_tt(lang, "self_service_disabled_contact"))
        return None
    if not self_service_svc:
        if not panel_user.get("enabled", True):
            await show(f"❌ {_tt(lang, 'account_disabled')}")
            return None
        user_limit = max(0, int(panel_user.get("max_connections") or 0))
        if user_limit <= 0:
            user_limit = max(0, int(_self_service_settings(data).get("max_connections_per_user", 5) or 0))
        used = sum(1 for conn in data.get("user_connections", [])
                   if conn.get("user_id") == panel_user.get("id"))
        if used >= user_limit:
            await show(f"❌ {_tt(lang, 'max_connections_reached')}")
            return None
        return {"remaining_connections": user_limit - used}

    try:
        options = await self_service_svc.get_self_service_options(panel_user["id"], "telegram")
    except Exception as exc:
        error_text = str(exc)
        if "User is disabled" in error_text:
            await show(f"❌ {_tt(lang, 'account_disabled')}")
        elif "Maximum self-service connections reached" in error_text:
            await show(f"❌ {_tt(lang, 'max_connections_reached')}")
        else:
            logger.warning("Bot: self-service preflight rejected user %s: %s",
                           panel_user.get("id"), error_text)
            await show(f"❌ {_tt(lang, 'self_service_unavailable')}")
        return None

    if int(options.get("remaining_connections", 1)) <= 0:
        await show(f"❌ {_tt(lang, 'max_connections_reached')}")
        return None
    return options


async def _user_prompt_connection_name(api: TelegramAPI, chat_id: int,
                                       message_id: Optional[int], tg_id: str,
                                       server_id: int, proto: str, server: dict,
                                       lang: str = "en"):
    _pending_inputs[_pending_key(chat_id, tg_id)] = {
        "kind": "user_add_client_name",
        "sid": server_id,
        "proto": proto,
        "ts": time.time(),
    }
    message = (
        f"➕ <b>{_tt(lang, 'btn_create_connection')}</b>\n\n"
        f"{_tt(lang, 'protocol_label')}: <b>{_e(_protocol_display_name(proto, server))}</b>\n\n"
        f"{_tt(lang, 'send_device_name')}\n"
        f"{_tt(lang, 'example_label')}: <code>Ivan iPhone</code>\n\n"
        f"{_tt(lang, 'cancel_instruction')}"
    )
    markup = {"inline_keyboard": [[{
        "text": f"❌ {_tt(lang, 'btn_cancel')}",
        "callback_data": "user_create_cancel",
    }]]}
    if message_id is None:
        await api.send_message(chat_id, message, reply_markup=markup)
    else:
        await api.edit_message(chat_id, message_id, message, reply_markup=markup)


async def _user_show_protocols(api: TelegramAPI, chat_id: int,
                               message_id: Optional[int], server_id: int,
                               server: dict, available_protos: list,
                               lang: str = "en"):
    server_name = server.get("name") or server.get("host") or _tt(
        lang, "default_server", number=server_id + 1)
    rows = [[{
        "text": _protocol_display_name(proto, server),
        "callback_data": _ref("user_create_protocol", {"sid": server_id, "proto": proto}),
    }] for proto in available_protos]
    rows.append([{
        "text": f"⬅️ {_tt(lang, 'btn_back')}",
        "callback_data": "user_create",
    }])
    message = (
        f"🖥 <b>{_e(server_name)}</b>\n\n"
        f"{_tt(lang, 'choose_protocol')}"
    )
    markup = {"inline_keyboard": rows}
    if message_id is None:
        await api.send_message(chat_id, message, reply_markup=markup)
    else:
        await api.edit_message(chat_id, message_id, message, reply_markup=markup)


async def _user_create_wizard(api: TelegramAPI, chat_id: int, tg_id: str,
                              tg_username: Optional[str], load_data_fn: Callable,
                              self_service_svc, lang: str = "en",
                              message_id: Optional[int] = None):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    async def show(message, markup=None):
        if message_id is None:
            await api.send_message(chat_id, message, reply_markup=markup)
        else:
            await api.edit_message(chat_id, message_id, message, reply_markup=markup)

    if not panel_user:
        await show(f"❌ {_tt(lang, 'access_denied')}")
        return

    options = await _user_create_access(
        api, chat_id, panel_user, load_data_fn, self_service_svc, lang, message_id)
    if options is None:
        return

    data = load_data_fn()
    eligible = _get_eligible_servers(data)
    if not eligible:
        await show(_tt(lang, "self_service_no_servers"))
        return

    if len(eligible) == 1:
        server_id, server, protocols = eligible[0]
        if len(protocols) == 1:
            await _user_prompt_connection_name(
                api, chat_id, message_id, tg_id, server_id, protocols[0], server, lang)
        else:
            await _user_show_protocols(
                api, chat_id, message_id, server_id, server, protocols, lang)
        return

    message = f"➕ <b>{_tt(lang, 'btn_create_connection')}</b>\n\n{_tt(lang, 'choose_server')}"
    markup = _user_create_server_keyboard(eligible, lang)
    await show(message, markup)


async def _user_create_start(api: TelegramAPI, chat_id: int, message_id: int,
                              callback_id: str, tg_id: str,
                              tg_username: Optional[str], load_data_fn: Callable,
                              self_service_svc, lang: str = "en"):
    await api.answer_callback(callback_id)
    await _user_create_wizard(
        api, chat_id, tg_id, tg_username, load_data_fn, self_service_svc,
        lang, message_id)


async def _user_create_start_message(api: TelegramAPI, chat_id: int, tg_id: str,
                                     tg_username: Optional[str], load_data_fn: Callable,
                                     self_service_svc, lang: str = "en"):
    await _user_create_wizard(
        api, chat_id, tg_id, tg_username, load_data_fn, self_service_svc, lang)


async def _user_create_server(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], server_id: int, load_data_fn: Callable, self_service_svc, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return
    if not panel_user.get("enabled", True):
        await api.answer_callback(callback_id, text=_tt(lang, "account_disabled"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'account_disabled')}")
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

    if len(available_protos) == 1:
        await _user_prompt_connection_name(
            api, chat_id, message_id, tg_id, server_id, available_protos[0], server, lang)
        return

    await _user_show_protocols(
        api, chat_id, message_id, server_id, server, available_protos, lang)


async def _user_create_protocol(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], server_id: int, proto: str, load_data_fn: Callable, lang: str = "en"):
    servers = load_data_fn().get("servers", [])
    server = servers[server_id] if 0 <= server_id < len(servers) else {}
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return
    if not panel_user.get("enabled", True):
        await api.answer_callback(callback_id, text=_tt(lang, "account_disabled"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'account_disabled')}")
        return

    await api.answer_callback(callback_id)

    await _user_prompt_connection_name(
        api, chat_id, message_id, tg_id, server_id, proto, server, lang)


async def _user_create_cancel(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], load_data_fn: Callable, lang: str = "en"):
    _pending_inputs.pop(_pending_key(chat_id, tg_id), None)
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
        await api.edit_message(chat_id, message_id, f" {_tt(lang, 'access_denied')}")
        return
    await api.answer_callback(callback_id)
    await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)


async def _user_delete(api: TelegramAPI, chat_id: int, message_id: int, callback_id: str, tg_id: str, tg_username: Optional[str], conn_id: str, name: str, load_data_fn: Callable, lang: str = "en"):
    panel_user = _find_user(load_data_fn, tg_id, tg_username)
    if not panel_user:
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
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

    conn_name = conn.get("name") or name or _tt(lang, "default_connection")
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
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return
    if not panel_user.get("enabled", True):
        await api.answer_callback(callback_id, text=_tt(lang, "account_disabled"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'account_disabled')}")
        return

    if not self_service_svc:
        await api.answer_callback(callback_id, text=_tt(lang, "self_service_unavailable"))
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
        await api.answer_callback(callback_id, text=_tt(lang, "access_denied"))
        await api.edit_message(chat_id, message_id, f"❌ {_tt(lang, 'access_denied')}")
        return

    if not self_service_svc:
        await api.answer_callback(callback_id, text=_tt(lang, "self_service_unavailable"))
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_unavailable"))
        return

    data = load_data_fn()
    if not _self_service_telegram_enabled(data):
        await api.answer_callback(callback_id)
        await api.edit_message(chat_id, message_id, _tt(lang, "self_service_disabled_contact"))
        return

    await api.answer_callback(callback_id)

    clean_name = (name or _tt(lang, "default_connection")).strip()[:80]
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
        if "Maximum self-service connections reached" in str(e):
            await api.send_message(chat_id, f"❌ {_tt(lang, 'max_connections_reached')}")
        else:
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
        try:
            await _set_webapp_menu_button(api, load_data_fn)
        except Exception as exc:
            logger.warning("Telegram WebApp menu button setup failed: %s", exc)

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
        lang = _selected_lang(load_data_fn, str(msg["from"]["id"]), msg["from"])
        chat_id = msg["chat"]["id"]
        if text.startswith(("/connections", "/connect", "/disconnect")) and not _is_private_chat(msg.get("chat")):
            await _reject_non_private(api, chat_id, lang)
            return
        if await _handle_pending_input(api, msg, load_data_fn, save_data_fn, generate_vpn_link_fn, self_service_svc):
            return
        if text.startswith("/start") or text.startswith("/admin"):
            await _handle_start(api, msg, load_data_fn, save_data_fn)
        elif text.startswith("/connections"):
            panel_user = _find_user(load_data_fn, str(msg["from"]["id"]), tg_username)
            if not panel_user:
                await api.send_message(chat_id, f" {_tt(lang, 'access_denied')}")
            else:
                await _send_user_connections(api, chat_id, panel_user, load_data_fn, lang=lang)
        elif text.startswith("/connect"):
            await _user_create_start_message(api, chat_id, str(msg["from"]["id"]), tg_username, load_data_fn, self_service_svc, lang)
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
        lang = _selected_lang(load_data_fn, tg_id, cq["from"])

        if data_str == "language_menu":
            await api.answer_callback(callback_id)
            await api.edit_message(chat_id, message_id, _tt(lang, "language_prompt"),
                                   reply_markup=_language_keyboard())
            return
        if data_str.startswith("lang:"):
            selected = data_str.split(":", 1)[1]
            if not _save_telegram_language(load_data_fn, save_data_fn, tg_id, selected):
                await api.answer_callback(callback_id, _tt(lang, "saving_not_available"))
                return
            lang = selected
            if _is_private_chat(chat):
                try:
                    await _set_webapp_menu_button(api, load_data_fn, chat_id=chat_id, lang=lang)
                except Exception as exc:
                    logger.warning("Telegram WebApp menu button language update failed: %s", exc)
            await api.answer_callback(callback_id, _tt(lang, "language_saved"))
            panel_user = _find_user(load_data_fn, tg_id, tg_username)
            created_password = None
            if not panel_user and _is_private_chat(chat):
                created = _auto_create_telegram_user(load_data_fn(), cq.get("from") or {}, save_data_fn)
                if created:
                    panel_user, created_password = created
            if created_password:
                await api.send_message(chat_id, _telegram_credentials_message(panel_user, created_password, lang, _panel_public_url(load_data_fn())))
            if not panel_user:
                await api.edit_message(chat_id, message_id,
                                       f"{_tt(lang, 'account_not_linked')}\n"
                                       f"{_tt(lang, 'contact_admin_to_link')}\n\n"
                                       f"{_tt(lang, 'your_telegram_id')}: <code>{_e(tg_id)}</code>",
                                       reply_markup={"inline_keyboard": [[_language_button(lang)]]})
            elif _is_admin(panel_user):
                await api.send_message(
                    chat_id,
                    f"{_tt(lang, 'registered_admin', username=_e(panel_user.get('username')))}\n"
                    f"{_tt(lang, 'choose_action')}",
                    reply_markup=_admin_main_keyboard(lang, include_language=True),
                )
            else:
                await _send_user_connections(api, chat_id, panel_user, load_data_fn,
                                             lang=lang, include_language=True)
            return
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
            await api.answer_callback(callback_id, _tt(lang, "access_denied"))
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
                servers = load_data_fn().get("servers", [])
                server = servers[sid] if 0 <= sid < len(servers) else {}
                await _admin_client_detail(api, chat_id, message_id, sid, proto, payload.get("client", {}), lang, server=server)
            elif action == "client_cfg":
                if not _is_private_chat(chat):
                    await _reject_non_private(api, chat_id, lang, callback_id)
                    return
                data = load_data_fn()
                server = data["servers"][sid]
                await _send_config_by_client(api, chat_id, server, proto, payload.get("client_id"), payload.get("name") or _tt(lang, "default_connection"), generate_vpn_link_fn, lang)
            elif action == "add_client":
                await _admin_add_client(api, chat_id, message_id, sid, proto, panel_user, load_data_fn, save_data_fn, generate_vpn_link_fn, lang, tg_id)
            elif action == "create_client":
                await _admin_create_client(api, chat_id, message_id, sid, proto, payload.get("name") or _tt(lang, "default_connection"), payload.get("user_id"), load_data_fn, save_data_fn, generate_vpn_link_fn, lang)
            elif action == "toggle_client":
                await _admin_toggle_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), bool(payload.get("enable")), load_data_fn, lang)
            elif action == "remove_client":
                await _admin_remove_client(api, chat_id, message_id, sid, proto, payload.get("client_id"), load_data_fn, save_data_fn, lang)
