"""Email delivery of client configurations and proxy links.

Everything the panel already hands a user by hand -- the `.conf` file of a
WireGuard-style peer, the `vpn://` key built from it, the `vless://` / `tg://`
link of a proxy -- this module puts into an email instead: to a single user
from their card, or to every user that has an address in one background run.

Nothing about a protocol is re-derived here. The config text comes from the
same manager call the share page and the Telegram bot use, and the link from
the same `config_payloads()`, so a protocol that renders correctly in the UI
renders correctly in an email. The only protocol-shaped decision made locally
is whether a connection travels as an attachment or as a link: Xray and Telemt
*are* links (their "config" is the URL itself), everything else is a file plus
the `vpn://` key generated from it.

Every message goes out as text plus an HTML alternative. The HTML half wears
the panel's own design tokens -- the light-theme colours, radius and type scale
from `static/css/style.css`, and the appearance title/logo the admin set -- and
nothing from anywhere else. The text half is what mail providers score for spam
and what a `vpn://` key survives intact, so it is never dropped.
"""

import html
import logging
import re
import smtplib
import ssl
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

logger = logging.getLogger(__name__)


DEFAULT_MAIL_SETTINGS = {
    'enabled': False,
    'host': '',
    'port': 587,
    'security': 'starttls',   # none | starttls | ssl
    'username': '',
    'password': '',
    'from_email': '',
    'from_name': '',
    'reply_to': '',
    'timeout_seconds': 30,
}

SECURITY_CHOICES = ('none', 'starttls', 'ssl')

# Protocols whose "config" is already a link: nothing to attach, and wrapping
# them in a .conf file would only give the user a file no client can import.
LINK_ONLY_PROTOCOLS = ('xray', 'telemt')

# Enough for a user with a peer on every server; a bulk run that tried to
# attach more than this hit something other than a normal account.
MAX_ATTACHMENTS_PER_MESSAGE = 50

# The panel's light theme (static/css/style.css), inlined: mail clients strip
# <style> blocks and know nothing about CSS variables, so the tokens have to
# travel as literal values on each element.
PANEL_STYLE = {
    'font': "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    'page_bg': '#f5f5f9',
    'card_bg': '#ffffff',
    'text': '#1a1a2e',
    'muted': '#6b6b83',
    'accent': '#7c3aed',
    'border': 'rgba(0, 0, 0, 0.08)',
    'radius': '12px',
}

# Deliberately loose: we reject the obviously unusable (no @, spaces, no dot in
# the domain) and leave the rest to the SMTP server, which is the only party
# that actually knows whether an address exists.
EMAIL_RE = re.compile(r'^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$')


class MailError(Exception):
    """Something the caller can fix: no SMTP settings, no recipient, no configs."""

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


# ===================== settings =====================

def mail_settings(data):
    """The mail block of data.json, with every default filled in."""
    stored = (data.get('settings', {}) or {}).get('mail', {}) or {}
    merged = dict(DEFAULT_MAIL_SETTINGS)
    for key in DEFAULT_MAIL_SETTINGS:
        if key in stored:
            merged[key] = stored[key]
    return merged


def _clamp_int(value, fallback, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, number))


def merge_mail_settings(current, incoming):
    """Fold a settings-form payload onto the stored block.

    The password is the one field the settings page never echoes back (it
    would put the SMTP password in the page source of every admin session),
    so an empty password in the payload means "keep the stored one". Clearing
    it is an explicit act: send a single space.
    """
    merged = dict(DEFAULT_MAIL_SETTINGS)
    for key in DEFAULT_MAIL_SETTINGS:
        if key in (current or {}):
            merged[key] = (current or {})[key]

    incoming = incoming or {}
    for key in ('host', 'username', 'from_email', 'from_name', 'reply_to'):
        if key in incoming:
            merged[key] = str(incoming.get(key) or '').strip()
    if 'enabled' in incoming:
        merged['enabled'] = bool(incoming.get('enabled'))
    if 'port' in incoming:
        merged['port'] = _clamp_int(incoming.get('port'), merged['port'] or 587, 1, 65535)
    if 'timeout_seconds' in incoming:
        merged['timeout_seconds'] = _clamp_int(
            incoming.get('timeout_seconds'), merged['timeout_seconds'] or 30, 5, 300)
    if 'security' in incoming:
        security = str(incoming.get('security') or '').strip().lower()
        if security in SECURITY_CHOICES:
            merged['security'] = security
    if 'password' in incoming:
        password = str(incoming.get('password') or '')
        if password.strip():
            merged['password'] = password
        elif password:            # a whitespace-only value is the explicit clear
            merged['password'] = ''
    return merged


def is_valid_email(value):
    return bool(EMAIL_RE.match(str(value or '').strip()))


def validate_mail_settings(settings):
    """Raise unless the block can actually send. Returns the settings."""
    if not settings.get('enabled'):
        raise MailError('mail_error_disabled')
    if not str(settings.get('host') or '').strip():
        raise MailError('mail_error_no_host')
    if not is_valid_email(settings.get('from_email')):
        raise MailError('mail_error_no_sender')
    if str(settings.get('security') or '') not in SECURITY_CHOICES:
        raise MailError('mail_error_bad_security')
    return settings


# ===================== SMTP transport =====================

def default_smtp_factory(settings):
    """A connected smtplib client for these settings (no login yet)."""
    host = str(settings.get('host') or '').strip()
    port = int(settings.get('port') or 587)
    timeout = int(settings.get('timeout_seconds') or 30)
    if settings.get('security') == 'ssl':
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    return smtplib.SMTP(host, port, timeout=timeout)


class SmtpTransport:
    """One SMTP session, reused for a whole run.

    A bulk send to a few hundred users over a fresh connection per message is
    both slow and the shape of traffic that gets an account rate-limited, so
    the session is opened once and handed every message. Providers still drop
    idle or long sessions, hence the single reconnect-and-retry on a dropped
    connection -- anything worse is the caller's problem to report per user.
    """

    def __init__(self, settings, smtp_factory=None):
        self.settings = settings
        self._factory = smtp_factory or default_smtp_factory
        self.client = None
        self.sent = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def open(self):
        if self.client is not None:
            return self.client
        client = self._factory(self.settings)
        try:
            if self.settings.get('security') == 'starttls':
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            username = str(self.settings.get('username') or '').strip()
            if username:
                client.login(username, str(self.settings.get('password') or ''))
        except Exception:
            try:
                client.quit()
            except Exception:
                pass
            raise
        self.client = client
        return client

    def send(self, message):
        client = self.open()
        try:
            client.send_message(message)
        except smtplib.SMTPServerDisconnected:
            logger.info("SMTP session dropped, reconnecting for one retry")
            self.close()
            self.open().send_message(message)
        self.sent += 1

    def close(self):
        client, self.client = self.client, None
        if client is None:
            return
        try:
            client.quit()
        except Exception:
            try:
                client.close()
            except Exception:
                pass


# ===================== message building =====================

def _safe_filename(name, protocol, used):
    base = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(name or protocol or 'config')).strip('._-')
    base = (base or 'config')[:48]
    candidate = f'{base}.conf'
    index = 2
    while candidate.lower() in used:
        candidate = f'{base}_{index}.conf'
        index += 1
    used.add(candidate.lower())
    return candidate


def _paragraphs(text):
    return [line for line in str(text or '').splitlines()]


class MailOptions:
    """What the admin ticked in the send dialog."""

    def __init__(self, include_configs=True, include_links=True, subject='', message='',
                 recipient='', only_enabled=True, skip_without_connections=True):
        self.include_configs = bool(include_configs)
        self.include_links = bool(include_links)
        # Header values may not carry linefeeds, and EmailMessage raises on
        # them -- fold a pasted multi-line subject instead of failing the send.
        self.subject = ' '.join(str(subject or '').split())
        self.message = str(message or '').strip()
        self.recipient = str(recipient or '').strip()
        self.only_enabled = bool(only_enabled)
        self.skip_without_connections = bool(skip_without_connections)
        if not self.include_configs and not self.include_links:
            raise MailError('mail_error_nothing_to_send')

    @classmethod
    def from_dict(cls, raw):
        raw = raw or {}
        return cls(
            include_configs=raw.get('include_configs', True),
            include_links=raw.get('include_links', True),
            subject=raw.get('subject', ''),
            message=raw.get('message', ''),
            recipient=raw.get('recipient', ''),
            only_enabled=raw.get('only_enabled', True),
            skip_without_connections=raw.get('skip_without_connections', True),
        )

    def to_dict(self):
        return {
            'include_configs': self.include_configs,
            'include_links': self.include_links,
            'subject': self.subject,
            'message': self.message,
            'only_enabled': self.only_enabled,
            'skip_without_connections': self.skip_without_connections,
        }


def _panel_header(appearance):
    """The panel's own logo and title, as it shows them in its header."""
    title = str((appearance or {}).get('title') or '').strip()
    logo = str((appearance or {}).get('logo') or '').strip()
    return ' '.join(part for part in (logo, title) if part)


def build_message(*, settings, recipient, username, items, options, translate, appearance=None):
    """The email itself: plain text, an HTML alternative and the attachments."""
    msg = EmailMessage()
    header = _panel_header(appearance)
    panel_title = str((appearance or {}).get('title') or '').strip()
    from_email = str(settings.get('from_email') or '').strip()
    from_name = str(settings.get('from_name') or '').strip() or panel_title
    msg['From'] = formataddr((from_name, from_email)) if from_name else from_email
    msg['To'] = recipient
    reply_to = str(settings.get('reply_to') or '').strip()
    if reply_to:
        msg['Reply-To'] = reply_to
    subject = options.subject or translate('mail_default_subject')
    if not options.subject and panel_title:
        subject = f'{subject} \u2014 {panel_title}'
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    domain = from_email.split('@')[-1] if '@' in from_email else None
    msg['Message-ID'] = make_msgid(domain=domain) if domain else make_msgid()
    # Auto-generated mail: keep vacation responders and other robots quiet.
    msg['Auto-Submitted'] = 'auto-generated'

    s = PANEL_STYLE
    lines = []
    html_parts = [
        f'<div style="background:{s["page_bg"]};padding:24px 12px;font-family:{s["font"]};">',
        f'<div style="max-width:560px;margin:0 auto;background:{s["card_bg"]};'
        f'border:1px solid {s["border"]};border-radius:{s["radius"]};padding:24px;'
        f'color:{s["text"]};font-size:15px;line-height:1.55;">',
    ]
    if header:
        lines.append(header)
        lines.append('')
        html_parts.append(
            f'<div style="font-size:18px;font-weight:700;color:{s["accent"]};'
            f'margin:0 0 16px 0;">{html.escape(header)}</div>'
        )

    greeting = translate('mail_greeting').replace('{}', username)
    lines.extend([greeting, ''])
    html_parts.append(f'<p style="margin:0 0 12px 0;">{html.escape(greeting)}</p>')

    if options.message:
        lines.extend(_paragraphs(options.message))
        lines.append('')
        body = '<br>'.join(html.escape(line) for line in _paragraphs(options.message))
        html_parts.append(f'<p style="margin:0 0 12px 0;">{body}</p>')

    if items:
        intro = translate('mail_intro_connections')
        lines.extend([intro, ''])
        html_parts.append(f'<p style="margin:0 0 16px 0;">{html.escape(intro)}</p>')

    attachments = []
    used_names = set()
    for item in items:
        heading = f"{item['name']} - {item['protocol_name']}"
        if item.get('server_name'):
            heading += f" ({item['server_name']})"
        lines.append(heading)
        html_parts.append(
            f'<div style="margin:0 0 12px 0;padding:12px 14px;border:1px solid {s["border"]};'
            f'border-radius:{s["radius"]};">'
            f'<div style="font-weight:600;">{html.escape(heading)}</div>'
        )
        if options.include_links and item.get('link'):
            label = translate('mail_link_label')
            lines.append(f"  {label}: {item['link']}")
            html_parts.append(
                f'<div style="margin-top:8px;color:{s["muted"]};font-size:13px;">'
                f'{html.escape(label)}</div>'
                f'<div style="word-break:break-all;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;'
                f'font-size:13px;color:{s["accent"]};">{html.escape(item["link"])}</div>'
            )
        if options.include_configs and item.get('config') and len(attachments) < MAX_ATTACHMENTS_PER_MESSAGE:
            filename = _safe_filename(item.get('name'), item.get('protocol'), used_names)
            attachments.append((filename, item['config']))
            label = translate('mail_file_label')
            lines.append(f"  {label}: {filename}")
            html_parts.append(
                f'<div style="margin-top:8px;color:{s["muted"]};font-size:13px;">'
                f'{html.escape(label)}: {html.escape(filename)}</div>'
            )
        lines.append('')
        html_parts.append('</div>')

    if not items:
        note = translate('mail_no_connections_note')
        lines.extend([note, ''])
        html_parts.append(f'<p style="margin:0 0 12px 0;">{html.escape(note)}</p>')

    footer = translate('mail_footer')
    lines.append(footer)
    html_parts.append(
        f'<p style="margin:20px 0 0 0;color:{s["muted"]};font-size:13px;">{html.escape(footer)}</p>'
        '</div></div>'
    )

    msg.set_content('\n'.join(lines))
    msg.add_alternative(''.join(html_parts), subtype='html')
    for filename, config in attachments:
        # text/plain, not application/octet-stream: every mail client then shows
        # a preview instead of a file it warns the user about.
        msg.add_attachment(config.encode('utf-8'), maintype='text', subtype='plain', filename=filename)
    return msg, len(attachments)


# ===================== the service =====================

class BulkJob:
    """State of one mass send, polled by the UI."""

    def __init__(self, total, options, started_by=''):
        self._lock = threading.Lock()
        self._state = {
            'running': True,
            'total': total,
            'sent': 0,
            'failed': 0,
            'skipped': 0,
            'started_at': datetime.now().isoformat(),
            'finished_at': None,
            'started_by': started_by,
            'error': '',
            'options': options.to_dict(),
            'results': [],
        }

    def record(self, entry):
        with self._lock:
            status = entry.get('status')
            if status in ('sent', 'failed', 'skipped'):
                self._state[status] += 1
            self._state['results'].append(entry)

    def finish(self, error=''):
        with self._lock:
            self._state['running'] = False
            self._state['finished_at'] = datetime.now().isoformat()
            if error:
                self._state['error'] = str(error)

    def snapshot(self):
        with self._lock:
            state = dict(self._state)
            state['results'] = list(self._state['results'])
            return state


class MailService:
    """Sends configs and links by email, to one user or to all of them.

    Every panel-specific operation is injected, which keeps this module free of
    FastAPI and of the SSH layer: the tests drive it with plain fakes.
    """

    def __init__(self, load_data, get_ssh, get_protocol_manager, manager_call,
                 config_payloads, protocol_display_name, protocol_base,
                 translate=None, smtp_factory=None):
        self._load_data = load_data
        self._get_ssh = get_ssh
        self._get_protocol_manager = get_protocol_manager
        self._manager_call = manager_call
        self._config_payloads = config_payloads
        self._protocol_display_name = protocol_display_name
        self._protocol_base = protocol_base
        self._translate = translate or (lambda key, lang='en': key)
        self._smtp_factory = smtp_factory
        self._job_lock = threading.Lock()
        self._job = None

    # ---------- helpers ----------

    def _t(self, lang):
        return lambda key: self._translate(key, lang)

    def settings(self, data=None):
        return mail_settings(data if data is not None else self._load_data())

    def _appearance(self, data):
        return (data.get('settings', {}) or {}).get('appearance', {}) or {}

    def _find_user(self, data, user_id):
        user = next((u for u in data.get('users', []) if u.get('id') == user_id), None)
        if not user:
            raise MailError('mail_error_user_not_found', status_code=404)
        return user

    def collect_items(self, data, user):
        """Config text and link for every connection the user owns.

        Unreachable servers are reported, not raised: an admin sending to 200
        users should not lose the run because one node is down, and the user
        whose peer lives there is told which connection is missing.
        """
        items, errors = [], []
        servers = data.get('servers', [])
        conns = [c for c in data.get('user_connections', []) if c.get('user_id') == user.get('id')]
        for conn in conns:
            sid = conn.get('server_id', 0)
            protocol = conn.get('protocol', 'awg')
            name = conn.get('name') or self._protocol_display_name(protocol)
            if sid >= len(servers):
                errors.append(f"{name}: server {sid} not found")
                continue
            server = servers[sid]
            record = (server.get('protocols') or {}).get(protocol, {})
            protocol_name = self._protocol_display_name(
                protocol, record.get('header_protection'), record.get('protocol_version'))
            if not conn.get('name'):
                name = protocol_name
            try:
                proto_info = (server.get('protocols', {}) or {}).get(protocol, {}) or {}
                port = proto_info.get('port', '55424')
                ssh = self._get_ssh(server)
                ssh.connect()
                try:
                    manager = self._get_protocol_manager(ssh, protocol)
                    config = self._manager_call(
                        manager, 'get_client_config', protocol,
                        conn.get('client_id'), server.get('host'), port)
                finally:
                    ssh.disconnect()
            except Exception as exc:
                logger.warning(f"Mail: cannot read config for {name} ({protocol}): {exc}")
                errors.append(f"{name}: {exc}")
                continue
            if not str(config or '').strip():
                errors.append(f"{name}: empty config")
                continue

            item = {
                'connection_id': conn.get('id', ''),
                'name': name,
                'protocol': protocol,
                'protocol_name': protocol_name,
                'server_name': server.get('name') or server.get('host', ''),
                'config': '',
                'link': '',
            }
            if self._protocol_base(protocol) in LINK_ONLY_PROTOCOLS:
                item['link'] = str(config).strip()
            else:
                payloads = self._config_payloads(config, server, protocol)
                item['config'] = payloads.get('config') or config
                item['link'] = payloads.get('vpn_link') or ''
            items.append(item)
        return items, errors

    # ---------- single user ----------

    def send_to_user(self, user_id, options, lang='en', transport=None):
        data = self._load_data()
        settings = validate_mail_settings(self.settings(data))
        user = self._find_user(data, user_id)
        recipient = options.recipient or str(user.get('email') or '').strip()
        if not is_valid_email(recipient):
            raise MailError('mail_error_no_recipient')

        items, errors = self.collect_items(data, user)
        if not items and options.skip_without_connections:
            raise MailError('mail_error_no_connections')

        message, attached = build_message(
            settings=settings,
            recipient=recipient,
            username=user.get('username', ''),
            items=items,
            options=options,
            translate=self._t(lang),
            appearance=self._appearance(data),
        )
        if transport is not None:
            transport.send(message)
        else:
            with SmtpTransport(settings, self._smtp_factory) as smtp:
                smtp.send(message)
        logger.info(f"Mail: sent {attached} attachment(s) to {recipient}")
        return {
            'status': 'sent',
            'user_id': user.get('id'),
            'username': user.get('username', ''),
            'email': recipient,
            'attachments': attached,
            'links': sum(1 for i in items if i.get('link')) if options.include_links else 0,
            'connections': len(items),
            'warnings': errors,
        }

    # ---------- everyone ----------

    def _bulk_recipients(self, data, options, user_ids=None):
        """(user, reason) pairs: reason empty means "send"."""
        wanted = set(user_ids or [])
        out = []
        for user in data.get('users', []):
            if wanted and user.get('id') not in wanted:
                continue
            email = str(user.get('email') or '').strip()
            if not email:
                out.append((user, 'mail_skip_no_email'))
            elif not is_valid_email(email):
                out.append((user, 'mail_skip_bad_email'))
            elif options.only_enabled and user.get('enabled') is False:
                out.append((user, 'mail_skip_disabled'))
            else:
                out.append((user, ''))
        return out

    def bulk_status(self):
        with self._job_lock:
            job = self._job
        return job.snapshot() if job else {'running': False, 'total': 0, 'sent': 0,
                                           'failed': 0, 'skipped': 0, 'results': []}

    def start_bulk(self, options, lang='en', user_ids=None, started_by='', background=True):
        """Kick off a mass send. One run at a time, progress polled from the UI."""
        data = self._load_data()
        validate_mail_settings(self.settings(data))
        targets = self._bulk_recipients(data, options, user_ids)
        if not targets:
            raise MailError('mail_error_no_recipients')

        with self._job_lock:
            if self._job is not None and self._job.snapshot().get('running'):
                raise MailError('mail_error_bulk_running', status_code=409)
            job = BulkJob(total=len(targets), options=options, started_by=started_by)
            self._job = job

        if background:
            threading.Thread(target=self._run_bulk, args=(job, targets, options, lang),
                             name='mail-bulk', daemon=True).start()
        else:
            self._run_bulk(job, targets, options, lang)
        return job.snapshot()

    def _run_bulk(self, job, targets, options, lang):
        # Everything lives inside the try: a settings block that went bad
        # between the click and this thread must finish the job with an error,
        # not leave it "running" forever and block every later run with a 409.
        transport = None
        try:
            settings = validate_mail_settings(self.settings())
            transport = SmtpTransport(settings, self._smtp_factory)
            for user, skip_reason in targets:
                entry = {'user_id': user.get('id'), 'username': user.get('username', ''),
                         'email': str(user.get('email') or '').strip()}
                if skip_reason:
                    job.record({**entry, 'status': 'skipped', 'reason': skip_reason})
                    continue
                try:
                    result = self.send_to_user(user.get('id'), options, lang=lang, transport=transport)
                    job.record({**entry, 'status': 'sent',
                                'attachments': result['attachments'],
                                'connections': result['connections'],
                                'warnings': result['warnings']})
                except MailError as exc:
                    # "no connections yet" is a property of the account, not a
                    # failure of the run: it lands in skipped so the counters
                    # keep meaning what they say.
                    status = 'skipped' if str(exc) == 'mail_error_no_connections' else 'failed'
                    job.record({**entry, 'status': status, 'reason': str(exc)})
                except Exception as exc:
                    logger.exception(f"Mail: bulk send failed for {entry['email']}")
                    job.record({**entry, 'status': 'failed', 'reason': str(exc)})
        except Exception as exc:
            logger.exception("Mail: bulk run aborted")
            job.finish(error=str(exc))
            return
        finally:
            if transport is not None:
                transport.close()
        job.finish()

    # ---------- smoke test from the settings page ----------

    def send_test(self, recipient, lang='en'):
        data = self._load_data()
        settings = validate_mail_settings(self.settings(data))
        recipient = str(recipient or '').strip()
        if not is_valid_email(recipient):
            raise MailError('mail_error_no_recipient')
        translate = self._t(lang)
        appearance = self._appearance(data)
        panel_title = str(appearance.get('title') or '').strip()
        msg = EmailMessage()
        from_email = str(settings.get('from_email') or '').strip()
        from_name = str(settings.get('from_name') or '').strip() or panel_title
        msg['From'] = formataddr((from_name, from_email)) if from_name else from_email
        msg['To'] = recipient
        subject = translate('mail_test_subject')
        msg['Subject'] = f'{subject} \u2014 {panel_title}' if panel_title else subject
        msg['Date'] = formatdate(localtime=True)
        msg['Auto-Submitted'] = 'auto-generated'
        msg.set_content(translate('mail_test_body'))
        started = time.time()
        with SmtpTransport(settings, self._smtp_factory) as smtp:
            smtp.send(msg)
        return {'status': 'sent', 'email': recipient, 'took_ms': int((time.time() - started) * 1000)}
