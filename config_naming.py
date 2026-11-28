"""Per-instance client-facing config name templates and filename sanitization.

Allows an instance to customize the display name embedded into issued `vpn://`
payloads (`description`), `vless://` fragments (`#Name`), and downloadable
`.conf` filenames without altering server-side `awg0.conf` / `wg0.conf`.
"""
import re
import unicodedata

from protocol_names import protocol_display_name

CONFIG_NAME_TEMPLATE_MAX = 128
CONF_FILENAME_MAX_STEM = 15
CONFIG_NAME_PLACEHOLDERS = ('client', 'server', 'protocol', 'instance', 'exit')

_CYRILLIC_MAP = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'yo',
    'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm',
    'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u',
    'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch',
    'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e', 'ю': 'yu', 'я': 'ya',
    'і': 'i', 'ї': 'yi', 'є': 'ye', 'ґ': 'g', 'ў': 'u',
    'А': 'A', 'Б': 'B', 'В': 'V', 'Г': 'G', 'Д': 'D', 'Е': 'E', 'Ё': 'Yo',
    'Ж': 'Zh', 'З': 'Z', 'И': 'I', 'Й': 'Y', 'К': 'K', 'Л': 'L', 'М': 'M',
    'Н': 'N', 'О': 'O', 'П': 'P', 'Р': 'R', 'С': 'S', 'Т': 'T', 'У': 'U',
    'Ф': 'F', 'Х': 'Kh', 'Ц': 'Ts', 'Ч': 'Ch', 'Ш': 'Sh', 'Щ': 'Shch',
    'Ъ': '', 'Ы': 'Y', 'Ь': '', 'Э': 'E', 'Ю': 'Yu', 'Я': 'Ya',
    'І': 'I', 'Ї': 'Yi', 'Є': 'Ye', 'Ґ': 'G', 'Ў': 'U',
}

_WINDOWS_RESERVED_NAMES = {
    'CON', 'PRN', 'AUX', 'NUL',
    *(f'COM{i}' for i in range(1, 10)),
    *(f'LPT{i}' for i in range(1, 10)),
}

_PLACEHOLDER_RE = re.compile(r'\{(' + '|'.join(CONFIG_NAME_PLACEHOLDERS) + r')\}')
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]+')


def normalize_config_name_template(value) -> str:
    """Clean and bound a config-name template input; empty means default."""
    cleaned = _CONTROL_RE.sub(' ', str(value or '')).strip()
    return cleaned[:CONFIG_NAME_TEMPLATE_MAX]


def _instance_record(server, protocol):
    return ((server or {}).get('protocols') or {}).get(protocol) or {}


def resolve_config_name_template(server=None, protocol=None) -> str:
    """Read the template for this protocol instance."""
    return normalize_config_name_template(_instance_record(server, protocol).get('config_name_template'))


def resolve_exit_label(server=None, protocol=None, warp_ctx=None) -> str:
    """Return the active exit label for an instance (exit node name or WARP)."""
    record = _instance_record(server, protocol)
    exit_name = str(((record.get('exit_link') or {}).get('exit_name')) or '').strip()
    if exit_name:
        return exit_name
    if (warp_ctx or {}).get('active'):
        return 'WARP'
    return ''


def render_config_name(template: str, *, client='', server='', protocol='', instance='', exit_name='') -> str:
    """Substitute the supported placeholders in a client-facing name."""
    values = {
        'client': _CONTROL_RE.sub(' ', str(client or '')).strip(),
        'server': _CONTROL_RE.sub(' ', str(server or '')).strip(),
        'protocol': _CONTROL_RE.sub(' ', str(protocol or '')).strip(),
        'instance': _CONTROL_RE.sub(' ', str(instance or '')).strip(),
        'exit': _CONTROL_RE.sub(' ', str(exit_name or '')).strip(),
    }
    rendered = _PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], str(template or ''))
    # Empty optional placeholders like "({exit})" or "[{client}]" leave empty
    # brackets or dangling edge separators; clean them conservatively.
    rendered = re.sub(r'\(\s*\)|\[\s*\]', '', rendered)
    rendered = _CONTROL_RE.sub(' ', rendered)
    rendered = re.sub(r'\s+', ' ', rendered).strip()
    # Collapse doubled separator tokens caused by an empty middle placeholder.
    rendered = re.sub(r'(?:\s+[-|/·:]\s+){2,}', ' - ', rendered)
    rendered = re.sub(r'^[-|/·:\s]+|[-|/·:\s]+$', '', rendered)
    return rendered[:CONFIG_NAME_TEMPLATE_MAX].strip()


def sanitize_conf_filename(name: str, max_stem_len: int = CONF_FILENAME_MAX_STEM) -> str:
    """Sanitize a tunnel name into an ASCII `.conf` filename safe for native WG/AWG.

    Native WireGuard / AmneziaWG clients use the `.conf` stem as the tunnel name
    and reject path separators, special characters, overly long names, or
    non-ASCII names on `wg-quick`.
    """
    raw = str(name or '').strip()
    if raw.lower().endswith('.conf'):
        raw = raw[:-5]
    transliterated = ''.join(_CYRILLIC_MAP.get(ch, ch) for ch in raw)
    folded = unicodedata.normalize('NFKD', transliterated)
    ascii_only = folded.encode('ascii', 'ignore').decode('ascii')
    stem = re.sub(r'[^A-Za-z0-9_-]+', '_', ascii_only)
    stem = re.sub(r'(?:_+-+_*|-+_+_*)', '_', stem)
    stem = re.sub(r'_+', '_', stem).strip('_-')
    limit = max(1, int(max_stem_len or CONF_FILENAME_MAX_STEM))
    if len(stem) > limit:
        stem = stem[:limit].rstrip('_-')
    if not stem:
        stem = 'tunnel'
    if stem.upper() in _WINDOWS_RESERVED_NAMES:
        stem = f'{stem[:max(1, limit - 3)]}_wg'
    return f'{stem}.conf'


def connection_display_name(
    server=None,
    protocol=None,
    client_name='',
    *,
    short_name_fn=None,
    warp_ctx=None,
) -> str:
    """Compute the client-visible name for `vpn://` description and `vless://#name`."""
    node = str((server or {}).get('name') or (server or {}).get('host') or '').strip()
    record = _instance_record(server, protocol)
    if protocol and short_name_fn is not None:
        tag = short_name_fn(protocol, record.get('header_protection'), record.get('protocol_version'))
    else:
        tag = str(protocol or '').strip()
    default_name = ' '.join(part for part in (node, tag) if part)

    template = resolve_config_name_template(server, protocol)
    if not template:
        return default_name

    exit_name = resolve_exit_label(server, protocol, warp_ctx=warp_ctx)
    instance = ''
    if protocol:
        instance = record.get('custom_name') or protocol_display_name(
            protocol, record.get('header_protection'), record.get('protocol_version'))
    rendered = render_config_name(
        template,
        client=client_name,
        server=node,
        protocol=tag,
        instance=instance,
        exit_name=exit_name,
    )
    return rendered or default_name
