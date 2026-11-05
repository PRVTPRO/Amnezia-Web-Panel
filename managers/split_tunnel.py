"""Networks that bypass the VPN, baked into every WireGuard/AmneziaWG client config.

The admin keeps one list of IPv4 networks (typed in, loaded from a file or
fetched from public country lists). Every client config the panel generates
then carries `AllowedIPs = 0.0.0.0/0 minus those networks minus local ranges`,
so traffic to them leaves through the user's own ISP and everything else goes
into the tunnel. Nothing changes on the server: a peer's server-side
AllowedIPs is its tunnel address, so configs issued before keep working next
to regenerated ones. IPv6 parts of the line (`::/0`) are left as they are.

Size matters on Windows: every AllowedIPs entry becomes an on-link route plus
a broadcast /32 Windows adds by itself. With the full Russian list (~8.7k
networks -> ~22k entries -> ~43k routes) the Network List Service keeps a CPU
core busy and connecting takes minutes; the shortened list (big networks plus
the networks of popular services, ~1.1k entries) does not. That is why the
public-list fetch shortens by default.
"""
import bisect
import ipaddress
import json
import os
import re
import socket
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

DEFAULT_SETTINGS = {
    'enabled': False,
    'networks': [],
    'source': '',
    'source_detail': '',
    'shortened': False,
    'updated_at': None,
}


def default_settings():
    return {**DEFAULT_SETTINGS, 'networks': []}

# Never sent into the tunnel and never worth a route: "this host", private,
# CGNAT, loopback, link-local, multicast and reserved.
LOCAL_V4 = tuple(ipaddress.IPv4Network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3'))

FULL_TUNNEL_V4 = '0.0.0.0/0'
MAX_NETWORKS = 100000
# Above this many AllowedIPs entries Windows clients slow down noticeably.
LARGE_ALLOWED_IPS = 3000
SHORTEN_MAX_PREFIXLEN = 16
MIN_COUNTRY_NETWORKS = 100
FETCH_TIMEOUT = 60

COUNTRY_SOURCES = (
    ('RIPEstat', 'ripestat',
     'https://stat.ripe.net/data/country-resource-list/data.json?resource={cc}&v4_format=prefix'),
    ('ipdeny.com', 'text',
     'https://www.ipdeny.com/ipblocks/data/aggregated/{cc_lower}-aggregated.zone'),
    ('herrbischoff/country-ip-blocks', 'text',
     'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{cc_lower}.cidr'),
)

# Services whose networks stay outside the tunnel even in the shortened list:
# the whole registered network containing any of their current addresses.
RU_SERVICE_HOSTS = (
    # Yandex
    'ya.ru', 'yandex.ru', 'mail.yandex.ru', 'disk.yandex.ru', 'music.yandex.ru',
    'market.yandex.ru', 'eda.yandex.ru', 'taxi.yandex.ru', 'maps.yandex.ru',
    'kinopoisk.ru', 'dzen.ru', 'ipv4-internet.yandex.net', 'yandex.net',
    'yastatic.net', 'avatars.mds.yandex.net', 'storage.yandexcloud.net',
    # VK
    'vk.com', 'vk.ru', 'vkvideo.ru', 'userapi.com', 'vkuser.net', 'vk-portal.net',
    'ok.ru', 'mail.ru', 'e.mail.ru', 'max.ru', 'web.max.ru', 'api.oneme.ru',
    # State services
    'gosuslugi.ru', 'esia.gosuslugi.ru', 'nalog.gov.ru', 'lkfl2.nalog.ru', 'mos.ru',
    'sfr.gov.ru', 'gu.spb.ru',
    # Banks
    'sberbank.ru', 'online.sberbank.ru', 'sber.ru', 'tbank.ru', 'tinkoff.ru',
    'vtb.ru', 'online.vtb.ru', 'alfabank.ru', 'gazprombank.ru', 'raiffeisen.ru',
    'pochtabank.ru', 'open.ru', 'psbank.ru', 'rshb.ru', 'mkb.ru', 'sovcombank.ru',
    # Shops and delivery
    'ozon.ru', 'wildberries.ru', 'avito.ru', 'dns-shop.ru', 'mvideo.ru', 'eldorado.ru',
    'lamoda.ru', 'sportmaster.ru', 'citilink.ru', 'lenta.com', 'magnit.ru', '5ka.ru',
    'perekrestok.ru', 'vkusvill.ru', 'samokat.ru', 'kuper.ru', 'cdek.ru', 'pochta.ru',
    # Telecom
    'mts.ru', 'beeline.ru', 'megafon.ru', 't2.ru', 'rt.ru',
    # Media and video
    'rutube.ru', 'ivi.ru', 'okko.tv', 'wink.ru', 'kion.ru', 'premier.one', 'rbc.ru',
    'ria.ru', 'lenta.ru', 'kommersant.ru', 'rambler.ru', 'gismeteo.ru',
    # Travel, jobs, maps, other
    '2gis.ru', 'hh.ru', 'cian.ru', 'domclick.ru', 'rzd.ru', 'aeroflot.ru',
    'pobeda.aero', 'tutu.ru', 'auto.ru', 'drom.ru', 'kaspersky.ru', '1c.ru',
    'consultant.ru', 'sbis.ru', 'kontur.ru',
)
SERVICE_HOSTS = {'RU': RU_SERVICE_HOSTS}


class SplitTunnelError(Exception):
    """A user-facing failure; `code` selects the translated message."""

    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.details = details


# ======================== Parsing ========================

_RANGE_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})')
_TOKEN_SPLIT_RE = re.compile(r'[\s,;"\'\[\]{}()<>]+')
_LOOKS_V4_RE = re.compile(r'^\d+(?:\.\d+){3}(?:/\d+)?$')


def parse_networks(text):
    """Pull IPv4 networks out of whatever the admin pasted or uploaded.

    Accepts one CIDR per line as well as comma/space separated lists, bare
    addresses, `a.b.c.d-e.f.g.h` ranges, JSON (AmneziaVPN site lists
    included) and ipset/iptables dumps: everything that is not an address is
    ignored, `#` starts a comment. Returns (networks, invalid, ipv6_skipped).
    """
    networks, invalid, ipv6_skipped = [], [], 0
    for raw_line in str(text or '').splitlines():
        line = raw_line.split('#', 1)[0]

        def take_range(match):
            try:
                first, last = (ipaddress.IPv4Address(x) for x in match.groups())
                if first > last:
                    raise ValueError
                networks.extend(ipaddress.summarize_address_range(first, last))
            except ValueError:
                invalid.append(match.group(0))
            return ' '

        line = _RANGE_RE.sub(take_range, line)
        for token in _TOKEN_SPLIT_RE.split(line):
            token = token.strip()
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                try:  # "1.2.3.0/24:" from key:value dumps
                    net = ipaddress.ip_network(token.rstrip(':'), strict=False)
                except ValueError:
                    if _LOOKS_V4_RE.match(token):
                        invalid.append(token)
                    continue
            if net.version == 4:
                networks.append(net)
            else:
                ipv6_skipped += 1
        if len(networks) > MAX_NETWORKS:
            raise SplitTunnelError('too_many', f'More than {MAX_NETWORKS} networks', limit=MAX_NETWORKS)
    return networks, invalid, ipv6_skipped


def normalize(networks):
    """Collapse, sort and stringify; drops ranges the client never routes anyway."""
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(n) for n in collapsed if not any(n.subnet_of(local) for local in LOCAL_V4)]


# ======================== AllowedIPs ========================

def complement(excluded):
    """0.0.0.0/0 minus `excluded`, as the shortest list of CIDRs."""
    out, cursor = [], 0
    for net in ipaddress.collapse_addresses(excluded):
        first, last = int(net.network_address), int(net.broadcast_address)
        if first > cursor:
            out.extend(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(first - 1)))
        cursor = max(cursor, last + 1)
    if cursor <= 2 ** 32 - 1:
        out.extend(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(2 ** 32 - 1)))
    return out


def tunnel_entries(networks):
    """IPv4 AllowedIPs entries replacing 0.0.0.0/0 for this bypass list."""
    excluded = [ipaddress.IPv4Network(n) for n in networks] + list(LOCAL_V4)
    entries = [str(n) for n in complement(excluded)]
    if not entries:
        raise SplitTunnelError('covers_all', 'The list leaves nothing for the tunnel')
    return entries


def _map_allowed_ips(config_text, change):
    """Run `change(parts)` over every [Peer] AllowedIPs line; a None result
    keeps the line as it was."""
    out, section = [], ''
    for line in str(config_text).splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped.lower()
        key, sep, value = line.partition('=')
        if section == '[peer]' and sep and key.strip().lower() == 'allowedips':
            parts = change([p.strip() for p in value.split(',') if p.strip()])
            if parts is not None:
                ending = line[len(line.rstrip('\r\n')):]
                line = 'AllowedIPs = ' + ', '.join(parts) + ending
        out.append(line)
    return ''.join(out)


def rewrite_allowed_ips(config_text, entries):
    """Replace 0.0.0.0/0 in the [Peer] AllowedIPs line with `entries`.

    Lines without 0.0.0.0/0 were narrowed on purpose (a hand-edited config)
    and are left alone, as is every other part of the line (::/0 included).
    """
    if not entries or not config_text:
        return config_text

    def expand(parts):
        if FULL_TUNNEL_V4 not in parts:
            return None
        return list(entries) + [p for p in parts if p != FULL_TUNNEL_V4]

    return _map_allowed_ips(config_text, expand)


def fold_allowed_ips(config_text, entries):
    """The inverse of rewrite_allowed_ips: an AllowedIPs line whose IPv4 part
    is exactly `entries` goes back to 0.0.0.0/0. Used before a hand-edited
    config is stored, so the stored copy keeps following the bypass list
    instead of freezing today's expansion."""
    if not entries or not config_text:
        return config_text
    wanted = set(entries)

    def fold(parts):
        v4 = [p for p in parts if ':' not in p]
        if set(v4) != wanted:
            return None
        return [FULL_TUNNEL_V4] + [p for p in parts if ':' in p]

    return _map_allowed_ips(config_text, fold)


# ======================== Public country lists ========================

def _http_get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Amnezia-Web-Panel'})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read().decode('utf-8', 'replace')


def _parse_ripestat(text):
    data = json.loads(text).get('data') or {}
    entries = (data.get('resources') or {}).get('ipv4') or []
    networks, _, _ = parse_networks('\n'.join(entries))
    stamp = str(data.get('query_time') or '')[:10]
    return networks, stamp


def fetch_country_networks(country='RU', fetch=_http_get):
    """Networks registered to `country`, from the first source that answers.

    A source that fails or returns fewer than MIN_COUNTRY_NETWORKS networks
    is skipped. Returns (networks, source label); raises SplitTunnelError when
    every source fails.
    """
    cc = str(country or '').upper()
    if not re.fullmatch(r'[A-Z]{2}', cc):
        raise SplitTunnelError('bad_country', f'Unknown country code: {country}')
    problems = []
    for name, kind, template in COUNTRY_SOURCES:
        url = template.format(cc=cc, cc_lower=cc.lower())
        try:
            text = fetch(url)
            if kind == 'ripestat':
                networks, stamp = _parse_ripestat(text)
            else:
                networks, _, _ = parse_networks(text)
                stamp = ''
        except Exception as exc:  # network, HTTP, JSON: try the next source
            problems.append(f'{name}: {exc}')
            continue
        networks = list(ipaddress.collapse_addresses(networks))
        if len(networks) < MIN_COUNTRY_NETWORKS:
            problems.append(f'{name}: only {len(networks)} networks')
            continue
        return networks, (f'{name} {stamp}' if stamp else name)
    raise SplitTunnelError('fetch_failed', '; '.join(problems) or 'No source answered')


def _resolve_v4(host):
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
    except OSError:
        return set()


def shorten(networks, hosts=(), resolve=_resolve_v4, max_prefixlen=SHORTEN_MAX_PREFIXLEN):
    """Keep networks of /max_prefixlen and larger plus every network that holds
    an address of one of `hosts`. Whatever is dropped simply stays in the
    tunnel, so the cost of a miss is a foreign IP for that site, never a
    blocked foreign site outside the tunnel.

    Returns (networks, unresolved hosts).
    """
    networks = sorted(ipaddress.collapse_addresses(networks))
    kept = {n for n in networks if n.prefixlen <= max_prefixlen}
    starts = [int(n.network_address) for n in networks]
    unresolved = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        for host, addresses in zip(hosts, pool.map(resolve, hosts)):
            if not addresses:
                unresolved.append(host)
            for address in addresses:
                value = int(ipaddress.IPv4Address(address))
                i = bisect.bisect_right(starts, value) - 1
                if i >= 0 and value <= int(networks[i].broadcast_address):
                    kept.add(networks[i])
    return sorted(kept), unresolved


def build_public_list(country='RU', shorten_list=True, fetch=_http_get, resolve=_resolve_v4):
    """Fetch the country list and, by default, shorten it. Returns a summary
    dict ready to be stored with `settings_update`."""
    networks, source = fetch_country_networks(country, fetch=fetch)
    full_count = len(networks)
    unresolved = []
    if shorten_list:
        networks, unresolved = shorten(networks, SERVICE_HOSTS.get(str(country).upper(), ()),
                                       resolve=resolve)
    return {
        'networks': normalize(networks),
        'source': f'public:{str(country).upper()}',
        'source_detail': source,
        'shortened': bool(shorten_list),
        'full_count': full_count,
        'unresolved_hosts': unresolved,
    }


# ======================== Stored settings ========================

def settings_update(current, networks, source, source_detail='', shortened=False, enabled=None):
    """New settings dict for a list that passed validation."""
    networks = normalize(ipaddress.IPv4Network(str(n)) for n in networks)
    if networks:
        tunnel_entries(networks)  # rejects a list that leaves nothing for the tunnel
    updated = default_settings()
    updated.update(current or {})
    updated.update({
        'networks': networks,
        'source': source,
        'source_detail': source_detail,
        'shortened': bool(shortened),
        'updated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    })
    if enabled is not None:
        updated['enabled'] = bool(enabled)
    return updated


def describe(settings):
    """What the settings card shows."""
    s = default_settings()
    s.update(settings or {})
    networks = list(s.get('networks') or [])
    entries = len(tunnel_entries(networks)) if networks else 1
    return {
        'enabled': bool(s.get('enabled')),
        'networks': networks,
        'source': s.get('source') or '',
        'source_detail': s.get('source_detail') or '',
        'shortened': bool(s.get('shortened')),
        'updated_at': s.get('updated_at'),
        'network_count': len(networks),
        'allowed_ips_entries': entries,
        'large': entries > LARGE_ALLOWED_IPS,
        'active': bool(s.get('enabled') and networks),
    }


# ======================== Runtime policy ========================

_DATA_FILE_GETTER = None
_LOCK = threading.Lock()
_FILE_CACHE = {'key': None, 'networks': ()}
_ENTRY_CACHE = {'networks': None, 'entries': None}


def configure(data_file_getter):
    """Point the policy at the panel's data file (a callable, so a test that
    swaps the data file is followed)."""
    global _DATA_FILE_GETTER
    _DATA_FILE_GETTER = data_file_getter
    with _LOCK:
        _FILE_CACHE.update(key=None, networks=())


def _active_networks():
    path = _DATA_FILE_GETTER() if _DATA_FILE_GETTER else None
    if not path:
        return ()
    try:
        st = os.stat(path)
    except OSError:
        return ()
    key = (path, st.st_mtime_ns, st.st_size)
    with _LOCK:
        if _FILE_CACHE['key'] == key:
            return _FILE_CACHE['networks']
    try:
        with open(path, encoding='utf-8') as f:
            conf = (json.load(f).get('settings') or {}).get('split_tunnel') or {}
    except (OSError, ValueError, AttributeError):
        return ()
    networks = tuple(conf.get('networks') or ()) if conf.get('enabled') else ()
    with _LOCK:
        _FILE_CACHE.update(key=key, networks=networks)
    return networks


def current_entries():
    """IPv4 AllowedIPs entries of the active list, or None when it is off."""
    networks = _active_networks()
    if not networks:
        return None
    with _LOCK:
        if _ENTRY_CACHE['networks'] == networks:
            return _ENTRY_CACHE['entries']
    try:
        entries = tunnel_entries(networks)
    except (SplitTunnelError, ValueError):
        return None
    with _LOCK:
        _ENTRY_CACHE.update(networks=networks, entries=entries)
    return entries


def apply_to_config(config_text):
    """The client config as the panel hands it out: with the active bypass
    list expanded into AllowedIPs, or unchanged when there is none."""
    entries = current_entries()
    return rewrite_allowed_ips(config_text, entries) if entries else config_text


def fold_config(config_text):
    """A config about to be stored, with the active expansion folded back."""
    entries = current_entries()
    return fold_allowed_ips(config_text, entries) if entries else config_text
