"""Cloudflare WARP as a server app + per-instance warp egress (issue #277).

Pure logic only: state store, MTU budget, DNS slot parsing, instance state
classification and quota bookkeeping. SSH orchestration and HTTP wiring live
in app.py / warp_runtime.py, so everything here is unit-tested without a
panel, network or Docker.

State layout (``<DATA_FILE>.srv_warp_state.json``)::

    {
      "version": 1,
      "servers": {
        "<server_uid>": {
          "protocols": {
            "<protocol>": {
              "warp": {registered, conf_hash, handshake_fails,
                       last_handshake_fail_at, rate_limited_until,
                       repair_state: {...}, quarantine,
                       first_seen_stopped},
              "client_mtu_warp": int | null,
              "warp_link": {active, dns_via_warp, applied_at, stale,
                            dataplane_ok, dataplane_ok_at,
                            server_uid, entry_uid, protocol},
              "warp_egress_regen": {"<uid>:<proto>": {mtu, done, ts}}
            }
          },
          "exit": {warp_egress, warp_egress_entries: {...},
                   registered, conf_hash}
        }
      }
    }
"""

import ipaddress
import json
import logging
import os
import tempfile
import threading
import time

logger = logging.getLogger(__name__)

# --- constants (single source of truth) -------------------------------------

WARP_TABLE = 210
WARP_IFACE_MTU = 1280
# warp0 runs at 1280 and the entry decapsulates the client packet before it
# reaches warp0, so a full 1280-byte inner packet still fits. Going lower is
# not an option while the client config advertises ::/0: IPv6 needs 1280
# (RFC 8200) and Windows/Apple clients refuse to set up an IPv6 interface
# under that floor. A narrower uplink budget is still accepted, but then the
# generated client config drops ::/0 instead of advertising a route it cannot
# carry (see warp_peer_allowed_ips in awg_manager).
WARP_CLIENT_MTU_CAP = 1280
WARP_MIN_CLIENT_MTU = 1200
# Links created before the cap was corrected stored that old cap verbatim.
# A one-time state migration (migrate_legacy_client_mtu) rewrites them; a
# budget of 1220 written afterwards is a real constraint and must be kept.
_LEGACY_CLIENT_MTU_CAP = 1220
WARP_MTU_MIGRATION_KEY = 'client_mtu_cap_1280_migrated'
WARP_TRANSPORT_OVERHEAD = 60
WARP_DEFAULT_LINK_MTU = 1500
WARP_DNS_SLOTS = 7
WARP_REGISTER_LIMIT = 3
WARP_REGISTER_WINDOW_SECONDS = 7 * 24 * 3600
WARP_REGISTERS_KEEP = 20

# Причины устаревания активного линка: короткие машинные строки в state.
STALE_DATAPLANE_DOWN = 'dataplane_down'
STALE_CONTAINER_RESTART = 'container_restart'
STALE_CONTAINER_RECREATED = 'container_recreated'
STALE_EGRESS_SWITCH = 'egress_switch'

WARP_PREF_ENTRY_C2C = 181
WARP_PREF_ENTRY_DNS_NET = 182
WARP_PREF_ENTRY_DNS_FIRST = 183
WARP_PREF_B_TRANSIT = 171
WARP_PREF_CATCH_ALL = WARP_TABLE  # pref convention: pref == table number

STATE_VERSION = 1
# Set on a state loaded from a newer panel: reads are allowed, writes are not.
STATE_VERSION_MARKER = '_unsupported_version'

# Instance states (per-instance view; aggregate is separate).
ST_NOT_INSTALLED = 'not_installed'
ST_AVAILABLE_NOT_LINKED = 'available_not_linked'
ST_CONNECTED = 'connected'
ST_CONNECTING = 'connecting'
ST_DISCONNECTED = 'disconnected'
ST_ERROR = 'error'
ST_STOPPED = 'stopped'
ST_UNREACHABLE = 'unreachable'
ST_RATE_LIMITED = 'warp_rate_limited'

INSTANCE_STATES = (
    ST_NOT_INSTALLED, ST_AVAILABLE_NOT_LINKED, ST_CONNECTED, ST_CONNECTING,
    ST_DISCONNECTED, ST_ERROR, ST_STOPPED, ST_UNREACHABLE, ST_RATE_LIMITED,
)

AGG_NOT_INSTALLED = 'not_installed'
AGG_INSTALLED = 'installed'
AGG_DEGRADED = 'degraded'
AGG_UNREACHABLE = 'unreachable'

_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
))


class SrvWarpError(Exception):
    """User-facing failure with a stable code for the UI/i18n."""

    def __init__(self, code, http_status=400, message=''):
        super().__init__(message or code)
        self.code = code
        self.http_status = int(http_status)


# --- small helpers -----------------------------------------------------------

def _norm_uid(value):
    return '' if value is None else str(value)


def now_ts():
    return int(time.time())


def container_warp_prefix(protocol, kind='awg'):
    """Credential directory inside the instance container."""
    if kind == 'exit':
        return '/opt/amnezia/exit/warp'
    return '/opt/amnezia/awg/warp/%s' % protocol


def marker_path(protocol):
    return '/opt/amnezia/awg/warp-link-%s' % protocol


def is_public_ipv4(text):
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_link_local \
            or ip.is_unspecified or ip.is_reserved:
        return False
    return not any(ip in net for net in _PRIVATE_NETWORKS)


def _ipv4_token(token):
    """Return the bare IPv4 address from one Address token, or ``''``."""
    token = str(token or '').strip()
    if '/' in token:
        token = token.split('/', 1)[0]
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return ''
    return token if ip.version == 4 else ''


def _section_index(lines, name):
    target = name.strip().lower()
    for index, line in enumerate(lines):
        if line.strip().lower() == target:
            return index
    return None


def sanitize_warp_profile(text):
    """Return a warp0.conf that is safe to feed to ``wg setconf``.

    wgcf emits a full wg-quick profile: a ``DNS`` line, an IPv4+IPv6
    ``Address``, ``::/0`` in ``AllowedIPs`` and no MTU/Table hints. The panel
    manages WARP inside an already running namespace, so DNS must never touch
    the container resolv.conf, IPv6 is not routed and quick-style routing is
    disabled explicitly (``Table = off``) in case the file is ever passed to
    ``wg-quick`` by mistake. The function is pure and idempotent.
    """
    header = '# DO NOT wg-quick/awg-quick up'
    lines = []
    for raw in str(text or '').replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        stripped = raw.strip()
        lowered = stripped.lower()
        if not stripped:
            lines.append('')
            continue
        if stripped == header:
            continue
        if lowered.startswith('dns'):
            continue
        if lowered.startswith('address'):
            _key, _sep, value = raw.partition('=')
            ipv4 = ''
            for token in value.split(','):
                ipv4 = _ipv4_token(token)
                if ipv4:
                    break
            if ipv4:
                lines.append('Address = %s' % ipv4)
            continue
        if lowered.startswith('allowedips'):
            lines.append('AllowedIPs = 0.0.0.0/0')
            continue
        if lowered.startswith('mtu') or lowered.startswith('table') \
                or lowered.startswith('persistentkeepalive'):
            continue
        lines.append(raw.rstrip())

    interface_index = _section_index(lines, '[Interface]')
    if interface_index is None:
        lines = ['[Interface]', 'MTU = 1280', 'Table = off'] + lines
    else:
        lines[interface_index + 1:interface_index + 1] = [
            'MTU = 1280', 'Table = off']

    peer_index = _section_index(lines, '[Peer]')
    if peer_index is None:
        lines += ['', '[Peer]', 'PersistentKeepalive = 25']
    else:
        lines[peer_index + 1:peer_index + 1] = ['PersistentKeepalive = 25']

    compact = []
    for line in lines:
        if line == '' and (not compact or compact[-1] == ''):
            continue
        compact.append(line)
    while compact and compact[0] == '':
        compact.pop(0)
    while compact and compact[-1] == '':
        compact.pop()
    return '\n'.join([header] + compact) + '\n'


def parse_dns_targets(dns_value):
    """Split a DNS setting into (public_ipv4, private_or_v6, hostnames).

    ``_get_dns`` may return a comma-joined string that includes a hostname or
    an IPv6 address. Only public IPv4 addresses get their own warp exception
    rule (one pref slot each); everything else is returned for the caller to
    reject or resolve.
    """
    public, other, hosts = [], [], []
    if not dns_value:
        return public, other, hosts
    tokens = [t.strip() for t in str(dns_value).replace(';', ',').split(',')]
    for token in tokens:
        if not token:
            continue
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            hosts.append(token)
            continue
        if ip.version == 4 and is_public_ipv4(token):
            if token not in public:
                public.append(token)
        else:
            other.append(token)
    return public, other, hosts


def dns_rule_targets(dns_value, dns_via_warp, dns_net_cidr=None):
    """Pref/selector pairs for the entry warp block.

    With ``dns_via_warp`` the client resolver is Cloudflare itself, so no
    direct-DNS exception is installed. Without it every public IPv4 resolver
    gets its own rule (max ``WARP_DNS_SLOTS``), and the AmneziaDNS network
    keeps its own direct rule.
    """
    if dns_via_warp:
        return []
    public, _other, _hosts = parse_dns_targets(dns_value)
    if len(public) > WARP_DNS_SLOTS:
        raise SrvWarpError('srv_warp_dns_too_many', 409)
    rules = []
    if dns_net_cidr:
        rules.append({'pref': WARP_PREF_ENTRY_DNS_NET, 'to': dns_net_cidr})
    for index, ip in enumerate(public):
        rules.append({
            'pref': WARP_PREF_ENTRY_DNS_FIRST + index,
            'to': '%s/32' % ip,
        })
    return rules


def warp_client_mtu(raw_conf_mtu, transport_overhead, warped_b=False,
                    b_regen_mtu=None):
    """Client MTU budget for a warp-linked instance.

    The inner client packet stops at warp0, whose MTU is 1280, so 1280 is the
    ceiling; it is also the RFC-8200 floor for IPv6. The awg uplink adds its
    own obfuscation overhead on the wire, which is what the second candidate
    accounts for.

    Returns ``(mtu, reason)`` where ``mtu`` is None when the budget falls
    below ``WARP_MIN_CLIENT_MTU`` and ``reason`` explains a refusal.
    """
    candidates = [WARP_CLIENT_MTU_CAP,
                  WARP_DEFAULT_LINK_MTU - int(transport_overhead or 0)]
    if warped_b and b_regen_mtu:
        candidates.append(int(b_regen_mtu))
    if raw_conf_mtu:
        candidates.append(int(raw_conf_mtu))
    budget = min(candidates)
    if budget < WARP_MIN_CLIENT_MTU:
        return None, 'srv_warp_budget_mismatch'
    return budget, None


# --- state store -------------------------------------------------------------

def _empty_state():
    return {'version': STATE_VERSION, 'servers': {}}


class WarpStateUnsupportedVersion(RuntimeError):
    """State written by a newer panel: read-only here.

    Raising (instead of returning an empty state) keeps the file intact: the
    old behaviour wiped every AWG registration on the next save.
    """

    def __init__(self, found, supported=STATE_VERSION):
        super().__init__('warp state version %r is newer than supported %r'
                         % (found, supported))
        self.found = found
        self.supported = supported


# A mutate() callback returns this when there is nothing to write. Without it
# an idempotent prune would create the state file on hosts that have none.
SKIP_SAVE = object()


def _coerce_state_version(raw):
    """Version of a parsed state file, or None when it cannot be trusted."""
    if not isinstance(raw, dict):
        return None
    if 'version' not in raw:
        return 1
    value = raw['version']
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def migrate_state(raw):
    """Normalize a supported state without losing any record.

    The version is deliberately *not* bumped: an older panel returns an empty
    state for any unknown version and its next save overwrites the file, so a
    bump would make a rollback destructive. Only additive normalization
    happens here (``registers`` -> ``registers_ts``), and every unknown key is
    preserved for the same reason.
    """
    if not isinstance(raw, dict):
        return _empty_state(), False
    state = dict(raw)
    changed = False
    if state.get('version') != STATE_VERSION:
        state['version'] = STATE_VERSION
        changed = True
    servers = state.get('servers')
    if not isinstance(servers, dict):
        state['servers'] = {}
        changed = True
        servers = state['servers']
    for record in servers.values():
        if not isinstance(record, dict):
            continue
        current = record.get('registers_ts')
        if current is None:
            legacy = record.get('registers')
            record['registers_ts'] = (list(legacy)
                                      if isinstance(legacy, list) else [])
            changed = True
        elif not isinstance(current, list):
            record['registers_ts'] = []
            changed = True
    return state, changed


class WarpStateStore:
    """Atomic JSON store for operational warp state.

    Kept separate from ``data.json`` on purpose: dozens of panel writers save
    their own stale ``data.json`` snapshots, so warp records would be silently
    overwritten. This file has a single writer discipline and tmp+rename
    atomicity.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()

    def load(self):
        with self._lock:
            try:
                with open(self.path, 'r', encoding='utf-8') as fh:
                    raw = json.load(fh)
            except (OSError, ValueError):
                return _empty_state()
            if not isinstance(raw, dict):
                return _empty_state()
            version = _coerce_state_version(raw)
            if version is None or version > STATE_VERSION:
                state = dict(raw)
                if not isinstance(state.get('servers'), dict):
                    state['servers'] = {}
                state[STATE_VERSION_MARKER] = version
                return state
            state, changed = migrate_state(raw)
            if changed:
                # Read paths must keep working on a read-only or full disk.
                try:
                    self.save(state)
                except OSError:
                    logger.warning("warp state migration could not be saved",
                                   exc_info=True)
            return state

    def save(self, state):
        if isinstance(state, dict) and STATE_VERSION_MARKER in state:
            raise WarpStateUnsupportedVersion(state.get(STATE_VERSION_MARKER))
        directory = os.path.dirname(os.path.abspath(self.path))
        with self._lock:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=os.path.basename(self.path) + '.', suffix='.tmp',
                dir=directory,
            )
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                    json.dump(state, fh, ensure_ascii=False, sort_keys=True)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def mutate(self, fn):
        """Load, mutate in place, save atomically. Returns fn's result."""
        with self._lock:
            state = self.load()
            if isinstance(state, dict) and STATE_VERSION_MARKER in state:
                raise WarpStateUnsupportedVersion(
                    state.get(STATE_VERSION_MARKER))
            result = fn(state)
            if result is SKIP_SAVE:
                return result
            self.save(state)
            return result


# --- state accessors ---------------------------------------------------------

def server_record(state, server_uid):
    servers = state.setdefault('servers', {})
    return servers.setdefault(_norm_uid(server_uid), {
        'protocols': {},
        'exit': {
            'warp_egress': False,
            'warp_egress_entries': {},
            'registered': False,
            'conf_hash': None,
        },
    })


def proto_record(state, server_uid, protocol):
    server = server_record(state, server_uid)
    return (server.setdefault('protocols', {})
            .setdefault(protocol, {
                'warp': {
                    'registered': False,
                    'conf_hash': None,
                    'handshake_fails': 0,
                    'last_handshake_fail_at': None,
                    'rate_limited_until': None,
                    'repair_state': None,
                    'quarantine': False,
                    'first_seen_stopped': None,
                },
                'client_mtu_warp': None,
                'warp_link': None,
                'warp_egress_regen': {},
            }))


def warp_link(record):
    link = (record or {}).get('warp_link') or {}
    return link if link.get('active') else None


def mark_warp_links_stale(state, server_uid, protocols=None,
                          reason=STALE_DATAPLANE_DOWN):
    """Пометить активные линки сервера устаревшими.

    Вызывается внутри ``warp_state_store.mutate``: мутатор меняет только
    ``stale`` и ``dataplane_ok``, остальные поля записи линка сохраняет.
    ``protocols=None`` означает все протоколы сервера, отсутствующие записи
    не создаются. Возвращает число затронутых линков.
    """
    server = (state.get('servers') or {}).get(_norm_uid(server_uid)) or {}
    records = server.get('protocols') or {}
    selected = records if protocols is None else protocols
    changed = 0
    for proto in selected:
        rec = records.get(proto)
        link = warp_link(rec)
        if not link:
            continue
        link['stale'] = reason
        link['dataplane_ok'] = False
        changed += 1
    return changed


def clear_warp_links_stale(state, server_uid, protocols=None):
    """Снять метку устаревания с активных линков сервера.

    Подтверждение dataplane_ok выставляется вызывающей стороной только после
    реальной пробы; здесь сбрасывается исключительно ``stale``.
    """
    server = (state.get('servers') or {}).get(_norm_uid(server_uid)) or {}
    records = server.get('protocols') or {}
    selected = records if protocols is None else protocols
    changed = 0
    for proto in selected:
        rec = records.get(proto)
        link = warp_link(rec)
        if not link:
            continue
        link['stale'] = None
        changed += 1
    return changed


def exit_record(state, server_uid):
    return server_record(state, server_uid).setdefault('exit', {
        'warp_egress': False,
        'warp_egress_entries': {},
        'registered': False,
        'conf_hash': None,
    })


def egress_regen_for(record, entry_uid, protocol):
    key = '%s:%s' % (_norm_uid(entry_uid), protocol)
    return ((record or {}).get('warp_egress_regen') or {}).get(key)


def warp_ctx_for(state, server_uid, protocol):
    """Context handed to the managers for config generation and rendering."""
    record = proto_record(state, server_uid, protocol)
    link = warp_link(record)
    server_uid = _norm_uid(server_uid)
    transit_cidr = transit_gateway = ''
    regen = None
    if link:
        regen = egress_regen_for(record, server_uid, protocol)
        if regen:
            transit_cidr = regen.get('subnet_cidr') or ''
            transit_gateway = regen.get('transit_gateway') or ''
    return {
        'active': bool(link),
        'dns_via_warp': bool((link or {}).get('dns_via_warp')),
        'client_mtu': _authoritative_client_mtu(record, link, regen),
        'dns_ips': list((record or {}).get('warp_dns_ips') or []),
        'transit_cidr': transit_cidr,
        'transit_gateway': transit_gateway,
        'prefix': container_warp_prefix(protocol),
        'protocol': protocol,
        'entry_uid': _norm_uid((link or {}).get('entry_uid') or server_uid),
    }


def migrate_legacy_client_mtu(state):
    """One-time persistent rewrite of budgets stored with the old cap.

    Deciding by value on every read would silently inflate a *legitimate*
    1220 budget (a narrow uplink or an instance whose own MTU is 1220). The
    marker makes the rewrite happen exactly once, at startup, so budgets
    written later are never touched. Regen records are migrated too.
    """
    if state.get(WARP_MTU_MIGRATION_KEY):
        return 0
    changed = 0
    for srv in (state.get('servers') or {}).values():
        for rec in (srv.get('protocols') or {}).values():
            if rec.get('client_mtu_warp') == _LEGACY_CLIENT_MTU_CAP:
                rec['client_mtu_warp'] = WARP_CLIENT_MTU_CAP
                changed += 1
            for entry in (rec.get('warp_egress_regen') or {}).values():
                if isinstance(entry, dict) and entry.get('mtu') == _LEGACY_CLIENT_MTU_CAP:
                    entry['mtu'] = WARP_CLIENT_MTU_CAP
                    changed += 1
    state[WARP_MTU_MIGRATION_KEY] = True
    return changed


def _authoritative_client_mtu(record, link, regen):
    if regen and regen.get('mtu'):
        return int(regen['mtu'])
    stored = (record or {}).get('client_mtu_warp')
    return int(stored) if stored else None


# --- quota -------------------------------------------------------------------

def register_timestamps(registers, now=None):
    """Valid registration timestamps inside the rolling window."""
    now = now_ts() if now is None else now
    stamps = []
    for item in registers or []:
        ts = item.get('ts') if isinstance(item, dict) else item
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            continue
        if now - ts < WARP_REGISTER_WINDOW_SECONDS:
            stamps.append(ts)
    return stamps


def registers_prune(registers, keep=WARP_REGISTERS_KEEP):
    items = list(registers or [])
    return items[-keep:]


def quota_exhausted(registers, now=None):
    return len(register_timestamps(registers, now)) >= WARP_REGISTER_LIMIT


def _normalize_register(item):
    """One registration entry as ``{ts, source, protocol, source_uid}`` or None."""
    if isinstance(item, dict):
        raw_ts = item.get('ts')
    else:
        raw_ts = item
    try:
        ts = int(raw_ts)
    except (TypeError, ValueError):
        return None

    def text(value):
        return '' if value is None else str(value)

    if not isinstance(item, dict):
        return {'ts': ts, 'source': '', 'protocol': '', 'source_uid': ''}
    return {
        'ts': ts,
        'source': text(item.get('source')),
        'protocol': text(item.get('protocol')),
        'source_uid': text(item.get('source_uid')),
    }


def merged_registers(server, state, uid):
    """Registration timestamps from ``data.json`` and the state store.

    Imports used to record timestamps in ``data.json``; registration accounting
    now writes them to the store. The quota window must see both, and legacy
    entries must keep counting without migrating ``data.json``.
    """
    record = ((state or {}).get('servers') or {}).get(_norm_uid(uid)) or {}
    buckets = ((server or {}).get('warp') or {}, record)
    seen = set()
    merged = []
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        for key in ('registers_ts', 'registers'):
            value = bucket.get(key)
            if not isinstance(value, list):
                continue
            for item in value:
                entry = _normalize_register(item)
                if entry is None:
                    continue
                dedup = (entry['ts'], entry['source'],
                         entry['protocol'], entry['source_uid'])
                if dedup in seen:
                    continue
                seen.add(dedup)
                merged.append(entry)
    merged.sort(key=lambda entry: entry['ts'])
    return registers_prune(merged)


# --- state classification ----------------------------------------------------

def classify_instance_state(*, installed, link_active, ssh_ok=True,
                            container_running=True, handshake_age=None,
                            probe_ok=None, probe_private=None,
                            probe_direct=None, rate_limited=False,
                            max_age=240):
    """Map live signals to exactly one of ``INSTANCE_STATES``.

    Precedence: unreachable > stopped > error > disconnected > connecting >
    connected; ``not_installed``/``available_not_linked``/``rate_limited``
    come from the record, not from the probe.  With no handshake telemetry
    a linked instance is ``connecting`` (awaiting confirmation), never
    ``disconnected``.
    """
    if not ssh_ok:
        return ST_UNREACHABLE
    if not installed:
        return ST_NOT_INSTALLED
    if not link_active:
        return ST_RATE_LIMITED if rate_limited else ST_AVAILABLE_NOT_LINKED
    if not container_running:
        return ST_STOPPED
    if probe_private or probe_direct is True:
        return ST_ERROR
    if rate_limited:
        return ST_RATE_LIMITED
    if handshake_age is None:
        # No handshake telemetry: the status projection has no live probe, so
        # an unknown age must not be reported as a failure.  A configured but
        # unmeasured link is "connecting", not "disconnected" -- otherwise
        # every linked instance kept the server badge at "degraded" forever.
        return ST_CONNECTING
    if handshake_age > max_age:
        return ST_DISCONNECTED
    if probe_ok is False:
        return ST_CONNECTING
    return ST_CONNECTED


def aggregate_state(per_instance_states, remote_unreachable=False):
    """Server-level view over per-instance states."""
    states = [s for s in per_instance_states if s]
    if remote_unreachable:
        return AGG_UNREACHABLE
    if not states or all(s == ST_NOT_INSTALLED for s in states):
        return AGG_NOT_INSTALLED
    for state in states:
        if state in (ST_ERROR, ST_DISCONNECTED, ST_STOPPED):
            return AGG_DEGRADED
    return AGG_INSTALLED
