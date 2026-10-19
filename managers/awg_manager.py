"""
AWG Protocol Manager - handles AmneziaWG and AmneziaWG-Legacy protocol
installation, configuration, and client management on remote servers.

Replicates the logic from:
- client/server_scripts/awg/ and awg_legacy/
- client/configurators/wireguard_configurator.cpp
- client/ui/models/clientManagementModel.cpp
"""

import json
import os
import secrets
import struct
import hashlib
import ipaddress
import logging
import re
import time
import functools
import threading
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# Dual-stack behaviour for AWG tunnels, overridable like the panel's other
# environment knobs (SECRET_KEY, TUNNEL_BIN_DIR): "auto" probes the server,
# "off" keeps every tunnel IPv4-only, "on" forces dual-stack.
AWG_IPV6_ENV = 'AWG_IPV6'
IPV6_FORCE_OFF = ('off', 'false', '0', 'no', 'disable', 'disabled')
IPV6_FORCE_ON = ('on', 'true', '1', 'yes', 'force', 'forced')

# Default AWG parameters (from protocols_defs.h)
AWG_DEFAULTS = {
    'port': '55424',
    'mtu': '1376',
    'subnet_address': '10.8.1.0',
    'subnet_cidr': '24',
    'subnet_ip': '10.8.1.1',
    # IPv6 ULA subnet used for dual-stack tunnels (NAT66, no provider prefix needed)
    'subnet_ipv6_ip': 'fd42:8:1::1',
    'subnet_ipv6_cidr': '64',    'dns1': '1.1.1.1',
    'dns2': '1.0.0.1',
    # Default IPv6 resolver appended to client DNS when the tunnel is dual-stack
    'dns6': '2606:4700:4700::1111',
    # AWG obfuscation parameters
    'junk_packet_count': '3',
    'junk_packet_min_size': '10',
    'junk_packet_max_size': '30',
    'init_packet_junk_size': '15',
    'response_packet_junk_size': '18',
    'cookie_reply_packet_junk_size': '20',
    'transport_packet_junk_size': '23',
    'init_packet_magic_header': '1020325451',
    'response_packet_magic_header': '3288052141',
    'transport_packet_magic_header': '2528465083',
    'underload_packet_magic_header': '1766607858',
}

def parse_subnet_indexes(address_lines):
    """Subnet indexes (N in 10.8.N.x / fd42:8:N::) already used on a host.

    `address_lines` are Address lines ("Address = ..." or a bare value) from
    the server configs of all awg/wireguard containers on the host. Both the
    IPv4 and the IPv6 form encode the same index, so either is enough to
    mark N as taken.
    """
    used = set()
    for line in address_lines:
        line = line.strip()
        if line.lower().startswith('address'):
            _, _, line = line.partition('=')
        for part in line.split(','):
            addr = part.strip().split('/')[0].strip()
            if not addr:
                continue
            m = re.match(r'^10\.8\.(\d+)\.\d+$', addr)
            if not m:
                m = re.match(r'^fd42:8:([0-9a-f]+)::', addr)
            if m:
                used.add(int(m.group(1), 16))
    return used


def first_free_subnet_index(used):
    """Smallest subnet index >= 1 not present in `used`."""
    n = 1
    while n in used:
        n += 1
    return n


# AWG 3.1 parameters: (internal key, config key).
# HeaderProtectionKey/ContentPaddingAddition and the timings came with 3.0,
# RandomTrailers/DisableCookies with 3.1. Ranges use the "min-max" form.
AWG3_PARAM_MAP = [
    ('header_protection_key', 'HeaderProtectionKey'),
    ('content_padding_addition', 'ContentPaddingAddition'),
    ('rekey_after_time', 'RekeyAfterTime'),
    ('rekey_timeout', 'RekeyTimeout'),
    ('reject_after_time', 'RejectAfterTime'),
    ('keepalive_timeout', 'KeepaliveTimeout'),
    ('max_handshake_attempts', 'MaxHandshakeAttempts'),
    ('random_trailers', 'RandomTrailers'),
    ('disable_cookies', 'DisableCookies'),
]

# AWG 3.1 keys must not leak into legacy configs — the legacy container
# ships tools that reject them.
AWG3_CONFIG_KEYS = tuple(config_key for _, config_key in AWG3_PARAM_MAP)

# With HeaderProtectionKey set, the kernel module requires every junk size
# S1-S4 to be at least HEADER_PROTECTION_NONCE_SIZE (12) — see the S1..S4
# checks in netlink.c. Below that `awg setconf` fails with a bare
# "Invalid argument": the explanation only goes to net_dbg_ratelimited.
AWG3_MIN_JUNK_SIZE = 12

# AWG 3.1 keys only exist in amneziawg kernel module 3.0+ (the 1.0.x line the
# Amnezia PPA still ships predates them). awg-quick prefers the host module and
# falls back to amneziawg-go only when `ip link add ... type amneziawg` fails,
# i.e. when no module is installed at all. With an older module loaded the
# interface is created, `awg setconf` then fails with a bare "Invalid argument"
# and awg-quick deletes the interface again: the install reports success and no
# tunnel exists (issue #113). The container's amneziawg-go does speak the full
# 3.1 key set, so the way out is to force userspace for awg3 on such hosts.
AWG3_MIN_KERNEL_MODULE_MAJOR = 3

# awg-quick has no switch for that, so the image gets a one-line patch adding
# one. Without WG_FORCE_USERSPACE set the function behaves exactly as before.
AWG_QUICK_FORCE_USERSPACE_PATCH = (
    'RUN sed -i \'s|if ! cmd ip link add "$INTERFACE" type amneziawg; then'
    '|if [ -n "$WG_FORCE_USERSPACE" ]; then'
    ' cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE";'
    ' return 0; fi;'
    ' if ! cmd ip link add "$INTERFACE" type amneziawg; then|\' /usr/bin/awg-quick'
    ' && grep -q WG_FORCE_USERSPACE /usr/bin/awg-quick\n'
)

# Entry side of an exit-node link: a second WireGuard interface inside the
# protocol container plus policy routing that sends the client subnet through
# it. State is file-driven - exit0.conf present means "linked" - so the same
# shell block runs at container start and when the panel (un)links live.
EXIT_DIR = '/opt/amnezia/awg/exit'
EXIT_CONF = f'{EXIT_DIR}/exit0.conf'
EXIT_KEY = f'{EXIT_DIR}/exit_private.key'
EXIT_IFACE = 'exit0'
EXIT_TABLE = 200
EXIT_MTU = 1420

# Every AWG data packet on the wire is the client payload plus 20 (IPv4)
# + 8 (UDP) + 32 (WireGuard transport header), and on top of that whatever
# the obfuscation appends to *each* packet: S4 always, and on 3.x a random
# ContentPaddingAddition. Junk packets (Jc/Jmin/Jmax) and the handshake
# sizes (S1-S3) travel in their own packets and do not count here.
WG_TRANSPORT_OVERHEAD = 60
# Ethernet without jumbo frames. Hosts that tunnel customer traffic hand
# out less (1456 and 1400 are both common); the AWG settings let an
# operator dial the client MTU down to whatever their uplink really is.
DEFAULT_LINK_MTU = 1500
# RFC 8200 floor - never propose a client MTU below this.
MIN_CLIENT_MTU = 1280
EXIT_HANDSHAKE_UP_SECONDS = 300  # REJECT_AFTER_TIME (180) + keepalive slack; 180 itself flaps on idle links
DNS_NET = '172.29.172.0/24'      # amnezia-dns-net: AmneziaDNS / AdGuard live here, reached via eth1
ENTRY_PRIVATE_KEY_PLACEHOLDER = '__ENTRY_PRIVATE_KEY__'

# Egress check: the container asks a public "what is my IP" service twice -
# once bound to the tunnel gateway (that source address is what policy routing
# sends through exit0, i.e. exactly the client path) and once unbound. Two
# services, so a single one being down does not read as "no egress".
EGRESS_CHECK_URLS = ('https://api.ipify.org', 'https://ifconfig.me/ip')
EGRESS_CHECK_TIMEOUT = 8
IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# Obfuscation keys carried on a transit link (exit node <-> entry node). S3/S4
# pad every cookie/transport packet and would eat the MTU budget of a tunnel
# inside a tunnel, so only the handshake-side keys are used on that hop.
TRANSIT_PARAM_KEYS = (
    ('junk_packet_count', 'Jc'),
    ('junk_packet_min_size', 'Jmin'),
    ('junk_packet_max_size', 'Jmax'),
    ('init_packet_junk_size', 'S1'),
    ('response_packet_junk_size', 'S2'),
    ('init_packet_magic_header', 'H1'),
    ('response_packet_magic_header', 'H2'),
    ('underload_packet_magic_header', 'H3'),
    ('transport_packet_magic_header', 'H4'),
)

# Runs inside the awg3 container before awg-quick. Creating a throwaway
# interface both loads the module (a module present on disk but not yet loaded
# would otherwise read as absent) and proves the container can reach it.
AWG3_USERSPACE_GUARD = """
# AWG 3.1 needs amneziawg kernel module 3.0+; an older one accepts the
# interface but rejects the config, and awg-quick will not fall back once
# `ip link add` has succeeded (issue #113).
if ip link add awgprobe type amneziawg 2>/dev/null; then
  KMOD_VERSION=$(cat /sys/module/amneziawg/version 2>/dev/null)
  ip link delete awgprobe 2>/dev/null
  case "$KMOD_VERSION" in
    3.*|[4-9].*|[1-9][0-9].*) ;;
    *) echo "amneziawg kernel module ${KMOD_VERSION:-unknown} predates AWG 3.1, using userspace amneziawg-go"
       export WG_FORCE_USERSPACE=1 ;;
  esac
fi
"""

# Special junk packets I1-I5: free-form packets the peer sends right before
# the handshake initiation, so a session opens with bytes that belong to some
# other protocol. The kernel module parses each value as a list of tags
# (jp_parse_tags in junk.c):
#   <b 0xHEX>  fixed bytes          <r N>   N random bytes
#   <c>        packet counter, 4B   <rc N>  N random latin letters
#   <t>        unix time, 4B        <rd N>  N random digits
SPECIAL_JUNK_KEYS = ('i1', 'i2', 'i3', 'i4', 'i5')

# Byte-identical to protocols::awg::defaultSpecialJunk1 in the desktop client:
# a DNS response for icloud.com preceded by a random 2-byte transaction id.
AWG_DEFAULT_I1 = (
    '<r 2><b 0x858000010001000000000669636c6f756403636f6d'
    '0000010001c00c000100010000105a00044d583737>'
)

_SPECIAL_JUNK_TAG_RE = re.compile(r'<\s*(b|c|t|r|rc|rd)(?:\s+([^>]*?))?\s*>')

# A junk packet still has to fit into one datagram.
SPECIAL_JUNK_MAX_SIZE = 1280


def validate_special_junk(value):
    """Validate an I1-I5 value and return the packet size it produces."""
    text = (value or '').strip()
    if not text:
        return 0

    size = 0
    pos = 0
    for match in _SPECIAL_JUNK_TAG_RE.finditer(text):
        between = text[pos:match.start()].strip()
        if between:
            raise ValueError(f"unexpected text outside a tag: {between!r}")
        pos = match.end()

        tag = match.group(1)
        arg = (match.group(2) or '').strip()
        if tag in ('c', 't'):
            if arg:
                raise ValueError(f"<{tag}> takes no argument")
            size += 4
        elif tag == 'b':
            digits = arg[2:] if arg[:2].lower() == '0x' else ''
            if not digits or len(digits) % 2 or not all(c in '0123456789abcdefABCDEF' for c in digits):
                raise ValueError("<b> expects an even number of hex digits, e.g. <b 0xdeadbeef>")
            size += len(digits) // 2
        else:
            if not arg.isdigit() or int(arg) <= 0:
                raise ValueError(f"<{tag}> expects a positive byte count, e.g. <{tag} 16>")
            size += int(arg)

    trailing = text[pos:].strip()
    if trailing:
        raise ValueError(f"unexpected text outside a tag: {trailing!r}")
    if size == 0:
        raise ValueError("no packet tags found, nothing would be sent")
    if size > SPECIAL_JUNK_MAX_SIZE:
        raise ValueError(f"packet is {size} bytes, maximum is {SPECIAL_JUNK_MAX_SIZE}")
    return size


def normalize_special_junk(values):
    """Validate an {'i1': ..., 'i5': ...} mapping and drop empty entries."""
    result = {}
    for key in SPECIAL_JUNK_KEYS:
        value = (values or {}).get(key)
        value = (value or '').strip()
        if not value:
            continue
        try:
            validate_special_junk(value)
        except ValueError as exc:
            raise ValueError(f"{key.upper()}: {exc}") from exc
        result[key] = value
    return result

# Connection flood monitoring (P2P/torrent detection)
# 600 triggers false positives on peers whose OS downloads updates over P2P
# (Windows Delivery Optimization opens ~500-800 connections), so the bar
# sits above that range at 900.
CONN_WARN_THRESHOLD = 900    # simultaneous connections per peer that trigger a warning
CONN_WARN_COOLDOWN = 3600    # min seconds between two recorded warnings for the same peer
CONN_WARN_MAX_EVENTS = 5     # how many recent warnings are kept per peer
# Conntrack entries outlive the VPN session by hours/days (TCP ESTABLISHED
# timeout), so a peer that disconnected keeps "owning" its old flows in the
# table. Counts are only trusted for peers whose handshake is fresh.
CONN_LIVE_HANDSHAKE_SECONDS = 300

# Multi-IP (key sharing) detection: a peer whose WireGuard endpoint changes
# to a DIFFERENT public IP while the previous endpoint was still seen within
# MULTI_IP_WINDOW seconds is very likely the same key on 2+ devices at once
# (a single device switching networks cleanly would show a gap: the old
# endpoint disappears and the new one appears minutes later, outside the
# window). Legit fast network switches (Wi-Fi -> LTE) can still false-positive,
# which is why the alert shows both IPs and the timestamp instead of banning.
MULTI_IP_WINDOW = 1800        # seconds: previous endpoint must be this fresh
MULTI_IP_COOLDOWN = 3600      # min seconds between two recorded alerts per peer
MULTI_IP_MAX_EVENTS = 10      # how many recent alerts are kept per peer
MULTI_IP_SEEN_TTL = 7 * 86400 # drop endpoint observations older than this

# Simultaneous-use detection (the strong evidence): conntrack on the HOST
# keeps one UDP flow per client device, even for devices sharing one key.
# A flow's timeout counts down (default UDP timeout 120s) and jumps back to
# the full value on every packet, so two samples ~SIM_SAMPLE_GAP seconds
# apart tell which flows passed traffic inside that exact window — with no
# byte counters (nf_conntrack_acct stays off), no sysctl changes and no
# extra packages.
#
# The gap is 60s on purpose. Client configs carry PersistentKeepalive=25,
# so EVERY online device re-sends every 25s and its flow stays refreshed
# indefinitely: two devices = two flows active in BOTH samples = overlap
# lasting at least a minute. A Wi-Fi->LTE handover kills the old flow
# within seconds and conntrack expires it in <=120s, so at the second
# sample only one flow is active and nothing is recorded. A 15s gap would
# false-positive on someone walking out of the house; a "same second" rule
# would not help either — handover packets land in the same second too.
# What separates sharing from switching is DURATION, not simultaneity.
SIM_SAMPLE_GAP = 60           # seconds between the two conntrack samples
SIM_ACTIVE_MARGIN = 2         # timeout slop: refreshed if t2 >= t1 - margin
SIM_ROUND_FULL_EVERY = 6      # every Nth monitor round covers ALL instances
SIM_RECENT_ALERT = 86400      # once alerted, check this instance every round
SIM_COOLDOWN = 3600           # min seconds between two recorded events
SIM_MAX_EVENTS = 10           # how many recent events are kept per peer

# Round counters for SIM_ROUND_FULL_EVERY; managers are recreated each
# round, so this lives at module level, keyed by (host, protocol).
_sim_round_counters = {}


# ----- clientsTable mutation serialization -----
# Every mutating op does read-table -> modify -> save-table. Uvicorn serves
# requests concurrently (blocking manager calls run in a thread pool), and
# the prefetched batch cache can hand out a table snapshot taken seconds
# earlier. Two overlapping ops then overwrite each other: the last save
# wins with a stale snapshot, silently dropping rows added by the other op.
# A dropped row resurfaces as a synthesized 'External (native app)' entry
# (the config carries no names), which is how peer names were lost. The
# lock is keyed by server host + container so unrelated servers/instances
# never block each other.
_TABLE_LOCKS = {}
_TABLE_LOCKS_GUARD = threading.Lock()


def _clients_table_lock(host, container_name):
    with _TABLE_LOCKS_GUARD:
        return _TABLE_LOCKS.setdefault((host, container_name), threading.Lock())


def _serialized_table_write(method):
    """Hold the per-container table lock for the whole read-modify-write."""
    @functools.wraps(method)
    def wrapper(self, protocol_type, *args, **kwargs):
        host = getattr(self.ssh, 'host', '') or 'unknown'
        container = self._container_name(protocol_type)
        with _clients_table_lock(host, container):
            return method(self, protocol_type, *args, **kwargs)
    return wrapper


def generate_wg_keypair():
    """Generate a WireGuard X25519 keypair (private, public) as base64 strings."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(private_bytes).decode(), b64encode(public_bytes).decode()


def generate_psk():
    """Generate a WireGuard preshared key."""
    return b64encode(secrets.token_bytes(32)).decode()


def _param_max(value):
    """Largest value a parameter can take, for plain numbers and "min-max" ranges.

    Returns 0 for anything unparseable so a malformed config degrades into
    "assume no overhead" instead of raising while generating a client config.
    """
    text = str(value or '').strip()
    if not text:
        return 0
    try:
        return max(int(part) for part in text.split('-') if part.strip())
    except ValueError:
        return 0


def transport_overhead(awg_params):
    """Bytes added to every data packet on top of the client payload."""
    params = awg_params or {}
    return (WG_TRANSPORT_OVERHEAD
            + _param_max(params.get('transport_packet_junk_size'))
            + _param_max(params.get('content_padding_addition')))


def safe_client_mtu(awg_params, link_mtu=DEFAULT_LINK_MTU):
    """Largest client MTU whose worst-case data packet still fits the link.

    ContentPaddingAddition is a range, so the oversized packets are only the
    ones that happen to draw its upper end: the tunnel looks healthy, small
    requests succeed, and bulk transfers stall. Sizing against the maximum is
    what keeps that from happening.
    """
    try:
        link = int(link_mtu)
    except (TypeError, ValueError):
        link = DEFAULT_LINK_MTU
    return max(MIN_CLIENT_MTU, link - transport_overhead(awg_params))


def generate_awg_params(use_ranges=False, awg3=False):
    """Generate random AWG obfuscation parameters.
    
    For AWG 2.0 (use_ranges=True): generates H1-H4 as non-overlapping
    ranges (min-max) for dynamic packet signature. Each packet gets a
    random value from its range, defeating static DPI signatures.
    For legacy AWG (use_ranges=False): generates fixed single H values.
    For AWG 3.1 (awg3=True): additionally generates header protection key,
    content padding and randomized protocol timings.
    Non-legacy protocols also get the default special junk packet (I1).
    """
    import random

    # Official amneziawg-go README: "Jc: int, recommended range is 4-12".
    # The native AmneziaVPN installer picks 4-6; stay within the documented
    # band so fresh instances do not fall below the recommended floor.
    jc = random.randint(4, 12)
    jmin = random.randint(5, 20)
    jmax = random.randint(jmin + 10, jmin + 50)
    # AWG 3.1 enables header protection, which puts a floor under the junk sizes.
    s_min = AWG3_MIN_JUNK_SIZE if awg3 else 10
    s1 = random.randint(s_min, 50)
    s2 = random.randint(s_min, 50)
    s3 = random.randint(s_min, 50)
    s4 = random.randint(s_min, 50)

    if use_ranges:
        # AWG 2.0: H1-H4 as non-overlapping ranges (min-max)
        # Split [1B, 4.29B] into 4 equal zones, pick random sub-range in each
        # Guarantees no intersections between H1-H4 per AWG 2.0 spec
        def make_ranges(total_min=1000000000, total_max=4294967295):
            zone_size = (total_max - total_min) // 4
            result = []
            for i in range(4):
                z_start = total_min + i * zone_size
                z_end = z_start + zone_size - 1
                padding = min(100000, zone_size // 4)
                a = random.randint(z_start + padding, z_end - padding)
                b = random.randint(a + 1, z_end)
                result.append(f"{a}-{b}")
            return result
        
        h1, h2, h3, h4 = make_ranges()
    elif awg3:
        # AWG 3.1: the official docs prescribe the compatibility values
        # 1,2,3,4 when HeaderProtection is enabled - the custom-header
        # mechanism is OFF then and Header Protection (ChaCha20 with the
        # random per-server HeaderProtectionKey) hides the message type.
        # This is exactly what the native AmneziaVPN client generates.
        # Ranged H1-H4 with RandomTrailers=on are actively harmful:
        # transport packets get misclassified as handshakes and die at
        # CheckMAC1 (amneziawg-go#186, kernel-module#226).
        h1, h2, h3, h4 = '1', '2', '3', '4'
    else:
        h1 = str(random.randint(100000000, 4294967295))
        h2 = str(random.randint(100000000, 4294967295))
        h3 = str(random.randint(100000000, 4294967295))
        h4 = str(random.randint(100000000, 4294967295))

    params = {
        'junk_packet_count': str(jc),
        'junk_packet_min_size': str(jmin),
        'junk_packet_max_size': str(jmax),
        'init_packet_junk_size': str(s1),
        'response_packet_junk_size': str(s2),
        'cookie_reply_packet_junk_size': str(s3),
        'transport_packet_junk_size': str(s4),
        'init_packet_magic_header': h1,
        'response_packet_magic_header': h2,
        'underload_packet_magic_header': h3,
        'transport_packet_magic_header': h4,
    }

    if use_ranges:
        # The desktop client ships a special junk packet out of the box; not
        # setting one leaves the first packet of every session recognisable.
        params['i1'] = AWG_DEFAULT_I1

    if awg3:
        # Ranges are "min-max" (u16_range_from_string in amneziawg-tools).
        # reject_after_time must stay above rekey_after_time, otherwise a
        # session is dropped before the rekey window opens.
        rekey_after = random.randint(100, 130)
        reject_after = random.randint(rekey_after + 40, rekey_after + 70)
        keepalive = random.randint(8, 12)
        rekey_timeout = random.randint(4, 6)
        attempts = random.randint(15, 20)
        padding_min = random.randint(8, 24)

        params.update({
            'header_protection_key': generate_psk(),
            'content_padding_addition': f"{padding_min}-{padding_min + random.randint(24, 48)}",
            'rekey_after_time': f"{rekey_after}-{rekey_after + random.randint(10, 40)}",
            'rekey_timeout': f"{rekey_timeout}-{rekey_timeout + random.randint(1, 3)}",
            'reject_after_time': f"{reject_after}-{reject_after + random.randint(10, 30)}",
            'keepalive_timeout': f"{keepalive}-{keepalive + random.randint(2, 6)}",
            'max_handshake_attempts': f"{attempts}-{attempts + random.randint(2, 6)}",
            'random_trailers': 'on',
            'disable_cookies': 'on',
        })

    return params


class AWGManager:
    """Manages AmneziaWG protocol installation and client management."""

    # Protocol types
    AWG = 'awg'          # New AWG (awg-go based, uses awg/awg-quick)
    AWG_LEGACY = 'awg_legacy'  # Legacy AWG (uses wg/wg-quick)
    AWG2 = 'awg2'        # AmneziaWG 2.0 (separate container amnezia-awg2)
    AWG3 = 'awg3'        # AmneziaWG 3.1 (separate container amnezia-awg3)

    def __init__(self, ssh_manager):
        self.ssh = ssh_manager
        # Short-lived caches: a single UI refresh asks for the same config
        # path/content several times; each call is a separate SSH command.
        # 10s TTL keeps edits visible while collapsing duplicates.
        self._config_path_cache = {}   # protocol_type -> (ts, path)
        self._server_config_cache = {} # protocol_type -> (ts, content)
        self._CACHE_TTL = 10

    def _base_protocol(self, protocol_type):
        """Return base protocol for instance keys like awg__2."""
        return str(protocol_type or self.AWG).split('__', 1)[0]

    def _instance_index(self, protocol_type):
        parts = str(protocol_type or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol_type):
        """Get Docker container name for protocol type/instance.
        First instances keep legacy names; additional instances get -N suffix.
        """
        base = self._base_protocol(protocol_type)
        idx = self._instance_index(protocol_type)
        if base == self.AWG_LEGACY:
            name = 'amnezia-awg-legacy'
        elif base == self.AWG2:
            name = 'amnezia-awg2'
        elif base == self.AWG3:
            name = 'amnezia-awg3'
        else:
            name = 'amnezia-awg'
        return name if idx <= 1 else f'{name}-{idx}'

    def _config_path(self, protocol_type):
        """Get server config path inside container."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return '/opt/amnezia/awg/wg0.conf'
        # Both AWG and AWG2 use awg0.conf
        return '/opt/amnezia/awg/awg0.conf'

    def _config_path_candidates(self, protocol_type):
        """Return possible config paths, ordered by the expected path first."""
        expected = self._config_path(protocol_type)
        fallback = '/opt/amnezia/awg/awg0.conf' if self._base_protocol(protocol_type) == self.AWG_LEGACY else '/opt/amnezia/awg/wg0.conf'
        return [expected, fallback]

    def _resolve_config_path(self, protocol_type):
        """Resolve the real config path in existing containers.

        AWG Legacy should use wg0.conf, but some older or manually modified
        installations may have a different file name. Resolve the existing file
        instead of requiring users to create symlinks inside the container.
        """
        container_name = self._container_name(protocol_type)
        cached = self._config_path_cache.get(protocol_type)
        if cached and time.time() - cached[0] < self._CACHE_TTL:
            return cached[1]
        candidates = self._config_path_candidates(protocol_type)
        paths = ' '.join(candidates)
        script = f'for p in {paths}; do if [ -f "$p" ]; then echo "$p"; exit 0; fi; done; exit 1'
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c '{script}'"
        )
        result = out.strip().splitlines()[0] if code == 0 and out.strip() else self._config_path(protocol_type)
        self._config_path_cache[protocol_type] = (time.time(), result)
        return result

    def _wg_binary(self, protocol_type):
        """Get the wireguard binary name."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg'
        # AWG and AWG2 both use 'awg' binary
        return 'awg'


    def _quick_binary(self, protocol_type):
        """Get the wireguard-quick binary name."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg-quick'
        # AWG and AWG2 both use 'awg-quick'
        return 'awg-quick'


    def _interface_name(self, protocol_type, config_path=None):
        """Get the interface name."""
        if config_path:
            return os.path.splitext(os.path.basename(config_path))[0]
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg0'
        # AWG and AWG2 both use 'awg0' interface
        return 'awg0'

    def _docker_image(self, protocol_type):
        """Get Docker image for protocol type."""
        if self._base_protocol(protocol_type) in (self.AWG, self.AWG2, self.AWG3):
            return 'amneziavpn/amneziawg-go:latest'
        return 'amneziavpn/amnezia-wg:latest'

    def _clients_table_path(self):
        """Path to the clients table file inside container."""
        return '/opt/amnezia/awg/clientsTable'

    def _used_subnet_indexes(self):
        """Subnet indexes (N of 10.8.N.0/24) taken by the other awg/wireguard
        containers on this host. Best effort: on any SSH failure returns an
        empty set, which falls back to the default subnet (index 1)."""
        cmd = (
            "for c in $(docker ps -a --format '{{.Names}}' "
            "| grep -E '^amnezia-(awg|wireguard)'); do "
            "docker exec \"$c\" sh -c "
            "'grep -h -m1 \"^Address\" "
            "/opt/amnezia/awg/awg0.conf /opt/amnezia/awg/wg0.conf "
            "/opt/amnezia/wireguard/wg0.conf 2>/dev/null' 2>/dev/null; "
            "done"
        )
        out, _, code = self.ssh.run_sudo_command(cmd, timeout=60)
        if code != 0 or not out:
            return set()
        return parse_subnet_indexes(out.splitlines())

    def _config_exists(self, protocol_type):
        container_name = self._container_name(protocol_type)
        config_path = self._config_path(protocol_type)
        _, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} test -f {config_path}")
        return code == 0

    def _get_subnet_ip(self, protocol_type):
        """Get the subnet IP (gateway) from server config, or fallback to default."""
        try:
            config = self._get_server_config(protocol_type)
            for line in config.split('\n'):
                if line.startswith('Address'):
                    # Take the first (IPv4) part of a possibly dual-stack Address line
                    addr = line.split('=')[1].strip().split(',')[0].strip()
                    ip = addr.split('/')[0]
                    return ip
        except Exception:
            pass
        return AWG_DEFAULTS['subnet_ip']

    def _get_subnet_cidr(self, protocol_type):
        """Get the subnet CIDR from server config, or fallback to default."""
        try:
            config = self._get_server_config(protocol_type)
            for line in config.split('\n'):
                if line.startswith('Address'):
                    # Take the first (IPv4) part of a possibly dual-stack Address line
                    addr = line.split('=')[1].strip().split(',')[0].strip()
                    if '/' in addr:
                        return addr.split('/')[1]
        except Exception:
            pass
        return AWG_DEFAULTS['subnet_cidr']

    def _get_subnet_base(self, protocol_type):
        """Get the subnet network address (e.g. 172.16.21.0) from server config."""
        subnet_ip = self._get_subnet_ip(protocol_type)
        cidr = int(self._get_subnet_cidr(protocol_type))
        parts = list(map(int, subnet_ip.split('.')))
        mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network = struct.pack('!I', (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
        net_int = struct.unpack('!I', network)[0] & mask
        net_parts = [(net_int >> 24) & 0xFF, (net_int >> 16) & 0xFF, (net_int >> 8) & 0xFF, net_int & 0xFF]
        return '.'.join(map(str, net_parts))

    def _get_subnet_ipv6_ip(self, protocol_type):
        """Get the IPv6 gateway from server config, or '' if the tunnel is IPv4-only."""
        try:
            config = self._get_server_config(protocol_type)
            for line in config.split('\n'):
                line = line.strip()
                if line.startswith('Address'):
                    addr = line.split('=', 1)[1]
                    for part in addr.split(','):
                        part = part.strip()
                        if ':' in part:
                            return part.split('/')[0]
        except Exception:
            pass
        return ''

    def _get_client_ipv6(self, protocol_type, client_ip):
        """Derive a client's IPv6 address from its IPv4 address.

        The last hextet mirrors the IPv4 last octet (in hex), so every client
        with 10.8.1.N deterministically gets <prefix>::<hex(N)>. Returns ''
        when the server tunnel has no IPv6 gateway configured.
        """
        gateway = self._get_subnet_ipv6_ip(protocol_type)
        if not gateway:
            return ''
        try:
            octet = int(client_ip.split('.')[3])
        except (ValueError, IndexError, AttributeError):
            return ''
        prefix = gateway.rsplit(':', 1)[0] + ':'
        return f"{prefix}{octet:x}"

    def _detect_server_ipv6(self, protocol_type=None):
        """Decide whether the tunnel should be dual-stack.

        The AWG_IPV6 environment variable forces the answer ("off" / "on");
        in the default "auto" mode the server is probed.

        Auto-detection requires IPv6 to work end-to-end: a global address on
        the host *and* a default IPv6 route inside the protocol container.
        Docker networks are IPv4-only unless the daemon is explicitly
        configured for IPv6, so checking the host alone can enable a
        dual-stack tunnel whose NAT66 has nowhere to forward. Clients then
        receive an IPv6 address, an IPv6 DNS server and ::/0 with no route
        out, which blackholes traffic on IPv6-preferring clients (notably
        macOS) even though the host's own IPv6 is fine.
        """
        mode = os.environ.get(AWG_IPV6_ENV, 'auto').strip().lower()
        if mode in IPV6_FORCE_OFF:
            logger.info("%s=%s, keeping the tunnel IPv4-only", AWG_IPV6_ENV, mode)
            return False
        if mode in IPV6_FORCE_ON:
            logger.info("%s=%s, forcing a dual-stack tunnel", AWG_IPV6_ENV, mode)
            return True

        out, _, _ = self.ssh.run_sudo_command("ip -6 route show default 2>/dev/null")
        if not out.strip():
            out, _, _ = self.ssh.run_sudo_command("ip -6 addr show scope global 2>/dev/null")
            if not out.strip():
                return False

        if protocol_type is None:
            return True

        container_name = self._container_name(protocol_type)
        out, _, _ = self.ssh.run_sudo_command(
            f"docker exec {container_name} ip -6 route show default 2>/dev/null"
        )
        if out.strip():
            return True

        logger.info(
            "Host has IPv6 but container %s has no IPv6 default route "
            "(Docker IPv6 is disabled), keeping the tunnel IPv4-only",
            container_name,
        )
        return False

    def _userspace_guard(self, protocol_type):
        """Shell snippet forcing userspace for awg3 on a pre-3.1 kernel module."""
        if self._base_protocol(protocol_type) != self.AWG3:
            return ''
        return AWG3_USERSPACE_GUARD

    def _host_awg_module_version(self):
        """Version of the amneziawg kernel module on the host, or None.

        modinfo covers the module that is installed but not loaded yet: the
        container loads it implicitly on the first `ip link add`, so it counts.
        """
        out, _, _ = self.ssh.run_sudo_command(
            "cat /sys/module/amneziawg/version 2>/dev/null || "
            "modinfo -F version amneziawg 2>/dev/null"
        )
        version = out.strip().split('\n')[0].strip()
        return version or None

    @staticmethod
    def _module_supports_awg3(version):
        """Whether an amneziawg module version speaks the AWG 3.1 key set."""
        try:
            return int(version.split('.')[0]) >= AWG3_MIN_KERNEL_MODULE_MAJOR
        except (AttributeError, ValueError):
            return False

    def _verify_interface_up(self, protocol_type):
        """Fail loudly when the tunnel interface did not survive awg-quick.

        A config the kernel module rejects leaves a running container with no
        interface at all, which used to be reported to the UI as a successful
        install (issue #113).
        """
        container_name = self._container_name(protocol_type)
        iface = self._interface_name(protocol_type)
        _, _, code = self.ssh.run_sudo_command(
            f"docker exec {container_name} ip link show {iface}"
        )
        if code == 0:
            return

        logs, _, _ = self.ssh.run_sudo_command(
            f"docker logs --tail 20 {container_name} 2>&1"
        )
        raise RuntimeError(
            f"{iface} is not up in {container_name}: the tunnel config was "
            f"rejected. Container log:\n{logs.strip()}"
        )

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        """Check if Docker is installed and running."""
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, code2 = self.ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        return 'active' in out2 or 'running' in out2.lower()

    def install_docker(self):
        """Install Docker on the server (mirrors install_docker.sh)."""
        script = r"""
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
elif which zypper > /dev/null 2>&1; then pm=$(which zypper); silent_inst="-nq install"; check_pkgs="-nq refresh"; docker_pkg="docker"; dist="opensuse";
elif which pacman > /dev/null 2>&1; then pm=$(which pacman); silent_inst="-S --noconfirm --noprogressbar --quiet"; check_pkgs="-Sup"; docker_pkg="docker"; dist="archlinux";
else echo "Packet manager not found"; exit 1; fi;
echo "Dist: $dist, Packet manager: $pm";
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl enable --now docker; sleep 5;
fi;
if [ "$(systemctl is-active docker)" != "active" ]; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl start docker; sleep 5;
fi;
docker --version
"""
        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            raise RuntimeError(f"Failed to install Docker: {err}")
        return out

    def check_container_running(self, protocol_type):
        """Check if AWG container is running."""
        container_name = self._container_name(protocol_type)
        state = self._snapshot_state(container_name)
        if state is not None:
            return state[1]
        # Use ^name$ for exact match (Docker name filter does substring match)
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{container_name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self, protocol_type):
        """Check if protocol is installed (container exists)."""
        container_name = self._container_name(protocol_type)
        state = self._snapshot_state(container_name)
        if state is not None:
            return state[0]
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{container_name}$ --format '{{{{.Names}}}}'"
        )
        # Exact match check
        return container_name in out.strip().split('\n')

    def _snapshot_state(self, container_name):
        """(exists, running) from the shared docker ps snapshot, or None."""
        fn = getattr(self.ssh, 'docker_container_state', None)
        return fn(container_name) if fn else None

    # ----- batched status prefetch: one SSH command for every AWG container -----

    def prefetch_awg_state(self, protocol_types):
        """Populate ssh._awg_batch with configs and clients tables.

        A /check used to spend 3-4 SSH round trips per running AWG instance
        (config, awg params, clientsTable). On high-latency servers this was
        the bulk of the wait. Here a single command dumps everything for all
        running AWG containers; _get_server_config/_get_clients_table then
        read from the cache. The cache lives only for this request (TTL)."""
        containers = []
        for proto in protocol_types:
            cname = self._container_name(proto)
            state = self._snapshot_state(cname)
            if state is None:
                try:
                    state = self.ssh.docker_container_state(cname)
                except Exception:
                    state = None
            if state and state[1]:
                containers.append(cname)
        if not containers:
            self.ssh._awg_batch = {'_ts': time.time(), 'containers': {}}
            return
        # The trailing `echo` inside sh -c matters: when awg0.conf or
        # clientsTable has no trailing newline, `cat` leaves the cursor
        # mid-line and the next marker gets glued to the payload's last
        # line (observed on FIRSTBYTE: all three containers' dumps merged
        # into one section -> the awg2 card counted ~120 union peers).
        cmd = (
            'for c in ' + ' '.join(containers) + '; do '
            'echo "@@CONTAINER@@ $c"; '
            'docker exec "$c" sh -c \'cat /opt/amnezia/awg/awg0.conf 2>/dev/null; '
            'echo; echo "@@CLIENTS@@"; '
            'cat /opt/amnezia/awg/clientsTable 2>/dev/null; echo\'; '
            'done'
        )
        out, err, code = self.ssh.run_sudo_command(cmd, timeout=60)
        batch = {}
        current = None
        # Belt and braces: split on markers found anywhere in the stream,
        # not only at line start, so even a glued marker still separates
        # sections (the payload fragment before it stays with its owner).
        for piece in re.split(r'(@@CONTAINER@@ [^\n]+|@@CLIENTS@@)', out or ''):
            if piece.startswith('@@CONTAINER@@ '):
                current = piece.split(' ', 1)[1].strip()
                batch[current] = {'config': [], 'clients': [], 'part': 'config'}
            elif current and piece.strip() == '@@CLIENTS@@':
                batch[current]['part'] = 'clients'
            elif current:
                batch[current][batch[current]['part']].extend(piece.splitlines())
        self.ssh._awg_batch = {
            '_ts': time.time(),
            'containers': {
                name: {'config': '\n'.join(parts['config']),
                       'clients': '\n'.join(parts['clients'])}
                for name, parts in batch.items()
            },
        }
        # Forensics for poisoned batch entries (config of container A paired
        # with clientsTable of container B — observed on NATA 29.09). Section
        # sizes at build time show exactly what the parser saw.
        sections = ', '.join(
            f"{name}: cfg={len(parts['config'])}L, tbl={len(parts['clients'])}L"
            for name, parts in batch.items())
        logger.info(
            f"prefetch batch built ({len(out or '')}B output): {sections or 'no sections'}")

    def _batch_entry(self, container_name):
        batch = getattr(self.ssh, '_awg_batch', None)
        if batch is None or time.time() - batch.get('_ts', 0) > 15:
            return None
        return batch['containers'].get(container_name)

    def prepare_host(self, protocol_type):
        """Prepare host for container (mirrors prepare_host.sh)."""
        container_name = self._container_name(protocol_type)
        dockerfile_folder = f"/opt/amnezia/{container_name}"
        script = f"""
mkdir -p {dockerfile_folder}
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
# Enable Docker IPv6 when the host has a global IPv6 address. Without this
# containers get no IPv6 route and dual-stack tunnels silently fall back
# to IPv4-only. Also enable ip6tables (+experimental): without them Docker
# sets no NAT66 for the fixed-cidr-v6 ULA subnet and v6 traffic blackholes.
# daemon.json is merged (not overwritten) and backed up. Docker is
# restarted only when the file actually changed AND no amnezia-* or panel
# containers are running - restarting the daemon mid-install kills every
# container on the host (tunnels drop, a dockerized panel dies with its
# own install request). Otherwise the restart is deferred and reported
# as AWP_DOCKER_IPV6=pending so the install log can warn the admin.
if ip -6 -o addr show scope global 2>/dev/null | grep -q inet6; then
  cp /etc/docker/daemon.json /etc/docker/daemon.json.bak.awp 2>/dev/null
  IPV6_CHANGED=$(python3 - <<'PYEOF' 2>/dev/null
import json, os
p = '/etc/docker/daemon.json'
d = {{}}
if os.path.exists(p):
    d = json.load(open(p))
need = {{'ipv6': True, 'experimental': True, 'ip6tables': True}}
changed = False
for k, v in need.items():
    if d.get(k) != v:
        d[k] = v; changed = True
if 'fixed-cidr-v6' not in d:
    d['fixed-cidr-v6'] = 'fd00:42::/64'; changed = True
if changed:
    json.dump(d, open(p, 'w'), indent=2)
    print('yes')
PYEOF
)
  if [ -z "$IPV6_CHANGED" ] && ! grep -q '"ipv6"' /etc/docker/daemon.json 2>/dev/null; then
    echo '{{"ipv6": true, "fixed-cidr-v6": "fd00:42::/64", "experimental": true, "ip6tables": true}}' > /etc/docker/daemon.json
    IPV6_CHANGED=yes
  fi
  if [ "$IPV6_CHANGED" = "yes" ]; then
    if docker ps --format '{{{{.Names}}}}' 2>/dev/null | grep -qiE '^amnezia-|panel'; then
      echo "AWP_DOCKER_IPV6=pending"
    else
      systemctl restart docker
      echo "AWP_DOCKER_IPV6=restarted"
    fi
  else
    echo "AWP_DOCKER_IPV6=ok"
  fi
fi
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            logger.warning(f"prepare_host warning: {err}")
        for line in (out or '').splitlines():
            if line.startswith('AWP_DOCKER_IPV6='):
                return line.split('=', 1)[1].strip()
        return None

    # Kernel module version that supports AWG 3.1 features and stays
    # backward-compatible with AWG 2.0 configs.
    AWG_MODULE_VERSION = "3.1.20260812"
    AWG_MODULE_REPO = "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git"

    def setup_kernel_module(self):
        """Install the amneziawg kernel module via DKMS (best effort).

        Without the module, awg-quick inside the container falls back to
        the userspace amneziawg-go implementation, which is noticeably
        slower under load. The container mounts /lib/modules and has
        SYS_MODULE capability, so once the module exists on the host,
        awg-quick picks it automatically on (re)start.

        Skipped (userspace fallback) when:
        - module already present
        - Secure Boot is enabled (unsigned module would not load)
        - kernel headers / build tools cannot be installed
        - the DKMS build fails (e.g. very old kernels)
        """
        v = self.AWG_MODULE_VERSION
        script = f"""
CUR=$(modinfo amneziawg 2>/dev/null | awk '/^version:/{{print $2; exit}}')
if [ -n "$CUR" ] && [ "$CUR" = "{v}" ]; then
    echo "KERNEL_MODULE: ok: already present ($CUR)"
    exit 0
fi
if [ -n "$CUR" ]; then
    # An older/newer module is present: upgrade. The module can only be
    # unloaded when no tunnel uses it; otherwise defer the upgrade.
    if ! modprobe -r amneziawg 2>/dev/null; then
        echo "KERNEL_MODULE: skipped: version $CUR present but in use by running tunnels; stop all AWG containers and reinstall to upgrade to {v}"
        exit 0
    fi
    dkms remove "amneziawg/$CUR" --all >/dev/null 2>&1 || true
    echo "KERNEL_MODULE: upgrading from $CUR"
fi
if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi 'enabled'; then
    echo "KERNEL_MODULE: skipped: Secure Boot enabled (unsigned module would not load)"
    exit 0
fi
KVER=$(uname -r)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
if ! apt-get install -y -qq dkms "linux-headers-$KVER" git make gcc >/tmp/awg-kmod.log 2>&1; then
    if ! apt-cache show "linux-headers-$KVER" >/dev/null 2>&1; then
        echo "KERNEL_MODULE: failed: headers for the running kernel $KVER are no longer in the repos - upgrade the kernel (apt install linux-image-amd64) and reboot, then reinstall the protocol"
    else
        echo "KERNEL_MODULE: failed: cannot install build tools: $(tail -3 /tmp/awg-kmod.log | tr '\\n' ' ' | cut -c1-300)"
    fi
    exit 1
fi
rm -rf /tmp/awg-module
if ! git clone --depth 1 --branch v{v} {self.AWG_MODULE_REPO} /tmp/awg-module >>/tmp/awg-kmod.log 2>&1; then
    echo "KERNEL_MODULE: failed: cannot clone the module repo (github.com unreachable?)"
    exit 1
fi
cd /tmp/awg-module/src
sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION="{v}"/' dkms.conf
if ! dkms add . >>/tmp/awg-kmod.log 2>&1; then
    echo "KERNEL_MODULE: failed: dkms add failed: $(tail -3 /tmp/awg-kmod.log | tr '\\n' ' ' | cut -c1-300)"
    exit 1
fi
if ! dkms build amneziawg/{v} >>/tmp/awg-kmod.log 2>&1; then
    REASON=$(tail -5 /var/lib/dkms/amneziawg/{v}/build/make.log 2>/dev/null | tr '\\n' ' ' | cut -c1-300)
    echo "KERNEL_MODULE: failed: dkms build failed: ${{REASON:-see /var/lib/dkms/amneziawg/{v}/build/make.log}}"
    exit 1
fi
if ! dkms install amneziawg/{v} >>/tmp/awg-kmod.log 2>&1; then
    echo "KERNEL_MODULE: failed: dkms install failed: $(tail -3 /tmp/awg-kmod.log | tr '\\n' ' ' | cut -c1-300)"
    exit 1
fi
if ! modprobe amneziawg 2>/tmp/awg-kmod.log; then
    echo "KERNEL_MODULE: failed: module built but modprobe failed: $(tail -2 /tmp/awg-kmod.log | tr '\\n' ' ' | cut -c1-200)"
    exit 1
fi
cd / && rm -rf /tmp/awg-module
echo "KERNEL_MODULE: ok: installed {v}"
"""
        try:
            out, err, code = self.ssh.run_sudo_script(script, timeout=600)
            marker = ''
            for line in (out or '').splitlines():
                if line.startswith('KERNEL_MODULE:'):
                    marker = line.split(':', 1)[1].strip()
                    logger.info(f"setup_kernel_module: {line}")
            if not marker:
                logger.warning(f"setup_kernel_module: no marker, userspace fallback: {err}")
                return 'failed: no result (SSH or script error)'
            return marker
        except Exception as err:
            logger.warning(f"setup_kernel_module warning (userspace fallback): {err}")
            return f'failed: {err}'

    def setup_firewall(self):
        """Setup host firewall (mirrors setup_host_firewall.sh).

        Also raises net.netfilter.nf_conntrack_max: the default on small
        VMs can be as low as ~7680 entries, and every client flow through
        the NAT consumes one entry. A full conntrack table makes the
        kernel silently drop packets ("nf_conntrack: table full"), which
        users see as random connection freezes. 262144 is a safe value
        for a VPN gateway; persisted via /etc/sysctl.d.
        """
        script = """
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
    cur=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    if [ "$cur" -lt 262144 ] 2>/dev/null; then
        printf '%s\n' 'net.netfilter.nf_conntrack_max = 262144' > /etc/sysctl.d/98-awp-conntrack.conf
        sysctl -w net.netfilter.nf_conntrack_max=262144
    fi
fi
"""
        self.ssh.run_sudo_script(script)
        return True

    def setup_host_tuning(self):
        """Enable BBR congestion control on the host (with persistence).

        BBR is available in all kernels >= 4.9 (any modern Debian/Ubuntu).
        If the tcp_bbr module is not loaded, load it and persist across
        reboots. Falls back silently when the kernel has no BBR support.
        BBR significantly outperforms cubic on lossy paths, which VPN
        tunnels often traverse.
        """
        script = """
set -e
if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    modprobe tcp_bbr 2>/dev/null || true
fi
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    echo tcp_bbr > /etc/modules-load.d/awp-bbr.conf
    printf '%s\\n' \\
        'net.core.default_qdisc = fq' \\
        'net.ipv4.tcp_congestion_control = bbr' \\
        > /etc/sysctl.d/99-awp-bbr.conf
    sysctl -w net.core.default_qdisc=fq
    sysctl -w net.ipv4.tcp_congestion_control=bbr
fi
"""
        try:
            self.ssh.run_sudo_script(script)
        except Exception as err:
            logger.warning(f"setup_host_tuning warning: {err}")
        return True

    def get_host_tuning(self):
        """Read live network-tuning state for the whole server (host + all
        AWG containers). Used by the server-level "Host tuning" modal.
        """
        script = """
echo "HOST_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "HOST_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)"
echo "HOST_CONNTRACK=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
echo "HOST_CONNTRACK_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
echo "HOST_BACKLOG=$(sysctl -n net.core.netdev_max_backlog 2>/dev/null)"
echo "HOST_SOMAXCONN=$(sysctl -n net.core.somaxconn 2>/dev/null)"
echo "HOST_AWG_MODULE=$(modinfo amneziawg 2>/dev/null | awk '/^version:/{print $2; exit}')"
for c in $(docker ps -a --format '{{.Names}}' | grep -E '^amnezia-(awg|exit)' | sort); do
  echo "CT_NAME=$c"
  if docker ps --format '{{.Names}}' | grep -qx "$c"; then
    echo "CT_RUNNING=1"
    docker exec "$c" sh -c 'for p in net.core.rmem_max net.core.wmem_max net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing; do echo "CTK_$p=$(sysctl -n $p 2>/dev/null)"; done; echo "CTK_nofile=$(ulimit -n)"' 2>/dev/null
  else
    echo "CT_RUNNING=0"
  fi
done
"""
        # A multi-line script has to go through run_sudo_script: `sudo <script>`
        # only elevates its first line, so every `docker` call below would run
        # unprivileged and the container list would silently come back empty.
        out, err, code = self.ssh.run_sudo_script(script, timeout=60)
        info = {'host': {}, 'containers': []}
        if code != 0 or not out:
            return info
        current = None
        for line in out.splitlines():
            if '=' not in line:
                continue
            key, _, val = line.partition('=')
            key, val = key.strip(), val.strip()
            if key.startswith('HOST_'):
                info['host'][key[5:].lower()] = val
            elif key == 'CT_NAME':
                current = {'name': val, 'running': False, 'ct': {}}
                info['containers'].append(current)
            elif key == 'CT_RUNNING' and current is not None:
                current['running'] = val == '1'
            elif key.startswith('CTK_') and current is not None:
                current['ct'][key[4:]] = val
        return info

    def install_protocol(self, protocol_type, port=None, awg_params=None,
                         mtu=None, dns=None, special_junk=None, dns6=None):
        """
        Full installation of AWG or AWG-Legacy protocol.
        Steps: install docker -> prepare host -> build container ->
               configure container -> run container -> setup firewall

        mtu/dns end up in the generated client configs; special_junk is an
        {'i1': ..., 'i5': ...} mapping overriding the generated I1-I5.
        """
        if port is None:
            port = AWG_DEFAULTS['port']

        base_proto = self._base_protocol(protocol_type)
        if awg_params is None:
            awg_params = generate_awg_params(
                # AWG 2.0: ranged H1-H4 ("min-max"). AWG 3.1: fixed 1,2,3,4
                # per the official docs (custom headers off, Header
                # Protection hides the message type) - same as the native
                # AmneziaVPN client generates.
                use_ranges=(base_proto in (self.AWG, self.AWG2)),
                awg3=(base_proto == self.AWG3),
            )

        if special_junk is not None:
            # An explicit mapping replaces the generated set outright, so
            # clearing I1 in the UI actually clears it.
            for key in SPECIAL_JUNK_KEYS:
                awg_params.pop(key, None)
            awg_params.update(normalize_special_junk(special_junk))

        # An explicit MTU from the UI wins. Otherwise derive one from the
        # obfuscation actually in use: AWG_DEFAULTS['mtu'] (1376) predates
        # ContentPaddingAddition and overflows a 1500-byte link on 3.x.
        mtu = str(mtu or safe_client_mtu(awg_params)).strip()
        dns = (dns or '').strip() or self._default_dns()

        container_name = self._container_name(protocol_type)
        docker_image = self._docker_image(protocol_type)
        config_path = self._config_path(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        iface = self._interface_name(protocol_type)

        results = []

        # Step 1: Install Docker
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        # Step 2: Prepare host
        results.append("Preparing host...")
        docker_ipv6 = self.prepare_host(protocol_type)
        results.append("Host prepared")
        if docker_ipv6 == 'pending':
            results.append(
                "! Docker IPv6 was enabled in /etc/docker/daemon.json, but Docker "
                "was NOT restarted because other containers are running. Tunnels "
                "stay IPv4-only until you run: systemctl restart docker"
            )
        elif docker_ipv6 == 'restarted':
            results.append("Docker restarted to apply IPv6 config")

        # Step 2.5: Kernel module (best effort, userspace fallback)
        results.append("Checking amneziawg kernel module...")
        km = self.setup_kernel_module()
        if km.startswith('ok'):
            detail = km.split(':', 1)[1].strip() if ':' in km else ''
            results.append(f"Kernel module ready ({detail})" if detail else "Kernel module ready")
        elif km.startswith('skipped'):
            results.append(f"Kernel module skipped, userspace mode (amneziawg-go): {km.split(':', 1)[-1].strip()}")
        else:
            results.append(f"Kernel module failed, userspace mode (amneziawg-go): {km.split(':', 1)[-1].strip()}")

        # Step 2.6: warn about sibling AWG containers whose image still carries
        # awg-tools of another version than the host kernel module - such a
        # pair fails setconf with EINVAL and the tunnel silently stays down
        # (the new start.sh self-heals via userspace, but a stale image should
        # be rebuilt by reinstalling that instance).
        module_v = self._host_awg_module_version()
        if module_v and base_proto in (self.AWG, self.AWG2, self.AWG3):
            out, _, _ = self.ssh.run_sudo_command(
                "docker ps --format '{{.Names}}' | grep -E '^amnezia-awg' || true"
            )
            for cname in out.split():
                if cname == self._container_name(protocol_type):
                    continue
                tv, _, _ = self.ssh.run_sudo_command(
                    f"docker exec {cname} sh -c \"awg --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1\" 2>/dev/null"
                )
                tools_v = tv.strip()
                if tools_v and tools_v != module_v:
                    results.append(
                        f"! {cname}: awg-tools {tools_v} vs kernel module {module_v} mismatch - "
                        f"the tunnel self-heals in userspace mode on restart, but reinstall "
                        f"this instance to rebuild its image and keep the fast kernel datapath."
                    )

        # Step 3: Remove old container if exists
        if self.check_protocol_installed(protocol_type):
            results.append("Removing old container...")
            # AWG containers keep /opt/amnezia/awg (peers, keys, clientsTable)
            # INSIDE the container - there is no bind mount, so docker rm is
            # irreversible data loss. Snapshot it to the host first.
            self._backup_container_state(container_name, results)
            self.remove_container(protocol_type)
            results.append("Old container removed")

        # Step 4: Build/Pull container
        if base_proto == self.AWG3:
            module_version = self._host_awg_module_version()
            if module_version and not self._module_supports_awg3(module_version):
                results.append(
                    f"! Host amneziawg kernel module {module_version} predates "
                    f"AWG 3.1, the tunnel will run on userspace amneziawg-go "
                    f"(slower). Upgrade the module to 3.1+ for the kernel "
                    f"datapath."
                )
        results.append("Pulling Docker image...")
        dockerfile_folder = f"/opt/amnezia/{container_name}"

        dockerfile_content = self._dockerfile_content(
            docker_image,
            AWG_QUICK_FORCE_USERSPACE_PATCH if base_proto in (self.AWG, self.AWG2, self.AWG3) else '',
        )
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        # Run the build detached and poll for its exit code. On flaky links
        # the SSH channel dies seconds into the build while the docker daemon
        # keeps building - a synchronous wait then reports a false failure
        # for a build that actually succeeded. Detached, the build is immune
        # to channel/transport drops; each poll is a fresh short channel.
        build_log = f"/tmp/docker-build-{container_name}.log"
        code_file = f"{build_log}.code"
        self.ssh.run_sudo_command(f"rm -f {build_log} {code_file}")
        self.ssh.run_sudo_command(
            f"nohup sh -c 'docker build --no-cache --pull -t {container_name} "
            f"{dockerfile_folder} > {build_log} 2>&1; echo $? > {code_file}' "
            f">/dev/null 2>&1 &",
            timeout=30
        )
        build_code = None
        deadline = time.time() + 900
        while time.time() < deadline:
            time.sleep(5)
            out, err, code = self.ssh.run_sudo_command(
                f"cat {code_file} 2>/dev/null", timeout=30)
            if code == 0 and (out or '').strip().isdigit():
                build_code = int(out.strip())
                break
        if build_code is None:
            raise RuntimeError(
                f"Build did not finish within 900s; "
                f"full log on the server: {build_log}")
        if build_code != 0:
            out, err, _ = self.ssh.run_sudo_command(
                f"tail -c 6000 {build_log}", timeout=30)
            detail = (out or '').strip() or (
                f"no output; full log on the server: {build_log}")
            raise RuntimeError(f"Failed to build container: {detail}")
        results.append("Docker image built successfully")

        # Step 5: Run container
        results.append("Starting container...")
        # Detect host IPv6 BEFORE creating the container: the netns
        # disable_ipv6 flags are fixed at container creation time, see
        # _docker_run_cmd.
        ipv6_enabled = self._detect_server_ipv6()
        run_cmd = self._docker_run_cmd(container_name, container_name, port, ipv6_enabled)

        out, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")
        if hasattr(self.ssh, 'docker_ps_invalidate'):
            self.ssh.docker_ps_invalidate()

        # Connect to DNS network
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {container_name}")

        # Wait for container to be fully running
        results.append("Waiting for container to start...")
        self._wait_container_running(container_name)
        results.append("Container started")

        # Step 6: Configure container (generate server keys and config)
        results.append("Configuring AWG...")
        ipv6_enabled = self._detect_server_ipv6(protocol_type)
        results.append(
            "IPv6 works end-to-end, enabling dual-stack tunnel"
            if ipv6_enabled else
            "No usable IPv6 (host or Docker), tunnel will be IPv4-only"
        )
        self._configure_container(protocol_type, port, awg_params, ipv6=ipv6_enabled,
                                  mtu=mtu, dns=dns, dns6=dns6)
        results.append("AWG configured")

        # Step 7: Upload and run start script
        results.append("Starting AWG service...")
        self._upload_start_script(protocol_type)
        self._verify_interface_up(protocol_type)
        results.append("AWG service started")

        # Step 8: Setup firewall
        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")

        # Step 9: Host network tuning (BBR)
        results.append("Applying host network tuning (BBR)...")
        self.setup_host_tuning()
        results.append("Host network tuning applied")

        return {
            'status': 'success',
            'protocol': protocol_type,
            'port': port,
            'awg_params': awg_params,
            'mtu': mtu,
            'dns': dns,
            'log': results,
        }

    def _wait_container_running(self, container_name, timeout=30):
        """Wait for a container to be in 'running' state."""
        import time
        last_status = 'unknown'
        for i in range(timeout // 2):
            out, _, _ = self.ssh.run_sudo_command(
                f"docker inspect --format='{{{{.State.Status}}}}' {container_name}"
            )
            last_status = out.strip().strip("'\"")
            if last_status == 'running':
                logger.info(f"Container {container_name} is running")
                time.sleep(1)
                return True
            logger.info(f"Container {container_name} status: {last_status}, waiting...")
            time.sleep(2)

        # Container failed to start — fetch logs for diagnostics
        logs_out, _, _ = self.ssh.run_sudo_command(
            f"docker logs --tail 50 {container_name} 2>&1"
        )
        raise RuntimeError(
            f"Container {container_name} did not start within {timeout}s "
            f"(status: {last_status}). Logs:\n{logs_out}"
        )

    def _configure_container(self, protocol_type, port, awg_params, ipv6=False,
                             mtu=None, dns=None, dns6=None):
        """Configure the AWG container (generate keys and server config)."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._config_path(protocol_type)

        subnet_ip = self._get_subnet_ip(protocol_type)
        subnet_cidr = self._get_subnet_cidr(protocol_type)
        ipv6_gateway = AWG_DEFAULTS['subnet_ipv6_ip']
        if not self._config_exists(protocol_type):
            # Fresh install (no server config yet): every instance would
            # otherwise fall back to the same default 10.8.1.0/24 and start
            # handing out client IPs that another instance on this host
            # already gave out. Pick a subnet index no other awg/wireguard
            # container uses, for IPv6 as well (fd42:8:N::/64).
            try:
                subnet_index = first_free_subnet_index(self._used_subnet_indexes())
            except Exception:
                subnet_index = 1
            subnet_ip = f"10.8.{subnet_index}.1"
            subnet_cidr = AWG_DEFAULTS['subnet_cidr']
            ipv6_gateway = f"fd42:8:{subnet_index}::1"

        # AWG 3.1 parameters are written only when the protocol asks for them,
        # so awg/awg2 installations keep byte-identical configs.
        awg3_config_lines = ''.join(
            f"{config_key} = {awg_params[param_key]}\n"
            for param_key, config_key in AWG3_PARAM_MAP
            if awg_params.get(param_key)
        )

        special_junk_lines = ''.join(
            f"{param_key.upper()} = {awg_params[param_key]}\n"
            for param_key in SPECIAL_JUNK_KEYS
            if awg_params.get(param_key)
        )

        # MTU and DNS belong to the generated client configs, not to the
        # server interface, so they are stored as comments: awg-quick would
        # otherwise resize the server tunnel and call resolvconf, which the
        # container does not have. _get_mtu/_get_dns read them back.
        client_defaults_lines = (
            f"# MTU = {mtu or AWG_DEFAULTS['mtu']}\n"
            f"# DNS = {dns or self._default_dns()}\n"
        )
        # IPv6 DNS for dual-stack tunnels, stored the same comment way;
        # _get_dns6 reads it back when building client configs.
        if ipv6:
            client_defaults_lines += f"# DNS6 = {AWG_DEFAULTS['dns6']}\n"

        address_line = f"{subnet_ip}/{subnet_cidr}"
        if ipv6:
            address_line += f", {ipv6_gateway}/{AWG_DEFAULTS['subnet_ipv6_cidr']}"     
        
        # Build the server config generation script
        if self._base_protocol(protocol_type) in (self.AWG, self.AWG2, self.AWG3):
            config_script = f"""
mkdir -p /opt/amnezia/awg
cd /opt/amnezia/awg
WIREGUARD_SERVER_PRIVATE_KEY=$({wg_bin} genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | {wg_bin} pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key

WIREGUARD_PSK=$({wg_bin} genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/awg/wireguard_psk.key

cat > {config_path} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {address_line}
ListenPort = {port}
Jc = {awg_params['junk_packet_count']}
Jmin = {awg_params['junk_packet_min_size']}
Jmax = {awg_params['junk_packet_max_size']}
S1 = {awg_params['init_packet_junk_size']}
S2 = {awg_params['response_packet_junk_size']}
S3 = {awg_params['cookie_reply_packet_junk_size']}
S4 = {awg_params['transport_packet_junk_size']}
H1 = {awg_params['init_packet_magic_header']}
H2 = {awg_params['response_packet_magic_header']}
H3 = {awg_params['underload_packet_magic_header']}
H4 = {awg_params['transport_packet_magic_header']}
{special_junk_lines}{awg3_config_lines}{client_defaults_lines}EOF
"""
        else:
            # AWG Legacy uses wg commands
            config_script = f"""
mkdir -p /opt/amnezia/awg
cd /opt/amnezia/awg
WIREGUARD_SERVER_PRIVATE_KEY=$({wg_bin} genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | {wg_bin} pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key

WIREGUARD_PSK=$({wg_bin} genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/awg/wireguard_psk.key

cat > {config_path} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {address_line}
ListenPort = {port}
Jc = {awg_params['junk_packet_count']}
Jmin = {awg_params['junk_packet_min_size']}
Jmax = {awg_params['junk_packet_max_size']}
S1 = {awg_params['init_packet_junk_size']}
S2 = {awg_params['response_packet_junk_size']}
H1 = {awg_params['init_packet_magic_header']}
H2 = {awg_params['response_packet_magic_header']}
H3 = {awg_params['underload_packet_magic_header']}
H4 = {awg_params['transport_packet_magic_header']}
{client_defaults_lines}EOF
"""

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{config_script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure container: {err}")

    # ===================== CONTAINER BUILDERS =====================
    # Pure string builders (no SSH), pinned by golden fixtures in
    # tests/test_awg_start_script.py so the generated container files can be
    # changed deliberately, never by accident.

    @staticmethod
    def _dockerfile_content(docker_image, userspace_patch):
        """Dockerfile of a protocol container - matches the original from
        client/server_scripts/awg/. `userspace_patch` is the awg-quick sed
        patch for AWG images or '' for the legacy one (it runs wg-quick
        against the plain WireGuard module, which has nothing to fall back
        to)."""
        return (
            f"FROM {docker_image}\n"
            f"\n"
            f'LABEL maintainer="AmneziaVPN"\n'
            f"\n"
            f"RUN apk add --no-cache bash curl dumb-init iptables iproute2 conntrack-tools\n"
            f"RUN apk --update upgrade --no-cache\n"
            f"\n"
            f"{userspace_patch}"
            f"\n"
            f"RUN mkdir -p /opt/amnezia\n"
            f'RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && '
            f'echo "sysctl -p /etc/sysctl.conf 2>/dev/null || true" >> /opt/amnezia/start.sh && '
            f'echo "tail -f /dev/null" >> /opt/amnezia/start.sh\n'
            f"RUN chmod a+x /opt/amnezia/start.sh\n"
            f"\n"
            f"# Network tuning (mirrors AmneziaVPN container tuning)\n"
            f"RUN printf '%s\\n' \\\n"
            f"'fs.file-max = 51200' \\\n"
            f"'net.core.rmem_max = 67108864' \\\n"
            f"'net.core.wmem_max = 67108864' \\\n"
            f"'net.core.netdev_max_backlog = 250000' \\\n"
            f"'net.core.somaxconn = 4096' \\\n"
            f"'net.ipv4.tcp_syncookies = 1' \\\n"
            f"'net.ipv4.tcp_tw_reuse = 1' \\\n"
            f"'net.ipv4.tcp_fin_timeout = 30' \\\n"
            f"'net.ipv4.tcp_keepalive_time = 1200' \\\n"
            f"'net.ipv4.ip_local_port_range = 10000 65000' \\\n"
            f"'net.ipv4.tcp_max_syn_backlog = 8192' \\\n"
            f"'net.ipv4.tcp_max_tw_buckets = 5000' \\\n"
            f"'net.ipv4.tcp_fastopen = 3' \\\n"
            f"'net.ipv4.tcp_mem = 25600 51200 102400' \\\n"
            f"'net.ipv4.tcp_rmem = 4096 87380 67108864' \\\n"
            f"'net.ipv4.tcp_wmem = 4096 65536 67108864' \\\n"
            f"'net.ipv4.tcp_mtu_probing = 1' \\\n"
            f" >> /etc/sysctl.conf && \\\n"
            f"mkdir -p /etc/security && \\\n"
            f"printf '%s\\n' '* soft nofile 51200' '* hard nofile 51200' >> /etc/security/limits.conf\n"
            f"\n"
            f'ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]\n'
        )

    @staticmethod
    def _docker_run_cmd(container_name, image, port, ipv6_enabled):
        """`docker run` command line of a protocol container.

        The IPv6 sysctls have to be passed at creation time: the netns
        disable_ipv6 flags are fixed then, so a container started without
        them can never add an IPv6 address to a tunnel interface (ip -6
        address add -> RTNETLINK Permission denied, and awg-quick then
        deletes the whole awg0).
        """
        ipv6_sysctls = (
            '--sysctl="net.ipv6.conf.all.disable_ipv6=0" \\\n'
            '--sysctl="net.ipv6.conf.default.disable_ipv6=0" \\\n'
            if ipv6_enabled else ''
        )
        return f"""docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p {port}:{port}/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
{ipv6_sysctls} --name {container_name} \
--ulimit nofile=51200:51200 \
{image}"""

    @staticmethod
    def _mss_clamp_body(iface):
        """Clamp TCP MSS on a transit link in both directions, so a tunnel
        carried inside another tunnel never depends on PMTU discovery."""
        return (
            f"# Clamp TCP MSS on the transit link so entry->exit->internet never needs fragmentation\n"
            f"iptables -t mangle -A FORWARD -i {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n"
            f"iptables -t mangle -A FORWARD -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n"
        )

    @staticmethod
    def _start_script_body(config_path, quick_bin, userspace_guard, subnet_default, bwlimits_path,
                           extra_blocks=(), pre_blocks=()):
        """/opt/amnezia/start.sh of a protocol container: brings the tunnel
        up, sets up forwarding/NAT and applies per-peer bandwidth limits.
        `pre_blocks` go in before the tunnel comes up (the exit-node
        kill-switch must exist before awg0 can forward anything),
        `extra_blocks` are appended verbatim before the final `tail -f`."""
        pre = ''.join(f"{block}\n" for block in pre_blocks)
        extra = ''.join(f"{block}\n" for block in extra_blocks)
        return f"""#!/bin/bash
echo "Container startup"

# Apply container network tuning (see Dockerfile)
sysctl -p /etc/sysctl.conf 2>/dev/null || true

# Read subnet from server config dynamically (IPv4 part of the Address line)
SUBNET=$(grep '^Address' {config_path} | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET={subnet_default}
fi

# IPv6 subnet, if the tunnel is dual-stack (second part of the Address line)
SUBNET6=$(grep '^Address' {config_path} | head -1 | tr ',' '\n' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)
{pre}{userspace_guard}
# kill daemons in case of restart
{quick_bin} down {config_path} 2>/dev/null

IFACE=$(basename {config_path} .conf)

# start daemons if configured
if [ -f {config_path} ]; then
  {quick_bin} up {config_path}
  # Self-heal: when awg-tools and the host kernel module disagree on the
  # version (e.g. module upgraded to 3.1 while the image still carries old
  # tools), setconf fails with EINVAL and the tunnel silently stays down.
  # Detect the mismatch and retry in userspace mode (amneziawg-go) - slower,
  # but the clients keep their internet.
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    TOOLS_V=$(awg --version 2>/dev/null | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)
    MOD_V=$(cat /sys/module/amneziawg/version 2>/dev/null || true)
    if [ -n "$MOD_V" ] && [ -n "$TOOLS_V" ] && [ "$TOOLS_V" != "$MOD_V" ]; then
      echo "! awg-tools $TOOLS_V vs kernel module $MOD_V mismatch"
      if grep -q WG_FORCE_USERSPACE "$(command -v {quick_bin})" 2>/dev/null; then
        echo "! retrying in userspace mode (amneziawg-go)"
        WG_FORCE_USERSPACE=1 {quick_bin} up {config_path}
      fi
    fi
  fi
fi

# Allow traffic on the TUN interface
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i $IFACE -o eth0 -s $SUBNET -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s $SUBNET -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $SUBNET -o eth1 -j MASQUERADE

# IPv6 forwarding + NAT66, only when the tunnel has an IPv6 subnet
if [ -n "$SUBNET6" ] && command -v ip6tables >/dev/null 2>&1; then
  sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
  ip6tables -A INPUT -i $IFACE -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -j ACCEPT
  ip6tables -A OUTPUT -o $IFACE -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -o eth0 -s $SUBNET6 -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -o eth1 -s $SUBNET6 -j ACCEPT
  ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  ip6tables -t nat -A POSTROUTING -s $SUBNET6 -o eth0 -j MASQUERADE
  ip6tables -t nat -A POSTROUTING -s $SUBNET6 -o eth1 -j MASQUERADE
fi

# Apply per-peer bandwidth limits (flat file written by the panel)
if [ -f {bwlimits_path} ]; then
(
{AWGManager._tc_apply_body(bwlimits_path, config_path)}
)
fi

{extra}tail -f /dev/null
"""

    def _render_start_script(self, protocol_type, config_path=None):
        """start.sh for one protocol instance. `config_path` overrides the
        default location - save_server_config passes the resolved path of an
        existing container. The exit-node block is always emitted: it is
        inert without exit0.conf and makes the container restart-safe for a
        link written later."""
        config_path = config_path or self._config_path(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        subnet_default = f"{AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}"
        functions = self._exit_shell_functions(config_path, quick_bin, subnet_default)
        return self._start_script_body(
            config_path,
            quick_bin,
            self._userspace_guard(protocol_type),
            subnet_default,
            self._bwlimits_path(),
            pre_blocks=(functions + '[ -f "$EXIT_CONF" ] && x_killswitch_on\n',),
            extra_blocks=('# ---- Exit-node link: bring it up now that the client tunnel exists ----\n'
                          'if [ -f "$EXIT_CONF" ]; then x_link_up || echo "! exit link not applied, clients stay on the kill-switch"; fi\n',),
        )

    def _write_start_script(self, protocol_type, config_path=None):
        """Put a freshly rendered start.sh into the container (no restart)."""
        container_name = self._container_name(protocol_type)
        self.ssh.upload_file(self._render_start_script(protocol_type, config_path), "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {container_name}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {container_name} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

    def _upload_start_script(self, protocol_type):
        """Write the start script and restart the container to run it."""
        self._write_start_script(protocol_type)
        self.ssh.run_sudo_command(f"docker restart {self._container_name(protocol_type)}")
        time.sleep(5)

    # ===================== EXIT-NODE LINK (ENTRY SIDE) =====================

    _EXIT_SHELL_TEMPLATE = """# ---- Exit-node link (panel-managed; driven by __EXIT_CONF__) ----
EXIT_CONF=__EXIT_CONF__
EXIT_IF=__EXIT_IF__
EXIT_TABLE=__EXIT_TABLE__
EXIT_PREF=__EXIT_TABLE__      # slot 0: 190/191 exceptions, catch-all at the table number
DNS_NET=__DNS_NET__
X_CONF=__CONF__
X_QUICK=__QUICK__
X_IFACE=$(basename $X_CONF .conf)
X_SUBNET=$(grep '^Address' $X_CONF | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
[ -n "$X_SUBNET" ] || X_SUBNET=__SUBNET_DEFAULT__
X_SUBNET6=$(grep '^Address' $X_CONF | head -1 | tr ',' '\\n' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)

x_rule()    { ip "$1" rule show 2>/dev/null | grep -q "^$2:" || ip "$1" rule add pref "$2" "${@:3}"; }
x_unrule()  { while ip "$1" rule del pref "$2" 2>/dev/null; do :; done; }
x_ipt_add() { iptables -t "$1" -C "${@:2}" 2>/dev/null || iptables -t "$1" -A "${@:2}"; }
x_ipt_del() { while iptables -t "$1" -D "${@:2}" 2>/dev/null; do :; done; }

x_killswitch_on() {
  # Everything from the client subnet is answered by the exit table. Until
  # exit0 is up that table holds only a blackhole, so nothing falls through
  # to eth0 - this runs before the client tunnel comes up on purpose.
  ip -4 route replace blackhole default metric 1000 table $EXIT_TABLE
  x_rule -4 190 from $X_SUBNET to $X_SUBNET lookup main
  if grep -qs '^# DnsViaExit = on' "$EXIT_CONF"; then x_unrule -4 191
  else x_rule -4 191 from $X_SUBNET to $DNS_NET lookup main; fi
  x_rule -4 $EXIT_PREF from $X_SUBNET lookup $EXIT_TABLE
  if [ -n "$X_SUBNET6" ]; then
    # No IPv6 path through the exit yet: refuse fast instead of leaking via eth0
    ip -6 route replace unreachable default table $EXIT_TABLE
    x_rule -6 190 from $X_SUBNET6 to $X_SUBNET6 lookup main
    x_rule -6 $EXIT_PREF from $X_SUBNET6 lookup $EXIT_TABLE
  fi
}
x_killswitch_off() {
  for p in 190 191 $EXIT_PREF; do x_unrule -4 $p; x_unrule -6 $p; done
  ip -4 route flush table $EXIT_TABLE 2>/dev/null
  ip -6 route flush table $EXIT_TABLE 2>/dev/null
}
x_link_up() {
  $X_QUICK down $EXIT_CONF 2>/dev/null
  if ! $X_QUICK up $EXIT_CONF; then
    echo "! $EXIT_IF failed to start; clients stay on the kill-switch until the link is repaired or removed"
    return 3
  fi
  # Loose reverse-path check on the link only: containers inherit rp_filter
  # from the host, and per-client exit tables (later) can make the reverse
  # lookup resolve to another exitN.
  sysctl -w net.ipv4.conf.$EXIT_IF.rp_filter=2 >/dev/null 2>&1 || true
  ip -4 route replace default dev $EXIT_IF table $EXIT_TABLE
  x_ipt_add filter FORWARD -i $X_IFACE -o $EXIT_IF -s $X_SUBNET -j ACCEPT
  # SNAT clients into this node's transit address: the exit sees one /32 per entry
  x_ipt_add nat POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE
  x_ipt_add mangle FORWARD -o $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  x_ipt_add mangle FORWARD -i $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  # NAT is decided once per flow: flows opened before the link were SNATed to
  # eth0 and would leave exit0 with the wrong source. Drop them so they reopen.
  if command -v conntrack >/dev/null 2>&1; then conntrack -D -s $X_SUBNET >/dev/null 2>&1
  else echo "! conntrack-tools missing: client flows opened before the link keep leaving via eth0 until they end"; fi
  # Never report success while clients could still leave via eth0
  if ! ip -4 rule show | grep -q "^$EXIT_PREF:" \\
     || ! ip -4 route show table $EXIT_TABLE | grep -q "^default dev $EXIT_IF" \\
     || ! iptables -t nat -C POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE 2>/dev/null; then
    echo "! FATAL: policy routing for $EXIT_IF is not in place"
    return 3
  fi
  echo "exit link up: $(ip -4 -o addr show dev $EXIT_IF | awk '{print $4}') -> table $EXIT_TABLE"
}
x_link_down() {
  # Take the interface down first: MASQUERADE forgets the flows NATed through
  # it (device notifier) and the table keeps blackholing until the rules go.
  [ -f "$EXIT_CONF" ] && $X_QUICK down $EXIT_CONF 2>/dev/null
  ip link del $EXIT_IF 2>/dev/null
  x_ipt_del filter FORWARD -i $X_IFACE -o $EXIT_IF -s $X_SUBNET -j ACCEPT
  x_ipt_del nat POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE
  x_ipt_del mangle FORWARD -o $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  x_ipt_del mangle FORWARD -i $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}
x_exit_sync() {
  if [ -f "$EXIT_CONF" ]; then x_killswitch_on && x_link_up
  else x_link_down; x_killswitch_off; fi
}
"""

    @staticmethod
    def _exit_shell_functions(config_path, quick_bin, subnet_default):
        """Shell functions of the entry side of an exit-node link (no
        side effects by themselves): kill-switch, link up/down and the sync
        entry point used both by start.sh and by the live apply."""
        return (AWGManager._EXIT_SHELL_TEMPLATE
                .replace('__EXIT_CONF__', EXIT_CONF)
                .replace('__EXIT_IF__', EXIT_IFACE)
                .replace('__EXIT_TABLE__', str(EXIT_TABLE))
                .replace('__DNS_NET__', DNS_NET)
                .replace('__CONF__', config_path)
                .replace('__QUICK__', quick_bin)
                .replace('__SUBNET_DEFAULT__', subnet_default))

    @staticmethod
    def _exit_conf_body(link):
        """exit0.conf of the entry side. The private key is substituted
        inside the container (it never leaves it); `Table = off` keeps
        awg-quick from touching the routing - the shell block owns it."""
        lines = [
            '[Interface]',
            '# Managed by Amnezia Web Panel - exit node link',
            f"# ExitUid = {link.get('exit_uid', '')}",
            f"# ExitName = {link.get('exit_name', '')}",
            f"# Obfuscation = {'on' if link.get('obfuscation') else 'off'}",
            f"# DnsViaExit = {'on' if link.get('dns_via_exit') else 'off'}",
            f"PrivateKey = {ENTRY_PRIVATE_KEY_PLACEHOLDER}",
            f"Address = {link['transit_ip']}/{link.get('subnet_cidr', 24)}",
            f"MTU = {EXIT_MTU}",
            'Table = off',
        ]
        if link.get('obfuscation'):
            params = link.get('awg_params') or {}
            lines += [f"{config_key} = {params[param_key]}"
                      for param_key, config_key in TRANSIT_PARAM_KEYS if params.get(param_key)]
        lines += [
            '',
            '[Peer]',
            f"PublicKey = {link['exit_public_key']}",
            f"PresharedKey = {link['psk']}",
            'AllowedIPs = 0.0.0.0/0',
            f"Endpoint = {link['endpoint_host']}:{link['endpoint_port']}",
            'PersistentKeepalive = 25',
        ]
        return '\n'.join(lines) + '\n'

    def exit_prepare_keys(self, protocol_type):
        """Create the entry-side key pair inside the container (kept if it
        exists) and return the public key."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c 'umask 077; mkdir -p {EXIT_DIR}; "
            f"[ -s {EXIT_KEY} ] || {wg_bin} genkey > {EXIT_KEY}; {wg_bin} pubkey < {EXIT_KEY}'"
        )
        if code != 0 or not out.strip():
            raise RuntimeError(f"Failed to prepare the exit link key: {err or out}")
        return out.strip()

    def _exit_apply(self, protocol_type, teardown=False):
        """Run the exit block live inside the container (same snippet as in
        start.sh). Raises when the link could not be brought up, so a caller
        never records a link whose clients would still leave via eth0."""
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        functions = self._exit_shell_functions(
            config_path, self._quick_binary(protocol_type),
            f"{AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}")
        action = ('x_link_down\nx_killswitch_off\nrm -f "$EXIT_CONF"\n' if teardown
                  else 'x_exit_sync\n')
        # One docker step per sudo call: the sudo prefix covers only the first
        # command of a `&&` chain, the rest would run unprivileged.
        self.ssh.upload_file(functions + action, "/tmp/_amnz_exit.sh")
        out, err, code = self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_exit.sh {container_name}:/tmp/_amnz_exit.sh")
        if code != 0:
            self.ssh.run_command("rm -f /tmp/_amnz_exit.sh")
            raise RuntimeError(f"exit link apply failed: {err or out or f'SSH exit code {code}'}")
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {container_name} bash /tmp/_amnz_exit.sh", timeout=60)
        self.ssh.run_command("rm -f /tmp/_amnz_exit.sh")
        if code != 0:
            raise RuntimeError(f"exit link apply failed: {out or err or f'SSH exit code {code}'}")
        return out

    def exit_link(self, protocol_type, link):
        """Write exit0.conf into the container, refresh start.sh (no restart)
        and bring the link up live. `link` carries transit_ip, subnet_cidr,
        exit_public_key, psk, endpoint_host, endpoint_port, obfuscation,
        awg_params, exit_uid, exit_name, dns_via_exit."""
        container_name = self._container_name(protocol_type)
        self.ssh.upload_file(self._exit_conf_body(link), "/tmp/_amnz_exit0.conf")
        # One docker step per sudo call (the sudo prefix covers only the first
        # command of a `&&` chain).
        steps = (
            f"docker exec -i {container_name} mkdir -p {EXIT_DIR}",
            f"docker cp /tmp/_amnz_exit0.conf {container_name}:{EXIT_CONF}",
            f"docker exec -i {container_name} bash -c 'k=$(cat {EXIT_KEY}) && "
            f"sed -i \"s|{ENTRY_PRIVATE_KEY_PLACEHOLDER}|$k|\" {EXIT_CONF} && chmod 600 {EXIT_CONF}'",
        )
        try:
            for step in steps:
                out, err, code = self.ssh.run_sudo_command(step)
                if code != 0:
                    raise RuntimeError(f"Failed to write exit0.conf: {err or out or f'SSH exit code {code}'}")
        finally:
            self.ssh.run_command("rm -f /tmp/_amnz_exit0.conf")
        # Resolved path: an older legacy install may keep its config at awg0.conf.
        self._write_start_script(protocol_type, config_path=self._resolve_config_path(protocol_type))
        return self._exit_apply(protocol_type)

    def exit_set_dns_via_exit(self, protocol_type, enabled):
        """Flip the DnsViaExit marker in exit0.conf and re-apply the block.
        With it on, the exception that keeps client DNS on this node is not
        installed, so DNS queries follow the client subnet through the link
        and are answered by the AmneziaDNS of the exit node. Re-applying
        recreates exit0, so flows opened before the change reopen."""
        container_name = self._container_name(protocol_type)
        value = 'on' if enabled else 'off'
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c 'test -f {EXIT_CONF} || exit 9; "
            f"sed -i \"s|^# DnsViaExit = .*|# DnsViaExit = {value}|\" {EXIT_CONF}'")
        if code == 9:
            raise RuntimeError('This instance has no exit link file')
        if code != 0:
            raise RuntimeError(f"Failed to update the DNS route of the link: {err or out}")
        return self._exit_apply(protocol_type)

    def exit_unlink(self, protocol_type):
        """Tear the link down live and delete exit0.conf; the key pair stays
        so a re-link reuses the public key already known to the exit."""
        return self._exit_apply(protocol_type, teardown=True)

    def exit_link_info(self, protocol_type):
        """What the container believes it is linked to, or None. Reads only
        the panel metadata, the address and the endpoint - never the key."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c 'test -f {EXIT_CONF} || exit 9; "
            f"grep -E \"^# (ExitUid|ExitName|Obfuscation|DnsViaExit) =|^Address|^Endpoint\" {EXIT_CONF}'"
        )
        if code != 0:
            return None
        info = {}
        for line in out.split('\n'):
            stripped = line.strip().lstrip('#').strip()
            if '=' not in stripped:
                continue
            key, _, value = stripped.partition('=')
            info[key.strip()] = value.strip()
        return {
            'exit_uid': info.get('ExitUid', ''),
            'exit_name': info.get('ExitName', ''),
            'obfuscation': info.get('Obfuscation') == 'on',
            'dns_via_exit': info.get('DnsViaExit') == 'on',
            'address': info.get('Address', ''),
            'endpoint': info.get('Endpoint', ''),
        }

    @staticmethod
    def _parse_wg_peer_lists(text):
        """Parse `wg show <if> latest-handshakes; ---; transfer; ---; endpoints`
        (tab-separated, one peer per line) into per-peer dicts. `dump` is
        avoided on purpose: its first line carries the interface private key."""
        sections = [s.strip() for s in text.split('---')]
        sections += [''] * (3 - len(sections))
        peers = {}

        def rows(section):
            for line in section.split('\n'):
                parts = line.strip().split('\t')
                if len(parts) >= 2 and parts[0]:
                    yield parts

        for parts in rows(sections[0]):
            try:
                peers.setdefault(parts[0], {})['latest_handshake'] = int(parts[1])
            except ValueError:
                peers.setdefault(parts[0], {})['latest_handshake'] = 0
        for parts in rows(sections[1]):
            peer = peers.setdefault(parts[0], {})
            try:
                peer['rx_bytes'] = int(parts[1])
                peer['tx_bytes'] = int(parts[2]) if len(parts) > 2 else 0
            except ValueError:
                peer['rx_bytes'], peer['tx_bytes'] = 0, 0
        for parts in rows(sections[2]):
            peers.setdefault(parts[0], {})['endpoint'] = '' if parts[1] == '(none)' else parts[1]
        return peers

    def exit_link_status(self, protocol_type, now=None):
        """Live state of the link: None when the container has no link file,
        otherwise up/handshake age/transfer/endpoint of the exit peer."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c 'test -f {EXIT_CONF} || exit 9; "
            f"{wg_bin} show {EXIT_IFACE} latest-handshakes; echo ---; "
            f"{wg_bin} show {EXIT_IFACE} transfer; echo ---; {wg_bin} show {EXIT_IFACE} endpoints'"
        )
        if code == 9:
            return None
        if code != 0:
            return {'up': False, 'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0,
                    'endpoint': '', 'error': (err or out).strip()}
        peers = self._parse_wg_peer_lists(out)
        peer = next(iter(peers.values()), {})
        handshake = peer.get('latest_handshake', 0)
        age = int((now or time.time()) - handshake) if handshake else None
        return {
            'up': age is not None and 0 <= age < EXIT_HANDSHAKE_UP_SECONDS,
            'handshake_age': age,
            'rx_bytes': peer.get('rx_bytes', 0),
            'tx_bytes': peer.get('tx_bytes', 0),
            'endpoint': peer.get('endpoint', ''),
        }

    @staticmethod
    def _egress_probe_script(subnet_ip):
        """POSIX sh (single-quoted into `docker exec sh -c`, so no quotes of
        its own) printing the client-path egress IP, `---`, and the container's
        own egress IP."""
        urls = ' '.join(EGRESS_CHECK_URLS)
        probe = (
            'x_ip() { for u in %s; do '
            'r=$(curl -fsS -4 --max-time %d "$@" "$u" 2>/dev/null | tr -d "[:space:]"); '
            'case "$r" in ""|*[!0-9.]*) ;; *) echo "$r"; return 0;; esac; '
            'done; echo ""; }' % (urls, EGRESS_CHECK_TIMEOUT)
        )
        return f'{probe}; x_ip --interface {subnet_ip}; echo ---; x_ip'

    @staticmethod
    def _first_ipv4(text):
        """First line of `text` that is a bare IPv4 address, or ''."""
        for line in (text or '').split('\n'):
            line = line.strip()
            if IPV4_RE.match(line):
                return line
        return ''

    def exit_check_egress(self, protocol_type):
        """Which public IP the clients of this instance leave from, and which
        one this node leaves from. The client probe is bound to the tunnel
        gateway address, so it takes the client path (ip rule -> table 200 ->
        exit0) instead of the container's default route; when no link is up it
        simply reports the node's own address twice."""
        container_name = self._container_name(protocol_type)
        script = self._egress_probe_script(self._get_subnet_ip(protocol_type))
        # both probes may fall through every URL before giving up
        timeout = EGRESS_CHECK_TIMEOUT * len(EGRESS_CHECK_URLS) * 2 + 20
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c '{script}'", timeout=timeout)
        if code != 0:
            raise RuntimeError(f"Egress check failed: {(err or out).strip()}")
        via, _, direct = out.partition('---')
        return {'via_exit': self._first_ipv4(via), 'direct': self._first_ipv4(direct)}

    def remove_container(self, protocol_type):
        """Remove AWG container (mirrors remove_container.sh)."""
        container_name = self._container_name(protocol_type)
        self.ssh.run_sudo_command(f"docker stop {container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {container_name}")
        self.ssh.run_sudo_command(f"docker rmi {container_name}")
        if hasattr(self.ssh, 'docker_ps_invalidate'):
            self.ssh.docker_ps_invalidate()
        return True

    def _backup_container_state(self, container_name, results=None):
        """Snapshot the container's /opt/amnezia/awg to a timestamped host dir.

        AWG containers have no bind mount for their state, so removing the
        container destroys every peer. Called before any destructive remove;
        failures are reported but never block the install (the admin sees the
        warning line in the install log)."""
        ts = time.strftime('%Y%m%d-%H%M%S')
        dest = f"/opt/amnezia/backups/{container_name}-{ts}"
        out, err, code = self.ssh.run_sudo_command(
            f"mkdir -p /opt/amnezia/backups && "
            f"docker cp {container_name}:/opt/amnezia/awg {dest}"
        )
        if code == 0:
            msg = f"Peer state backed up to {dest}"
        else:
            msg = (f"! Peer state backup of {container_name} FAILED: "
                   f"{((err or out) or '').strip()[:200]}")
        logger.info(f"_backup_container_state: {msg}")
        if results is not None:
            results.append(msg)
        return code == 0

    # ===================== CLIENT MANAGEMENT =====================

    def _get_clients_table(self, protocol_type):
        """Get the clients table from the server."""
        container_name = self._container_name(protocol_type)
        batch = self._batch_entry(container_name)
        if batch is not None:
            out = batch['clients']
        else:
            # A container known to be stopped has nothing to read: answer
            # empty WITHOUT an exec, instead of failing docker exec on every
            # poll and spamming the log with 'exit code 1'.
            try:
                state_fn = getattr(self.ssh, 'docker_container_state', None)
                st = state_fn(container_name) if state_fn else None
            except Exception:
                st = None
            if st and st[0] and not st[1]:
                return []
            clients_table_path = self._clients_table_path()
            out, err, code = self.ssh.run_sudo_command(
                f"docker exec -i {container_name} cat {clients_table_path} 2>/dev/null"
            )
            if code != 0:
                # Never let a failed read masquerade as an empty table: that
                # is how a transient docker exec failure once painted every
                # peer as 'External'. Distinguish the honest empty cases.
                state = None
                try:
                    state_fn = getattr(self.ssh, 'docker_container_state', None)
                    if state_fn:
                        state = state_fn(container_name)
                except Exception:
                    state = None
                if state and not state[1]:
                    # Container exists but is stopped: nothing to read, and
                    # the UI already shows the card as stopped.
                    return []
                # Running (or state unknown): probe the file itself.
                _, _, fcode = self.ssh.run_sudo_command(
                    f"docker exec -i {container_name} test -f {clients_table_path}")
                if fcode == 0:
                    raise RuntimeError(
                        f"clientsTable exists in {container_name} but could "
                        f"not be read (docker exec exit {code}): "
                        f"{err or 'no output'}")
                return []  # fresh instance: no clientsTable yet

        if not out.strip():
            if batch is not None:
                # The batched prefetch runs one composite SSH command whose
                # exit code is not checked per part: a transient `cat
                # clientsTable` failure inside it yields an EMPTY clients
                # section while the config section above it read fine. An
                # empty table next to a config full of peers is exactly the
                # 'everything became External for one poll' paint — distrust
                # it and re-read directly instead.
                conf_part = batch.get('config') or ''
                if 'PublicKey' in conf_part:
                    logger.warning(
                        f"prefetch gave an empty clientsTable for "
                        f"{container_name} but its config has peers; dropping "
                        f"batch entry and re-reading directly")
                    try:
                        del self.ssh._awg_batch['containers'][container_name]
                    except Exception:
                        pass
                    return self._get_clients_table(protocol_type)
            return []

        try:
            data = json.loads(out)
            if isinstance(data, list):
                if batch is not None and data:
                    # Integrity guard against a poisoned prefetch batch: a
                    # batch entry must contain ONE container's files. A mixed
                    # entry (config of container A + clientsTable of container
                    # B) once painted 68 of 71 awg2 peers as 'External' on
                    # NATA: the table pubkeys must exist in the SAME entry's
                    # config; otherwise drop the entry and read directly.
                    conf_text = batch.get('config') or ''
                    missing = [c.get('clientId', '') for c in data
                               if c.get('clientId', '') not in conf_text]
                    if missing:
                        logger.warning(
                            f"clientsTable {container_name} from prefetch is "
                            f"inconsistent with its own batch config "
                            f"({len(missing)}/{len(data)} table pubkeys absent "
                            f"from config, e.g. {missing[0][:12]}...); dropping "
                            f"batch entry and reading directly")
                        try:
                            del self.ssh._awg_batch['containers'][container_name]
                        except Exception:
                            pass
                        return self._get_clients_table(protocol_type)
                return data
            elif isinstance(data, dict):
                # Migration from old format
                result = []
                for client_id, info in data.items():
                    result.append({
                        'clientId': client_id,
                        'userData': {
                            'clientName': info.get('clientName', 'Unknown'),
                        }
                    })
                return result
        except json.JSONDecodeError:
            if batch is not None:
                # A truncated/corrupt prefetched read (flaky link, channel
                # drop mid-batch) must not masquerade as "0 peers": drop the
                # batch entry and retry with a direct per-container read.
                logger.warning(
                    f"clientsTable from prefetch for {container_name} did not "
                    f"parse; dropping batch and retrying directly")
                try:
                    del self.ssh._awg_batch['containers'][container_name]
                except Exception:
                    pass
                return self._get_clients_table(protocol_type)
            # The direct read itself is corrupt: better to surface an error
            # (get_server_status reports it, UI shows no number) than to
            # silently display 0 connections for a server that has peers.
            raise RuntimeError(
                f"clientsTable in {container_name} is not valid JSON "
                f"(truncated read or corrupt file)")

    def _save_clients_table(self, protocol_type, clients_table):
        """Save the clients table to the server."""
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()
        content = json.dumps(clients_table, indent=2)

        # Write to /tmp via SFTP, then docker cp into container
        self.ssh.upload_file(content, "/tmp/_amnz_clients.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_clients.json {container_name}:{clients_table_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_clients.json")

        # Drop prefetched batch snapshot so next read sees fresh data
        if getattr(self.ssh, '_awg_batch', None) is not None:
            self.ssh._awg_batch = None

        # Keep per-peer bandwidth limits in sync (best effort)
        try:
            self._apply_bw_limits(protocol_type, clients_table)
        except Exception as err:
            logger.warning(f"apply bw limits warning: {err}")

    def _bwlimits_path(self):
        """Flat file with per-peer speed limits, next to clientsTable."""
        return '/opt/amnezia/awg/bwlimits'

    @staticmethod
    def _tc_apply_body(bw_path, config_path):
        """Shell snippet applying per-peer limits from a flat file via tc.

        File format (space separated): "<ipv4> <ipv6|-> <mbps>".
        Rebuilds qdiscs from scratch; unclassified traffic is unlimited.
        Limits both download (HTB class on egress) and upload (ingress policer).
        """
        return f"""
BW={bw_path}
IFACE=$(basename {config_path} .conf)
[ -f "$BW" ] || exit 0
command -v tc >/dev/null 2>&1 || exit 0
ip link show dev $IFACE >/dev/null 2>&1 || exit 0
tc qdisc del dev $IFACE root 2>/dev/null
tc qdisc del dev $IFACE ingress 2>/dev/null
tc qdisc add dev $IFACE root handle 1: htb default 0 2>/dev/null || exit 0
tc qdisc add dev $IFACE handle ffff: ingress 2>/dev/null || true
i=0
while read -r ip4 ip6 mbps; do
  [ -z "$ip4" ] && continue
  [ -z "$mbps" ] && continue
  kbit=$(echo "$mbps" | awk '{{printf "%d", $1*1000}}')
  [ "$kbit" -gt 0 ] 2>/dev/null || continue
  i=$((i+1))
  cid=$((100+i))
  tc class add dev $IFACE parent 1: classid 1:$cid htb rate ${{kbit}}kbit ceil ${{kbit}}kbit 2>/dev/null
  tc filter add dev $IFACE parent 1: protocol ip u32 match ip dst $ip4/32 flowid 1:$cid 2>/dev/null
  [ "$ip6" != "-" ] && [ -n "$ip6" ] && tc filter add dev $IFACE parent 1: protocol ipv6 u32 match ip6 dst $ip6/128 flowid 1:$cid 2>/dev/null
  tc filter add dev $IFACE parent ffff: protocol ip u32 match ip src $ip4/32 police rate ${{kbit}}kbit burst 64k drop 2>/dev/null
  [ "$ip6" != "-" ] && [ -n "$ip6" ] && tc filter add dev $IFACE parent ffff: protocol ipv6 u32 match ip6 src $ip6/128 police rate ${{kbit}}kbit burst 64k drop 2>/dev/null
done < "$BW"
"""

    def _apply_bw_limits(self, protocol_type, clients_table):
        """Write the flat bwlimits file into the container and apply via tc."""
        container_name = self._container_name(protocol_type)
        lines = []
        for client in clients_table:
            ud = client.get('userData', {}) or {}
            try:
                mbps = float(ud.get('maxSpeed') or 0)
            except (TypeError, ValueError):
                continue
            if mbps <= 0:
                continue
            ip4 = ud.get('clientIp') or ''
            ip6 = ud.get('clientIpv6') or '-'
            if not ip4:
                continue
            lines.append(f"{ip4} {ip6} {mbps:g}")
        content = "\n".join(lines) + ("\n" if lines else "")
        self.ssh.upload_file(content, "/tmp/_amnz_bwlimits")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_bwlimits {container_name}:{self._bwlimits_path()}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_bwlimits")
        if self.check_container_running(protocol_type):
            body = self._tc_apply_body(self._bwlimits_path(), self._resolve_config_path(protocol_type))
            self.ssh.upload_file(body, "/tmp/_amnz_tc.sh")
            self.ssh.run_sudo_command(
                f"docker cp /tmp/_amnz_tc.sh {container_name}:/tmp/_amnz_tc.sh && "
                f"docker exec {container_name} bash /tmp/_amnz_tc.sh",
                timeout=60
            )
            self.ssh.run_command("rm -f /tmp/_amnz_tc.sh")

    @_serialized_table_write
    def set_speed_limit(self, protocol_type, client_id, max_speed):
        """Set per-peer bandwidth limit in Mbit/s (0 = unlimited).

        Enforced via tc inside the container (HTB on egress + ingress
        policer), per peer IPv4/IPv6. Persisted in clientsTable
        (userData.maxSpeed) and re-applied at container start from the
        bwlimits flat file.
        """
        mbps = round(float(max_speed), 1)
        if mbps < 0:
            raise RuntimeError('max_speed must be >= 0')
        clients_table = self._get_clients_table(protocol_type)
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        if client is None:
            raise RuntimeError('Client not found')
        ud = client.setdefault('userData', {})
        if mbps == 0:
            ud.pop('maxSpeed', None)
        else:
            ud['maxSpeed'] = mbps
        self._save_clients_table(protocol_type, clients_table)
        return {'status': 'success', 'max_speed': mbps}

    def _get_server_config(self, protocol_type):
        """Get the server WireGuard config."""
        cached = self._server_config_cache.get(protocol_type)
        if cached and time.time() - cached[0] < self._CACHE_TTL:
            return cached[1]
        container_name = self._container_name(protocol_type)
        batch = self._batch_entry(container_name)
        if batch is not None:
            config = batch['config']
            self._server_config_cache[protocol_type] = (time.time(), config)
            return config
        config_path = self._resolve_config_path(protocol_type)

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {config_path}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server config: {err}")
        self._server_config_cache[protocol_type] = (time.time(), out)
        return out

    def _invalidate_config_cache(self, protocol_type):
        """Forget the cached server config after the file in the container was
        rewritten. Every writer must call this, otherwise a second read on the
        same manager instance within _CACHE_TTL returns the pre-write content
        (a peer removed and re-added in one go would be resurrected)."""
        self._server_config_cache.pop(protocol_type, None)
        # The /check batch cache holds configs AND clientsTables of every
        # container on this connection - any peer/config write must drop it,
        # or a read within the batch TTL would resurrect pre-write state.
        if getattr(self.ssh, '_awg_batch', None) is not None:
            self.ssh._awg_batch = None

    @staticmethod
    def _sanitize_server_config(config_content):
        """awg-quick chokes on a bare `DNS =` key in the server config (it calls
        resolvconf, which is missing in the container, and the interface goes
        down). Convert active `DNS = ...` lines into `# DNS = ...` comments:
        the panel still reads them via _get_dns(), but quick-tools ignore them."""
        lines = []
        for line in config_content.split('\n'):
            stripped = line.strip()
            if stripped.startswith('DNS') and '=' in stripped and not stripped.startswith('#'):
                indent = line[:len(line) - len(line.lstrip())]
                lines.append(f"{indent}# {stripped}")
            else:
                lines.append(line)
        return '\n'.join(lines)

    def save_server_config(self, protocol_type, config_content):
        """Save the server WireGuard config and restart container."""
        config_content = self._sanitize_server_config(config_content)
        self._server_config_cache.pop(protocol_type, None)
        self._config_path_cache.pop(protocol_type, None)
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)

        # Upload new config into container via SFTP + docker cp
        self.ssh.upload_file(config_content.replace('\r\n', '\n'), "/tmp/_amnz_edit_config.conf")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_edit_config.conf {container_name}:{config_path}")
        self.ssh.run_command("rm -f /tmp/_amnz_edit_config.conf")

        # Regenerate start script so iptables rules pick up the (possibly changed) subnet
        self._write_start_script(protocol_type, config_path)

        # Restart container to apply all changes (including port and interface changes)
        self.ssh.run_sudo_command(f"docker restart {container_name}")

    def _get_server_public_key(self, protocol_type):
        """Get server public key."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat /opt/amnezia/awg/wireguard_server_public_key.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server public key: {err}")
        return out.strip()

    def _get_server_psk(self, protocol_type):
        """Get server preshared key."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat /opt/amnezia/awg/wireguard_psk.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get PSK: {err}")
        return out.strip()

    def _get_awg_params_from_config(self, protocol_type):
        """Extract AWG obfuscation params from server config."""
        config = self._get_server_config(protocol_type)
        params = {}
        # Mapping from server config keys to our param dictionary keys
        param_map = {
            'ListenPort': 'port',
            'Jc': 'junk_packet_count',
            'Jmin': 'junk_packet_min_size',
            'Jmax': 'junk_packet_max_size',
            'S1': 'init_packet_junk_size',
            'S2': 'response_packet_junk_size',
            'S3': 'cookie_reply_packet_junk_size',
            'S4': 'transport_packet_junk_size',
            'H1': 'init_packet_magic_header',
            'H2': 'response_packet_magic_header',
            'H3': 'underload_packet_magic_header',
            'H4': 'transport_packet_magic_header',
            'I1': 'i1',
            'I2': 'i2',
            'I3': 'i3',
            'I4': 'i4',
            'I5': 'i5',
            'CPS': 'cps',
        }
        param_map.update({config_key: param_key for param_key, config_key in AWG3_PARAM_MAP})

        for line in config.split('\n'):
            line = line.strip()
            # Support both 'key=value' and 'key = value'
            if '=' in line and not line.startswith('#') and not line.startswith('['):
                parts = line.split('=', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key in param_map:
                    params[param_map[key]] = val

        return params

    def _get_used_ips(self, protocol_type):
        """Get list of IPs already assigned in the config."""
        config = self._get_server_config(protocol_type)
        ips = []
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('AllowedIPs'):
                ips.extend(self._ipv4_addresses(line.split('=', 1)[-1]))
            elif line.startswith('Address'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
        return ips

    def _get_reserved_ips(self, protocol_type):
        """IPv4 addresses reserved in clientsTable by ANY client, disabled included.

        A disabled client keeps its address, so allocation must never hand it
        to someone else. Raises if the table cannot be read at all — silently
        treating the reservation pool as empty would break that guarantee.
        """
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {clients_table_path} 2>/dev/null"
        )
        if code != 0:
            # cat fails both when docker exec is broken and when the file
            # simply does not exist yet (fresh instance). Fail loudly only
            # for the former; an absent table means no reservations.
            _, terr, tcode = self.ssh.run_sudo_command(
                f"docker exec -i {container_name} true")
            if tcode != 0:
                raise RuntimeError(
                    f"Cannot read clients table from {container_name}: {terr.strip() or err.strip()}")
            return set()
        if not out.strip():
            return set()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise RuntimeError(f"Clients table in {container_name} is not valid JSON")
        entries = data if isinstance(data, list) else [
            {'clientId': k, 'userData': v} for k, v in data.items()]
        reserved = set()
        for c in entries:
            ud = c.get('userData') or {}
            reserved.update(self._client_ipv4_addresses(ud))
        return reserved

    def _get_next_ip(self, protocol_type):
        """Return the first free IP in the subnet, filling gaps left by deleted clients.

        The old implementation took the last IP in file order and incremented it,
        which produced duplicate IPs when peers were not sorted by IP and never
        reused addresses freed by deleted clients.

        Occupied = active config peers + reservations in clientsTable (disabled
        clients keep their IPs; only deletion releases an address).
        """
        used_ips = set(self._get_used_ips(protocol_type)) | self._get_reserved_ips(protocol_type)
        base = self._get_subnet_base(protocol_type)
        parts = base.split('.')
        prefix = '.'.join(parts[:3])

        used_octets = set()
        for ip in used_ips:
            ip_parts = ip.split('.')
            if len(ip_parts) != 4 or '.'.join(ip_parts[:3]) != prefix:
                continue
            try:
                used_octets.add(int(ip_parts[3]))
            except ValueError:
                continue

        for octet in range(2, 255):
            if octet not in used_octets:
                parts[3] = str(octet)
                return '.'.join(parts)

        raise RuntimeError("No free IP addresses left in the subnet")

    @staticmethod
    def _peer_block_ip(block):
        """Sort key for a [Peer] config block: its first AllowedIPs IPv4 address."""
        match = re.search(r'AllowedIPs\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)', block)
        if match:
            return tuple(int(match.group(i)) for i in range(1, 5))
        return (255, 255, 255, 255)

    def _insert_peer_sorted(self, protocol_type, peer_section):
        """Insert a new [Peer] section into the server config keeping peers sorted by IP.

        Creates a timestamped backup of the config inside the container before
        overwriting it, then rewrites the file with all [Peer] sections ordered
        by their AllowedIPs address.
        """
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)

        config = self._get_server_config(protocol_type)

        # Backup current config inside the container before modifying it
        ts = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cp {config_path} {config_path}.bak.{ts}"
        )

        head, _, rest = config.partition('[Peer]')
        blocks = []
        if rest:
            for chunk in rest.split('[Peer]'):
                chunk = chunk.strip()
                if chunk:
                    blocks.append('[Peer]\n' + chunk)

        blocks.append(peer_section.strip())
        blocks.sort(key=self._peer_block_ip)

        new_config = head.rstrip('\n') + '\n\n' + '\n\n'.join(blocks) + '\n'

        self.ssh.upload_file(new_config, "/tmp/_amnz_add_peer.conf")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_add_peer.conf {container_name}:{config_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_add_peer.conf")
        self._invalidate_config_cache(protocol_type)

    def _extract_ipv4(self, value):
        """Extract the first IPv4 address from AllowedIPs/clientIp-like values."""
        if not value:
            return ''
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(value))
        return match.group(1) if match else ''

    @staticmethod
    def _ipv4_addresses(value):
        """Read IPv4 addresses from native string/list and panel address fields."""
        addresses = set()
        for token in re.findall(r'(?<![\w.])\d+\.\d+\.\d+\.\d+(?![\w.])', str(value or '')):
            try:
                addresses.add(str(ipaddress.IPv4Address(token)))
            except ipaddress.AddressValueError:
                continue
        return addresses

    def _client_ipv4_addresses(self, user_data):
        addresses = set()
        for key in ('clientIp', 'allowedIps', 'allowed_ip', 'allowed_ips'):
            addresses.update(self._ipv4_addresses(user_data.get(key)))
        return addresses

    def _client_ip_from_userdata(self, user_data):
        """Return the saved address only when the record is unambiguous."""
        addresses = self._client_ipv4_addresses(user_data)
        return next(iter(addresses)) if len(addresses) == 1 else ''

    def _parse_peers_from_config(self, protocol_type):
        """Parse [Peer] sections from WireGuard server config and return dict of pubkey -> {allowedIps}."""
        try:
            config = self._get_server_config(protocol_type)
        except Exception:
            return {}

        peers = {}
        current_key = None
        for line in config.split('\n'):
            line = line.strip()
            if line == '[Peer]':
                current_key = None
            elif current_key is None and line.startswith('PublicKey'):
                current_key = line.split('=', 1)[1].strip()
                peers[current_key] = {'allowedIps': ''}
            elif current_key and line.startswith('AllowedIPs'):
                peers[current_key]['allowedIps'] = line.split('=', 1)[1].strip()
        return peers

    def get_clients(self, protocol_type):
        """Get list of all clients."""
        clients_table = self._get_clients_table(protocol_type)

        # Also try to get live data from wg show
        try:
            wg_show_data = self._wg_show(protocol_type)
        except Exception:
            wg_show_data = {}

        # Enrich clients table with wg show data
        known_ids = set()
        for client in clients_table:
            client_id = client.get('clientId', '')
            known_ids.add(client_id)
            if client_id in wg_show_data:
                show_data = wg_show_data[client_id]
                user_data = client.get('userData', {})
                user_data['latestHandshake'] = show_data.get('latestHandshake', '')
                user_data['dataReceived'] = show_data.get('dataReceived', '')
                user_data['dataSent'] = show_data.get('dataSent', '')
                user_data['dataReceivedBytes'] = show_data.get('dataReceivedBytes', 0)
                user_data['dataSentBytes'] = show_data.get('dataSentBytes', 0)
                user_data['allowedIps'] = show_data.get('allowedIps', '')
                client['userData'] = user_data

        # Pick up peers from conf that are NOT in clientsTable (created via native Amnezia app)
        try:
            conf_peers = self._parse_peers_from_config(protocol_type)
            for pub_key, peer_info in conf_peers.items():
                if pub_key in known_ids:
                    continue  # already in table
                show_data = wg_show_data.get(pub_key, {})
                # Derive display name from AllowedIPs (e.g. 10.8.1.5/32 -> peer-10.8.1.5)
                allowed_ip = peer_info.get('allowedIps', '') or show_data.get('allowedIps', '')
                ip_part = ''
                if allowed_ip:
                    import re as _re
                    m = _re.search(r'(\d+\.\d+\.\d+\.\d+)', allowed_ip)
                    if m:
                        ip_part = m.group(1)
                display_name = f'External ({ip_part})' if ip_part else 'External (native app)'
                clients_table.append({
                    'clientId': pub_key,
                    'userData': {
                        'clientName': display_name,
                        'clientPrivateKey': '',   # not available
                        'externalClient': True,
                        'clientIp': ip_part,
                        'latestHandshake': show_data.get('latestHandshake', ''),
                        'dataReceived': show_data.get('dataReceived', ''),
                        'dataSent': show_data.get('dataSent', ''),
                        'dataReceivedBytes': show_data.get('dataReceivedBytes', 0),
                        'dataSentBytes': show_data.get('dataSentBytes', 0),
                        'allowedIps': allowed_ip,
                    }
                })
        except Exception as e:
            logger.warning(f'get_clients: failed to parse conf peers: {e}')

        # Connection flood monitoring: attach the latest snapshot written by
        # the background collector (collect_conn_stats). Only if the snapshot
        # does not exist yet (fresh install / right after upgrade) fall back
        # to a one-off live count so the UI is not empty for the first minute.
        try:
            conn_counts = self._load_conn_counts(protocol_type)
            if not conn_counts:
                conn_counts = self._count_connections_by_ip(protocol_type)
            conn_warnings = self._load_conn_warnings(protocol_type)
            mi_state = self._load_multi_ip_state(protocol_type)
            multi_alerts = mi_state.get('alerts', {})
            sim_alerts = mi_state.get('sim', {})
            for client in clients_table:
                user_data = client.get('userData', {})
                ip = user_data.get('clientIp', '')
                if not ip:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', user_data.get('allowedIps', '') or '')
                    ip = m.group(1) if m else ''
                if not ip:
                    continue
                user_data['clientIp'] = ip
                user_data['connCount'] = conn_counts.get(ip, 0)
                if ip in conn_warnings:
                    user_data['connWarnings'] = conn_warnings[ip]
                if ip in multi_alerts:
                    user_data['multiIpAlerts'] = multi_alerts[ip]
                if ip in sim_alerts:
                    user_data['simAlerts'] = sim_alerts[ip]
                client['userData'] = user_data
        except Exception as e:
            logger.warning(f'get_clients: conn monitoring failed: {e}')

        return clients_table

    def _parse_bytes(self, size_str):
        """Parse human readable size string like '1.50 MiB' into bytes."""
        try:
            parts = size_str.strip().split()
            if len(parts) != 2: return 0
            val, unit = float(parts[0]), parts[1]
            units = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}
            return int(val * units.get(unit, 1))
        except Exception:
            return 0

    # ---- Connection flood monitoring (P2P/torrent detection) ----

    def _conn_warnings_path(self):
        """Path inside container, next to clientsTable (persisted via volume)."""
        return '/opt/amnezia/awg/conn_warnings.json'

    def _count_connections_by_ip(self, protocol_type):
        """Count conntrack entries per peer IP.

        Aggregates /proc/net/nf_conntrack INSIDE the instance container
        (NAT for the VPN subnet happens in the container's netns, so the
        host table only shows the container's own IP) and transfers only
        the compact "count ip" summary instead of the multi-megabyte raw
        table.
        Returns {ip: count}; empty dict if conntrack is unavailable.
        """
        try:
            subnet_ip = self._get_subnet_ip(protocol_type)
            cidr = int(self._get_subnet_cidr(protocol_type))
            network = ipaddress.ip_network(f'{subnet_ip}/{cidr}', strict=False)
        except Exception:
            return {}

        container = self._container_name(protocol_type)
        # tr/grep/cut pipeline instead of awk: the command travels through a
        # double remote shell (ssh + sh -c "..."), which mangles awk's $i
        # fields no matter how they are escaped. Each conntrack line has two
        # src= tokens (peer + external); the subnet filter below keeps only
        # peer IPs, so counts match the awk version.
        count_cmd = ("tr ' ' '\\n' < /proc/net/nf_conntrack 2>/dev/null "
                     "| grep '^src=' | cut -d= -f2 | sort | uniq -c")
        out, err, code = self.ssh.run_sudo_command(
            f'docker exec -i {container} sh -c "{count_cmd}"'
        )
        if code != 0 or not out.strip():
            return {}

        counts = {}
        for line in out.split('\n'):
            parts = line.split()
            if len(parts) != 2:
                continue
            cnt_s, ip = parts
            try:
                if ipaddress.ip_address(ip) in network:
                    counts[ip] = int(cnt_s)
            except ValueError:
                continue

        # Conntack keeps flows for hours/days after the peer disconnects, so
        # a raw per-IP count attributes stale entries to offline peers and
        # floods the UI with phantom warnings. Only peers with a fresh
        # handshake can actually be opening connections right now.
        live_ips = self._connected_peer_ips(protocol_type)
        if live_ips is None:
            return {}
        return {ip: cnt for ip, cnt in counts.items() if ip in live_ips}

    @staticmethod
    def _parse_handshake_age(text):
        """'1 minute, 51 seconds ago' -> 111. None when there was no handshake."""
        if not text or 'ago' not in text:
            return None
        total = 0
        for value, unit in re.findall(r'(\d+)\s+(second|minute|hour|day)', text):
            total += int(value) * {'second': 1, 'minute': 60,
                                   'hour': 3600, 'day': 86400}[unit]
        return total

    def _connected_peer_ips(self, protocol_type):
        """IPs of peers whose latest handshake is recent (awg show, in-container).

        Returns a set of IPv4 addresses, or None when liveness cannot be
        determined (tool missing, empty output) so callers skip counting
        instead of trusting stale data.
        """
        container = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f'docker exec -i {container} sh -c "awg show 2>/dev/null || wg show 2>/dev/null"'
        )
        if code != 0 or not out.strip():
            return None
        live = set()
        current_ip = None
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_ip = None
            elif line.startswith('allowed ips:'):
                first = line.split(':', 1)[1].split(',')[0].strip()
                current_ip = first.split('/')[0].strip()
            elif line.startswith('latest handshake:') and current_ip:
                age = self._parse_handshake_age(line.split(':', 1)[1].strip())
                if age is not None and age <= CONN_LIVE_HANDSHAKE_SECONDS:
                    live.add(current_ip)
        return live

    def _conn_counts_path(self):
        """Path inside container with the latest per-IP connection counts."""
        return '/opt/amnezia/awg/conn_counts.json'

    def _load_conn_counts(self, protocol_type):
        """Load latest {ip: count} snapshot written by the collector."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {self._conn_counts_path()} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return {}
        try:
            data = json.loads(out)
            return {k: int(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}

    def _save_conn_counts(self, protocol_type, counts):
        """Persist the {ip: count} snapshot into the container."""
        container_name = self._container_name(protocol_type)
        self.ssh.upload_file(json.dumps(counts), "/tmp/_amnz_conncount.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_conncount.json {container_name}:{self._conn_counts_path()}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_conncount.json")

    def collect_conn_stats(self, protocol_type, port=None, public_port=None):
        """Background collector: one cheap SSH roundtrip per instance.

        Counts conntrack entries per peer IP inside the container (compact
        awk summary, no raw table transfer), saves the snapshot and records
        flood warnings. Also runs the multi-IP (key sharing) detector and —
        when due — the simultaneous-use detector, which reads the HOST's
        conntrack table around the same awg show snapshot. Called by the
        panel's background monitor so that detection runs 24/7 even when
        nobody has the UI open.
        """
        endpoints = self._collect_peer_endpoints(protocol_type)
        try:
            self.detect_multi_ip_use(protocol_type, endpoints)
        except Exception as e:
            logger.warning(f'multi-IP detection failed: {e}')
        try:
            self.detect_simultaneous_use(protocol_type, endpoints,
                                         port=port, public_port=public_port)
        except Exception as e:
            logger.warning(f'simultaneous-use detection failed: {e}')
        counts = self._count_connections_by_ip(protocol_type)
        if not counts:
            return False
        try:
            self._save_conn_counts(protocol_type, counts)
        except Exception as e:
            logger.warning(f'failed to save conn counts: {e}')
        self._update_conn_warnings(protocol_type, counts)
        return True

    def _load_conn_warnings(self, protocol_type):
        """Load recorded warnings {ip: [{ts, count}, ...]} from the container."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {self._conn_warnings_path()} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return {}
        try:
            data = json.loads(out)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _save_conn_warnings(self, protocol_type, warnings):
        """Persist warnings into the container (same pattern as clientsTable)."""
        container_name = self._container_name(protocol_type)
        self.ssh.upload_file(json.dumps(warnings), "/tmp/_amnz_connwarn.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_connwarn.json {container_name}:{self._conn_warnings_path()}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_connwarn.json")

    def _update_conn_warnings(self, protocol_type, counts):
        """Record a warning for every peer above CONN_WARN_THRESHOLD.

        At most one warning per peer per CONN_WARN_COOLDOWN seconds; only the
        last CONN_WARN_MAX_EVENTS are kept. Returns {ip: [{ts, count}, ...]}.
        """
        warnings = self._load_conn_warnings(protocol_type)
        now = int(time.time())
        changed = False
        for ip, count in counts.items():
            if count < CONN_WARN_THRESHOLD:
                continue
            events = warnings.get(ip, [])
            if events and now - int(events[-1].get('ts', 0)) < CONN_WARN_COOLDOWN:
                continue
            events.append({'ts': now, 'count': count})
            warnings[ip] = events[-CONN_WARN_MAX_EVENTS:]
            changed = True
        if changed:
            try:
                self._save_conn_warnings(protocol_type, warnings)
            except Exception as e:
                logger.warning(f'failed to save conn warnings: {e}')
        return warnings

    def clear_conn_warnings(self, protocol_type, client_id):
        """Clear all recorded warnings for one peer: connection-flood and multi-IP."""
        clients_table = self._get_clients_table(protocol_type)
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        ip = None
        if client:
            ud = client.get('userData', {}) or {}
            ip = ud.get('clientIp')
            if not ip:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', ud.get('allowedIps', '') or '')
                ip = m.group(1) if m else None
        if not ip:
            raise RuntimeError('Client IP not found')
        warnings = self._load_conn_warnings(protocol_type)
        if ip in warnings:
            warnings.pop(ip, None)
            self._save_conn_warnings(protocol_type, warnings)
        state = self._load_multi_ip_state(protocol_type)
        changed = False
        if ip in state.get('alerts', {}):
            state['alerts'].pop(ip, None)
            changed = True
        if ip in state.get('sim', {}):
            state['sim'].pop(ip, None)
            changed = True
        if changed:
            self._save_multi_ip_state(protocol_type, state)
        return {'status': 'success', 'cleared_ip': ip}

    # ---- Multi-IP (key sharing) detection ----

    def _multi_ip_path(self):
        """Path inside container for endpoint observations + alerts."""
        return '/opt/amnezia/awg/multi_ip.json'

    def _load_multi_ip_state(self, protocol_type):
        """Load {"seen": {ip: {endpoint, ts}}, "alerts": {ip: [{ts, ips}]}}."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {self._multi_ip_path()} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return {'seen': {}, 'alerts': {}}
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data.setdefault('seen', {})
                data.setdefault('alerts', {})
                return data
        except json.JSONDecodeError:
            pass
        return {'seen': {}, 'alerts': {}}

    def _save_multi_ip_state(self, protocol_type, state):
        """Persist the multi-IP state into the container."""
        container_name = self._container_name(protocol_type)
        self.ssh.upload_file(json.dumps(state), "/tmp/_amnz_multiip.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_multiip.json {container_name}:{self._multi_ip_path()}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_multiip.json")

    def _collect_peer_endpoints(self, protocol_type):
        """Map each connected peer's tunnel IP to its current public endpoint.

        Runs 'awg show' in the container and pairs every peer's first allowed
        IP (tunnel identity, same key used elsewhere in this file) with its
        endpoint line. Peers without an endpoint (never connected) are skipped.
        Returns {tunnel_ip: endpoint_host}; empty dict when show fails.
        """
        container = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f'docker exec -i {container} sh -c "awg show 2>/dev/null || wg show 2>/dev/null"'
        )
        if code != 0 or not out.strip():
            return {}
        endpoints = {}
        current_ip = None
        pending_ep = None
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_ip = None
                pending_ep = None
            elif line.startswith('endpoint:'):
                # Comes BEFORE 'allowed ips' in wg show output: remember it
                # and pair it with the peer identity on the allowed ips line.
                ep = line.split(':', 1)[1].strip()
                if ep and ep != '(none)':
                    # Strip the port; IPv6 literals come bracketed: [::1]:51820
                    host = ep.rsplit(':', 1)[0].strip()
                    pending_ep = host.strip('[]')
            elif line.startswith('allowed ips:'):
                first = line.split(':', 1)[1].split(',')[0].strip()
                current_ip = first.split('/')[0].strip()
                if pending_ep:
                    endpoints[current_ip] = pending_ep
        return endpoints

    def detect_multi_ip_use(self, protocol_type, endpoints=None):
        """Record an alert when one key is used from 2+ public IPs at once.

        Called by the background collector next to conntrack counting. A peer
        whose endpoint IP changed while the previous endpoint was still seen
        within MULTI_IP_WINDOW seconds very likely runs the same key on 2+
        devices simultaneously. Alerts are {ts, ips} events per tunnel IP,
        deduplicated by MULTI_IP_COOLDOWN and capped at MULTI_IP_MAX_EVENTS.
        Returns True when the state file was modified.
        """
        if endpoints is None:
            endpoints = self._collect_peer_endpoints(protocol_type)
        if not endpoints:
            return False
        state = self._load_multi_ip_state(protocol_type)
        seen = state.setdefault('seen', {})
        alerts = state.setdefault('alerts', {})
        now = int(time.time())
        changed = False

        # Prune stale observations so the file stays small.
        for ip in [i for i, v in seen.items()
                   if now - int(v.get('ts', 0)) > MULTI_IP_SEEN_TTL]:
            seen.pop(ip, None)
            changed = True

        for ip, ep in endpoints.items():
            prev = seen.get(ip)
            seen[ip] = {'endpoint': ep, 'ts': now}
            if not prev:
                # First time we see this peer: persist the observation even
                # though there is nothing to alert about yet.
                changed = True
                continue
            prev_ep = prev.get('endpoint')
            if not prev_ep or prev_ep == ep:
                continue
            if now - int(prev.get('ts', 0)) > MULTI_IP_WINDOW:
                continue
            events = alerts.get(ip, [])
            if events and now - int(events[-1].get('ts', 0)) < MULTI_IP_COOLDOWN:
                # Same incident still unfolding: merge the new IP into the
                # open alert instead of spamming one event per poll round.
                merged = sorted(set(events[-1].get('ips', [])) | {prev_ep, ep})
                if merged != events[-1].get('ips'):
                    events[-1]['ips'] = merged
                    changed = True
                continue
            events.append({'ts': now, 'ips': sorted({prev_ep, ep})})
            alerts[ip] = events[-MULTI_IP_MAX_EVENTS:]
            changed = True

        if changed:
            try:
                self._save_multi_ip_state(protocol_type, state)
            except Exception as e:
                logger.warning(f'failed to save multi-IP state: {e}')
        return changed

    def _collect_outer_flows(self, ports):
        """Active UDP flows to any of the given ports on the HOST.

        Host conntrack (not the container's) carries the pre-DNAT tuples, so
        every client device is a separate flow keyed by its public
        src_ip:sport — even devices sharing one key, and even two devices
        behind the same NAT (same src_ip, different sport). Returns
        {src_ip:sport: timeout_seconds}; {} when nothing matches or the
        table is unreadable.
        """
        ports = [str(p).strip() for p in ports if str(p or '').strip()]
        if not ports:
            return {}
        pattern = '|'.join(p.replace('.', '\\.') for p in ports)
        cmd = (f"grep -E 'dport=({pattern}) ' /proc/net/nf_conntrack "
               f"2>/dev/null | grep ' udp '")
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0 or not out.strip():
            return {}
        flows = {}
        for line in out.split('\n'):
            tokens = line.split()
            if len(tokens) < 9 or tokens[2] != 'udp':
                continue
            try:
                timeout = int(tokens[4])
            except (ValueError, IndexError):
                continue
            src = sport = None
            for t in tokens[5:]:
                if t.startswith('src=') and src is None:
                    src = t.split('=', 1)[1]
                elif t.startswith('sport=') and sport is None:
                    sport = t.split('=', 1)[1]
                if src and sport:
                    break
            if src and sport:
                flows[f'{src}:{sport}'] = timeout
        return flows

    def _sim_check_due(self, protocol_type, state):
        """Sampling costs SIM_SAMPLE_GAP seconds, so it does not run for
        every instance every round: every SIM_ROUND_FULL_EVERY-th round
        covers all instances, and any instance with a recent multi-IP or
        simultaneous-use alert is re-checked every round while suspicious.
        """
        key = (getattr(self.ssh, 'host', '') or '', protocol_type)
        n = _sim_round_counters.get(key, 0) + 1
        _sim_round_counters[key] = n
        if n % SIM_ROUND_FULL_EVERY == 0:
            return True
        now = int(time.time())
        for bucket in ('alerts', 'sim'):
            for events in (state.get(bucket) or {}).values():
                for ev in events:
                    if now - int(ev.get('ts', 0)) < SIM_RECENT_ALERT:
                        return True
        return False

    def detect_simultaneous_use(self, protocol_type, endpoints=None,
                                port=None, public_port=None):
        """Record hard evidence when one key moves data from 2+ devices at
        the same time.

        Takes two conntrack samples SIM_SAMPLE_GAP (60s) apart and keeps
        flows whose timeout was refreshed (i.e. packets actually flowed)
        inside that window. Two or more active flows in BOTH samples means
        the overlap lasted at least a minute — impossible for a Wi-Fi->LTE
        handover (old flow dies within seconds, expires within 120s) and
        guaranteed while 2+ devices with PersistentKeepalive=25 share one
        key. distinct src IPs means different locations, same src IP with
        different ports means several devices behind one NAT. Attributed to
        the peer whose current endpoint is one of the active source IPs
        ('*' when unresolvable). Events are {ts, ips, sessions}, merged into
        an open event during SIM_COOLDOWN and capped at SIM_MAX_EVENTS.
        Returns True when the state file was modified.
        """
        state = self._load_multi_ip_state(protocol_type)
        if not self._sim_check_due(protocol_type, state):
            return False
        ports = [port, public_port]
        flows1 = self._collect_outer_flows(ports)
        if not flows1:
            return False
        time.sleep(SIM_SAMPLE_GAP)
        flows2 = self._collect_outer_flows(ports)
        active = sorted(k for k in flows1
                        if k in flows2
                        and flows2[k] >= flows1[k] - SIM_ACTIVE_MARGIN)
        if len(active) < 2:
            return False

        active_ips = sorted({k.rsplit(':', 1)[0] for k in active})
        if endpoints is None:
            endpoints = self._collect_peer_endpoints(protocol_type)
        owner = next((tip for tip, ep in endpoints.items()
                      if ep in active_ips), '*')

        sim = state.setdefault('sim', {})
        events = sim.get(owner, [])
        now = int(time.time())
        if events and now - int(events[-1].get('ts', 0)) < SIM_COOLDOWN:
            merged = sorted(set(events[-1].get('ips', [])) | set(active_ips))
            events[-1]['ips'] = merged
            events[-1]['sessions'] = max(int(events[-1].get('sessions', 0)),
                                         len(active))
            events[-1]['ts'] = now
        else:
            events.append({'ts': now, 'ips': active_ips,
                           'sessions': len(active)})
        sim[owner] = events[-SIM_MAX_EVENTS:]
        try:
            self._save_multi_ip_state(protocol_type, state)
        except Exception as e:
            logger.warning(f'failed to save simultaneous-use state: {e}')
        return True

    def _wg_show(self, protocol_type):
        """Run 'wg show all' and parse output."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} show all'"
        )
        if code != 0 or not out.strip():
            return {}

        result = {}
        current_peer = None

        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result[current_peer] = {}
            elif current_peer and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == 'latest handshake':
                    result[current_peer]['latestHandshake'] = value
                elif key == 'transfer':
                    parts = value.split(',')
                    if len(parts) == 2:
                        received = parts[0].strip().replace(' received', '')
                        sent = parts[1].strip().replace(' sent', '')
                        result[current_peer]['dataReceived'] = received
                        result[current_peer]['dataSent'] = sent
                        result[current_peer]['dataReceivedBytes'] = self._parse_bytes(received)
                        result[current_peer]['dataSentBytes'] = self._parse_bytes(sent)
                elif key == 'allowed ips':
                    result[current_peer]['allowedIps'] = value

        return result

    @_serialized_table_write
    def add_client(self, protocol_type, client_name, server_host, port, public_port=None):
        """
        Add a new client/peer to the AWG config.
        Returns the client config as a string for the .conf file.

        `public_port` is the port clients dial when it differs from the
        listen port (instance published on another address, port forward);
        the interface keeps listening on `port`.
        """
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)

        # Generate client keys
        client_priv_key, client_pub_key = generate_wg_keypair()

        # Get server info
        server_pub_key = self._get_server_public_key(protocol_type)
        psk = self._get_server_psk(protocol_type)

        # Get next available IP
        client_ip = self._get_next_ip(protocol_type)
        # Dual-stack: derive the client's IPv6 when the tunnel has an IPv6 gateway
        client_ipv6 = self._get_client_ipv6(protocol_type, client_ip)
        allowed_ips = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")

        # Get AWG params from server config
        awg_params = self._get_awg_params_from_config(protocol_type)

        # Add peer to server config
        peer_section = f"""
[Peer]
PublicKey = {client_pub_key}
PresharedKey = {psk}
AllowedIPs = {allowed_ips}

"""
        # Insert peer into server config, keeping peers sorted by IP (with backup)
        self._insert_peer_sorted(protocol_type, peer_section)

        # Sync config without restart
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update clients table — store keys for config reconstruction
        clients_table = self._get_clients_table(protocol_type)
        new_client = {
            'clientId': client_pub_key,
            'userData': {
                'clientName': client_name,
                'creationDate': __import__('datetime').datetime.now().isoformat(),
                'clientPrivateKey': client_priv_key,
                'clientIp': client_ip,
                'psk': psk,
                'enabled': True,
            }
        }
        if client_ipv6:
            new_client['userData']['clientIpv6'] = client_ipv6
        clients_table.append(new_client)
        self._save_clients_table(protocol_type, clients_table)

        # Build client config
        awg_params = self._get_awg_params_from_config(protocol_type)
        if awg_params.get('port'):
            port = awg_params['port']

        dns = self._get_dns(protocol_type)
        mtu = self._get_mtu(protocol_type)

        # Standard fields (dual-stack when the client has an IPv6 address)
        address_line = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
        dns6 = self._get_dns6(protocol_type) if client_ipv6 else ""
        # Guard against duplicates: a manually saved client config may
        # already carry the v6 resolver inside userData.dns.
        dns_line = dns + (", " + dns6 if dns6 and dns6 not in dns else "")
        config_lines = [
            f"Address = {address_line}",
            f"DNS = {dns_line}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        # Conditional obfuscation fields
        mapping = [
            ('junk_packet_count', 'Jc'),
            ('junk_packet_min_size', 'Jmin'),
            ('junk_packet_max_size', 'Jmax'),
            ('init_packet_junk_size', 'S1'),
            ('response_packet_junk_size', 'S2'),
            ('cookie_reply_packet_junk_size', 'S3'),
            ('transport_packet_junk_size', 'S4'),
            ('init_packet_magic_header', 'H1'),
            ('response_packet_magic_header', 'H2'),
            ('underload_packet_magic_header', 'H3'),
            ('transport_packet_magic_header', 'H4'),
            ('i1', 'I1'),
            ('i2', 'I2'),
            ('i3', 'I3'),
            ('i4', 'I4'),
            ('i5', 'I5'),
            ('cps', 'CPS')
        ] + AWG3_PARAM_MAP

        for param_key, config_key in mapping:
            val = awg_params.get(param_key)
            if val:
                # Basic compatibility filtering
                if self._base_protocol(protocol_type) == self.AWG_LEGACY and config_key in ('S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5', 'CPS') + AWG3_CONFIG_KEYS:
                    continue
                config_lines.append(f"{config_key} = {val}")

        # Always advertise both default routes in the *client* config.
        # AmneziaVPN treats AllowedIPs without ::/0 as a non-full-tunnel
        # server and disables split tunneling in the UI (#158/#193).
        # This does not assign the client an IPv6 address or enable AWG_IPV6;
        # server-side peer AllowedIPs stay IPv4-only unless client_ipv6 is set.
        peer_allowed_ips = "0.0.0.0/0, ::/0"

        client_config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = {peer_allowed_ips}
Endpoint = {server_host}:{public_port or port}
PersistentKeepalive = 25
"""

        return {
            'client_name': client_name,
            'client_id': client_pub_key,
            'client_ip': client_ip,
            'config': client_config,
        }

    def get_client_config(self, protocol_type, client_id, server_host, port, public_port=None):
        """Reconstruct client config from stored data.

        `public_port` overrides the Endpoint port the same way it does in
        add_client, so a reissued config matches the one handed out first.
        """
        clients_table = self._get_clients_table(protocol_type)
        client = None
        for c in clients_table:
            if c.get('clientId') == client_id:
                client = c
                break

        if not client:
            raise RuntimeError(f"Client {client_id} not found")

        ud = client.get('userData', {})
        if ud.get('customConfig'):
            return ud['customConfig']
        client_priv_key = ud.get('clientPrivateKey', '')
        client_ip = ud.get('clientIp', '')
        psk = ud.get('psk', '')
        # Dual-stack: use the stored IPv6 or derive it from the IPv4 address
        client_ipv6 = ud.get('clientIpv6', '') or self._get_client_ipv6(protocol_type, client_ip)

        if not client_priv_key:
            raise RuntimeError("Client private key not stored. Config cannot be reconstructed.")

        server_pub_key = self._get_server_public_key(protocol_type)
        if not psk:
            psk = self._get_server_psk(protocol_type)

        awg_params = self._get_awg_params_from_config(protocol_type)
        if awg_params.get('port'):
            port = awg_params['port']

        dns = self._get_dns(protocol_type, ud)
        mtu = self._get_mtu(protocol_type, ud)

        # Standard fields (dual-stack when the client has an IPv6 address)
        address_line = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
        dns6 = self._get_dns6(protocol_type, ud) if client_ipv6 else ""
        # Guard against duplicates: a manually saved client config may
        # already carry the v6 resolver inside userData.dns.
        dns_line = dns + (", " + dns6 if dns6 and dns6 not in dns else "")
        config_lines = [
            f"Address = {address_line}",
            f"DNS = {dns_line}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        # Conditional obfuscation fields
        mapping = [
            ('junk_packet_count', 'Jc'),
            ('junk_packet_min_size', 'Jmin'),
            ('junk_packet_max_size', 'Jmax'),
            ('init_packet_junk_size', 'S1'),
            ('response_packet_junk_size', 'S2'),
            ('cookie_reply_packet_junk_size', 'S3'),
            ('transport_packet_junk_size', 'S4'),
            ('init_packet_magic_header', 'H1'),
            ('response_packet_magic_header', 'H2'),
            ('underload_packet_magic_header', 'H3'),
            ('transport_packet_magic_header', 'H4'),
            ('i1', 'I1'),
            ('i2', 'I2'),
            ('i3', 'I3'),
            ('i4', 'I4'),
            ('i5', 'I5'),
            ('cps', 'CPS')
        ] + AWG3_PARAM_MAP

        for param_key, config_key in mapping:
            val = awg_params.get(param_key)
            if val:
                # Basic compatibility filtering
                if self._base_protocol(protocol_type) == self.AWG_LEGACY and config_key in ('S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5', 'CPS') + AWG3_CONFIG_KEYS:
                    continue
                config_lines.append(f"{config_key} = {val}")

        # See the client-creation path: always include ::/0 for Amnezia split tunneling.
        peer_allowed_ips = "0.0.0.0/0, ::/0"

        config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = {peer_allowed_ips}
Endpoint = {server_host}:{public_port or port}
PersistentKeepalive = 25
"""
        return config

    @_serialized_table_write
    def toggle_client(self, protocol_type, client_id, enable):
        """Enable or disable a client by adding/removing their [Peer] from server config."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)
        clients_table = self._get_clients_table(protocol_type)
        table_changed = False

        if enable:
            # Restore native addresses without silently replacing issued configs.
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if not client:
                raise RuntimeError(f"Client {client_id} not found")

            ud = client.setdefault('userData', {})
            psk = ud.get('psk', '')
            addresses = self._client_ipv4_addresses(ud)
            if len(addresses) > 1:
                raise RuntimeError('Cannot enable client: IP address is ambiguous; resolve it manually')
            client_ip = next(iter(addresses)) if addresses else ''
            if not client_ip:
                if not ud.get('clientPrivateKey') or any(
                        ud.get(k) for k in ('clientIp', 'allowedIps', 'allowed_ip', 'allowed_ips')):
                    raise RuntimeError('Cannot enable client: IP address is unavailable; cannot safely reassign it')
                # Legacy panel clients can still receive a new configuration.
                client_ip = self._get_next_ip(protocol_type)

            # Validate before any config, metadata, or live-interface mutation.
            # A fresh read reduces stale-cache conflicts, but is not a transaction
            # with the official app or another panel process.
            self._invalidate_config_cache(protocol_type)
            for other in clients_table:
                if other.get('clientId') == client_id:
                    continue
                if client_ip in self._client_ipv4_addresses(other.get('userData') or {}):
                    raise RuntimeError(
                        f'Cannot enable client: IP {client_ip} is occupied by another reservation; '
                        'resolve the conflict manually')
            if client_ip in self._get_used_ips(protocol_type):
                raise RuntimeError(
                    f'Cannot enable client: IP {client_ip} is occupied in the active server config; '
                    'resolve the conflict manually')

            ud['clientIp'] = client_ip
            client_ipv6 = ud.get('clientIpv6', '') or self._get_client_ipv6(protocol_type, client_ip)
            allowed_ips = f'{client_ip}/32' + (f', {client_ipv6}/128' if client_ipv6 else '')
            ud['allowedIps'] = allowed_ips
            if client_ipv6:
                ud['clientIpv6'] = client_ipv6
            table_changed = True

            if 'psk' not in ud:
                if not ud.get('clientPrivateKey'):
                    raise RuntimeError(
                        'Cannot enable client: preshared key (PSK) is unknown; '
                        'restore the original key or explicitly record no PSK')
                # Only legacy panel-generated clients used the global PSK.
                psk = self._get_server_psk(protocol_type)
                ud['psk'] = psk
                table_changed = True

            psk_line = f'PresharedKey = {psk}\n' if psk else ''
            peer_section = (
                f'\n[Peer]\nPublicKey = {client_id}\n'
                f'{psk_line}AllowedIPs = {allowed_ips}\n\n'
            )
            self._insert_peer_sorted(protocol_type, peer_section)
            self._invalidate_config_cache(protocol_type)
        else:
            # Remove peer from server config, but first persist its current
            # AllowedIPs so native/external clients can be enabled later.
            config = self._get_server_config(protocol_type)
            conf_peers = self._parse_peers_from_config(protocol_type)
            allowed_ips = conf_peers.get(client_id, {}).get('allowedIps', '')
            client_ip = self._extract_ipv4(allowed_ips)
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if client is None:
                client = {
                    'clientId': client_id,
                    'userData': {
                        'clientName': f'External ({client_ip})' if client_ip else 'External (native app)',
                        'externalClient': True,
                    }
                }
                clients_table.append(client)
                table_changed = True

            ud = client.setdefault('userData', {})
            if client_ip:
                ud['clientIp'] = client_ip
                ud['allowedIps'] = allowed_ips or f'{client_ip}/32'
                table_changed = True
            for block in config.split('[Peer]')[1:]:
                key = re.search(r'^\s*PublicKey\s*=\s*(\S+)', block, re.MULTILINE)
                if key and key.group(1) == client_id:
                    saved_psk = re.search(
                        r'^[ \t]*PresharedKey[ \t]*=[ \t]*([^\s#]+)', block, re.MULTILINE)
                    # An observed peer without a PSK is known no-PSK mode,
                    # not missing metadata eligible for the global fallback.
                    ud['psk'] = saved_psk.group(1) if saved_psk else ''
                    table_changed = True
                    break

            sections = config.split('[')
            new_sections = []
            for section in sections:
                if not section.strip():
                    continue
                if client_id in section:
                    continue
                new_sections.append(section)

            new_config = '[' + '['.join(new_sections)
            self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
            self.ssh.run_sudo_command(
                f"docker cp /tmp/_amnz_config.conf {container_name}:{config_path}"
            )
            self.ssh.run_command("rm -f /tmp/_amnz_config.conf")
            self._invalidate_config_cache(protocol_type)

        # Sync config
        _, sync_err, sync_code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )
        if sync_code != 0:
            # A failed sync with an already-updated clients table is exactly
            # how a peer ends up half-toggled (working in wg but shown off, or
            # vice versa) — refuse to persist the new state instead.
            raise RuntimeError(
                f"syncconf failed for {container_name} (exit {sync_code}): "
                f"{sync_err or 'no output'}. The clients table was NOT updated; "
                f"retry the toggle.")

        # Verify the toggle actually landed before persisting enabled=... .
        # Read the config DIRECTLY from the container — not via
        # _get_server_config, which may consume a freshly prefetched batch
        # (built a request-moment ago) and misjudge the peer's presence.
        # Rapid successive toggles (two requests racing the same config file)
        # can make the first read-back see a pre-write state: retry a couple
        # of times on a presence mismatch before raising.
        self._invalidate_config_cache(protocol_type)
        peer_present = None
        for attempt in range(3):
            applied_config, _, vcode = self.ssh.run_sudo_command(
                f"docker exec -i {container_name} cat {config_path}")
            if vcode != 0 or not (applied_config or '').strip():
                # Unreadable config must not be mistaken for a successful toggle.
                if attempt == 2:
                    raise RuntimeError(
                        f"Could not read back {container_name} config after syncconf "
                        f"— NOT updating the clients table (verification impossible).")
                time.sleep(0.6)
                continue
            peer_present = client_id in applied_config
            if peer_present == enable:
                break
            if attempt < 2:
                time.sleep(0.6)
        if enable and not peer_present:
            raise RuntimeError(
                f"Peer {client_id[:12]}... is absent from {container_name} "
                f"config right after enable — NOT updating the clients table "
                f"(the enable did not land). Investigate the container state.")
        if not enable and peer_present:
            raise RuntimeError(
                f"Peer {client_id[:12]}... is still present in "
                f"{container_name} config right after disable — NOT marking "
                f"it disabled in the clients table (a half-applied disable "
                f"once left a working peer shown as off and un-re-enablable).")

        # Update enabled status in clients table
        for c in clients_table:
            if c.get('clientId') == client_id:
                c.setdefault('userData', {})['enabled'] = enable
                table_changed = True
                break
        if table_changed:
            self._save_clients_table(protocol_type, clients_table)

    @_serialized_table_write
    def remove_client(self, protocol_type, client_id):
        """Remove a client from AWG config (mirrors revokeWireGuard)."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)

        # Get current config
        config = self._get_server_config(protocol_type)

        # Split by [Peer] sections and remove the matching one
        sections = config.split('[')
        new_sections = []
        for section in sections:
            if not section.strip():
                continue
            if client_id in section:
                continue
            new_sections.append(section)

        new_config = '[' + '['.join(new_sections)

        # Upload new config into container via SFTP + docker cp
        self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_config.conf {container_name}:{config_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_config.conf")
        self._invalidate_config_cache(protocol_type)

        # Sync config
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update clients table
        clients_table = self._get_clients_table(protocol_type)
        clients_table = [c for c in clients_table if c.get('clientId') != client_id]
        self._save_clients_table(protocol_type, clients_table)

        return True

    def _default_dns(self):
        """Fallback DNS pair: the AmneziaDNS container when it is installed,
        otherwise the built-in resolvers."""
        dns1 = AWG_DEFAULTS['dns1']
        dns2 = AWG_DEFAULTS['dns2']
        try:
            out, _, _ = self.ssh.run_sudo_command(
                "docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'"
            )
            if 'amnezia-dns' in out:
                dns1 = '172.29.172.254'
        except Exception:
            pass
        return f"{dns1}, {dns2}"

    def _read_config_key(self, protocol_type, key):
        """Read a key from the server config, comment or not.

        MTU and DNS are stored commented out on purpose (see
        _configure_container), so both forms have to be accepted.
        """
        try:
            server_config = self._get_server_config(protocol_type)
        except Exception:
            return None
        for line in server_config.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#'):
                stripped = stripped.lstrip('#').strip()
            if '=' not in stripped:
                continue
            name, _, value = stripped.partition('=')
            if name.strip() == key:
                value = value.strip()
                if value:
                    return value
        return None

    def _get_dns(self, protocol_type, user_data=None):
        """DNS servers for generated client configs.

        Priority: per-client override (userData.dns, set by saving an edited
        config) > `DNS = ...` line in the server config (wg-quick-style key,
        stripped by awg-quick so it does not affect syncconf) > AmneziaDNS
        container address > built-in defaults.
        """
        if user_data and user_data.get('dns'):
            return user_data['dns']
        return self._read_config_key(protocol_type, 'DNS') or self._default_dns()

    def _get_dns6(self, protocol_type, user_data=None):
        """IPv6 DNS appended to client configs on dual-stack tunnels.

        Priority: per-client override (userData.dns6) > `# DNS6 = ...` line in
        the server config (written at install when IPv6 is enabled) > built-in
        default (Cloudflare v6)."""
        if user_data and user_data.get('dns6'):
            return user_data['dns6']
        return self._read_config_key(protocol_type, 'DNS6') or AWG_DEFAULTS['dns6']

    def get_awg_settings(self, protocol_type):
        """Client-facing AWG settings currently stored in the server config."""
        params = self._get_awg_params_from_config(protocol_type)
        link_info = self.exit_link_info(protocol_type)
        settings = {
            'mtu': self._get_mtu(protocol_type),
            'dns': self._get_dns(protocol_type),
            'dns6': self._get_dns6(protocol_type),
            'default_i1': AWG_DEFAULT_I1,
            'supports_special_junk': self._base_protocol(protocol_type) != self.AWG_LEGACY,
            # an instance behind an exit link cannot carry more than the link
            'exit_linked': bool(link_info),
            'exit_mtu': EXIT_MTU,
            # What the current obfuscation costs per packet, so the UI can
            # flag an MTU that cannot fit a standard 1500-byte link.
            'safe_mtu': safe_client_mtu(params),
            'transport_overhead': transport_overhead(params),
        }
        for key in SPECIAL_JUNK_KEYS:
            settings[key] = params.get(key, '')
        return settings

    def update_awg_settings(self, protocol_type, mtu=None, dns=None, special_junk=None, dns6=None):
        """Rewrite MTU/DNS/I1-I5 in the server config and apply them live.

        I1-I5 go to the kernel through `awg syncconf`, so peers stay up; MTU
        and DNS only matter when a client config is generated. Existing
        clients pick the new values up on their next config export -- the
        config they already imported keeps the old ones.
        """
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            special_junk = None
        junk = normalize_special_junk(special_junk) if special_junk is not None else None

        current_junk = self._get_awg_params_from_config(protocol_type)
        config = self._get_server_config(protocol_type)
        lines = config.split('\n')

        def key_of(line):
            stripped = line.strip()
            if stripped.startswith('#'):
                stripped = stripped.lstrip('#').strip()
            if '=' not in stripped:
                return None
            return stripped.partition('=')[0].strip()

        # A None means "leave this alone"; an empty string means "clear it",
        # which drops the line so the built-in default applies again.
        replaced = {}
        if mtu is not None:
            value = str(mtu).strip()
            replaced['MTU'] = f"# MTU = {value}" if value else None
        if dns is not None:
            value = str(dns).strip()
            replaced['DNS'] = f"# DNS = {value}" if value else None
        if dns6 is not None:
            value = str(dns6).strip()
            replaced['DNS6'] = f"# DNS6 = {value}" if value else None
        if junk is not None:
            for key in SPECIAL_JUNK_KEYS:
                value = junk.get(key)
                replaced[key.upper()] = f"{key.upper()} = {value}" if value else None

        # Everything lives in [Interface]; drop the old occurrences first so a
        # cleared field really disappears instead of being shadowed.
        interface_end = len(lines)
        for idx, line in enumerate(lines):
            if idx and line.strip().startswith('['):
                interface_end = idx
                break

        head = [line for line in lines[:interface_end] if key_of(line) not in replaced]
        while head and not head[-1].strip():
            head.pop()
        head.extend(value for value in replaced.values() if value)

        tail = lines[interface_end:]
        if tail:
            head.append('')  # keep [Interface] and [Peer] visually apart
        self._write_server_config(protocol_type, '\n'.join(head + tail))

        if junk is not None:
            # There is no way to spell an empty I1-I5 in a config file
            # (get_value in amneziawg-tools rejects `I1 =`), so a dropped
            # packet cannot be pushed through syncconf -- the kernel would
            # keep sending the old one. Recreating the interface is the only
            # way to make a removal take effect.
            dropped = any(current_junk.get(key) and not junk.get(key)
                          for key in SPECIAL_JUNK_KEYS)
            if dropped:
                self._restart_container(protocol_type)
            else:
                self._sync_server_config(protocol_type)
        return self.get_awg_settings(protocol_type)

    def _write_server_config(self, protocol_type, config_content):
        """Upload the server config into the container without restarting it."""
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        self.ssh.upload_file(config_content.replace('\r\n', '\n'), "/tmp/_amnz_settings.conf")
        out, err, code = self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_settings.conf {container_name}:{config_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_settings.conf")
        self._invalidate_config_cache(protocol_type)
        if code != 0:
            raise RuntimeError(f"Failed to write server config: {err or out}")

    def _restart_container(self, protocol_type):
        """Restart the container so its start script recreates the interface."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(f"docker restart {container_name}")
        if code != 0:
            raise RuntimeError(f"Failed to restart {container_name}: {err or out}")

    def _sync_server_config(self, protocol_type):
        """Apply the on-disk server config to the running interface."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c "
            f"'{wg_bin} syncconf {iface} <({quick_bin} strip {config_path})'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to apply config: {err or out}")

    def _get_mtu(self, protocol_type, user_data=None):
        """MTU for generated client configs.

        Priority: per-client override > `MTU = ...` line in the server config
        > built-in default. Amnezia's own clients use 1376; the 1280 this
        panel used to hardcode is itself a usable fingerprint.
        """
        if user_data and user_data.get('mtu'):
            return str(user_data['mtu'])
        return self._read_config_key(protocol_type, 'MTU') or AWG_DEFAULTS['mtu']

    @_serialized_table_write
    def save_client_config(self, protocol_type, client_id, config_text):
        """Persist a manually edited client config. Stored verbatim in
        clientsTable (userData.customConfig) and returned by get_client_config
        from now on; the DNS and MTU lines are indexed into userData as the
        per-client overrides _get_dns/_get_mtu read on future regenerations."""
        config_text = (config_text or '').strip()
        if not config_text:
            raise RuntimeError('Config is empty')
        clients_table = self._get_clients_table(protocol_type)
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        if client is None:
            raise RuntimeError('Client not found')
        ud = client.setdefault('userData', {})
        ud['customConfig'] = config_text
        ud.pop('dns', None)
        ud.pop('mtu', None)
        indexed = {'DNS': 'dns', 'MTU': 'mtu'}
        for line in config_text.split('\n'):
            stripped = line.strip()
            if stripped.startswith('#') or '=' not in stripped:
                continue
            name, _, value = stripped.partition('=')
            field = indexed.get(name.strip())
            if field and value.strip():
                ud[field] = value.strip()
        self._save_clients_table(protocol_type, clients_table)
        return {'status': 'success'}

    @_serialized_table_write
    def rename_client(self, protocol_type, client_id, new_name):
        """Rename a client. The name lives only in the clientsTable
        (userData.clientName); keys, IPs and the WireGuard config itself
        are untouched, so existing configs keep working."""
        clients_table = self._get_clients_table(protocol_type)
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        if client is None:
            # Peer added via the native Amnezia app is not in the table yet —
            # persist a minimal entry so the chosen name sticks.
            conf_peers = self._parse_peers_from_config(protocol_type)
            if client_id not in conf_peers:
                raise RuntimeError('Client not found')
            client = {
                'clientId': client_id,
                'userData': {
                    'clientName': new_name,
                    'clientPrivateKey': '',
                    'externalClient': True,
                }
            }
            clients_table.append(client)
        else:
            client.setdefault('userData', {})['clientName'] = new_name
        self._save_clients_table(protocol_type, clients_table)
        return {'status': 'success', 'name': new_name}

    def get_server_status(self, protocol_type):
        """Get detailed status of the AWG server."""
        container_name = self._container_name(protocol_type)

        info = {
            'container_exists': self.check_protocol_installed(protocol_type),
            'container_running': False,
            'protocol': protocol_type,
        }

        if info['container_exists']:
            info['container_running'] = self.check_container_running(protocol_type)

            if info['container_running']:
                try:
                    config = self._get_server_config(protocol_type)
                    # Extract port
                    for line in config.split('\n'):
                        if 'ListenPort' in line:
                            info['port'] = line.split('=')[1].strip()
                            break
                    info['awg_params'] = self._get_awg_params_from_config(protocol_type)
                    # The official Amnezia client installs AWG 3.x into the
                    # amnezia-awg2 container, so only the config tells 2.0 and 3.x apart.
                    info['header_protection'] = bool(info['awg_params'].get('header_protection_key'))
                    # Count ALL peers, not only clientsTable rows: peers that
                    # exist in awg0.conf but not in the table (shown as
                    # 'External' in the list) are still real connections.
                    known = {c.get('clientId')
                             for c in self._get_clients_table(protocol_type)}
                    conf_peers = self._parse_peers_from_config(protocol_type)
                    info['clients_count'] = len(known | set(conf_peers))
                    info['external_count'] = len(set(conf_peers) - known)
                except Exception as e:
                    info['error'] = str(e)

        return info
