"""Generation and parsing of the AWG 'special junk' packets (I1-I5).

I1 is the packet an initiating peer sends right before its handshake, so a
session opens with bytes that belong to another protocol. The Amnezia
desktop client ships a fixed DNS response for ``icloud.com`` as its default
(42 of the 44 bytes are constant), which means every instance that keeps that
default emits a byte-identical first packet.

This module builds a valid DNS answer for a chosen domain, with the address
taken from that domain's own address pool, so each instance (and each client
config) can carry its own packet instead of a shared fingerprint.

Only tags understood by BOTH implementations are produced here: amneziawg-go
(``device/obf.go``) and the kernel module (``src/junk.c``). ``<c>`` exists in
the kernel module only, ``d/ds/dz`` in the Go implementation only, so none of
them can be used in a config that has to work for every client.
"""

import ipaddress
import random
import re
import struct
# Byte-identical to protocols::awg::defaultSpecialJunk1 in the desktop client:
# a DNS response for icloud.com (address 77.88.55.55 belongs to Yandex)
# preceded by a random 2-byte transaction id.
DEFAULT_I1 = (
    '<r 2><b 0x858000010001000000000669636c6f756403636f6d'
    '0000010001c00c000100010000105a00044d583737>'
)

# Address pools. Every entry is the real allocation of the domain's operator,
# so a generated answer does not mix a domain with an address from a foreign
# network. "slots" lists the octets that may vary: (position, min, max).
DOMAIN_POOLS = {
    'icloud.com': {
        'cidr': '17.0.0.0/8',
        'owner': 'Apple',
        'slots': ((0, 17, 17), (1, 0, 255), (2, 0, 255), (3, 1, 254)),
    },
    'gateway.icloud.com': {
        'cidr': '17.0.0.0/8',
        'owner': 'Apple',
        'slots': ((0, 17, 17), (1, 0, 255), (2, 0, 255), (3, 1, 254)),
    },
    'push.apple.com': {
        'cidr': '17.0.0.0/8',
        'owner': 'Apple',
        'slots': ((0, 17, 17), (1, 0, 255), (2, 0, 255), (3, 1, 254)),
    },
    'captive.apple.com': {
        'cidr': '17.0.0.0/8',
        'owner': 'Apple',
        'slots': ((0, 17, 17), (1, 0, 255), (2, 0, 255), (3, 1, 254)),
    },
    'www.google.com': {
        'cidr': '142.250.0.0/15',
        'owner': 'Google',
        'slots': ((0, 142, 142), (1, 250, 251), (2, 0, 255), (3, 1, 254)),
    },
    'connectivitycheck.gstatic.com': {
        'cidr': '142.250.0.0/15',
        'owner': 'Google',
        'slots': ((0, 142, 142), (1, 250, 251), (2, 0, 255), (3, 1, 254)),
    },
    'mtalk.google.com': {
        'cidr': '142.250.0.0/15',
        'owner': 'Google',
        'slots': ((0, 142, 142), (1, 250, 251), (2, 0, 255), (3, 1, 254)),
    },
    'cloudflare.com': {
        'cidr': '104.16.0.0/13',
        'owner': 'Cloudflare',
        'slots': ((0, 104, 104), (1, 16, 23), (2, 0, 255), (3, 1, 254)),
    },
    'yandex.ru': {
        'cidr': '77.88.0.0/18',
        'owner': 'Yandex',
        'slots': ((0, 77, 77), (1, 88, 88), (2, 0, 63), (3, 1, 254)),
    },
    'web.telegram.org': {
        'cidr': '149.154.160.0/20',
        'owner': 'Telegram',
        'slots': ((0, 149, 149), (1, 154, 154), (2, 160, 175), (3, 1, 254)),
    },
    'www.microsoft.com': {
        'cidr': '20.0.0.0/8',
        'owner': 'Microsoft',
        'slots': ((0, 20, 20), (1, 1, 255), (2, 0, 255), (3, 1, 254)),
    },
    'www.msftconnecttest.com': {
        'cidr': '20.0.0.0/8',
        'owner': 'Microsoft',
        'slots': ((0, 20, 20), (1, 1, 255), (2, 0, 255), (3, 1, 254)),
    },
    'github.com': {
        'cidr': '140.82.112.0/20',
        'owner': 'GitHub',
        'slots': ((0, 140, 140), (1, 82, 82), (2, 112, 127), (3, 1, 254)),
    },
}

# Optional "which device is the key for" presets. Purely a convenience: it
# narrows the domain list, it is not a promise that the packet matches the
# device. "any" is the default and mixes every pool.
DEVICE_PROFILES = (
    ('any', ('icloud.com', 'www.google.com', 'cloudflare.com', 'www.microsoft.com',
             'github.com', 'web.telegram.org', 'yandex.ru')),
    ('apple', ('icloud.com', 'gateway.icloud.com', 'push.apple.com', 'captive.apple.com')),
    ('windows', ('www.microsoft.com', 'www.msftconnecttest.com')),
    ('android', ('www.google.com', 'connectivitycheck.gstatic.com', 'mtalk.google.com')),
    ('linux', ('cloudflare.com', 'github.com', 'yandex.ru')),
)

PROFILE_KEYS = tuple(key for key, _ in DEVICE_PROFILES)

MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63

_TAG_RE = re.compile(r'<\s*([a-z]+)(?:\s+([^>]*?))?\s*>')


def is_valid_domain(domain):
    """Whether a string is a plausible DNS name (no scheme, no spaces)."""
    text = (domain or '').strip().lower()
    if not text or len(text) > MAX_DOMAIN_LEN or text.endswith('.'):
        return False
    labels = text.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > MAX_LABEL_LEN:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False
        # ASCII only: the answer is encoded byte by byte, and a homograph
        # label (Cyrillic "і" for Latin "i") would either crash the encoder or
        # build a packet no resolver would ever emit.
        if not all(ch.isascii() and (ch.isalnum() or ch == '-') for ch in label):
            return False
    return labels[-1].isalpha()


def profile_domains(profile=None):
    """Domains offered by a device preset ('any' when unknown)."""
    key = (profile or 'any').strip().lower()
    for name, domains in DEVICE_PROFILES:
        if name == key:
            return domains
    return DEVICE_PROFILES[0][1]


def _slots_to_ip(slots, rng):
    octets = [0, 0, 0, 0]
    for index, low, high in slots:
        octets[index] = rng.randint(low, high)
    return tuple(octets)


def random_ip(domain, rng=None):
    """Pick an address from the pool that belongs to the domain's operator."""
    rng = rng or random
    pool = DOMAIN_POOLS.get((domain or '').strip().lower())
    if pool is None:
        raise ValueError(f"no address pool for {domain!r}")
    return _slots_to_ip(pool['slots'], rng)


def pool_for(domain):
    """Pool metadata of a known domain, or None."""
    return DOMAIN_POOLS.get((domain or '').strip().lower())


def _dns_answer(domain, ip, ttl, flags, rng):
    """Build a DNS response for an A record, as the bytes after the id."""
    body = bytearray()
    body += struct.pack('>HHHHH', flags, 1, 1, 0, 0)
    for label in domain.split('.'):
        body.append(len(label))
        body += label.encode('ascii')
    body.append(0)
    body += struct.pack('>HH', 1, 1)          # QTYPE A, QCLASS IN
    body += b'\xc0\x0c'                       # name -> question name
    body += struct.pack('>HHIH', 1, 1, ttl, 4)
    body += bytes(ip)
    return bytes(body)


def generate_i1(domain=None, pool=None, rng=None):
    """Build a fresh I1 value: a valid DNS answer with a random address.

    domain -- the name inside the answer; None picks one at random from
              every known pool.
    pool   -- address pool to use when the domain is custom (not in
              DOMAIN_POOLS). Without it a custom domain cannot be made
              plausible, so ValueError is raised.
    """
    rng = rng or random
    name = (domain or '').strip().lower()
    if not name:
        name = rng.choice(sorted(DOMAIN_POOLS))
    if not is_valid_domain(name):
        raise ValueError(f"not a domain name: {domain!r}")

    pool_name = (pool or '').strip().lower()
    if pool_name and pool_name not in DOMAIN_POOLS:
        raise ValueError(f"unknown address pool: {pool!r}")
    ip = random_ip(name, rng) if name in DOMAIN_POOLS else random_ip(pool_name, rng)

    ttl = rng.randint(60, 86400)
    flags = rng.choice((0x8180, 0x8580))
    body = _dns_answer(name, ip, ttl, flags, rng)
    return '<r 2><b 0x' + body.hex().upper() + '>'


def tags_to_bytes(value, rng=None):
    """Expand a tag string into the bytes that go on the wire.

    Random tags are filled with zeros: the result is only used for parsing
    and size checks, never sent anywhere.
    """
    rng = rng or random
    out = bytearray()
    for match in _TAG_RE.finditer(value or ''):
        tag = match.group(1)
        arg = (match.group(2) or '').strip()
        if tag == 'b':
            if arg[:2].lower() != '0x':
                raise ValueError("<b> expects hex bytes, e.g. <b 0xdeadbeef>")
            out += bytes.fromhex(arg[2:])
        elif tag in ('r', 'rc', 'rd'):
            out += bytes(int(arg))
        elif tag == 't':
            out += b'\x00\x00\x00\x00'
        else:
            raise ValueError(f"unsupported tag <{tag}>")
    return bytes(out)


def _tag_size(value):
    """Wire size of a tag string, counting random parts as their full length."""
    total = 0
    for match in _TAG_RE.finditer(value or ''):
        tag = match.group(1)
        arg = (match.group(2) or '').strip()
        if tag == 'b':
            if arg[:2].lower() != '0x':
                raise ValueError("<b> expects hex bytes, e.g. <b 0xdeadbeef>")
            total += len(arg[2:]) // 2
        elif tag in ('r', 'rc', 'rd'):
            total += int(arg)
        elif tag == 't':
            total += 4
    return total


def _read_name(data, offset):
    labels = []
    while offset < len(data) and data[offset]:
        length = data[offset]
        if length > MAX_LABEL_LEN or offset + 1 + length > len(data):
            return None, offset
        labels.append(data[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
        offset += length + 1
    if not labels:
        return None, offset
    return '.'.join(labels), offset + 1


def _decode_dns(data, start, size):
    """Decode a DNS answer starting at ``start``; None when it is not one."""
    if len(data) < start + 12:
        return None
    try:
        flags, qdcount, ancount = struct.unpack('>HHH', data[start + 2:start + 8])
        domain, offset = _read_name(data, start + 12)
        if not domain or qdcount < 1:
            return None
        qtype, _qclass = struct.unpack('>HH', data[offset:offset + 4])
        offset += 4
        if qtype != 1 or ancount < 1 or data[offset:offset + 2] != b'\xc0\x0c':
            return None
        offset += 2
        _atype, _aclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        if rdlen != 4 or offset + 4 > len(data):
            return None
        ip = ipaddress.IPv4Address(data[offset:offset + 4])
    except (struct.error, IndexError, UnicodeDecodeError, ValueError):
        return None
    pool = DOMAIN_POOLS.get(domain.lower())
    owner = None
    if pool is not None:
        try:
            if ip in ipaddress.ip_network(pool['cidr']):
                owner = pool['owner']
        except ValueError:
            owner = None
    return {
        'domain': domain,
        'ip': str(ip),
        'ttl': ttl,
        'flags': flags,
        'size': size,
        'owner': owner,
        'in_pool': owner is not None,
    }


def parse_i1(value):
    """Decode an I1 value into its DNS fields, or None when it is not a DNS answer.

    Returns {'domain', 'ip', 'ttl', 'flags', 'size', 'owner', 'default'}.
    Random tags are decoded as zeros; only structure and literals matter here.
    """
    text = (value or '').strip()
    if not text:
        return None
    try:
        data = tags_to_bytes(text)
        size = _tag_size(text)
    except (ValueError, TypeError):
        return None
    if size < 12 or len(data) < 12:
        return None
    # The generated packet starts with a 2-byte random id, a hand-written one
    # may include the id in <b>: try both shapes instead of assuming one.
    for start in (2, 0):
        parsed = _decode_dns(data, start, size)
        if parsed is not None:
            parsed['default'] = normalize_i1(text) == normalize_i1(DEFAULT_I1)
            return parsed
    return None


def normalize_i1(value):
    """Case- and whitespace-insensitive form used to compare two values."""
    return ''.join((value or '').split()).lower()


def is_legacy_default(value):
    """Whether a value is byte-identical to the client's public default."""
    text = (value or '').strip()
    if not text:
        return False
    if normalize_i1(text) == normalize_i1(DEFAULT_I1):
        return True
    try:
        # A hand-written <b 0x...> packet carries the same bytes even though the
        # literal differs; random tags decode as zeros on both sides.
        return tags_to_bytes(text) == tags_to_bytes(DEFAULT_I1)
    except (ValueError, TypeError):
        return False


def catalog():
    """Domains and pools, for the panel's domain picker."""
    result = []
    for domain in sorted(DOMAIN_POOLS):
        pool = DOMAIN_POOLS[domain]
        profiles = [key for key, domains in DEVICE_PROFILES if domain in domains]
        result.append({
            'domain': domain,
            'cidr': pool['cidr'],
            'owner': pool['owner'],
            'profiles': profiles,
        })
    return result
