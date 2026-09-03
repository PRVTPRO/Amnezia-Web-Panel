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
CONN_WARN_THRESHOLD = 600    # simultaneous connections per peer that trigger a warning
CONN_WARN_COOLDOWN = 3600    # min seconds between two recorded warnings for the same peer
CONN_WARN_MAX_EVENTS = 5     # how many recent warnings are kept per peer


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

    jc = random.randint(1, 10)
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
        # Use ^name$ for exact match (Docker name filter does substring match)
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{container_name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self, protocol_type):
        """Check if protocol is installed (container exists)."""
        container_name = self._container_name(protocol_type)
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{container_name}$ --format '{{{{.Names}}}}'"
        )
        # Exact match check
        return container_name in out.strip().split('\n')

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
# daemon.json is merged (not overwritten), backed up, docker restarted
# only when the file actually changed.
if ip -6 -o addr show scope global 2>/dev/null | grep -q inet6; then
  cp /etc/docker/daemon.json /etc/docker/daemon.json.bak.awp 2>/dev/null
  python3 - <<'PYEOF' 2>/dev/null || (grep -q '"ipv6"' /etc/docker/daemon.json 2>/dev/null || (echo '{{"ipv6": true, "fixed-cidr-v6": "fd00:42::/64", "experimental": true, "ip6tables": true}}' > /etc/docker/daemon.json && systemctl restart docker))
import json, os, subprocess
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
    subprocess.run(['systemctl', 'restart', 'docker'], check=False)
PYEOF
fi
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            logger.warning(f"prepare_host warning: {err}")
        return True

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
for c in $(docker ps -a --format '{{.Names}}' | grep '^amnezia-awg' | sort); do
  echo "CT_NAME=$c"
  if docker ps --format '{{.Names}}' | grep -qx "$c"; then
    echo "CT_RUNNING=1"
    docker exec "$c" sh -c 'for p in net.core.rmem_max net.core.wmem_max net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing; do echo "CTK_$p=$(sysctl -n $p 2>/dev/null)"; done; echo "CTK_nofile=$(ulimit -n)"' 2>/dev/null
  else
    echo "CT_RUNNING=0"
  fi
done
"""
        out, err, code = self.ssh.run_sudo_command(script, timeout=60)
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
                         mtu=None, dns=None, special_junk=None):
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

        mtu = str(mtu or AWG_DEFAULTS['mtu']).strip()
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
        self.prepare_host(protocol_type)
        results.append("Host prepared")

        # Step 3: Remove old container if exists
        if self.check_protocol_installed(protocol_type):
            results.append("Removing old container...")
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

        # Create Dockerfile - matches original from client/server_scripts/awg/
        dockerfile_content = (
            f"FROM {docker_image}\n"
            f"\n"
            f'LABEL maintainer="AmneziaVPN"\n'
            f"\n"
            f"RUN apk add --no-cache bash curl dumb-init iptables\n"
            f"RUN apk --update upgrade --no-cache\n"
            f"\n"
            # Only the AWG images ship awg-quick; the legacy one runs wg-quick
            # against the plain WireGuard module, which has nothing to fall
            # back to.
            f"{AWG_QUICK_FORCE_USERSPACE_PATCH if base_proto in (self.AWG, self.AWG2, self.AWG3) else ''}"
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
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {container_name} {dockerfile_folder}",
            timeout=300
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        # Step 5: Run container
        results.append("Starting container...")
        # Detect host IPv6 BEFORE creating the container: the netns
        # disable_ipv6 flags are fixed at container creation time, so a
        # container started without these sysctls can never add an IPv6
        # address to a tunnel interface (ip -6 address add -> RTNETLINK
        # Permission denied, and awg-quick then deletes the whole awg0).
        ipv6_enabled = self._detect_server_ipv6()
        ipv6_sysctls = (
            '--sysctl="net.ipv6.conf.all.disable_ipv6=0" \\\n'
            '--sysctl="net.ipv6.conf.default.disable_ipv6=0" \\\n'
            if ipv6_enabled else ''
        )
        run_cmd = f"""docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p {port}:{port}/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
{ipv6_sysctls} --name {container_name} \
--ulimit nofile=51200:51200 \
--name {container_name} \
{container_name}"""

        out, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")

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
                                  mtu=mtu, dns=dns)
        results.append("AWG configured")

        # Step 7: Upload and run start script
        results.append("Starting AWG service...")
        self._upload_start_script(protocol_type, port, awg_params)
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
                             mtu=None, dns=None):
        """Configure the AWG container (generate keys and server config)."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._config_path(protocol_type)

        subnet_ip = self._get_subnet_ip(protocol_type)
        subnet_cidr = self._get_subnet_cidr(protocol_type)

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

        address_line = f"{subnet_ip}/{subnet_cidr}"
        if ipv6:
            address_line += f", {AWG_DEFAULTS['subnet_ipv6_ip']}/{AWG_DEFAULTS['subnet_ipv6_cidr']}"     
        
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

    def _upload_start_script(self, protocol_type, port, awg_params):
        """Upload and execute the start script inside the container."""
        container_name = self._container_name(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        config_path = self._config_path(protocol_type)
        userspace_guard = self._userspace_guard(protocol_type)

        start_script = f"""#!/bin/bash
echo "Container startup"

# Apply container network tuning (see Dockerfile)
sysctl -p /etc/sysctl.conf 2>/dev/null || true

# Read subnet from server config dynamically (IPv4 part of the Address line)
SUBNET=$(grep '^Address' {config_path} | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET={AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}
fi

# IPv6 subnet, if the tunnel is dual-stack (second part of the Address line)
SUBNET6=$(grep '^Address' {config_path} | head -1 | tr ',' '\n' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)
{userspace_guard}
# kill daemons in case of restart
{quick_bin} down {config_path} 2>/dev/null

# start daemons if configured
if [ -f {config_path} ]; then {quick_bin} up {config_path}; fi

# Allow traffic on the TUN interface
IFACE=$(basename {config_path} .conf)
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
if [ -f /opt/amnezia/awg/bwlimits ]; then
(
{self._tc_apply_body('/opt/amnezia/awg/bwlimits', config_path)}
)
fi

tail -f /dev/null
"""

        # Upload start script to container via SFTP + docker cp
        self.ssh.upload_file(start_script, "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {container_name}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {container_name} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

        # Restart to apply the start script
        self.ssh.run_sudo_command(f"docker restart {container_name}")
        import time
        time.sleep(5)

    def remove_container(self, protocol_type):
        """Remove AWG container (mirrors remove_container.sh)."""
        container_name = self._container_name(protocol_type)
        self.ssh.run_sudo_command(f"docker stop {container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {container_name}")
        self.ssh.run_sudo_command(f"docker rmi {container_name}")
        return True

    # ===================== CLIENT MANAGEMENT =====================

    def _get_clients_table(self, protocol_type):
        """Get the clients table from the server."""
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {clients_table_path} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return []

        try:
            data = json.loads(out)
            if isinstance(data, list):
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
            return []

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
        quick_bin = self._quick_binary(protocol_type)
        userspace_guard = self._userspace_guard(protocol_type)
        start_script = f"""#!/bin/bash
echo "Container startup"

# Apply container network tuning (see Dockerfile)
sysctl -p /etc/sysctl.conf 2>/dev/null || true

# Read subnet from server config dynamically (IPv4 part of the Address line)
SUBNET=$(grep '^Address' {config_path} | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET={AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}
fi

# IPv6 subnet, if the tunnel is dual-stack (second part of the Address line)
SUBNET6=$(grep '^Address' {config_path} | head -1 | tr ',' '\n' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)
{userspace_guard}
# kill daemons in case of restart
{quick_bin} down {config_path} 2>/dev/null

# start daemons if configured
if [ -f {config_path} ]; then {quick_bin} up {config_path}; fi

# Allow traffic on the TUN interface
IFACE=$(basename {config_path} .conf)
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
if [ -f /opt/amnezia/awg/bwlimits ]; then
(
{self._tc_apply_body('/opt/amnezia/awg/bwlimits', config_path)}
)
fi

tail -f /dev/null
"""
        self.ssh.upload_file(start_script, "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {container_name}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {container_name} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

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
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
            elif line.startswith('Address'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
        return ips

    def _get_next_ip(self, protocol_type):
        """Return the first free IP in the subnet, filling gaps left by deleted clients.

        The old implementation took the last IP in file order and incremented it,
        which produced duplicate IPs when peers were not sorted by IP and never
        reused addresses freed by deleted clients.
        """
        used_ips = self._get_used_ips(protocol_type)
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

    def _client_ip_from_userdata(self, user_data):
        """Return a valid client IP from stored userData, tolerating native Amnezia records."""
        return (
            self._extract_ipv4(user_data.get('clientIp'))
            or self._extract_ipv4(user_data.get('allowedIps'))
            or self._extract_ipv4(user_data.get('allowed_ip'))
        )

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
        return counts

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

    def collect_conn_stats(self, protocol_type):
        """Background collector: one cheap SSH roundtrip per instance.

        Counts conntrack entries per peer IP inside the container (compact
        awk summary, no raw table transfer), saves the snapshot and records
        flood warnings. Called by the panel's background monitor so that
        detection runs 24/7 even when nobody has the UI open.
        """
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
        """Clear all recorded connection-flood warnings for one peer."""
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
        return {'status': 'success', 'cleared_ip': ip}

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

    def add_client(self, protocol_type, client_name, server_host, port):
        """
        Add a new client/peer to the AWG config.
        Returns the client config as a string for the .conf file.
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
        dns_line = dns + (", 2606:4700:4700::1111" if client_ipv6 else "")
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

        # Route ::/0 only when the client actually holds an IPv6 address:
        # claiming the IPv6 default route on an IPv4-only tunnel blackholes
        # the client's own native IPv6.
        peer_allowed_ips = "0.0.0.0/0, ::/0" if client_ipv6 else "0.0.0.0/0"

        client_config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = {peer_allowed_ips}
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""

        return {
            'client_name': client_name,
            'client_id': client_pub_key,
            'client_ip': client_ip,
            'config': client_config,
        }

    def get_client_config(self, protocol_type, client_id, server_host, port):
        """Reconstruct client config from stored data."""
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
        dns_line = dns + (", 2606:4700:4700::1111" if client_ipv6 else "")
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

        # See the client-creation path: ::/0 only on dual-stack tunnels.
        peer_allowed_ips = "0.0.0.0/0, ::/0" if client_ipv6 else "0.0.0.0/0"

        config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = {peer_allowed_ips}
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""
        return config

    def toggle_client(self, protocol_type, client_id, enable):
        """Enable or disable a client by adding/removing their [Peer] from server config."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)
        clients_table = self._get_clients_table(protocol_type)
        table_changed = False

        if enable:
            # Re-add peer to server config. Native Amnezia clients may not have
            # userData.clientIp in clientsTable, so recover it from allowedIps
            # before falling back to a new free address.
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if not client:
                raise RuntimeError(f"Client {client_id} not found")

            ud = client.setdefault('userData', {})
            psk = ud.get('psk', '')
            client_ip = self._client_ip_from_userdata(ud)
            if not client_ip:
                client_ip = self._get_next_ip(protocol_type)
                logger.warning(
                    "Client %s had no saved AWG IP/AllowedIPs; assigning next free IP %s",
                    client_id,
                    client_ip,
                )

            ud['clientIp'] = client_ip
            client_ipv6 = ud.get('clientIpv6', '') or self._get_client_ipv6(protocol_type, client_ip)
            allowed_ips = f'{client_ip}/32' + (f', {client_ipv6}/128' if client_ipv6 else '')
            ud['allowedIps'] = allowed_ips
            if client_ipv6:
                ud['clientIpv6'] = client_ipv6
            table_changed = True

            if not psk:
                psk = self._get_server_psk(protocol_type)
                ud['psk'] = psk
                table_changed = True

            peer_section = f"""
[Peer]
PublicKey = {client_id}
PresharedKey = {psk}
AllowedIPs = {allowed_ips}

"""
            escaped_peer = peer_section.replace("'", "'\\''")
            self.ssh.run_sudo_command(
                f"docker exec -i {container_name} bash -c 'echo \"{escaped_peer}\" >> {config_path}'"
            )
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
            if not ud.get('psk'):
                ud['psk'] = self._get_server_psk(protocol_type)
                table_changed = True

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
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update enabled status in clients table
        for c in clients_table:
            if c.get('clientId') == client_id:
                c.setdefault('userData', {})['enabled'] = enable
                table_changed = True
                break
        if table_changed:
            self._save_clients_table(protocol_type, clients_table)

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

    def get_awg_settings(self, protocol_type):
        """Client-facing AWG settings currently stored in the server config."""
        params = self._get_awg_params_from_config(protocol_type)
        settings = {
            'mtu': self._get_mtu(protocol_type),
            'dns': self._get_dns(protocol_type),
            'default_i1': AWG_DEFAULT_I1,
            'supports_special_junk': self._base_protocol(protocol_type) != self.AWG_LEGACY,
        }
        for key in SPECIAL_JUNK_KEYS:
            settings[key] = params.get(key, '')
        return settings

    def update_awg_settings(self, protocol_type, mtu=None, dns=None, special_junk=None):
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
                    info['clients_count'] = len(self._get_clients_table(protocol_type))
                except Exception as e:
                    info['error'] = str(e)

        return info
