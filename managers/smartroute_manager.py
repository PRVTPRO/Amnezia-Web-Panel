"""Smart Route: split egress for exit-linked instances by destination country.

Host-level marketplace app. The host side is a prefix list
(/etc/smartroute/ru_v4.cidr + ru_v6.cidr) refreshed hourly by a systemd
timer from a prioritized source list with fallback and a <N guard. The
routing side lives INSIDE the AWG container netns (same place the exit
table lives): RU prefixes are loaded into the exit table as throw routes
BEFORE the default dev exit0, so a lookup that hits a throw aborts that
table and falls through to the main table - the traffic leaves directly
via eth0. Kill-switch semantics are unchanged: RU goes direct always,
non-RU is still blackholed when the link is down.

Coexistence with amnezia-blocker/rkn-extra-block: this module only touches
ip rule/route table 200 (per-container netns) and its own SMARTR_ACCT
mangle chain - never FORWARD/OUTPUT, never ipset. Blocker chains sit at
FORWARD position 1 and keep filtering both paths regardless.
"""

import ipaddress
import json
import re

# Host-side layout (all panel-managed, no docker on the host side)
SMARTR_DIR = '/etc/smartroute'
SMARTR_BIN = '/usr/local/sbin/smartroute-update.sh'
SMARTR_V4 = f'{SMARTR_DIR}/ru_v4.cidr'
SMARTR_V6 = f'{SMARTR_DIR}/ru_v6.cidr'
SMARTR_OWN = f'{SMARTR_DIR}/own.cidr'
SMARTR_STATUS = f'{SMARTR_DIR}/status.json'
SMARTR_INSTANCES = f'{SMARTR_DIR}/instances'
SMARTR_MIN_PREFIXES = 100

# Inside the container netns (mirrors managers.awg_manager EXIT_*)
SMARTR_TABLE = 200          # == awg_manager.EXIT_TABLE
SMARTR_EXIT_IF = 'exit0'    # == awg_manager.EXIT_IFACE
SMARTR_ACCT_CHAIN = 'SMARTR_ACCT'
SMARTR_ACCT_CHAIN_IN = f'{SMARTR_ACCT_CHAIN}_IN'

# Prioritized sources with fallback. RIPE delegated covers both families in
# one file and is parsed (start+count -> CIDR), the others are plain lists.
SOURCES_V4 = [
    'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone',
    'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ru.cidr',
    'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest',
]
SOURCES_V6 = [
    'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone',
    'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/ru.cidr',
    'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest',
]

_CIDR_V4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

# Formats of `iptables -t mangle -L SMARTR_ACCT[_IN] -vnx` data rows:
#   " 123 456 RETURN all -- * exit0 10.8.0.0/24 0.0.0.0/0"   (egress: out-iface)
#   " 123 456 RETURN all -- exit0 * 0.0.0.0/0 10.8.0.0/24"   (ingress: in-iface)
# fields[0]=pkts fields[1]=bytes fields[5]=in-iface fields[6]=out-iface
_ACCT_ROW_RE = re.compile(
    r'^\s*(\d+)\s+(\d+)\s+RETURN\s+\S+\s+\S+\s+(\S+)\s+(\S+)')


# ======================== Pure parsing helpers ========================

def parse_ripe_delegated(text, family='ipv4', country='RU'):
    """delegated-ripencc-latest -> sorted list of CIDR strings.

    Rows look like: ripencc|RU|ipv4|83.172.0.0|131072|20130912|allocated|...
    IPv4 start+count is folded to CIDRs via summarize_address_range.
    """
    nets = set()
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) < 7 or parts[1] != country or parts[2] != family:
            continue
        if parts[6] not in ('allocated', 'assigned'):
            continue
        try:
            if family == 'ipv4':
                first = ipaddress.IPv4Address(parts[3])
                last = first + int(parts[4]) - 1
                nets.update(str(n) for n in ipaddress.summarize_address_range(first, last))
            else:
                nets.add(str(ipaddress.IPv6Network(f'{parts[3]}/{parts[4]}')))
        except (ValueError, IndexError):
            continue
    return sorted(nets)


def normalize_cidrs(lines, family='ipv4'):
    """Validate/normalize a list of CIDR strings: strict-parse, dedupe, sort.

    Raises ValueError on the first garbage line (used for own subnets input).
    """
    nets = set()
    for raw in lines:
        line = (raw or '').strip()
        if not line or line.startswith('#'):
            continue
        net = ipaddress.ip_network(line, strict=False)
        if (family == 'ipv4' and net.version != 4) or (family == 'ipv6' and net.version != 6):
            raise ValueError(f'{line}: expected an IPv{family[-1]} CIDR')
        nets.add(str(net))
    return sorted(nets, key=lambda c: (ipaddress.ip_network(c).version,
                                       int(ipaddress.ip_network(c).network_address),
                                       ipaddress.ip_network(c).prefixlen))


def parse_acct_counters(text):
    """`iptables -t mangle -L SMARTR_ACCT[_IN] -vnx` -> counter dict.

    Egress rows carry the path in the OUT-iface (chain on POSTROUTING),
    ingress rows in the IN-iface (chain on PREROUTING). Anything else in
    the chains (nothing should be) is ignored. Missing chains -> zeros.

    Returns {'via_exit': {pkts, bytes}, 'direct': {pkts, bytes},      # totals
            'via_exit_out'/'direct_out', 'via_exit_in'/'direct_in'}   # split
    """
    def bucket():
        return {'pkts': 0, 'bytes': 0}

    out = {k: bucket() for k in (
        'via_exit', 'direct', 'via_exit_out', 'direct_out', 'via_exit_in', 'direct_in')}
    for line in (text or '').splitlines():
        m = _ACCT_ROW_RE.match(line)
        if not m:
            continue
        pkts, bytez, in_if, out_if = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
        if out_if in (SMARTR_EXIT_IF, 'eth0'):      # egress row
            path, direction = ('via_exit' if out_if == SMARTR_EXIT_IF else 'direct'), 'out'
        elif in_if in (SMARTR_EXIT_IF, 'eth0'):     # ingress row
            path, direction = ('via_exit' if in_if == SMARTR_EXIT_IF else 'direct'), 'in'
        else:
            continue
        for key in (path, f'{path}_{direction}'):
            out[key]['pkts'] += pkts
            out[key]['bytes'] += bytez
    return out


# ======================== Shell script builders ========================

# Runs INSIDE the container: refresh throw routes only. The default/blackhole
# routes of the exit table are untouched. The merged prefix list must already
# be at /tmp/smartr_v4.cidr (docker cp'd by the caller).
CONTAINER_APPLY_SCRIPT = """\
set -u
TABLE=__TABLE__
ip -4 route show table $TABLE | awk '$1==\"throw\"{print \"route del throw \"$2\" table '$TABLE'\"}' > /tmp/smartr_del.batch
[ -s /tmp/smartr_del.batch ] && ip -4 -batch /tmp/smartr_del.batch 2>/dev/null
if [ -s /tmp/smartr_v4.cidr ]; then
  awk 'NF{print \"route add throw \"$1\" table '$TABLE'\"}' /tmp/smartr_v4.cidr > /tmp/smartr_add.batch
  ip -4 -batch /tmp/smartr_add.batch 2>&1 || true
fi
echo "smartroute: $(ip -4 route show table $TABLE | grep -c '^throw') throw routes in table $TABLE"
"""

# Runs INSIDE the container when split routing is enabled: the accounting
# chain (mangle/POSTROUTING, never FORWARD/OUTPUT - blockers own those) and
# a conntrack flush so flows reopen on the new path (same rationale as
# x_link_up). X_SUBNET is read from the instance config, like the x_ block.
CONTAINER_ENABLE_SCRIPT = CONTAINER_APPLY_SCRIPT + """
X_SUBNET=$(grep '^Address' __CONF__ | head -1 | cut -d= -f2 | cut -d, -f1 | tr -d ' ')
[ -n "$X_SUBNET" ] || X_SUBNET=__SUBNET_DEFAULT__
CH=__CHAIN__
CHI=__CHAIN_IN__
# egress: client -> internet (upload per path)
iptables -t mangle -N $CH 2>/dev/null || true
iptables -t mangle -F $CH
iptables -t mangle -A $CH -s "$X_SUBNET" -o __EXIT_IF__ -j RETURN
iptables -t mangle -A $CH -s "$X_SUBNET" -o eth0 -j RETURN
iptables -t mangle -C POSTROUTING -j $CH 2>/dev/null || iptables -t mangle -A POSTROUTING -j $CH
# ingress: internet -> client (download per path)
iptables -t mangle -N $CHI 2>/dev/null || true
iptables -t mangle -F $CHI
iptables -t mangle -A $CHI -i __EXIT_IF__ -d "$X_SUBNET" -j RETURN
iptables -t mangle -A $CHI -i eth0 -d "$X_SUBNET" -j RETURN
iptables -t mangle -C PREROUTING -j $CHI 2>/dev/null || iptables -t mangle -A PREROUTING -j $CHI
if command -v conntrack >/dev/null 2>&1; then conntrack -D -s "$X_SUBNET" >/dev/null 2>&1
else echo "! conntrack-tools missing: flows opened before the change keep their old path until they end"; fi
echo "smartroute: accounting on for $X_SUBNET"
"""

# Runs INSIDE the container when split routing is disabled or the app is
# removed: drop throw routes (traffic falls back to default dev exit0 - NOT
# to eth0), tear the accounting chain down, flush flows.
CONTAINER_DISABLE_SCRIPT = """\
set -u
TABLE=__TABLE__
X_SUBNET=$(grep '^Address' __CONF__ | head -1 | cut -d= -f2 | cut -d, -f1 | tr -d ' ')
ip -4 route show table $TABLE | awk '$1==\"throw\"{print \"route del throw \"$2\" table '$TABLE'\"}' > /tmp/smartr_del.batch
[ -s /tmp/smartr_del.batch ] && ip -4 -batch /tmp/smartr_del.batch 2>/dev/null
CH=__CHAIN__
CHI=__CHAIN_IN__
iptables -t mangle -D POSTROUTING -j $CH 2>/dev/null || true
iptables -t mangle -F $CH 2>/dev/null || true
iptables -t mangle -X $CH 2>/dev/null || true
iptables -t mangle -D PREROUTING -j $CHI 2>/dev/null || true
iptables -t mangle -F $CHI 2>/dev/null || true
iptables -t mangle -X $CHI 2>/dev/null || true
if [ -n "$X_SUBNET" ] && command -v conntrack >/dev/null 2>&1; then conntrack -D -s "$X_SUBNET" >/dev/null 2>&1; fi
echo "smartroute: split off, $(ip -4 route show table $TABLE | grep -c '^throw') throw routes left"
"""

_RIPE_PARSE_PY = '''import sys, ipaddress
family = sys.argv[1]
out = set()
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    p = line.split("|")
    if len(p) < 7 or p[1] != "RU" or p[2] != family or p[6] not in ("allocated", "assigned"):
        continue
    try:
        if family == "ipv4":
            first = ipaddress.IPv4Address(p[3])
            last = first + int(p[4]) - 1
            out.update(str(n) for n in ipaddress.summarize_address_range(first, last))
        else:
            out.add(str(ipaddress.IPv6Network(p[3] + "/" + p[4])))
    except Exception:
        continue
print("\\n".join(sorted(out)))
'''


def build_update_script():
    """The host-side /usr/local/sbin/smartroute-update.sh."""
    sources_v4 = ' '.join(SOURCES_V4)
    sources_v6 = ' '.join(SOURCES_V6)
    apply = CONTAINER_APPLY_SCRIPT.replace('__TABLE__', str(SMARTR_TABLE))
    return f'''#!/bin/bash
# Smart Route prefix updater (panel-managed, host-level). Downloads the RU
# prefix list with source fallback + a <{SMARTR_MIN_PREFIXES} guard, stores
# it and re-applies the throw routes of every enabled split instance.
set -u
SMARTR_DIR="{SMARTR_DIR}"
V4_FILE="{SMARTR_V4}"
V6_FILE="{SMARTR_V6}"
OWN_FILE="{SMARTR_OWN}"
STATUS_FILE="{SMARTR_STATUS}"
INSTANCES_DIR="{SMARTR_INSTANCES}"
MIN_PREFIXES={SMARTR_MIN_PREFIXES}
LOCK_FILE="/run/smartroute.lock"

log() {{ echo "$(date '+%F %T') $1"; }}

ripe_parse() {{ # $1 = family; reads stdin (delegated file), prints CIDRs
python3 - "$1" <<'PYEOF'
{_RIPE_PARSE_PY}PYEOF
}}

fetch_family() {{ # $1 = v4|v6, $2 = family; prints "tmpfile source count" or fails
  local kind=$1 family=$2 urls tmp n url
  case $kind in
    v4) urls="{sources_v4}" ;;
    v6) urls="{sources_v6}" ;;
  esac
  tmp=$(mktemp)
  for url in $urls; do
    case $url in
      *delegated-ripencc*)
        curl -fsSL --max-time 180 "$url" 2>/dev/null | ripe_parse "$family" > "$tmp" 2>/dev/null ;;
      *)
        if [ "$kind" = v4 ]; then
          curl -fsSL --max-time 90 "$url" 2>/dev/null | grep -E '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}/[0-9]{{1,2}}$' > "$tmp" 2>/dev/null
        else
          curl -fsSL --max-time 90 "$url" 2>/dev/null | grep -E '^[0-9a-fA-F:]{{2,}}/[0-9]{{1,3}}$' > "$tmp" 2>/dev/null
        fi ;;
    esac
    sort -u "$tmp" -o "$tmp" 2>/dev/null
    n=$(grep -c / "$tmp" 2>/dev/null || echo 0)
    if [ "$n" -ge "$MIN_PREFIXES" ]; then
      echo "$tmp $url $n"
      return 0
    fi
    log "source $url gave $n prefixes ($kind) - trying next"
    : > "$tmp"
  done
  rm -f "$tmp"
  return 1
}}

write_status() {{ # $1 src4 $2 cnt4 $3 src6 $4 cnt6 $5 error
python3 - "$@" <<'PYEOF'
import json, sys, time
src4, cnt4, src6, cnt6, err = sys.argv[1:7]
json.dump({{
    "prefixes_v4": int(cnt4), "prefixes_v6": int(cnt6),
    "source_v4": src4, "source_v6": src6,
    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "error": err or None,
}}, open("{SMARTR_STATUS}", "w"))
PYEOF
}}

apply_instances() {{ # push the merged list into every marked container
  local merged c
  merged=$(mktemp)
  cat "$V4_FILE" 2>/dev/null > "$merged"
  if [ -s "$OWN_FILE" ]; then
    grep -vE '^\\s*(#|$)' "$OWN_FILE" >> "$merged"
  fi
  for marker in "$INSTANCES_DIR"/*; do
    [ -f "$marker" ] || continue
    c=$(basename "$marker")
    docker ps --format '{{{{.Names}}}}' 2>/dev/null | grep -qx "$c" || continue
    docker cp "$merged" "$c:/tmp/smartr_v4.cidr" 2>/dev/null || {{ log "apply: $c unreachable, skipped"; continue; }}
    docker exec -i "$c" bash -s <<'APPEOF'
{apply}APPEOF
  done
  rm -f "$merged"
}}

exec 9>"$LOCK_FILE" || exit 1
flock -n 9 || {{ log "another update is running, exit"; exit 0; }}

mkdir -p "$SMARTR_DIR" "$INSTANCES_DIR"
SRC4=""; CNT4=0; SRC6=""; CNT6=0; ERR=""
if fetch_family v4 ipv4 > /tmp/smartr_v4.out 2>/dev/null; then
  read -r TMP4 SRC4 CNT4 < /tmp/smartr_v4.out
  mv "$TMP4" "$V4_FILE"
else
  ERR="no v4 source gave >= $MIN_PREFIXES prefixes; old list kept"
  log "$ERR"
fi
if fetch_family v6 ipv6 > /tmp/smartr_v6.out 2>/dev/null; then
  read -r TMP6 SRC6 CNT6 < /tmp/smartr_v6.out
  mv "$TMP6" "$V6_FILE"
else
  log "WARNING: v6 list not updated (old file kept if any)"
fi
rm -f /tmp/smartr_v4.out /tmp/smartr_v6.out
[ -f "$V4_FILE" ] && CNT4_ONDISK=$(grep -c / "$V4_FILE" 2>/dev/null || echo 0) || CNT4_ONDISK=0
[ -f "$V6_FILE" ] && CNT6_ONDISK=$(grep -c / "$V6_FILE" 2>/dev/null || echo 0) || CNT6_ONDISK=0
write_status "$SRC4" "${{CNT4:-$CNT4_ONDISK}}" "$SRC6" "${{CNT6:-$CNT6_ONDISK}}" "$ERR"
apply_instances
log "update done: v4=${{CNT4:-$CNT4_ONDISK}} v6=${{CNT6:-$CNT6_ONDISK}}"
'''


_SMARP_UNIT = '''[Unit]
Description=Smart Route prefix updater

[Service]
Type=oneshot
ExecStart={bin}
'''

_SMARP_TIMER = '''[Unit]
Description=Smart Route prefix updater timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=900
Persistent=true
Unit=smartroute.service

[Install]
WantedBy=timers.target
'''


def build_install_script():
    """One-shot host install: script + systemd units + first update."""
    return f'''#!/bin/bash
set -u
mkdir -p {SMARTR_DIR} {SMARTR_INSTANCES}
touch {SMARTR_OWN}
cat > {SMARTR_BIN} <<'SMARPBIN'
{build_update_script()}SMARPBIN
chmod +x {SMARTR_BIN}
cat > /etc/systemd/system/smartroute.service <<'SMARPSVC'
{_SMARP_UNIT.format(bin=SMARTR_BIN)}SMARPSVC
cat > /etc/systemd/system/smartroute.timer <<'SMARPTMR'
{_SMARP_TIMER}SMARPTMR
systemctl daemon-reload
systemctl enable --now smartroute.timer >/dev/null 2>&1
systemctl enable smartroute.service >/dev/null 2>&1
# First list download runs in the background: the source fallback can take
# up to ~12 min (3 sources x 2 families), far beyond any SSH timeout. The
# timer (OnBootSec=2min) is the safety net; status.json reports progress.
nohup {SMARTR_BIN} > /var/log/smartroute-install.log 2>&1 &
echo "smartroute: installed, first list download running in background"
'''


def build_remove_script():
    """Full cleanup: throw routes + counters out of every marked container,
    markers, files, timer and service. Never touches FORWARD/OUTPUT/ipset."""
    disable = CONTAINER_DISABLE_SCRIPT.replace('__TABLE__', str(SMARTR_TABLE)) \
                                      .replace('__CHAIN__', SMARTR_ACCT_CHAIN) \
                                      .replace('__CONF__', '/opt/amnezia/awg/awg0.conf') \
                                      .replace('__SUBNET_DEFAULT__', '')
    return f'''#!/bin/bash
set -u
if [ -d {SMARTR_INSTANCES} ]; then
  for marker in {SMARTR_INSTANCES}/*; do
    [ -f "$marker" ] || continue
    c=$(basename "$marker")
    docker ps --format '{{{{.Names}}}}' 2>/dev/null | grep -qx "$c" || continue
    docker exec -i "$c" bash -s <<'DISEOF'
{disable}DISEOF
  done
fi
systemctl disable --now smartroute.timer smartroute.service >/dev/null 2>&1
rm -f /etc/systemd/system/smartroute.timer /etc/systemd/system/smartroute.service
systemctl daemon-reload
rm -rf {SMARTR_DIR}
echo "smartroute: removed"
'''


def render_container_script(template, *, config_path, subnet_default):
    return (template
            .replace('__TABLE__', str(SMARTR_TABLE))
            .replace('__CHAIN__', SMARTR_ACCT_CHAIN)
            .replace('__CHAIN_IN__', SMARTR_ACCT_CHAIN_IN)
            .replace('__CONF__', config_path)
            .replace('__SUBNET_DEFAULT__', subnet_default)
            .replace('__EXIT_IF__', SMARTR_EXIT_IF))


# ======================== Manager (SSH-bound) ========================

class SmartRouteError(RuntimeError):
    pass


class SmartRouteManager:
    """Host-level operations over SSH. All methods raise SmartRouteError on
    a failed step, so the panel never records state the server does not have."""

    def __init__(self, ssh):
        self.ssh = ssh

    def _run_script(self, script, timeout=420):
        self.ssh.upload_file(script, '/tmp/_smartr.sh')
        try:
            out, err, code = self.ssh.run_sudo_command('bash /tmp/_smartr.sh', timeout=timeout)
        finally:
            self.ssh.run_command('rm -f /tmp/_smartr.sh')
        if code != 0:
            raise SmartRouteError((err or out or f'SSH exit code {code}').strip())
        return out

    def install(self):
        return self._run_script(build_install_script())

    def uninstall(self):
        return self._run_script(build_remove_script())

    def run_update(self):
        out, err, code = self.ssh.run_sudo_command(SMARTR_BIN, timeout=420)
        if code != 0:
            raise SmartRouteError((err or out or f'SSH exit code {code}').strip())
        return out

    def is_installed(self):
        out, _, code = self.ssh.run_command(f'test -f {SMARTR_BIN} && echo yes')
        return code == 0 and out.strip() == 'yes'

    def host_status(self):
        """status.json + timer state + markers. All reads are best-effort."""
        out, _, code = self.ssh.run_command(f'cat {SMARTR_STATUS} 2>/dev/null')
        status = {}
        if code == 0 and out.strip():
            try:
                status = json.loads(out)
            except ValueError:
                status = {'error': 'status file is not valid JSON'}
        out, _, code = self.ssh.run_command(
            'systemctl list-timers smartroute.timer --no-legend 2>/dev/null | awk \'{print $1, $2}\'')
        next_run = ''
        if code == 0 and out.strip():
            next_run = out.strip().split()[0]
        out, _, code = self.ssh.run_command(f'ls {SMARTR_INSTANCES} 2>/dev/null')
        instances = sorted(out.split()) if code == 0 and out.strip() else []
        return {
            'installed': self.is_installed(),
            'status': status,
            'next_run': next_run,
            'instances': instances,
        }

    def set_own_subnets(self, cidrs):
        """Own subnets live on the host and are merged into every apply."""
        body = '\n'.join(cidrs) + ('\n' if cidrs else '')
        self.ssh.upload_file(body, '/tmp/_smartr_own.cidr')
        try:
            _, err, code = self.ssh.run_sudo_command(
                f'mkdir -p {SMARTR_DIR} && cp /tmp/_smartr_own.cidr {SMARTR_OWN}')
        finally:
            self.ssh.run_command('rm -f /tmp/_smartr_own.cidr')
        if code != 0:
            raise SmartRouteError((err or f'SSH exit code {code}').strip())

    # ----- per-instance (container netns) -----

    def _container_run(self, container, script, timeout=120):
        self.ssh.upload_file(script, '/tmp/_smartr_c.sh')
        try:
            steps = (
                f'docker cp /tmp/_smartr_c.sh {container}:/tmp/_smartr_c.sh',
                f'docker exec {container} bash /tmp/_smartr_c.sh',
            )
            last = ''
            for step in steps:
                out, err, code = self.ssh.run_sudo_command(step, timeout=timeout)
                last = out or err
                if code != 0:
                    raise SmartRouteError((err or out or f'SSH exit code {code}').strip())
            return last
        finally:
            self.ssh.run_command('rm -f /tmp/_smartr_c.sh')

    def _push_merged_list(self, container):
        """Rebuild merged v4 list on the host and docker cp it into the box."""
        _, err, code = self.ssh.run_sudo_command(
            f'cat {SMARTR_V4} {SMARTR_OWN} 2>/dev/null | grep -vE "^\\s*(#|$)" > /tmp/_smartr_v4.cidr')
        if code != 0:
            raise SmartRouteError((err or 'failed to build the merged prefix list').strip())
        try:
            _, err, code = self.ssh.run_sudo_command(
                f'docker cp /tmp/_smartr_v4.cidr {container}:/tmp/smartr_v4.cidr')
        finally:
            self.ssh.run_command('rm -f /tmp/_smartr_v4.cidr')
        if code != 0:
            raise SmartRouteError((err or f'could not push the prefix list to {container}').strip())

    def enable_instance(self, container, config_path, subnet_default):
        """Marker on the host + throws + accounting inside the container."""
        _, err, code = self.ssh.run_sudo_command(
            f'mkdir -p {SMARTR_INSTANCES} && echo {SMARTR_TABLE} > {SMARTR_INSTANCES}/{container}')
        if code != 0:
            raise SmartRouteError((err or 'failed to write the instance marker').strip())
        self._push_merged_list(container)
        script = render_container_script(
            CONTAINER_ENABLE_SCRIPT, config_path=config_path, subnet_default=subnet_default)
        return self._container_run(container, script)

    def disable_instance(self, container, config_path, subnet_default):
        """Drop marker + throws + accounting; traffic falls back to the exit."""
        self.ssh.run_sudo_command(f'rm -f {SMARTR_INSTANCES}/{container}')
        script = render_container_script(
            CONTAINER_DISABLE_SCRIPT, config_path=config_path, subnet_default=subnet_default)
        return self._container_run(container, script)

    def refresh_instance(self, container):
        """Re-apply the current lists to one container (after list edits)."""
        self._push_merged_list(container)
        script = render_container_script(
            CONTAINER_APPLY_SCRIPT, config_path='/opt/amnezia/awg/awg0.conf',
            subnet_default='')
        return self._container_run(container, script)

    def instance_counters(self, container, config_path, subnet_default):
        """Read-only probe: accounting chains (egress + ingress) + throw count."""
        script = render_container_script(
            'iptables -t mangle -L __CHAIN__ -vnx 2>/dev/null\n'
            'iptables -t mangle -L __CHAIN_IN__ -vnx 2>/dev/null\n'
            'echo ---\n'
            'ip -4 route show table __TABLE__ | grep -c "^throw"\n',
            config_path=config_path, subnet_default=subnet_default)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container} sh -c '{script}'", timeout=60)
        if code != 0:
            raise SmartRouteError((err or out or f'SSH exit code {code}').strip())
        counters_text, _, throws = out.partition('---')
        return {
            **parse_acct_counters(counters_text),
            'throw_routes': int(throws.strip() or 0),
        }
