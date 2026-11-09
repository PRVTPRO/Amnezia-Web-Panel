"""Collect the existing host statistics with one read-only SSH command."""
import shlex
import uuid
import math


HOST_STATS_COMMANDS = {
    'cpu': (
        "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || "
        "awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' "
        "<(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null"
    ),
    'ram': "free -b | awk 'NR==2{printf \"%.0f %.0f\", $3, $2}'",
    # Sum the physical filesystems, not just "/": a small root partition next
    # to a large data mount must not hide the real volume. Devices are counted
    # once (bind mounts, btrfs subvolumes and docker overlays repeat the same
    # device). "%.0f" instead of "%d": mawk on Debian clamps %d to 2^31-1, so
    # every disk larger than 2 GiB was reported as 2147483647 bytes.
    'disk': (
        "df -B1 -P -x tmpfs -x devtmpfs -x overlay -x squashfs -x devfs -x procfs -x sysfs "
        "2>/dev/null | awk 'NR>1 && $2>0 && $1 ~ /^\\/dev\\// && !seen[$1]++ "
        "{used+=$3; total+=$2} "
        "END {if(total>0) printf \"%.0f %.0f\", used, total; else print \"0 0\"}'"
    ),
    # Swap is reported only when the host has some; the UI hides the row for 0.
    'swap': (
        "awk '/^SwapTotal:/{t=$2} /^SwapFree:/{f=$2} "
        "END {if(f==\"\") f=0; printf \"%.0f %.0f\", (t-f)*1024, t*1024}' /proc/meminfo"
    ),
    'network': (
        "DEV=$(ip route | awk '/default/ {print $5}' | head -1); "
        "cat /proc/net/dev | awk -v dev=\"$DEV:\" '$1==dev{printf \"%.0f %.0f\", $2, $10}'"
    ),
    'uptime': 'uptime -p 2>/dev/null || uptime',
    'ipv6': (
        "ip -6 addr show scope global 2>/dev/null | "
        "awk '/inet6/ && $2 !~ /^fd[0-9a-fA-F]{2}:/ {"
        "split($2, a, \"/\"); if (a[2] <= 64) print a[1]}'"
    ),
}


HOST_STATS_TIMEOUT = 30


def collect_host_stats(ssh):
    """One Bash probe (supported Ubuntu hosts), with partial results on failure.

    Completed, independently framed fields survive a truncated SSH response.
    Missing Bash, timeouts and failed fields are reported in errors, never as
    a successful zero reading. No retry storm of individual SSH commands.
    """
    marker = '@@HOST_STATS_' + uuid.uuid4().hex + '@@'
    script = ['export LC_ALL=C', 'set -o pipefail']
    for name, command in HOST_STATS_COMMANDS.items():
        script.extend([f"printf '\\n%s\\n' '{marker}:{name}'", '( ' + command + ' )',
                       'field_status=$?',
                       f"printf '\\n%s:%s\\n' '{marker}:end:{name}' \"$field_status\""])
    script.append(f"printf '\\n%s\\n' '{marker}:done'")
    command = 'command -v bash >/dev/null 2>&1 && bash -c ' + shlex.quote('\n'.join(script))
    try:
        out, _, code = ssh.run_command(command, timeout=HOST_STATS_TIMEOUT)
    except Exception:
        out, code = '', -1
    sections, errors = {}, {}
    current, lines, complete = None, [], False
    for line in (out or '').splitlines():
        if line == marker + ':done':
            complete = True
            break
        if line.startswith(marker + ':end:'):
            parts = line[len(marker + ':end:'):].split(':')
            if len(parts) != 2 or parts[0] != current or not parts[1].isdigit():
                errors['batch'] = 'invalid_framing'
                break
            if parts[1] == '0':
                sections[current] = '\n'.join(lines).strip()
            else:
                errors[current] = 'probe_failed'
            current, lines = None, []
        elif line.startswith(marker + ':'):
            name = line[len(marker) + 1:]
            if current is not None or name not in HOST_STATS_COMMANDS or name in sections or name in errors:
                errors['batch'] = 'invalid_framing'
                break
            current, lines = name, []
        elif current is not None:
            lines.append(line)
    if code != 0:
        errors['batch'] = 'command_failed'
    elif not complete:
        errors.setdefault('batch', 'incomplete_response')
    for name in HOST_STATS_COMMANDS:
        if name not in sections:
            errors.setdefault(name, 'unavailable')
            sections[name] = ''
    stats = {}
    try:
        cpu = float(sections['cpu'].split('\n')[0])
        if not math.isfinite(cpu):
            raise ValueError('Non-finite CPU reading')
        stats['cpu'] = round(cpu, 1)
    except (ValueError, IndexError):
        stats['cpu'] = 0
        errors.setdefault('cpu', 'invalid_value')
    for field in ('ram', 'disk', 'swap'):
        try:
            used, total = map(int, sections[field].split())
            percent = round(used / total * 100, 1) if total > 0 else 0
        except (ValueError, IndexError):
            used, total, percent = 0, 0, 0
            errors.setdefault(field, 'invalid_value')
        stats.update({field + '_used': used, field + '_total': total, field + '_percent': percent})
    try:
        stats['net_rx'], stats['net_tx'] = map(int, sections['network'].split())
    except (ValueError, IndexError):
        stats['net_rx'] = stats['net_tx'] = 0
        errors.setdefault('network', 'invalid_value')
    stats['uptime'] = sections['uptime']
    stats['ipv6'] = [line.strip() for line in sections['ipv6'].splitlines() if line.strip()]
    if errors:
        stats['errors'] = errors
    return stats
