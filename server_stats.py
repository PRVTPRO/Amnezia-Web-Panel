"""Collect the existing host statistics with one read-only SSH command."""
import shlex
import uuid


HOST_STATS_COMMANDS = {
    'cpu': (
        "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || "
        "awk '{u=$2+$4; t=$2+$4+$5; if(NR==1){pu=u;pt=t} else printf \"%.1f\", (u-pu)/(t-pt)*100}' "
        "<(grep 'cpu ' /proc/stat) <(sleep 0.5 && grep 'cpu ' /proc/stat) 2>/dev/null"
    ),
    'ram': "free -b | awk 'NR==2{printf \"%d %d\", $3, $2}'",
    'disk': "df -B1 / | awk 'NR==2{printf \"%d %d\", $3, $2}'",
    'network': (
        "DEV=$(ip route | awk '/default/ {print $5}' | head -1); "
        "cat /proc/net/dev | awk -v dev=\"$DEV:\" '$1==dev{printf \"%d %d\", $2, $10}'"
    ),
    'uptime': 'uptime -p 2>/dev/null || uptime',
    'ipv6': (
        "ip -6 addr show scope global 2>/dev/null | "
        "awk '/inet6/ && $2 !~ /^fd[0-9a-fA-F]{2}:/ {"
        "split($2, a, \"/\"); if (a[2] <= 64) print a[1]}'"
    ),
}


def collect_host_stats(ssh):
    marker = '@@HOST_STATS_' + uuid.uuid4().hex + '@@'
    script = []
    for name, command in HOST_STATS_COMMANDS.items():
        script.extend([f"printf '\\n%s\\n' '{marker}:{name}'", '{ ' + command + '; }'])
    script.append(f"printf '\\n%s\\n' '{marker}:done'")
    # The existing CPU fallback uses Bash process substitution. One shell
    # preserves it while avoiding six remote channel round trips.
    out, _, code = ssh.run_command('bash -c ' + shlex.quote('\n'.join(script)))
    if code != 0:
        raise RuntimeError('Host statistics batch failed')
    sections = {}
    current = None
    complete = False
    for line in out.splitlines():
        if line == marker + ':done':
            complete = True
            break
        if line.startswith(marker + ':'):
            current = line[len(marker) + 1:]
            if current not in HOST_STATS_COMMANDS or current in sections:
                raise RuntimeError('Invalid host statistics batch')
            sections[current] = []
        elif current:
            sections[current].append(line)
    if not complete or set(sections) != set(HOST_STATS_COMMANDS):
        raise RuntimeError('Incomplete host statistics batch')
    sections = {name: '\n'.join(lines).strip() for name, lines in sections.items()}
    stats = {}
    try:
        stats['cpu'] = round(float(sections['cpu'].split('\n')[0]), 1)
    except (ValueError, IndexError):
        stats['cpu'] = 0
    for field in ('ram', 'disk'):
        try:
            used, total = map(int, sections[field].split())
            percent = round(used / total * 100, 1) if total > 0 else 0
        except (ValueError, IndexError):
            used, total, percent = 0, 0, 0
        stats.update({field + '_used': used, field + '_total': total, field + '_percent': percent})
    try:
        stats['net_rx'], stats['net_tx'] = map(int, sections['network'].split())
    except (ValueError, IndexError):
        stats['net_rx'] = stats['net_tx'] = 0
    stats['uptime'] = sections['uptime']
    stats['ipv6'] = [line.strip() for line in sections['ipv6'].splitlines() if line.strip()]
    return stats
