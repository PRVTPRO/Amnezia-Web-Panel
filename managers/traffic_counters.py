"""Strict read-only WG/AWG accounting, independent of display/cache fallbacks."""
import base64
import hashlib
import re
import shlex


def counter(value):
    return type(value) is int and value >= 0


def parse_transfer_snapshot(output):
    """Only public peer IDs, exact integer counters and epoch metadata cross SSH."""
    try:
        header, rows = output.split('\nTRANSFER\n', 1)
        if not rows.endswith('\nEND'):
            raise ValueError
        rows = rows[:-4]
        lines = header.splitlines()
        if (len(lines) != 5 or lines[0] != 'COUNTERS_V1'
                or not re.fullmatch(r'[0-9a-f]{64} \S+ [1-9][0-9]*', lines[1])
                or not re.fullmatch(r'[0-9a-fA-F-]{36}', lines[2])
                or not re.fullmatch(r'[1-9][0-9]*', lines[3])
                or not re.fullmatch(r'(?:no-socket|[0-9]+:[0-9]+(?::[0-9]+:[0-9]+)?)', lines[4])):
            raise ValueError
        peers = {}
        for row in rows.splitlines():
            parts = row.split()
            if (len(parts) != 3 or len(base64.b64decode(parts[0], validate=True)) != 32
                    or parts[0] in peers or not all(re.fullmatch(r'[0-9]+', n) for n in parts[1:])):
                raise ValueError
            peers[parts[0]] = {'rx_bytes': int(parts[1]), 'tx_bytes': int(parts[2])}
        return {'epoch': hashlib.sha256(header.encode()).hexdigest(), 'peers': peers}
    except (ValueError, TypeError, AttributeError):
        # Never include output, keys or a remote stderr in an exception.
        raise ValueError('Invalid live traffic snapshot') from None


def read_transfer_snapshot(ssh, container, binary, interface):
    """Bracket a single exact `show transfer` by container/interface identities.

    This identifies observable container/interface/UAPI restarts, not every
    peer remove/re-add. It cannot recover bytes lost before an unobserved reset.
    No configuration, PSK or private key is requested, even on the remote side.
    """
    if not all(isinstance(s, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', s)
               for s in (container, binary, interface)):
        raise ValueError('Invalid counter endpoint')
    inner = f'''set -eu
epoch() {{
    cat /proc/sys/kernel/random/boot_id
    cat /sys/class/net/{interface}/ifindex
    sockets=''
    for p in /var/run/wireguard/{interface}.sock /var/run/amneziawg/{interface}.sock; do
        if [ -S "$p" ]; then
            identity=$(stat -Lc '%i:%Z' "$p") || return 1
            sockets="${{sockets:+$sockets:}}$identity"
        fi
    done
    printf '%s\\n' "${{sockets:-no-socket}}"
}}
before=$(epoch)
transfer=$({binary} show {interface} transfer)
after=$(epoch)
[ "$before" = "$after" ]
printf '%s\\nTRANSFER\\n%s\\nEND\\n' "$before" "$transfer"
'''
    inspect = 'docker inspect --format ' + shlex.quote('{{.Id}} {{.State.StartedAt}} {{.State.Pid}}') + ' ' + shlex.quote(container)
    script = f'''set -eu
before=$({inspect})
sample=$(docker exec {shlex.quote(container)} sh -c {shlex.quote(inner)})
after=$({inspect})
[ "$before" = "$after" ]
printf 'COUNTERS_V1\\n%s\\n%s\\n' "$before" "$sample"
'''
    output, _, code = ssh.run_sudo_command('sh -c ' + shlex.quote(script), timeout=20)
    if code != 0:
        raise RuntimeError('Live traffic snapshot unavailable')
    return parse_transfer_snapshot(output)
