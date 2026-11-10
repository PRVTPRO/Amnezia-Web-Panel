"""Fail-closed reconciliation of panel-owned Docker public-port forwards.

This stdlib-only module also runs on the SSH host, as one privileged Python
process. Docker's rules are discovery input only; they are never modified.
"""
import hashlib
import ipaddress
import json
import re
import shlex
import subprocess


class ForwardError(ValueError):
    pass


def port(value):
    value = str(value)
    if not re.fullmatch(r'[0-9]{1,5}', value) or not 1 <= int(value) <= 65535:
        raise ForwardError('invalid forwarding port')
    return str(int(value))


def option(tokens, key, default=None):
    if tokens.count(key) > 1:
        raise ForwardError('ambiguous netfilter option')
    if key not in tokens:
        return default
    i = tokens.index(key)
    if i + 1 == len(tokens) or (i and tokens[i - 1] == '!'):
        raise ForwardError('unsupported netfilter match')
    return tokens[i + 1]


def rules(text, chain):
    result = []
    for line in text.splitlines():
        tokens = shlex.split(line)
        if tokens[:2] == ['-A', chain]:
            result.append(tokens[2:])
    return result


def destination(value):
    try:
        host, p = value.rsplit(':', 1)
        addr = ipaddress.ip_address(host.strip('[]'))
        return addr, port(p)
    except (ValueError, AttributeError):
        raise ForwardError('invalid Docker DNAT destination') from None


def overlaps(rule, l4, p, addr):
    if option(rule, '-p', l4) != l4:
        return False
    rp = option(rule, '--dport')
    if rp is not None and re.fullmatch(r'[0-9]+', rp) and port(rp) != p:
        return False
    scope = option(rule, '-d')
    return not scope or not addr or ipaddress.ip_address(addr) in ipaddress.ip_network(scope, strict=False)


def docker_destination(output, l4, listen, family, container, addr):
    """Cross-check L4, publication, network IP and internal port; never first-win."""
    networks = container[3] or {}
    ips = {ipaddress.ip_address(n.get('IPAddress' if family == 4 else 'GlobalIPv6Address'))
           for n in networks.values() if n.get('IPAddress' if family == 4 else 'GlobalIPv6Address')}
    published = set()
    for key, bindings in (container[4] or {}).items():
        inner, transport = key.split('/')
        for binding in bindings or []:
            host = ipaddress.ip_address(binding['HostIp'])
            if (transport == l4 and port(binding['HostPort']) == listen and host.version == family
                    and (host.is_unspecified or (addr and str(host) == addr))):
                published.add(port(inner))
    candidates = set()
    for rule in rules(output, 'DOCKER'):
        if option(rule, '-j') != 'DNAT' or not overlaps(rule, l4, listen, addr):
            continue
        if option(rule, '-p') != l4 or option(rule, '--dport') != listen:
            raise ForwardError('unsupported Docker publication match')
        target = destination(option(rule, '--to-destination'))
        # A different container matching the same external endpoint is ambiguous.
        if target[0] not in ips or target[1] not in published:
            raise ForwardError('Docker publication belongs to another container or is ambiguous')
        candidates.add(target)
    if len(candidates) != 1:
        raise ForwardError('Docker publication missing or ambiguous; forward unchanged')
    ip, p = candidates.pop()
    return f'[{ip}]:{p}' if family == 6 else f'{ip}:{p}'


INSPECT_FORMAT = '[{{json .Id}},{{json .Name}},{{json .State.Running}},{{json .NetworkSettings.Networks}},{{json .NetworkSettings.Ports}}]'


def run_command(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise ForwardError('forward discovery/command unavailable or timed out') from None
    return p.stdout, p.returncode


def reconcile(request, run=run_command):
    """Called under the host lock. Validate everything before any mutation.

    Unmarked pre-existing forwards are not attributable to this panel. Report
    conflicts instead of deleting/adopting them, including legacy REDIRECTs.
    """
    name = request['container']
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', name):
        raise ForwardError('invalid container identity')
    if not request.get('server_uid') or request['l4'] not in ('tcp', 'udp'):
        raise ForwardError('missing server identity or transport')
    marker = 'amnezia-pf:' + hashlib.sha256(
        (request['server_uid'] + '\0' + request['protocol']).encode()).hexdigest()[:32]
    listen = port(request['listen_port'])
    public = port(request['public_port']) if request.get('public_port') else ''
    old = port(request['old_public_port']) if request.get('old_public_port') else ''
    adding = bool(public and public != listen)
    scopes = {int(k): v for k, v in request['scopes'].items()}
    if set(scopes) != {4, 6}:
        raise ForwardError('invalid address families')
    for family, addresses in scopes.items():
        for addr in addresses:
            if addr and ipaddress.ip_address(addr).version != family:
                raise ForwardError('invalid public address')

    def checked(argv):
        out, code = run(argv)
        if code:
            raise ForwardError('forward discovery/command failed: ' + ' '.join(argv[:4]))
        return out

    def inspect():
        c = json.loads(checked(['docker', 'inspect', '--format', INSPECT_FORMAT, name]))
        if len(c) != 5 or c[1] != '/' + name or c[2] is not True or not c[0]:
            raise ForwardError('container missing, stopped or identity mismatch')
        return c

    container = inspect() if adding else None
    plans = []
    warnings = []
    for family, ipt in ((4, 'iptables'), (6, 'ip6tables')):
        prefix = [ipt, '-w', '5', '-t', 'nat']
        out, code = run(prefix + ['-S', 'PREROUTING'])
        if code:
            if adding and scopes[family]:
                raise ForwardError('required nat/PREROUTING unavailable; forward unchanged')
            warnings.append(f'IPv{family} cleanup unavailable; rules left unchanged')
            continue
        existing = rules(out, 'PREROUTING')
        owned = [r for r in existing if option(r, '--comment') == marker]
        if old and old != public and any(
                option(r, '-j') in ('DNAT', 'REDIRECT')
                and option(r, '--comment') != marker
                and overlaps(r, request['l4'], old, addr)
                for r in existing for addr in (scopes[family] or [''])):
            warnings.append(f'IPv{family} unmarked previous forward left untouched; manual review required')
        desired = []
        if adding and scopes[family]:
            docker = checked(prefix + ['-S', 'DOCKER'])
            for addr in scopes[family]:
                target = docker_destination(docker, request['l4'], listen, family, container, addr)
                for r in rules(docker, 'DOCKER') + existing:
                    if (option(r, '-j') in ('DNAT', 'REDIRECT')
                            and option(r, '--comment') != marker
                            and overlaps(r, request['l4'], public, addr)):
                        raise ForwardError('public port conflicts with an unowned NAT rule; forward unchanged')
                desired.append(['-p', request['l4'], '-m', request['l4']]
                               + (['-d', addr] if addr else [])
                               + ['--dport', public, '-m', 'addrtype', '--dst-type', 'LOCAL',
                                  '-m', 'comment', '--comment', marker,
                                  '-j', 'DNAT', '--to-destination', target])
        # iptables -S canonicalizes host addresses to /32 or /128.
        def canonical(r):
            r = list(r)
            if '-d' in r:
                i = r.index('-d') + 1
                r[i] = str(ipaddress.ip_network(r[i], strict=False))
            # -S moves -d before -p regardless of insertion order, and may
            # reorder match modules. All options in our generated rule are
            # key/value pairs; compare pairs rather than shell text/order.
            return sorted(zip(r[::2], r[1::2]))
        keep = [canonical(r) for r in desired]
        stale = []
        for r in owned:
            cr = canonical(r)
            if cr in keep:
                keep.remove(cr)  # remove duplicate owned rules as well
            else:
                stale.append(r)
        plans.append((prefix, stale, desired))
    if adding and inspect() != container:
        raise ForwardError('container changed during discovery; forward unchanged')
    # Only our own comment-tagged rules can be removed. The lock serializes
    # panel writers; xtables -w also cooperates with Docker/firewall writers.
    for prefix, stale, desired in plans:
        for r in desired:
            _, code = run(prefix + ['-C', 'PREROUTING'] + r)
            if code:
                # Do not jump ahead of existing Docker/administrator NAT.
                checked(prefix + ['-A', 'PREROUTING'] + r)
        for r in stale:
            checked(prefix + ['-D', 'PREROUTING'] + r)
        for r in desired:
            checked(prefix + ['-C', 'PREROUTING'] + r)
    try:
        changed = adding and inspect() != container
    except Exception:
        changed = True
    if changed:
        # A just-replaced IP may belong to someone else now. Withdraw only
        # the exact owned rules we applied; never leave a confirmed stale target.
        for prefix, _, desired in plans:
            for r in desired:
                checked(prefix + ['-D', 'PREROUTING'] + r)
        raise ForwardError('container changed while applying; owned forward withdrawn, retry required')
    return '; '.join(warnings)


def main():
    import fcntl
    import os
    import stat
    import sys
    try:
        # Root-owned private lock, never follow a symlink or wait indefinitely.
        fd = os.open('/run/lock/amnezia-public-forward.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            st = os.fstat(lock.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
                raise ForwardError('unsafe forwarding lock')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ForwardError('another forward operation is in progress; retry') from None
            warning = reconcile(json.loads(sys.argv[1]))
        print(json.dumps({'warning': warning}))
    except Exception as e:
        # No Docker inspect payload or arbitrary command stdout in logs/UI.
        message = str(e) if isinstance(e, ForwardError) else 'forward reconciliation failed'
        print(json.dumps({'warning': message}))
        sys.exit(1)


if __name__ == '__main__':
    main()
