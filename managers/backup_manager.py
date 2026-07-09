import json
import re
import shlex


class BackupManager:
    """Create/list downloadable protocol backups on the remote server.

    Backups are intentionally allowlisted per protocol and include only files
    needed to recreate protocol state: host config directories, matching
    container config directories when present, and docker inspect metadata.
    """

    BACKUP_ROOT = '/opt/amnezia/backups'

    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    @staticmethod
    def proto_base(protocol):
        return str(protocol or '').split('__', 1)[0]

    @staticmethod
    def proto_instance(protocol):
        match = re.search(r'__(\d+)$', str(protocol or ''))
        return int(match.group(1)) if match else 1

    @staticmethod
    def safe_protocol(protocol):
        safe = re.sub(r'[^a-zA-Z0-9_.-]+', '_', str(protocol or '').replace('__', '-'))
        return safe.strip('._-') or 'protocol'

    @staticmethod
    def safe_filename(filename):
        name = str(filename or '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.tar\.gz', name):
            return None
        return name

    def _paths_for(self, protocol, container_name):
        base = self.proto_base(protocol)
        idx = self.proto_instance(protocol)
        paths = {
            'host': [],
            'container': [],
        }

        def inst_path(path, suffix_fmt='-{idx}'):
            return path if idx <= 1 else f"{path}{suffix_fmt.format(idx=idx)}"

        if base in ('awg', 'awg2', 'awg_legacy'):
            paths['host'] = ['/opt/amnezia/awg', f'/opt/amnezia/{container_name}']
            paths['container'] = ['/opt/amnezia/awg', '/opt/amnezia/start.sh']
        elif base == 'wireguard':
            paths['host'] = ['/opt/amnezia/wireguard', f'/opt/amnezia/{container_name}']
            paths['container'] = ['/opt/amnezia/wireguard', '/opt/amnezia/start.sh']
        elif base == 'xray':
            config_dir = inst_path('/opt/amnezia/xray')
            paths['host'] = [config_dir, f'/opt/amnezia/{container_name}']
            paths['container'] = [config_dir]
        elif base == 'telemt':
            remote_dir = inst_path('/opt/amnezia/telemt')
            paths['host'] = [remote_dir]
            paths['container'] = [remote_dir]
        elif base == 'dns':
            paths['host'] = ['/opt/amnezia/dns']
            paths['container'] = ['/opt/amnezia/dns']
        elif base == 'adguard':
            paths['host'] = ['/opt/amnezia/adguard']
            paths['container'] = ['/opt/adguardhome/conf', '/opt/adguardhome/work']
        elif base == 'socks5':
            config_dir = inst_path('/opt/amnezia/socks5proxy')
            paths['host'] = [config_dir]
            paths['container'] = ['/etc/3proxy']
        elif base == 'nginx':
            paths['host'] = ['/opt/amnezia/nginx']
            paths['container'] = ['/etc/nginx/conf.d', '/usr/share/nginx/html']
        else:
            paths['host'] = [f'/opt/amnezia/{base}']
            paths['container'] = [f'/opt/amnezia/{base}']

        return paths

    def list_backups(self, protocol):
        safe_proto = self.safe_protocol(protocol)
        backup_dir = f'{self.BACKUP_ROOT}/{safe_proto}'
        cmd = (
            f"mkdir -p {shlex.quote(backup_dir)} && "
            f"find {shlex.quote(backup_dir)} -maxdepth 1 -type f -name '*.tar.gz' "
            "-printf '%f|%s|%T@\\n' 2>/dev/null | sort -t '|' -k3,3nr"
        )
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0:
            return {'status': 'error', 'message': err or out or 'Failed to list backups'}
        backups = []
        for line in (out or '').splitlines():
            parts = line.split('|')
            if len(parts) != 3:
                continue
            name, size, mtime = parts
            backups.append({
                'name': name,
                'size': int(float(size or 0)),
                'mtime': float(mtime or 0),
            })
        return {'status': 'success', 'protocol': protocol, 'backups': backups}

    def create_backup(self, protocol, container_name):
        safe_proto = self.safe_protocol(protocol)
        backup_dir = f'{self.BACKUP_ROOT}/{safe_proto}'
        paths = self._paths_for(protocol, container_name)
        host_paths = ' '.join(shlex.quote(p) for p in paths['host'])
        container_paths = ' '.join(shlex.quote(p) for p in paths['container'])
        protocol_q = shlex.quote(str(protocol))
        safe_proto_q = shlex.quote(safe_proto)
        container_q = shlex.quote(str(container_name or ''))
        backup_dir_q = shlex.quote(backup_dir)

        script = f"""
set -eu
umask 077
protocol={protocol_q}
safe_proto={safe_proto_q}
container={container_q}
backup_dir={backup_dir_q}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
work_dir=$(mktemp -d /tmp/amnezia-backup-${{safe_proto}}.XXXXXX)
cleanup() {{ rm -rf "$work_dir"; }}
trap cleanup EXIT
mkdir -p "$backup_dir" "$work_dir/host" "$work_dir/container" "$work_dir/docker"
cat > "$work_dir/backup-info.json" <<EOF
{{
  "protocol": "$protocol",
  "container": "$container",
  "created_at_utc": "$timestamp",
  "backup_format": "amnezia-web-panel-protocol-v1"
}}
EOF
copy_host_path() {{
  src="$1"
  if [ -e "$src" ]; then
    mkdir -p "$work_dir/host$(dirname "$src")"
    cp -a "$src" "$work_dir/host$src"
  fi
}}
copy_container_path() {{
  src="$1"
  if [ -n "$container" ] && docker inspect "$container" >/dev/null 2>&1; then
    mkdir -p "$work_dir/container$(dirname "$src")"
    docker cp "$container:$src" "$work_dir/container$src" >/dev/null 2>&1 || true
  fi
}}
for p in {host_paths}; do copy_host_path "$p"; done
for p in {container_paths}; do copy_container_path "$p"; done
if [ -n "$container" ] && docker inspect "$container" >/dev/null 2>&1; then
  docker inspect "$container" > "$work_dir/docker/inspect.json" 2>/dev/null || true
  docker logs --tail 300 "$container" > "$work_dir/docker/logs-tail.txt" 2>&1 || true
fi
archive="$backup_dir/${{safe_proto}}-${{timestamp}}.tar.gz"
tar -C "$work_dir" -czf "$archive" .
chmod 0644 "$archive"
printf '%s\n' "$archive"
""".strip()

        out, err, code = self.ssh.run_sudo_command(script)
        if code != 0:
            return {'status': 'error', 'message': err or out or 'Failed to create backup'}
        path = (out or '').strip().splitlines()[-1] if (out or '').strip() else ''
        name = path.rsplit('/', 1)[-1] if path else ''
        return {'status': 'success', 'protocol': protocol, 'backup': {'name': name, 'path': path}}
