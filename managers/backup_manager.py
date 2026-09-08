import json
import os
import re
import shlex
import tarfile
import tempfile
import time


class BackupManager:
    """Create/list downloadable protocol backups on the remote server.

    Backups are intentionally allowlisted per protocol and include only files
    needed to recreate protocol state: host config directories, matching
    container config directories when present, and docker inspect metadata.
    """

    BACKUP_ROOT = '/opt/amnezia/backups'
    MAX_UPLOAD_BYTES = 32 * 1024 * 1024
    BACKUP_FORMAT = 'amnezia-web-panel-protocol-v1'

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

    @classmethod
    def normalize_member_name(cls, name):
        name = str(name or '').replace('\\', '/')
        while name.startswith('./'):
            name = name[2:]
        if name in ('', '.'):
            return ''
        if name != 'backup-info.json':
            name = name.strip('/')
        else:
            name = name.lstrip('/')
        return name

    @classmethod
    def is_ignored_member_name(cls, name):
        """Skip macOS AppleDouble / Finder noise that tar may include."""
        base = os.path.basename(cls.normalize_member_name(name) or name.replace('\\', '/'))
        return base.startswith('._') or base in ('.DS_Store', 'Thumbs.db')

    @classmethod
    def is_allowed_member_path(cls, name):
        """Return True if a tar member path stays inside the backup layout."""
        name = cls.normalize_member_name(name)
        # Root entry produced by `tar -C work_dir -czf archive .`
        if name == '':
            return True
        if not name or '\0' in name:
            return False
        if name.startswith('/') or name.startswith('~'):
            return False
        parts = [p for p in name.split('/') if p not in ('', '.')]
        if not parts or any(p == '..' for p in parts):
            return False
        top = parts[0]
        if top == 'backup-info.json':
            return len(parts) == 1
        return top in ('host', 'container', 'docker')

    @classmethod
    def is_allowed_link_target(cls, member_name, linkname):
        linkname = str(linkname or '').replace('\\', '/')
        if not linkname or linkname.startswith('/') or linkname.startswith('~'):
            return False
        member_dir = os.path.dirname(cls.normalize_member_name(member_name))
        resolved = os.path.normpath(os.path.join(member_dir or '.', linkname)).replace('\\', '/')
        if resolved.startswith('../') or resolved == '..':
            return False
        return cls.is_allowed_member_path(resolved)

    def _paths_for(self, protocol, container_name):
        base = self.proto_base(protocol)
        idx = self.proto_instance(protocol)
        paths = {
            'host': [],
            'container': [],
        }

        def inst_path(path, suffix_fmt='-{idx}'):
            return path if idx <= 1 else f"{path}{suffix_fmt.format(idx=idx)}"

        if base in ('awg', 'awg2', 'awg3', 'awg_legacy'):
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
        elif base == 'exit':
            paths['host'] = [f'/opt/amnezia/{container_name}']
            paths['container'] = ['/opt/amnezia/exit', '/opt/amnezia/start.sh']
        else:
            paths['host'] = [f'/opt/amnezia/{base}']
            paths['container'] = [f'/opt/amnezia/{base}']

        return paths

    def list_backups(self, protocol):
        safe_proto = self.safe_protocol(protocol)
        backup_dir = f'{self.BACKUP_ROOT}/{safe_proto}'
        # Entire pipeline must run under sudo: `sudo mkdir && find` leaves find as cloud.
        inner = (
            f"mkdir -p {shlex.quote(backup_dir)} && "
            f"find {shlex.quote(backup_dir)} -maxdepth 1 -type f -name '*.tar.gz' "
            "-printf '%f|%s|%T@\\n' 2>/dev/null | sort -t '|' -k3,3nr"
        )
        cmd = f"bash -c {shlex.quote(inner)}"
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

        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            return {'status': 'error', 'message': err or out or 'Failed to create backup'}
        path = (out or '').strip().splitlines()[-1] if (out or '').strip() else ''
        name = path.rsplit('/', 1)[-1] if path else ''
        if not name or not path.startswith(self.BACKUP_ROOT):
            return {'status': 'error', 'message': err or out or 'Backup archive was not created'}
        return {'status': 'success', 'protocol': protocol, 'backup': {'name': name, 'path': path}}

    @classmethod
    def inspect_archive(cls, path):
        """Validate layout/metadata of a protocol backup archive.

        Rejects tar-slip paths, absolute members, and link targets that escape
        the allowlisted backup tree before any remote extract runs.
        """
        try:
            with tarfile.open(path, 'r:gz') as archive:
                members = archive.getmembers()
                if not members:
                    return {'status': 'error', 'message': 'Invalid backup archive'}
                info_member = None
                for member in members:
                    if cls.is_ignored_member_name(member.name):
                        continue
                    if not cls.is_allowed_member_path(member.name):
                        return {'status': 'error', 'message': 'Backup archive contains unsafe paths'}
                    normalized = cls.normalize_member_name(member.name)
                    if normalized == '':
                        if not member.isdir():
                            return {'status': 'error', 'message': 'Backup archive contains unsafe paths'}
                        continue
                    if member.issym() or member.islnk():
                        if not cls.is_allowed_link_target(member.name, member.linkname):
                            return {'status': 'error', 'message': 'Backup archive contains unsafe paths'}
                    elif not (member.isfile() or member.isdir()):
                        return {'status': 'error', 'message': 'Backup archive contains unsupported entries'}
                    if normalized == 'backup-info.json':
                        if not member.isfile() or member.size > 65536:
                            return {'status': 'error', 'message': 'Invalid backup archive'}
                        info_member = member
                if info_member is None:
                    return {'status': 'error', 'message': 'Invalid backup archive'}
                raw = archive.extractfile(info_member)
                if raw is None:
                    return {'status': 'error', 'message': 'Invalid backup archive'}
                info = json.loads(raw.read().decode('utf-8'))
        except (tarfile.TarError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return {'status': 'error', 'message': 'Invalid backup archive'}
        if not isinstance(info, dict):
            return {'status': 'error', 'message': 'Invalid backup archive'}
        if str(info.get('backup_format') or '') != cls.BACKUP_FORMAT:
            return {'status': 'error', 'message': 'Unsupported backup format'}
        return {'status': 'success', 'info': info}

    def _fetch_remote_archive(self, remote_path):
        """Copy a remote backup to a local temp file for validation."""
        filename = os.path.basename(remote_path)
        safe_name = self.safe_filename(filename)
        if not safe_name:
            return None, 'Invalid backup filename'
        tmp_remote = f'/tmp/_amnz_validate_{safe_name}'
        quoted_remote = shlex.quote(remote_path)
        quoted_tmp = shlex.quote(tmp_remote)
        _, err, code = self.ssh.run_sudo_command(
            f"test -f {quoted_remote} && cp {quoted_remote} {quoted_tmp} && chmod 0644 {quoted_tmp}"
        )
        if code != 0:
            return None, err or 'Backup not found'
        fd, local_path = tempfile.mkstemp(prefix='amnezia-backup-validate-', suffix='.tar.gz')
        os.close(fd)
        try:
            self.ssh.ensure_connected()
            sftp = self.ssh.client.open_sftp()
            try:
                sftp.get(tmp_remote, local_path)
            finally:
                sftp.close()
                self.ssh.run_sudo_command(f"rm -f {quoted_tmp}")
            return local_path, None
        except Exception as exc:
            try:
                os.remove(local_path)
            except OSError:
                pass
            self.ssh.run_sudo_command(f"rm -f {quoted_tmp}")
            return None, str(exc) or 'Failed to read backup archive'

    def upload_backup(self, protocol, filename, local_path):
        inspected = self.inspect_archive(local_path)
        if inspected.get('status') != 'success':
            return inspected
        info = inspected.get('info') or {}
        archived_proto = str(info.get('protocol') or '')
        if archived_proto != str(protocol):
            return {'status': 'error', 'message': 'Backup protocol mismatch'}

        safe_proto = self.safe_protocol(protocol)
        safe_name = self.safe_filename(os.path.basename(filename or ''))
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        if not safe_name:
            safe_name = f'{safe_proto}-{stamp}.tar.gz'
        backup_dir = f'{self.BACKUP_ROOT}/{safe_proto}'
        dest = f'{backup_dir}/{safe_name}'
        dest_q = shlex.quote(dest)
        _, _, exists_code = self.ssh.run_sudo_command(f'test -f {dest_q}')
        if exists_code == 0:
            safe_name = f'{safe_proto}-{stamp}.tar.gz'
            dest = f'{backup_dir}/{safe_name}'
            dest_q = shlex.quote(dest)
        tmp_remote = f'/tmp/_amnz_upload_{safe_name}'
        tmp_q = shlex.quote(tmp_remote)
        self.ssh.ensure_connected()
        sftp = self.ssh.client.open_sftp()
        try:
            sftp.put(local_path, tmp_remote)
        finally:
            sftp.close()
        backup_dir_q = shlex.quote(backup_dir)
        inner = (
            f'mkdir -p {backup_dir_q} && '
            f'mv {tmp_q} {dest_q} && chmod 0644 {dest_q}'
        )
        out, err, code = self.ssh.run_sudo_command(f'bash -c {shlex.quote(inner)}')
        if code != 0:
            self.ssh.run_sudo_command(f'rm -f {tmp_q}')
            return {'status': 'error', 'message': err or out or 'Failed to upload backup'}
        return {'status': 'success', 'protocol': protocol, 'backup': {'name': safe_name, 'path': dest}}

    def delete_backup(self, protocol, filename):
        safe_proto = self.safe_protocol(protocol)
        safe_name = self.safe_filename(filename)
        if not safe_name:
            return {'status': 'error', 'message': 'Invalid backup filename'}
        remote_path = f'{self.BACKUP_ROOT}/{safe_proto}/{safe_name}'
        quoted = shlex.quote(remote_path)
        inner = f'test -f {quoted} && rm -f {quoted}'
        out, err, code = self.ssh.run_sudo_command(f'bash -c {shlex.quote(inner)}')
        if code != 0:
            return {'status': 'error', 'message': err or out or 'Backup not found'}
        return {'status': 'success', 'protocol': protocol, 'filename': safe_name}

    def restore_backup(self, protocol, container_name, filename):
        safe_proto = self.safe_protocol(protocol)
        safe_name = self.safe_filename(filename)
        if not safe_name:
            return {'status': 'error', 'message': 'Invalid backup filename'}
        backup_dir = f'{self.BACKUP_ROOT}/{safe_proto}'
        remote_path = f'{backup_dir}/{safe_name}'
        local_path, fetch_err = self._fetch_remote_archive(remote_path)
        if not local_path:
            return {'status': 'error', 'message': fetch_err or 'Backup not found'}
        try:
            inspected = self.inspect_archive(local_path)
            if inspected.get('status') != 'success':
                return inspected
            info = inspected.get('info') or {}
            if str(info.get('protocol') or '') != str(protocol):
                return {'status': 'error', 'message': 'Backup protocol mismatch'}
        finally:
            try:
                os.remove(local_path)
            except OSError:
                pass

        paths = self._paths_for(protocol, container_name)
        filename_q = shlex.quote(safe_name)
        backup_dir_q = shlex.quote(backup_dir)
        container_q = shlex.quote(str(container_name or ''))

        host_restore_cmds = ''
        for dest in paths['host']:
            dest_q = shlex.quote(dest)
            src = f'$work_dir/host{dest}'
            # Replace host path when present in backup; remove when absent
            # so restore is idempotent with the archived state.
            host_restore_cmds += (
                f'if [ -d "{src}" ]; then\n'
                f'  mkdir -p "$(dirname {dest_q})"\n'
                f'  [ -e {dest_q} ] && rm -rf {dest_q}\n'
                f'  cp -a "{src}" {dest_q}\n'
                f'elif [ -e {dest_q} ]; then\n'
                f'  rm -rf {dest_q}\n'
                f'fi\n'
            )

        container_restore_cmds = ''
        for dest in paths['container']:
            dest_q = shlex.quote(dest)
            # Prefer container snapshot; fall back to host copy of the same path.
            # Replace via tar-stream so contents are fully overwritten (docker cp
            # of a directory is easy to get wrong / nest).
            container_restore_cmds += f"""
src="$work_dir/container{dest}"
host_src="$work_dir/host{dest}"
dest={dest_q}
if [ ! -d "$src" ] && [ -d "$host_src" ]; then
  src="$host_src"
fi
if [ -d "$src" ]; then
  docker exec "$container" rm -rf "$dest"
  docker exec "$container" mkdir -p "$dest"
  tar -C "$src" -cf - . | docker exec -i "$container" tar -C "$dest" -xf -
elif [ -f "$src" ] || [ -f "$host_src" ]; then
  if [ ! -f "$src" ]; then src="$host_src"; fi
  docker exec "$container" mkdir -p "$(dirname "$dest")"
  docker cp "$src" "$container:$dest"
else
  docker exec "$container" rm -rf "$dest"
fi
"""

        # Defense in depth: refuse absolute / traversal members before extract,
        # then keep extraction rooted under $work_dir.
        script = f"""
set -eu
umask 077
container={container_q}
backup_dir={backup_dir_q}
archive="$backup_dir/{filename_q}"
work_dir=$(mktemp -d /tmp/amnezia-restore-XXXXXX)
cleanup() {{ rm -rf "$work_dir"; }}
trap cleanup EXIT

if [ ! -f "$archive" ]; then
  echo "Backup not found: $archive" >&2
  exit 1
fi

while IFS= read -r member; do
  case "$member" in
    *..*|/*|~*)
      echo "Unsafe archive member: $member" >&2
      exit 1
      ;;
  esac
  member="${{member#./}}"
  base="${{member##*/}}"
  case "$base" in
    ._*|.DS_Store|Thumbs.db) continue ;;
  esac
  case "$member" in
    ''|.) continue ;;
    backup-info.json|host|host/*|container|container/*|docker|docker/*) ;;
    *)
      echo "Unsafe archive member: $member" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "$archive")

tar -C "$work_dir" -xzf "$archive"
# Fail closed if anything landed outside the work dir (symlink escapes, etc.).
while IFS= read -r -d '' path; do
  case "$path" in
    "$work_dir"|"$work_dir"/*) ;;
    *)
      echo "Extract escaped work dir: $path" >&2
      exit 1
      ;;
  esac
done < <(find "$work_dir" -print0)

{host_restore_cmds}

if [ -n "$container" ] && docker inspect "$container" >/dev/null 2>&1; then
  if ! docker start "$container" >/dev/null 2>&1; then
    echo "Failed to start container $container for restore" >&2
    exit 1
  fi
  # Stop VPN interfaces before replacing on-disk config so awg/wg do not
  # keep old peers alive across a partial file replace.
  docker exec "$container" sh -c '
    for p in /opt/amnezia/awg/awg0.conf /opt/amnezia/awg/wg0.conf /opt/amnezia/wireguard/wg0.conf; do
      [ -f "$p" ] || continue
      awg-quick down "$p" 2>/dev/null || true
      wg-quick down "$p" 2>/dev/null || true
    done
    true
  ' >/dev/null 2>&1 || true
{container_restore_cmds}
  if ! docker restart "$container" >/dev/null 2>&1; then
    echo "Failed to restart container $container after restore" >&2
    exit 1
  fi
fi

echo "restore_success"
""".strip()

        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            return {'status': 'error', 'message': err or out or 'Failed to restore backup'}
        return {'status': 'success', 'protocol': protocol, 'filename': filename}
