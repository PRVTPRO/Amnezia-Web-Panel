"""Copy a running AmneziaWG instance from one server to another.

The copy keeps peers, keys and panel settings "as is": only the ListenPort and
the container/instance identifiers change. The source server is never modified.

The transfer is deliberately independent from ``BackupManager``: a backup
archive is tied to its protocol key (``Backup protocol mismatch``) and would
leave an extra archive on the target. Here the container state is streamed
directly, patched on the panel and pushed into a fresh container.
"""
import logging
import os
import re
import shlex
import tarfile
import tempfile
import time

logger = logging.getLogger(__name__)

AWG_BASES = ('awg', 'awg2', 'awg3')
AWG_IFACE = 'awg0'
CONTAINER_NAMES = {
    'awg': 'amnezia-awg',
    'awg2': 'amnezia-awg2',
    'awg3': 'amnezia-awg3',
}
CONFIG_DIR = '/opt/amnezia/awg'
START_SCRIPT = '/opt/amnezia/start.sh'
MIN_PORT = 1024
MAX_PORT = 65535

# (step number, stage name) for the progress bar. The UI shows "step N of M".
COPY_STEPS = 8


class InstanceCopyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class CopyCancelled(InstanceCopyError):
    def __init__(self):
        super().__init__('cancelled', 'copy cancelled by user')


def proto_base(protocol):
    return str(protocol or '').split('__', 1)[0]


def proto_instance(protocol):
    match = re.search(r'__(\d+)$', str(protocol or ''))
    return int(match.group(1)) if match else 1


def container_name(base, index):
    name = CONTAINER_NAMES.get(base)
    if not name:
        raise InstanceCopyError('unsupported', 'Only AmneziaWG instances can be copied')
    return name if index <= 1 else '%s-%d' % (name, index)


def next_instance(protocols, base):
    """Lowest free instance index for a base protocol on the target."""
    used = {proto_instance(key) for key in (protocols or {}) if proto_base(key) == base}
    index = 1
    while index in used:
        index += 1
    return index


def parse_listen_port(config_text):
    match = re.search(r'^ListenPort\s*=\s*(\d+)', config_text or '', re.M)
    return int(match.group(1)) if match else None


def patch_listen_port(config_text, port):
    """Rewrite the single ListenPort line; anything else stays byte-identical."""
    pattern = re.compile(r'^ListenPort\s*=\s*\d+\s*$', re.M)
    patched, count = pattern.subn('ListenPort = %d' % int(port), config_text)
    if count != 1:
        raise InstanceCopyError(
            'config_invalid',
            'Server config must contain exactly one ListenPort line (found %d)' % count,
        )
    return patched


def parse_used_ports(*outputs):
    """UDP ports mentioned by `ss -lun` / `docker ps` output.

    ``docker ps`` prints published ports as ``0.0.0.0:50808->50808/udp``, so the
    port may be followed by an arrow, not only by whitespace.
    """
    ports = set()
    for output in outputs:
        for match in re.finditer(r':(\d{2,5})(?!\d)', (output or '') + ' '):
            port = int(match.group(1))
            if MIN_PORT <= port <= MAX_PORT:
                ports.add(port)
    return ports


def pick_port(source_port, used):
    """Prefer the source port; otherwise the first free port at or above it."""
    if source_port and int(source_port) not in used:
        return int(source_port)
    start = max(MIN_PORT, int(source_port or MIN_PORT))
    for port in range(start, MAX_PORT + 1):
        if port not in used:
            return port
    for port in range(MIN_PORT, start):
        if port not in used:
            return port
    raise InstanceCopyError('no_free_port', 'No free UDP port on the target server')


class InstanceCopier:
    """Runs on the panel: pulls state from one agent, pushes it to another."""

    def __init__(self, source_ssh, target_ssh):
        self.source_ssh = source_ssh
        self.target_ssh = target_ssh

    # ---- remote helpers -------------------------------------------------

    def _sudo(self, ssh, command, timeout=120):
        return ssh.run_sudo_command(command, timeout=timeout)

    def _sftp_get(self, ssh, remote_path, local_path):
        ssh.ensure_connected()
        sftp = ssh.client.open_sftp()
        try:
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()

    def _sftp_put(self, ssh, local_path, remote_path):
        ssh.ensure_connected()
        sftp = ssh.client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

    def used_udp_ports(self):
        ss_out, _, _ = self._sudo(self.target_ssh, 'ss -lun 2>/dev/null || netstat -lun 2>/dev/null')
        ps_out, _, _ = self._sudo(
            self.target_ssh,
            "docker ps --format '{{.Ports}}' 2>/dev/null",
        )
        return parse_used_ports(ss_out, ps_out)

    def inspect_container(self, ssh, container):
        # --type container matters: `docker inspect amnezia-awg3` also matches the
        # image of that name and would fake a name collision on the target.
        out, _, code = self._sudo(
            ssh, 'docker inspect --type container %s 2>/dev/null' % shlex.quote(container))
        if code != 0 or not (out or '').strip():
            return None
        import json
        try:
            parsed = json.loads(out)
        except ValueError:
            return None
        return parsed[0] if isinstance(parsed, list) and parsed else None

    def count_peers(self, ssh, container):
        out, _, code = self._sudo(
            ssh,
            "docker exec %s sh -c %s"
            % (shlex.quote(container),
               shlex.quote('grep -c "^\\[Peer\\]" %s/awg0.conf' % CONFIG_DIR)),
        )
        # `grep -c` prints 0 and exits 1 when there is no match: a fresh
        # instance without peers is valid, not unreadable.
        if code not in (0, 1):
            return None
        try:
            return int((out or '').strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None

    def disk_free_mb(self):
        out, _, _ = self._sudo(self.target_ssh, 'df -Pm /var/lib/docker 2>/dev/null | tail -1')
        parts = (out or '').split()
        try:
            return int(parts[3])
        except (IndexError, ValueError):
            return None

    # ---- planning -------------------------------------------------------

    def read_config(self, container):
        out, err, code = self._sudo(
            self.source_ssh,
            'docker exec %s cat %s/awg0.conf' % (shlex.quote(container), CONFIG_DIR),
        )
        if code != 0:
            raise InstanceCopyError('state_unreadable', err or 'Cannot read the source config')
        return out

    def plan(self, source_key, source_container, target_protocols):
        """Resolve names/port for a copy. No side effects on either server."""
        base = proto_base(source_key)
        if base not in AWG_BASES:
            raise InstanceCopyError(
                'unsupported', 'Only AmneziaWG instances can be copied (got %s)' % base)

        info = self.inspect_container(self.source_ssh, source_container)
        if info is None:
            raise InstanceCopyError('source_missing', 'Source container is not running')
        if not (info.get('State') or {}).get('Running'):
            raise InstanceCopyError('source_stopped', 'Source container is stopped')

        config_text = self.read_config(source_container)
        source_port = parse_listen_port(config_text)
        peers = self.count_peers(self.source_ssh, source_container)
        if peers is None:
            raise InstanceCopyError('state_unreadable', 'Cannot count the source peers')

        used = self.used_udp_ports()
        port = pick_port(source_port, used)
        index = next_instance(target_protocols, base)
        target_container = container_name(base, index)
        if self.inspect_container(self.target_ssh, target_container) is not None:
            raise InstanceCopyError(
                'name_taken',
                'A container named %s already exists on the target' % target_container) 
        image = ((info.get('Config') or {}).get('Image') or source_container)

        image_out, _, image_code = self._sudo(
            self.target_ssh, 'docker image inspect %s >/dev/null 2>&1' % shlex.quote(image))
        image_present = image_code == 0
        image_bytes = None
        if not image_present:
            size_out, _, _ = self._sudo(
                self.source_ssh,
                "docker image inspect -f '{{.Size}}' %s 2>/dev/null" % shlex.quote(image))
            try:
                image_bytes = int((size_out or '').strip())
            except ValueError:
                image_bytes = None

        warnings = []
        if port != source_port:
            warnings.append('port_in_use')
        if not image_present:
            warnings.append('image_transfer')
        return {
            'base': base,
            'source_key': source_key,
            'source_container': source_container,
            'source_port': source_port,
            'target_index': index,
            'target_key': base if index <= 1 else '%s__%d' % (base, index),
            'target_container': target_container,
            'port': port,
            'peers': peers,
            'image': image,
            'image_present': image_present,
            'image_bytes': image_bytes,
            'disk_free_mb': self.disk_free_mb(),
            'warnings': warnings,
        }

    # ---- execution ------------------------------------------------------

    def execute(self, plan, log, should_cancel=None):
        workdir = tempfile.mkdtemp(prefix='amnezia-copy-')
        created = False

        def check():
            if should_cancel and should_cancel():
                raise CopyCancelled()

        try:
            check()
            log('inspecting', 'reading the source container state')
            artifact = os.path.join(workdir, 'state.tar')
            self._export_state(plan, artifact, check)

            check()
            log('patching', 'setting ListenPort = %d' % plan['port'])
            self._patch_archive(artifact, plan['port'], workdir)

            check()
            self._ensure_image(plan, log, check)

            check()
            log('creating', 'creating %s' % plan['target_container'])
            self._create_container(plan)
            created = True

            check()
            log('uploading', 'uploading the server state')
            self._push_state(plan, artifact, check)

            log('starting', 'restarting %s to apply the copied state' % plan['target_container'])
            self._restart_container(plan)

            log('verifying', 'checking the tunnel and peers')
            self._verify(plan, log, check)
            log('done', 'copy finished')
            return {
                'container': plan['target_container'],
                'port': plan['port'],
                'peers': plan['peers'],
            }
        except BaseException:
            if created:
                try:
                    self.destroy(plan)
                except Exception:
                    # A dead target must not hide the error that caused the
                    # rollback: report it and leave the container to the admin.
                    logger.warning('instance copy: rollback failed', exc_info=True)
            raise
        finally:
            self._remove_tree(workdir)

    @staticmethod
    def _remove_tree(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)

    def destroy(self, plan):
        """Remove the container this operation created (never a foreign one)."""
        self._sudo(
            self.target_ssh,
            'docker rm -f %s >/dev/null 2>&1; true' % shlex.quote(plan['target_container']),
        )

    def _export_state(self, plan, local_path, check=None):
        token = os.urandom(6).hex()
        # The tar is written as root but downloaded over SFTP as the SSH user.
        # A private staging directory plus chown keeps the archive unreadable to
        # other local users and still readable for a non-root sudo account.
        stage = self.source_ssh._make_private_temp_dir()
        remote_tmp = stage + '/state.tar'
        quoted_tmp = shlex.quote(remote_tmp)
        exclude = (
            "--exclude='awg0.conf.bak.*' --exclude='awg/warp' "
            "--exclude='awg/warp-link-*'"
        )
        inner = (
            'docker exec %s tar -C /opt/amnezia %s -cf - awg start.sh > %s'
            % (shlex.quote(plan['source_container']), exclude, quoted_tmp)
        )
        if check:
            check()
        try:
            out, err, code = self._sudo(
                self.source_ssh, 'sh -c %s' % shlex.quote(inner), timeout=180)
            if code != 0:
                raise InstanceCopyError(
                    'export_failed', err or out or 'Cannot export the container state')
            user = shlex.quote(str(getattr(self.source_ssh, 'username', '') or 'root'))
            self._sudo(self.source_ssh,
                       'chown %s %s && chmod 0600 %s' % (user, quoted_tmp, quoted_tmp))
            self._sftp_get(self.source_ssh, remote_tmp, local_path)
        finally:
            self._sudo(self.source_ssh, 'rm -rf ' + shlex.quote(stage))
        if not os.path.getsize(local_path):
            raise InstanceCopyError('export_failed', 'The exported state is empty')

    def _patch_archive(self, archive_path, port, workdir):
        extract_dir = os.path.join(workdir, 'state')
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(archive_path, 'r:') as archive:
            archive.extractall(extract_dir, filter='data')
        config_path = os.path.join(extract_dir, 'awg', 'awg0.conf')
        with open(config_path, 'r', encoding='utf-8', errors='surrogateescape') as handle:
            config_text = handle.read()
        patched = patch_listen_port(config_text, port)
        if patched != config_text:
            with open(config_path, 'w', encoding='utf-8', errors='surrogateescape') as handle:
                handle.write(patched)
        patched_tar = os.path.join(workdir, 'state-patched.tar')
        with tarfile.open(patched_tar, 'w') as archive:
            for name in ('awg', 'start.sh'):
                archive.add(os.path.join(extract_dir, name), arcname=name)
        os.replace(patched_tar, archive_path)

    def _ensure_image(self, plan, log, check=None):
        if plan.get('image_present'):
            return
        if check:
            check()
        log('image', 'copying docker image %s' % plan['image'])
        token = os.urandom(6).hex()
        # The panel may run on the source host itself: a local /tmp path with the
        # same name as the remote one would be truncated by sftp.get before it is
        # read (same file, write handle first). Always stage inside a fresh dir.
        stage = tempfile.mkdtemp(prefix='amnezia-image-')
        local = os.path.join(stage, 'image.tar.gz')
        src_tmp = '/tmp/amnezia-image-%s.tar.gz' % token
        dst_tmp = '/tmp/amnezia-image-%s.tar.gz' % token
        try:
            inner = 'docker save %s | gzip -1 > %s' % (
                shlex.quote(plan['image']), shlex.quote(src_tmp))
            out, err, code = self._sudo(self.source_ssh, 'sh -c %s' % shlex.quote(inner), timeout=600)
            if code != 0:
                raise InstanceCopyError('image_export_failed', err or out or 'docker save failed')
            self._sftp_get(self.source_ssh, src_tmp, local)
            self._sftp_put(self.target_ssh, local, dst_tmp)
            out, err, code = self._sudo(
                self.target_ssh, 'sh -c %s' % shlex.quote('gunzip -c %s | docker load'
                                                        % shlex.quote(dst_tmp)),
                timeout=600)
            if code != 0:
                raise InstanceCopyError('image_load_failed', err or out or 'docker load failed')
        finally:
            self._sudo(self.source_ssh, 'rm -f ' + shlex.quote(src_tmp))
            self._sudo(self.target_ssh, 'rm -f ' + shlex.quote(dst_tmp))
            self._remove_tree(stage)

    def _create_container(self, plan):
        from managers.awg_manager import AWGManager
        info = self.inspect_container(self.source_ssh, plan['source_container'])
        if info is None:
            raise InstanceCopyError('source_missing', 'Source container disappeared')
        command = AWGManager._run_cmd_from_inspect(
            info, plan['target_container'], plan['image'], port_override=plan['port'])
        if not command:
            raise InstanceCopyError('create_failed', 'Cannot rebuild the docker run command')
        out, err, code = self._sudo(self.target_ssh, command, timeout=180)
        if code != 0:
            raise InstanceCopyError('create_failed', err or out or 'docker run failed')

    def _push_state(self, plan, archive_path, check=None):
        if check:
            check()
        token = os.urandom(6).hex()
        remote_tar = '/tmp/amnezia-copy-%s.tar' % token
        self._sftp_put(self.target_ssh, archive_path, remote_tar)
        try:
            inner = 'docker cp %s %s:/tmp/amnezia-state.tar' % (
                shlex.quote(remote_tar), shlex.quote(plan['target_container']))
            out, err, code = self._sudo(
                self.target_ssh, 'sh -c %s' % shlex.quote(inner), timeout=180)
            if code != 0:
                raise InstanceCopyError('upload_failed', err or out or 'docker cp failed')
            inner = (
                'docker exec %s sh -c %s'
                % (shlex.quote(plan['target_container']),
                   shlex.quote('tar -C /opt/amnezia -xf /tmp/amnezia-state.tar'
                               ' && chmod +x /opt/amnezia/start.sh'
                               ' && rm -f /tmp/amnezia-state.tar'))
            )
            out, err, code = self._sudo(self.target_ssh, inner, timeout=180)
            if code != 0:
                raise InstanceCopyError('upload_failed', err or out or 'Cannot unpack the state')
        finally:
            self._sudo(self.target_ssh, 'rm -f ' + shlex.quote(remote_tar))

    def _restart_container(self, plan):
        # The container was created with `docker run -d` and its start script
        # already ran against the image config. The copied state only becomes
        # live after a restart, so `docker start` (a no-op for a running
        # container) is not enough.
        out, err, code = self._sudo(
            self.target_ssh,
            'docker restart %s' % shlex.quote(plan['target_container']),
            timeout=120,
        )
        if code != 0:
            raise InstanceCopyError('start_failed', err or out or 'docker restart failed')

    def _tunnel_state(self, plan):
        """(interface_up, listening, peers) of the target container."""
        container = shlex.quote(plan['target_container'])
        show_out, _, _ = self._sudo(
            self.target_ssh, 'docker exec %s awg show %s' % (container, AWG_IFACE))
        peers = self.count_peers(self.target_ssh, plan['target_container'])
        interface_up = AWG_IFACE in (show_out or '')
        listening = False
        match = re.search(r'listening port:\s*(\d+)', show_out or '')
        if match:
            # Authoritative: taken from the interface itself, works without a
            # host userland proxy (hardened bridges often disable it).
            listening = int(match.group(1)) == int(plan['port'])
        else:
            listen_out, _, _ = self._sudo(
                self.target_ssh,
                'sh -c %s' % shlex.quote("ss -lun 2>/dev/null | grep -c ':%d '" % plan['port']),
            )
            listening = _count_ok(listen_out)
        return interface_up, listening, peers

    def _verify(self, plan, log, check):
        last = None
        for attempt in range(3):
            check()
            last = self._tunnel_state(plan)
            interface_up, listening, peers = last
            if interface_up and listening and peers == plan['peers']:
                return
            if not interface_up and attempt == 0:
                log('tools', 'the target image ships older awg tools; copying them from the source')
                self._copy_tools(plan)
                self._sudo(
                    self.target_ssh,
                    'docker restart %s' % shlex.quote(plan['target_container']),
                    timeout=120,
                )
            time.sleep(2)
        interface_up, listening, peers = last or (False, False, None)
        if not interface_up:
            raise InstanceCopyError(
                'tunnel_down',
                'The target tunnel did not come up (awg tools or kernel mismatch)')
        if not listening:
            raise InstanceCopyError(
                'port_not_listening',
                'The target container does not listen on port %d' % plan['port'])
        raise InstanceCopyError(
            'peer_mismatch',
            'Expected %d peers on the target, found %s' % (plan['peers'], peers))

    def _copy_tools(self, plan):
        """Carry /usr/bin/awg* when the target image ships older tools."""
        token = os.urandom(6).hex()
        remote_tmp = '/tmp/amnezia-tools-%s.tar' % token
        # Same-host copies: never reuse the remote name for the local staging file.
        stage = tempfile.mkdtemp(prefix='amnezia-tools-')
        local = os.path.join(stage, 'tools.tar')
        inner = 'docker exec %s tar -C /usr/bin -cf - awg awg-quick > %s' % (
            shlex.quote(plan['source_container']), shlex.quote(remote_tmp))
        out, err, code = self._sudo(self.source_ssh, 'sh -c %s' % shlex.quote(inner), timeout=120)
        if code != 0:
            raise InstanceCopyError('tools_failed', err or out or 'Cannot export awg tools')
        try:
            self._sftp_get(self.source_ssh, remote_tmp, local)
            target_tmp = '/tmp/amnezia-tools-%s.tar' % token
            self._sftp_put(self.target_ssh, local, target_tmp)
            try:
                inner = 'docker cp %s %s:/tmp/amnezia-tools.tar' % (
                    shlex.quote(target_tmp), shlex.quote(plan['target_container']))
                out, err, code = self._sudo(self.target_ssh, 'sh -c %s' % shlex.quote(inner))
                if code != 0:
                    raise InstanceCopyError('tools_failed', err or out or 'docker cp failed')
                inner = (
                    'docker exec %s sh -c %s'
                    % (shlex.quote(plan['target_container']),
                       shlex.quote('tar -C /usr/bin -xf /tmp/amnezia-tools.tar'
                                   ' && chmod +x /usr/bin/awg /usr/bin/awg-quick'
                                   ' && rm -f /tmp/amnezia-tools.tar'))
                )
                out, err, code = self._sudo(self.target_ssh, inner)
                if code != 0:
                    raise InstanceCopyError('tools_failed', err or out or 'Cannot install awg tools')
            finally:
                self._sudo(self.target_ssh, 'rm -f ' + shlex.quote(target_tmp))
        finally:
            self._sudo(self.source_ssh, 'rm -f ' + shlex.quote(remote_tmp))
            self._remove_tree(stage)


def _count_ok(text):
    try:
        return int((text or '').strip()) > 0
    except ValueError:
        return False
