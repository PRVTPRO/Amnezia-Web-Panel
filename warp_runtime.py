"""Background WARP jobs for the per-instance egress contour (issue #277).

The HTTP layer validates identity/ToS/XOR and starts a job, the job mutates
the authoritative state file and (for link/unlink) regenerates the container
start script with a warp context.

S4a adds the real wgcf install/repair/uninstall path: pinned wgcf delivery,
sanitized warp0.conf and the start.sh hand-off. Dataplane preparation,
verification and rollback belong to the follow-up stages. Everything here is
deliberately sequential and idempotent.
"""

import asyncio
import logging

import warp_service as ws

logger = logging.getLogger(__name__)

# awg_legacy is rejected by the warp contour (srv_warp_protocol_unsupported).
WARP_AWG_BASES = ('awg', 'awg2', 'awg3')

# wgcf is pinned. The sha256 map stays empty until PoC-0 records the hashes of
# the exact release binaries; sha256 verification is mandatory before release
# (see the TZ, wgcf: pin+sha256). When a hash is present _ensure_wgcf enforces it.
WGCF_VERSION = '2.2.22'
WGCF_URLS = {
    'amd64': 'https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_amd64',
    'arm64': 'https://github.com/ViRb3/wgcf/releases/download/v2.2.22/wgcf_2.2.22_linux_arm64',
}
WGCF_SHA256 = {}

WARP_DIR_TMPL = '/opt/amnezia/awg/warp/%s'


def _protocol_base(protocol):
    return str(protocol or '').split('__', 1)[0]


def _warp_dir(protocol):
    return WARP_DIR_TMPL % protocol


class WarpRuntime:
    """Run one warp job at a time per server uid.

    ``job_end`` is injected by app.py (its in-memory registry lives there) so
    this module never imports the application module.
    """

    # Protocol bases the warp contour may manage (awg_legacy is excluded).
    awg_protocols = WARP_AWG_BASES

    def __init__(self, load_data, save_data, data_lock, get_ssh,
                 awg_manager_factory, state_store, job_end=None):
        self.load_data = load_data
        self.save_data = save_data
        self.data_lock = data_lock
        self.get_ssh = get_ssh
        self.awg_manager_factory = awg_manager_factory
        self.state_store = state_store
        self.job_end = job_end

    # ----- helpers ----------------------------------------------------------

    @staticmethod
    def _server(data, server_id, uid=None):
        servers = data.get('servers') or []
        if uid:
            for idx, server in enumerate(servers):
                if server.get('uid') == uid:
                    return idx, server
            return None, None
        if isinstance(server_id, int) and 0 <= server_id < len(servers):
            return server_id, servers[server_id]
        return None, None

    def _awg_protocols(self, server):
        out = []
        for proto in (server.get('protocols') or {}):
            if _protocol_base(proto) in self.awg_protocols:
                out.append(proto)
        return out

    async def _awg(self, server):
        # get_ssh() blocks on ensure_connected; never call it on the loop.
        ssh = await asyncio.to_thread(self.get_ssh, server)
        return self.awg_manager_factory(ssh)

    async def _mutate_data(self, mutate):
        """Reload under DATA_LOCK after SSH and persist only what changed.

        Never write a whole pre-SSH snapshot: another panel writer may have
        updated data.json while the job was talking to the server.
        """
        async with self.data_lock:
            data = self.load_data()
            result = mutate(data)
            self.save_data(data)
            return result

    def _finish(self, uid, job_id):
        if not self.job_end:
            return
        try:
            self.job_end(uid, job_id)
        except Exception:
            logger.exception("Failed to release warp job %s for %s", job_id, uid)

    @staticmethod
    def _overhead(manager, protocol):
        """Transport bytes added per packet, from the live AWG parameters."""
        params = {}
        try:
            params = manager._get_awg_params_from_config(protocol) or {}
        except Exception:
            params = {}
        method = getattr(manager, 'transport_overhead', None)
        if callable(method):
            try:
                return int(method(params))
            except Exception:
                pass
        try:
            from managers.awg_manager import transport_overhead
            return int(transport_overhead(params))
        except Exception:
            return ws.WARP_TRANSPORT_OVERHEAD

    @staticmethod
    def _custom_config_mtu(text):
        """MTU from a saved customConfig, or None when there is no MTU line."""
        for line in str(text or '').splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or '=' not in stripped:
                continue
            name, _, value = stripped.partition('=')
            if name.strip().upper() != 'MTU':
                continue
            try:
                return int(value.strip())
            except (TypeError, ValueError):
                return None
        return None

    def _clients_over_budget(self, manager, protocol, budget):
        """Client names whose saved config exceeds the new warp MTU."""
        getter = getattr(manager, '_get_clients_table', None)
        if not callable(getter):
            return []
        try:
            clients = getter(protocol) or []
        except Exception:
            # Unreadable table is not proof of a conflict; reissue enforces
            # the budget again on the next client-config save.
            logger.exception("warp budget: clientsTable read failed for %s",
                             protocol)
            return []
        over = []
        for client in clients:
            user_data = client.get('userData') or {}
            mtu = self._custom_config_mtu(user_data.get('customConfig'))
            if mtu is not None and mtu > int(budget):
                over.append(str(user_data.get('clientName')
                                or client.get('clientId') or '?'))
        return over

    def _server_warp_installed(self, data, uid, installed):
        idx, server = self._server(data, None, uid)
        if idx is None:
            return False
        warp = server.setdefault('warp', {})
        warp['installed'] = bool(installed)
        return True

    async def _recount_installed(self, uid, protocols):
        state = self.state_store.load()
        installed = False
        for proto in protocols:
            rec = ws.proto_record(state, uid, proto)
            if (rec.get('warp') or {}).get('registered') or ws.warp_link(rec):
                installed = True
                break
        await self._mutate_data(
            lambda data: self._server_warp_installed(data, uid, installed))

    # ----- container-side helpers (wgcf, warp0.conf, start.sh) --------------

    def _targets(self, server, protocol=None):
        known = server.get('protocols') or {}
        if protocol:
            if _protocol_base(protocol) not in self.awg_protocols:
                raise ws.SrvWarpError('srv_warp_protocol_unsupported', 409)
            if protocol not in known:
                # The instance was deleted after the request was queued (or
                # the record never existed): an empty target list used to be
                # a silent no-op that still reported success.
                raise ws.SrvWarpError('srv_warp_no_targets', 409)
            return [protocol]
        return self._awg_protocols(server)

    @staticmethod
    def _config_path(manager, protocol):
        fn = getattr(manager, '_config_path', None)
        if not callable(fn):
            return None
        try:
            return fn(protocol)
        except Exception:
            return None

    @staticmethod
    def _container_running(manager, protocol):
        ssh = getattr(manager, 'ssh', None)
        state = None
        fn = getattr(ssh, 'docker_container_state', None)
        if callable(fn):
            try:
                state = fn(manager._container_name(protocol))
            except Exception:
                state = None
        if isinstance(state, (tuple, list)) and len(state) >= 2:
            return bool(state[1])
        if isinstance(state, str):
            return state.strip().lower() == 'running'
        if isinstance(state, bool):
            return state
        check = getattr(manager, 'check_container_running', None)
        if callable(check):
            try:
                return bool(check(protocol))
            except Exception:
                return False
        # A failed snapshot must not silently turn install into a no-op.
        return True

    def _sh(self, manager, protocol, script, timeout=60):
        """Run a shell snippet inside the instance container as root."""
        container = manager._container_name(protocol)
        quoted = str(script).replace("'", "'\\''")
        command = "docker exec -i %s sh -c '%s'" % (container, quoted)
        return manager.ssh.run_sudo_command(command, timeout=timeout)

    def _ensure_wgcf(self, manager, protocol):
        out, _err, code = self._sh(manager, protocol, 'command -v wgcf')
        if code == 0 and (out or '').strip():
            return

        out, _err, code = self._sh(manager, protocol, 'uname -m')
        machine = (out or '').strip().lower()
        arch = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'aarch64': 'arm64',
            'arm64': 'arm64',
        }.get(machine)
        if not arch:
            raise ws.SrvWarpError('srv_warp_arch_unsupported', 409)

        url = WGCF_URLS.get(arch)
        if not url:
            raise ws.SrvWarpError('srv_warp_arch_unsupported', 409)
        _out, err, code = self._sh(
            manager, protocol,
            'curl -fsSL %s -o /usr/local/bin/wgcf && chmod 755 /usr/local/bin/wgcf'
            % url,
            timeout=120,
        )
        if code != 0:
            logger.warning("wgcf download failed for %s/%s: %s",
                           protocol, arch, err)
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        expected = WGCF_SHA256.get(arch)
        if expected:
            out, _err, code = self._sh(
                manager, protocol, 'sha256sum /usr/local/bin/wgcf')
            actual = (out or '').split()[0] if (out or '').split() else ''
            if code != 0 or actual.lower() != expected.lower():
                logger.warning("wgcf sha256 mismatch for %s/%s", protocol, arch)
                raise ws.SrvWarpError('srv_warp_register_failed', 502)

        out, _err, code = self._sh(manager, protocol, 'command -v wgcf')
        if code != 0 or not (out or '').strip():
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

    @staticmethod
    def _warp_probe_script(protocol):
        """Shell snippet that reports the live facts of the WARP dataplane.

        Mirrors the fatal checks of ``x_warp_up`` in start.sh: a link that is
        only half applied leaves client traffic in a table that holds nothing
        but a blackhole.
        """
        table = int(ws.WARP_TABLE)
        return (
            "if ip link show warp0 >/dev/null 2>&1; then echo WARP_IF=up;"
            " else echo WARP_IF=down; fi\n"
            "if ip -4 route show table %d 2>/dev/null"
            " | grep -q '^default dev warp0'; then echo WARP_ROUTE=ok;"
            " else echo WARP_ROUTE=missing; fi\n"
            "if ip -4 rule show 2>/dev/null | grep -q '^%d:';"
            " then echo WARP_RULE=ok; else echo WARP_RULE=missing; fi\n"
            "if [ -f %s ]; then echo WARP_MARKER=ok;"
            " else echo WARP_MARKER=missing; fi\n"
        ) % (table, table, ws.marker_path(protocol))

    def _warp_dataplane(self, manager, protocol):
        """Read the WARP dataplane facts of one instance container."""
        try:
            out, err, code = self._sh(
                manager, protocol, self._warp_probe_script(protocol))
        except Exception as exc:
            return {'up': False, 'facts': {}, 'detail': str(exc)[:200]}
        facts = {}
        for line in (out or '').splitlines():
            key, _, value = line.strip().partition('=')
            if key.startswith('WARP_'):
                facts[key] = value
        up = (code == 0 and facts.get('WARP_IF') == 'up'
              and all(facts.get(key) == 'ok'
                      for key in ('WARP_ROUTE', 'WARP_RULE', 'WARP_MARKER')))
        return {'up': up, 'facts': facts, 'detail': (err or '').strip()[:200]}

    async def _wait_warp_dataplane(self, manager, protocol, attempts=5,
                                   delay=2.0):
        """Give start.sh a moment to raise warp0, then decide on the facts."""
        last = {'up': False, 'facts': {}, 'detail': 'not probed'}
        for attempt in range(max(1, attempts)):
            last = await asyncio.to_thread(
                self._warp_dataplane, manager, protocol)
            if last['up']:
                return last
            if attempt + 1 < attempts:
                await asyncio.sleep(delay)
        return last

    async def _sibling_warp_source(self, manager, server, uid, protocol):
        """Find a live WARP profile on another instance of the same server.

        A neighbour qualifies only when its state says registered and linked,
        it holds a complete credential pair, and its dataplane is really up.
        Copying a dead or incomplete profile would either give the new
        instance a tunnel that never handshakes or make _source_profile fall
        back to registration inside the healthy neighbour's container,
        replacing its identity. Both are failures this helper avoids.
        """
        state = self.state_store.load()
        for sibling in self._awg_protocols(server):
            if sibling == protocol:
                continue
            rec = ws.proto_record(state, uid, sibling)
            if not (rec.get('warp') or {}).get('registered'):
                continue
            if not ws.warp_link(rec):
                continue
            # A live warp0 with no readable credentials would make
            # _source_profile fall back to wgcf register *in the sibling's
            # container*, replacing the identity of a healthy neighbour.
            # Never mutate the source: skip incomplete profiles.
            if not await asyncio.to_thread(self._has_profile, manager, sibling):
                logger.info("warp source %s/%s has no complete profile",
                            uid, sibling)
                continue
            probe = await asyncio.to_thread(
                self._warp_dataplane, manager, sibling)
            if probe['up']:
                return sibling
            logger.info("warp source %s/%s dataplane is down: %s",
                        uid, sibling, probe.get('facts') or probe.get('detail'))
        return None

    def _write_warp_profile(self, manager, protocol, text):
        """Write warp0.conf without leaking the private key into the SSH log.

        ``run_sudo_script`` uploads the heredoc through SFTP, so the profile
        never becomes part of the docker exec command line.
        """
        container = manager._container_name(protocol)
        target = '%s/warp0.conf' % _warp_dir(protocol)
        payload = str(text or '').rstrip('\n')
        script = (
            "docker exec -i %s sh -c 'cat > %s && chmod 600 %s'"
            " <<'__WARP_PROFILE_EOF__'\n%s\n__WARP_PROFILE_EOF__\n"
            % (container, target, target, payload)
        )
        return manager.ssh.run_sudo_script(script, timeout=60)

    def _write_warp_creds(self, manager, protocol, text):
        """Write account.toml the same way as the profile: SFTP heredoc, 0600.

        The wgcf account carries the WARP private key, so it must never be
        part of a docker exec command line (those are logged by name).
        """
        container = manager._container_name(protocol)
        target = '%s/account.toml' % _warp_dir(protocol)
        payload = str(text or '').rstrip('\n')
        script = (
            "docker exec -i %s sh -c 'cat > %s && chmod 600 %s'"
            " <<'__WARP_ACCOUNT_EOF__'\n%s\n__WARP_ACCOUNT_EOF__\n"
            % (container, target, target, payload)
        )
        return manager.ssh.run_sudo_script(script, timeout=60)

    def _read_warp_file(self, manager, protocol, name):
        """Read a credential file out of the container.

        The file name (not its content) is the only thing that reaches the
        command line; the payload comes back over the SSH channel.
        """
        path = '%s/%s' % (_warp_dir(protocol), name)
        out, _err, code = self._sh(manager, protocol, 'cat %s' % path)
        if code != 0 or not (out or '').strip():
            return ''
        return out

    # One polling pass per second inside the container; the probe itself runs
    # in a single docker exec, so a stalled handshake costs one SSH round-trip.
    HANDSHAKE_TIMEOUT = 25

    _HANDSHAKE_PROBE = """IF=warp0
CONF=__CONF_DIR__/warp0.conf
[ -f "$CONF" ] || { echo NO_PROFILE; exit 0; }
# Guarantee the probe interface and its temp file are gone on every exit path,
# including a kill-switch SIGKILL of the SSH command: a leftover warp0 would
# otherwise survive until the next probe.
trap 'ip link del "$IF" 2>/dev/null; rm -f "${TMP:-}"' EXIT
ip link del "$IF" 2>/dev/null || true
if command -v amneziawg-go >/dev/null 2>&1 && [ ! -d /sys/module/amneziawg ]; then
  amneziawg-go "$IF" >/dev/null 2>&1 || { echo NO_LINK; exit 0; }
else
  ip link add dev "$IF" type amneziawg >/dev/null 2>&1 \\
    || ip link add dev "$IF" type wireguard >/dev/null 2>&1 \\
    || { echo NO_LINK; exit 0; }
fi
MTU=$(sed -n "s/^MTU *= *//p" "$CONF" | head -1)
[ -n "$MTU" ] || MTU=1280
ip link set dev "$IF" mtu "$MTU" up >/dev/null 2>&1
ADDR=$(sed -n "s/^Address *= *//p" "$CONF" | head -1 | cut -d, -f1 | tr -d " ")
[ -n "$ADDR" ] && ip -4 addr add "$ADDR" dev "$IF" >/dev/null 2>&1
QUICK=awg-quick; command -v awg-quick >/dev/null 2>&1 || QUICK=wg-quick
WG=awg; command -v awg >/dev/null 2>&1 || WG=wg
TMP=$(mktemp /tmp/_warp_probe.XXXXXX)
$QUICK strip "$CONF" > "$TMP" 2>/dev/null || cp "$CONF" "$TMP"
if ! $WG setconf "$IF" "$TMP" >/dev/null 2>&1; then
  rm -f "$TMP"; ip link del "$IF" 2>/dev/null || true; echo SETCONF_FAILED; exit 0
fi
rm -f "$TMP"
HS=0; i=0
while [ "$i" -lt __TRIES__ ]; do
  HS=$($WG show "$IF" latest-handshakes 2>/dev/null | awk "{print \\$2; exit}")
  [ -n "$HS" ] && [ "$HS" != "0" ] && break
  sleep 1; i=$((i+1))
done
ip link del "$IF" 2>/dev/null || true
if [ -n "$HS" ] && [ "$HS" != "0" ]; then echo "HANDSHAKE $HS"; else echo NO_HANDSHAKE; fi
"""

    def _handshake_probe(self, manager, protocol, timeout=None):
        """Bring warp0 up without any routes, wait for a handshake, tear it down.

        The probe adds no routes, NAT or kill-switch rules: it only proves the
        imported profile can complete a Cloudflare handshake before the panel
        records the instance as installed.
        """
        tries = int(timeout or self.HANDSHAKE_TIMEOUT)
        script = (self._HANDSHAKE_PROBE
                  .replace('__CONF_DIR__', _warp_dir(protocol))
                  .replace('__TRIES__', str(max(1, tries))))
        out, err, code = self._sh(manager, protocol, script,
                                  timeout=max(60, tries + 45))
        text = (out or '').strip()
        if code != 0:
            logger.warning("warp handshake probe failed for %s: %s",
                           protocol, (err or '')[-200:])
            return None
        if 'HANDSHAKE' in text and 'NO_HANDSHAKE' not in text:
            parts = text.split('HANDSHAKE', 1)[1].split()
            return parts[0] if parts else '0'
        if 'NO_HANDSHAKE' not in text:
            logger.warning("warp handshake probe: unexpected output %r for %s",
                           text[-120:], protocol)
        return None

    def _source_target(self, source_server, source_protocol=None):
        """AWG instance of the source server that supplies the profile."""
        known = source_server.get('protocols') or {}
        if source_protocol:
            if _protocol_base(source_protocol) not in self.awg_protocols:
                raise ws.SrvWarpError('srv_warp_protocol_unsupported', 409)
            if source_protocol not in known:
                raise ws.SrvWarpError('srv_warp_source_no_targets', 409)
            return source_protocol
        candidates = self._awg_protocols(source_server)
        if not candidates:
            raise ws.SrvWarpError('srv_warp_source_no_targets', 409)
        return candidates[0]

    def _conf_present(self, manager, protocol):
        warp_dir = _warp_dir(protocol)
        _out, _err, cred_code = self._sh(
            manager, protocol, 'test -f %s/account.toml' % warp_dir)
        _out, _err, conf_code = self._sh(
            manager, protocol, 'test -f %s/warp0.conf' % warp_dir)
        return cred_code == 0 and conf_code == 0

    def _has_profile(self, manager, protocol):
        """True when the instance already holds both WARP credential files."""
        warp_dir = _warp_dir(protocol)
        _out, _err, code = self._sh(
            manager, protocol,
            'test -s %s/account.toml && test -s %s/warp0.conf'
            % (warp_dir, warp_dir))
        return code == 0

    def _registration_api_reachable(self, manager, protocol, timeout=25):
        """Can this instance's host still reach the WARP registration API?

        ``wgcf`` calls ``api.cloudflareclient.com``; a provider that filters
        TLS by SNI breaks exactly that call while the WARP dataplane keeps
        working. The image already carries curl (it downloads wgcf), so the
        probe walks the same path registration does. Any HTTP status --
        including a 4xx -- proves the TLS handshake to the real API finished.

        True/False, or None when the probe itself could not run.
        """
        out, _err, _code = self._sh(
            manager, protocol,
            "curl -s -o /dev/null -w '%{http_code}' --max-time 8 "
            "https://api.cloudflareclient.com/v0a2158/reg || true",
            timeout=timeout)
        status = (out or '').strip()
        if not status.isdigit():
            return None
        return status != '000'

    async def _probe_source(self, source, protocols):
        """Capability row for one candidate source server (never raises)."""
        src_uid = ws._norm_uid(source.get('uid') or '')
        row = {
            'uid': src_uid,
            'name': source.get('name') or source.get('host') or src_uid,
            'host': source.get('host') or '',
            'protocols': protocols,
            'status': 'unreachable',
            'protocol': None,
        }
        try:
            manager = await self._awg(source)
            running = []
            for proto in protocols:
                if await asyncio.to_thread(
                        self._container_running, manager, proto):
                    running.append(proto)
            if not running:
                row['status'] = 'no_instance'
                return row
            for proto in running:
                if await asyncio.to_thread(
                        self._has_profile, manager, proto):
                    row.update(status='ready', protocol=proto)
                    return row
            proto = running[0]
            reachable = await asyncio.to_thread(
                self._registration_api_reachable, manager, proto)
            if reachable is True:
                row.update(status='can_register', protocol=proto)
            elif reachable is False:
                row.update(status='blocked', protocol=proto)
            else:
                row.update(status='unknown', protocol=proto)
        except Exception as exc:
            logger.warning("warp source probe failed for %s: %s", src_uid, exc)
            row.update(status='unreachable', protocol=None)
        return row

    async def probe_sources(self, server_id, uid, source_protocol=None,
                            concurrency=4):
        """Which other panel servers can actually donate a WARP profile.

        A source is usable when it already holds a profile, or when its host
        can still reach the registration API. The UI runs this before offering
        an import, so a user whose own host is SNI-filtered learns which server
        to register on instead of guessing.
        """
        data = self.load_data()
        idx, _server = self._server(data, server_id, uid)
        if idx is None:
            raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)

        candidates = []
        for index, source in enumerate(data.get('servers') or []):
            if index == idx:
                continue
            if not ws._norm_uid(source.get('uid') or ''):
                continue
            protocols = self._awg_protocols(source)
            if not protocols:
                continue
            candidates.append((source, protocols))

        gate = asyncio.Semaphore(max(1, int(concurrency)))

        async def one(source, protocols):
            async with gate:
                return await self._probe_source(source, protocols)

        return list(await asyncio.gather(
            *[one(source, protocols) for source, protocols in candidates]))

    def _register_and_write_conf(self, manager, protocol, uid=None):
        """Register (if needed), generate and sanitize warp0.conf.

        Returns the sha256 of the profile. When ``uid`` is supplied the warp
        state record is updated with ``conf_hash`` and ``registered=True``.
        """
        warp_dir = _warp_dir(protocol)
        self._sh(manager, protocol,
                 'mkdir -p %s && chmod 700 %s' % (warp_dir, warp_dir))

        _out, _err, code = self._sh(
            manager, protocol, 'test -f %s/account.toml' % warp_dir)
        if code != 0:
            # wgcf defaults to wgcf-account.toml/wgcf-profile.conf; pin the
            # panel artifact names explicitly instead of relying on those.
            _out, err, code = self._sh(
                manager, protocol,
                'cd %s && wgcf register --accept-tos --config account.toml'
                % warp_dir,
                timeout=120,
            )
            if code != 0:
                logger.warning("wgcf register failed for %s: %s", protocol, err)
                # A provider TLS/SNI block looks different from every other
                # failure: the WARP dataplane still works, only registration
                # is broken. Say so, so the UI can offer a profile import.
                if self._registration_api_reachable(manager, protocol) is False:
                    raise ws.SrvWarpError('srv_warp_register_api_unreachable', 502)
                raise ws.SrvWarpError('srv_warp_register_failed', 502)

        _out, err, code = self._sh(
            manager, protocol,
            'cd %s && wgcf generate --profile warp0.conf --config account.toml'
            % warp_dir,
            timeout=120)
        if code != 0:
            logger.warning("wgcf generate failed for %s: %s", protocol, err)
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        out, err, code = self._sh(
            manager, protocol, 'cat %s/warp0.conf' % warp_dir)
        if code != 0 or not (out or '').strip():
            logger.warning("warp0.conf missing for %s: %s", protocol, err)
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        profile = ws.sanitize_warp_profile(out)
        _out, err, code = self._write_warp_profile(manager, protocol, profile)
        if code != 0:
            logger.warning("warp0.conf write failed for %s: %s", protocol, err)
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        out, err, code = self._sh(
            manager, protocol, 'sha256sum %s/warp0.conf' % warp_dir)
        parts = (out or '').split()
        conf_hash = parts[0] if parts else ''
        if code != 0 or not conf_hash:
            logger.warning("warp0.conf sha256 failed for %s: %s",
                           protocol, err)
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        if uid is not None:
            def mark(state):
                record = ws.proto_record(state, uid, protocol)
                record['warp']['conf_hash'] = conf_hash
                record['warp']['registered'] = True

            self.state_store.mutate(mark)
        return conf_hash

    # ----- jobs -------------------------------------------------------------

    async def install(self, server_id, uid, protocol=None, job_id=None,
                      progress=None):
        def report(stage, message):
            if progress is not None:
                try:
                    progress(stage, message)
                except Exception:
                    logger.warning("warp install progress callback failed",
                                   exc_info=True)

        try:
            report('start', 'starting Cloudflare WARP installation')
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            protocols = self._targets(server, protocol)
            if not protocols:
                # WARP has no host-level binary: wgcf and warp0.conf live inside
                # an AmneziaWG container. A host without an AWG instance (an
                # exit-only node, for example) has nothing to install into, and
                # reporting success there left the marketplace on "Install"
                # with no explanation.
                raise ws.SrvWarpError('srv_warp_no_targets', 409)
            manager = await self._awg(server)

            done = []
            failures = []
            for proto in protocols:
                if not self._container_running(manager, proto):
                    logger.info("warp install: %s/%s container is not running",
                                uid, proto)
                    report('skip', 'skipped %s: container is not running'
                           % proto)
                    continue
                # A host-level install covers several instances: one broken
                # instance must not abort the others (the target list used to
                # be a single instance, so this loop never had to isolate).
                try:
                    report('download', 'downloading the wgcf client')
                    await asyncio.to_thread(self._ensure_wgcf, manager, proto)
                    report('register', 'registering with Cloudflare')
                    await asyncio.to_thread(
                        self._register_and_write_conf, manager, proto, uid)
                    report('profile', 'preparing the sanitized WARP profile')
                    # No restart on install: the running container keeps its
                    # current dataplane until the operator links WARP.
                    config_path = self._config_path(manager, proto)
                    report('startsh', 'updating the container start script')
                    await asyncio.to_thread(
                        manager._write_start_script, proto, config_path, None)
                except ws.SrvWarpError as exc:
                    logger.warning("warp install failed for %s/%s: %s",
                                   uid, proto, exc.code)
                    failures.append((proto, exc.code))
                    report('failed', 'failed %s: %s' % (proto, exc.code))
                    continue
                except Exception as exc:
                    logger.exception("warp install failed for %s/%s",
                                     uid, proto)
                    # A stable code: the per-instance isolation below needs a
                    # reason it can raise, and a class name would not be a code
                    # the UI could translate.
                    failures.append((proto, 'srv_warp_install_failed'))
                    report('failed', 'failed %s: %s'
                           % (proto, exc.__class__.__name__))
                    continue
                done.append(proto)

            if not done:
                # Nothing was registered: report the first concrete reason
                # instead of a generic "no targets", so a partial failure is
                # not disguised as an empty target list.
                if failures:
                    raise ws.SrvWarpError(failures[0][1], 502)
                # Every target container is stopped: no profile was registered,
                # so this is not an install and must not be reported as one.
                raise ws.SrvWarpError('srv_warp_no_targets', 409)

            await self._mutate_data(
                lambda current: self._server_warp_installed(
                    current, uid, bool(done)))
            report('done', 'Cloudflare WARP is installed')
        except ws.SrvWarpError as exc:
            logger.warning("warp install rejected for %s: %s", uid, exc.code)
            raise
        except Exception:
            logger.exception("warp install failed for %s", uid)
            raise
        finally:
            self._finish(uid, job_id)

    def _profile_hash(self, manager, protocol):
        out, err, code = self._sh(
            manager, protocol, 'sha256sum %s/warp0.conf' % _warp_dir(protocol))
        parts = (out or '').split()
        if code != 0 or not parts:
            logger.warning("warp0.conf sha256 failed for %s: %s",
                           protocol, err)
            return ''
        return parts[0]

    def _source_profile(self, manager, protocol, reuse=True):
        """(account_toml, sanitized_profile) read from the source instance.

        Registration is attempted only when the source has no usable profile:
        a server that can reach ``api.cloudflareclient.com`` supplies the
        account, a blocked one may already hold a previously imported one.
        """
        account = profile = ''
        if reuse and self._conf_present(manager, protocol):
            account = self._read_warp_file(manager, protocol, 'account.toml')
            profile = self._read_warp_file(manager, protocol, 'warp0.conf')
        if not account or not (profile or '').strip():
            try:
                self._ensure_wgcf(manager, protocol)
                self._register_and_write_conf(manager, protocol, None)
            except ws.SrvWarpError as exc:
                # The source may be behind the same SNI filter as the target:
                # report that instead of a generic registration failure.
                logger.warning("warp import: source register failed for %s: %s",
                               protocol, exc.code)
                raise ws.SrvWarpError('srv_warp_source_register_failed', 502)
            account = self._read_warp_file(manager, protocol, 'account.toml')
            profile = self._read_warp_file(manager, protocol, 'warp0.conf')
        if not account or not (profile or '').strip():
            raise ws.SrvWarpError('srv_warp_source_register_failed', 502)
        sanitized = ws.sanitize_warp_profile(profile)
        if 'PrivateKey' not in sanitized or 'PublicKey' not in sanitized:
            raise ws.SrvWarpError('srv_warp_source_register_failed', 502)
        return account, sanitized

    def _write_imported_profile(self, manager, protocol, account, profile):
        """Persist both credential files on the target (0600, via heredoc)."""
        self._sh(manager, protocol,
                 'mkdir -p %s && chmod 700 %s'
                 % (_warp_dir(protocol), _warp_dir(protocol)))
        try:
            _out, err, code = self._write_warp_creds(manager, protocol, account)
            if code != 0:
                logger.warning("account.toml write failed for %s: %s",
                               protocol, err)
                raise ws.SrvWarpError('srv_warp_register_failed', 502)
            _out, err, code = self._write_warp_profile(
                manager, protocol, profile)
            if code != 0:
                logger.warning("warp0.conf write failed for %s: %s",
                               protocol, err)
                raise ws.SrvWarpError('srv_warp_register_failed', 502)
            conf_hash = self._profile_hash(manager, protocol)
            if not conf_hash:
                raise ws.SrvWarpError('srv_warp_register_failed', 502)
        except Exception:
            # A half-written profile must not be picked up by a later link.
            self._remove_imported_profile(manager, protocol)
            raise
        return conf_hash

    def _remove_imported_profile(self, manager, protocol):
        """Undo _write_imported_profile after a failed handshake probe.

        The install path adopts an existing account.toml without running
        ``wgcf register`` and without a handshake check, so a profile that
        never handshook must not stay behind: a later install would silently
        mark the instance registered on a dead account.
        """
        warp_dir = _warp_dir(protocol)
        _out, err, code = self._sh(
            manager, protocol,
            'rm -f %s/account.toml %s/warp0.conf' % (warp_dir, warp_dir))
        if code != 0:
            logger.warning("imported profile cleanup failed for %s: %s",
                           protocol, err)

    async def import_profile(self, server_id, uid, source_uid, protocol=None,
                             source_protocol=None, job_id=None,
                             progress=None):
        """Copy a registered WARP profile from another panel server.

        Some hosts cannot reach ``api.cloudflareclient.com`` (the provider
        filters TLS by SNI) while the WARP dataplane itself works, so the
        account is registered elsewhere and imported here. The profile is
        only recorded after a live handshake proves it works.
        """
        def report(stage, message):
            if progress is not None:
                try:
                    progress(stage, message)
                except Exception:
                    logger.warning("warp import progress callback failed",
                                   exc_info=True)

        try:
            report('start', 'starting Cloudflare WARP profile import')
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            target_uid = ws._norm_uid(uid)
            src_uid = ws._norm_uid(source_uid)
            if not src_uid:
                raise ws.SrvWarpError('srv_warp_source_not_found', 409)
            if src_uid == target_uid:
                raise ws.SrvWarpError('srv_warp_source_is_self', 409)
            src_idx, source_server = self._server(data, None, src_uid)
            if src_idx is None:
                raise ws.SrvWarpError('srv_warp_source_not_found', 409)

            protocols = self._targets(server, protocol)
            if not protocols:
                raise ws.SrvWarpError('srv_warp_no_targets', 409)
            source_proto = self._source_target(source_server, source_protocol)

            if ws.quota_exhausted(self._registers_for(server, uid)):
                raise ws.SrvWarpError('srv_warp_quota_exhausted', 409)

            report('source', 'reading the WARP profile from the source server')
            try:
                source_manager = await self._awg(source_server)
            except Exception as exc:
                logger.warning("warp import: source ssh failed: %s", exc)
                raise ws.SrvWarpError('srv_warp_source_unreachable', 502)
            if not await asyncio.to_thread(
                    self._container_running, source_manager, source_proto):
                raise ws.SrvWarpError('srv_warp_source_unreachable', 502)
            try:
                account, profile = await asyncio.to_thread(
                    self._source_profile, source_manager, source_proto)
            except ws.SrvWarpError:
                raise
            except Exception as exc:
                logger.warning("warp import: source profile failed: %s", exc)
                raise ws.SrvWarpError('srv_warp_source_unreachable', 502)

            manager = await self._awg(server)
            imported, failed = [], []
            for proto in protocols:
                if not self._container_running(manager, proto):
                    logger.info("warp import: %s/%s container is not running",
                                target_uid, proto)
                    report('skip', 'skipped %s: container is not running'
                           % proto)
                    continue
                report('profile', 'writing the WARP profile to %s' % proto)
                conf_hash = await asyncio.to_thread(
                    self._write_imported_profile, manager, proto, account,
                    profile)
                report('handshake', 'verifying the WARP handshake on %s'
                       % proto)
                stamp = await asyncio.to_thread(
                    self._handshake_probe, manager, proto)
                if stamp is None:
                    # Leave nothing the install path could adopt silently:
                    # without cleanup a later install would treat the dead
                    # profile as already registered.
                    await asyncio.to_thread(
                        self._remove_imported_profile, manager, proto)
                    failed.append(proto)
                    continue

                def mark(state, proto=proto, conf_hash=conf_hash):
                    record = ws.proto_record(state, target_uid, proto)
                    record['warp']['conf_hash'] = conf_hash
                    record['warp']['registered'] = True
                    record['warp']['quarantine'] = False
                    record['warp']['handshake_fails'] = 0
                    record['warp']['last_handshake_fail_at'] = None

                self.state_store.mutate(mark)
                imported.append(proto)

            if not imported:
                if failed:
                    raise ws.SrvWarpError(
                        'srv_warp_handshake_failed', 502,
                        message='no WARP handshake on %s'
                                % ', '.join(failed))
                raise ws.SrvWarpError('srv_warp_no_targets', 409)

            report('startsh', 'updating the container start script')
            for proto in imported:
                await asyncio.to_thread(
                    manager._write_start_script, proto,
                    self._config_path(manager, proto), None)

            now = ws.now_ts()
            entry = {'ts': now, 'source': 'import',
                     'source_uid': src_uid, 'protocol': source_proto}

            def remember(current):
                _idx, current_server = self._server(current, None, target_uid)
                if current_server is None:
                    return False
                warp = current_server.setdefault('warp', {})
                registers = list(warp.get('registers_ts')
                                 or warp.get('registers') or [])
                registers.append(dict(entry))
                warp['registers_ts'] = ws.registers_prune(registers)
                warp['installed'] = True
                return True

            await self._mutate_data(remember)
            report('done', 'Cloudflare WARP profile imported')
            if failed:
                # Partial success: the imported instances are live, the rest
                # must be visible in the operation log instead of silently
                # looking installed.
                logger.warning("warp import: no handshake on %s for %s",
                               ', '.join(failed), target_uid)
                report('skip', 'no WARP handshake on %s' % ', '.join(failed))
        except ws.SrvWarpError as exc:
            logger.warning("warp import rejected for %s: %s", uid, exc.code)
            raise
        except Exception:
            logger.exception("warp import failed for %s", uid)
            raise
        finally:
            self._finish(uid, job_id)

    def _registers_for(self, server, uid):
        """Registration timestamps of a server, visible to the quota gate."""
        warp = server.get('warp') or {}
        registers = warp.get('registers_ts')
        if registers is None:
            registers = warp.get('registers')
        if registers is None:
            record = ((self.state_store.load().get('servers') or {})
                      .get(ws._norm_uid(uid)) or {})
            registers = record.get('registers_ts') or record.get('registers')
        return registers or []

    async def uninstall(self, server_id, uid, protocol=None, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            protocols = self._targets(server, protocol)
            if protocol is None:
                # A record can outlive its instance (deleted as a protocol while
                # unlinked). Uninstall must still be able to clear it, or the
                # card keeps showing a phantom "installed" instance forever.
                stored = ((self.state_store.load().get('servers') or {})
                          .get(str(uid)) or {}).get('protocols') or {}
                for proto in stored:
                    if (_protocol_base(proto) in self.awg_protocols
                            and proto not in protocols):
                        protocols.append(proto)
            manager = await self._awg(server) if protocols else None

            state = self.state_store.load()
            active = {
                proto: bool(ws.warp_link(ws.proto_record(state, uid, proto)))
                for proto in protocols
            }

            # A live link must be dropped from state before the warp-less
            # start.sh is rendered, otherwise it would re-add the warp block.
            if any(active.values()):
                self.state_store.mutate(
                    lambda current: self._clear_link_fields(
                        current, uid, protocols))

            for proto in protocols:
                # One missing container must not abort the state cleanup below:
                # the record is what keeps the card stuck, not the container.
                try:
                    warp_dir = _warp_dir(proto)
                    await asyncio.to_thread(
                        self._sh, manager, proto, 'rm -rf %s' % warp_dir)
                    await asyncio.to_thread(
                        self._sh, manager, proto,
                        'rm -f %s' % ws.marker_path(proto))
                    config_path = self._config_path(manager, proto)
                    await asyncio.to_thread(
                        manager._write_start_script, proto, config_path, None)
                    if active.get(proto):
                        await asyncio.to_thread(
                            manager._upload_start_script, proto, warp_ctx=None)
                except Exception:
                    logger.exception(
                        "warp uninstall: container cleanup failed for %s/%s",
                        uid, proto)

            def clear(state):
                for proto in protocols:
                    rec = ws.proto_record(state, uid, proto)
                    rec['warp']['registered'] = False
                    rec['warp']['conf_hash'] = None
                    rec['warp_link'] = None
                    rec['client_mtu_warp'] = None
                    rec['warp_egress_regen'] = {}

            self.state_store.mutate(clear)
            await self._recount_installed(uid, self._awg_protocols(server))
        except ws.SrvWarpError as exc:
            logger.warning("warp uninstall rejected for %s: %s", uid, exc.code)
        except Exception:
            logger.exception("warp uninstall failed for %s", uid)
        finally:
            self._finish(uid, job_id)

    @staticmethod
    def _clear_link_fields(state, uid, protocols):
        for proto in protocols:
            rec = ws.proto_record(state, uid, proto)
            rec['warp_link'] = None
            rec['client_mtu_warp'] = None

    async def repair(self, server_id, uid, protocol=None, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            protocols = self._targets(server, protocol)
            state = self.state_store.load()
            targets = []
            for proto in protocols:
                rec = ws.proto_record(state, uid, proto)
                if rec['warp'].get('registered') or ws.warp_link(rec):
                    targets.append(proto)
            manager = await self._awg(server) if targets else None

            # Repair order from the TZ: (1) creds, (2) start.sh, (3) restart.
            repaired = []
            failed = {}
            # Подтверждённые датаплейном линки: только им можно выставлять
            # dataplane_ok (успех без активного линка проверки не делал).
            confirmed = set()
            # Активные линки, у которых проба dataplane закончилась провалом.
            dataplane_down = set()
            for proto in targets:
                # Host-level repair covers every registered instance: isolate
                # each one, so a broken instance cannot cancel the rest.
                try:
                    await asyncio.to_thread(self._ensure_wgcf, manager, proto)
                    if not await asyncio.to_thread(
                            self._conf_present, manager, proto):
                        await asyncio.to_thread(
                            self._register_and_write_conf, manager, proto, uid)
                    current = self.state_store.load()
                    if ws.warp_link(ws.proto_record(current, uid, proto)):
                        ctx = ws.warp_ctx_for(current, uid, proto)
                        config_path = self._config_path(manager, proto)
                        await asyncio.to_thread(
                            manager._write_start_script, proto, config_path, ctx)
                        await asyncio.to_thread(
                            manager._upload_start_script, proto, warp_ctx=ctx)
                        # start.sh only *tries* to raise warp0; the link counts
                        # as repaired when the dataplane is actually in place.
                        probe = await self._wait_warp_dataplane(manager, proto)
                        if not probe['up']:
                            logger.warning(
                                "warp repair: %s/%s dataplane is down: %s",
                                uid, proto, probe.get('facts'))
                            # Причина запоминается до mark: ошибка не должна
                            # оставлять мёртвый линк подтверждённым.
                            dataplane_down.add(proto)
                            raise ws.SrvWarpError('srv_warp_link_failed', 502)
                        confirmed.add(proto)
                except ws.SrvWarpError as exc:
                    logger.warning("warp repair failed for %s/%s: %s",
                                   uid, proto, exc.code)
                    failed[proto] = exc.code
                    continue
                except Exception:
                    logger.exception("warp repair failed for %s/%s", uid, proto)
                    failed[proto] = 'srv_warp_repair_failed'
                    continue
                repaired.append(proto)

            if repaired or failed:
                def mark(current):
                    for proto in targets:
                        rec = ws.proto_record(current, uid, proto)
                        error = failed.get(proto)
                        rec['warp']['repair_state'] = {
                            'state': 'error' if error else 'ok',
                            'last_error': error,
                            'queue_reason': None,
                        }
                        if error and proto in dataplane_down:
                            # Проба активного линка провалилась: снимаем
                            # подтверждение датаплейна и помечаем причину.
                            ws.mark_warp_links_stale(
                                current, uid, [proto], ws.STALE_DATAPLANE_DOWN)
                        elif not error:
                            rec['warp']['quarantine'] = False
                            ws.clear_warp_links_stale(current, uid, [proto])
                            # Сохраняем факт подтверждённого датаплейна, не
                            # затирая остальные поля существующего линка.
                            if proto in confirmed:
                                link = ws.warp_link(rec)
                                if link:
                                    link['dataplane_ok'] = True
                                    link['dataplane_ok_at'] = ws.now_ts()

                self.state_store.mutate(mark)

            if failed:
                raise ws.SrvWarpError(
                    failed[sorted(failed)[0]], 502,
                    message='warp repair failed: %s'
                            % ', '.join('%s=%s' % item
                                        for item in sorted(failed.items())))
        except ws.SrvWarpError as exc:
            logger.warning("warp repair rejected for %s: %s", uid, exc.code)
        except Exception:
            logger.exception("warp repair failed for %s", uid)
        finally:
            self._finish(uid, job_id)

    async def link(self, server_id, uid, protocol, dns_via_warp=False,
                   job_id=None):
        applied = False
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            manager = await self._awg(server)

            raw_mtu = await asyncio.to_thread(
                manager._read_config_key_live, protocol, 'MTU')
            overhead = self._overhead(manager, protocol)
            mtu, reason = ws.warp_client_mtu(raw_mtu, overhead)
            if mtu is None:
                raise ws.SrvWarpError(reason or 'srv_warp_budget_mismatch', 409)

            over_budget = await asyncio.to_thread(
                self._clients_over_budget, manager, protocol, mtu)
            if over_budget:
                raise ws.SrvWarpError(
                    'srv_warp_budget_mismatch', 409,
                    message='client MTU above warp budget: %s'
                            % ', '.join(over_budget))

            # The start.sh of a linked instance is fail-closed: it blackholes
            # client traffic until warp0 is up. A missing profile therefore
            # used to leave clients with no internet while the panel claimed
            # the link was active. Prepare the profile first, announce the
            # link second. A working neighbour on this server is preferred:
            # Cloudflare registration is often blocked by SNI filtering while
            # the WARP dataplane itself works fine (MRAK, 2026-11-24).
            if not await asyncio.to_thread(
                    self._conf_present, manager, protocol):
                sibling = await self._sibling_warp_source(
                    manager, server, uid, protocol)
                if sibling:
                    account, profile = await asyncio.to_thread(
                        self._source_profile, manager, sibling, True)
                    conf_hash = await asyncio.to_thread(
                        self._write_imported_profile, manager, protocol,
                        account, profile)

                    def mark_copy(state):
                        rec = ws.proto_record(state, uid, protocol)
                        rec['warp']['conf_hash'] = conf_hash
                        rec['warp']['registered'] = True
                        rec['warp']['imported_from_protocol'] = sibling

                    self.state_store.mutate(mark_copy)
                    logger.info("warp profile %s copied from %s/%s",
                                protocol, uid, sibling)
                else:
                    await asyncio.to_thread(self._ensure_wgcf, manager, protocol)
                    await asyncio.to_thread(
                        self._register_and_write_conf, manager, protocol, uid)

            now = ws.now_ts()

            def apply(state):
                rec = ws.proto_record(state, uid, protocol)
                if ws.warp_link(rec):
                    raise ws.SrvWarpError('srv_warp_xor_conflict', 409)
                rec['warp_link'] = {
                    'active': True,
                    'dns_via_warp': bool(dns_via_warp),
                    'applied_at': now,
                    'stale': None,
                    'server_uid': ws._norm_uid(uid),
                    'entry_uid': ws._norm_uid(uid),
                    'protocol': protocol,
                }
                rec['client_mtu_warp'] = int(mtu)

            self.state_store.mutate(apply)
            applied = True
            ctx = ws.warp_ctx_for(self.state_store.load(), uid, protocol)
            config_path = manager._config_path(protocol)
            await asyncio.to_thread(
                manager._write_start_script, protocol, config_path, ctx)
            await asyncio.to_thread(
                manager._upload_start_script, protocol, warp_ctx=ctx)

            probe = await self._wait_warp_dataplane(manager, protocol)
            if not probe['up']:
                raise ws.SrvWarpError(
                    'srv_warp_link_failed', 502,
                    message='warp0 is not carrying traffic: %s'
                            % (probe.get('facts') or probe.get('detail') or ''))

            def mark_ok(state):
                rec = ws.proto_record(state, uid, protocol)
                rec['warp']['repair_state'] = {
                    'state': 'ok',
                    'last_error': None,
                    'queue_reason': None,
                }
                rec['warp']['quarantine'] = False
                # Dataplane уже подтверждён пробой: фиксируем это в линке,
                # чтобы /warp/status мог отличить успех от «подключения».
                ws.clear_warp_links_stale(state, uid, [protocol])
                link = ws.warp_link(rec)
                if link:
                    link['dataplane_ok'] = True
                    link['dataplane_ok_at'] = ws.now_ts()

            self.state_store.mutate(mark_ok)
            # Existing client configs must move onto the new budget. A failure
            # here is logged only: the link itself is already applied.
            try:
                await self.reissue(server_id, uid, protocol)
            except Exception:
                logger.exception(
                    "warp reissue after link failed for %s/%s", uid, protocol)
        except ws.SrvWarpError as exc:
            logger.warning("warp link rejected for %s/%s: %s %s",
                           uid, protocol, exc.code, str(exc))
            if applied:
                await self._undo_link(server_id, uid, protocol, exc.code)
        except Exception:
            logger.exception("warp link failed for %s/%s", uid, protocol)
            if applied:
                await self._undo_link(server_id, uid, protocol,
                                      'srv_warp_link_failed')
        finally:
            self._finish(uid, job_id)

    async def _undo_link(self, server_id, uid, protocol, error_code):
        """Drop a link that could not be brought up and restore direct egress.

        Leaving the kill-switch start.sh behind is worse than the original
        problem: clients would keep a tunnel to a server that cannot forward
        their traffic at all.
        """
        def clear(state):
            rec = ws.proto_record(state, uid, protocol)
            rec['warp_link'] = None
            rec['client_mtu_warp'] = None
            rec['warp']['repair_state'] = {
                'state': 'error',
                'last_error': error_code,
                'queue_reason': None,
            }

        try:
            self.state_store.mutate(clear)
        except Exception:
            logger.exception("warp link rollback state failed for %s/%s",
                             uid, protocol)
        try:
            data = self.load_data()
            idx, _server = self._server(data, server_id, uid)
            if idx is None:
                return
            manager = await self._awg(_server)
            config_path = manager._config_path(protocol)
            await asyncio.to_thread(
                manager._write_start_script, protocol, config_path, None)
            await asyncio.to_thread(
                manager._upload_start_script, protocol, warp_ctx=None)
        except Exception:
            logger.exception("warp link rollback failed for %s/%s",
                             uid, protocol)

    async def unlink(self, server_id, uid, protocol, job_id=None):
        await self._clear_link(server_id, uid, protocol, job_id=job_id)

    async def force_unlink(self, server_id, uid, protocol, job_id=None):
        # S3a has no backup to preserve, so force is the same safe path.
        await self._clear_link(server_id, uid, protocol, job_id=job_id)

    async def _clear_link(self, server_id, uid, protocol, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            manager = await self._awg(server)

            def clear(state):
                rec = ws.proto_record(state, uid, protocol)
                rec['warp_link'] = None
                rec['client_mtu_warp'] = None

            self.state_store.mutate(clear)
            config_path = manager._config_path(protocol)
            try:
                await asyncio.to_thread(
                    manager._write_start_script, protocol, config_path, None)
                await asyncio.to_thread(
                    manager._upload_start_script, protocol, warp_ctx=None)
            except Exception as exc:
                raise ws.SrvWarpError('srv_warp_unlink_failed', 409) from exc
            # TODO(S4): remove warp0/routes/rules, verify direct egress, reissue.
        except ws.SrvWarpError as exc:
            logger.warning("warp unlink rejected for %s/%s: %s",
                           uid, protocol, exc.code)
        except Exception:
            logger.exception("warp unlink failed for %s/%s", uid, protocol)
        finally:
            self._finish(uid, job_id)

    async def switch_egress(self, server_id, uid, protocol, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            now = ws.now_ts()

            def mark(state):
                rec = ws.proto_record(state, uid, protocol)
                link = rec.get('warp_link') or {}
                if not link.get('active'):
                    raise ws.SrvWarpError('srv_warp_xor_conflict', 409)
                link['applied_at'] = now
                # S4: сама смена маршрутизации ещё не реализована и пробы
                # dataplane здесь нет, поэтому старое подтверждение снимаем.
                link['stale'] = ws.STALE_EGRESS_SWITCH
                link['dataplane_ok'] = False
                rec['warp_link'] = link

            self.state_store.mutate(mark)
            # TODO(S4): exit<->warp ordered switch, rollback and reissue.
        except ws.SrvWarpError as exc:
            logger.warning("warp switch rejected for %s/%s: %s",
                           uid, protocol, exc.code)
        except Exception:
            logger.exception("warp switch failed for %s/%s", uid, protocol)
        finally:
            self._finish(uid, job_id)

    async def set_dns(self, server_id, uid, protocol, dns_on=False, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)

            def mark(state):
                rec = ws.proto_record(state, uid, protocol)
                link = rec.get('warp_link') or {}
                if not link.get('active'):
                    if dns_on:
                        raise ws.SrvWarpError('srv_warp_xor_conflict', 409)
                    return
                link['dns_via_warp'] = bool(dns_on)
                rec['warp_link'] = link

            self.state_store.mutate(mark)
            # TODO(S4): rewrite 182/183..189 rules, live apply, reissue.
        except ws.SrvWarpError as exc:
            logger.warning("warp dns rejected for %s/%s: %s",
                           uid, protocol, exc.code)
        except Exception:
            logger.exception("warp dns failed for %s/%s", uid, protocol)
        finally:
            self._finish(uid, job_id)

    async def reissue(self, server_id, uid, protocol, job_id=None):
        """Regenerate every client config for the current warp context.

        A saved customConfig may carry an MTU above the warp budget and its
        per-client mtu/dns overrides would otherwise win over the context, so
        all three are dropped before the config is rebuilt from scratch.
        """
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            manager = await self._awg(server)
            ctx = ws.warp_ctx_for(self.state_store.load(), uid, protocol)

            table = await asyncio.to_thread(
                manager._get_clients_table, protocol)
            table = table or []
            for client in table:
                user_data = client.get('userData')
                if not isinstance(user_data, dict):
                    continue
                user_data.pop('customConfig', None)
                user_data.pop('mtu', None)
                user_data.pop('dns', None)
            await asyncio.to_thread(
                manager._save_clients_table, protocol, table)

            port = None
            try:
                params = await asyncio.to_thread(
                    manager._get_awg_params_from_config, protocol) or {}
                port = params.get('port')
            except Exception:
                port = None
            if not port:
                port = ((server.get('protocols') or {}).get(protocol)
                        or {}).get('port') or '55424'
            host = server.get('host') or ''

            for client in table:
                client_id = client.get('clientId')
                if not client_id:
                    continue
                text = await asyncio.to_thread(
                    manager.get_client_config, protocol, client_id, host, port,
                    warp_ctx=ctx)
                await asyncio.to_thread(
                    manager.save_client_config, protocol, client_id, text,
                    warp_ctx=ctx)

            def mark(state):
                rec = ws.proto_record(state, uid, protocol)
                rec['warp']['quarantine'] = False
                rec['warp']['handshake_fails'] = 0
                rec['warp']['last_handshake_fail_at'] = None
                rec['warp']['last_reissue_at'] = ws.now_ts()

            self.state_store.mutate(mark)
        except ws.SrvWarpError as exc:
            logger.warning("warp reissue rejected for %s/%s: %s",
                           uid, protocol, exc.code)
        except Exception:
            logger.exception("warp reissue failed for %s/%s", uid, protocol)
        finally:
            self._finish(uid, job_id)

    async def exit_egress(self, server_id, uid, enable=False, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)

            def mark(state):
                ws.exit_record(state, uid)['warp_egress'] = bool(enable)

            self.state_store.mutate(mark)
            # TODO(S4): per-entry B-side rules, regen-keep, budget per entry.
        except ws.SrvWarpError as exc:
            logger.warning("warp exit-egress rejected for %s: %s", uid, exc.code)
        except Exception:
            logger.exception("warp exit-egress failed for %s", uid)
        finally:
            self._finish(uid, job_id)
