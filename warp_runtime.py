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
            return [protocol] if protocol in known else []
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

    def _conf_present(self, manager, protocol):
        warp_dir = _warp_dir(protocol)
        _out, _err, cred_code = self._sh(
            manager, protocol, 'test -f %s/account.toml' % warp_dir)
        _out, _err, conf_code = self._sh(
            manager, protocol, 'test -f %s/warp0.conf' % warp_dir)
        return cred_code == 0 and conf_code == 0

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
            manager = await self._awg(server) if protocols else None

            done = []
            for proto in protocols:
                if not self._container_running(manager, proto):
                    logger.info("warp install: %s/%s container is not running",
                                uid, proto)
                    continue
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
                done.append(proto)

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

    async def uninstall(self, server_id, uid, protocol=None, job_id=None):
        try:
            data = self.load_data()
            idx, server = self._server(data, server_id, uid)
            if idx is None:
                raise ws.SrvWarpError('srv_warp_identity_mismatch', 409)
            protocols = self._targets(server, protocol)
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
            for proto in targets:
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

            if targets:
                def mark(current):
                    for proto in targets:
                        rec = ws.proto_record(current, uid, proto)
                        rec['warp']['repair_state'] = {
                            'state': 'ok',
                            'last_error': None,
                            'queue_reason': None,
                        }
                        rec['warp']['quarantine'] = False

                self.state_store.mutate(mark)
        except ws.SrvWarpError as exc:
            logger.warning("warp repair rejected for %s: %s", uid, exc.code)
        except Exception:
            logger.exception("warp repair failed for %s", uid)
        finally:
            self._finish(uid, job_id)

    async def link(self, server_id, uid, protocol, dns_via_warp=False,
                   job_id=None):
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
            ctx = ws.warp_ctx_for(self.state_store.load(), uid, protocol)
            config_path = manager._config_path(protocol)
            # TODO(S4): prepare warp0/routes/NAT, verify egress, marker, reissue.
            await asyncio.to_thread(
                manager._write_start_script, protocol, config_path, ctx)
            await asyncio.to_thread(
                manager._upload_start_script, protocol, warp_ctx=ctx)
            # Existing client configs must move onto the new budget. A failure
            # here is logged only: the link itself is already applied.
            try:
                await self.reissue(server_id, uid, protocol)
            except Exception:
                logger.exception(
                    "warp reissue after link failed for %s/%s", uid, protocol)
        except ws.SrvWarpError as exc:
            logger.warning("warp link rejected for %s/%s: %s",
                           uid, protocol, exc.code)
        except Exception:
            logger.exception("warp link failed for %s/%s", uid, protocol)
        finally:
            self._finish(uid, job_id)

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
                link['stale'] = None
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
