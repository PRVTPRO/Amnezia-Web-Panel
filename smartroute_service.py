"""Orchestration of the Smart Route app and its per-instance split routing.

The host side (prefix lists + systemd timer) is plain SSH through
SmartRouteManager; the routing side lives in the AWG container netns and
reuses the exit-link plumbing (an instance must be linked to an exit node
before it can be split). Everything is idempotent: enabling an already
split instance re-applies the current lists, disabling twice is a no-op,
and uninstalling the app safely rolls every split instance back to
"everything via the exit node" - never to "everything direct".
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from managers.awg_manager import AWG_DEFAULTS
from managers.smartroute_manager import (
    SMARTR_MIN_PREFIXES,
    SmartRouteManager,
    normalize_cidrs,
)

logger = logging.getLogger(__name__)

# data.panel_migrations key for the one-shot host timer rewrite.
SMARTR_TIMER_MIGRATION_KEY = 'smartroute_timer_v1'

# How long one host's prefix-list reading stays usable when a later
# probe fails. The hourly timer refreshes the list, so a quarter of an
# hour cannot hide a real outage for long.
SMARTR_PREFIX_CACHE_TTL = 15 * 60


class SmartRouteError(Exception):
    """User-facing failure with a stable code for the UI/i18n."""

    def __init__(self, code, message, status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def split_instances(data, server_id):
    """(protocol, exit_link) pairs of this server that use Smart Route."""
    servers = data.get('servers', [])
    if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
        return []
    out = []
    for proto, rec in (servers[server_id].get('protocols') or {}).items():
        link = (rec or {}).get('exit_link') or {}
        if link.get('smart_route'):
            out.append((proto, link))
    return out


class SmartRouteService:
    def __init__(self, *, load_data, save_data, data_lock, get_ssh,
                 awg_manager_factory, protocol_base, awg_protocols,
                 apply_dns_via_exit=None):
        self.load_data = load_data
        self.save_data = save_data
        self.data_lock = data_lock
        self.get_ssh = get_ssh
        self.awg_manager_factory = awg_manager_factory
        self.protocol_base = protocol_base
        self.awg_protocols = awg_protocols
        # set_dns_via_exit(server_id, protocol, enabled) -> result; wired to
        # ExitLinkService in app.py so DNS stays a single mechanism.
        self.apply_dns_via_exit = apply_dns_via_exit
        self._locks = defaultdict(asyncio.Lock)
        # uid -> (monotonic_ts, error, v4_count); see _prefix_list_health.
        self._prefix_cache = {}

    # ----- helpers -----

    def _server(self, data, server_id):
        servers = data.get('servers', [])
        if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
            raise SmartRouteError('server_not_found', 'Server not found', 404)
        return servers[server_id]

    # A mutation spans several SSH calls; the inventory can be reordered or
    # edited meanwhile. Persisting by the positional server_id then writes the
    # result to whichever server now sits at that index. Capture the stable
    # identity at request time and resolve the final write by it instead.
    _IDENTITY_KEYS = ('uid', 'host', 'ssh_port', 'username')

    @classmethod
    def _identity(cls, server):
        return {key: server.get(key) for key in cls._IDENTITY_KEYS}

    def _resolve_identity(self, data, identity):
        """Server with this uid whose endpoint still matches, or a stable error.

        Never falls back to a positional index: a legacy record without a uid,
        a duplicate uid, or an endpoint change fails closed (409) rather than
        writing the result to the wrong server."""
        uid = identity.get('uid')
        if not uid:
            raise SmartRouteError('server_not_found', 'Server has no stable id', 404)
        matches = [srv for srv in data.get('servers', []) if srv.get('uid') == uid]
        if len(matches) != 1:
            raise SmartRouteError('server_changed',
                                  'Server identity changed; refresh the inventory', 409)
        server = matches[0]
        if any(server.get(key) != identity.get(key) for key in self._IDENTITY_KEYS):
            raise SmartRouteError('server_changed',
                                  'Server identity changed; refresh the inventory', 409)
        return server

    @staticmethod
    def _split_instances_of(server):
        out = []
        for proto, rec in (server.get('protocols') or {}).items():
            link = (rec or {}).get('exit_link') or {}
            if link.get('smart_route'):
                out.append((proto, link))
        return out

    def _settings(self, server):
        sm = server.setdefault('smartroute', {})
        sm.setdefault('own_subnets', [])
        sm.setdefault('dns_via_exit', False)
        # Global on/off switch (the server-page card toggle). Pausing only
        # rolls the split routing out of the containers; the prefix lists,
        # timer and per-instance preferences all stay in place.
        sm.setdefault('enabled', True)
        # Resolver pair written into split-instance client configs: the
        # direct resolver is expected to be a RU IP (routed directly by the
        # throw table), the exit resolver a foreign one (routed through the
        # exit node). Routing, not the client, decides which path a query
        # takes.
        sm.setdefault('direct_dns', '77.88.8.8')
        sm.setdefault('exit_dns', '1.1.1.1')
        return sm

    @staticmethod
    def _validate_dns(ip, field):
        import ipaddress
        try:
            return str(ipaddress.IPv4Address(str(ip).strip()))
        except Exception:
            raise SmartRouteError('invalid_dns', f'{field} must be an IPv4 address')

    def _dns_pair(self, server):
        sm = (server.get('smartroute') or {})
        direct = (sm.get('direct_dns') or '77.88.8.8').strip()
        exit_ = (sm.get('exit_dns') or '1.1.1.1').strip()
        return f"{direct}, {exit_}"

    async def _apply_dns_for_split(self, identity, protocol, enabled):
        """Point a split instance's client configs at the resolver pair, or
        restore what the instance had before its first split.

        Non-fatal by design: the routing works without it, so a failing DNS
        rewrite must not break the split toggle itself."""
        try:
            server = self._resolve_identity(self.load_data(), identity)
            rec = (server.get('protocols') or {}).get(protocol) or {}
            link = rec.get('exit_link') or {}
            awg = await self._awg(server)
            if enabled:
                if 'smart_route_prev_dns' not in link:
                    current = await asyncio.to_thread(awg._read_config_key, protocol, 'DNS')

                    def remember(lk):
                        lk.setdefault('smart_route_prev_dns', current)
                    await self._update_link(identity, protocol, remember)
                pair = self._dns_pair(server)
                await asyncio.to_thread(awg.update_awg_settings, protocol, dns=pair)
            elif 'smart_route_prev_dns' in link:
                prev = link.get('smart_route_prev_dns')

                def forget(lk):
                    lk.pop('smart_route_prev_dns', None)
                await asyncio.to_thread(awg.update_awg_settings, protocol,
                                        dns=prev if prev else '')
                await self._update_link(identity, protocol, forget)
        except SmartRouteError:
            raise
        except Exception as err:
            logger.warning("smartroute DNS %s of %s failed: %s",
                           'apply' if enabled else 'restore', protocol, err)

    def _entry(self, data, server_id, protocol):
        server = self._server(data, server_id)
        if self.protocol_base(protocol) not in self.awg_protocols:
            raise SmartRouteError('protocol_not_awg', 'Only AmneziaWG instances support Smart Route')
        rec = (server.get('protocols') or {}).get(protocol) or {}
        link = rec.get('exit_link') or {}
        if not link.get('exit_uid'):
            raise SmartRouteError('not_linked', 'Link this instance to an exit node first')
        return server, rec, link

    async def _awg(self, server):
        return self.awg_manager_factory(await asyncio.to_thread(self.get_ssh, server))

    async def _smartr(self, server):
        return SmartRouteManager(await asyncio.to_thread(self.get_ssh, server))

    @staticmethod
    def _subnet_default():
        return f"{AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}"

    async def _container_ctx(self, awg, protocol):
        return (awg._container_name(protocol),
                awg._resolve_config_path(protocol),
                SmartRouteService._subnet_default())

    async def _update_link(self, identity, protocol, mutate):
        async with self.data_lock:
            data = self.load_data()
            server = self._resolve_identity(data, identity)
            rec = ((server.get('protocols') or {}).get(protocol)) or {}
            link = rec.get('exit_link')
            if link is None:
                return None
            mutate(link)
            self.save_data(data)
            return link

    def is_enabled_in_data(self, data, server_id):
        """Panel-side mirror of "app installed", for cheap UI gating. The
        host binary remains the source of truth; this only hides the flag."""
        try:
            return bool((self._server(data, server_id).get('smartroute') or {}).get('installed'))
        except SmartRouteError:
            return False

    # ----- app lifecycle -----

    # Each phase is its own short SSH call so the progress bar advances live.
    INSTALL_PHASES = ('prepare', 'script', 'units', 'activate', 'download',
                      'verify')

    async def install(self, server_id, progress=None):
        """Install the host side phase by phase.

        ``progress(stage, line)`` is called from the event loop for every
        output line of every phase (after the phase's SSH thread finished, so
        no file or asyncio IO ever runs on that thread).
        """
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        label = server.get('uid') or server_id
        smartr = await self._smartr(server)
        logs = []
        for phase in self.INSTALL_PHASES:
            lines = []
            lock = threading.Lock()

            def collect(text, _lines=lines, _lock=lock):
                with _lock:
                    _lines.append(text)

            logger.info("smartroute install %s: phase %s started", label, phase)
            try:
                out = await asyncio.to_thread(smartr.install, phase, collect)
            except SmartRouteError as err:
                logger.warning("smartroute install %s: phase %s failed: %s",
                               label, phase, err)
                if progress is not None:
                    for line in list(lines):
                        progress(phase, line)
                    progress(phase, f"ERROR: {err}")
                raise
            with lock:
                drained = list(lines)
                del lines[:]
            if progress is not None:
                for line in drained:
                    progress(phase, line)
            logs.append(out or '')
            logger.info("smartroute install %s: phase %s finished", label, phase)

        async with self.data_lock:
            data = self.load_data()
            server = self._resolve_identity(data, identity)
            self._settings(server)['installed'] = True
            self._settings(server)['enabled'] = True
            self.save_data(data)
        return {'status': 'success', 'log': '\n'.join(logs)}

    async def uninstall(self, server_id):
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        splits = self._split_instances_of(server)

        # 1) Per-container rollback FIRST (containers still exist and are
        #    marked): throw routes out, accounting down, conntrack flushed.
        #    After this the clients are back on "everything via exit0".
        rollback_failed = []
        for proto, _link in splits:
            try:
                awg = await self._awg(server)
                container, config_path, subnet_default = await self._container_ctx(awg, proto)
                smartr = await self._smartr(server)
                await asyncio.to_thread(smartr.disable_instance, container, config_path, subnet_default)
                await self._apply_dns_for_split(identity, proto, False)
            except Exception as err:
                logger.warning("smartroute rollback of %s failed: %s", proto, err)
                rollback_failed.append({'protocol': proto, 'error': str(err)})

        if rollback_failed:
            # Fail-stop (review hardening): host cleanup would delete the
            # markers and timer, stranding throw routes nobody manages and
            # making the failure irreversible. Keep everything in place so
            # the uninstall can be retried; nothing is recorded as removed.
            details = '; '.join(f"{f['protocol']}: {f['error']}"
                                for f in rollback_failed)
            raise SmartRouteError(
                'rollback_incomplete',
                f"Rollback failed for {len(rollback_failed)} instance(s) "
                f"({details}). The app is left intact - retry the uninstall.",
                409)

        # 2) Host cleanup (files, timer, leftover markers). Its own container
        #    loop is a no-op now - the markers are already gone.
        smartr = await self._smartr(server)
        log = await asyncio.to_thread(smartr.uninstall)

        # 3) Record the rollback so the UI badges every affected instance.
        async with self.data_lock:
            data = self.load_data()
            server = self._resolve_identity(data, identity)
            sm = server.get('smartroute') or {}
            sm['installed'] = False
            sm['enabled'] = False
            server['smartroute'] = sm
            for proto, link in self._split_instances_of(server):
                link['smart_route'] = False
                link['smart_route_lost'] = True
            self.save_data(data)

        # 4) Normalize the link state (conntrack flush via x_exit_sync).
        for proto, _ in splits:
            try:
                awg = await self._awg(server)
                await asyncio.to_thread(awg._exit_apply, proto)
            except Exception as err:
                logger.warning("exit re-sync after smartroute uninstall of %s failed: %s", proto, err)

        return {'status': 'success', 'log': log, 'rolled_back': [p for p, _ in splits]}

    # ----- status / lists -----

    async def status(self, server_id):
        data = self.load_data()
        server = self._server(data, server_id)
        sm = server.get('smartroute') or {}
        smartr = await self._smartr(server)
        host = await asyncio.to_thread(smartr.host_status)
        host['installed'] = host['installed'] and sm.get('installed', host['installed'])
        return {
            'status': 'success',
            'installed': bool(sm.get('installed')) and host['installed'],
            'enabled': bool(sm.get('enabled', True)),
            'host': host,
            'own_subnets': sm.get('own_subnets', []),
            'dns_via_exit': bool(sm.get('dns_via_exit', False)),
            'direct_dns': (sm.get('direct_dns') or '77.88.8.8'),
            'exit_dns': (sm.get('exit_dns') or '1.1.1.1'),
            'split_instances': [p for p, _ in split_instances(data, server_id)],
        }

    async def set_enabled(self, server_id, enabled):
        """Global pause/resume. Pausing rolls the split routing out of every
        split container (traffic falls back to the exit node); resuming
        re-applies it. Per-instance preferences (smart_route flags) are kept,
        so a resume restores exactly what was paused."""
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        sm = server.get('smartroute') or {}
        if not sm.get('installed'):
            raise SmartRouteError('app_not_installed',
                                  'Install Smart Route from the marketplace first', 409)
        enabled = bool(enabled)
        if bool(sm.get('enabled', True)) == enabled:
            return {'status': 'success', 'enabled': enabled, 'unchanged': True}

        awg = await self._awg(server)
        smartr = await self._smartr(server)
        applied, failed = [], []
        for proto, _link in self._split_instances_of(server):
            try:
                container, config_path, subnet_default = await self._container_ctx(awg, proto)
                if enabled:
                    await asyncio.to_thread(smartr.enable_instance, container, config_path, subnet_default)
                else:
                    await asyncio.to_thread(smartr.disable_instance, container, config_path, subnet_default)
                applied.append(proto)
                await self._apply_dns_for_split(identity, proto, enabled)
            except Exception as err:
                logger.warning("smartroute %s of %s failed: %s",
                               'resume' if enabled else 'pause', proto, err)
                failed.append({'protocol': proto, 'error': str(err)})

        if failed:
            # Fail-stop (review hardening): recording `enabled` here would
            # report a state at least one container does not actually have.
            # The stored flag keeps its previous value, so the operation is
            # fully retryable; the error names every failed instance.
            details = '; '.join(f"{f['protocol']}: {f['error']}" for f in failed)
            raise SmartRouteError(
                'partial_failure',
                f"{'Resume' if enabled else 'Pause'} did not complete for "
                f"{len(failed)} instance(s) ({details}). No state was "
                f"recorded - fix the cause and retry.",
                409)

        async with self.data_lock:
            data = self.load_data()
            self._settings(self._resolve_identity(data, identity))['enabled'] = enabled
            self.save_data(data)

        return {'status': 'success', 'enabled': enabled,
                'applied': applied, 'failed': failed}

    async def set_dns_servers(self, server_id, direct, exit_):
        """Store the resolver pair and push it into every split instance.

        The pair is written as the instance's `DNS = direct, exit` line; the
        throw table routes each query by the resolver's own IP (RU resolver
        direct, foreign resolver through the exit). Previously remembered
        per-instance DNS is left untouched."""
        direct = self._validate_dns(direct, 'direct_dns')
        exit_ = self._validate_dns(exit_, 'exit_dns')
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        if not (server.get('smartroute') or {}).get('installed'):
            raise SmartRouteError('app_not_installed',
                                  'Install Smart Route from the marketplace first', 409)
        async with self.data_lock:
            data = self.load_data()
            sm = self._settings(self._resolve_identity(data, identity))
            sm['direct_dns'] = direct
            sm['exit_dns'] = exit_
            self.save_data(data)
        pair = f"{direct}, {exit_}"
        applied, failed = [], []
        for proto, _link in self._split_instances_of(server):
            try:
                awg = await self._awg(server)
                await asyncio.to_thread(awg.update_awg_settings, proto, dns=pair)
                applied.append(proto)
            except Exception as err:
                logger.warning("smartroute DNS pair apply to %s failed: %s", proto, err)
                failed.append({'protocol': proto, 'error': str(err)})
        return {'status': 'success', 'direct_dns': direct, 'exit_dns': exit_,
                'applied': applied, 'failed': failed}

    async def run_update(self, server_id):
        server = self._server(self.load_data(), server_id)
        smartr = await self._smartr(server)
        log = await asyncio.to_thread(smartr.run_update)
        return {'status': 'success', 'log': log}

    async def set_own_subnets(self, server_id, cidrs):
        try:
            normalized = normalize_cidrs(cidrs or [], family='ipv4')
        except ValueError as exc:
            raise SmartRouteError('invalid_cidr', str(exc))
        server = self._server(self.load_data(), server_id)
        identity = self._identity(server)
        smartr = await self._smartr(server)
        await asyncio.to_thread(smartr.set_own_subnets, normalized)
        async with self.data_lock:
            data = self.load_data()
            self._settings(self._resolve_identity(data, identity))['own_subnets'] = normalized
            self.save_data(data)
        # Refresh every split instance so the new subnets take effect now.
        for proto, _link in self._split_instances_of(server):
            try:
                awg = await self._awg(server)
                container, _, _ = await self._container_ctx(awg, proto)
                await asyncio.to_thread(smartr.refresh_instance, container)
            except Exception as err:
                logger.warning("smartroute refresh of %s after own-subnet change failed: %s", proto, err)
        return {'status': 'success', 'own_subnets': normalized}

    # ----- per-instance split toggle -----

    async def set_split(self, server_id, protocol, enabled):
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        if not (server.get('smartroute') or {}).get('installed'):
            raise SmartRouteError('app_not_installed',
                                  'Install Smart Route from the marketplace first', 409)
        _server, _rec, link = self._entry(data, server_id, protocol)
        enabled = bool(enabled)
        if enabled and not (server.get('smartroute') or {}).get('enabled', True):
            raise SmartRouteError('smartroute_paused',
                                  'Smart Route is paused server-wide; enable it from the Smart Route card first', 409)
        if bool(link.get('smart_route')) == enabled and not link.get('smart_route_lost'):
            return {'status': 'success', 'smart_route': enabled, 'unchanged': True}

        async with self._locks[(server.get('uid', server_id), protocol)]:
            awg = await self._awg(server)
            container, config_path, subnet_default = await self._container_ctx(awg, protocol)
            smartr = await self._smartr(server)
            if enabled:
                log = await asyncio.to_thread(smartr.enable_instance, container, config_path, subnet_default)
            else:
                log = await asyncio.to_thread(smartr.disable_instance, container, config_path, subnet_default)

            def mutate(lk):
                lk['smart_route'] = enabled
                if enabled:
                    lk['smart_route_lost'] = False
            await self._update_link(identity, protocol, mutate)
            await self._apply_dns_for_split(identity, protocol, enabled)

            # Apply the server-level DNS choice to the freshly split instance.
            if enabled and self.apply_dns_via_exit is not None:
                dns_via_exit = bool((server.get('smartroute') or {}).get('dns_via_exit', False))
                if bool(link.get('dns_via_exit')) != dns_via_exit:
                    try:
                        await self.apply_dns_via_exit(server_id, protocol, dns_via_exit)
                    except Exception as err:
                        logger.warning("dns_via_exit apply after split enable failed: %s", err)
        return {'status': 'success', 'smart_route': enabled, 'log': log}

    # ----- DNS choice for split instances -----

    async def set_dns_via_exit(self, server_id, enabled):
        data = self.load_data()
        server = self._server(data, server_id)
        identity = self._identity(server)
        self._settings(server)  # ensure shape (save below under lock)
        async with self.data_lock:
            data = self.load_data()
            self._settings(self._resolve_identity(data, identity))['dns_via_exit'] = bool(enabled)
            self.save_data(data)
        results = []
        if self.apply_dns_via_exit is not None:
            for proto, _link in self._split_instances_of(server):
                try:
                    await self.apply_dns_via_exit(server_id, proto, bool(enabled))
                    results.append({'protocol': proto, 'status': 'success'})
                except Exception as err:
                    logger.warning("dns_via_exit for %s failed: %s", proto, err)
                    results.append({'protocol': proto, 'status': 'error', 'error': str(err)})
        return {'status': 'success', 'dns_via_exit': bool(enabled), 'results': results}

    # ----- self-healing after container restarts -----

    async def migrate_timer(self, server_id=None):
        """Re-install the host timer with an absolute schedule, once per host.

        Panels up to v1.8.14 wrote ``OnUnitActiveSec=1h``: a monotonic timer
        that silently stops arming when the service's activation stamp goes
        stale (ZK and MAMKAM, 2026-11-19: "active" but no next run for days).
        The unit is rewritten only on install, so existing installations would
        keep the broken timer forever without this pass.

        Skips servers that do not run Smart Route, hosts without systemd, and
        units the panel does not own. Never raises for one host: the report
        says what happened and a failing host stays pending for the next start.

        Review A5: a repeated panel start re-enters only hosts whose record is
        still pending; a host this very record marks done (or unsupported) is
        not contacted again. An explicit server_id is a manual repair: it is
        always checked, record notwithstanding.
        """
        data = self.load_data()
        servers = data.get('servers') or []
        if server_id is None:
            targets = list(enumerate(servers))
        else:
            targets = [(server_id, self._server(data, server_id))]
        known = self._timer_migration_hosts(data) if server_id is None else {}
        report = []
        for idx, server in targets:
            if not (server.get('smartroute') or {}).get('installed'):
                continue
            if server_id is None:
                done = known.get(server.get('uid'))
                if isinstance(done, dict) and done.get('pending') != True:
                    continue
            label = server.get('name') or server.get('uid') or idx
            entry = {'server': label, 'uid': server.get('uid')}
            report.append(entry)
            try:
                smartr = await self._smartr(server)
                if not await asyncio.to_thread(smartr.is_installed):
                    entry['state'] = 'not-installed'
                    continue
                result = await asyncio.to_thread(smartr.migrate_timer)
                entry.update(result)
                if result['state'] == 'migrated':
                    logger.warning(
                        "smartroute: timer unit of %s was legacy (OnUnitActiveSec) "
                        "and has been rewritten to an absolute schedule (%s)",
                        label, result.get('detail') or 'no backup')
                elif result['state'].startswith('failed'):
                    logger.warning("smartroute: timer migration failed on %s: %s",
                                   label, result.get('detail') or result['state'])
                # An unrecognised answer (no marker in the script output) is
                # not proof of success: keep the host pending instead of
                # closing the one-shot migration on an empty read.
                await self._set_timer_migration(
                    entry['uid'],
                    ok=not (result['state'].startswith('failed')
                            or result['state'] == 'unknown'),
                    state=result['state'])
            except Exception as err:
                logger.warning("smartroute timer migration on %s failed: %s", label, err)
                entry['state'] = 'failed-exception'
                entry['detail'] = str(err)
        return report

    async def _set_timer_migration(self, uid, *, ok, state):
        """Record the per-host outcome in data.json (best effort)."""
        if not uid:
            return
        try:
            async with self.data_lock:
                data = self.load_data()
                rec = (data.setdefault('panel_migrations', {})
                       .setdefault(SMARTR_TIMER_MIGRATION_KEY, {}))
                hosts = rec.setdefault('hosts', {})
                hosts[uid] = {'state': state,
                              'at': datetime.now(timezone.utc).isoformat(timespec='seconds')}
                if ok:
                    hosts[uid].pop('pending', None)
                else:
                    hosts[uid]['pending'] = True
                self.save_data(data)
        except Exception as err:
            logger.warning("smartroute: could not record timer migration of %s: %s",
                           uid, err)

    @staticmethod
    def _timer_migration_hosts(data):
        """Per-host timer migration bookkeeping from data.json (read-only)."""
        migrations = data.get('panel_migrations') or {}
        rec = migrations.get(SMARTR_TIMER_MIGRATION_KEY) or {}
        hosts = rec.get('hosts') or {}
        return hosts if isinstance(hosts, dict) else {}

    def _remember_prefix_list(self, uid, error, count):
        """Remember the last prefix-list reading for one host (in memory).

        A later pass reuses it when the host is briefly unreachable instead of
        returning "0 prefixes" and standing down for the whole fleet. The panel
        does not persist this anywhere: a restart re-reads the host, so a stale
        cache cannot outlive the process.
        """
        if uid:
            self._prefix_cache[uid] = (time.monotonic(), error, int(count))

    def _cached_prefix_list(self, uid):
        """(error, count) from the cache, or None when absent/expired."""
        entry = self._prefix_cache.get(uid or '')
        if not entry:
            return None
        stored_at, error, count = entry
        if time.monotonic() - stored_at > SMARTR_PREFIX_CACHE_TTL:
            return None
        return (error, count)

    async def _prefix_list_health(self, server):
        """(error, v4_count) of this host's prefix list, best effort.

        The list lives on the panel-managed host, and every host has its own:
        a broken download on one server must not stop the self-heal of the
        others, and an unreachable host must not decide the fate of a pass that
        was started for a different one. The reading is cached per uid for a
        short while so repeated passes do not re-probe every host.
        """
        uid = server.get('uid')
        cached = self._cached_prefix_list(uid)
        if cached is not None:
            return cached
        try:
            smartr = await self._smartr(server)
            status = await asyncio.to_thread(smartr.host_status)
        except Exception as err:
            return str(err), 0
        # host_status merges status.json both flat and under 'status';
        # accept either shape so the guard never depends on the manager
        # version that produced it.
        counts = status.get('status') if isinstance(status.get('status'), dict) else status
        try:
            error = status.get('error')
            count = int(counts.get('prefixes_v4') or 0)
        except (TypeError, ValueError):
            return 'invalid prefix count', 0
        self._remember_prefix_list(uid, error, count)
        return error, count

    async def reconcile(self, server_id=None):
        """Re-apply split routing to instances whose in-container state is gone.

        Every path that recreates an AWG container (kernel/plugin upgrade,
        ``docker restart``, host reboot, image change) wipes table 200 and the
        mangle accounting chains, while the panel still records the instance
        as split. Until now only the hourly host timer put the throw routes
        back - and if that timer was stuck, RU traffic silently went through
        the exit node with no error anywhere (ZK, 2026-11-19).

        This pass asks the container for its throw count and re-applies the
        host-side enable when it is zero. Idempotent: a healthy instance is
        only read. Never raises for a single container - the report says what
        failed, and the next round retries.
        """
        data = self.load_data()
        servers = data.get('servers') or []
        if server_id is None:
            targets = list(enumerate(servers))
        else:
            targets = [(server_id, self._server(data, server_id))]
        targets = [(idx, server) for idx, server in targets
                   if (server.get('smartroute') or {}).get('installed')
                   and (server.get('smartroute') or {}).get('enabled', True)
                   and self._split_instances_of(server)]
        if not targets:
            return []
        report = []
        for idx, server in targets:
            # The list is per host. A stale `error` from the last download does
            # NOT make it unusable: the host script keeps the previous file on
            # a failed fetch and reports its real count, so only the count
            # decides. Skipping one host must not stop the others - an
            # unreachable host previously cancelled the whole pass, including
            # the reconcile started right after a plugin update.
            list_error, list_count = await self._prefix_list_health(server)
            if list_count < SMARTR_MIN_PREFIXES:
                logger.warning(
                    "smartroute: reconcile of %s skipped - prefix list is not "
                    "usable (v4=%s error=%s)", server.get('name') or idx,
                    list_count, list_error or 'none')
                report.append({'server': server.get('name') or idx,
                               'protocol': '-', 'skipped': 'prefix-list',
                               'prefixes_v4': list_count, 'error': list_error})
                continue
            if list_error:
                logger.info("smartroute: %s keeps its last good prefix list "
                            "(download error: %s)",
                            server.get('name') or idx, list_error)
            identity = self._identity(server)
            label = server.get('name') or server.get('uid') or idx
            for proto, _link in self._split_instances_of(server):
                entry = {'server': label, 'protocol': proto}
                report.append(entry)
                try:
                    awg = await self._awg(server)
                    container, config_path, subnet_default = await self._container_ctx(awg, proto)
                    smartr = await self._smartr(server)
                    before = await asyncio.to_thread(
                        smartr.instance_counters, container, config_path, subnet_default)
                    throws = int(before.get('throw_routes') or 0)
                    entry['throw_routes'] = throws
                    if throws:
                        # Healthy. Clear a leftover "lost" badge so the UI does
                        # not keep warning after the routes are back.
                        await self._set_lost(identity, proto, False)
                        continue
                    # enable_instance restores both the throw routes and the
                    # accounting chains, and is a plain re-apply when present.
                    await asyncio.to_thread(smartr.enable_instance, container,
                                            config_path, subnet_default)
                    after = await asyncio.to_thread(
                        smartr.instance_counters, container, config_path, subnet_default)
                    restored = int(after.get('throw_routes') or 0)
                    entry.update({'repaired': True, 'throw_routes_after': restored})
                    logger.warning(
                        "smartroute: %s/%s had no split routes (container was "
                        "recreated?); re-applied, %s throw routes now",
                        label, proto, restored)
                    if not restored:
                        entry['error'] = 'no throw routes after re-apply (empty prefix list?)'
                    await self._set_lost(identity, proto, not restored)
                except Exception as err:
                    logger.warning("smartroute reconcile of %s/%s failed: %s",
                                   label, proto, err)
                    entry['error'] = str(err)
        return report

    async def _set_lost(self, identity, protocol, lost):
        """Persist the UI badge flag; never fail the reconcile pass for it."""
        try:
            async with self.data_lock:
                data = self.load_data()
                server = self._resolve_identity(data, identity)
                rec = (server.get('protocols') or {}).get(protocol) or {}
                link = rec.get('exit_link')
                if link is None or bool(link.get('smart_route_lost')) == bool(lost):
                    return
                link['smart_route_lost'] = bool(lost)
                self.save_data(data)
        except Exception as err:
            logger.warning("smartroute: could not record smart_route_lost for %s: %s",
                           protocol, err)

    # ----- counters (merged into the exit-link status payload) -----

    async def counters(self, server_id, protocol):
        data = self.load_data()
        server, _rec, link = self._entry(data, server_id, protocol)
        if not link.get('smart_route'):
            return {'enabled': False}
        awg = await self._awg(server)
        container, config_path, subnet_default = await self._container_ctx(awg, protocol)
        smartr = await self._smartr(server)
        out = await asyncio.to_thread(smartr.instance_counters, container, config_path, subnet_default)
        return {'enabled': True, **out}
