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
from collections import defaultdict

from managers.awg_manager import AWG_DEFAULTS
from managers.smartroute_manager import SmartRouteManager, normalize_cidrs

logger = logging.getLogger(__name__)


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

    # ----- helpers -----

    def _server(self, data, server_id):
        servers = data.get('servers', [])
        if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
            raise SmartRouteError('server_not_found', 'Server not found', 404)
        return servers[server_id]

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

    def _dns_pair(self, data, server_id):
        sm = (self._server(data, server_id).get('smartroute') or {})
        direct = (sm.get('direct_dns') or '77.88.8.8').strip()
        exit_ = (sm.get('exit_dns') or '1.1.1.1').strip()
        return f"{direct}, {exit_}"

    async def _apply_dns_for_split(self, server_id, protocol, enabled):
        """Point a split instance's client configs at the resolver pair, or
        restore what the instance had before its first split.

        Non-fatal by design: the routing works without it, so a failing DNS
        rewrite must not break the split toggle itself."""
        data = self.load_data()
        server = self._server(data, server_id)
        rec = (server.get('protocols') or {}).get(protocol) or {}
        link = rec.get('exit_link') or {}
        awg = await self._awg(server)
        try:
            if enabled:
                if 'smart_route_prev_dns' not in link:
                    current = await asyncio.to_thread(awg._read_config_key, protocol, 'DNS')

                    def remember(lk):
                        lk.setdefault('smart_route_prev_dns', current)
                    await self._update_link(server_id, protocol, remember)
                pair = self._dns_pair(self.load_data(), server_id)
                await asyncio.to_thread(awg.update_awg_settings, protocol, dns=pair)
            elif 'smart_route_prev_dns' in link:
                prev = link.get('smart_route_prev_dns')

                def forget(lk):
                    lk.pop('smart_route_prev_dns', None)
                await asyncio.to_thread(awg.update_awg_settings, protocol,
                                        dns=prev if prev else '')
                await self._update_link(server_id, protocol, forget)
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

    async def _update_link(self, server_id, protocol, mutate):
        async with self.data_lock:
            data = self.load_data()
            rec = ((self._server(data, server_id).get('protocols') or {}).get(protocol)) or {}
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

    async def install(self, server_id):
        data = self.load_data()
        server = self._server(data, server_id)
        smartr = await self._smartr(server)
        log = await asyncio.to_thread(smartr.install)
        async with self.data_lock:
            data = self.load_data()
            server = self._server(data, server_id)
            self._settings(server)['installed'] = True
            self._settings(server)['enabled'] = True
            self.save_data(data)
        return {'status': 'success', 'log': log}

    async def uninstall(self, server_id):
        data = self.load_data()
        server = self._server(data, server_id)
        splits = split_instances(self.load_data(), server_id)

        # 1) Per-container rollback FIRST (containers still exist and are
        #    marked): throw routes out, accounting down, conntrack flushed.
        #    After this the clients are back on "everything via exit0".
        for proto, _link in splits:
            try:
                awg = await self._awg(server)
                container, config_path, subnet_default = await self._container_ctx(awg, proto)
                smartr = await self._smartr(server)
                await asyncio.to_thread(smartr.disable_instance, container, config_path, subnet_default)
                await self._apply_dns_for_split(server_id, proto, False)
            except Exception as err:
                logger.warning("smartroute rollback of %s failed: %s", proto, err)

        # 2) Host cleanup (files, timer, leftover markers). Its own container
        #    loop is a no-op now - the markers are already gone.
        smartr = await self._smartr(server)
        log = await asyncio.to_thread(smartr.uninstall)

        # 3) Record the rollback so the UI badges every affected instance.
        async with self.data_lock:
            data = self.load_data()
            server = self._server(data, server_id)
            sm = server.get('smartroute') or {}
            sm['installed'] = False
            sm['enabled'] = False
            server['smartroute'] = sm
            for proto, link in split_instances(data, server_id):
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
        for proto, _link in split_instances(data, server_id):
            try:
                container, config_path, subnet_default = await self._container_ctx(awg, proto)
                if enabled:
                    await asyncio.to_thread(smartr.enable_instance, container, config_path, subnet_default)
                else:
                    await asyncio.to_thread(smartr.disable_instance, container, config_path, subnet_default)
                applied.append(proto)
                await self._apply_dns_for_split(server_id, proto, enabled)
            except Exception as err:
                logger.warning("smartroute %s of %s failed: %s",
                               'resume' if enabled else 'pause', proto, err)
                failed.append({'protocol': proto, 'error': str(err)})

        async with self.data_lock:
            data = self.load_data()
            self._settings(self._server(data, server_id))['enabled'] = enabled
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
        if not (server.get('smartroute') or {}).get('installed'):
            raise SmartRouteError('app_not_installed',
                                  'Install Smart Route from the marketplace first', 409)
        async with self.data_lock:
            data = self.load_data()
            sm = self._settings(self._server(data, server_id))
            sm['direct_dns'] = direct
            sm['exit_dns'] = exit_
            self.save_data(data)
        pair = f"{direct}, {exit_}"
        applied, failed = [], []
        for proto, _link in split_instances(self.load_data(), server_id):
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
        smartr = await self._smartr(server)
        await asyncio.to_thread(smartr.set_own_subnets, normalized)
        async with self.data_lock:
            data = self.load_data()
            self._settings(self._server(data, server_id))['own_subnets'] = normalized
            self.save_data(data)
        # Refresh every split instance so the new subnets take effect now.
        for proto, _link in split_instances(self.load_data(), server_id):
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
            await self._update_link(server_id, protocol, mutate)
            await self._apply_dns_for_split(server_id, protocol, enabled)

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
        self._settings(server)  # ensure shape (save below under lock)
        async with self.data_lock:
            data = self.load_data()
            self._settings(self._server(data, server_id))['dns_via_exit'] = bool(enabled)
            self.save_data(data)
        results = []
        if self.apply_dns_via_exit is not None:
            for proto, _link in split_instances(self.load_data(), server_id):
                try:
                    await self.apply_dns_via_exit(server_id, proto, bool(enabled))
                    results.append({'protocol': proto, 'status': 'success'})
                except Exception as err:
                    logger.warning("dns_via_exit for %s failed: %s", proto, err)
                    results.append({'protocol': proto, 'status': 'error', 'error': str(err)})
        return {'status': 'success', 'dns_via_exit': bool(enabled), 'results': results}

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
