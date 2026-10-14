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
        return sm

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
            'host': host,
            'own_subnets': sm.get('own_subnets', []),
            'dns_via_exit': bool(sm.get('dns_via_exit', False)),
            'split_instances': [p for p, _ in split_instances(data, server_id)],
        }

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
