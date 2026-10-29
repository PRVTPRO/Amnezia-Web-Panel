"""Orchestration of exit-node links between two panel servers.

An *entry* AWG instance is linked to an *exit* node in three SSH steps on two
servers: the entry generates its key pair, the exit registers it as a peer,
the entry writes exit0.conf and reroutes its clients. Every step is idempotent
and a failed link is rolled back, so a link is recorded in data.json only
when the tunnel is really up (or the caller insisted with force=True).

Dependencies are injected (like ConnectionService) so the whole flow is unit
tested with fake managers and an in-memory data.json.
"""

import asyncio
import logging
import re
import time
from collections import defaultdict
from datetime import datetime

import exit_failover as failover_policy

logger = logging.getLogger(__name__)

EXIT_MTU_LIMIT = 1420          # exit0 MTU; client MTU must not exceed it
HANDSHAKE_WAIT_SECONDS = 15
HANDSHAKE_POLL_SECONDS = 2


class ExitLinkError(Exception):
    """A user-facing failure: `code` is a stable identifier for the UI/i18n."""

    def __init__(self, code, message, status_code=400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def peer_id_for(entry_uid, protocol):
    """Identity of an entry instance on the exit: one link per AWG instance."""
    return f"{entry_uid}:{protocol}"


class ExitLinkService:
    def __init__(self, *, load_data, save_data, data_lock, get_ssh,
                 awg_manager_factory, exit_manager_factory,
                 protocol_base, awg_protocols, protocol_display_name,
                 find_server_by_uid, sleep=None, time_fn=None):
        self.load_data = load_data
        self.save_data = save_data
        self.data_lock = data_lock
        self.get_ssh = get_ssh
        self.awg_manager_factory = awg_manager_factory
        self.exit_manager_factory = exit_manager_factory
        self.protocol_base = protocol_base
        self.awg_protocols = awg_protocols
        self.protocol_display_name = protocol_display_name
        self.find_server_by_uid = find_server_by_uid
        self._sleep = sleep or asyncio.sleep
        self._time = time_fn or time.time
        # Two SSH sessions and no cross-server lock: serialize per (entry, protocol)
        self._locks = defaultdict(asyncio.Lock)
        # Automatic switches of different entries still go one at a time so a
        # failed apply can restore the previous conf without overlapping writes.
        self._failover_switch_lock = asyncio.Lock()

    # ----- read-only helpers (no SSH) -----

    def list_exit_nodes(self, data):
        nodes = []
        for idx, server in enumerate(data.get('servers', [])):
            rec = (server.get('protocols') or {}).get('exit') or {}
            if not rec.get('installed'):
                continue
            nodes.append({
                'uid': server.get('uid', ''),
                'server_id': idx,
                'name': server.get('name') or server.get('host', ''),
                'host': server.get('host', ''),
                'port': rec.get('port'),
                'subnet': rec.get('subnet'),
                'obfuscation': bool(rec.get('obfuscation')),
            })
        return nodes

    def linked_entries(self, data, exit_uid):
        """Every (server, protocol) whose exit_link points at `exit_uid`."""
        entries = []
        if not exit_uid:
            return entries
        for idx, server in enumerate(data.get('servers', [])):
            for proto, rec in (server.get('protocols') or {}).items():
                link = (rec or {}).get('exit_link') or {}
                if link.get('exit_uid') == exit_uid:
                    entries.append({
                        'server_id': idx,
                        'server_uid': server.get('uid', ''),
                        'name': server.get('name') or server.get('host', ''),
                        'protocol': proto,
                        'stale': link.get('stale'),
                    })
        return entries

    # ----- validation -----

    def _entry(self, data, server_id, protocol):
        servers = data.get('servers', [])
        if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
            raise ExitLinkError('server_not_found', 'Server not found', 404)
        server = servers[server_id]
        if self.protocol_base(protocol) not in self.awg_protocols:
            raise ExitLinkError('protocol_not_awg', 'Only AmneziaWG instances can be linked to an exit node')
        rec = (server.get('protocols') or {}).get(protocol)
        if not rec or not rec.get('installed'):
            raise ExitLinkError('protocol_not_installed', f'{protocol} is not installed on this server')
        if not server.get('uid'):
            raise ExitLinkError('entry_no_uid', 'This server has no uid yet; restart the panel once', 500)
        return server, rec

    def _exit(self, data, exit_uid):
        _, server = self.find_server_by_uid(data, exit_uid)
        rec = ((server or {}).get('protocols') or {}).get('exit') or {}
        if not server or not rec.get('installed'):
            raise ExitLinkError('exit_not_found', 'Exit node not found or not installed', 404)
        return server, rec

    async def _awg(self, server):
        # get_ssh() blocks on ensure_connected (TCP+SSH handshake, up to the
        # connect timeout) — never run it inside the event loop.
        return self.awg_manager_factory(await asyncio.to_thread(self.get_ssh, server))

    async def _exit_manager(self, server):
        return self.exit_manager_factory(await asyncio.to_thread(self.get_ssh, server))

    # ----- persistence under the lock, resolved by uid (indices may shift) -----

    async def _update_record(self, entry_uid, protocol, mutate):
        async with self.data_lock:
            data = self.load_data()
            _, server = self.find_server_by_uid(data, entry_uid)
            rec = ((server or {}).get('protocols') or {}).get(protocol)
            if rec is None:
                return None
            mutate(rec)
            self.save_data(data)
            return rec

    # ----- link / unlink -----

    async def _wait_handshake(self, awg, protocol):
        polls = max(1, HANDSHAKE_WAIT_SECONDS // HANDSHAKE_POLL_SECONDS)
        for attempt in range(polls):
            status = await asyncio.to_thread(awg.exit_link_status, protocol)
            if status and status.get('handshake_age') is not None:
                return status
            if attempt < polls - 1:
                await self._sleep(HANDSHAKE_POLL_SECONDS)
        return None

    async def _rollback(self, awg, protocol, exit_manager, peer_id):
        for what, call in (('entry unlink', lambda: awg.exit_unlink(protocol)),
                           ('exit remove_peer', lambda: exit_manager.remove_peer(peer_id=peer_id))):
            try:
                await asyncio.to_thread(call)
            except Exception as err:  # the original error is what the user must see
                logger.warning("exit link rollback: %s failed: %s", what, err)

    @staticmethod
    def _require_exit_dns(exit_srv):
        """DNS via the exit only works when that node runs AmneziaDNS: the
        clients keep resolving 172.29.172.254, which is answered on whichever
        node the query comes out of."""
        dns_rec = (exit_srv.get('protocols') or {}).get('dns') or {}
        if not dns_rec.get('installed'):
            raise ExitLinkError('exit_dns_needs_dns',
                                'Install AmneziaDNS on the exit node before routing client DNS through it')

    async def set_dns_via_exit(self, entry_server_id, protocol, enabled):
        """Turn client DNS resolution at the exit node on or off for a linked
        instance. Off (the default) keeps DNS on the entry node."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        enabled = bool(enabled)
        if enabled:
            exit_srv, _ = self._exit(data, link.get('exit_uid'))
            self._require_exit_dns(exit_srv)
        async with self._locks[(entry['uid'], protocol)]:
            awg = await self._awg(entry)
            try:
                log = await asyncio.to_thread(awg.exit_set_dns_via_exit, protocol, enabled)
            except Exception as err:
                raise ExitLinkError('exit_apply_failed', str(err))
            await self._update_record(
                entry['uid'], protocol,
                lambda r: (r.get('exit_link') or {}).__setitem__('dns_via_exit', enabled))
        return {'status': 'success', 'dns_via_exit': enabled, 'log': [log]}

    async def disable_dns_via_exit_for_exit(self, exit_uid):
        """AmneziaDNS is gone from an exit node: bring the DNS of every entry
        linked to it back home instead of leaving queries in a black hole."""
        results = []
        data = self.load_data()
        for item in self.linked_entries(data, exit_uid):
            _, rec = self._entry(data, item['server_id'], item['protocol'])
            if not (rec.get('exit_link') or {}).get('dns_via_exit'):
                continue
            try:
                await self.set_dns_via_exit(item['server_id'], item['protocol'], False)
                results.append({**item, 'status': 'success'})
            except Exception as err:
                logger.warning("could not bring DNS back to entry %s/%s: %s",
                               item['server_id'], item['protocol'], err)
                results.append({**item, 'status': 'error', 'error': str(err)})
        return results

    async def link(self, entry_server_id, protocol, exit_uid, force=False, dns_via_exit=None,
                   *, restore_on_failure=False, source='manual', _locked=False):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        exit_srv, exit_rec = self._exit(data, exit_uid)
        if exit_srv.get('uid') == entry['uid']:
            raise ExitLinkError('exit_self', 'A server cannot be its own exit node')
        if self.protocol_base(protocol) == 'awg_legacy' and exit_rec.get('obfuscation'):
            raise ExitLinkError('exit_legacy_obfuscation',
                                'AmneziaWG Legacy can only link to a non-obfuscated exit node')
        previous = rec.get('exit_link') or {}
        explicit_dns = dns_via_exit is not None
        dns_via_exit = bool(previous.get('dns_via_exit') if dns_via_exit is None else dns_via_exit)
        peer_id = peer_id_for(entry['uid'], protocol)
        warnings, log = [], []
        if dns_via_exit:
            try:
                self._require_exit_dns(exit_srv)
            except ExitLinkError:
                # Repairing a link must not fail over an option the caller did
                # not ask for; the flag inherited from the saved link is dropped
                # so DNS comes back to this node instead of a black hole.
                if explicit_dns:
                    raise
                dns_via_exit = False
                warnings.append('exit_dns_disabled_no_dns')
        if restore_on_failure and not previous.get('exit_uid'):
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')

        async def _go():
            nonlocal warnings, log
            awg = await self._awg(entry)
            entry_pub = await asyncio.to_thread(awg.exit_prepare_keys, protocol)
            try:
                mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
            except (TypeError, ValueError):
                mtu = 0
            ipv6 = bool(await asyncio.to_thread(awg._get_subnet_ipv6_ip, protocol))
            if mtu > EXIT_MTU_LIMIT and not force:
                raise ExitLinkError('exit_mtu_too_big',
                                    f'Client MTU {mtu} exceeds the link MTU {EXIT_MTU_LIMIT}; '
                                    f'lower it in the AWG settings or link anyway')

            # The peer on a previous exit is dropped only after the new link is
            # confirmed (below): until then the old exit is what Repair falls
            # back to if this attempt has to be rolled back.
            switching = bool(previous.get('exit_uid')) and previous['exit_uid'] != exit_uid

            if restore_on_failure:
                try:
                    await asyncio.to_thread(awg.exit_backup_conf, protocol)
                except Exception as err:
                    raise ExitLinkError('exit_apply_failed',
                                        f'Could not snapshot the current exit link: {err}')

            exit_manager = await self._exit_manager(exit_srv)

            async def rolled_back():
                # Manual link: teardown so a half-applied conf cannot leak.
                # Failover switch: restore the previous conf so clients keep
                # the last working (or last known) exit instead of a hole.
                if restore_on_failure:
                    restored = False
                    try:
                        await asyncio.to_thread(awg.exit_restore_conf, protocol)
                        restored = True
                    except Exception as err:
                        logger.warning("exit failover restore failed, falling back to unlink: %s", err)
                    try:
                        await asyncio.to_thread(exit_manager.remove_peer, None, peer_id)
                    except Exception as err:
                        logger.warning("exit link rollback: exit remove_peer failed: %s", err)
                    if restored:
                        return True
                await self._rollback(awg, protocol, exit_manager, peer_id)
                if previous.get('exit_uid'):
                    reason = 'switch_failed' if switching else 'relink_failed'
                    await self._update_record(entry['uid'], protocol,
                                              lambda r: (r.get('exit_link') or {}).__setitem__('stale', reason))
                return False

            name = f"{entry.get('name') or entry.get('host', '')} / {self.protocol_display_name(protocol)}"
            peer = await asyncio.to_thread(exit_manager.add_peer, peer_id, name, entry_pub)
            link = {
                'exit_uid': exit_uid,
                'exit_name': exit_srv.get('name') or exit_srv.get('host', ''),
                'transit_ip': peer['transit_ip'],
                'subnet_cidr': str(peer.get('subnet') or '10.9.0.0/24').split('/')[1],
                'exit_public_key': peer['public_key'],
                'psk': peer['psk'],
                'endpoint_host': exit_srv['host'],
                'endpoint_port': peer['port'] or exit_rec.get('port'),
                'obfuscation': bool(peer.get('obfuscation')),
                'awg_params': peer.get('awg_params') or {},
                'dns_via_exit': dns_via_exit,
            }
            try:
                log.append(await asyncio.to_thread(awg.exit_link, protocol, link))
            except Exception as err:
                await rolled_back()
                raise ExitLinkError('exit_apply_failed', str(err))

            handshake = await self._wait_handshake(awg, protocol)
            if not handshake:
                if not force:
                    await rolled_back()
                    raise ExitLinkError('exit_no_handshake',
                                        f"No handshake from the exit node within {HANDSHAKE_WAIT_SECONDS} s "
                                        f"(is {link['endpoint_port']}/udp reachable on {link['endpoint_host']}?). "
                                        f"The link was rolled back")
                warnings.append('no_handshake_yet')

            if switching:
                # New link confirmed: drop our peer on the previous exit, best effort.
                try:
                    old_exit, _ = self._exit(data, previous['exit_uid'])
                    old_exit_manager = await self._exit_manager(old_exit)
                    await asyncio.to_thread(old_exit_manager.remove_peer, None, peer_id)
                except Exception as err:
                    logger.warning("previous exit %s unreachable, peer left behind: %s", previous['exit_uid'], err)
                    warnings.append('old_exit_unreachable_orphan_peer')

            record = {
                'exit_uid': exit_uid,
                'exit_name': link['exit_name'],
                'transit_ip': link['transit_ip'],
                'exit_public_key': link['exit_public_key'],
                'endpoint_host': link['endpoint_host'],
                'endpoint_port': link['endpoint_port'],
                'obfuscation': link['obfuscation'],
                'dns_via_exit': dns_via_exit,
                'linked_at': datetime.now().isoformat(),
                'stale': None,
            }
            await self._update_record(
                entry['uid'], protocol,
                lambda r: self._persist_link_record(r, record, source, exit_uid))
            return {'status': 'success', 'exit_link': record, 'ipv6_refused': ipv6,
                    'warnings': warnings, 'log': log}

        if _locked:
            return await _go()
        async with self._locks[(entry['uid'], protocol)]:
            return await _go()

    async def unlink(self, entry_server_id, protocol):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            return {'status': 'success', 'warnings': [], 'unlinked': False}
        warnings = []
        async with self._locks[(entry['uid'], protocol)]:
            # Entry first: direct egress must come back even when the exit is dead.
            awg = await self._awg(entry)
            await asyncio.to_thread(awg.exit_unlink, protocol)
            try:
                exit_srv, _ = self._exit(data, link.get('exit_uid'))
                exit_manager = await self._exit_manager(exit_srv)
                await asyncio.to_thread(exit_manager.remove_peer, None,
                                        peer_id_for(entry['uid'], protocol))
            except Exception as err:
                logger.warning("exit %s unreachable on unlink, peer left behind: %s", link.get('exit_uid'), err)
                warnings.append('exit_unreachable_orphan_peer')
            await self._update_record(entry['uid'], protocol, lambda r: self._drop_link_keep_failover(r))
        return {'status': 'success', 'warnings': warnings, 'unlinked': True}

    async def relink_entry(self, entry_server_id, protocol):
        data = self.load_data()
        _, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        return await self.link(entry_server_id, protocol, link['exit_uid'], force=True)

    async def relink_entries_for_exit(self, exit_uid):
        """After an exit node was reinstalled: re-register every linked entry."""
        results = []
        for item in self.linked_entries(self.load_data(), exit_uid):
            try:
                await self.relink_entry(item['server_id'], item['protocol'])
                results.append({**item, 'status': 'success', 'error': None})
            except Exception as err:
                logger.warning("re-link %s/%s failed: %s", item['name'], item['protocol'], err)
                results.append({**item, 'status': 'error', 'error': str(err)})
        return results

    async def reconcile_after_restore(self, server_id, protocol):
        """A protocol restore overwrites the very files a link lives in: the
        entry keeps exit0.conf inside its AWG config directory, the exit keeps
        its peer table. So an archive can bring back a link the panel does not
        know about, drop the one it does, or restore a peer list that no longer
        matches the entries. Called after a successful restore to make the two
        sides agree again."""
        data = self.load_data()
        base = self.protocol_base(protocol)

        if base == 'exit':
            servers = data.get('servers', [])
            if not isinstance(server_id, int) or server_id < 0 or server_id >= len(servers):
                return {}
            uid = servers[server_id].get('uid')
            entries = await self.relink_entries_for_exit(uid) if uid else []
            return {'exit_entries_relinked': entries} if entries else {}

        if base not in self.awg_protocols:
            return {}
        try:
            entry, rec = self._entry(data, server_id, protocol)
        except ExitLinkError:
            return {}

        if rec.get('exit_link'):
            try:
                await self.relink_entry(server_id, protocol)
                return {'exit_link_restored': 'relinked'}
            except Exception as err:
                logger.warning("re-link after restore failed for %s/%s: %s",
                               entry.get('name'), protocol, err)
                await self._update_record(
                    entry['uid'], protocol,
                    lambda r: (r.get('exit_link') or {}).__setitem__('stale', 'restore_relink_failed'))
                return {'exit_link_restored': 'stale', 'exit_link_error': str(err)}

        # The panel knows of no link, so a link file coming out of the archive
        # would silently route clients through an exit nobody is tracking.
        try:
            awg = await self._awg(entry)
            info = await asyncio.to_thread(awg.exit_link_info, protocol)
        except Exception as err:
            logger.warning("could not read the link state after restore: %s", err)
            return {}
        if not info:
            return {}
        try:
            await asyncio.to_thread(awg.exit_unlink, protocol)
            return {'exit_link_restored': 'removed', 'exit_name': info.get('exit_name', '')}
        except Exception as err:
            logger.warning("could not remove the restored link file: %s", err)
            return {'exit_link_restored': 'orphan', 'exit_name': info.get('exit_name', '')}

    async def detach_entries_for_exit(self, exit_uid, reason):
        """The exit is gone (uninstalled, deleted, cleared): restore direct
        egress on every linked entry; unreachable ones keep the record marked
        stale so the UI offers Unlink/Repair and the kill-switch keeps
        protecting their clients."""
        results = []
        data = self.load_data()
        for item in self.linked_entries(data, exit_uid):
            entry = data['servers'][item['server_id']]
            try:
                awg = await self._awg(entry)
                await asyncio.to_thread(awg.exit_unlink, item['protocol'])
                await self._update_record(item['server_uid'], item['protocol'],
                                          lambda r: self._drop_link_keep_failover(r))
                results.append({**item, 'status': 'success', 'error': None})
            except Exception as err:
                logger.warning("detach %s/%s failed, marking stale: %s", item['name'], item['protocol'], err)
                await self._update_record(item['server_uid'], item['protocol'],
                                          lambda r: (r.get('exit_link') or {}).__setitem__('stale', reason))
                results.append({**item, 'status': 'error', 'error': str(err)})
        return results

    async def forget_entry_peers(self, server):
        """An entry server is deleted or cleared: drop its peers on the exits."""
        results = []
        data = self.load_data()
        for proto, rec in (server.get('protocols') or {}).items():
            link = (rec or {}).get('exit_link') or {}
            if not link.get('exit_uid') or not server.get('uid'):
                continue
            try:
                exit_srv, _ = self._exit(data, link['exit_uid'])
                exit_manager = await self._exit_manager(exit_srv)
                await asyncio.to_thread(exit_manager.remove_peer, None,
                                        peer_id_for(server['uid'], proto))
                results.append({'protocol': proto, 'exit_uid': link['exit_uid'], 'status': 'success'})
            except Exception as err:
                logger.warning("could not drop peer for %s on exit %s: %s", proto, link['exit_uid'], err)
                results.append({'protocol': proto, 'exit_uid': link['exit_uid'], 'status': 'error', 'error': str(err)})
        return results

    @staticmethod
    def _endpoint_ip(status):
        """IPv4 of the live `host:port` endpoint of the link, or '' (an IPv6
        endpoint has no bearing on the IPv4-only egress probe)."""
        endpoint = (status or {}).get('endpoint') or ''
        host = endpoint.rsplit(':', 1)[0]
        return host if IPV4_RE.match(host) else ''

    async def check_egress(self, entry_server_id, protocol):
        """Ask the entry container which public IP its clients leave from and
        compare it with the exit node's address. `leaks` means the clients
        still leave from the entry node itself."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link')
        if not link:
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')
        awg = await self._awg(entry)
        try:
            probe = await asyncio.to_thread(awg.exit_check_egress, protocol)
        except RuntimeError as err:
            raise ExitLinkError('exit_egress_failed', str(err))
        via, direct = probe.get('via_exit', ''), probe.get('direct', '')
        expected = link.get('endpoint_host', '')
        # `endpoint_host` is whatever the admin typed when adding the server and
        # is often a hostname; the probe always answers with an address. The
        # live WireGuard endpoint is the resolved form of that same host, so it
        # is what the comparison uses when available.
        status = await asyncio.to_thread(awg.exit_link_status, protocol)
        expected_ip = self._endpoint_ip(status) or (expected if IPV4_RE.match(expected or '') else '')
        return {
            'status': 'success',
            'via_exit': via,
            'direct': direct,
            'expected': expected,
            'expected_ip': expected_ip,
            'exit_name': link.get('exit_name', ''),
            # A NATed exit answers from another address, so a mismatch is a
            # warning, not a failure; leaving from the entry address is not.
            'matches': bool(via) and bool(expected_ip) and via == expected_ip,
            'leaks': bool(via) and via == direct,
        }

    async def status(self, entry_server_id, protocol):
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        awg = await self._awg(entry)
        link_status = await asyncio.to_thread(awg.exit_link_status, protocol)
        try:
            mtu = int(await asyncio.to_thread(awg._get_mtu, protocol) or 0)
        except (TypeError, ValueError):
            mtu = 0
        ipv6 = bool(await asyncio.to_thread(awg._get_subnet_ipv6_ip, protocol))
        return {
            'status': 'success',
            'exit_link': rec.get('exit_link'),
            'exit_link_status': link_status,
            'exit_failover': self.failover_view(data, rec, entry.get('uid')),
            'ipv6': ipv6,
            'mtu': mtu,
            'exit_mtu': EXIT_MTU_LIMIT,
        }

    # ----- automatic exit failover (opt-in, disabled by default) -----

    @staticmethod
    def _persist_link_record(rec, record, source, exit_uid):
        rec['exit_link'] = record
        fo = rec.get('exit_failover')
        if not isinstance(fo, dict):
            return
        state = failover_policy.normalize_state(fo.get('state'))
        state['active_uid'] = exit_uid
        if source != 'failover':
            # A manual (un)link is operator intent: that exit becomes primary.
            state['primary_uid'] = exit_uid
            state['consecutive_failures'] = 0
            state['consecutive_successes'] = 0
            state['primary_healthy_since'] = None
            fo['backup_uids'] = [uid for uid in (fo.get('backup_uids') or []) if uid != exit_uid]
        fo['state'] = state
        rec['exit_failover'] = fo

    @staticmethod
    def _drop_link_keep_failover(rec):
        rec.pop('exit_link', None)
        fo = rec.get('exit_failover')
        if not isinstance(fo, dict):
            return
        # Unlink must not keep probing: disable, keep the backup list so the
        # operator can re-enable after linking again.
        fo['enabled'] = False
        state = failover_policy.normalize_state(fo.get('state'))
        state['active_uid'] = ''
        state['consecutive_failures'] = 0
        state['consecutive_successes'] = 0
        state['primary_healthy_since'] = None
        state['last_ok'] = None
        state['last_reason'] = 'not_linked'
        fo['state'] = state
        rec['exit_failover'] = fo

    def failover_view(self, data, rec, entry_uid):
        """JSON-safe failover config + state for the API/UI (no SSH)."""
        raw = rec.get('exit_failover') if isinstance(rec, dict) else None
        cfg = failover_policy.normalize_config(raw)
        state = failover_policy.normalize_state((raw or {}).get('state') if isinstance(raw, dict) else None)
        events = list((raw or {}).get('events') or []) if isinstance(raw, dict) else []
        nodes = {n['uid']: n for n in self.list_exit_nodes(data) if n.get('uid')}
        link = (rec or {}).get('exit_link') or {}
        if not state.get('primary_uid'):
            state['primary_uid'] = link.get('exit_uid') or ''
        if not state.get('active_uid'):
            state['active_uid'] = link.get('exit_uid') or ''
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry_uid,
            primary_uid=state.get('primary_uid'),
            known_exit_uids=nodes.keys(),
        )

        def named(uid):
            node = nodes.get(uid) or {}
            return {
                'uid': uid or '',
                'name': node.get('name') or '',
                'host': node.get('host') or '',
                'installed': uid in nodes,
            }

        return {
            **cfg,
            'state': state,
            'events': events[:failover_policy.MAX_EVENTS],
            'primary': named(state.get('primary_uid')),
            'active': named(state.get('active_uid') or link.get('exit_uid')),
            'backups': [named(uid) for uid in cfg['backup_uids']],
        }

    async def configure_failover(self, entry_server_id, protocol, **fields):
        """Opt-in per AWG instance. Missing/disabled is a no-op for existing
        single-exit setups. Backups are stored by server uid, never index."""
        data = self.load_data()
        entry, rec = self._entry(data, entry_server_id, protocol)
        link = rec.get('exit_link') or {}
        enabled = bool(fields.get('enabled'))
        if enabled and not link.get('exit_uid'):
            raise ExitLinkError('not_linked', 'This instance is not linked to an exit node')

        known = {n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')}
        stored = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        previous_state = failover_policy.normalize_state(stored.get('state'))
        primary_uid = (previous_state.get('primary_uid') or link.get('exit_uid') or '').strip()
        if enabled and primary_uid and primary_uid not in known:
            raise ExitLinkError('exit_not_found', 'Primary exit node not found or not installed', 404)
        if enabled and primary_uid == entry.get('uid'):
            raise ExitLinkError('exit_self', 'A server cannot be its own exit node')

        backups = failover_policy.sanitize_backup_uids(
            fields.get('backup_uids', stored.get('backup_uids')),
            entry_uid=entry.get('uid'),
            primary_uid=primary_uid,
            known_exit_uids=known,
        )
        if enabled and not backups:
            raise ExitLinkError('failover_no_backups',
                                'Add at least one backup exit node before enabling failover')

        merged = failover_policy.normalize_config({**stored, **{
            key: fields[key] for key in (
                'enabled', 'backup_uids', 'check_interval_seconds', 'failure_threshold',
                'failback_stable_seconds', 'handshake_max_age_seconds',
                'auto_failback', 'probe_egress',
            ) if key in fields
        }})
        merged['enabled'] = enabled
        merged['backup_uids'] = backups
        state = previous_state
        state['primary_uid'] = primary_uid
        state['active_uid'] = link.get('exit_uid') or state.get('active_uid') or primary_uid
        if not enabled:
            state['consecutive_failures'] = 0
            state['consecutive_successes'] = 0
            state['primary_healthy_since'] = None
        events = list(stored.get('events') or [])

        def mutate(r):
            payload = dict(merged)
            payload['state'] = state
            payload['events'] = events
            r['exit_failover'] = payload

        await self._update_record(entry['uid'], protocol, mutate)
        data = self.load_data()
        _, server = self.find_server_by_uid(data, entry['uid'])
        rec = ((server or {}).get('protocols') or {}).get(protocol) or {}
        return {
            'status': 'success',
            'exit_failover': self.failover_view(data, rec, entry['uid']),
        }

    async def _probe_active(self, entry, protocol, cfg):
        awg = await self._awg(entry)
        status = None
        status_missing = False
        handshake_error = None
        try:
            status = await asyncio.to_thread(awg.exit_link_status, protocol)
        except Exception as err:
            handshake_error = str(err)
        if status is None and not handshake_error:
            status_missing = True
        elif isinstance(status, dict) and status.get('error') and status.get('handshake_age') is None:
            handshake_error = status.get('error')
        egress = None
        if cfg['probe_egress']:
            try:
                probe = await asyncio.to_thread(awg.exit_check_egress, protocol)
                via, direct = probe.get('via_exit', ''), probe.get('direct', '')
                egress = {
                    'via_exit': via,
                    'direct': direct,
                    'leaks': bool(via) and via == direct,
                }
            except Exception as err:
                egress = {'error': str(err)}
        ok, reason = failover_policy.evaluate_active_health(
            handshake_age=None if not status else status.get('handshake_age'),
            handshake_error=handshake_error,
            status_missing=status_missing,
            egress=egress,
            probe_egress=cfg['probe_egress'],
            handshake_max_age=cfg['handshake_max_age_seconds'],
        )
        return ok, reason, {'status': status, 'egress': egress}

    async def _probe_candidate(self, exit_uid):
        data = self.load_data()
        try:
            exit_srv, rec = self._exit(data, exit_uid)
        except ExitLinkError:
            return False, failover_policy.REASON_EXIT_NOT_FOUND
        if not rec.get('installed'):
            return False, failover_policy.REASON_EXIT_NOT_FOUND
        try:
            manager = await self._exit_manager(exit_srv)
            running = await asyncio.to_thread(manager.check_container_running, 'exit')
        except Exception as err:
            logger.warning("failover candidate probe %s failed: %s", exit_uid, err)
            return False, failover_policy.REASON_SSH_ERROR
        ok, reason = failover_policy.evaluate_candidate_health(
            installed=True, container_running=bool(running), ssh_error=None)
        return ok, reason

    async def _persist_failover(self, entry_uid, protocol, cfg, state, events):
        def mutate(r):
            payload = failover_policy.normalize_config(r.get('exit_failover'))
            payload.update({
                'enabled': cfg.get('enabled', payload['enabled']),
                'backup_uids': cfg.get('backup_uids', payload['backup_uids']),
                'check_interval_seconds': cfg.get('check_interval_seconds', payload['check_interval_seconds']),
                'failure_threshold': cfg.get('failure_threshold', payload['failure_threshold']),
                'failback_stable_seconds': cfg.get('failback_stable_seconds', payload['failback_stable_seconds']),
                'handshake_max_age_seconds': cfg.get('handshake_max_age_seconds', payload['handshake_max_age_seconds']),
                'auto_failback': cfg.get('auto_failback', payload['auto_failback']),
                'probe_egress': cfg.get('probe_egress', payload['probe_egress']),
            })
            payload['state'] = state
            payload['events'] = events
            r['exit_failover'] = payload
        await self._update_record(entry_uid, protocol, mutate)

    async def tick_failover(self, entry_server_id, protocol):
        """One health-check of a single instance. No-op when disabled."""
        data = self.load_data()
        try:
            entry, rec = self._entry(data, entry_server_id, protocol)
        except ExitLinkError as err:
            return {'action': failover_policy.ACTION_NOOP, 'reason': err.code}

        raw = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        cfg = failover_policy.normalize_config(raw)
        if not cfg['enabled']:
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_DISABLED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        link = rec.get('exit_link') or {}
        if not link.get('exit_uid'):
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_NOT_LINKED,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        now = self._time()
        state = failover_policy.normalize_state(raw.get('state'))
        if not state.get('primary_uid'):
            state['primary_uid'] = link['exit_uid']
        if not state.get('active_uid'):
            state['active_uid'] = link['exit_uid']
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry.get('uid'),
            primary_uid=state.get('primary_uid'),
            known_exit_uids={n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')},
        )
        if not failover_policy.due_for_check(state, cfg['check_interval_seconds'], now):
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_NOT_DUE,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        lock = self._locks[(entry['uid'], protocol)]
        if lock.locked():
            return {'action': failover_policy.ACTION_NOOP, 'reason': failover_policy.REASON_BUSY,
                    'entry_uid': entry.get('uid'), 'protocol': protocol}

        async with lock:
            return await self._tick_failover_locked(entry['uid'], protocol, now)

    async def _tick_failover_locked(self, entry_uid, protocol, now):
        data = self.load_data()
        _, entry = self.find_server_by_uid(data, entry_uid)
        rec = ((entry or {}).get('protocols') or {}).get(protocol)
        if not entry or not rec:
            return {'action': failover_policy.ACTION_NOOP, 'reason': 'entry_gone',
                    'entry_uid': entry_uid, 'protocol': protocol}

        raw = rec.get('exit_failover') if isinstance(rec.get('exit_failover'), dict) else {}
        cfg = failover_policy.normalize_config(raw)
        link = rec.get('exit_link') or {}
        if not cfg['enabled'] or not link.get('exit_uid'):
            reason = (failover_policy.REASON_DISABLED if not cfg['enabled']
                      else failover_policy.REASON_NOT_LINKED)
            return {'action': failover_policy.ACTION_NOOP, 'reason': reason,
                    'entry_uid': entry_uid, 'protocol': protocol}

        state = failover_policy.normalize_state(raw.get('state'))
        if not state.get('primary_uid'):
            state['primary_uid'] = link['exit_uid']
        state['active_uid'] = link['exit_uid']
        events = list(raw.get('events') or [])
        known = {n['uid'] for n in self.list_exit_nodes(data) if n.get('uid')}
        cfg['backup_uids'] = failover_policy.sanitize_backup_uids(
            cfg['backup_uids'],
            entry_uid=entry_uid,
            primary_uid=state.get('primary_uid'),
            known_exit_uids=known,
        )

        active_ok, active_reason, _probe = await self._probe_active(entry, protocol, cfg)
        healthy = set()
        if active_ok:
            healthy.add(link['exit_uid'])

        primary_uid = state.get('primary_uid') or ''
        primary_ok = False
        if primary_uid:
            if primary_uid == link['exit_uid']:
                primary_ok = active_ok
            elif cfg['auto_failback'] or not active_ok:
                primary_ok, _primary_reason = await self._probe_candidate(primary_uid)
            if primary_ok:
                healthy.add(primary_uid)

        if not active_ok:
            for uid in cfg['backup_uids']:
                if uid == link['exit_uid'] or uid in healthy:
                    continue
                ok, _reason = await self._probe_candidate(uid)
                if ok:
                    healthy.add(uid)

        decision = failover_policy.decide(
            config=cfg,
            state=state,
            now=now,
            active_ok=active_ok,
            active_reason=active_reason,
            primary_ok=primary_ok,
            healthy_uids=healthy,
        )
        state = decision['state']
        action = decision['action']
        target = decision['target_uid']

        if action in (failover_policy.ACTION_FAILOVER, failover_policy.ACTION_FAILBACK) and target:
            from_uid = link['exit_uid']
            switch_ok = False
            switch_error = None
            async with self._failover_switch_lock:
                try:
                    # Re-resolve the entry by uid: indices may have shifted
                    # while we were probing.
                    data = self.load_data()
                    idx, current = self.find_server_by_uid(data, entry_uid)
                    if idx is None or current is None:
                        raise ExitLinkError('server_not_found', 'Server not found', 404)
                    await self.link(
                        idx, protocol, target, force=False,
                        restore_on_failure=True, source='failover', _locked=True)
                    switch_ok = True
                except Exception as err:
                    switch_error = str(err)
                    logger.warning("exit failover switch %s/%s %s -> %s failed: %s",
                                   entry_uid, protocol, from_uid, target, err)

            if switch_ok:
                state = failover_policy.record_switch(
                    state, now=now, from_uid=from_uid, to_uid=target,
                    action=action, reason=decision['reason'])
                events = failover_policy.append_event(
                    events, now=now, action=action, from_uid=from_uid,
                    to_uid=target, reason=decision['reason'])
                await self._persist_failover(entry_uid, protocol, cfg, state, events)
                return {
                    'action': action,
                    'reason': decision['reason'],
                    'from_uid': from_uid,
                    'to_uid': target,
                    'entry_uid': entry_uid,
                    'protocol': protocol,
                }

            events = failover_policy.append_event(
                events, now=now, action='switch_failed', from_uid=from_uid,
                to_uid=target, reason=switch_error or decision['reason'])
            await self._persist_failover(entry_uid, protocol, cfg, state, events)
            return {
                'action': 'switch_failed',
                'reason': switch_error or decision['reason'],
                'from_uid': from_uid,
                'to_uid': target,
                'entry_uid': entry_uid,
                'protocol': protocol,
            }

        if not active_ok and state['consecutive_failures'] == cfg['failure_threshold']:
            events = failover_policy.append_event(
                events, now=now, action='check_failed', from_uid=link['exit_uid'],
                to_uid='', reason=active_reason)

        await self._persist_failover(entry_uid, protocol, cfg, state, events)
        return {
            'action': action,
            'reason': decision['reason'],
            'from_uid': link.get('exit_uid'),
            'to_uid': None,
            'entry_uid': entry_uid,
            'protocol': protocol,
            'consecutive_failures': state['consecutive_failures'],
        }

    def list_failover_targets(self, data):
        """(server_id, protocol, entry_uid) for every instance with failover on."""
        targets = []
        for idx, server in enumerate(data.get('servers', [])):
            uid = server.get('uid')
            if not uid:
                continue
            for proto, rec in (server.get('protocols') or {}).items():
                fo = (rec or {}).get('exit_failover') or {}
                if not fo.get('enabled'):
                    continue
                if not ((rec or {}).get('exit_link') or {}).get('exit_uid'):
                    continue
                targets.append((idx, proto, uid))
        return targets

    async def run_failover_pass(self):
        """Scheduler entry: tick every instance that opted in. Disabled-by-default
        single-exit setups never appear here."""
        data = self.load_data()
        results = []
        for idx, proto, uid in self.list_failover_targets(data):
            try:
                results.append(await self.tick_failover(idx, proto))
            except Exception as err:
                logger.warning("exit failover tick %s/%s failed: %s", uid, proto, err)
                results.append({
                    'action': 'error',
                    'reason': str(err),
                    'entry_uid': uid,
                    'protocol': proto,
                })
        return results
