import asyncio
import copy
import unittest

from exit_link_service import ExitLinkError, ExitLinkService, peer_id_for
from app import backfill_server_uids, find_server_by_uid, protocol_base

AWG_PROTOCOLS = ('awg', 'awg2', 'awg3', 'awg_legacy')


def base_data():
    data = {
        'servers': [
            {'name': 'Paris', 'host': '198.51.100.1', 'uid': 'entry-uid', 'protocols': {
                'awg2': {'installed': True, 'port': '55424'},
                'awg_legacy': {'installed': True, 'port': '55426'},
            }},
            {'name': 'Berlin-1', 'host': '203.0.113.5', 'uid': 'exit-a', 'protocols': {
                'exit': {'installed': True, 'port': '55520', 'subnet': '10.9.0.0/24', 'obfuscation': False},
            }},
            {'name': 'Oslo-obf', 'host': '203.0.113.9', 'uid': 'exit-b', 'protocols': {
                'exit': {'installed': True, 'port': '55520', 'subnet': '10.9.0.0/24', 'obfuscation': True},
            }},
        ],
        'users': [],
        'user_connections': [],
    }
    backfill_server_uids(data['servers'])
    return data


class FakeAWG:
    def __init__(self, host, events=None):
        self.host = host
        self.calls = []
        self.events = events if events is not None else []
        self.mtu = '1376'
        self.ipv6 = ''
        self.link_error = None
        self.status_sequence = None       # list of exit_link_status answers
        self.fail_unlink = False
        self.egress = {'via_exit': '203.0.113.5', 'direct': '198.51.100.1'}
        self.egress_error = None
        self.endpoint = '203.0.113.5:55520'
        self.link_info = None          # what exit0.conf inside the container says
        self.link_info_error = None
        self.dns_error = None

    def exit_prepare_keys(self, protocol):
        self.calls.append(('exit_prepare_keys', protocol))
        return f'PUB-{self.host}-{protocol}'

    def _get_mtu(self, protocol):
        return self.mtu

    def _get_subnet_ipv6_ip(self, protocol):
        return self.ipv6

    def exit_link(self, protocol, link):
        self.calls.append(('exit_link', protocol, link))
        self.events.append((self.host, 'exit_link'))
        if self.link_error:
            raise RuntimeError(self.link_error)
        return 'exit link up: 10.9.0.7/24 -> table 200'

    def exit_link_status(self, protocol, now=None):
        self.calls.append(('exit_link_status', protocol))
        if self.status_sequence:
            return self.status_sequence.pop(0)
        return {'up': True, 'handshake_age': 3, 'rx_bytes': 1, 'tx_bytes': 2, 'endpoint': self.endpoint}

    def exit_link_info(self, protocol):
        self.calls.append(('exit_link_info', protocol))
        if self.link_info_error:
            raise RuntimeError(self.link_info_error)
        return self.link_info

    def exit_check_egress(self, protocol):
        self.calls.append(('exit_check_egress', protocol))
        if self.egress_error:
            raise RuntimeError(self.egress_error)
        return dict(self.egress)

    def exit_set_dns_via_exit(self, protocol, enabled):
        self.calls.append(('exit_set_dns_via_exit', protocol, enabled))
        if self.dns_error:
            raise RuntimeError(self.dns_error)
        return 'exit link up: 10.9.0.7/24 -> table 200'

    def exit_unlink(self, protocol):
        self.calls.append(('exit_unlink', protocol))
        if self.fail_unlink:
            raise RuntimeError('entry unreachable')
        return ''


class FakeExit:
    def __init__(self, host, events=None):
        self.host = host
        self.calls = []
        self.events = events if events is not None else []
        self.add_error = None
        self.remove_error = None
        self.next_ip = '10.9.0.7'

    def add_peer(self, peer_id, name, public_key):
        self.calls.append(('add_peer', peer_id, name, public_key))
        self.events.append((self.host, 'add_peer'))
        if self.add_error:
            raise RuntimeError(self.add_error)
        return {'transit_ip': self.next_ip, 'psk': 'PSK', 'public_key': f'EXITPUB-{self.host}', 'port': '55520',
                'subnet': '10.9.0.0/24', 'obfuscation': self.host == '203.0.113.9', 'awg_params': {}}

    def remove_peer(self, public_key=None, peer_id=None):
        self.calls.append(('remove_peer', public_key, peer_id))
        self.events.append((self.host, 'remove_peer'))
        if self.remove_error:
            raise RuntimeError(self.remove_error)
        return True


class Harness:
    """In-memory data.json plus one fake manager per host, injected the way app.py wires the real ones."""

    def __init__(self, data=None):
        self.data = data or base_data()
        self.awgs = {}
        self.exits = {}
        self.unreachable = set()
        self.sleeps = []
        self.events = []

        async def sleep(seconds):
            self.sleeps.append(seconds)

        def get_ssh(server):
            if server['host'] in self.unreachable:
                raise ConnectionError(f"SSH to {server['host']} failed")
            return server['host']

        self.service = ExitLinkService(
            load_data=lambda: copy.deepcopy(self.data),
            save_data=self._save,
            data_lock=asyncio.Lock(),
            get_ssh=get_ssh,
            awg_manager_factory=lambda host: self.awgs.setdefault(host, FakeAWG(host, self.events)),
            exit_manager_factory=lambda host: self.exits.setdefault(host, FakeExit(host, self.events)),
            protocol_base=protocol_base,
            awg_protocols=AWG_PROTOCOLS,
            protocol_display_name=lambda p: {'awg2': 'AmneziaWG 2.0'}.get(p, p),
            find_server_by_uid=find_server_by_uid,
            sleep=sleep,
        )

    def _save(self, data):
        self.data = copy.deepcopy(data)

    def awg(self, host='198.51.100.1'):
        return self.awgs.setdefault(host, FakeAWG(host, self.events))

    def exit(self, host='203.0.113.5'):
        return self.exits.setdefault(host, FakeExit(host, self.events))

    def record(self, server_idx=0, protocol='awg2'):
        return self.data['servers'][server_idx]['protocols'][protocol]


def run(coro):
    return asyncio.run(coro)


class LinkTests(unittest.TestCase):
    def test_happy_path_persists_the_link(self):
        h = Harness()
        result = run(h.service.link(0, 'awg2', 'exit-a'))

        self.assertEqual(result['status'], 'success')
        self.assertEqual([c[0] for c in h.awg().calls], ['exit_prepare_keys', 'exit_link', 'exit_link_status'])
        self.assertEqual(h.exit().calls, [('add_peer', 'entry-uid:awg2', 'Paris / AmneziaWG 2.0', 'PUB-198.51.100.1-awg2')])
        link = h.awg().calls[1][2]
        self.assertEqual(link['transit_ip'], '10.9.0.7')
        self.assertEqual(link['subnet_cidr'], '24')
        self.assertEqual(link['endpoint_host'], '203.0.113.5')
        self.assertEqual(link['endpoint_port'], '55520')
        self.assertEqual(link['psk'], 'PSK')
        self.assertFalse(link['dns_via_exit'])
        saved = h.record()['exit_link']
        self.assertEqual(saved['exit_uid'], 'exit-a')
        self.assertEqual(saved['exit_name'], 'Berlin-1')
        self.assertEqual(saved['transit_ip'], '10.9.0.7')
        self.assertIsNone(saved['stale'])
        self.assertNotIn('psk', saved)
        self.assertEqual(result['warnings'], [])
        self.assertFalse(result['ipv6_refused'])

    def test_validation_errors(self):
        h = Harness()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'xray', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'protocol_not_awg')
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg3', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'protocol_not_installed')
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'no-such-uid'))
        self.assertEqual(ctx.exception.code, 'exit_not_found')
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(9, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.status_code, 404)
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg_legacy', 'exit-b'))
        self.assertEqual(ctx.exception.code, 'exit_legacy_obfuscation')
        # a server cannot be its own exit
        h.data['servers'][1]['protocols']['awg2'] = {'installed': True}
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(1, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_self')
        self.assertEqual(h.exit().calls, [])

    def test_add_peer_failure_leaves_everything_untouched(self):
        h = Harness()
        h.exit().add_error = 'exit down'
        with self.assertRaises(RuntimeError):
            run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertNotIn('exit_link', h.record())
        self.assertEqual([c[0] for c in h.awg().calls], ['exit_prepare_keys'])

    def test_apply_failure_rolls_back_both_sides(self):
        h = Harness()
        h.awg().link_error = '! FATAL: policy routing for exit0 is not in place'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_apply_failed')
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)
        self.assertEqual(h.exit().calls[-1], ('remove_peer', None, 'entry-uid:awg2'))
        self.assertNotIn('exit_link', h.record())

    def test_no_handshake_rolls_back_unless_forced(self):
        h = Harness()
        never = {'up': False, 'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''}
        h.awg().status_sequence = [never] * 20
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_no_handshake')
        self.assertIn('55520/udp', str(ctx.exception))
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)
        self.assertNotIn('exit_link', h.record())

        h = Harness()
        h.awg().status_sequence = [never] * 20
        result = run(h.service.link(0, 'awg2', 'exit-a', force=True))
        self.assertEqual(result['warnings'], ['no_handshake_yet'])
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-a')

    def test_handshake_wait_polls_until_it_arrives(self):
        h = Harness()
        never = {'up': False, 'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''}
        h.awg().status_sequence = [never, never, {'up': True, 'handshake_age': 1, 'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': 'x'}]
        result = run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(result['status'], 'success')
        self.assertEqual(h.sleeps, [2, 2])

    def test_mtu_gate(self):
        h = Harness()
        h.awg().mtu = '1500'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_mtu_too_big')
        self.assertEqual(h.exit().calls, [])
        result = run(h.service.link(0, 'awg2', 'exit-a', force=True))
        self.assertEqual(result['status'], 'success')

    def test_ipv6_instances_are_flagged(self):
        h = Harness()
        h.awg().ipv6 = 'fd42:8:1::1'
        self.assertTrue(run(h.service.link(0, 'awg2', 'exit-a'))['ipv6_refused'])

    def test_switching_exits_drops_the_old_peer_only_after_the_new_link_is_confirmed(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        h.events.clear()
        result = run(h.service.link(0, 'awg2', 'exit-b'))
        self.assertEqual(result['status'], 'success')
        self.assertEqual(h.events, [('203.0.113.9', 'add_peer'), ('198.51.100.1', 'exit_link'),
                                    ('203.0.113.5', 'remove_peer')])
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-b')

    def test_failed_switch_keeps_the_old_peer_and_marks_the_record_stale(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        h.events.clear()
        h.awg().link_error = 'apply failed'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-b'))
        self.assertEqual(ctx.exception.code, 'exit_apply_failed')
        # rollback touched the new exit and the entry, never the old exit
        self.assertNotIn(('203.0.113.5', 'remove_peer'), h.events)
        self.assertIn(('203.0.113.9', 'remove_peer'), h.events)
        link = h.record()['exit_link']
        self.assertEqual(link['exit_uid'], 'exit-a')
        self.assertEqual(link['stale'], 'switch_failed')
        # Repair goes back to the old exit, whose peer is still there
        h.awg().link_error = None
        self.assertEqual(run(h.service.relink_entry(0, 'awg2'))['exit_link']['exit_uid'], 'exit-a')
        self.assertIsNone(h.record()['exit_link']['stale'])

    def test_failed_relink_to_the_same_exit_marks_the_record_stale(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        h.awg().link_error = 'apply failed'
        with self.assertRaises(ExitLinkError):
            run(h.service.link(0, 'awg2', 'exit-a', force=True))
        self.assertEqual(h.record()['exit_link']['stale'], 'relink_failed')

    def test_switching_exits_tolerates_an_unreachable_old_exit(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        h.unreachable.add('203.0.113.5')
        result = run(h.service.link(0, 'awg2', 'exit-b'))
        self.assertEqual(result['warnings'], ['old_exit_unreachable_orphan_peer'])
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-b')

    def test_persist_resolves_the_entry_by_uid_after_a_reorder(self):
        h = Harness()
        original_save = h._save

        def reorder_then_save(data):
            # someone reordered servers while we were busy with SSH
            data['servers'] = [data['servers'][2], data['servers'][0], data['servers'][1]]
            original_save(data)

        h.service.save_data = reorder_then_save
        run(h.service.link(0, 'awg2', 'exit-a'))
        entry = next(s for s in h.data['servers'] if s['uid'] == 'entry-uid')
        self.assertEqual(entry['protocols']['awg2']['exit_link']['exit_uid'], 'exit-a')


class UnlinkAndLifecycleTests(unittest.TestCase):
    def linked(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        h.awg().calls.clear()
        h.exit().calls.clear()
        return h

    def test_unlink_entry_first_then_exit(self):
        h = self.linked()
        result = run(h.service.unlink(0, 'awg2'))
        self.assertEqual(result, {'status': 'success', 'warnings': [], 'unlinked': True})
        self.assertEqual(h.awg().calls, [('exit_unlink', 'awg2')])
        self.assertEqual(h.exit().calls, [('remove_peer', None, 'entry-uid:awg2')])
        self.assertNotIn('exit_link', h.record())

    def test_unlink_with_a_dead_exit_still_restores_the_entry(self):
        h = self.linked()
        h.unreachable.add('203.0.113.5')
        result = run(h.service.unlink(0, 'awg2'))
        self.assertEqual(result['warnings'], ['exit_unreachable_orphan_peer'])
        self.assertEqual(h.awg().calls, [('exit_unlink', 'awg2')])
        self.assertNotIn('exit_link', h.record())

    def test_unlink_is_idempotent(self):
        h = Harness()
        self.assertEqual(run(h.service.unlink(0, 'awg2')), {'status': 'success', 'warnings': [], 'unlinked': False})

    def test_relink_entry_reuses_the_saved_exit_and_forces(self):
        h = self.linked()
        h.data['servers'][1]['protocols']['dns'] = {'installed': True}
        h.data['servers'][0]['protocols']['awg2']['exit_link']['dns_via_exit'] = True
        never = {'up': False, 'handshake_age': None, 'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''}
        h.awg().status_sequence = [never] * 20
        result = run(h.service.relink_entry(0, 'awg2'))
        self.assertEqual(result['warnings'], ['no_handshake_yet'])
        self.assertTrue(h.awg().calls[1][2]['dns_via_exit'])
        self.assertTrue(h.record()['exit_link']['dns_via_exit'])
        with self.assertRaises(ExitLinkError):
            run(h.service.relink_entry(0, 'awg_legacy'))

    def test_relink_drops_dns_via_exit_when_the_exit_lost_its_dns(self):
        # repairing a link must not fail over an option the caller did not ask
        # for: the saved flag is dropped so DNS comes home instead of nowhere
        h = self.linked()
        h.data['servers'][0]['protocols']['awg2']['exit_link']['dns_via_exit'] = True
        result = run(h.service.relink_entry(0, 'awg2'))
        self.assertIn('exit_dns_disabled_no_dns', result['warnings'])
        self.assertFalse(h.awg().calls[1][2]['dns_via_exit'])
        self.assertFalse(h.record()['exit_link']['dns_via_exit'])

    def test_relink_entries_for_exit_reports_per_entry(self):
        h = Harness()
        h.data['servers'].append({'name': 'Rome', 'host': '198.51.100.2', 'uid': 'entry-2',
                                  'protocols': {'awg': {'installed': True}}})
        run(h.service.link(0, 'awg2', 'exit-a'))
        run(h.service.link(3, 'awg', 'exit-a'))
        h.unreachable.add('198.51.100.2')
        results = run(h.service.relink_entries_for_exit('exit-a'))
        self.assertEqual([(r['name'], r['protocol'], r['status']) for r in results],
                         [('Paris', 'awg2', 'success'), ('Rome', 'awg', 'error')])
        self.assertIn('SSH to 198.51.100.2 failed', results[1]['error'])

    def test_detach_marks_unreachable_entries_stale(self):
        h = Harness()
        h.data['servers'].append({'name': 'Rome', 'host': '198.51.100.2', 'uid': 'entry-2',
                                  'protocols': {'awg': {'installed': True}}})
        run(h.service.link(0, 'awg2', 'exit-a'))
        run(h.service.link(3, 'awg', 'exit-a'))
        h.unreachable.add('198.51.100.2')
        results = run(h.service.detach_entries_for_exit('exit-a', 'exit_uninstalled'))
        self.assertEqual([r['status'] for r in results], ['success', 'error'])
        self.assertNotIn('exit_link', h.record(0, 'awg2'))
        self.assertEqual(h.record(3, 'awg')['exit_link']['stale'], 'exit_uninstalled')
        self.assertEqual(h.service.linked_entries(h.data, 'exit-a')[0]['stale'], 'exit_uninstalled')

    def test_forget_entry_peers(self):
        h = self.linked()
        results = run(h.service.forget_entry_peers(h.data['servers'][0]))
        self.assertEqual(results, [{'protocol': 'awg2', 'exit_uid': 'exit-a', 'status': 'success'}])
        self.assertEqual(h.exit().calls, [('remove_peer', None, 'entry-uid:awg2')])

    def test_status_and_listings(self):
        h = self.linked()
        status = run(h.service.status(0, 'awg2'))
        self.assertEqual(status['exit_link']['exit_uid'], 'exit-a')
        self.assertTrue(status['exit_link_status']['up'])
        self.assertEqual(status['mtu'], 1376)
        self.assertEqual(status['exit_mtu'], 1420)
        nodes = h.service.list_exit_nodes(h.data)
        self.assertEqual([(n['uid'], n['server_id'], n['obfuscation']) for n in nodes],
                         [('exit-a', 1, False), ('exit-b', 2, True)])
        self.assertEqual(h.service.linked_entries(h.data, 'exit-a'),
                         [{'server_id': 0, 'server_uid': 'entry-uid', 'name': 'Paris', 'protocol': 'awg2', 'stale': None}])
        self.assertEqual(h.service.linked_entries(h.data, ''), [])

    def test_check_egress_matches_the_exit_address(self):
        h = self.linked()
        result = run(h.service.check_egress(0, 'awg2'))
        self.assertIn(('exit_check_egress', 'awg2'), h.awg().calls)
        self.assertTrue(result['matches'])
        self.assertFalse(result['leaks'])
        self.assertEqual(result['expected'], '203.0.113.5')
        self.assertEqual(result['exit_name'], 'Berlin-1')

    def test_check_egress_flags_a_leak_and_a_natted_exit(self):
        h = self.linked()
        # clients still leave from the entry node
        h.awg().egress = {'via_exit': '198.51.100.1', 'direct': '198.51.100.1'}
        leaking = run(h.service.check_egress(0, 'awg2'))
        self.assertTrue(leaking['leaks'])
        self.assertFalse(leaking['matches'])
        # a NATed exit answers from another address: neither a match nor a leak
        h.awg().egress = {'via_exit': '203.0.113.77', 'direct': '198.51.100.1'}
        natted = run(h.service.check_egress(0, 'awg2'))
        self.assertFalse(natted['matches'])
        self.assertFalse(natted['leaks'])
        # nothing answered at all
        h.awg().egress = {'via_exit': '', 'direct': ''}
        blind = run(h.service.check_egress(0, 'awg2'))
        self.assertFalse(blind['matches'])
        self.assertFalse(blind['leaks'])

    def test_check_egress_compares_against_the_resolved_endpoint(self):
        # a server added by hostname: the probe answers with an address, so the
        # comparison uses the endpoint WireGuard resolved that hostname to
        h = self.linked()
        h.data['servers'][1]['host'] = 'exit.example.com'
        run(h.service.relink_entry(0, 'awg2'))
        h.awg().status_sequence = None
        h.awg().egress = {'via_exit': '203.0.113.5', 'direct': '198.51.100.1'}
        h.awg().endpoint = '203.0.113.5:55520'
        result = run(h.service.check_egress(0, 'awg2'))
        self.assertEqual(result['expected'], 'exit.example.com')
        self.assertEqual(result['expected_ip'], '203.0.113.5')
        self.assertTrue(result['matches'])

        # no live endpoint and a hostname to compare with: not a match, but the
        # clients are provably not leaving from the entry either
        h.awg().endpoint = ''
        unresolved = run(h.service.check_egress(0, 'awg2'))
        self.assertEqual(unresolved['expected_ip'], '')
        self.assertFalse(unresolved['matches'])
        self.assertFalse(unresolved['leaks'])

    def test_check_egress_requires_a_link_and_maps_failures(self):
        h = Harness()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.check_egress(0, 'awg2'))
        self.assertEqual(ctx.exception.code, 'not_linked')

        h = self.linked()
        h.awg().egress_error = 'No such container: amnezia-awg2'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.check_egress(0, 'awg2'))
        self.assertEqual(ctx.exception.code, 'exit_egress_failed')
    def test_dns_via_exit_needs_amnezia_dns_on_the_exit(self):
        h = self.linked()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.set_dns_via_exit(0, 'awg2', True))
        self.assertEqual(ctx.exception.code, 'exit_dns_needs_dns')
        self.assertIsNone(h.record().get('exit_link', {}).get('dns_via_exit') or None)
        # linking with the flag is refused for the same reason
        h2 = Harness()
        with self.assertRaises(ExitLinkError) as ctx:
            run(h2.service.link(0, 'awg2', 'exit-a', dns_via_exit=True))
        self.assertEqual(ctx.exception.code, 'exit_dns_needs_dns')

    def test_dns_via_exit_toggles_and_persists(self):
        h = self.linked()
        h.data['servers'][1]['protocols']['dns'] = {'installed': True}
        result = run(h.service.set_dns_via_exit(0, 'awg2', True))
        self.assertTrue(result['dns_via_exit'])
        self.assertEqual(h.awg().calls[-1], ('exit_set_dns_via_exit', 'awg2', True))
        self.assertTrue(h.record()['exit_link']['dns_via_exit'])

        run(h.service.set_dns_via_exit(0, 'awg2', False))
        self.assertEqual(h.awg().calls[-1], ('exit_set_dns_via_exit', 'awg2', False))
        self.assertFalse(h.record()['exit_link']['dns_via_exit'])

    def test_dns_via_exit_survives_a_relink_and_is_reported_by_the_apply_error(self):
        h = self.linked()
        h.data['servers'][1]['protocols']['dns'] = {'installed': True}
        run(h.service.set_dns_via_exit(0, 'awg2', True))
        run(h.service.relink_entry(0, 'awg2'))
        self.assertTrue(h.awg().calls[-2][2]['dns_via_exit'] if h.awg().calls[-2][0] == 'exit_link'
                        else h.record()['exit_link']['dns_via_exit'])
        self.assertTrue(h.record()['exit_link']['dns_via_exit'])

        h.awg().dns_error = 'container is gone'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.set_dns_via_exit(0, 'awg2', False))
        self.assertEqual(ctx.exception.code, 'exit_apply_failed')
        # the record still says what the container actually has
        self.assertTrue(h.record()['exit_link']['dns_via_exit'])

    def test_removing_dns_from_the_exit_brings_entry_dns_back(self):
        h = self.linked()
        h.data['servers'][1]['protocols']['dns'] = {'installed': True}
        run(h.service.set_dns_via_exit(0, 'awg2', True))
        del h.data['servers'][1]['protocols']['dns']

        restored = run(h.service.disable_dns_via_exit_for_exit('exit-a'))
        self.assertEqual([(r['protocol'], r['status']) for r in restored], [('awg2', 'success')])
        self.assertFalse(h.record()['exit_link']['dns_via_exit'])
        # nothing to do the second time
        self.assertEqual(run(h.service.disable_dns_via_exit_for_exit('exit-a')), [])

    def test_restore_of_a_linked_entry_re_establishes_the_link(self):
        h = self.linked()
        result = run(h.service.reconcile_after_restore(0, 'awg2'))
        self.assertEqual(result, {'exit_link_restored': 'relinked'})
        self.assertIn('exit_link', [c[0] for c in h.awg().calls])
        self.assertIsNone(h.record()['exit_link']['stale'])

    def test_restore_marks_the_link_stale_when_it_cannot_be_re_established(self):
        h = self.linked()
        h.awg().link_error = 'container is gone'
        result = run(h.service.reconcile_after_restore(0, 'awg2'))
        self.assertEqual(result['exit_link_restored'], 'stale')
        self.assertEqual(h.record()['exit_link']['stale'], 'restore_relink_failed')

    def test_restore_drops_a_link_the_panel_does_not_track(self):
        # the archive predates the unlink: the container comes back linked
        h = Harness()
        h.awg().link_info = {'exit_uid': 'exit-a', 'exit_name': 'Berlin-1', 'obfuscation': False,
                             'dns_via_exit': False, 'address': '10.9.0.7/24', 'endpoint': '203.0.113.5:55520'}
        result = run(h.service.reconcile_after_restore(0, 'awg2'))
        self.assertEqual(result, {'exit_link_restored': 'removed', 'exit_name': 'Berlin-1'})
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)

    def test_restore_of_an_unlinked_entry_without_a_link_file_does_nothing(self):
        h = Harness()
        self.assertEqual(run(h.service.reconcile_after_restore(0, 'awg2')), {})
        self.assertNotIn('exit_unlink', [c[0] for c in h.awg().calls])

    def test_restore_of_an_exit_node_re_registers_its_entries(self):
        h = self.linked()
        result = run(h.service.reconcile_after_restore(1, 'exit'))
        self.assertEqual([(e['protocol'], e['status']) for e in result['exit_entries_relinked']],
                         [('awg2', 'success')])
        # nothing to do when no entry points at this exit
        self.assertEqual(run(h.service.reconcile_after_restore(2, 'exit')), {})

    def test_restore_of_an_unrelated_protocol_is_ignored(self):
        h = self.linked()
        self.assertEqual(run(h.service.reconcile_after_restore(0, 'xray')), {})

    def test_peer_id_format(self):
        self.assertEqual(peer_id_for('abc', 'awg2'), 'abc:awg2')


if __name__ == '__main__':
    unittest.main()
