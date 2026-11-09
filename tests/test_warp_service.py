"""Unit tests for the pure WARP logic (no SSH, no Docker).

Covers the MTU budget, DNS exception slots, the atomic state store, the
rolling registration quota and the instance state machine.
"""
import json
import os
import tempfile
import unittest

import warp_service as ws


class WarpClientMtuTests(unittest.TestCase):
    def test_cap_wins_over_large_raw(self):
        mtu, reason = ws.warp_client_mtu(1376, 60)
        self.assertEqual(mtu, 1220)
        self.assertIsNone(reason)

    def test_uplink_budget_wins_with_big_overhead(self):
        mtu, _ = ws.warp_client_mtu(1376, 280)
        self.assertEqual(mtu, 1220)
        mtu, _ = ws.warp_client_mtu(1376, 300)
        self.assertEqual(mtu, 1200)

    def test_below_floor_is_refused(self):
        mtu, reason = ws.warp_client_mtu(1376, 320)
        self.assertIsNone(mtu)
        self.assertEqual(reason, 'srv_warp_budget_mismatch')

    def test_small_raw_is_kept(self):
        mtu, _ = ws.warp_client_mtu(1210, 60)
        self.assertEqual(mtu, 1210)

    def test_warped_budget_is_respected(self):
        mtu, _ = ws.warp_client_mtu(1376, 60, warped_b=True, b_regen_mtu=1205)
        self.assertEqual(mtu, 1205)

    def test_missing_raw_still_caps(self):
        mtu, _ = ws.warp_client_mtu(None, 60)
        self.assertEqual(mtu, 1220)


class DnsTargetTests(unittest.TestCase):
    def test_public_ipv4_only(self):
        public, other, hosts = ws.parse_dns_targets(
            '1.1.1.1, 8.8.8.8, 172.29.172.254, 2606:4700::1111, dns.example')
        self.assertEqual(public, ['1.1.1.1', '8.8.8.8'])
        self.assertIn('172.29.172.254', other)
        self.assertIn('2606:4700::1111', other)
        self.assertEqual(hosts, ['dns.example'])

    def test_private_ranges_rejected(self):
        for ip in ('10.0.0.1', '192.168.1.1', '100.64.0.1', '127.0.0.1',
                   '169.254.1.1'):
            self.assertFalse(ws.is_public_ipv4(ip), ip)

    def test_rules_without_warp_dns(self):
        rules = ws.dns_rule_targets(
            '1.1.1.1, 8.8.8.8', dns_via_warp=False,
            dns_net_cidr='172.29.172.0/24')
        prefs = [r['pref'] for r in rules]
        self.assertEqual(prefs[0], ws.WARP_PREF_ENTRY_DNS_NET)
        self.assertEqual(prefs[1:], [183, 184])
        self.assertEqual(rules[1]['to'], '1.1.1.1/32')

    def test_no_rules_when_dns_via_warp(self):
        self.assertEqual(
            ws.dns_rule_targets('1.1.1.1', dns_via_warp=True), [])

    def test_too_many_public_resolvers(self):
        many = ', '.join('1.1.1.%d' % i for i in range(1, 9))
        with self.assertRaises(ws.SrvWarpError) as ctx:
            ws.dns_rule_targets(many, dns_via_warp=False)
        self.assertEqual(ctx.exception.code, 'srv_warp_dns_too_many')
        self.assertEqual(ctx.exception.http_status, 409)


class WarpStateStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='warp-state-')
        self.path = os.path.join(self.dir, 'data.json.srv_warp_state.json')

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_roundtrip_and_version(self):
        store = ws.WarpStateStore(self.path)
        store.mutate(lambda state: ws.proto_record(state, 'uid-1', 'awg3'))
        raw = json.load(open(self.path, encoding='utf-8'))
        self.assertEqual(raw['version'], ws.STATE_VERSION)
        self.assertIn('uid-1', raw['servers'])
        self.assertIn('awg3', raw['servers']['uid-1']['protocols'])

    def test_corrupt_file_is_empty_state(self):
        with open(self.path, 'w', encoding='utf-8') as fh:
            fh.write('{not json')
        self.assertEqual(ws.WarpStateStore(self.path).load()['servers'], {})

    def test_no_temp_files_left(self):
        store = ws.WarpStateStore(self.path)
        store.mutate(lambda state: ws.server_record(state, 'uid'))
        leftovers = [n for n in os.listdir(self.dir) if n.endswith('.tmp')]
        self.assertEqual(leftovers, [])

    def test_ctx_uses_authoritative_budget(self):
        store = ws.WarpStateStore(self.path)

        def build(state):
            rec = ws.proto_record(state, 'uid-1', 'awg')
            rec['warp_link'] = {'active': True, 'dns_via_warp': False,
                                'server_uid': 'uid-1', 'entry_uid': 'uid-1',
                                'protocol': 'awg'}
            rec['client_mtu_warp'] = 1220
            rec['warp_egress_regen'] = {
                'uid-1:awg': {'mtu': 1205, 'done': False, 'ts': 0,
                              'subnet_cidr': '10.9.0.0/24',
                              'transit_gateway': '10.9.0.1'},
            }

        state = store.load()
        build(state)
        ctx = ws.warp_ctx_for(state, 'uid-1', 'awg')
        self.assertTrue(ctx['active'])
        self.assertEqual(ctx['client_mtu'], 1205)
        self.assertEqual(ctx['transit_cidr'], '10.9.0.0/24')
        self.assertEqual(ctx['prefix'], '/opt/amnezia/awg/warp/awg')


class QuotaTests(unittest.TestCase):
    NOW = 1_700_000_000

    def test_window_filters_old_entries(self):
        stamps = [{'ts': self.NOW - 10}, {'ts': self.NOW - 8 * 24 * 3600}]
        self.assertEqual(ws.register_timestamps(stamps, now=self.NOW),
                         [self.NOW - 10])

    def test_quota_exhausted_after_limit(self):
        stamps = [{'ts': self.NOW - i} for i in range(1, 4)]
        self.assertTrue(ws.quota_exhausted(stamps, now=self.NOW))
        self.assertFalse(ws.quota_exhausted(stamps[:2], now=self.NOW))

    def test_prune_keeps_last_entries(self):
        stamps = list(range(30))
        self.assertEqual(ws.registers_prune(stamps), list(range(10, 30)))


class ClassifyStateTests(unittest.TestCase):
    def _classify(self, **kwargs):
        base = dict(installed=True, link_active=True, ssh_ok=True,
                    container_running=True, handshake_age=10, probe_ok=True,
                    probe_private=False, probe_direct=False,
                    rate_limited=False)
        base.update(kwargs)
        return ws.classify_instance_state(**base)

    def test_connected(self):
        self.assertEqual(self._classify(), ws.ST_CONNECTED)

    def test_unreachable_beats_everything(self):
        self.assertEqual(self._classify(ssh_ok=False), ws.ST_UNREACHABLE)

    def test_stopped(self):
        self.assertEqual(self._classify(container_running=False),
                         ws.ST_STOPPED)

    def test_direct_egress_is_error(self):
        self.assertEqual(self._classify(probe_direct=True), ws.ST_ERROR)

    def test_private_egress_is_error(self):
        self.assertEqual(self._classify(probe_private=True), ws.ST_ERROR)

    def test_stale_handshake_is_disconnected(self):
        self.assertEqual(self._classify(handshake_age=300),
                         ws.ST_DISCONNECTED)

    def test_probe_failure_is_connecting(self):
        self.assertEqual(self._classify(probe_ok=False), ws.ST_CONNECTING)

    def test_not_linked_and_rate_limited(self):
        self.assertEqual(self._classify(link_active=False),
                         ws.ST_AVAILABLE_NOT_LINKED)
        self.assertEqual(
            self._classify(link_active=False, rate_limited=True),
            ws.ST_RATE_LIMITED)

    def test_aggregate(self):
        self.assertEqual(
            ws.aggregate_state([ws.ST_CONNECTED, ws.ST_CONNECTED]),
            ws.AGG_INSTALLED)
        self.assertEqual(
            ws.aggregate_state([ws.ST_CONNECTED, ws.ST_DISCONNECTED]),
            ws.AGG_DEGRADED)
        self.assertEqual(ws.aggregate_state([]), ws.AGG_NOT_INSTALLED)
        self.assertEqual(
            ws.aggregate_state([ws.ST_CONNECTED], remote_unreachable=True),
            ws.AGG_UNREACHABLE)


if __name__ == '__main__':
    unittest.main()
