"""Smart Route service: orchestration between the panel data, the host-side
manager and the per-container exit-link plumbing. Fakes mirror the contracts
of AWGManager (_container_name/_resolve_config_path/_exit_apply) and of
SmartRouteManager; the service builds the latter itself, so the tests patch
smartroute_service.SmartRouteManager."""

import asyncio
import unittest
from unittest import mock

import smartroute_service
from managers.awg_manager import AWG_DEFAULTS
from smartroute_service import SmartRouteError, SmartRouteService, split_instances

SUBNET_DEFAULT = f"{AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}"


def make_data(installed=True):
    return {'servers': [{
        'uid': 'srv-entry',
        'name': 'MAMKAM',
        'smartroute': {
            'installed': installed,
            'own_subnets': [],
            'dns_via_exit': False,
        },
        'protocols': {
            'awg': {'exit_link': {'exit_uid': 'EXITUID', 'smart_route': False}},
            'awg2': {'exit_link': {'exit_uid': 'EXITUID', 'smart_route': True,
                                  'dns_via_exit': False}},
            'awg3': {'exit_link': {}},
            'wg': {'exit_link': {'exit_uid': 'EXITUID'}},
        },
    }]}


class FakeAWG:
    def __init__(self):
        self.exit_applies = []
        self.dns_lines = {}   # protocol -> current DNS line (None = unset)
        self.dns_writes = []  # (protocol, dns) log

    def _container_name(self, protocol):
        return f'amnezia-{protocol}'

    def _resolve_config_path(self, protocol):
        return f'/opt/amnezia/awg/{protocol}/wg0.conf'

    def _exit_apply(self, protocol, teardown=False):
        self.exit_applies.append(protocol)

    def _read_config_key(self, protocol_type, key):
        assert key == 'DNS', key
        return self.dns_lines.get(protocol_type)

    def update_awg_settings(self, protocol_type, mtu=None, dns=None,
                            special_junk=None, dns6=None):
        self.dns_writes.append((protocol_type, dns))
        self.dns_lines[protocol_type] = dns or None
        return {'mtu': mtu, 'dns': self.dns_lines.get(protocol_type)}


class FakeSRM:
    """Records the manager calls; canned answers like a healthy server."""
    last = None

    # Class-level: the service builds a fresh manager per call, so the call
    # log must survive across instances within one test.
    calls = []
    last = None

    def __init__(self, ssh):
        FakeSRM.last = self

    def install(self):
        FakeSRM.calls.append(('install',))
        return 'installed'

    def uninstall(self):
        FakeSRM.calls.append(('uninstall',))
        return 'removed'

    def run_update(self):
        FakeSRM.calls.append(('run_update',))
        return 'updated 8000 prefixes'

    def host_status(self):
        return {'installed': True, 'prefixes_v4': 8000, 'prefixes_v6': 300,
                'source_v4': 'ipdeny', 'updated_at': '2026-10-14T10:00:00',
                'next_update': 'in 1h', 'error': None, 'instances': ['amnezia-awg2']}

    def set_own_subnets(self, cidrs):
        FakeSRM.calls.append(('set_own_subnets', tuple(cidrs)))

    def enable_instance(self, container, config_path, subnet_default):
        FakeSRM.calls.append(('enable_instance', container, config_path, subnet_default))
        return 'enabled'

    def disable_instance(self, container, config_path, subnet_default):
        FakeSRM.calls.append(('disable_instance', container, config_path, subnet_default))
        return 'disabled'

    def refresh_instance(self, container):
        FakeSRM.calls.append(('refresh_instance', container))

    def instance_counters(self, container, config_path, subnet_default):
        return {'via_exit': {'pkts': 13, 'bytes': 1300},
                'direct': {'pkts': 7, 'bytes': 700},
                'via_exit_out': {'pkts': 10, 'bytes': 1000},
                'direct_out': {'pkts': 5, 'bytes': 500},
                'via_exit_in': {'pkts': 3, 'bytes': 300},
                'direct_in': {'pkts': 2, 'bytes': 200},
                'throw_routes': 37}


class SmartRouteServiceTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeSRM.calls = []
        FakeSRM.last = None
        self.store = {'data': make_data()}
        self.awg = FakeAWG()
        self.dns_calls = []

        async def apply_dns(server_id, protocol, enabled):
            self.dns_calls.append((server_id, protocol, enabled))

        def load():
            return self.store['data']

        def save(data):
            self.store['data'] = data

        self.svc = SmartRouteService(
            load_data=load,
            save_data=save,
            data_lock=asyncio.Lock(),
            get_ssh=lambda server: object(),
            awg_manager_factory=lambda ssh: self.awg,
            protocol_base=lambda p: 'awg' if p.startswith('awg') else p,
            awg_protocols={'awg'},
            apply_dns_via_exit=apply_dns,
        )
        patcher = mock.patch.object(smartroute_service, 'SmartRouteManager', FakeSRM)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ----- split_instances (pure) -----

    def test_split_instances_lists_only_flagged(self):
        pairs = split_instances(self.store['data'], 0)
        self.assertEqual([p for p, _ in pairs], ['awg2'])

    def test_split_instances_bad_server_id(self):
        self.assertEqual(split_instances(self.store['data'], 7), [])
        self.assertEqual(split_instances(self.store['data'], '0'), [])

    # ----- install / uninstall -----

    async def test_install_marks_installed(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        out = await self.svc.install(0)
        self.assertEqual(out['status'], 'success')
        self.assertTrue(self.store['data']['servers'][0]['smartroute']['installed'])
        self.assertIn(('install',), FakeSRM.calls)

    async def test_install_bad_server(self):
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.install(9)
        self.assertEqual(ctx.exception.code, 'server_not_found')

    # ----- identity: a long SSH call must not persist to a reordered server -----

    async def test_install_persists_by_uid_after_reorder(self):
        original = make_data()
        original['servers'][0]['smartroute']['installed'] = False
        reordered = {'servers': [
            {'uid': 'other', 'name': 'OTHER', 'protocols': {}},
            original['servers'][0],
        ]}
        calls = {'n': 0}

        def load_seq():
            calls['n'] += 1
            return original if calls['n'] == 1 else reordered

        self.svc.load_data = load_seq
        saved = {}
        self.svc.save_data = lambda data: saved.__setitem__('data', data)
        out = await self.svc.install(0)
        self.assertEqual(out['status'], 'success')
        # Persisted to the uid, not to whatever now sits at index 0.
        self.assertTrue(saved['data']['servers'][1]['smartroute']['installed'])
        self.assertNotIn('smartroute', saved['data']['servers'][0])

    async def test_install_aborts_when_server_removed_during_ssh(self):
        original = make_data()
        original['servers'][0]['smartroute']['installed'] = False
        replaced = {'servers': [{'uid': 'other', 'name': 'OTHER', 'protocols': {}}]}
        calls = {'n': 0}

        def load_seq():
            calls['n'] += 1
            return original if calls['n'] == 1 else replaced

        self.svc.load_data = load_seq
        saved = {}
        self.svc.save_data = lambda data: saved.__setitem__('data', data)
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.install(0)
        self.assertEqual(ctx.exception.code, 'server_changed')
        self.assertNotIn('data', saved)
        self.assertNotIn('smartroute', replaced['servers'][0])

    async def test_install_aborts_when_endpoint_changes(self):
        original = make_data()
        original['servers'][0].update(host='192.0.2.1', ssh_port=22, username='root')
        original['servers'][0]['smartroute']['installed'] = False
        changed = {'servers': [dict(original['servers'][0], host='192.0.2.2')]}
        calls = {'n': 0}

        def load_seq():
            calls['n'] += 1
            return original if calls['n'] == 1 else changed

        self.svc.load_data = load_seq
        saved = {}
        self.svc.save_data = lambda data: saved.__setitem__('data', data)
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.install(0)
        self.assertEqual(ctx.exception.code, 'server_changed')
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertNotIn('data', saved)

    async def test_uninstall_rolls_back_instances_before_host_cleanup(self):
        out = await self.svc.uninstall(0)
        calls = FakeSRM.calls
        # container rollback happens before the host uninstall
        self.assertLess(calls.index(('disable_instance', 'amnezia-awg2',
                                     '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT)),
                        calls.index(('uninstall',)))
        # link state: flag off, lost-badge on, app not installed
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertFalse(link['smart_route'])
        self.assertTrue(link['smart_route_lost'])
        self.assertFalse(self.store['data']['servers'][0]['smartroute']['installed'])
        # exit-link plumbing re-synced so traffic stays on exit0
        self.assertEqual(self.awg.exit_applies, ['awg2'])
        self.assertEqual(out['rolled_back'], ['awg2'])

    async def test_uninstall_aborts_when_container_rollback_fails(self):
        # Review hardening: proceeding after a failed rollback would delete
        # the markers/timer and strand throw routes nobody manages. Fail-stop
        # leaves the app fully intact so the uninstall can be retried.
        original = FakeSRM.disable_instance

        def flaky(self, container, config_path, subnet_default):
            if container == 'amnezia-awg2':
                raise RuntimeError('docker exec failed')
            return original(self, container, config_path, subnet_default)

        with mock.patch.object(FakeSRM, 'disable_instance', flaky):
            with self.assertRaises(SmartRouteError) as ctx:
                await self.svc.uninstall(0)
        self.assertEqual(ctx.exception.code, 'rollback_incomplete')
        self.assertEqual(ctx.exception.status_code, 409)
        # no host cleanup ran, nothing recorded as removed
        self.assertNotIn(('uninstall',), FakeSRM.calls)
        self.assertTrue(self.store['data']['servers'][0]['smartroute']['installed'])
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertFalse(link.get('smart_route_lost', False))

    async def test_uninstall_without_splits(self):
        self.store['data']['servers'][0]['protocols']['awg2']['exit_link']['smart_route'] = False
        out = await self.svc.uninstall(0)
        self.assertEqual(out['rolled_back'], [])
        self.assertEqual(self.awg.exit_applies, [])

    # ----- status / lists -----

    async def test_status_merges_host_and_data(self):
        out = await self.svc.status(0)
        self.assertTrue(out['installed'])
        self.assertEqual(out['host']['prefixes_v4'], 8000)
        self.assertEqual(out['split_instances'], ['awg2'])
        self.assertFalse(out['dns_via_exit'])

    async def test_status_not_installed_when_flag_off(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        out = await self.svc.status(0)
        self.assertFalse(out['installed'])
        self.assertFalse(self.svc.is_enabled_in_data(self.store['data'], 0))
        self.assertFalse(self.svc.is_enabled_in_data(self.store['data'], 42))

    async def test_set_own_subnets_validates(self):
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_own_subnets(0, ['not-a-cidr'])
        self.assertEqual(ctx.exception.code, 'invalid_cidr')

    async def test_set_own_subnets_stores_and_refreshes_splits(self):
        out = await self.svc.set_own_subnets(0, ['192.168.0.0/16', '10.0.0.0/8'])
        self.assertEqual(out['own_subnets'], ['10.0.0.0/8', '192.168.0.0/16'])
        sm = self.store['data']['servers'][0]['smartroute']
        self.assertEqual(sm['own_subnets'], ['10.0.0.0/8', '192.168.0.0/16'])
        self.assertIn(('set_own_subnets', ('10.0.0.0/8', '192.168.0.0/16')),
                      FakeSRM.calls)
        self.assertIn(('refresh_instance', 'amnezia-awg2'), FakeSRM.calls)

    # ----- per-instance split toggle -----

    async def test_set_split_requires_app(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_split(0, 'awg', True)
        self.assertEqual(ctx.exception.code, 'app_not_installed')
        self.assertEqual(ctx.exception.status_code, 409)

    async def test_set_split_requires_exit_link(self):
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_split(0, 'awg3', True)
        self.assertEqual(ctx.exception.code, 'not_linked')

    async def test_set_split_rejects_non_awg(self):
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_split(0, 'wg', True)
        self.assertEqual(ctx.exception.code, 'protocol_not_awg')

    async def test_set_split_enable_applies_and_applies_server_dns_choice(self):
        self.store['data']['servers'][0]['smartroute']['dns_via_exit'] = True
        out = await self.svc.set_split(0, 'awg', True)
        self.assertTrue(out['smart_route'])
        self.assertIn(('enable_instance', 'amnezia-awg',
                       '/opt/amnezia/awg/awg/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)
        link = self.store['data']['servers'][0]['protocols']['awg']['exit_link']
        self.assertTrue(link['smart_route'])
        self.assertFalse(link.get('smart_route_lost'))
        # server-level DNS choice (dns_via_exit=True) pushed to the new split
        self.assertIn((0, 'awg', True), self.dns_calls)

    async def test_set_split_disable(self):
        out = await self.svc.set_split(0, 'awg2', False)
        self.assertFalse(out['smart_route'])
        self.assertIn(('disable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertFalse(link['smart_route'])

    async def test_set_split_idempotent(self):
        out = await self.svc.set_split(0, 'awg2', True)
        self.assertTrue(out.get('unchanged'))
        self.assertNotIn(('enable_instance', 'amnezia-awg2',
                          '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                         FakeSRM.calls)

    async def test_set_split_reenable_clears_lost_badge(self):
        self.store['data']['servers'][0]['protocols']['awg2']['exit_link']['smart_route_lost'] = True
        out = await self.svc.set_split(0, 'awg2', True)
        self.assertFalse(out.get('unchanged'))
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertFalse(link['smart_route_lost'])
        self.assertIn(('enable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)

    # ----- DNS choice -----

    async def test_set_dns_via_exit_applies_to_all_splits(self):
        out = await self.svc.set_dns_via_exit(0, True)
        self.assertTrue(out['dns_via_exit'])
        self.assertTrue(self.store['data']['servers'][0]['smartroute']['dns_via_exit'])
        self.assertEqual(self.dns_calls, [(0, 'awg2', True)])
        self.assertEqual(out['results'], [{'protocol': 'awg2', 'status': 'success'}])

    async def test_set_dns_via_exit_keeps_per_instance_errors(self):
        async def flaky_dns(server_id, protocol, enabled):
            raise RuntimeError('exit has no AmneziaDNS')

        self.svc.apply_dns_via_exit = flaky_dns
        out = await self.svc.set_dns_via_exit(0, True)
        self.assertEqual(out['status'], 'success')
        self.assertEqual(out['results'][0]['status'], 'error')

    # ----- counters -----

    async def test_counters_disabled_without_split(self):
        out = await self.svc.counters(0, 'awg')
        self.assertEqual(out, {'enabled': False})
        self.assertEqual(FakeSRM.calls, [])

    async def test_counters_reads_acct_chain(self):
        out = await self.svc.counters(0, 'awg2')
        self.assertTrue(out['enabled'])
        self.assertEqual(out['direct'], {'pkts': 7, 'bytes': 700})
        self.assertEqual(out['via_exit_in'], {'pkts': 3, 'bytes': 300})
        self.assertEqual(out['throw_routes'], 37)

    # ----- global pause/resume (card toggle) -----

    async def test_set_enabled_requires_installed(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_enabled(0, False)
        self.assertEqual(ctx.exception.code, 'app_not_installed')
        self.assertEqual(ctx.exception.status_code, 409)

    async def test_set_enabled_idempotent(self):
        out = await self.svc.set_enabled(0, True)
        self.assertTrue(out.get('unchanged'))
        self.assertNotIn(('disable_instance', 'amnezia-awg2',
                          '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                         FakeSRM.calls)

    async def test_set_enabled_pause_rolls_instances_back(self):
        out = await self.svc.set_enabled(0, False)
        self.assertFalse(out['enabled'])
        self.assertEqual(out['applied'], ['awg2'])
        self.assertIn(('disable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)
        # preference is kept so a resume restores it
        self.assertTrue(self.store['data']['servers'][0]['protocols']['awg2']['exit_link']['smart_route'])
        self.assertFalse(self.store['data']['servers'][0]['smartroute']['enabled'])

    async def test_set_enabled_resume_reapplies(self):
        self.store['data']['servers'][0]['smartroute']['enabled'] = False
        out = await self.svc.set_enabled(0, True)
        self.assertTrue(out['enabled'])
        self.assertIn(('enable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)

    async def test_set_enabled_partial_failure_aborts_without_recording(self):
        # Review hardening: a partial pause/resume must NOT be recorded as the
        # new global state - the panel would report a state at least one
        # container does not have. Fail-stop keeps the old flag (retryable).
        def flaky(self_, container, config_path, subnet_default):
            raise RuntimeError('docker exec failed')
        with mock.patch.object(FakeSRM, 'disable_instance', flaky):
            with self.assertRaises(SmartRouteError) as ctx:
                await self.svc.set_enabled(0, False)
        self.assertEqual(ctx.exception.code, 'partial_failure')
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn('awg2', str(ctx.exception))
        # the stored flag is untouched (absent means default-enabled), so
        # retrying the pause is safe
        self.assertTrue(self.store['data']['servers'][0]['smartroute'].get('enabled', True))

    async def test_status_reports_enabled_and_dns_pair(self):
        out = await self.svc.status(0)
        self.assertTrue(out['enabled'])
        self.assertEqual(out['direct_dns'], '77.88.8.8')
        self.assertEqual(out['exit_dns'], '1.1.1.1')

    async def test_set_split_blocked_while_paused(self):
        self.store['data']['servers'][0]['smartroute']['enabled'] = False
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_split(0, 'awg', True)
        self.assertEqual(ctx.exception.code, 'smartroute_paused')
        self.assertEqual(ctx.exception.status_code, 409)

    # ----- resolver pair (client-config DNS) -----

    async def test_set_split_enable_writes_dns_pair_and_remembers_prev(self):
        self.awg.dns_lines['awg'] = '172.29.172.254, 1.0.0.1'
        await self.svc.set_split(0, 'awg', True)
        self.assertIn(('awg', '77.88.8.8, 1.1.1.1'), self.awg.dns_writes)
        link = self.store['data']['servers'][0]['protocols']['awg']['exit_link']
        self.assertEqual(link['smart_route_prev_dns'], '172.29.172.254, 1.0.0.1')

    async def test_set_split_disable_restores_prev_dns(self):
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        link['smart_route'] = False
        self.awg.dns_lines['awg2'] = '172.29.172.254, 1.0.0.1'
        await self.svc.set_split(0, 'awg2', True)   # remembers prev + writes pair
        await self.svc.set_split(0, 'awg2', False)  # restores
        self.assertIn(('awg2', '172.29.172.254, 1.0.0.1'), self.awg.dns_writes)
        self.assertNotIn('smart_route_prev_dns', link)

    async def test_pause_and_resume_keep_dns_pair(self):
        self.awg.dns_writes.clear()
        await self.svc.set_enabled(0, False)
        await self.svc.set_enabled(0, True)
        # resume re-applies the resolver pair; pause does not restore DNS
        self.assertIn(('awg2', '77.88.8.8, 1.1.1.1'), self.awg.dns_writes)
        self.assertEqual(self.awg.dns_writes, [('awg2', '77.88.8.8, 1.1.1.1')])
        self.assertTrue(self.store['data']['servers'][0]['protocols']['awg2']['exit_link']['smart_route'])

    async def test_uninstall_restores_prev_dns(self):
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        link['smart_route'] = False
        self.awg.dns_lines['awg2'] = '172.29.172.254, 1.0.0.1'
        await self.svc.set_split(0, 'awg2', True)
        await self.svc.uninstall(0)
        self.assertIn(('awg2', '172.29.172.254, 1.0.0.1'), self.awg.dns_writes)

    async def test_set_dns_servers_validates(self):
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_dns_servers(0, 'dns.yandex', '1.1.1.1')
        self.assertEqual(ctx.exception.code, 'invalid_dns')
        with self.assertRaises(SmartRouteError):
            await self.svc.set_dns_servers(0, '77.88.8.8', '::1')

    async def test_set_dns_servers_stores_and_applies_to_splits(self):
        out = await self.svc.set_dns_servers(0, '77.88.8.1', '9.9.9.9')
        self.assertEqual(out['direct_dns'], '77.88.8.1')
        sm = self.store['data']['servers'][0]['smartroute']
        self.assertEqual((sm['direct_dns'], sm['exit_dns']), ('77.88.8.1', '9.9.9.9'))
        self.assertIn(('awg2', '77.88.8.1, 9.9.9.9'), self.awg.dns_writes)

    async def test_set_dns_servers_requires_installed(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.set_dns_servers(0, '77.88.8.8', '1.1.1.1')
        self.assertEqual(ctx.exception.code, 'app_not_installed')


if __name__ == '__main__':
    unittest.main()
