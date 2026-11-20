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
    # What a container reports for its throw routes. Set to 0 to simulate a
    # recreated container; enable_instance() puts it back to repaired_to.
    throw_routes = 37
    repaired_to = 37
    fail_enable = False

    def __init__(self, ssh):
        FakeSRM.last = self

    def install(self, phase='all', on_line=None):
        FakeSRM.calls.append(('install', phase))
        if on_line is not None:
            on_line(f'smartroute: {phase}: done')
        return f'{phase} done'

    def uninstall(self):
        FakeSRM.calls.append(('uninstall',))
        return 'removed'

    def run_update(self):
        FakeSRM.calls.append(('run_update',))
        return 'updated 8000 prefixes'

    prefixes_v4 = 8000
    list_error = None
    migrate_state = 'unchanged'
    migrate_fail = False

    fail_status = False

    def host_status(self):
        if FakeSRM.fail_status:
            raise SmartRouteError('ssh_failed', 'ssh failed')
        return {'installed': True, 'prefixes_v4': FakeSRM.prefixes_v4,
                'prefixes_v6': 300,
                'source_v4': 'ipdeny', 'updated_at': '2026-10-14T10:00:00',
                'next_update': 'in 1h', 'error': FakeSRM.list_error,
                'status': {'prefixes_v4': FakeSRM.prefixes_v4,
                           'error': FakeSRM.list_error},
                'instances': ['amnezia-awg2']}

    def is_installed(self):
        return True

    def migrate_timer(self):
        FakeSRM.calls.append(('migrate_timer',))
        if FakeSRM.migrate_fail:
            raise SmartRouteError('ssh_failed', 'ssh failed')
        detail = '' if FakeSRM.migrate_state == 'unchanged' else 'backup=/x'
        return {'state': FakeSRM.migrate_state, 'detail': detail, 'log': 'x'}

    def set_own_subnets(self, cidrs):
        FakeSRM.calls.append(('set_own_subnets', tuple(cidrs)))

    def enable_instance(self, container, config_path, subnet_default):
        FakeSRM.calls.append(('enable_instance', container, config_path, subnet_default))
        if FakeSRM.fail_enable:
            raise SmartRouteError('ssh_failed', 'ssh failed')
        FakeSRM.throw_routes = FakeSRM.repaired_to
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
                'throw_routes': FakeSRM.throw_routes}


class SmartRouteServiceTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeSRM.calls = []
        FakeSRM.last = None
        FakeSRM.throw_routes = 37
        FakeSRM.repaired_to = 37
        FakeSRM.fail_enable = False
        FakeSRM.prefixes_v4 = 8000
        FakeSRM.list_error = None
        FakeSRM.migrate_state = 'unchanged'
        FakeSRM.migrate_fail = False
        FakeSRM.fail_status = False
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
        self.assertEqual(FakeSRM.calls,
                         [('install', phase)
                          for phase in SmartRouteService.INSTALL_PHASES])

    async def test_install_reports_every_phase_line(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        seen = []
        out = await self.svc.install(
            0, progress=lambda stage, line: seen.append((stage, line)))
        self.assertEqual(out['status'], 'success')
        self.assertEqual([stage for stage, _ in seen],
                         list(SmartRouteService.INSTALL_PHASES))
        self.assertIn(('download', 'smartroute: download: done'), seen)
        self.assertTrue(out['log'])

    async def test_install_failure_keeps_the_app_uninstalled(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        seen = []
        original = FakeSRM.install

        def flaky(self, phase='all', on_line=None):
            if phase == 'units':
                raise SmartRouteError('ssh_failed', 'ssh failed')
            return original(self, phase, on_line)

        with mock.patch.object(FakeSRM, 'install', flaky):
            with self.assertRaises(SmartRouteError):
                await self.svc.install(
                    0, progress=lambda stage, line: seen.append((stage, line)))
        self.assertFalse(self.store['data']['servers'][0]['smartroute']['installed'])
        # The phase that produced output is still reported, plus the error.
        self.assertIn(('script', 'smartroute: script: done'), seen)
        self.assertTrue(any(stage == 'units' and 'ERROR' in line
                            for stage, line in seen))

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


    # ----- self-heal after container recreation -----

    async def test_reconcile_leaves_healthy_instance_alone(self):
        report = await self.svc.reconcile()
        self.assertEqual([r['protocol'] for r in report], ['awg2'])
        self.assertEqual(report[0]['throw_routes'], 37)
        self.assertNotIn('repaired', report[0])
        self.assertFalse([c for c in FakeSRM.calls if c[0] == 'enable_instance'])

    async def test_reconcile_reapplies_lost_split_routes(self):
        # Simulates the ZK case: container recreated, table 200 empty, panel
        # still records the instance as split.
        FakeSRM.throw_routes = 0
        report = await self.svc.reconcile()
        self.assertTrue(report[0]['repaired'])
        self.assertEqual(report[0]['throw_routes'], 0)
        self.assertEqual(report[0]['throw_routes_after'], 37)
        self.assertIn(('enable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertFalse(link.get('smart_route_lost'))

    async def test_reconcile_marks_lost_when_reapply_restores_nothing(self):
        FakeSRM.throw_routes = 0
        FakeSRM.repaired_to = 0
        report = await self.svc.reconcile()
        self.assertTrue(report[0]['repaired'])
        self.assertIn('error', report[0])
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        self.assertTrue(link['smart_route_lost'])

    async def test_reconcile_survives_a_failing_container(self):
        FakeSRM.throw_routes = 0
        FakeSRM.fail_enable = True
        report = await self.svc.reconcile()
        self.assertIn('error', report[0])
        self.assertNotIn('repaired', report[0])

    async def test_reconcile_skips_paused_server(self):
        self.store['data']['servers'][0]['smartroute']['enabled'] = False
        self.assertEqual(await self.svc.reconcile(), [])
        self.assertEqual(FakeSRM.calls, [])

    async def test_reconcile_skips_uninstalled_server(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        self.assertEqual(await self.svc.reconcile(), [])

    async def test_reconcile_single_server_by_id(self):
        report = await self.svc.reconcile(0)
        self.assertEqual([r['protocol'] for r in report], ['awg2'])
        with self.assertRaises(SmartRouteError) as ctx:
            await self.svc.reconcile(9)
        self.assertEqual(ctx.exception.code, 'server_not_found')

    async def test_reconcile_clears_a_stale_lost_badge(self):
        link = self.store['data']['servers'][0]['protocols']['awg2']['exit_link']
        link['smart_route_lost'] = True
        await self.svc.reconcile()
        self.assertFalse(link.get('smart_route_lost'))


    async def test_reconcile_skips_an_empty_prefix_list(self):
        # Re-applying with no list would "succeed" with zero routes and be
        # retried every round; the pass must stand down until the host has a
        # usable list again.
        FakeSRM.throw_routes = 0
        FakeSRM.prefixes_v4 = 0
        report = await self.svc.reconcile()
        self.assertEqual(report[0]['skipped'], 'prefix-list')
        self.assertNotIn('repaired', report[0])
        self.assertFalse([c for c in FakeSRM.calls if c[0] == 'enable_instance'])

    async def test_reconcile_still_heals_when_the_last_download_failed(self):
        # The host script keeps the previous list on a failed fetch and reports
        # its real count. A stale `error` must not stand the heal down: that
        # would disable it forever whenever the upstream source is down.
        FakeSRM.throw_routes = 0
        FakeSRM.list_error = 'no v4 source gave >= 100 prefixes; old list kept'
        report = await self.svc.reconcile()
        self.assertTrue(report[0]['repaired'])
        self.assertEqual(report[0]['throw_routes_after'], 37)
        self.assertIn(('enable_instance', 'amnezia-awg2',
                       '/opt/amnezia/awg/awg2/wg0.conf', SUBNET_DEFAULT),
                      FakeSRM.calls)

    async def test_one_unreachable_host_does_not_cancel_the_others(self):
        # The list is per host: a dead server must not stop the heal of the
        # rest, especially right after a plugin update recreated containers.
        self.store['data']['servers'].append({
            'uid': 'srv-broken', 'name': 'BROKEN',
            'smartroute': {'installed': True, 'enabled': True},
            'protocols': {'awg2': {'exit_link': {'exit_uid': 'E', 'smart_route': True}}}})

        class PerHost(FakeSRM):
            def host_status(self):
                if getattr(self, 'ssh', None) == 'srv-broken':
                    raise SmartRouteError('ssh_failed', 'unreachable')
                return super().host_status()

            def __init__(self, ssh):
                super().__init__(ssh)
                self.ssh = ssh

        self.svc.get_ssh = lambda server: server.get('uid')
        FakeSRM.throw_routes = 0
        with mock.patch.object(smartroute_service, 'SmartRouteManager', PerHost):
            report = await self.svc.reconcile()
        states = {e['server']: e for e in report}
        self.assertTrue(states['MAMKAM']['repaired'])
        self.assertEqual(states['BROKEN']['skipped'], 'prefix-list')

    async def test_reconcile_of_one_server_ignores_other_hosts(self):
        # reconcile(server_id) must read the prefix list of THAT host, not of
        # whichever installed server happens to be first in the inventory.
        self.store['data']['servers'].append({
            'uid': 'srv-other', 'name': 'OTHER',
            'smartroute': {'installed': True, 'enabled': True},
            'protocols': {'awg2': {'exit_link': {'exit_uid': 'E', 'smart_route': True}}}})
        self.svc.get_ssh = lambda server: server.get('uid')
        probed = []

        class PerHost(FakeSRM):
            def host_status(self):
                probed.append(getattr(self, 'ssh', None))
                return super().host_status()

            def __init__(self, ssh):
                super().__init__(ssh)
                self.ssh = ssh

        FakeSRM.throw_routes = 0
        with mock.patch.object(smartroute_service, 'SmartRouteManager', PerHost):
            await self.svc.reconcile(1)
        self.assertEqual(probed[:1], ['srv-other'])
        self.assertNotIn('srv-entry', probed)

    async def test_reconcile_without_splits_does_not_touch_the_host(self):
        for proto in ('awg', 'awg2'):
            self.store['data']['servers'][0]['protocols'][proto]['exit_link']['smart_route'] = False
        self.assertEqual(await self.svc.reconcile(), [])
        self.assertEqual(FakeSRM.calls, [])

    # ----- timer migration -----

    async def test_migrate_timer_reports_each_host(self):
        FakeSRM.migrate_state = 'migrated'
        report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['server'], 'MAMKAM')
        self.assertEqual(report[0]['state'], 'migrated')
        self.assertIn(('migrate_timer',), FakeSRM.calls)

    async def test_migrate_timer_noop_is_recorded_as_done(self):
        report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['state'], 'unchanged')
        rec = self.store['data']['panel_migrations']['smartroute_timer_v1']
        self.assertNotIn('pending', rec['hosts']['srv-entry'])

    async def test_migrate_timer_failure_stays_pending(self):
        FakeSRM.migrate_state = 'failed-not-armed'
        report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['state'], 'failed-not-armed')
        rec = self.store['data']['panel_migrations']['smartroute_timer_v1']
        self.assertTrue(rec['hosts']['srv-entry']['pending'])

    async def test_migrate_timer_ssh_exception_does_not_abort_the_pass(self):
        FakeSRM.migrate_fail = True
        report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['state'], 'failed-exception')

    async def test_migrate_timer_skips_uninstalled_server(self):
        self.store['data']['servers'][0]['smartroute']['installed'] = False
        self.assertEqual(await self.svc.migrate_timer(), [])
        self.assertEqual(FakeSRM.calls, [])

    async def test_migrate_timer_second_pass_skips_resolved_hosts(self):
        # Review A5: an unavailable host must not make every later panel start
        # pay a full SSH sweep again. A host recorded as done is not contacted.
        self.store['data']['panel_migrations'] = {
            'smartroute_timer_v1': {'hosts': {'srv-entry': {'state': 'unchanged'}}}}
        self.assertEqual(await self.svc.migrate_timer(), [])
        self.assertEqual(FakeSRM.calls, [])

    async def test_migrate_timer_second_pass_retries_pending_hosts(self):
        self.store['data']['panel_migrations'] = {
            'smartroute_timer_v1': {'hosts': {'srv-entry': {'state': 'failed-not-armed',
                                                            'pending': True}}}}
        report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['state'], 'unchanged')
        self.assertIn(('migrate_timer',), FakeSRM.calls)

    async def test_migrate_timer_explicit_server_ignores_the_record(self):
        # The manual repair path must always check the named host.
        self.store['data']['panel_migrations'] = {
            'smartroute_timer_v1': {'hosts': {'srv-entry': {'state': 'unchanged'}}}}
        report = await self.svc.migrate_timer(0)
        self.assertEqual(report[0]['state'], 'unchanged')
        self.assertIn(('migrate_timer',), FakeSRM.calls)

    async def test_prefix_list_caches_the_last_good_reading(self):
        # First probe reads the host and remembers 8000; a later probe that
        # fails must reuse it instead of reporting "0 prefixes" and standing
        # the whole fleet down.
        server = self.store['data']['servers'][0]
        self.assertEqual(await self.svc._prefix_list_health(server), (None, 8000))
        FakeSRM.fail_status = True
        server = self.store['data']['servers'][0]
        self.assertEqual(await self.svc._prefix_list_health(server), (None, 8000))

    async def test_prefix_list_without_cache_reports_the_failure(self):
        FakeSRM.fail_status = True
        error, count = await self.svc._prefix_list_health(self.store['data']['servers'][0])
        self.assertIn('ssh failed', error)
        self.assertEqual(count, 0)

    async def test_prefix_list_cache_expires(self):
        server = self.store['data']['servers'][0]
        await self.svc._prefix_list_health(server)
        FakeSRM.fail_status = True
        with mock.patch.object(smartroute_service, 'SMARTR_PREFIX_CACHE_TTL', -1):
            error, count = await self.svc._prefix_list_health(self.store['data']['servers'][0])
        self.assertIn('ssh failed', error)
        self.assertEqual(count, 0)

    async def test_migrate_timer_skips_host_without_the_script(self):
        # A record that says "installed" but a host with no updater: nothing to
        # migrate, and it must not become a permanent pending retry.
        class NoScript(FakeSRM):
            def is_installed(self):
                return False

        with mock.patch.object(smartroute_service, 'SmartRouteManager', NoScript):
            report = await self.svc.migrate_timer()
        self.assertEqual(report[0]['state'], 'not-installed')

    async def test_migrate_timer_repeat_pass_skips_finished_hosts(self):
        # A5: the first panel start finishes one host and fails the other; the
        # next start must skip the finished host and retry only the pending one.
        self.store['data']['servers'].append({
            'uid': 'srv-second', 'name': 'ZK',
            'smartroute': {'installed': True, 'own_subnets': [], 'dns_via_exit': False},
            'protocols': {}})
        self.svc.get_ssh = lambda server: server.get('uid')

        class PerHost(FakeSRM):
            attempts = {}

            def __init__(self, ssh):
                super().__init__(ssh)
                self.uid = ssh

            def migrate_timer(self):
                FakeSRM.calls.append(('migrate_timer', self.uid))
                tries = PerHost.attempts.get(self.uid, 0)
                PerHost.attempts[self.uid] = tries + 1
                if tries == 0 and self.uid == 'srv-second':
                    return {'state': 'failed-not-armed', 'detail': 'no backup',
                            'log': 'x'}
                return {'state': 'unchanged', 'detail': '', 'log': 'x'}

        with mock.patch.object(smartroute_service, 'SmartRouteManager', PerHost):
            first = await self.svc.migrate_timer()
            self.assertEqual([e['state'] for e in first],
                             ['unchanged', 'failed-not-armed'])
            self.assertEqual(FakeSRM.calls,
                             [('migrate_timer', 'srv-entry'),
                              ('migrate_timer', 'srv-second')])
            rec = self.store['data']['panel_migrations']['smartroute_timer_v1']['hosts']
            self.assertTrue(rec['srv-second']['pending'])
            FakeSRM.calls = []
            second = await self.svc.migrate_timer()
        self.assertEqual([e['uid'] for e in second], ['srv-second'])
        self.assertEqual(second[0]['state'], 'unchanged')
        # The finished host was not contacted again at all.
        self.assertEqual(FakeSRM.calls, [('migrate_timer', 'srv-second')])
        self.assertNotIn('pending', rec['srv-second'])

    async def test_migrate_timer_explicit_server_checks_finished_host(self):
        # A record that says "done" must not stop a manual repair: an explicit
        # server_id is checked even when the repeated pass would skip it.
        await self.svc.migrate_timer()
        rec = self.store['data']['panel_migrations']['smartroute_timer_v1']['hosts']
        self.assertNotIn('pending', rec['srv-entry'])
        FakeSRM.calls = []
        FakeSRM.migrate_state = 'migrated'
        report = await self.svc.migrate_timer(0)
        self.assertEqual([e['uid'] for e in report], ['srv-entry'])
        self.assertEqual(report[0]['state'], 'migrated')
        self.assertEqual(FakeSRM.calls, [('migrate_timer',)])

class StatusJsonSSH:
    """Minimal host stub whose `status.json` is the JSON we hand it."""

    def __init__(self, status_json):
        self._status_json = status_json

    def run_command(self, cmd, timeout=60):
        if 'cat /etc/smartroute/status.json' in cmd:
            return self._status_json, '', 0
        if 'systemctl list-timers' in cmd:
            return '2026-10-14 11:00:00\n', '', 0
        if 'test -f' in cmd:
            return 'yes', '', 0
        return '', '', 0


class SmartRouteStatusContractTest(unittest.IsolatedAsyncioTestCase):
    """The service must not blow up on a valid-but-non-object status.json:
    the real manager reports it as an error instead of raising on `**status`.
    This exercises the real SmartRouteManager (FakeSRM above is canned)."""

    def _service(self, status_json):
        store = {'data': make_data()}
        return SmartRouteService(
            load_data=lambda: store['data'],
            save_data=lambda data: store.__setitem__('data', data),
            data_lock=asyncio.Lock(),
            get_ssh=lambda server: StatusJsonSSH(status_json),
            awg_manager_factory=lambda ssh: FakeAWG(),
            protocol_base=lambda p: 'awg' if p.startswith('awg') else p,
            awg_protocols={'awg'},
            apply_dns_via_exit=lambda *args: asyncio.sleep(0),
        )

    async def test_status_surfaces_non_object_status_json(self):
        for raw in ('[]', '123', '"x"', 'null'):
            with self.subTest(raw):
                out = await self._service(raw).status(0)
                self.assertEqual(out['status'], 'success')
                self.assertEqual(out['host']['error'],
                                 'status file is not a JSON object')
                self.assertEqual(out['host']['status']['error'],
                                 'status file is not a JSON object')
                self.assertEqual(out['host']['next_update'], '2026-10-14 11:00:00')


if __name__ == '__main__':
    unittest.main()
