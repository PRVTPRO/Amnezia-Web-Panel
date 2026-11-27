"""Unit tests for the S4a WARP runtime (wgcf install/repair/uninstall).

Everything runs against a fake SSH transport and a fake AWG manager: the
tests pin the container command sequence, the warp0.conf sanitizer and the
state transitions without touching a real server.
"""

import asyncio
import concurrent.futures
import copy
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import warp_service as ws
from warp_runtime import WarpRuntime


def run_coro(coro):
    """Run a coroutine even when another test leaked a running event loop.

    The full suite has a pre-existing leak (some earlier test leaves a loop
    running in the main thread), after which ``asyncio.run`` refuses to start.
    A dedicated thread keeps these unit tests independent of that ordering.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


SAMPLE_PROFILE = """[Interface]
PrivateKey = private-key==
Address = 172.16.0.2/32, 2606:4700:110:8a36:df92:102a:9602:fa18/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1420
Table = auto

[Peer]
PublicKey = public-key==
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
"""


class FakeSSH:
    def __init__(self):
        self.commands = []
        self.scripts = []
        self.wgcf_present = True
        self.machine = 'x86_64'
        self.account_present = False
        self.conf_present = False
        self.profile = SAMPLE_PROFILE
        self.download_code = 0
        self.register_code = 0
        self.generate_code = 0
        self.conf_hash = 'deadbeef'
        self.container_state = (True, True)

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'command -v wgcf' in command:
            return ('/usr/local/bin/wgcf\n', '', 0) if self.wgcf_present \
                else ('', '', 1)
        if 'uname -m' in command:
            return self.machine + '\n', '', 0
        if 'curl -fsSL' in command:
            return '', '', self.download_code
        if 'test -f' in command:
            if 'account.toml' in command:
                return '', '', 0 if self.account_present else 1
            if 'warp0.conf' in command:
                return '', '', 0 if self.conf_present else 1
        if 'wgcf register' in command:
            return '', '', self.register_code
        if 'wgcf generate' in command:
            return '', '', self.generate_code
        if 'cat ' in command and 'warp0.conf' in command:
            return self.profile, '', 0
        if 'sha256sum' in command:
            return '%s  /opt/amnezia/awg/warp/awg/warp0.conf\n' % (
                self.conf_hash), '', 0
        return '', '', 0

    def run_sudo_script(self, script, timeout=120):
        self.scripts.append(script)
        return '', '', 0

    def docker_container_state(self, name):
        if isinstance(self.container_state, dict):
            return self.container_state.get(name, (True, True))
        return self.container_state


class FakeManager:
    def __init__(self, ssh):
        self.ssh = ssh
        self.config_path = '/opt/amnezia/awg/awg0.conf'
        self.writes = []
        self.uploads = []

    def _container_name(self, protocol):
        base = str(protocol).split('__', 1)[0]
        return {
            'awg': 'amnezia-awg',
            'awg2': 'amnezia-awg2',
            'awg3': 'amnezia-awg3',
        }.get(base, 'amnezia-awg')

    def _config_path(self, protocol):
        return self.config_path

    def _write_start_script(self, protocol_type=None, config_path=None,
                            warp_ctx=None):
        self.writes.append({
            'protocol': protocol_type,
            'config_path': config_path,
            'warp_ctx': warp_ctx,
        })

    def _upload_start_script(self, protocol_type=None, warp_ctx=None):
        self.uploads.append({
            'protocol': protocol_type,
            'warp_ctx': warp_ctx,
        })

    def _read_config_key_live(self, protocol, key):
        return 1500

    def check_container_running(self, protocol):
        return True


class _FakeLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class WarpRuntimeHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = {
            'servers': [{
                'uid': 'srv-1',
                'name': 'warp box',
                'protocols': {
                    'awg': {'installed': True},
                    'awg2': {'installed': True},
                },
            }],
        }
        self.state_store = ws.WarpStateStore(
            os.path.join(self.tmp, 'data.json.srv_warp_state.json'))
        self.ssh = FakeSSH()
        self.manager = FakeManager(self.ssh)
        self.jobs = []
        self.runtime = WarpRuntime(
            load_data=self._load_data,
            save_data=self._save_data,
            data_lock=_FakeLock(),
            get_ssh=lambda server: self.ssh,
            awg_manager_factory=lambda ssh: self.manager,
            state_store=self.state_store,
            job_end=lambda uid, job_id: self.jobs.append((uid, job_id)),
        )

    def _load_data(self):
        return copy.deepcopy(self.data)

    def _save_data(self, data):
        self.data = copy.deepcopy(data)

    def seed_state(self, registered=True, link=None, client_mtu=None,
                   regen=None):
        def mutate(state):
            rec = ws.proto_record(state, 'srv-1', 'awg')
            rec['warp']['registered'] = registered
            rec['warp_link'] = link
            rec['client_mtu_warp'] = client_mtu
            rec['warp_egress_regen'] = regen or {}

        self.state_store.mutate(mutate)

    def record(self, protocol='awg'):
        return ws.proto_record(self.state_store.load(), 'srv-1', protocol)

    def registrations(self, uid='srv-1'):
        record = (self.state_store.load().get('servers') or {}).get(uid) or {}
        return record.get('registers_ts') or []

    def seed_registers(self, count, age=0):
        now = ws.now_ts()
        def seed(state):
            record = ws.server_record(state, 'srv-1')
            record['registers_ts'] = [
                {'ts': now - age - index, 'source': 'install',
                 'protocol': 'awg'} for index in range(count)]
        self.state_store.mutate(seed)

    # ----- install ---------------------------------------------------------

    def test_install_registers_generates_and_does_not_restart(self):
        run_coro(self.runtime.install(
            0, 'srv-1', protocol='awg', job_id='job-install'))

        commands = '\n'.join(self.ssh.commands)
        self.assertIn('command -v wgcf', commands)
        self.assertIn('wgcf register --accept-tos', commands)
        self.assertIn('wgcf generate', commands)
        self.assertNotIn('docker restart', commands)

        rec = self.record()
        self.assertTrue(rec['warp']['registered'])
        self.assertEqual(rec['warp']['conf_hash'], 'deadbeef')

        self.assertEqual(len(self.manager.writes), 1)
        self.assertEqual(self.manager.writes[0]['protocol'], 'awg')
        self.assertIsNone(self.manager.writes[0]['warp_ctx'])
        self.assertEqual(self.manager.uploads, [])

        self.assertTrue(self.data['servers'][0]['warp']['installed'])
        self.assertEqual(self.jobs, [('srv-1', 'job-install')])

        # The sanitized profile is delivered through a heredoc script, not
        # through a logged docker exec command line.
        self.assertTrue(any('# DO NOT wg-quick/awg-quick up' in script
                            for script in self.ssh.scripts))
        self.assertTrue(any('MTU = 1280' in script
                            for script in self.ssh.scripts))

    def test_install_records_its_registration_in_the_store(self):
        run_coro(self.runtime.install(
            0, 'srv-1', protocol='awg', job_id='job-record'))
        registers = self.registrations()
        self.assertEqual(len(registers), 1)
        self.assertEqual(registers[0]['source'], 'install')
        self.assertEqual(registers[0]['protocol'], 'awg')

    def test_install_with_an_existing_account_spends_no_quota(self):
        self.ssh.account_present = True
        run_coro(self.runtime.install(
            0, 'srv-1', protocol='awg', job_id='job-existing'))
        self.assertNotIn('wgcf register --accept-tos',
                         '\n'.join(self.ssh.commands))
        self.assertEqual(self.registrations(), [])

    def test_quota_blocks_a_new_registration_before_wgcf(self):
        self.seed_registers(3)
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(
                0, 'srv-1', protocol='awg', job_id='job-quota'))
        self.assertEqual(ctx.exception.code, 'srv_warp_quota_exhausted')
        self.assertNotIn('wgcf register --accept-tos',
                         '\n'.join(self.ssh.commands))
        self.assertEqual(len(self.registrations()), 3)

    def test_registrations_outside_the_window_are_allowed(self):
        self.seed_registers(3, age=8 * 24 * 3600)
        run_coro(self.runtime.install(
            0, 'srv-1', protocol='awg', job_id='job-old-quota'))
        registers = self.registrations()
        self.assertEqual(len(registers), 4)
        self.assertEqual(registers[-1]['source'], 'install')

    def test_two_registrations_cannot_pass_the_gate_together(self):
        # Distinct seconds: a dedup key equal to the new entry would hide one.
        self.seed_registers(2, age=10)
        entered = threading.Event()
        release = threading.Event()
        calls = []
        original = self.ssh.run_sudo_command

        def slow(command, timeout=60):
            if 'wgcf register' in command:
                calls.append(command)
                entered.set()
                release.wait(5)
            return original(command, timeout)

        self.ssh.run_sudo_command = slow
        results = []

        def run():
            try:
                self.runtime._register_and_write_conf(
                    self.manager, 'awg', 'srv-1', 'install')
                results.append('ok')
            except ws.SrvWarpError as exc:
                results.append(exc.code)

        first = threading.Thread(target=run)
        first.start()
        self.assertTrue(entered.wait(5))
        second = threading.Thread(target=run)
        second.start()
        release.set()
        first.join(5)
        second.join(5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(results),
                         ['ok', 'srv_warp_quota_exhausted'])
        self.assertEqual(len(self.registrations()), 3)

    def test_a_newer_state_file_blocks_jobs_before_ssh(self):
        with open(self.state_store.path, 'w', encoding='utf-8') as fh:
            json.dump({'version': 99,
                       'servers': {'srv-1': {'protocols': {}}}}, fh)
        with self.assertRaises(ws.WarpStateUnsupportedVersion):
            run_coro(self.runtime.install(
                0, 'srv-1', protocol='awg', job_id='job-newer'))
        self.assertEqual(self.ssh.commands, [])
        self.assertEqual(self.manager.writes, [])

    def test_install_with_every_container_stopped_is_an_error(self):
        # A "success" with no registered profile is what left the marketplace
        # on "Install" after a finished install (FINN, 2026-11-15).
        self.ssh.container_state = (True, False)
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(
                0, 'srv-1', protocol='awg', job_id='job-stopped'))

        self.assertEqual(ctx.exception.code, 'srv_warp_no_targets')
        self.assertNotIn('wgcf register --accept-tos',
                         '\n'.join(self.ssh.commands))
        self.assertEqual(self.manager.writes, [])
        self.assertFalse(self.data['servers'][0].get('warp') or {})

    def test_install_without_an_awg_instance_is_an_error(self):
        self.data['servers'][0]['protocols'] = {'exit': {'installed': True}}
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(0, 'srv-1', job_id='job-no-targets'))

        self.assertEqual(ctx.exception.code, 'srv_warp_no_targets')
        # Nothing may be attempted over SSH on a host without a target.
        self.assertEqual(self.ssh.commands, [])
        self.assertFalse(self.data['servers'][0].get('warp') or {})

    def test_install_for_a_missing_instance_is_an_error(self):
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(
                0, 'srv-1', protocol='awg3', job_id='job-missing'))

        self.assertEqual(ctx.exception.code, 'srv_warp_no_targets')
        self.assertEqual(self.ssh.commands, [])

    def test_install_isolates_a_failing_instance(self):
        # A host-level install covers every AWG instance: one failing
        # instance must not abort the others (the target list used to hold
        # a single instance, so the loop never had to isolate failures).
        calls = {'n': 0}
        original = self.runtime._ensure_wgcf

        def flaky(manager, proto):
            calls['n'] += 1
            if proto == 'awg':
                raise ws.SrvWarpError('srv_warp_register_failed', 502)
            return original(manager, proto)

        self.runtime._ensure_wgcf = flaky
        stages = []
        # awg fails, awg2 still installs: a host-level run must not abort on
        # a single broken instance.
        run_coro(self.runtime.install(
            0, 'srv-1', job_id='job-isolate',
            progress=lambda stage, msg: stages.append(stage)))

        self.assertEqual(calls['n'], 2)
        self.assertIn('failed', stages)
        self.assertTrue(self.record('awg2')['warp']['registered'])
        self.assertFalse(self.record('awg')['warp']['registered'])
        self.assertTrue(self.data['servers'][0]['warp']['installed'])

    def test_a_total_install_failure_keeps_its_reason(self):
        # Every instance fails: the job must report the concrete reason, not a
        # misleading "no targets" (nothing was skipped).
        def always_fail(manager, proto):
            raise ws.SrvWarpError('srv_warp_register_failed', 502)

        self.runtime._ensure_wgcf = always_fail
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(0, 'srv-1', job_id='job-all-fail'))

        self.assertEqual(ctx.exception.code, 'srv_warp_register_failed')
        self.assertFalse((self.data['servers'][0].get('warp') or {})
                         .get('installed'))

    def test_an_unexpected_install_error_gets_a_stable_code(self):
        # The per-instance isolation needs a translatable reason to raise: a
        # class name would not be a code the UI could map.
        def boom(manager, proto):
            raise TimeoutError('ssh went away')

        self.runtime._ensure_wgcf = boom
        with self.assertRaises(ws.SrvWarpError) as ctx:
            run_coro(self.runtime.install(0, 'srv-1', job_id='job-boom'))

        self.assertEqual(ctx.exception.code, 'srv_warp_install_failed')

    def test_install_reports_a_skipped_stopped_instance(self):
        self.ssh.container_state = {
            'amnezia-awg': (True, True),
            'amnezia-awg2': (True, False),
        }
        stages = []
        run_coro(self.runtime.install(
            0, 'srv-1', job_id='job-partial',
            progress=lambda stage, msg: stages.append(stage)))

        self.assertIn('skip', stages)
        self.assertTrue(self.record('awg')['warp']['registered'])
        self.assertFalse(self.record('awg2')['warp']['registered'])
        self.assertTrue(self.data['servers'][0]['warp']['installed'])

    # ----- link ------------------------------------------------------------

    def test_link_registers_missing_profile_before_the_killswitch(self):
        # The start.sh of a linked instance blackholes client traffic until
        # warp0 is up, so an unregistered instance must never be announced as
        # linked: that is what left awg3__3 without internet.
        self.seed_state(registered=False)
        self.ssh.account_present = False
        self.ssh.conf_present = False
        probes = []

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            probes.append(protocol)
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.link(0, 'srv-1', 'awg', job_id='job-link'))

        commands = '\n'.join(self.ssh.commands)
        self.assertIn('wgcf register --accept-tos', commands)
        rec = self.record()
        self.assertTrue(rec['warp']['registered'])
        self.assertIsNotNone(ws.warp_link(rec))
        self.assertEqual(rec['client_mtu_warp'], 1280)
        self.assertEqual(rec['warp']['repair_state']['state'], 'ok')
        self.assertEqual(len(self.manager.uploads), 1)
        self.assertTrue(self.manager.uploads[0]['warp_ctx']['active'])
        self.assertEqual(probes, ['awg'])

    def test_link_rolls_back_when_warp0_never_comes_up(self):
        self.seed_state(registered=True)
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def down(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': False, 'facts': {'WARP_ROUTE': 'missing'},
                    'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane',
                               down):
            run_coro(self.runtime.link(0, 'srv-1', 'awg',
                                       job_id='job-link-down'))

        rec = self.record()
        self.assertIsNone(ws.warp_link(rec))
        self.assertIsNone(rec['client_mtu_warp'])
        self.assertEqual(rec['warp']['repair_state']['state'], 'error')
        self.assertEqual(rec['warp']['repair_state']['last_error'],
                         'srv_warp_link_failed')
        # The kill-switch must be removed again: start.sh is re-rendered
        # without the warp block and the container is restarted.
        self.assertEqual(len(self.manager.uploads), 2)
        self.assertTrue(self.manager.uploads[0]['warp_ctx']['active'])
        self.assertIsNone(self.manager.uploads[1]['warp_ctx'])

    def test_link_confirms_dataplane_in_warp_link(self):
        """Успешный link должен оставлять подтверждение датаплейна в записи."""
        self.seed_state(registered=True)
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.link(0, 'srv-1', 'awg',
                                       job_id='job-link-confirmed'))

        link = ws.warp_link(self.record())
        self.assertTrue(link['dataplane_ok'])
        self.assertIsInstance(link['dataplane_ok_at'], int)
        self.assertGreater(link['dataplane_ok_at'], 0)
        # Метка подтверждения не затирает остальные поля линка.
        self.assertEqual(link['protocol'], 'awg')
        self.assertEqual(link['server_uid'], 'srv-1')
        self.assertIsNone(link['stale'])
        self.assertIsNotNone(link['applied_at'])

    def test_link_rollback_leaves_no_dataplane_confirmation(self):
        """При сбое warp0 запись линка (и подтверждения) не остаётся."""
        self.seed_state(registered=True)
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def down(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': False, 'facts': {'WARP_ROUTE': 'missing'},
                    'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane',
                               down):
            run_coro(self.runtime.link(
                0, 'srv-1', 'awg', job_id='job-link-no-confirmation'))

        rec = self.record()
        self.assertIsNone(rec['warp_link'])
        self.assertIsNone(ws.warp_link(rec))
        self.assertEqual(rec['warp']['repair_state']['last_error'],
                         'srv_warp_link_failed')

    def test_link_copies_profile_from_a_live_sibling(self):
        # MRAK's Cloudflare registration API is SNI-filtered, but awg3__2 has
        # a working profile: linking awg3__3 must copy it instead of calling
        # wgcf register.
        def seed_sibling(state):
            rec = ws.proto_record(state, 'srv-1', 'awg')
            rec['warp']['registered'] = True
            rec['warp_link'] = {'active': True}

        self.state_store.mutate(seed_sibling)
        self.ssh.conf_present = False
        sources = []

        def source(self, manager, protocol, reuse=True, uid=None,
                   source_name='import_source'):
            sources.append(protocol)
            return 'account body', 'profile body'

        def write(self, manager, protocol, account, profile):
            return 'copied-hash'

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_warp_dataplane',
                               lambda self, manager, protocol:
                               {'up': True, 'facts': {}, 'detail': ''}), \
             mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up), \
             mock.patch.object(type(self.runtime), '_source_profile', source), \
             mock.patch.object(type(self.runtime), '_write_imported_profile',
                               write):
            run_coro(self.runtime.link(0, 'srv-1', 'awg2',
                                       job_id='job-link-copy'))

        commands = '\n'.join(self.ssh.commands)
        self.assertNotIn('wgcf register --accept-tos', commands)
        self.assertEqual(sources, ['awg'])
        rec = self.record('awg2')
        self.assertTrue(rec['warp']['registered'])
        self.assertEqual(rec['warp']['conf_hash'], 'copied-hash')
        self.assertEqual(rec['warp']['imported_from_protocol'], 'awg')
        self.assertIsNotNone(ws.warp_link(rec))
        self.assertTrue(self.manager.uploads[-1]['warp_ctx']['active'])

    def test_link_registers_when_sibling_dataplane_is_down(self):
        def seed_sibling(state):
            rec = ws.proto_record(state, 'srv-1', 'awg')
            rec['warp']['registered'] = True
            rec['warp_link'] = {'active': True}

        self.state_store.mutate(seed_sibling)
        self.ssh.conf_present = False

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_warp_dataplane',
                               lambda self, manager, protocol:
                               {'up': False, 'facts': {}, 'detail': ''}), \
             mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.link(0, 'srv-1', 'awg2',
                                       job_id='job-link-register'))

        self.assertIn('wgcf register --accept-tos',
                      '\n'.join(self.ssh.commands))
        rec = self.record('awg2')
        self.assertTrue(rec['warp']['registered'])
        self.assertNotIn('imported_from_protocol', rec['warp'])
        registers = self.registrations()
        self.assertEqual(len(registers), 1)
        self.assertEqual(registers[0]['source'], 'link')

    def test_link_skips_sibling_without_a_complete_profile(self):
        def seed_sibling(state):
            rec = ws.proto_record(state, 'srv-1', 'awg')
            rec['warp']['registered'] = True
            rec['warp_link'] = {'active': True}

        self.state_store.mutate(seed_sibling)
        self.ssh.conf_present = False
        sourced = []

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        def source(self, manager, protocol, reuse=True, uid=None,
                   source_name='import_source'):
            sourced.append(protocol)
            return 'account', 'profile'

        with mock.patch.object(type(self.runtime), '_warp_dataplane',
                               lambda self, manager, protocol:
                               {'up': True, 'facts': {}, 'detail': ''}), \
             mock.patch.object(type(self.runtime), '_has_profile',
                               lambda self, manager, protocol: False), \
             mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up), \
             mock.patch.object(type(self.runtime), '_source_profile', source):
            run_coro(self.runtime.link(0, 'srv-1', 'awg2',
                                       job_id='job-link-no-source'))

        self.assertEqual(sourced, [])
        self.assertIn('wgcf register --accept-tos',
                      '\n'.join(self.ssh.commands))
        self.assertTrue(self.record('awg2')['warp']['registered'])

    def test_repair_records_a_real_registration(self):
        self.seed_state(registered=True, link={'active': True})
        self.ssh.conf_present = False

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-record'))

        registers = self.registrations()
        self.assertEqual(len(registers), 1)
        self.assertEqual(registers[0]['source'], 'repair')

    def test_repair_marks_error_when_dataplane_stays_down(self):
        self.seed_state(registered=True, link={'active': True},
                        client_mtu=1280)

        async def down(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': False, 'facts': {'WARP_ROUTE': 'missing'},
                    'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', down):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-down'))

        state = self.record()['warp']['repair_state']
        self.assertEqual(state['state'], 'error')
        self.assertEqual(state['last_error'], 'srv_warp_link_failed')

    # ----- sanitizer -------------------------------------------------------

    def test_sanitize_warp_profile(self):
        profile = ws.sanitize_warp_profile(SAMPLE_PROFILE)

        self.assertTrue(profile.startswith('# DO NOT wg-quick/awg-quick up\n'))
        self.assertNotIn('DNS', profile)
        self.assertNotIn('2606:', profile)
        self.assertNotIn('::/0', profile)
        self.assertNotIn('172.16.0.2/32', profile)
        self.assertIn('Address = 172.16.0.2\n', profile)
        self.assertIn('AllowedIPs = 0.0.0.0/0\n', profile)
        self.assertIn('MTU = 1280\n', profile)
        self.assertIn('Table = off\n', profile)
        self.assertIn('PersistentKeepalive = 25\n', profile)
        self.assertEqual(ws.sanitize_warp_profile(profile), profile)

    def test_install_arch_unsupported(self):
        self.ssh.wgcf_present = False
        self.ssh.machine = 'mips64'

        with self.assertRaises(ws.SrvWarpError) as ctx:
            self.runtime._ensure_wgcf(self.manager, 'awg')

        self.assertEqual(ctx.exception.code, 'srv_warp_arch_unsupported')
        self.assertEqual(ctx.exception.http_status, 409)
        self.assertFalse(any('curl -fsSL' in cmd for cmd in self.ssh.commands))

    # ----- repair ----------------------------------------------------------

    def test_repair_host_level_isolates_a_failing_instance(self):
        # Both instances are registered; a host-level repair must not let one
        # broken instance cancel the repair of the other.
        def seed(state):
            for proto in ('awg', 'awg2'):
                ws.proto_record(state, 'srv-1', proto)['warp']['registered'] = True

        self.state_store.mutate(seed)

        calls = {'n': 0}
        original = self.runtime._ensure_wgcf

        def flaky(manager, proto):
            calls['n'] += 1
            if proto == 'awg':
                raise ws.SrvWarpError('srv_warp_arch_unsupported', 409)
            return original(manager, proto)

        self.runtime._ensure_wgcf = flaky
        run_coro(self.runtime.repair(0, 'srv-1', job_id='job-repair-isolate'))

        self.assertEqual(calls['n'], 2)
        # The healthy instance is repaired, the broken one records why.
        self.assertEqual(self.record('awg2')['warp']['repair_state']['state'],
                         'ok')
        self.assertEqual(self.record('awg')['warp']['repair_state']['state'],
                         'error')
        self.assertEqual(
            self.record('awg')['warp']['repair_state']['last_error'],
            'srv_warp_arch_unsupported')

    def test_repair_missing_creds_registers_again(self):
        self.seed_state(registered=True, link=None)
        self.ssh.account_present = False
        self.ssh.conf_present = False

        run_coro(self.runtime.repair(
            0, 'srv-1', protocol='awg', job_id='job-repair'))

        self.assertIn('wgcf register --accept-tos',
                      '\n'.join(self.ssh.commands))
        self.assertEqual(self.manager.uploads, [])
        self.assertEqual(self.record()['warp']['repair_state']['state'], 'ok')

    def test_repair_active_link_rewrites_and_restarts_with_ctx(self):
        self.seed_state(
            registered=True,
            link={
                'active': True,
                'dns_via_warp': False,
                'applied_at': ws.now_ts(),
                'stale': None,
                'server_uid': 'srv-1',
                'entry_uid': 'srv-1',
                'protocol': 'awg',
            },
            client_mtu=1280,
        )
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        def down(self, manager, protocol):
            return {'up': False, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_warp_dataplane', down), \
             mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-link'))

        self.assertEqual(len(self.manager.writes), 1)
        self.assertEqual(len(self.manager.uploads), 1)
        ctx = self.manager.uploads[0]['warp_ctx']
        self.assertTrue(ctx['active'])
        self.assertEqual(ctx['client_mtu'], 1280)
        self.assertEqual(self.manager.writes[0]['warp_ctx'], ctx)
        self.assertEqual(self.record()['warp']['repair_state']['state'], 'ok')

    def test_repair_confirms_dataplane_on_active_link(self):
        """Успешный repair активного линка сохраняет факт подтверждения."""
        self.seed_state(
            registered=True,
            link={
                'active': True,
                'dns_via_warp': True,
                'applied_at': 1,
                'stale': None,
                'server_uid': 'srv-1',
                'entry_uid': 'srv-1',
                'protocol': 'awg',
            },
            client_mtu=1280,
        )
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        def down(self, manager, protocol):
            return {'up': False, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_warp_dataplane', down), \
             mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-confirmed'))

        rec = self.record()
        link = ws.warp_link(rec)
        self.assertTrue(link['dataplane_ok'])
        self.assertIsInstance(link['dataplane_ok_at'], int)
        self.assertGreater(link['dataplane_ok_at'], 0)
        # Не подтверждённые поля линка сохраняются как есть.
        self.assertTrue(link['dns_via_warp'])
        self.assertEqual(link['applied_at'], 1)
        self.assertEqual(rec['warp']['repair_state']['state'], 'ok')

    def test_repair_failed_dataplane_marks_active_link_stale(self):
        """Провал пробы активного линка снимает dataplane_ok и ставит stale."""
        link = {
            'active': True,
            'dns_via_warp': False,
            'applied_at': 1,
            'stale': None,
            'dataplane_ok': True,
            'dataplane_ok_at': 1,
            'server_uid': 'srv-1',
            'entry_uid': 'srv-1',
            'protocol': 'awg',
        }
        self.seed_state(registered=True, link=link, client_mtu=1280)
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def down(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': False, 'facts': {'WARP_ROUTE': 'missing'},
                    'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', down):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-down'))

        rec = self.record()
        state_link = ws.warp_link(rec)
        self.assertEqual(state_link['stale'], ws.STALE_DATAPLANE_DOWN)
        self.assertFalse(state_link['dataplane_ok'])
        self.assertEqual(state_link['applied_at'], 1)
        self.assertEqual(rec['warp']['repair_state']['last_error'],
                         'srv_warp_link_failed')

    def test_repair_success_clears_stale_on_active_link(self):
        """Успешный repair возвращает линк в подтверждённое состояние."""
        self.seed_state(
            registered=True,
            link={
                'active': True,
                'dns_via_warp': False,
                'applied_at': 1,
                'stale': 'dataplane_down',
                'dataplane_ok': False,
                'server_uid': 'srv-1',
                'entry_uid': 'srv-1',
                'protocol': 'awg',
            },
            client_mtu=1280,
        )
        self.ssh.account_present = True
        self.ssh.conf_present = True

        async def up(self, manager, protocol, attempts=5, delay=2.0):
            return {'up': True, 'facts': {}, 'detail': ''}

        with mock.patch.object(type(self.runtime), '_wait_warp_dataplane', up):
            run_coro(self.runtime.repair(
                0, 'srv-1', protocol='awg', job_id='job-repair-recover'))

        state_link = ws.warp_link(self.record())
        self.assertIsNone(state_link['stale'])
        self.assertTrue(state_link['dataplane_ok'])

    def test_switch_egress_does_not_clear_stale(self):
        """Смена egress без пробы dataplane делает линк устаревшим."""
        self.seed_state(
            registered=True,
            link={
                'active': True,
                'dns_via_warp': False,
                'applied_at': 1,
                'stale': 'container_restart',
                'dataplane_ok': True,
                'server_uid': 'srv-1',
                'entry_uid': 'srv-1',
                'protocol': 'awg',
            },
            client_mtu=1280,
        )
        run_coro(self.runtime.switch_egress(
            0, 'srv-1', 'awg', job_id='job-switch'))

        state_link = ws.warp_link(self.record())
        self.assertEqual(state_link['stale'], ws.STALE_EGRESS_SWITCH)
        self.assertFalse(state_link['dataplane_ok'])

    # ----- uninstall -------------------------------------------------------

    def test_uninstall_clears_store_only_instance_when_container_ops_fail(self):
        # A deleted instance can leave a registered warp record behind. Its
        # container is gone, but the state cleanup must still happen.
        self.data['servers'][0]['protocols'] = {'awg': {'installed': True}}

        def seed(state):
            ws.proto_record(state, 'srv-1', 'awg2')['warp']['registered'] = True

        self.state_store.mutate(seed)
        original_name = self.manager._container_name

        def flaky_name(protocol):
            if protocol == 'awg2':
                raise RuntimeError('container is gone')
            return original_name(protocol)

        self.manager._container_name = flaky_name
        run_coro(self.runtime.uninstall(0, 'srv-1', job_id='job-orphan'))

        self.assertFalse(self.record('awg2')['warp']['registered'])

    def test_uninstall_removes_artifacts_and_clears_state(self):
        self.seed_state(registered=True, link=None, client_mtu=1280)
        self.data['servers'][0]['warp'] = {'installed': True}

        run_coro(self.runtime.uninstall(
            0, 'srv-1', protocol='awg', job_id='job-uninstall'))

        commands = '\n'.join(self.ssh.commands)
        self.assertIn('rm -rf /opt/amnezia/awg/warp/awg', commands)
        self.assertIn('rm -f /opt/amnezia/awg/warp-link-awg', commands)

        rec = self.record()
        self.assertFalse(rec['warp']['registered'])
        self.assertIsNone(rec['warp']['conf_hash'])
        self.assertIsNone(rec['warp_link'])
        self.assertIsNone(rec['client_mtu_warp'])
        self.assertEqual(rec['warp_egress_regen'], {})

        self.assertEqual(len(self.manager.writes), 1)
        self.assertIsNone(self.manager.writes[0]['warp_ctx'])
        self.assertEqual(self.manager.uploads, [])
        self.assertFalse(self.data['servers'][0]['warp']['installed'])


if __name__ == '__main__':
    unittest.main()
