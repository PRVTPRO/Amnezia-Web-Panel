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
import unittest

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

    def test_install_skips_stopped_container(self):
        self.ssh.container_state = (True, False)
        run_coro(self.runtime.install(
            0, 'srv-1', protocol='awg', job_id='job-stopped'))

        self.assertNotIn('wgcf register --accept-tos',
                         '\n'.join(self.ssh.commands))
        self.assertEqual(self.manager.writes, [])
        self.assertFalse(self.data['servers'][0]['warp']['installed'])

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
            client_mtu=1220,
        )
        self.ssh.account_present = True
        self.ssh.conf_present = True

        run_coro(self.runtime.repair(
            0, 'srv-1', protocol='awg', job_id='job-repair-link'))

        self.assertEqual(len(self.manager.writes), 1)
        self.assertEqual(len(self.manager.uploads), 1)
        ctx = self.manager.uploads[0]['warp_ctx']
        self.assertTrue(ctx['active'])
        self.assertEqual(ctx['client_mtu'], 1220)
        self.assertEqual(self.manager.writes[0]['warp_ctx'], ctx)

    # ----- uninstall -------------------------------------------------------

    def test_uninstall_removes_artifacts_and_clears_state(self):
        self.seed_state(registered=True, link=None, client_mtu=1220)
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
