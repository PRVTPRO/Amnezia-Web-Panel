"""ICMP echo-request: the panel must remove the DROP rule, not add it.

The rule used to go into INPUT during setup_firewall(), so hosts stopped
answering ping and ICMP inside tunnels died after decryption. New installs
clear the rule; a one-shot migration clears it on hosts provisioned before
the fix.
"""

import asyncio
import copy
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi.responses import JSONResponse

from managers.awg_manager import AWGManager, ICMP_ECHO_ALLOW_SCRIPT
from managers.wireguard_manager import WireGuardManager

ROOT = Path(__file__).resolve().parents[1]


class CapturingSSH:
    def __init__(self):
        self.scripts = []

    def run_sudo_script(self, script, timeout=300, **kwargs):
        self.scripts.append(script)
        return '', '', 0


class FirewallScriptTests(unittest.TestCase):
    def _script(self, manager_cls):
        ssh = CapturingSSH()
        self.assertTrue(manager_cls(ssh).setup_firewall())
        self.assertEqual(len(ssh.scripts), 1)
        return ssh.scripts[0]

    def _assert_clears_only(self, script):
        self.assertNotIn('-A INPUT -p icmp', script)
        self.assertNotIn('-A INPUT -p icmp --icmp-type echo-request -j DROP', script)
        self.assertIn('-D INPUT $spec -j DROP', script)
        self.assertIn('for bin in iptables iptables-legacy', script)
        self.assertIn('ICMP_ECHO_DROP_LEFT=', script)
        self.assertIn('/etc/iptables/rules.v4', script)
        # The rest of setup_firewall must be untouched.
        self.assertIn('net.ipv4.ip_forward=1', script)
        self.assertIn('DOCKER-USER', script)

    def test_awg_setup_firewall_removes_rule(self):
        script = self._script(AWGManager)
        self._assert_clears_only(script)
        self.assertTrue(script.startswith(ICMP_ECHO_ALLOW_SCRIPT))

    def test_wireguard_setup_firewall_removes_rule(self):
        script = self._script(WireGuardManager)
        self._assert_clears_only(script)
        self.assertTrue(script.startswith(ICMP_ECHO_ALLOW_SCRIPT))

    def test_script_covers_both_spec_forms_and_binaries(self):
        script = ICMP_ECHO_ALLOW_SCRIPT
        self.assertIn('--icmp-type echo-request', script)
        self.assertIn('--icmp-type 8', script)
        self.assertIn('-m icmp', script)
        self.assertIn('iptables-legacy', script)
        self.assertNotIn('-A INPUT -p icmp', script)
        # Missing rule is not an error.
        self.assertIn('exit 0', script)
        self.assertTrue(script.rstrip().endswith('exit 0'))

    def test_setup_firewall_bash_is_syntactically_valid(self):
        import shutil
        import subprocess
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('bash is not installed on this host')
        probe = ('ICMP_ECHO_DROP_LEFT=0\n'
                 'for bin in iptables iptables-legacy; do\n'
                 '  command -v "$bin" >/dev/null 2>&1 || continue\n'
                 'done\n'
                 'echo "ICMP_ECHO_DROP_LEFT=$ICMP_ECHO_DROP_LEFT"\n'
                 'exit 0\n')
        # `bash -n` parses without running; validate the real removal script.
        result = subprocess.run([bash, '-n', '-c', ICMP_ECHO_ALLOW_SCRIPT + probe],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


class IcmpMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import app
        self.app = app
        self.data = {
            'servers': [
                {'name': 'A', 'uid': 'node-a', 'host': '192.0.2.1'},
                {'name': 'B', 'uid': 'node-b', 'host': '192.0.2.2'},
            ],
            'users': [{'id': 'u', 'traffic_used': 1}],
            'settings': {'appearance': {'title': 'x'}},
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(
            app, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(app, 'save_data', side_effect=self._save))
        self.stack.enter_context(patch.object(app, 'AWP_ICMP_ECHO_DELAY', 0))
        self.stack.enter_context(patch.object(app, 'AWP_ICMP_ECHO_MIGRATION', True))

    def _save(self, data):
        self.data = copy.deepcopy(data)

    def _record(self):
        return self.data.get('panel_migrations', {}).get(self.app.AWP_ICMP_ECHO_KEY, {})

    async def test_skips_when_already_done(self):
        self.data['panel_migrations'] = {
            self.app.AWP_ICMP_ECHO_KEY: {'done_at': 'yes'}}
        with patch.object(self.app, '_rkn_ssh_run') as run:
            await self.app.icmp_echo_unblock_migration()
        run.assert_not_called()

    async def test_disabled_by_env(self):
        with patch.object(self.app, 'AWP_ICMP_ECHO_MIGRATION', False), \
                patch.object(self.app, '_rkn_ssh_run') as run:
            await self.app.icmp_echo_unblock_migration()
        run.assert_not_called()

    async def test_runs_on_every_server_and_marks_done(self):
        calls = []

        async def run(server, script, timeout):
            calls.append((server['uid'], script, timeout))
            return None

        with patch.object(self.app, '_rkn_ssh_run', side_effect=run):
            await self.app.icmp_echo_unblock_migration()

        self.assertEqual([c[0] for c in calls], ['node-a', 'node-b'])
        for _, script, timeout in calls:
            self.assertEqual(script, self.app.ICMP_ECHO_ALLOW_SCRIPT)
            self.assertEqual(timeout, self.app.AWP_ICMP_ECHO_TIMEOUT)
        rec = self._record()
        self.assertTrue(rec.get('done_at'))
        self.assertEqual(rec['pending'], 0)
        self.assertEqual(self.data['users'], [{'id': 'u', 'traffic_used': 1}])

    async def test_failed_host_keeps_others_and_retries_next_start(self):
        calls = []

        async def run(server, script, timeout):
            calls.append(server['uid'])
            if server['uid'] == 'node-a':
                return JSONResponse({'error': 'sudo denied'}, status_code=500)
            return None

        with patch.object(self.app, '_rkn_ssh_run', side_effect=run):
            await self.app.icmp_echo_unblock_migration()

        self.assertEqual(calls, ['node-a', 'node-b'])
        rec = self._record()
        self.assertNotIn('done_at', rec)
        self.assertEqual(rec['pending'], 1)

    async def test_exception_on_one_host_does_not_stop_the_rest(self):
        seen = []

        async def run(server, script, timeout):
            seen.append(server['uid'])
            if server['uid'] == 'node-a':
                raise OSError('ssh unreachable')
            return None

        with patch.object(self.app, '_rkn_ssh_run', side_effect=run):
            await self.app.icmp_echo_unblock_migration()

        self.assertEqual(seen, ['node-a', 'node-b'])
        self.assertEqual(self._record()['pending'], 1)

    async def test_no_servers_marks_done(self):
        self.data['servers'] = []
        with patch.object(self.app, '_rkn_ssh_run') as run:
            await self.app.icmp_echo_unblock_migration()
        run.assert_not_called()
        self.assertTrue(self._record().get('done_at'))


class StartupRegistrationTests(unittest.TestCase):
    def test_migration_is_started_at_startup(self):
        src = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn('asyncio.create_task(icmp_echo_unblock_migration())', src)
        self.assertIn("AWP_ICMP_ECHO_KEY = 'icmp_echo_unblock_v1'", src)


if __name__ == '__main__':
    unittest.main()
