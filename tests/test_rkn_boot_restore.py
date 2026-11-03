"""RKN boot-restore: repair command, API, one-shot migration, fallback, i18n.

Covers the regression from the 2026-10 installs: a unit without [Install] is
"static", so systemd never runs `boot` after a reboot and the live iptables
rules vanish while the lists stay intact.
"""
import ast
import asyncio
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi.responses import JSONResponse
from managers.ssh_manager import SSHManager

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'rknblock' / 'rkn-extra-block.sh'
INSTALL = ROOT / 'scripts' / 'rknblock' / 'install-rkn-extra.sh'
SERVICE = ROOT / 'scripts' / 'rknblock' / 'rkn-extra-block.service'
TIMER = ROOT / 'scripts' / 'rknblock' / 'rkn-extra-block.timer'


def status_out(boot='enabled', unit='ok', state='on'):
    return (
        f'rkn_extra_block: {state}\n'
        '  incoming: v4=1151 networks v6=21 networks\n'
        '  outgoing: v4=204 networks v6=3 networks\n'
        '  flags: block_in=on block_out=on log_in=on log_out=on\n'
        '  last_update: 2026-10-16T12:00:00Z\n'
        '  health: ok\n'
        f'  boot_restore: {boot}\n'
        f'  unit: {unit}\n'
        '===LOG===\n')


class ParserTests(unittest.TestCase):
    """The status parser must expose boot_restore/unit without breaking old output."""

    def setUp(self):
        path = ROOT / 'app.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        nodes = [n for n in tree.body
                 if isinstance(n, ast.FunctionDef) and n.name == '_parse_rkn_scan_output']
        namespace = {
            'json': json, 're': __import__('re'),
            'datetime': __import__('datetime').datetime,
            'timedelta': __import__('datetime').timedelta,
            'timezone': __import__('datetime').timezone,
        }
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
        self.parse = namespace['_parse_rkn_scan_output']

    def test_reads_boot_fields(self):
        parsed = self.parse(status_out('disabled', 'legacy'), True)
        self.assertEqual(parsed['boot_restore'], 'disabled')
        self.assertEqual(parsed['unit'], 'legacy')

    def test_old_status_without_fields_is_none(self):
        parsed = self.parse('rkn_extra_block: on\n  health: ok\n===LOG===\n', True)
        self.assertIsNone(parsed['boot_restore'])
        self.assertIsNone(parsed['unit'])


class RknAppCase(unittest.IsolatedAsyncioTestCase):
    """Import the real app, but keep every file/SSH side effect local."""

    async def asyncSetUp(self):
        import app
        self.app = app
        self.data = {
            'servers': [{'name': 'A', 'uid': 'node-a', 'host': '192.0.2.1',
                         'rknblock': {'installed': True, 'enabled': True}}],
            'users': [{'id': 'u', 'traffic_used': 1}],
            'user_connections': [{'id': 'l'}],
            'settings': {'appearance': {'title': 'x'}},
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(app, '_check_admin', return_value=True))
        self.stack.enter_context(patch.object(
            app, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(app, 'save_data', side_effect=self._save))
        self.stack.enter_context(patch.object(app, 'RKN_AUTO_REPAIR_DELAY', 0))
        self.stack.enter_context(patch.object(app, 'RKN_AUTO_REPAIR', True))
        self.request = SimpleNamespace(session={'user_id': 'admin'}, headers={})

    def _save(self, data):
        self.data = copy.deepcopy(data)


class RepairEndpointTests(RknAppCase):
    def _ssh(self, username='root', password=None):
        ssh = SSHManager('192.0.2.1', 22, username, password=password)
        ssh.connect = Mock()
        ssh.disconnect = Mock()
        ssh.upload_file = Mock()

        def run(command, timeout=60, **kwargs):
            if command.startswith('mktemp -d'):
                return ('/tmp/amnezia-private.fixture', '', 0)
            return ('', '', 0)

        ssh.run_command = Mock(side_effect=run)
        return ssh

    async def _run(self, server_id=0, uid=None):
        return await self.app.api_rknblock_repair(self.request, server_id, uid)

    async def test_admin_only(self):
        self.app._check_admin.return_value = False
        response = await self._run()
        self.assertEqual(response.status_code, 403)

    async def test_requires_installed_app(self):
        self.data['servers'][0]['rknblock'] = {}
        with patch.object(self.app, 'get_ssh') as get_ssh:
            response = await self._run()
        self.assertEqual(response.status_code, 409)
        get_ssh.assert_not_called()

    async def _assert_success(self, username, password=None):
        ssh = self._ssh(username, password)
        self.stack.enter_context(patch.object(self.app, 'get_ssh', return_value=ssh))
        self.stack.enter_context(patch.object(
            self.app, '_fetch_rkn_scan_output', return_value=status_out('enabled', 'ok')))
        result = await self._run()
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['boot_enabled'])
        self.assertFalse(result['repair_available'])
        self.assertEqual(self.data['servers'][0]['rknblock']['boot_restore'], 'enabled')
        self.assertIsNone(self.data['servers'][0]['rknblock']['last_repair_error'])
        self.assertTrue(self.data['servers'][0]['rknblock']['last_repair_at'])
        self.assertEqual(self.data['users'], [{'id': 'u', 'traffic_used': 1}])
        if username == 'root':
            payload = ssh.run_command.call_args.args[0]
        else:
            payload = ssh.upload_file.call_args.args[0]
            self.assertNotIn(password, payload)
        self.assertIn('backups-rkn-repair-', payload)
        self.assertIn('/usr/local/sbin/rkn-extra-block repair', payload)
        self.assertIn('systemctl enable rkn-extra-block.service', payload)
        self.assertIn('systemctl enable --now rkn-extra-block.timer', payload)
        self.assertIn('base64 -d', payload)
        return payload

    async def test_root_repair_payload(self):
        await self._assert_success('root')

    async def test_non_root_sudo_repair_payload(self):
        await self._assert_success('admin', 'synthetic-password')

    async def test_bundled_files_are_embedded_not_fetched(self):
        payload = await self._assert_success('root')
        self.assertNotIn('curl ', payload)
        for dest in ('/usr/local/sbin/rkn-extra-block',
                     '/etc/systemd/system/rkn-extra-block.service',
                     '/etc/systemd/system/rkn-extra-block.timer'):
            self.assertIn(dest + '.amnezia-tmp', payload)
        encoded = payload.split("printf '%s' '", 2)[1].split("'", 1)[0]
        import base64
        self.assertIn('cmd_repair()', base64.b64decode(encoded).decode('utf-8'))

    async def test_failure_records_error_and_keeps_record(self):
        ssh = self._ssh()
        ssh.run_command = Mock(return_value=('', 'systemctl: failed', 1))
        self.stack.enter_context(patch.object(self.app, 'get_ssh', return_value=ssh))
        response = await self._run()
        self.assertEqual(response.status_code, 500)
        rec = self.data['servers'][0]['rknblock']
        self.assertTrue(rec['installed'])
        self.assertIn('systemctl: failed', rec['last_repair_error'])
        self.assertTrue(rec['last_repair_at'])

    async def test_missing_bundled_files_is_a_clean_500(self):
        with patch.object(self.app, 'RKN_BLOCK_DIR', str(ROOT / 'does-not-exist')):
            response = await self._run()
        self.assertEqual(response.status_code, 500)
        self.assertIn('payload unavailable', json.loads(response.body)['error'])


class ScansBootFieldsTests(RknAppCase):
    async def _scans(self, out):
        with patch.object(self.app, '_fetch_rkn_scan_output', return_value=out):
            return await self.app.api_rkn_scans(self.request, 0, 'node-a')

    async def test_legacy_host_offers_repair(self):
        result = await self._scans(status_out('disabled', 'legacy'))
        self.assertFalse(result['boot_enabled'])
        self.assertTrue(result['repair_available'])

    async def test_fixed_host_hides_repair(self):
        result = await self._scans(status_out('enabled', 'ok'))
        self.assertTrue(result['boot_enabled'])
        self.assertFalse(result['repair_available'])

    async def test_old_script_offers_repair(self):
        result = await self._scans('rkn_extra_block: on\n  health: ok\n===LOG===\n')
        self.assertFalse(result['boot_enabled'])
        self.assertTrue(result['repair_available'])

    async def test_unreachable_host_does_not_offer_repair(self):
        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=OSError('down')):
            result = await self.app.api_rkn_scans(self.request, 0, 'node-a')
        self.assertFalse(result['available'])
        self.assertFalse(result['repair_available'])


class MigrationTests(RknAppCase):
    async def test_skips_already_fixed_hosts(self):
        calls = []

        async def fetch(server):
            return status_out('enabled', 'ok')
        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=fetch), \
                patch.object(self.app, '_rkn_ssh_run', side_effect=lambda *a, **k: calls.append(a)):
            await self.app.rkn_boot_restore_migration()
        self.assertEqual(calls, [])
        rec = self.data['panel_migrations'][self.app.RKN_MIGRATION_KEY]
        self.assertTrue(rec['done_at'])
        self.assertEqual(rec['pending'], 0)

    async def test_repairs_legacy_host_and_marks_done(self):
        probes = {'node-a': 0}
        calls = []

        async def fetch(server):
            probes[server['uid']] += 1
            if probes[server['uid']] == 1:
                return status_out('disabled', 'legacy')
            return status_out('enabled', 'ok')

        async def repair(server, script, timeout):
            calls.append((server['uid'], timeout))
            return None

        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=fetch), \
                patch.object(self.app, '_rkn_ssh_run', side_effect=repair):
            await self.app.rkn_boot_restore_migration()
        self.assertEqual(len(calls), 1)
        rec = self.data['servers'][0]['rknblock']
        self.assertEqual(rec['boot_restore'], 'enabled')
        self.assertIsNone(rec['last_repair_error'])
        self.assertTrue(self.data['panel_migrations'][self.app.RKN_MIGRATION_KEY]['done_at'])

    async def test_all_hosts_fixed_but_done_at_prevents_second_run(self):
        self.data['panel_migrations'] = {self.app.RKN_MIGRATION_KEY: {'done_at': 'yes'}}
        with patch.object(self.app, '_fetch_rkn_scan_output') as fetch:
            await self.app.rkn_boot_restore_migration()
        fetch.assert_not_called()

    async def test_disabled_by_env(self):
        with patch.object(self.app, 'RKN_AUTO_REPAIR', False), \
                patch.object(self.app, '_fetch_rkn_scan_output') as fetch:
            await self.app.rkn_boot_restore_migration()
        fetch.assert_not_called()

    async def test_one_broken_host_is_isolated_and_data_survives(self):
        self.data['servers'] = [
            {'name': 'fixed', 'uid': 'fixed', 'host': 'h1',
             'rknblock': {'installed': True}},
            {'name': 'old', 'uid': 'old', 'host': 'h2',
             'rknblock': {'installed': True}},
            {'name': 'dead', 'uid': 'dead', 'host': 'h3',
             'rknblock': {'installed': True}},
        ]
        probes = {'old': 0}

        async def fetch(server):
            uid = server['uid']
            if uid == 'fixed':
                return status_out('enabled', 'ok')
            if uid == 'dead':
                raise OSError('ssh unreachable')
            probes[uid] += 1
            if probes[uid] == 1:
                return status_out('disabled', 'legacy')
            return status_out('enabled', 'ok')

        repaired = []

        async def repair(server, script, timeout):
            repaired.append(server['uid'])
            return None

        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=fetch), \
                patch.object(self.app, '_rkn_ssh_run', side_effect=repair):
            await self.app.rkn_boot_restore_migration()

        self.assertEqual(repaired, ['old'])
        by_uid = {s['uid']: s['rknblock'] for s in self.data['servers']}
        self.assertEqual(by_uid['fixed']['boot_restore'], 'enabled')
        self.assertEqual(by_uid['old']['boot_restore'], 'enabled')
        self.assertIn('ssh unreachable', by_uid['dead']['last_repair_error'])
        migration = self.data['panel_migrations'][self.app.RKN_MIGRATION_KEY]
        self.assertNotIn('done_at', migration)  # retry on the next panel restart
        self.assertEqual(migration['pending'], 1)
        self.assertEqual(self.data['users'], [{'id': 'u', 'traffic_used': 1}])
        self.assertEqual(self.data['user_connections'], [{'id': 'l'}])
        self.assertEqual(self.data['settings'], {'appearance': {'title': 'x'}})

    async def test_repair_failure_keeps_other_results(self):
        async def fetch(server):
            return status_out('disabled', 'legacy')

        async def repair(server, script, timeout):
            return JSONResponse({'error': 'sudo denied'}, status_code=500)

        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=fetch), \
                patch.object(self.app, '_rkn_ssh_run', side_effect=repair):
            await self.app.rkn_boot_restore_migration()
        rec = self.data['servers'][0]['rknblock']
        self.assertIn('sudo denied', rec['last_repair_error'])
        self.assertEqual(self.data['panel_migrations'][self.app.RKN_MIGRATION_KEY]['pending'], 1)


class StaticContractTests(unittest.TestCase):
    def test_repair_is_idempotent_and_enables_both_units(self):
        src = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('cmd_repair()', src)
        self.assertIn('repair|ensure-boot) lock; cmd_repair', src)
        self.assertIn('systemctl daemon-reload', src)
        self.assertIn('systemctl enable --now rkn-extra-block.timer', src)
        self.assertIn('systemctl enable rkn-extra-block.service', src)
        self.assertIn('boot_restore:', src)
        self.assertIn('unit: ok', src)
        self.assertIn('unit: legacy', src)
        self.assertIn('*incompatible*)', src)

    def test_units_are_present_with_install(self):
        for path in (SERVICE, TIMER):
            text = path.read_text(encoding='utf-8')
            self.assertIn('[Install]', text, path)

    def test_installer_checks_is_enabled(self):
        src = INSTALL.read_text(encoding='utf-8')
        self.assertIn('systemctl is-enabled rkn-extra-block.service', src)
        self.assertIn('if [ "$ENABLED_STATE" != "enabled" ]', src)

    def test_installer_and_repair_units_match_embedded_copies(self):
        src = SCRIPT.read_text(encoding='utf-8')
        for path in (SERVICE, TIMER):
            body = path.read_text(encoding='utf-8').strip()
            self.assertIn(body, src, f'{path.name} drifted from cmd_repair heredoc')


BASH = shutil.which('bash') or next(
    (str(p) for p in (Path(r'C:\Program Files\Git\bin\bash.exe'),
                      Path(r'C:\Program Files\Git\usr\bin\bash.exe')) if p.exists()), None)


@unittest.skipUnless(BASH, 'requires POSIX bash')
class ShellBehaviorTests(unittest.TestCase):
    def _sandbox(self):
        tmp = Path(tempfile.mkdtemp(prefix='rkn-repair-'))
        self.addCleanup(shutil.rmtree, tmp, True)
        bindir = tmp / 'bin'
        bindir.mkdir()
        return tmp, bindir

    def _exe(self, path, body):
        path.write_text('#!/usr/bin/env bash\n' + textwrap.dedent(body), encoding='utf-8')
        path.chmod(0o755)

    def _run(self, driver, tmp):
        proc = subprocess.run([BASH, str(driver)], capture_output=True, text=True,
                              timeout=60, env=dict(os.environ, SANDBOX=str(tmp)))
        return proc

    def test_repair_is_idempotent(self):
        tmp, bindir = self._sandbox()
        calls = tmp / 'systemctl.log'
        self._exe(bindir / 'id', """
            if [ "$1" = "-u" ]; then echo 0; exit 0; fi
            exec /usr/bin/id "$@"
        """)
        self._exe(bindir / 'systemctl', """
            echo "$*" >> "$SANDBOX/systemctl.log"
            if [ "$1" = "is-enabled" ]; then echo enabled; fi
            exit 0
        """)
        for name in ('iptables', 'ip6tables'):
            self._exe(bindir / name, '[ "$1" = "-C" ] && exit 1; exit 0\n')
        self._exe(bindir / 'ipset', 'exit 1\n')
        self._exe(bindir / 'nft', 'exit 0\n')
        driver = tmp / 'driver.sh'
        driver.write_text(textwrap.dedent(f"""\
            set -u
            export PATH="{bindir}:$PATH"
            source "{SCRIPT}" status >/dev/null 2>&1
            export CONF_DIR="$SANDBOX/conf"; mkdir -p "$CONF_DIR"
            export STATE_FILE="$CONF_DIR/state"
            export LOG_FILE="$SANDBOX/rkn.log"
            export UNIT_SERVICE="$SANDBOX/rkn.service"
            export UNIT_TIMER="$SANDBOX/rkn.timer"
            cmd_repair >"$SANDBOX/out1" 2>&1; echo "rc1=$?"
            cmd_repair >"$SANDBOX/out2" 2>&1; echo "rc2=$?"
        """), encoding='utf-8')
        proc = self._run(driver, tmp)
        self.assertEqual(proc.stdout.strip().splitlines()[-2:], ['rc1=0', 'rc2=0'], proc.stderr)
        log = calls.read_text(encoding='utf-8')
        self.assertEqual(log.count('daemon-reload'), 2)
        self.assertEqual(log.count('enable --now rkn-extra-block.timer'), 2)
        self.assertEqual(log.count('enable rkn-extra-block.service'), 2)
        for name in ('rkn.service', 'rkn.timer'):
            text = (tmp / name).read_text(encoding='utf-8')
            self.assertEqual(text.count('[Install]'), 1)
        self.assertIn('boot_restore: enabled', (tmp / 'out2').read_text(encoding='utf-8'))

    def test_incompatible_chain_is_recreated_via_nft(self):
        tmp, bindir = self._sandbox()
        self._exe(bindir / 'id', 'echo 0; exit 0\n')
        self._exe(bindir / 'systemctl', 'exit 0\n')
        self._exe(bindir / 'ipset', 'exit 1\n')
        self._exe(bindir / 'nft', """
            echo "$*" >> "$SANDBOX/nft.log"
            touch "$SANDBOX/recreated"
            exit 0
        """)
        self._exe(bindir / 'iptables', """
            echo "$*" >> "$SANDBOX/iptables.log"
            if [ "$1" = "-F" ] && [ ! -f "$SANDBOX/recreated" ]; then
                echo "iptables: incompatible with this kernel" >&2
                exit 1
            fi
            exit 0
        """)
        self._exe(bindir / 'ip6tables', 'exit 0\n')
        driver = tmp / 'driver.sh'
        driver.write_text(textwrap.dedent(f"""\
            set -u
            export PATH="{bindir}:$PATH"
            source "{SCRIPT}" status >/dev/null 2>&1
            export LOG_FILE="$SANDBOX/rkn.log"
            chain_ready iptables ip RKN_EXTRA_IN; echo "rc=$?"
        """), encoding='utf-8')
        proc = self._run(driver, tmp)
        self.assertIn('rc=0', proc.stdout, proc.stderr)
        self.assertIn('delete chain ip filter RKN_EXTRA_IN',
                      (tmp / 'nft.log').read_text(encoding='utf-8'))
        self.assertEqual((tmp / 'iptables.log').read_text(encoding='utf-8').lower().count('-f rkn_extra_in'), 2)

    def test_unexpected_flush_error_is_fatal(self):
        tmp, bindir = self._sandbox()
        self._exe(bindir / 'id', 'echo 0; exit 0\n')
        self._exe(bindir / 'systemctl', 'exit 0\n')
        self._exe(bindir / 'ipset', 'exit 1\n')
        self._exe(bindir / 'nft', 'exit 1\n')
        self._exe(bindir / 'iptables', 'echo "boom" >&2; exit 1\n')
        self._exe(bindir / 'ip6tables', 'exit 0\n')
        driver = tmp / 'driver.sh'
        driver.write_text(textwrap.dedent(f"""\
            set -u
            export PATH="{bindir}:$PATH"
            source "{SCRIPT}" status >/dev/null 2>&1
            export LOG_FILE="$SANDBOX/rkn.log"
            chain_ready iptables ip RKN_EXTRA_IN; echo "rc=$?"
        """), encoding='utf-8')
        proc = self._run(driver, tmp)
        self.assertIn('rc=1', proc.stdout, proc.stderr)
        self.assertIn('CHAIN-FAIL', (tmp / 'rkn.log').read_text(encoding='utf-8'))


class I18nParityTests(unittest.TestCase):
    NEW_KEYS = ('rknblock_boot_warning', 'rknblock_boot_warning_short',
                'rknblock_repair_boot', 'rknblock_repairing',
                'rknblock_boot_repaired', 'rknblock_boot_repair_failed')

    def test_all_locales_have_same_keys_and_new_boot_keys(self):
        tables = {}
        for lang in ('en', 'ru', 'fr', 'zh', 'fa'):
            tables[lang] = json.loads((ROOT / 'translations' / f'{lang}.json')
                                      .read_text(encoding='utf-8'))
        base = set(tables['en'])
        for lang, table in tables.items():
            self.assertEqual(set(table), base, lang)
            for key in self.NEW_KEYS:
                self.assertIn(key, table, lang)
                self.assertTrue(table[key].strip(), (lang, key))


if __name__ == '__main__':
    unittest.main()
