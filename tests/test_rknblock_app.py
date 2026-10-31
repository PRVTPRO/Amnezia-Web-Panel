"""RKN Block marketplace app endpoints: install/uninstall/enable/update, no SSH.

The endpoints are AST-isolated out of app.py (same harness as
test_rkn_scan_flags.py) and driven with a canned SSH double.
"""
import ast
import asyncio
import copy
import json
import os
import shlex
import shutil
import subprocess
import threading
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi.responses import JSONResponse
from managers.ssh_manager import SSHManager

FUNCTIONS = {'_rkn_ssh_run', '_rkn_run_cmd', '_rkn_record',
             '_rkn_server_index', '_rkn_store_record', '_rkn_drop_record',
             'api_rknblock_install', 'api_rknblock_uninstall',
             'api_rknblock_enable', 'api_rknblock_update'}


class BaseModelStub:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)


def isolated_panel():
    path = Path(__file__).resolve().parents[1] / 'app.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    nodes = [node for node in tree.body
             if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in FUNCTIONS)
             or (isinstance(node, ast.ClassDef) and node.name == 'RknBlockEnableRequest')]
    assert {node.name for node in nodes} == FUNCTIONS | {'RknBlockEnableRequest'}
    for node in nodes:
        node.decorator_list = []
    namespace = {
        'Request': object, 'JSONResponse': JSONResponse, 'logger': Mock(),
        'get_ssh': Mock(), 'load_data': Mock(), 'save_data': Mock(),
        '_check_admin': Mock(return_value=True),
        'RKN_FLAG_CACHE': {}, 'RKN_INSTALL_CMD': 'install-cmd',
        'RKN_SCRIPT_URL': 'https://example.test/rkn.sh',
        'BaseModel': BaseModelStub,
        'asyncio': __import__('asyncio'),
        'DATA_LOCK': __import__('asyncio').Lock(),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


class SshCase(unittest.TestCase):
    def setUp(self):
        self.panel = isolated_panel()
        self.request = SimpleNamespace(session={'user_id': 'admin'}, headers={})
        self.ran = []
        self.fail_next = False
        ssh = SimpleNamespace(
            connect=lambda: None,
            disconnect=lambda: None,
            run_sudo_script=self._run_sudo)
        self.panel['get_ssh'] = Mock(return_value=ssh)
        self.server = {'name': 'A', 'uid': 'node-a', 'host': '192.0.2.1', 'protocols': {}}
        self.panel['load_data'] = Mock(return_value={'servers': [self.server],
                                                     'users': [], 'user_connections': []})
        self.panel['RKN_FLAG_CACHE'][0] = {'ts': 1, 'data': {'events24': 5}}

    def _run_sudo(self, cmd, timeout=60):
        self.ran.append((cmd, timeout))
        if self.fail_next:
            return ('', 'boom', 1)
        return ('ok', '', 0)

    def enable_req(self, enabled):
        req = self.panel['RknBlockEnableRequest']()
        req.enabled = enabled
        return req


class RunCmdTests(SshCase):
    def test_run_cmd_fetches_fresh_script_to_tmp(self):
        cmd = self.panel['_rkn_run_cmd']('uninstall')
        self.assertIn('curl -fsSL https://example.test/rkn.sh', cmd)
        self.assertIn('mktemp -d /tmp/amnezia-rkn.', cmd)
        self.assertIn('bash "$tmp_dir/rkn-extra-block-run.sh" uninstall', cmd)
        self.assertIn('trap \'rm -rf -- "$tmp_dir"\' EXIT', cmd)


class SudoExecutionTests(SshCase):
    def test_compound_payload_uses_the_existing_script_helper(self):
        payload = 'first && second; third'
        for username, password in [('root', None), ('admin', None), ('admin', 'synthetic-secret')]:
            with self.subTest(username=username, password_sudo=bool(password)):
                ssh = SSHManager('example.test', 22, username, password=password)
                ssh.connect = Mock()
                ssh.disconnect = Mock()
                ssh.upload_file = Mock()
                ssh.run_command = Mock(return_value=('/tmp/amnezia-private.fixture', '', 0))
                self.panel['get_ssh'].return_value = ssh
                self.assertIsNone(asyncio.run(self.panel['_rkn_ssh_run'](self.server, payload, 42)))
                if username == 'root':
                    ssh.run_command.assert_called_once_with(payload, timeout=42)
                    ssh.upload_file.assert_not_called()
                else:
                    ssh.upload_file.assert_called_once_with(payload, '/tmp/amnezia-private.fixture/script.sh')
                    call = ssh.run_command.call_args_list[1]
                    argv = shlex.split(call.args[0])
                    self.assertEqual(argv[-2:], ['bash', '/tmp/amnezia-private.fixture/script.sh'])
                    self.assertEqual(argv[0], 'sudo')
                    self.assertEqual(call.kwargs['timeout'], 42)
                    self.assertEqual(call.kwargs.get('stdin_input'), password + '\n' if password else None)
                    self.assertNotIn('synthetic-secret', call.args[0])
                    self.assertEqual(ssh.run_command.call_args_list[-1].args[0], 'rm -rf -- /tmp/amnezia-private.fixture')
                ssh.disconnect.assert_called_once()

    def test_sudo_failure_and_timeout_are_not_success(self):
        ssh = Mock()
        self.panel['get_ssh'].return_value = ssh
        for result in [('', 'sudo denied', 1), ('', 'SSH timed out', -1), ('failure on stdout', '', 7)]:
            with self.subTest(code=result[2]):
                ssh.run_sudo_script.return_value = result
                response = asyncio.run(self.panel['_rkn_ssh_run'](self.server, 'first && second', 42))
                self.assertEqual(response.status_code, 500)
                self.assertIn(result[1] or result[0], json.loads(response.body)['error'])
        self.assertEqual(ssh.disconnect.call_count, 3)

    def test_script_exception_always_disconnects(self):
        ssh = Mock()
        ssh.run_sudo_script.side_effect = TimeoutError('synthetic timeout')
        self.panel['get_ssh'].return_value = ssh
        with self.assertRaises(TimeoutError):
            asyncio.run(self.panel['_rkn_ssh_run'](self.server, 'first && second', 42))
        ssh.disconnect.assert_called_once()

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'requires POSIX bash')
    def test_real_shell_chain_with_synthetic_non_root_sudo(self):
        # No real sudo, SSH, installer or network: the shell function emulates
        # a privilege boundary only in its child process, like actual sudo.
        class ShellSSH(SSHManager):
            def run_command(self, command, timeout=60, **kwargs):
                bootstrap = '''sudo() {
                    while [ "$#" -gt 0 ]; do
                        case "$1" in -S) shift;; -p) shift 2;; *) break;; esac
                    done
                    (export RKN_TEST_ROOT=1; "$@")
                };
                curl() {
                    [ "$RKN_TEST_ROOT" = 1 ] || return 71
                    printf '%s\\n' '[ "$RKN_TEST_ROOT" = 1 ] || exit 72' 'printf script-root' > "${@: -1}"
                };
                install() { [ "$RKN_TEST_ROOT" = 1 ]; };
                export -f curl install; '''
                env = dict(os.environ, RKN_TEST_ROOT='1' if self._is_root else '0')
                p = subprocess.run(['bash', '-c', bootstrap + command], env=env,
                                   capture_output=True, text=True, timeout=timeout)
                return p.stdout.strip(), p.stderr.strip(), p.returncode

            def upload_file(self, content, path):
                Path(path).write_text(content, encoding='utf-8')

        payload = '[ "$RKN_TEST_ROOT" = 1 ] && printf first; [ "$RKN_TEST_ROOT" = 1 ] && printf second'
        for username, password in [('root', None), ('admin', None), ('admin', 'synthetic-secret')]:
            with self.subTest(username=username, password_sudo=bool(password)):
                ssh = ShellSSH('example.test', 22, username, password=password)
                ssh.connect = Mock()
                ssh.disconnect = Mock()
                self.panel['get_ssh'].return_value = ssh
                if username != 'root':
                    self.assertNotEqual(ssh.run_sudo_command(payload)[2], 0)
                self.assertIsNone(asyncio.run(self.panel['_rkn_ssh_run'](self.server, payload, 5)))
                # Execute the actual command builders with inert download and
                # install doubles: no remote script or system path is touched.
                tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
                constants = [n for n in tree.body if isinstance(n, ast.Assign)
                             and any(isinstance(t, ast.Name) and t.id in ('RKN_RAW_BASE', 'RKN_INSTALL_CMD') for t in n.targets)]
                namespace = {}
                exec(compile(ast.Module(body=constants, type_ignores=[]), '<rkn-constants>', 'exec'), namespace)
                scripts = [namespace['RKN_INSTALL_CMD']] + [self.panel['_rkn_run_cmd'](sub)
                    for sub in ('uninstall', 'on', 'off', 'update', 'set block_in=on block_out=off log_in=on log_out=off')]
                for script in scripts:
                    self.assertEqual(ssh.run_sudo_script(script, timeout=5), ('script-root', '', 0))


class InstallTests(SshCase):
    def call(self):
        return self.panel['asyncio'].run(
            self.panel['api_rknblock_install'](self.request, 0))

    def test_install_marks_record_and_clears_cache(self):
        result = self.call()
        self.assertEqual(result, {'status': 'success', 'installed': True, 'enabled': True})
        self.assertEqual(self.server['rknblock'],
                         {'installed': True, 'enabled': True, 'last_error': None})
        self.assertEqual(self.ran[0][1], 420)  # install timeout
        self.assertNotIn(0, self.panel['RKN_FLAG_CACHE'])

    def test_install_failure_returns_500_and_no_record(self):
        self.fail_next = True
        resp = self.call()
        self.assertIsInstance(resp, JSONResponse)
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn('rknblock', self.server)

    def test_install_updates_reloaded_server_by_uid(self):
        # A long SSH call may be followed by a fresh data.json snapshot and a
        # reorder. The record must land on the same uid, not a stale object.
        self.server['uid'] = 'u1'
        initial = {'servers': [self.server], 'users': [], 'user_connections': []}
        fresh = {'servers': [{'name': 'B', 'uid': 'u2'},
                             dict(self.server)],
                 'users': [], 'user_connections': []}
        self.panel['load_data'] = Mock(return_value=initial)
        original_run = self.panel['get_ssh'].return_value.run_sudo_script
        def run(*args):
            self.panel['load_data'].return_value = fresh
            return original_run(*args)
        self.panel['get_ssh'].return_value.run_sudo_script = run
        result = self.call()
        self.assertEqual(result, {'status': 'success', 'installed': True, 'enabled': True})
        self.assertNotIn('rknblock', self.server)
        self.assertEqual(fresh['servers'][1]['rknblock'],
                         {'installed': True, 'enabled': True, 'last_error': None})

    def test_forbidden(self):
        self.panel['_check_admin'] = Mock(return_value=False)
        resp = self.call()
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self.ran, [])

    def test_missing_uid_never_falls_back_to_reused_index(self):
        self.server['uid'] = 'removed'
        fresh = {'servers': [{'uid': 'other', 'rknblock': {'installed': False}}]}
        self.panel['get_ssh'].return_value.connect = lambda: setattr(self.panel['load_data'], 'return_value', fresh)
        response = self.call()
        self.assertEqual(fresh['servers'][0]['rknblock'], {'installed': False})
        self.assertEqual(response.status_code, 409)
        self.panel['save_data'].assert_not_called()

    def test_legacy_missing_uid_and_explicit_empty_uid_never_start_ssh(self):
        for value in ('', 'missing'):
            response = self.panel['asyncio'].run(self.panel['api_rknblock_install'](self.request, 0, value))
            self.assertEqual(response.status_code, 404)
        self.server.pop('uid')
        self.assertEqual(self.call().status_code, 404)
        self.panel['get_ssh'].assert_not_called()
        self.panel['save_data'].assert_not_called()

    def test_duplicate_uid_is_ambiguous_even_for_legacy_index_request(self):
        self.panel['load_data'].return_value['servers'].append(dict(self.server, name='B'))
        self.assertEqual(self.call().status_code, 404)
        self.panel['get_ssh'].assert_not_called()

    def test_endpoint_changed_during_connect_does_not_run_remote_command(self):
        self.panel['get_ssh'].return_value.connect = lambda: self.server.update(host='192.0.2.2')
        self.assertEqual(self.call().status_code, 409)
        self.assertEqual(self.ran, [])
        self.panel['save_data'].assert_not_called()

    def test_deleted_during_command_cannot_commit_to_reused_index(self):
        def run(*args):
            self.panel['load_data'].return_value = {'servers': [{'uid': 'replacement', 'rknblock': {'installed': False}}]}
            return ('ok', '', 0)
        self.panel['get_ssh'].return_value.run_sudo_script = run
        self.assertEqual(self.call().status_code, 409)
        self.assertFalse(self.panel['load_data'].return_value['servers'][0]['rknblock']['installed'])
        self.panel['save_data'].assert_not_called()

    def test_connection_failure_always_disconnects(self):
        ssh = self.panel['get_ssh'].return_value
        ssh.disconnect = Mock()
        ssh.connect = Mock(side_effect=OSError('synthetic failure'))
        with self.assertRaises(OSError):
            self.call()
        ssh.disconnect.assert_called_once()

    def test_request_uid_is_checked_before_ssh(self):
        self.server['uid'] = 'other'
        response = self.panel['asyncio'].run(self.panel['api_rknblock_install'](self.request, 0, 'missing'))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.ran, [])


class UninstallTests(SshCase):
    def call(self):
        return self.panel['asyncio'].run(
            self.panel['api_rknblock_uninstall'](self.request, 0))

    def test_uninstall_removes_record_and_clears_cache(self):
        self.server['rknblock'] = {'installed': True, 'enabled': False}
        result = self.call()
        self.assertEqual(result, {'status': 'success', 'installed': False})
        self.assertNotIn('rknblock', self.server)
        self.assertIn('uninstall', self.ran[0][0])
        self.assertNotIn(0, self.panel['RKN_FLAG_CACHE'])

    def test_uninstall_failure_keeps_record(self):
        self.server['rknblock'] = {'installed': True, 'enabled': True}
        self.fail_next = True
        resp = self.call()
        self.assertEqual(resp.status_code, 500)
        self.assertIn('rknblock', self.server)


class EnableTests(SshCase):
    def call(self, enabled):
        return self.panel['asyncio'].run(
            self.panel['api_rknblock_enable'](self.request, 0, self.enable_req(enabled)))

    def test_enable_requires_installed(self):
        resp = self.call(True)
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self.ran, [])

    def test_disable_runs_off_and_flips_record(self):
        self.server['rknblock'] = {'installed': True, 'enabled': True}
        result = self.call(False)
        self.assertEqual(result, {'status': 'success', 'enabled': False})
        self.assertEqual(self.server['rknblock'],
                         {'installed': True, 'enabled': False, 'last_error': None})
        self.assertIn(' off;', self.ran[0][0].split('rkn-extra-block-run.sh', 1)[1])

    def test_enable_runs_on(self):
        self.server['rknblock'] = {'installed': True, 'enabled': False}
        result = self.call(True)
        self.assertEqual(result, {'status': 'success', 'enabled': True})
        self.assertIn(' on;', self.ran[0][0].split('rkn-extra-block-run.sh', 1)[1])

    def test_enable_failure_keeps_previous_record(self):
        self.server['rknblock'] = {'installed': True, 'enabled': True}
        self.fail_next = True
        resp = self.call(False)
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self.server['rknblock'], {'installed': True, 'enabled': True})


class UpdateTests(SshCase):
    def call(self):
        return self.panel['asyncio'].run(
            self.panel['api_rknblock_update'](self.request, 0))

    def test_update_requires_installed(self):
        resp = self.call()
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self.ran, [])

    def test_update_runs_update_subcommand(self):
        self.server['rknblock'] = {'installed': True, 'enabled': True}
        result = self.call()
        self.assertEqual(result, {'status': 'success', 'updated': True})
        self.assertIn(' update;', self.ran[0][0])
        self.assertEqual(self.ran[0][1], 300)


class ScansResponseTests(unittest.TestCase):
    """api_rkn_scans exposes installed/enabled plus live running/healthy flags."""

    def _run(self, parsed, record, unavailable=False):
        path = Path(__file__).resolve().parents[1] / 'app.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        nodes = [n for n in tree.body
                 if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef)) and n.name in ('api_rkn_scans', '_rkn_server_index')]
        assert len(nodes) == 2
        for node in nodes:
            node.decorator_list = []
        namespace = {
            'Request': object, 'JSONResponse': JSONResponse, 'logger': Mock(),
            'load_data': Mock(), '_check_admin': Mock(return_value=True),
            '_parse_rkn_scan_output': lambda out, flag: dict(parsed),
            'asyncio': __import__('asyncio'),
        }

        async def fake_fetch(server):
            if unavailable:
                raise OSError('synthetic SSH outage')
            return '===LOG==='  # Complete probe envelope, even for an empty scan log.

        namespace['_fetch_rkn_scan_output'] = fake_fetch
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
        server = {'name': 'A', 'uid': 'node-a', 'rknblock': record}
        namespace['load_data'] = Mock(return_value={'servers': [server]})
        request = SimpleNamespace(session={'user_id': 'admin'}, headers={})
        return namespace['asyncio'].run(
            namespace['api_rkn_scans'](request, 0))

    def test_isolated_scans_endpoint_shape(self):
        result = self._run(
            {'flag_enabled': True, 'agent_state': 'unknown', 'sets_ok': False,
             'health': None, 'problems': ['not_running', 'lists_empty'],
             'sets': {'in4': 0, 'in6': 0, 'out4': 0, 'out6': 0}},
            {'installed': True, 'enabled': False})
        self.assertTrue(result['installed'])
        self.assertFalse(result['enabled'])
        self.assertTrue(result['flag_enabled'])
        self.assertFalse(result['running'])
        self.assertFalse(result['healthy'])

    def test_live_running_and_healthy_flags(self):
        result = self._run(
            {'flag_enabled': True, 'agent_state': 'on', 'sets_ok': True,
             'health': 'ok', 'problems': [],
             'sets': {'in4': 1151, 'in6': 21, 'out4': 204, 'out6': 3}},
            {'installed': True, 'enabled': True})
        self.assertTrue(result['running'])
        self.assertTrue(result['healthy'])

    def test_empty_sets_make_running_unhealthy(self):
        result = self._run(
            {'flag_enabled': True, 'agent_state': 'on', 'sets_ok': False,
             'health': 'failed', 'problems': ['lists_empty', 'health_failed'],
             'sets': {'in4': 0, 'in6': 0, 'out4': 0, 'out6': 0}},
            {'installed': True, 'enabled': True})
        self.assertTrue(result['running'])
        self.assertFalse(result['healthy'])
        self.assertIn('lists_empty', result['problems'])
        self.assertIn('health_failed', result['problems'])

    def test_ssh_outage_preserves_installed_record(self):
        result = self._run({'agent_state': 'unknown'}, {'installed': True, 'enabled': True}, unavailable=True)
        self.assertTrue(result['installed'])
        self.assertFalse(result['available'])
        self.assertFalse(result['running'])

    def test_live_installation_is_not_offered_for_install_again(self):
        result = self._run({'agent_state': 'on', 'sets_ok': True, 'health': 'ok'}, {})
        self.assertTrue(result['installed'])


class RknRequestRaces(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import app
        self.app = app
        self.data = {'servers': [{'uid': 'fixture-node', 'host': '192.0.2.1'}],
                     'users': [{'id': 'u', 'traffic_used': 450, 'traffic_total': 700}],
                     'user_connections': [{'id': 'link', 'last_bytes': 60}]}
        self.before = copy.deepcopy(self.data)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(app, '_check_admin', return_value=True))
        self.stack.enter_context(patch.object(app, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(app, 'save_data', side_effect=self.save))
        self.ssh = Mock()
        self.ssh.run_sudo_script.return_value = ('ok', '', 0)
        self.stack.enter_context(patch.object(app, 'get_ssh', return_value=self.ssh))
        self.request = SimpleNamespace()

    def save(self, data):
        self.data = copy.deepcopy(data)

    def accounting_preserved(self):
        for key in ('users', 'user_connections'):
            self.assertEqual(self.data[key], self.before[key])

    async def test_options_emit_only_validated_fixed_flags_via_script(self):
        self.data['servers'][0]['rknblock'] = {'installed': True}
        req = self.app.RknBlockOptionsRequest(block_in=False, log_out=False)
        result = await self.app.api_rknblock_options(self.request, 0, req, 'fixture-node')
        self.assertEqual(result['status'], 'success')
        script, timeout = self.ssh.run_sudo_script.call_args.args
        self.assertIn('set block_in=off block_out=on log_in=on log_out=off;', script)
        self.assertEqual(timeout, 120)
        with self.assertRaises(ValueError):
            self.app.RknBlockOptionsRequest(block_in='on; id')
        self.accounting_preserved()

    async def test_cancelled_install_retains_interlock_and_duplicate_never_runs(self):
        entered, release = threading.Event(), threading.Event()
        def run(*args):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('synthetic barrier')
            return ('ok', '', 0)
        self.ssh.run_sudo_script.side_effect = run
        first = asyncio.create_task(self.app.api_rknblock_install(self.request, 0, 'fixture-node'))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            second = asyncio.create_task(self.app.api_rknblock_install(self.request, 0, 'fixture-node'))
        finally:
            release.set()
        self.assertEqual((await second).status_code, 409)
        self.ssh.run_sudo_script.assert_called_once()
        self.ssh.disconnect.assert_called_once()
        self.assertTrue(self.data['servers'][0]['rknblock']['installed'])
        self.accounting_preserved()

    async def test_status_started_before_install_preserves_new_record_then_recovers(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def probe(server):
            entered.set()
            await release.wait()
            return '===LOG==='  # Old response from before installation.
        with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=probe):
            status = asyncio.create_task(self.app.api_rkn_scans(self.request, 0, 'fixture-node'))
            await entered.wait()
            self.assertEqual((await self.app.api_rknblock_install(self.request, 0, 'fixture-node'))['status'], 'success')
            release.set()
            result = await status
        self.assertTrue(result['installed'])
        self.assertFalse(result['available'])
        for output in (OSError('synthetic outage'), 'rkn_extra_block: on\n===LOG==='):
            with patch.object(self.app, '_fetch_rkn_scan_output', side_effect=output if isinstance(output, Exception) else None,
                              return_value=output):
                result = await self.app.api_rkn_scans(self.request, 0, 'fixture-node')
            self.assertTrue(result['installed'])
            self.assertEqual(result['available'], isinstance(output, str))
        self.accounting_preserved()


if __name__ == '__main__':
    unittest.main()
