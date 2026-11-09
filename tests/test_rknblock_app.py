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
import tempfile
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
             'api_rknblock_uninstall',
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

    def test_dpkg_failure_returns_actionable_hint_and_full_detail(self):
        ssh = Mock()
        self.panel['get_ssh'].return_value = ssh
        detail = ('No apport report written because the error message indicates '
                  'its a followup error from a previous failure.\n'
                  + 'x' * 700 + '\nE: Sub-process /usr/bin/dpkg returned an error code (1)')
        ssh.run_sudo_script.return_value = ('', detail, 100)
        response = asyncio.run(self.panel['_rkn_ssh_run'](self.server, 'install', 420))
        self.assertEqual(response.status_code, 500)
        error = json.loads(response.body)['error']
        self.assertIn('dpkg returned an error code', error)
        self.assertIn("dpkg --configure -a", error)
        # The panel used to cut the detail to 500 chars, hiding the real cause.
        self.assertIn('x' * 700, error)

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
                             and any(isinstance(t, ast.Name) and t.id == 'RKN_RAW_BASE' for t in n.targets)]
                namespace = {}
                exec(compile(ast.Module(body=constants, type_ignores=[]), '<rkn-constants>', 'exec'), namespace)
                scripts = [self.panel['_rkn_run_cmd'](sub)
                    for sub in ('uninstall', 'on', 'off', 'update', 'set block_in=on block_out=off log_in=on log_out=off')]
                for script in scripts:
                    self.assertEqual(ssh.run_sudo_script(script, timeout=5), ('script-root', '', 0))
                # The install payload is the bundled phased installer, embedded
                # as base64: it must never be executed locally by this test.
                import app as panel_app
                install_cmd = panel_app._rkn_install_script('preflight')
                self.assertIn("bash \"$tmp_dir/install-rkn-extra.sh\" preflight", install_cmd)
                self.assertIn("printf '%s' '", install_cmd)
                self.assertEqual(panel_app.RKN_INSTALL_CMD,
                                 str(Path(__file__).resolve().parents[1] / 'scripts' / 'rknblock' / 'install-rkn-extra.sh'))


class InstallOperationTests(unittest.IsolatedAsyncioTestCase):
    """POST /rknblock/install starts a phased background operation.

    The endpoint returns an operation_id immediately; the worker runs the
    bundled installer phase by phase over one SSH session and the page polls
    /rknblock/install/{op_id}.
    """

    async def asyncSetUp(self):
        import app
        self.app = app
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = app.DATA_FILE
        app.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, app, 'DATA_FILE', self._data_file)
        self._ops = dict(app._INSTALL_OPS)
        self._active = dict(app._INSTALL_ACTIVE)
        self._loaded = dict(app._INSTALL_OPS_LOADED)
        app._INSTALL_OPS.clear()
        app._INSTALL_ACTIVE.clear()
        app._INSTALL_OPS_LOADED['done'] = False
        self.addCleanup(self.engine_state, app)

        self.data = {'servers': [{'name': 'A', 'uid': 'node-a',
                                  'host': '192.0.2.1', 'protocols': {}}],
                     'users': [], 'user_connections': []}
        self.ran = []
        self.fail_phase = None
        self.ssh = Mock()
        self.ssh.run_sudo_script.side_effect = self.run_phase
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(app, '_check_admin', return_value=True))
        self.stack.enter_context(patch.object(
            app, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(app, 'save_data', side_effect=self.save))
        self.stack.enter_context(patch.object(app, 'get_ssh', return_value=self.ssh))
        app.RKN_FLAG_CACHE.clear()
        app.RKN_FLAG_CACHE[0] = {'ts': 1, 'data': {'events24': 5}}
        self.request = SimpleNamespace(session={'user_id': 'admin'}, headers={},
                                       query_params={})

    def engine_state(self, app):
        app._INSTALL_OPS.clear()
        app._INSTALL_OPS.update(self._ops)
        app._INSTALL_ACTIVE.clear()
        app._INSTALL_ACTIVE.update(self._active)
        app._INSTALL_OPS_LOADED.clear()
        app._INSTALL_OPS_LOADED.update(self._loaded)

    def save(self, data):
        self.data = copy.deepcopy(data)

    def phase_of(self, cmd):
        for phase in self.app.RKN_INSTALL_PHASES:
            if cmd.rstrip().endswith(' ' + phase):
                return phase
        return '?'

    def run_phase(self, cmd, timeout=60):
        self.ran.append((cmd, timeout))
        phase = self.phase_of(cmd)
        if self.fail_phase == phase:
            return '', 'boom', 1
        return f'rknblock: {phase}: ok\n', '', 0

    async def install(self, server_uid=None, await_worker=True):
        tasks = []
        real = asyncio.create_task

        def capture(coro):
            task = real(coro)
            tasks.append(task)
            return task

        with patch.object(self.app.asyncio, 'create_task', side_effect=capture):
            response = await self.app.api_rknblock_install(
                self.request, 0, server_uid)
        if await_worker:
            for task in list(tasks):
                await task
        return response, tasks

    def op_of(self, response):
        return self.app._INSTALL_OPS[response['operation_id']]

    async def test_install_runs_every_phase_and_marks_record(self):
        response, _ = await self.install()
        self.assertEqual(set(response), {'operation_id'})
        op = self.op_of(response)
        self.assertEqual(op['state'], 'success')
        self.assertEqual(op['percent'], 100)
        self.assertEqual(op['result'],
                         {'status': 'success', 'installed': True, 'enabled': True})
        self.assertEqual(self.data['servers'][0]['rknblock'],
                         {'installed': True, 'enabled': True, 'last_error': None})
        self.assertNotIn(0, self.app.RKN_FLAG_CACHE)
        self.assertEqual([self.phase_of(cmd) for cmd, _ in self.ran],
                         list(self.app.RKN_INSTALL_PHASES))
        self.assertEqual(self.ran[0][1], 420)  # install timeout
        self.ssh.connect.assert_called_once()  # one SSH session for all phases
        self.ssh.disconnect.assert_called_once()
        stages = [line['stage'] for line in op['lines']]
        for phase in self.app.RKN_INSTALL_PHASES:
            self.assertIn(phase, stages)
        self.assertIn('done', stages)

    async def test_install_failure_stops_and_writes_no_record(self):
        self.fail_phase = 'packages'
        response, _ = await self.install()
        op = self.op_of(response)
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'install_failed')
        self.assertIn('boom', op['error']['message'])
        self.assertNotIn('rknblock', self.data['servers'][0])
        self.assertEqual([self.phase_of(cmd) for cmd, _ in self.ran],
                         ['preflight', 'packages'])  # fail-stop
        self.assertIn(0, self.app.RKN_FLAG_CACHE)

    async def test_install_updates_reloaded_server_by_uid(self):
        # A long SSH call may be followed by a fresh data.json snapshot and a
        # reorder. The record must land on the same uid, not a stale object.
        self.data['servers'][0]['uid'] = 'u1'
        original = copy.deepcopy(self.data['servers'][0])
        fresh = {'servers': [{'name': 'B', 'uid': 'u2'}, dict(original)],
                 'users': [], 'user_connections': []}
        original_run = self.run_phase

        def run(cmd, timeout=60):
            self.data = copy.deepcopy(fresh)
            return original_run(cmd, timeout)

        self.ssh.run_sudo_script.side_effect = run
        response, _ = await self.install()
        self.assertEqual(self.op_of(response)['state'], 'success')
        self.assertNotIn('rknblock', self.data['servers'][0])
        self.assertEqual(self.data['servers'][1]['rknblock'],
                         {'installed': True, 'enabled': True, 'last_error': None})

    async def test_forbidden(self):
        with patch.object(self.app, '_check_admin', return_value=False):
            response, tasks = await self.install()
        self.assertEqual(response.status_code, 403)
        self.assertFalse([op for op in self.app._INSTALL_OPS.values()
                          if op.get('flow') == 'rknblock'])
        self.ssh.run_sudo_script.assert_not_called()

    async def test_missing_uid_never_falls_back_to_reused_index(self):
        def connect():
            self.data = {'servers': [{'uid': 'other',
                                      'rknblock': {'installed': False}}]}

        self.ssh.connect.side_effect = connect
        response, _ = await self.install()
        op = self.op_of(response)
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'server_changed')
        self.assertEqual(self.data['servers'][0]['rknblock'],
                         {'installed': False})
        self.ssh.run_sudo_script.assert_not_called()

    async def test_legacy_missing_uid_and_explicit_empty_uid_never_start_ssh(self):
        for value in ('', 'missing'):
            response, _ = await self.install(value)
            self.assertEqual(response.status_code, 404)
        self.data['servers'][0].pop('uid')
        response, _ = await self.install()
        self.assertEqual(response.status_code, 404)
        self.ssh.run_sudo_script.assert_not_called()

    async def test_duplicate_uid_is_ambiguous_even_for_legacy_index_request(self):
        self.data['servers'].append(dict(self.data['servers'][0], name='B'))
        response, _ = await self.install()
        self.assertEqual(response.status_code, 404)
        self.ssh.run_sudo_script.assert_not_called()

    async def test_endpoint_changed_during_connect_does_not_run_remote_command(self):
        def connect():
            self.data['servers'][0]['host'] = '192.0.2.2'

        self.ssh.connect.side_effect = connect
        response, _ = await self.install()
        op = self.op_of(response)
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'server_changed')
        self.assertEqual(self.ran, [])
        self.assertNotIn('rknblock', self.data['servers'][0])

    async def test_deleted_during_command_cannot_commit_to_reused_index(self):
        original_run = self.run_phase

        def run(cmd, timeout=60):
            self.data = {'servers': [{'uid': 'replacement',
                                      'rknblock': {'installed': False}}]}
            return original_run(cmd, timeout)

        self.ssh.run_sudo_script.side_effect = run
        response, _ = await self.install()
        op = self.op_of(response)
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'server_changed')
        self.assertFalse(self.data['servers'][0]['rknblock']['installed'])

    async def test_connection_failure_always_disconnects(self):
        self.ssh.connect.side_effect = OSError('synthetic failure')
        response, _ = await self.install()
        op = self.op_of(response)
        self.assertEqual(op['state'], 'failed')
        self.assertEqual(op['error']['code'], 'internal_error')
        self.ssh.disconnect.assert_called_once()

    async def test_request_uid_is_checked_before_ssh(self):
        self.data['servers'][0]['uid'] = 'other'
        response, _ = await self.install('missing')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.ran, [])

    async def test_second_install_of_the_same_flow_is_rejected(self):
        entered = threading.Event()
        release = threading.Event()
        original_run = self.run_phase

        def run(cmd, timeout=60):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('synthetic barrier')
            return original_run(cmd, timeout)

        self.ssh.run_sudo_script.side_effect = run
        response, tasks = await self.install(await_worker=False)
        self.assertTrue(await asyncio.to_thread(entered.wait, 3))
        try:
            second, _ = await self.install()
        finally:
            release.set()
            for task in tasks:
                await task
        self.assertEqual(second.status_code, 409)
        self.assertEqual(json.loads(second.body)['code'], 'install_in_progress')
        rkn_ops = [op for op in self.app._INSTALL_OPS.values()
                   if op.get('flow') == 'rknblock']
        self.assertEqual(len(rkn_ops), 1)
        self.assertTrue(self.data['servers'][0]['rknblock']['installed'])

    async def test_progress_endpoint_reports_real_stages(self):
        response, _ = await self.install()
        op = self.op_of(response)
        payload = self.app.api_rknblock_install_status(
            self.request, 0, op['id'])
        for key in ('operation_id', 'flow', 'state', 'step', 'total',
                    'percent', 'result', 'error', 'started_at',
                    'finished_at', 'lines', 'next_offset'):
            self.assertIn(key, payload)
        self.assertEqual(payload['flow'], 'rknblock')
        self.assertEqual(payload['percent'], 100)
        self.assertEqual({line['stage'] for line in payload['lines']},
                         set(self.app.RKN_INSTALL_PHASES) | {'start', 'done'})
        missing = self.app.api_rknblock_install_status(
            self.request, 1, op['id'])
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(json.loads(missing.body)['code'], 'not_found')


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
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = app.DATA_FILE
        app.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, app, 'DATA_FILE', self._data_file)
        self._ops = dict(app._INSTALL_OPS)
        self._active = dict(app._INSTALL_ACTIVE)
        self._loaded = dict(app._INSTALL_OPS_LOADED)
        app._INSTALL_OPS.clear()
        app._INSTALL_ACTIVE.clear()
        app._INSTALL_OPS_LOADED['done'] = False
        self.addCleanup(self.engine_state, app)
        self.data = {'servers': [{'uid': 'fixture-node', 'host': '192.0.2.1',
                                  'protocols': {}}],
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
        self.app.RKN_FLAG_CACHE.clear()
        self.request = SimpleNamespace()

    def engine_state(self, app):
        app._INSTALL_OPS.clear()
        app._INSTALL_OPS.update(self._ops)
        app._INSTALL_ACTIVE.clear()
        app._INSTALL_ACTIVE.update(self._active)
        app._INSTALL_OPS_LOADED.clear()
        app._INSTALL_OPS_LOADED.update(self._loaded)

    async def start_install(self):
        tasks = []
        real = asyncio.create_task

        def capture(coro):
            task = real(coro)
            tasks.append(task)
            return task

        with patch.object(self.app.asyncio, 'create_task', side_effect=capture):
            response = await self.app.api_rknblock_install(
                self.request, 0, 'fixture-node')
        return response, tasks

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

    async def test_running_install_rejects_a_second_install_and_runs_once(self):
        # The interlock is now the operation registry: the first install owns
        # the flow until its worker finishes, a duplicate gets 409 and never
        # starts a second SSH session.
        entered, release = threading.Event(), threading.Event()

        def run(*args):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('synthetic barrier')
            return ('ok', '', 0)

        self.ssh.run_sudo_script.side_effect = run
        first, tasks = await self.start_install()
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            second = await self.app.api_rknblock_install(self.request, 0, 'fixture-node')
        finally:
            release.set()
            for task in tasks:
                await task
        self.assertEqual(second.status_code, 409)
        self.assertEqual(json.loads(second.body)['code'], 'install_in_progress')
        self.assertIn(first['operation_id'], self.app._INSTALL_OPS)
        self.assertEqual(self.app._INSTALL_OPS[first['operation_id']]['state'], 'success')
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
            response, tasks = await self.start_install()
            for task in tasks:
                await task
            self.assertEqual(
                self.app._INSTALL_OPS[response['operation_id']]['state'], 'success')
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
