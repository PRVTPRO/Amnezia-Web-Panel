"""Synthetic SSH/container filesystem: no Docker daemon or network is used."""
import copy
import json
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager


TABLE = [{'clientId': 'synthetic-key', 'userData': {
    'clientName': 'old', 'clientPrivateKey': 'synthetic-private',
    'customConfig': 'synthetic-config'}}]
PATHS = {'awg': '/opt/amnezia/awg/clientsTable',
         'wg': '/opt/amnezia/wireguard/clientsTable'}


class FilesystemSSH:
    def __init__(self, root, fail=None, barrier=None):
        self.root = pathlib.Path(root)
        self.host = 'example.test'
        self.fail = fail
        self.barrier = barrier
        self.counter = 0
        self.lock = threading.Lock()
        self.uploads = []

    def host_file(self, name):
        return self.root / 'host' / name.lstrip('/')

    def container_file(self, container, name):
        return self.root / container / name.lstrip('/')

    def run_command(self, command, timeout=60):
        if command.startswith('chmod ') and self.fail == 'chmod':
            return '', 'synthetic permission failure', 1
        if command.startswith('mktemp '):
            with self.lock:
                self.counter += 1
                name = '/tmp/amnezia-clients.fixture' + str(self.counter)
            self.host_file(name).mkdir(parents=True)
            return name + '\n', '', 0
        if command.startswith('rm '):
            p = self.host_file(shlex.split(command)[-1])
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        return '', '', 0

    def upload_file(self, content, name):
        p = self.host_file(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
        self.uploads.append(name)
        if self.fail == 'upload':
            raise TimeoutError('synthetic upload timeout')
        if self.barrier:
            self.barrier.wait(timeout=5)

    def run_sudo_command(self, command, timeout=60):
        args = shlex.split(command)
        if args[:2] == ['docker', 'cp']:
            args = [a for a in args if a != '--']
            source, target = args[-2:]
            container, name = target.split(':', 1)
            destination = self.container_file(container, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if self.fail == 'copy':
                destination.write_text('partial transfer', encoding='utf-8')
                return '', 'synthetic copy failure', 1
            shutil.copyfile(self.host_file(source), destination)
            return '', '', 0
        if args[:2] == ['docker', 'exec']:
            if self.fail == 'commit':
                return '', 'synthetic commit failure', 1
            if self.fail == 'reset':
                raise ConnectionResetError('synthetic SSH reset')
            container = args[3] if args[2] == '-i' else args[2]
            if 'rm' in args and 'sh' not in args:
                self.container_file(container, args[-1]).unlink(missing_ok=True)
                return '', '', 0
            script = args[-1]
            # Execute the actual commit shell script against synthetic files.
            mapped = (self.root / container / 'opt').as_posix()
            script = script.replace('/opt', mapped)
            if self.fail == 'backup':
                script = 'cp() { return 37; }\n' + script
            if self.fail == 'rename':
                script = 'mv() { case "$4" in */clientsTable) return 38;; *) command mv "$@";; esac; }\n' + script
            shell = shutil.which('sh') or 'C:/Program Files/Git/bin/bash.exe'
            result = subprocess.run([shell, '-c', script], capture_output=True, text=True, timeout=10)
            if self.fail == 'lost_reply' and result.returncode == 0:
                raise TimeoutError('synthetic lost commit reply')
            return result.stdout, result.stderr, result.returncode
        raise AssertionError('Unexpected command: ' + command)


def make_manager(ssh, kind, container):
    mgr = AWGManager(ssh) if kind == 'awg' else WireGuardManager(ssh)
    mgr._apply_bw_limits = Mock()
    if kind == 'awg':
        mgr._container_name = Mock(return_value=container)
    else:
        mgr.CONTAINER_NAME = container
    return mgr


def save(mgr, kind, table):
    return mgr._save_clients_table('awg3', table) if kind == 'awg' else mgr._save_clients_table(table)


class AtomicClientsTableTests(unittest.TestCase):
    def test_lost_commit_reply_requires_reconciliation_but_keeps_complete_keys(self):
        for kind in PATHS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                ssh = FilesystemSSH(root, fail='lost_reply')
                ssh._awg_batch = {'containers': {}}
                p = self.initialize(ssh, kind, 'synthetic-container')
                updated = copy.deepcopy(TABLE)
                updated[0]['userData']['clientName'] = 'renamed'
                with self.assertRaises(TimeoutError):
                    save(make_manager(ssh, kind, 'synthetic-container'), kind, updated)
                self.assertEqual(json.loads(p.read_text()), updated)
                self.assertEqual(json.loads(pathlib.Path(str(p) + '.panel-backup').read_text()), TABLE)
                if kind == 'awg':
                    self.assertIsNone(ssh._awg_batch)

    def initialize(self, ssh, kind, container):
        p = ssh.container_file(container, PATHS[kind])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(TABLE), encoding='utf-8')
        return p

    def test_success_preserves_backup_and_survives_new_manager(self):
        for kind in PATHS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                ssh = FilesystemSSH(root)
                p = self.initialize(ssh, kind, 'synthetic-container')
                updated = copy.deepcopy(TABLE)
                updated[0]['userData']['clientName'] = 'renamed'
                save(make_manager(ssh, kind, 'synthetic-container'), kind, updated)
                self.assertEqual(json.loads(p.read_text()), updated)
                self.assertEqual(json.loads(pathlib.Path(str(p) + '.panel-backup').read_text()), TABLE)
                restarted = FilesystemSSH(root)
                self.assertEqual(json.loads(restarted.container_file('synthetic-container', PATHS[kind]).read_text()), updated)
                self.assertFalse(list((pathlib.Path(root) / 'host/tmp').iterdir()))

    def test_failed_transfer_cannot_truncate_live_keys(self):
        for kind in PATHS:
            for failure in ('copy', 'commit', 'upload', 'reset', 'chmod', 'backup', 'rename'):
                with self.subTest(kind=kind, failure=failure), tempfile.TemporaryDirectory() as root:
                    ssh = FilesystemSSH(root, fail=failure)
                    p = self.initialize(ssh, kind, 'synthetic-container')
                    mgr = make_manager(ssh, kind, 'synthetic-container')
                    with self.assertRaises((RuntimeError, TimeoutError, ConnectionResetError)):
                        save(mgr, kind, [])
                    self.assertEqual(json.loads(p.read_text()), TABLE)
                    mgr._apply_bw_limits.assert_not_called()

    def test_two_containers_do_not_share_upload_paths(self):
        with tempfile.TemporaryDirectory() as root:
            ssh = FilesystemSSH(root, barrier=threading.Barrier(2))
            a = make_manager(ssh, 'awg', 'synthetic-awg2')
            b = make_manager(ssh, 'awg', 'synthetic-awg3')
            pa = self.initialize(ssh, 'awg', 'synthetic-awg2')
            pb = self.initialize(ssh, 'awg', 'synthetic-awg3')
            first = [{'clientId': 'synthetic-first', 'userData': {'clientPrivateKey': 'test-a'}}]
            second = [{'clientId': 'synthetic-second', 'userData': {'clientPrivateKey': 'test-b'}}]
            errors = []
            def write(mgr, table):
                try:
                    save(mgr, 'awg', table)
                except Exception as exc:
                    errors.append(exc)
            threads = [threading.Thread(target=write, args=(a, first)), threading.Thread(target=write, args=(b, second))]
            for t in threads: t.start()
            for t in threads: t.join(10)
            self.assertFalse(any(t.is_alive() for t in threads))
            self.assertEqual(errors, [])
            self.assertEqual(json.loads(pa.read_text()), first)
            self.assertEqual(json.loads(pb.read_text()), second)
            self.assertEqual(len(set(ssh.uploads)), 2)

    def test_backup_failure_aborts_replace(self):
        for kind in PATHS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                ssh = FilesystemSSH(root)
                p = self.initialize(ssh, kind, 'synthetic-container')
                # An existing directory at the staging-backup destination must
                # fail rather than overwrite the only live copy.
                with unittest.mock.patch('secrets.token_hex', return_value='fixed'):
                    stage_backup = p.parent / '.clientsTable.fixed.backup'
                    stage_backup.mkdir()
                    (stage_backup / 'keep').write_text('synthetic', encoding='utf-8')
                    with self.assertRaises(RuntimeError):
                        save(make_manager(ssh, kind, 'synthetic-container'), kind, [])
                self.assertEqual(json.loads(p.read_text()), TABLE)


if __name__ == '__main__':
    unittest.main()
