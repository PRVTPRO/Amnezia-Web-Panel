"""clientsTable read-modify-write ops must be serialized per container.

Uvicorn runs blocking manager calls in a thread pool, so two overlapping
ops (e.g. two renames, or a rename racing an add) used to read the same
table snapshot and save in arbitrary order: the last save silently dropped
the other op's change. The lost row resurfaced as a synthesized
'External (native app)' entry because the WireGuard config stores no
names — that is how peer names were lost in production.

The interleaving here is deterministic: both ops must read before either
is allowed to save, so without serialization the last save necessarily
clobbers the other op's change.
"""
import json
import threading
import time
import unittest
from unittest import mock

from managers.awg_manager import AWGManager, _clients_table_lock
from managers.wireguard_manager import WireGuardManager

TABLE = [
    {'clientId': 'KEY_A', 'userData': {'clientName': 'alpha'}},
    {'clientId': 'KEY_B', 'userData': {'clientName': 'beta'}},
]


def fake_ssh():
    """In-memory clientsTable behind the SSH command interface."""
    ssh = mock.Mock()
    ssh.host = 'testhost'
    ssh._awg_batch = None  # real attribute; a bare Mock would break _batch_entry
    ssh.docker_container_state = lambda name: (True, True)
    state = {'table': json.dumps(TABLE)}
    sync = {'reads': 0, 'both_read': threading.Event()}

    def sudo(command, timeout=60):
        if ' cat ' in command and 'clientsTable' in command:
            time.sleep(0.2)  # keep the snapshots overlapping
            snapshot = state['table']  # capture BEFORE signalling: the
            sync['reads'] += 1       # snapshot must predate the other
            if sync['reads'] >= 2:   # op's save, or the race is invisible
                sync['both_read'].set()
            return snapshot, '', 0
        if command.startswith('docker cp'):
            return '', '', 0
        return '', '', 1

    def upload(content, remote_path):
        # only the clientsTable snapshot models the server's table;
        # _apply_bw_limits uploads other files (tc scripts, bwlimits)
        if remote_path.endswith('_clients.json'):
            state['table'] = content

    ssh.run_sudo_command = sudo
    ssh.upload_file = upload
    return ssh, state, sync


def awg_mgr(ssh):
    mgr = AWGManager(ssh)
    mgr._container_name = mock.Mock(return_value='amnezia-awg2')
    return mgr


def save_last(sync):
    """Decorator for a save that waits until both ops have read.

    Both snapshots predate both saves, so whichever op saves last
    clobbers the other — guaranteed without serialization.
    """
    def wrap(mgr, method_name, protocol_aware):
        original = getattr(type(mgr), method_name)

        def wrapped(*args):
            # args: (protocol_type, clients_table) for AWG, (table) for WG
            sync['both_read'].wait(10)
            if protocol_aware:
                return original(mgr, args[0], args[1])
            return original(mgr, args[0])
        setattr(mgr, method_name, wrapped)
    return wrap


def run_pair(op_a, op_b):
    errors = []
    threads = [
        threading.Thread(target=lambda: op_a(errors)),
        threading.Thread(target=lambda: op_b(errors)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return errors


class ConcurrentRenameTests(unittest.TestCase):
    def test_two_concurrent_renames_both_survive(self):
        ssh, state, sync = fake_ssh()

        def rename_a(errors):
            try:
                mgr = awg_mgr(ssh)
                save_last(sync)(mgr, '_save_clients_table', True)
                mgr.rename_client('awg2', 'KEY_A', 'renamed-A')
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append(exc)

        def rename_b(errors):
            try:
                awg_mgr(ssh).rename_client('awg2', 'KEY_B', 'renamed-B')
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        errors = run_pair(rename_a, rename_b)
        self.assertFalse(errors)
        names = {c['clientId']: c['userData']['clientName']
                 for c in json.loads(state['table'])}
        self.assertEqual(names.get('KEY_A'), 'renamed-A')
        self.assertEqual(names.get('KEY_B'), 'renamed-B')

    def test_rename_racing_an_add_keeps_the_new_row(self):
        ssh, state, sync = fake_ssh()

        def rename_a(errors):
            try:
                mgr = awg_mgr(ssh)
                save_last(sync)(mgr, '_save_clients_table', True)
                mgr.rename_client('awg2', 'KEY_A', 'renamed-A')
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        def add_c(errors):
            try:
                mgr = awg_mgr(ssh)
                # model a real writer (add_client is decorated the same way)
                with _clients_table_lock('testhost', 'amnezia-awg2'):
                    table = mgr._get_clients_table('awg2')
                    table.append({'clientId': 'KEY_C',
                                  'userData': {'clientName': 'gamma'}})
                    mgr._save_clients_table('awg2', table)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        errors = run_pair(rename_a, add_c)
        self.assertFalse(errors)
        rows = {c['clientId']: c['userData']['clientName']
                for c in json.loads(state['table'])}
        self.assertIn('KEY_C', rows, 'row added by the concurrent op was lost')
        self.assertEqual(rows.get('KEY_A'), 'renamed-A')


class WireGuardLockTests(unittest.TestCase):
    def test_wireguard_renames_serialize_too(self):
        ssh, state, sync = fake_ssh()

        def rename_a(errors):
            try:
                mgr = WireGuardManager(ssh)
                save_last(sync)(mgr, '_save_clients_table', False)
                mgr.rename_client('KEY_A', 'renamed-A')
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        def rename_b(errors):
            try:
                WireGuardManager(ssh).rename_client('KEY_B', 'renamed-B')
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        errors = run_pair(rename_a, rename_b)
        self.assertFalse(errors)
        names = {c['clientId']: c['userData']['clientName']
                 for c in json.loads(state['table'])}
        self.assertEqual(names.get('KEY_A'), 'renamed-A')
        self.assertEqual(names.get('KEY_B'), 'renamed-B')


if __name__ == '__main__':
    unittest.main()
