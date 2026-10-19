"""Failed metadata reads must not replace existing VPN keys with native rows."""
import copy
import json
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager
from managers.wireguard_manager import WireGuardManager


TABLE = [
    {'clientId': 'synthetic-a', 'userData': {
        'clientName': 'alpha', 'clientPrivateKey': 'synthetic-private-a'}},
    {'clientId': 'synthetic-b', 'userData': {
        'clientName': 'beta', 'customConfig': 'synthetic-config'}},
]


def manager(kind, read=('', 'read failed', -1), probe=('', '', -1)):
    ssh = Mock()
    ssh.host = 'example.test'
    ssh._awg_batch = None
    ssh.docker_container_state.return_value = (True, True)
    ssh.run_sudo_command.side_effect = [read, probe]
    mgr = AWGManager(ssh) if kind == 'awg' else WireGuardManager(ssh)
    if kind == 'awg':
        mgr._container_name = Mock(return_value='amnezia-awg3')
    return mgr, ssh


def read_table(mgr, kind):
    return mgr._get_clients_table('awg3') if kind == 'awg' else mgr._get_clients_table()


def rename(mgr, kind):
    return mgr.rename_client('awg3', 'synthetic-a', 'renamed') if kind == 'awg' else mgr.rename_client('synthetic-a', 'renamed')


class ClientsTableReadTests(unittest.TestCase):
    def test_awg_legacy_dictionary_keeps_keys_ips_and_custom_config_on_rename(self):
        metadata = dict(TABLE[0]['userData'], clientIp='10.8.1.2',
                        psk='synthetic-psk', customConfig='synthetic-config')
        mgr, _ = manager('awg', (json.dumps({'synthetic-a': metadata}), '', 0))
        mgr._save_clients_table = Mock()
        rename(mgr, 'awg')
        saved = mgr._save_clients_table.call_args.args[-1]
        self.assertEqual(saved, [{'clientId': 'synthetic-a',
                                 'userData': dict(metadata, clientName='renamed')}])

    def test_reservation_read_error_is_not_an_empty_ip_pool(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, ('', 'read failed', 1), ('', '', 0))
                with self.assertRaises(RuntimeError):
                    mgr._get_reserved_ips('awg3') if kind == 'awg' else mgr._get_reserved_ips()

    def test_empty_reservation_file_does_not_release_disabled_ips(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, ('', '', 0))
                with self.assertRaises(RuntimeError):
                    mgr._get_reserved_ips('awg3') if kind == 'awg' else mgr._get_reserved_ips()

    def test_missing_reservation_file_is_allowed_only_with_proof(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, ('', 'not found', 1), ('missing', '', 0))
                result = mgr._get_reserved_ips('awg3') if kind == 'awg' else mgr._get_reserved_ips()
                self.assertEqual(result, set())

    def test_failed_reads_and_failed_absence_probes_abort(self):
        for kind in ('awg', 'wg'):
            for code in (-1, 1, 255):
                with self.subTest(kind=kind, code=code):
                    mgr, ssh = manager(kind, ('', 'read failed', code))
                    with self.assertRaises(RuntimeError):
                        read_table(mgr, kind)
                    ssh.upload_file.assert_not_called()

    def test_existing_file_is_not_empty_on_read_failure(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, probe=('', '', 1))
                with self.assertRaises(RuntimeError):
                    read_table(mgr, kind)

    def test_confirmed_missing_file_is_a_fresh_table(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, probe=('missing', '', 0))
                self.assertEqual(read_table(mgr, kind), [])

    def test_success_without_absence_marker_is_not_proof(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, _ = manager(kind, probe=('', '', 0))
                with self.assertRaises(RuntimeError):
                    read_table(mgr, kind)

    def test_empty_truncated_and_wrong_shape_data_are_rejected(self):
        for kind in ('awg', 'wg'):
            for raw in ('', '  ', '[', 'null', '7', '"text"'):
                with self.subTest(kind=kind, raw=raw):
                    mgr, _ = manager(kind, (raw, '', 0))
                    with self.assertRaises(RuntimeError):
                        read_table(mgr, kind)

    def test_wireguard_object_is_not_silently_discarded(self):
        mgr, _ = manager('wg', ('{"old":"metadata"}', '', 0))
        with self.assertRaises(RuntimeError):
            read_table(mgr, 'wg')

    def test_valid_empty_and_existing_tables_roundtrip(self):
        for kind in ('awg', 'wg'):
            for value in ([], TABLE):
                with self.subTest(kind=kind, value=value):
                    mgr, _ = manager(kind, (json.dumps(value), '', 0))
                    self.assertEqual(read_table(mgr, kind), value)

    def test_ssh_exceptions_never_write(self):
        for kind in ('awg', 'wg'):
            for error in (TimeoutError('synthetic timeout'), ConnectionResetError('synthetic reset')):
                with self.subTest(kind=kind, error=type(error).__name__):
                    mgr, ssh = manager(kind)
                    ssh.run_sudo_command.side_effect = error
                    with self.assertRaises(type(error)):
                        rename(mgr, kind)
                    ssh.upload_file.assert_not_called()

    def test_rename_read_failure_preserves_persisted_keys(self):
        for kind in ('awg', 'wg'):
            with self.subTest(kind=kind):
                mgr, ssh = manager(kind)
                persisted = copy.deepcopy(TABLE)
                mgr._parse_peers_from_config = Mock(return_value={'synthetic-a': {}})
                def save(*args):
                    persisted[:] = copy.deepcopy(args[-1])
                mgr._save_clients_table = Mock(side_effect=save)
                with self.assertRaises(RuntimeError):
                    rename(mgr, kind)
                self.assertEqual(persisted, TABLE)
                mgr._save_clients_table.assert_not_called()
                ssh.upload_file.assert_not_called()

    def test_awg_mutation_ignores_stale_poll_batch(self):
        mgr, ssh = manager('awg', (json.dumps(TABLE), '', 0))
        mgr._batch_entry = Mock(return_value={'clients': '[]', 'config': ''})
        persisted = copy.deepcopy(TABLE)
        mgr._parse_peers_from_config = Mock(return_value={'synthetic-a': {}})
        mgr._save_clients_table = Mock(side_effect=lambda _, table: persisted.__setitem__(slice(None), table))
        rename(mgr, 'awg')
        self.assertEqual(len(persisted), 2)
        self.assertEqual(persisted[0]['userData']['clientPrivateKey'], 'synthetic-private-a')
        self.assertEqual(persisted[0]['userData']['clientName'], 'renamed')
        ssh.run_sudo_command.assert_called_once()

    def test_awg_mutation_cannot_treat_stopped_container_as_empty(self):
        mgr, ssh = manager('awg')
        ssh.docker_container_state.return_value = (True, False)
        mgr._parse_peers_from_config = Mock(return_value={'synthetic-a': {}})
        mgr._save_clients_table = Mock()
        with self.assertRaises(RuntimeError):
            rename(mgr, 'awg')
        mgr._save_clients_table.assert_not_called()

    def test_awg_readonly_stopped_container_still_avoids_ssh(self):
        mgr, ssh = manager('awg')
        ssh.docker_container_state.return_value = (True, False)
        self.assertEqual(read_table(mgr, 'awg'), [])
        ssh.run_sudo_command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
