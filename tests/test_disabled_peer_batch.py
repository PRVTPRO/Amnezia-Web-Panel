"""P3: a disabled peer must not poison the whole prefetch batch.

`toggle_client(enable=False)` rewrites awg0.conf without that peer's [Peer]
block, so its clientId is legitimately absent from the config. The integrity
guard (which detects a batch entry mixing two containers' files) must ignore
exactly those entries, and nothing else: an enabled peer that is missing still
means the batch cannot be trusted.

Production evidence: 971 guard warnings in /root/amnezia-panel.log, 84 of them
caused by a single disabled peer (1/62 … e.g. 6jqpd9gz96je…).
"""
import unittest

import managers.awg_manager as _awg_mod
from managers.awg_manager import AWGManager


class _FixedUUID:
    hex = 'a' * 32


_ORIGINAL_UUID4 = _awg_mod.uuid.uuid4


def setUpModule():
    _awg_mod.uuid.uuid4 = lambda: _FixedUUID()


def tearDownModule():
    _awg_mod.uuid.uuid4 = _ORIGINAL_UUID4


CONFIG = ('@@CONTAINER@@ amnezia-awg2\n'
          '[Interface]\nPrivateKey = SRV\nListenPort = 55424\n'
          '[Peer]\nPublicKey = PEER_A\nAllowedIPs = 10.8.1.2/32\n'
          '@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n')


class FakeSSH:
    _is_root = True

    def __init__(self, clients_json, config=CONFIG):
        self.clients_json = clients_json
        self.batch_output = config + clients_json + '\n'
        self.commands = []

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd.startswith('for c in '):
            return self.batch_output, '', 0
        if 'clientsTable' in cmd:
            return '[]', '', 0
        return '', '', 0

    def docker_container_state(self, name):
        return (name, True)


def table(*rows):
    import json
    return json.dumps(list(rows))


ENABLED_A = {'clientId': 'PEER_A', 'userData': {'clientName': 'alice'}}
DISABLED_B = {'clientId': 'PEER_B', 'userData': {'clientName': 'bob', 'enabled': False}}
ENABLED_B = {'clientId': 'PEER_B', 'userData': {'clientName': 'bob'}}


class DisabledPeerBatchTest(unittest.TestCase):
    def _run(self, clients):
        ssh = FakeSSH(table(*clients))
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        ssh.commands.clear()
        result = mgr._get_clients_table('awg2')
        direct = [c for c in ssh.commands
                  if 'docker exec' in c and not c.startswith('for c in ')]
        return result, direct

    def test_all_enabled_peers_present_accepts_batch(self):
        result, direct = self._run([ENABLED_A])
        self.assertEqual([c['clientId'] for c in result], ['PEER_A'])
        self.assertEqual(direct, [], 'batch must be accepted')

    def test_disabled_peer_missing_from_config_accepts_batch(self):
        # bob is disabled: his [Peer] is gone from awg0.conf by design.
        result, direct = self._run([ENABLED_A, DISABLED_B])
        self.assertEqual({c['clientId'] for c in result}, {'PEER_A', 'PEER_B'})
        self.assertEqual(direct, [], 'a disabled peer must not drop the batch')

    def test_enabled_peer_missing_from_config_drops_batch(self):
        # bob is missing from the config but NOT disabled: this is the shape
        # of a poisoned/mixed entry and must still be re-read directly.
        result, direct = self._run([ENABLED_A, ENABLED_B])
        self.assertEqual(result, [], 'FakeSSH answers [] to a direct read')
        self.assertTrue(direct, 'direct read expected after the entry was dropped')

    def test_legacy_dict_format_is_converted_unchanged(self):
        # Legacy clientsTable shape: a dict, not a list. The integrity guard
        # applies only to the list branch, so this path is unchanged by P3:
        # the record is converted and returned as before.
        legacy = '{"PEER_B": {"clientName": "bob"}}'
        ssh = FakeSSH(legacy)
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        result = mgr._get_clients_table('awg2')
        self.assertEqual([c['clientId'] for c in result], ['PEER_B'])

    def test_empty_table_with_config_peers_still_dropped(self):
        # Guard A must stay intact: an empty table next to a config full of
        # peers is the "everything became External" paint, never trusted.
        ssh = FakeSSH('')
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        ssh.commands.clear()
        mgr._get_clients_table('awg2')
        direct = [c for c in ssh.commands
                  if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertTrue(direct, 'guard A must re-read directly')


if __name__ == '__main__':
    unittest.main()
