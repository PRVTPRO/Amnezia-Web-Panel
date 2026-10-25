import time
import unittest
import uuid as _uuid

class _FixedUUID:
    hex = 'a' * 32

import managers.awg_manager as _awg_mod

_ORIGINAL_UUID4 = _awg_mod.uuid.uuid4


def setUpModule():
    _awg_mod.uuid.uuid4 = lambda: _FixedUUID()


def tearDownModule():
    _awg_mod.uuid.uuid4 = _ORIGINAL_UUID4


from managers.awg_manager import AWGManager
from managers.ssh_manager import SSHManager


class FakeSSH:
    """Records commands and serves canned docker answers."""

    def __init__(self):
        self.commands = []
        self.ps_output = "amnezia-awg2\trunning\namnezia-awg3\texited\n"
        self.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nPrivateKey = SRV\nListenPort = 55424\n"
            "[Peer]\nPublicKey = PEER_A\nAllowedIPs = 10.8.1.2/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "PEER_A", "userData": {"clientName": "alice"}}]\n'
        )

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd.startswith('docker ps -a --format'):
            return self.ps_output, '', 0
        if cmd.startswith('for c in '):
            return self.batch_output, '', 0
        if 'cat /opt/amnezia/awg/awg0.conf' in cmd and 'docker exec' in cmd:
            return '[Interface]\nListenPort = 55424\n', '', 0
        if 'clientsTable' in cmd:
            return '[]', '', 0
        return '', '', 0

    # Mirror the real SSHManager snapshot API against the canned output.
    def docker_ps_snapshot(self):
        now = time.time()
        cached = getattr(self, '_docker_ps_cache', None)
        if cached and now - cached[0] < SSHManager.DOCKER_PS_TTL:
            return cached[1]
        states = {}
        out, _, code = self.run_sudo_command(
            "docker ps -a --format '{{.Names}}\t{{.State}}'")
        if code == 0:
            for line in out.splitlines():
                parts = line.split('\t')
                if len(parts) == 2 and parts[0]:
                    states[parts[0]] = parts[1]
        self._docker_ps_cache = (now, states)
        return states

    def docker_container_state(self, name):
        try:
            states = self.docker_ps_snapshot()
        except Exception:
            return None
        return (name in states, states.get(name) == 'running')

    def docker_ps_invalidate(self):
        self._docker_ps_cache = None


class DockerPsSnapshotTest(unittest.TestCase):
    def test_snapshot_answers_all_container_queries_with_one_command(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)

        exists_a = mgr.check_protocol_installed('awg2')
        running_a = mgr.check_container_running('awg2')
        exists_b = mgr.check_protocol_installed('awg3')
        running_b = mgr.check_container_running('awg3')
        exists_c = mgr.check_protocol_installed('xray')

        self.assertTrue(exists_a)
        self.assertTrue(running_a)
        self.assertTrue(exists_b)
        self.assertFalse(running_b)
        self.assertFalse(exists_c)

        ps_cmds = [c for c in ssh.commands if c.startswith('docker ps')]
        self.assertEqual(len(ps_cmds), 1, f"snapshot must be a single command, got: {ps_cmds}")

    def test_invalidate_forces_refetch(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)
        mgr.check_protocol_installed('awg2')
        ssh.docker_ps_invalidate()
        mgr.check_protocol_installed('awg2')
        ps_cmds = [c for c in ssh.commands if c.startswith('docker ps')]
        self.assertEqual(len(ps_cmds), 2)


class PrefetchAwgStateTest(unittest.TestCase):
    def test_prefetch_feeds_config_and_clients_from_one_command(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)

        mgr.prefetch_awg_state(['awg2', 'awg3', 'awg2__2'])
        batch_cmds = [c for c in ssh.commands if c.startswith('for c in ')]
        self.assertEqual(len(batch_cmds), 1)
        # only the running container is dumped
        self.assertIn('amnezia-awg2', batch_cmds[0])
        self.assertNotIn('amnezia-awg3', batch_cmds[0])

        config = mgr._get_server_config('awg2')
        clients = mgr._get_clients_table('awg2')

        self.assertIn('ListenPort = 55424', config)
        self.assertEqual(clients[0]['clientId'], 'PEER_A')

        exec_cmds = [c for c in ssh.commands
                     if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertEqual(exec_cmds, [], f"no per-container exec expected after prefetch: {exec_cmds}")

    def test_poisoned_batch_entry_is_detected_and_reread_directly(self):
        """A mixed batch entry (config of container A + clientsTable of
        container B, observed on NATA) must not be trusted: the table
        pubkeys are absent from the entry's own config, so the entry is
        dropped and the table is read directly."""
        ssh = FakeSSH()
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nPrivateKey = SRV\nListenPort = 55424\n"
            "[Peer]\nPublicKey = PEER_A\nAllowedIPs = 10.8.1.2/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "ALIEN_PUBKEY", "userData": {"clientName": "eve"}}]\n'
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        clients = mgr._get_clients_table('awg2')
        # FakeSSH answers '[]' to any direct clientsTable read.
        self.assertEqual(clients, [])
        exec_cmds = [c for c in ssh.commands
                     if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertTrue(exec_cmds,
                        "direct read expected after poisoned batch entry was dropped")
        self.assertIsNone(ssh._awg_batch['containers'].get('amnezia-awg2'),
                         "poisoned batch entry must be invalidated")

    def test_glued_markers_still_split_sections(self):
        """A dump file without a trailing newline glues the next marker
        onto the payload's last line (observed on FIRSTBYTE: three
        containers merged into one awg2 section and the card counted
        ~119 union peers instead of 67). The parser must still split
        sections at embedded markers."""
        ssh = FakeSSH()
        ssh.ps_output = ("amnezia-awg2\trunning\namnezia-awg2-2\trunning\n"
                         "amnezia-awg3\trunning\n")
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nPrivateKey = S1\nListenPort = 1\n"
            "[Peer]\nPublicKey = K1\nAllowedIPs = 10.8.1.2/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "K1", "userData": {"clientName": "a"}}]'  # no \n
            "@@CONTAINER@@ amnezia-awg2-2\n"
            "[Interface]\nPrivateKey = S2\nListenPort = 2\n"
            "[Peer]\nPublicKey = K2\nAllowedIPs = 10.8.2.2/32"  # no \n
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "K2", "userData": {"clientName": "b"}}]\n'
            "@@CONTAINER@@ amnezia-awg3\n"
            "[Interface]\nPrivateKey = S3\nListenPort = 3\n"
            "[Peer]\nPublicKey = K3\nAllowedIPs = 10.8.3.2/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "K3", "userData": {"clientName": "c"}}]\n'
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2', 'awg2__2', 'awg3'])

        cfg2 = mgr._get_server_config('awg2')
        self.assertIn('K1', cfg2)
        self.assertNotIn('K2', cfg2)
        self.assertNotIn('K3', cfg2)
        cfg22 = mgr._get_server_config('awg2__2')
        self.assertIn('K2', cfg22)
        self.assertNotIn('K1', cfg22)
        self.assertNotIn('K3', cfg22)
        cfg3 = mgr._get_server_config('awg3')
        self.assertIn('K3', cfg3)
        self.assertNotIn('K1', cfg3)

        names = {p: [c.get('userData', {}).get('clientName')
                     for c in mgr._get_clients_table(p)]
                 for p in ('awg2', 'awg2__2', 'awg3')}
        self.assertEqual(names, {'awg2': ['a'], 'awg2__2': ['b'], 'awg3': ['c']})

    def test_batch_cache_expires(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        ssh._awg_batch['_ts'] = time.time() - 100  # force stale
        self.assertIsNone(mgr._batch_entry('amnezia-awg2'))

    def test_no_running_containers_means_no_batch_command(self):
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\texited\n"
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        batch_cmds = [c for c in ssh.commands if c.startswith('for c in ')]
        self.assertEqual(batch_cmds, [])
        self.assertEqual(mgr._get_clients_table('awg2'), [])

    def test_corrupt_prefetched_clients_falls_back_to_direct_read(self):
        """A truncated batch read (flaky link) must not show up as 0 peers."""
        ssh = FakeSSH()
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nListenPort = 55424\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "PEER_A", "userData": {"clie'  # cut off mid-JSON
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])

        clients = mgr._get_clients_table('awg2')
        # direct read returns '[]' in FakeSSH, but the point is the retry happened
        self.assertEqual(clients, [])
        self.assertIsNone(ssh._awg_batch['containers'].get('amnezia-awg2'))
        direct = [c for c in ssh.commands
                  if 'clientsTable' in c and not c.startswith('for c in ')]
        self.assertEqual(len(direct), 1)

    def test_corrupt_direct_clients_read_raises_instead_of_zero(self):
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\trunning\n"   # direct path, container up
        ssh.commands = ssh.commands
        mgr = AWGManager(ssh)
        # make the direct read return garbage
        orig = ssh.run_sudo_command
        def garbage(cmd, timeout=60):
            if 'clientsTable' in cmd and 'docker exec' in cmd:
                return '[{"clientId": "BROKEN"', '', 0
            return orig(cmd, timeout)
        ssh.run_sudo_command = garbage
        with self.assertRaises(RuntimeError):
            mgr._get_clients_table('awg2')

    def test_empty_prefetched_clients_with_peers_in_config_rereads_directly(self):
        """Empty clients section in batch + config WITH peers = transient
        cat failure inside the composite prefetch command: re-read directly
        instead of painting every peer 'External' for one poll."""
        ssh = FakeSSH()
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nListenPort = 55424\n"
            "[Peer]\nPublicKey = PEER_A\nAllowedIPs = 10.8.1.2/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"   # <- cat failed transiently, nothing followed
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])

        clients = mgr._get_clients_table('awg2')
        self.assertEqual(clients, [])  # FakeSSH direct read returns '[]'
        self.assertIsNone(ssh._awg_batch['containers'].get('amnezia-awg2'))
        direct = [c for c in ssh.commands
                  if 'clientsTable' in c and not c.startswith('for c in ')]
        self.assertEqual(len(direct), 1)

    def test_empty_prefetched_clients_with_empty_config_stays_empty(self):
        """Empty clients + config without peers = genuinely fresh instance:
        no direct re-read, no log noise."""
        ssh = FakeSSH()
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nListenPort = 55424\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])

        self.assertEqual(mgr._get_clients_table('awg2'), [])
        self.assertIn('amnezia-awg2', ssh._awg_batch['containers'])
        direct = [c for c in ssh.commands
                  if 'clientsTable' in c and not c.startswith('for c in ')]
        self.assertEqual(direct, [])

    def test_stopped_container_reads_nothing(self):
        """A stopped instance must not be exec-polled on every refresh."""
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\texited\n"
        mgr = AWGManager(ssh)
        self.assertEqual(mgr._get_clients_table('awg2'), [])
        exec_cmds = [c for c in ssh.commands
                     if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertEqual(exec_cmds, [])

    def test_unreadable_existing_table_raises(self):
        """Running container, table exists, cat fails -> honest error."""
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\trunning\n"
        orig = ssh.run_sudo_command
        def broken_cat(cmd, timeout=60):
            if 'cat /opt/amnezia/awg/clientsTable' in cmd:
                return '', '', 1
            if 'test -f' in cmd:
                return '', '', 0
            return orig(cmd, timeout)
        ssh.run_sudo_command = broken_cat
        mgr = AWGManager(ssh)
        with self.assertRaises(RuntimeError):
            mgr._get_clients_table('awg2')

    def test_fresh_instance_without_table_is_empty(self):
        """Running container, no clientsTable yet -> empty, not an error."""
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\trunning\n"
        orig = ssh.run_sudo_command
        def no_file(cmd, timeout=60):
            if 'cat /opt/amnezia/awg/clientsTable' in cmd:
                return '', '', 1
            if 'printf missing' in cmd:
                return 'missing', '', 0
            return orig(cmd, timeout)
        ssh.run_sudo_command = no_file
        mgr = AWGManager(ssh)
        self.assertEqual(mgr._get_clients_table('awg2'), [])

    def test_status_counts_conf_only_peers_as_connections(self):
        """clients_count must include peers that exist only in awg0.conf
        (the ones the list renders as 'External')."""
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\trunning\n"
        ssh.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nPrivateKey = SRV\nListenPort = 55424\n\n"
            "[Peer]\nPublicKey = PEER_A\nAllowedIPs = 10.8.1.2/32\n\n"
            "[Peer]\nPublicKey = PEER_EXT\nAllowedIPs = 10.8.1.9/32\n"
            "@@CLIENTS_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@@\n"
            '[{"clientId": "PEER_A", "userData": {"clientName": "alice"}}]\n'
        )
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        info = mgr.get_server_status('awg2')
        self.assertEqual(info['clients_count'], 2)
        self.assertEqual(info['external_count'], 1)



    def test_prefetch_nonzero_exit_code_leaves_batch_invalid(self):
        """A failing composite prefetch must not leave a half-built batch:
        _awg_batch is set to None so callers fall back to direct reads."""
        ssh = FakeSSH()
        orig = ssh.run_sudo_command
        def failing(cmd, timeout=60):
            if cmd.startswith('for c in '):
                return '', 'boom: something failed', 1
            return orig(cmd, timeout)
        ssh.run_sudo_command = failing
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        self.assertIsNone(ssh._awg_batch)

if __name__ == '__main__':
    unittest.main()
