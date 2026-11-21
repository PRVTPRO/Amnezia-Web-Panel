"""P2: exit-link state from the /check prefetch must equal the direct read.

The prefetch runs one composite command for every running AWG container and
adds a `wg show exit0` block only for instances that have a link. These tests
pin the three outcomes the direct `exit_link_status` distinguishes — success,
"file absent" (docker exec rc 9) and "command failed" — plus the fallback when
no block was collected at all.
"""
import re
import unittest
from pathlib import Path

from managers.awg_manager import AWGManager

ROOT = Path(__file__).resolve().parents[1]

PEER = 'PEERKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='


class FakeSSH:
    """Answers the composite with an exit block built for THIS command.

    The markers are random per prefetch call, so the fake parses them out of
    the command it just received instead of relying on a hardcoded string.
    """

    _is_root = True

    def __init__(self, link_rc=0, payload=''):
        self.link_rc = link_rc
        self.payload = payload
        self.commands = []
        self.direct_reads = 0

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd.startswith('for c in '):
            clients = re.search(r'@@CLIENTS_[0-9a-f]+@@', cmd)
            found = re.search(r'@@EXIT_[0-9a-f]+@@', cmd)
            rc_marker = re.search(r'@@EXITRC_[0-9a-f]+@@', cmd)
            if not clients:
                return '', '', 0
            # A realistic composite: the container dumps come first, then the
            # exit block. Omitting the dumps is what previously hid the bug
            # where the last clientsTable swallowed the exit tail.
            out = ('@@CONTAINER@@ amnezia-awg2\n'
                   '[Interface]\n[Peer]\nPublicKey = PEER_A\n'
                   f'{clients.group(0)}\n[{{"clientId": "PEER_A"}}]\n')
            if found and rc_marker:
                container = re.search(
                    re.escape(found.group(0)) + r' ([A-Za-z0-9_.-]+)', cmd).group(1)
                out += (f'{found.group(0)} {container}\n\n'
                        f'{rc_marker.group(0)} {self.link_rc}\n{self.payload}')
            return out, '', 0
        if 'exit0.conf' in cmd:
            self.direct_reads += 1
            return 'PEERKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1700000000\n' \
                   '---\nPEERKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1234\t5678\n' \
                   '---\nPEERKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t203.0.113.9:51820\n', '', 0
        return '', '', 0

    def docker_container_state(self, name):
        return (name, True)


class ExitLinkBatchTest(unittest.TestCase):
    def _prefetch(self, link_rc=0, payload='', exit_protocols=('awg2',)):
        ssh = FakeSSH(link_rc=link_rc, payload=payload)
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'], exit_protocols=list(exit_protocols))
        return ssh, mgr

    def test_last_container_keeps_its_clients_table(self):
        # Regression for B1: the exit tail used to be glued to the last
        # container's clientsTable, so json.loads failed and the batch entry
        # was dropped on every check of a server with an exit link.
        ssh, mgr = self._prefetch(payload='')
        clients = mgr._get_clients_table('awg2')
        self.assertEqual([c['clientId'] for c in clients], ['PEER_A'])
        direct = [c for c in ssh.commands
                  if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertEqual(direct, [], 'the batch must stay usable')

    def test_missing_file_is_reported_as_none(self):
        # The composite maps `test -f` failure to 9 (the direct path uses
        # `|| exit 9`); rc 1 must never appear for a missing file.
        ssh, mgr = self._prefetch(link_rc=9)
        self.assertIsNone(mgr.exit_link_status('awg2'))
        self.assertEqual(ssh.direct_reads, 0)

    def test_success_matches_direct_read_shape(self):
        payload = (f'{PEER}\t1700000000\n'
                   '---\n'
                   f'{PEER}\t1234\t5678\n'
                   '---\n'
                   f'{PEER}\t203.0.113.9:51820\n')
        ssh, mgr = self._prefetch(payload=payload)
        state = mgr.exit_link_status('awg2', now=1700000005)
        self.assertIsNotNone(state)
        self.assertTrue(state['up'])
        self.assertEqual(state['handshake_age'], 5)
        self.assertEqual(state['endpoint'], '203.0.113.9:51820')
        self.assertNotIn('error', state)
        self.assertEqual(ssh.direct_reads, 0, 'answer must come from the batch')

    def test_failed_command_answers_error_dict_without_ssh(self):
        ssh, mgr = self._prefetch(link_rc=1, payload='RTNETLINK answers: No such device\n')
        state = mgr.exit_link_status('awg2')
        self.assertFalse(state['up'])
        self.assertIsNone(state['handshake_age'])
        self.assertIn('No such device', state['error'])
        self.assertEqual(ssh.direct_reads, 0)

    def test_no_exit_block_falls_back_to_direct_read(self):
        ssh, mgr = self._prefetch(exit_protocols=())
        state = mgr.exit_link_status('awg2', now=1700000005)
        self.assertIsNotNone(state)
        self.assertEqual(ssh.direct_reads, 1,
                         'direct read expected when the prefetch has no exit block')

    def test_composite_maps_a_missing_file_to_rc_nine(self):
        # Pin the shell text: `test -f` answers 1, while the direct path uses
        # `|| exit 9`. Without this mapping "no link file" would be reported as
        # a probe error instead of None.
        source = (ROOT / 'managers' / 'awg_manager.py').read_text(encoding='utf-8')
        self.assertIn('else rc=9; fi', source)
        self.assertNotIn('test -f {EXIT_CONF}; rc=$?;', source)
        ssh, _mgr = self._prefetch(link_rc=9)
        cmd = [c for c in ssh.commands if c.startswith('for c in ')][0]
        self.assertIn('else rc=9; fi', cmd)

    def test_exit_block_is_emitted_only_for_flagged_instances(self):
        ssh, _mgr = self._prefetch(exit_protocols=())
        cmd = [c for c in ssh.commands if c.startswith('for c in ')][0]
        self.assertNotIn('@@EXIT_', cmd)
        self.assertNotIn('exit0.conf', cmd)


if __name__ == '__main__':
    unittest.main()
