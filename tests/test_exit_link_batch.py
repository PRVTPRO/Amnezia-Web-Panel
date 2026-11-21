"""P2: exit-link state from the /check prefetch must equal the direct read.

The prefetch runs one composite command for every running AWG container and
adds a `wg show exit0` block only for instances that have a link. These tests
pin the three outcomes the direct `exit_link_status` distinguishes — success,
"file absent" (docker exec rc 9) and "command failed" — plus the fallback when
no block was collected at all.
"""
import re
import unittest

from managers.awg_manager import AWGManager

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
            found = re.search(r'@@EXIT_[0-9a-f]+@@', cmd)
            rc_marker = re.search(r'@@EXITRC_[0-9a-f]+@@', cmd)
            if not found or not rc_marker:
                return '', '', 0
            exit_marker = found.group(0)
            container = re.search(re.escape(exit_marker) + r' ([A-Za-z0-9_.-]+)', cmd).group(1)
            out = (f'{exit_marker} {container}\n\n'
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

    def test_missing_file_answers_none_without_ssh(self):
        ssh, mgr = self._prefetch(link_rc=9)
        self.assertIsNone(mgr.exit_link_status('awg2'))
        self.assertEqual(ssh.direct_reads, 0)

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

    def test_exit_block_is_emitted_only_for_flagged_instances(self):
        ssh, _mgr = self._prefetch(exit_protocols=())
        cmd = [c for c in ssh.commands if c.startswith('for c in ')][0]
        self.assertNotIn('@@EXIT_', cmd)
        self.assertNotIn('exit0.conf', cmd)


if __name__ == '__main__':
    unittest.main()
