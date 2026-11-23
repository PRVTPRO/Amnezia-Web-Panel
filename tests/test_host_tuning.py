import unittest

from managers.awg_manager import AWGManager


class FakeSSH:
    """Records which transport a caller used: a single sudo command only
    elevates its first line, a script is uploaded and run as a whole."""

    def __init__(self, script_output='', command_output=''):
        self.script_output = script_output
        self.command_output = command_output
        self.calls = []

    def run_sudo_script(self, script, timeout=120):
        self.calls.append(('script', script))
        return self.script_output, '', 0

    def run_sudo_command(self, command, timeout=60):
        self.calls.append(('command', command))
        return self.command_output, '', 0


TUNING_OUTPUT = """HOST_CC=bbr
HOST_QDISC=fq
HOST_AWG_MODULE=3.1.20260812
CT_NAME=amnezia-awg2
CT_RUNNING=1
CTK_net.core.rmem_max=26214400
CT_NAME=amnezia-exit
CT_RUNNING=0
"""


class HostTuningTests(unittest.TestCase):
    def test_reads_containers_through_a_privileged_script(self):
        ssh = FakeSSH(script_output=TUNING_OUTPUT)
        info = AWGManager(ssh).get_host_tuning()

        # the whole thing runs as one privileged script, not as `sudo <script>`
        self.assertEqual([kind for kind, _ in ssh.calls], ['script'])
        script = ssh.calls[0][1]
        self.assertIn('HOST_AWG_MODULE=', script)
        self.assertIn("grep -E '^amnezia-(awg|exit)'", script)

        self.assertEqual(info['host']['cc'], 'bbr')
        self.assertEqual(info['host']['awg_module'], '3.1.20260812')
        self.assertEqual([(c['name'], c['running']) for c in info['containers']],
                         [('amnezia-awg2', True), ('amnezia-exit', False)])
        self.assertEqual(info['containers'][0]['ct'], {'net.core.rmem_max': '26214400'})

    def test_empty_output_is_not_an_error(self):
        self.assertEqual(AWGManager(FakeSSH()).get_host_tuning(), {'host': {}, 'containers': []})


if __name__ == '__main__':
    unittest.main()
