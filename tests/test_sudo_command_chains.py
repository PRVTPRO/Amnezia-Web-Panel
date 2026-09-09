"""A privileged command chain must run inside one shell.

`SSHManager.run_sudo_command` builds `echo <pw> | sudo -S -p '' <command>`, so
in `sudo a && b` only `a` is privileged: `b` runs as the panel's unprivileged
SSH user. Wherever both halves need root, the chain has to be handed to a
single `sh -c` (the pattern the rest of BackupManager already uses).
"""

import unittest

from managers.backup_manager import BackupManager
from managers.adguard_manager import AdguardManager
from managers.dns_manager import DNSManager


class RecordingSSH:
    def __init__(self, code=1):
        self.commands = []
        self.code = code

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        return '', 'not found', self.code

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        # DNSManager gates its install on this probe
        return ('Docker version 27.0.3' if 'docker --version' in command else ''), '', 0

    def write_file(self, path, content):
        pass


def chain_is_wrapped(command):
    """True when every `&&`/`||`/`|` sits inside a `sh -c`/`bash -c` argument."""
    for token in ('&&', '||', '|'):
        idx = command.find(token)
        if idx == -1:
            continue
        shell = min((command.find(s) for s in ('sh -c', 'bash -c') if command.find(s) != -1), default=-1)
        if shell == -1 or shell > idx:
            return False
    return True


class SudoChainTests(unittest.TestCase):
    def test_backup_fetch_runs_the_chain_in_one_shell(self):
        ssh = RecordingSSH()
        BackupManager(ssh)._fetch_remote_archive('/opt/amnezia/backups/awg2/awg2-2026.tar.gz')
        cmd = ssh.commands[0]
        self.assertTrue(cmd.startswith('sh -c '), cmd)
        self.assertTrue(chain_is_wrapped(cmd), cmd)
        # the copy still targets the same paths
        self.assertIn('/opt/amnezia/backups/awg2/awg2-2026.tar.gz', cmd)
        self.assertIn('chmod 0644', cmd)

    def test_dns_network_creation_runs_the_chain_in_one_shell(self):
        ssh = RecordingSSH(code=0)
        try:
            DNSManager(ssh).install_protocol()
        except Exception:
            pass
        network = [c for c in ssh.commands if 'amnezia-dns-net' in c and 'network' in c]
        self.assertTrue(network, ssh.commands)
        self.assertTrue(chain_is_wrapped(network[0]), network[0])

    def test_dns_attaches_existing_containers_in_one_shell(self):
        ssh = RecordingSSH(code=0)
        try:
            DNSManager(ssh).install_protocol()
        except Exception:
            pass
        connects = [c for c in ssh.commands if 'network connect' in c]
        self.assertTrue(connects, ssh.commands)
        for cmd in connects:
            self.assertTrue(chain_is_wrapped(cmd), cmd)
        # a representative container is among the ones attached
        self.assertTrue(any('amnezia-awg2' in c for c in connects), connects)

    def test_adguard_network_creation_runs_the_chain_in_one_shell(self):
        ssh = RecordingSSH(code=0)
        AdguardManager(ssh)._ensure_network()
        self.assertTrue(chain_is_wrapped(ssh.commands[0]), ssh.commands[0])

    def test_helper_flags_a_bare_chain(self):
        self.assertFalse(chain_is_wrapped("test -f a && cp a b"))
        self.assertTrue(chain_is_wrapped("sh -c 'test -f a && cp a b'"))


if __name__ == '__main__':
    unittest.main()
