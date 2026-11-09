"""WARP credentials must never enter a protocol backup archive."""

import unittest

from managers.backup_manager import BackupManager


class FakeSSH:
    """Records the script and answers like a successful remote run."""

    def __init__(self):
        self.scripts = []

    def run_sudo_script(self, script, timeout=120):
        self.scripts.append(script)
        return ('/opt/amnezia/backups/awg/awg-20260101T000000Z.tar.gz', '', 0)

    def find(self, needle):
        return [script for script in self.scripts if needle in script]


class WarpExcludeTests(unittest.TestCase):
    def _script(self, protocol, container='amnezia-awg3'):
        ssh = FakeSSH()
        result = BackupManager(ssh).create_backup(protocol, container)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(ssh.scripts), 1)
        return ssh.scripts[0]

    def test_warp_credentials_are_removed_before_the_archive_is_built(self):
        script = self._script('awg3')
        cleanup = script.index(
            'rm -rf "$root/opt/amnezia/awg/warp" "$root/opt/amnezia/exit/warp"'
        )
        marker = script.index('rm -f "$root/opt/amnezia/awg/"warp-link-*')
        archive = script.index('tar -C "$work_dir"')
        self.assertLess(cleanup, archive)
        self.assertLess(marker, archive)
        # The clean-up runs for both staging trees.
        self.assertIn(
            'for root in "$work_dir/host" "$work_dir/container"; do', script,
        )

    def test_non_awg_protocol_still_gets_the_harmless_cleanup(self):
        script = self._script('xray', 'amnezia-xray')
        archive = script.index('tar -C "$work_dir"')
        self.assertLess(script.index(
            'rm -rf "$root/opt/amnezia/awg/warp" "$root/opt/amnezia/exit/warp"'
        ), archive)
        self.assertLess(script.index('rm -f "$root/opt/amnezia/awg/"warp-link-*'), archive)


if __name__ == '__main__':
    unittest.main()
