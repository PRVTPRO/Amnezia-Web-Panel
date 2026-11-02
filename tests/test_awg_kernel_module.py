import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager


def _render_script():
    mgr = AWGManager.__new__(AWGManager)
    mgr.ssh = Mock()
    mgr.ssh.run_sudo_script.return_value = ('KERNEL_MODULE: ok: test', '', 0)
    mgr.setup_kernel_module()
    return mgr.ssh.run_sudo_script.call_args[0][0]


class KernelModuleScriptTests(unittest.TestCase):
    """setup_kernel_module() must never break a running AWG tunnel: no
    downgrades, no unload while containers are up, and no stale DKMS tree
    entry for the target version."""

    def setUp(self):
        self.script = _render_script()

    def test_uses_version_sort_so_it_never_downgrades(self):
        self.assertIn('sort -V', self.script)
        self.assertIn('NEWEST=', self.script)

    def test_checks_running_containers_before_unloading(self):
        self.assertIn('docker ps --format', self.script)

    def test_never_unloads_module_while_containers_run(self):
        guard = self.script.index('docker ps --format')
        unload = self.script.index('modprobe -r amneziawg')
        self.assertLess(guard, unload)

    def test_removes_stale_dkms_entry_for_target_version(self):
        self.assertIn('dkms status -m amneziawg -v', self.script)
        remove = self.script.index('dkms status -m amneziawg -v')
        add = self.script.index('dkms add .')
        self.assertLess(remove, add)

    def test_builds_installs_and_loads_the_module(self):
        self.assertIn('dkms install', self.script)
        self.assertIn('modprobe amneziawg', self.script)

    def test_starts_with_newline_and_uses_real_target_version(self):
        self.assertTrue(self.script.startswith('\n'))
        self.assertIn(AWGManager.AWG_MODULE_VERSION, self.script)


if __name__ == '__main__':
    unittest.main()
