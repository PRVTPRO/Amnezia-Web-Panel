"""Uninstalling a protocol must not leave /opt/amnezia/<container> behind.

The directory only ever holds the generated Dockerfile (the next install
rewrites it and builds with --no-cache --pull), so a removed instance has no
reason to keep it. Failures must stay safe: if the container itself could not
be removed the build context is left untouched, so a retry still has a
consistent host state.
"""

import unittest

from managers.awg_manager import AWGManager
from managers.exit_manager import ExitManager
from managers.wireguard_manager import WireGuardManager
from managers.xray_manager import XrayManager


class FakeSSH:
    """Records every sudo command and lets a test force the docker answers."""

    def __init__(self, rm=(0, ''), ps_images=''):
        self.commands = []
        self.rm_code, self.rm_err = rm
        self.ps_images = ps_images

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'docker rm -fv' in command:
            return '', self.rm_err, self.rm_code
        if command.startswith('docker ps -a'):
            return self.ps_images, '', 0
        return '', '', 0

    def docker_ps_invalidate(self):
        self.commands.append('<docker_ps_invalidate>')


def deletes_dir(ssh, path):
    return f"rm -rf {path}" in ssh.commands


class AWGUninstallCleanupTests(unittest.TestCase):
    def test_second_instance_dir_is_removed(self):
        ssh = FakeSSH()
        AWGManager(ssh).remove_container('awg2__2')
        self.assertIn('docker rm -fv amnezia-awg2-2', ssh.commands)
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-awg2-2'))
        self.assertFalse(deletes_dir(ssh, '/opt/amnezia/amnezia-awg2'))

    def test_first_instance_dir_is_removed(self):
        ssh = FakeSSH()
        AWGManager(ssh).remove_container('awg3')
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-awg3'))

    def test_absent_container_dir_is_removed(self):
        ssh = FakeSSH(rm=(1, 'Error: No such container: amnezia-awg2'))
        AWGManager(ssh).remove_container('awg2')
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-awg2'))

    def test_failed_removal_keeps_dir_for_retry(self):
        ssh = FakeSSH(rm=(1, 'Error response from daemon: device or resource busy'))
        AWGManager(ssh).remove_container('awg2')
        self.assertFalse(deletes_dir(ssh, '/opt/amnezia/amnezia-awg2'))

    def test_exit_build_context_is_removed(self):
        ssh = FakeSSH()
        ExitManager(ssh).remove_container('exit')
        self.assertIn('docker rm -fv amnezia-exit', ssh.commands)
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-exit'))
        # transit config/peers live in /opt/amnezia/exit and must survive
        self.assertFalse(deletes_dir(ssh, '/opt/amnezia/exit'))


class WireGuardUninstallCleanupTests(unittest.TestCase):
    def test_dir_is_removed(self):
        ssh = FakeSSH()
        WireGuardManager(ssh).remove_container()
        self.assertIn('docker rm -fv amnezia-wireguard', ssh.commands)
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-wireguard'))

    def test_failed_removal_keeps_dir(self):
        ssh = FakeSSH(rm=(1, 'Error response from daemon: container is paused'))
        WireGuardManager(ssh).remove_container()
        self.assertFalse(deletes_dir(ssh, '/opt/amnezia/amnezia-wireguard'))


class XrayUninstallCleanupTests(unittest.TestCase):
    def test_second_instance_removes_its_own_image_and_dir(self):
        ssh = FakeSSH(ps_images='amnezia-xray\n')
        XrayManager(ssh, 'xray__2').remove_container()
        self.assertIn('docker rm -fv amnezia-xray-2', ssh.commands)
        self.assertIn('docker rmi amneziavpn/amnezia-xray-2', ssh.commands)
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-xray-2'))

    def test_image_kept_when_another_container_uses_it(self):
        ssh = FakeSSH(ps_images='amneziavpn/amnezia-xray-2\nother:latest\n')
        XrayManager(ssh, 'xray__2').remove_container()
        self.assertNotIn('docker rmi amneziavpn/amnezia-xray-2', ssh.commands)
        # the build context is per instance and still goes away
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-xray-2'))

    def test_first_instance_removes_image(self):
        ssh = FakeSSH()
        XrayManager(ssh, 'xray').remove_container()
        self.assertIn('docker rmi amneziavpn/amnezia-xray', ssh.commands)
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-xray'))

    def test_missing_image_is_not_an_error(self):
        ssh = FakeSSH()

        def answer(command, timeout=60):
            ssh.commands.append(command)
            if 'docker rmi' in command:
                return '', 'Error: No such image: amneziavpn/amnezia-xray-2', 1
            return '', '', 0

        ssh.run_sudo_command = answer
        XrayManager(ssh, 'xray__2').remove_container()
        self.assertTrue(deletes_dir(ssh, '/opt/amnezia/amnezia-xray-2'))

    def test_failed_container_removal_raises_and_keeps_dir(self):
        ssh = FakeSSH(rm=(1, 'Error response from daemon: driver error'))
        with self.assertRaises(RuntimeError):
            XrayManager(ssh, 'xray__2').remove_container()
        self.assertFalse(deletes_dir(ssh, '/opt/amnezia/amnezia-xray-2'))


if __name__ == '__main__':
    unittest.main()
