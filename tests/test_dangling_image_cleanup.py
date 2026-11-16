"""Rebuilds must not pile up dangling images.

`docker build -t <fixed name>` moves the tag and leaves the previous image
behind as `<none>:<none>`; nothing ever removed it, so every reinstall leaked
one image. The installer now records the old ID before the build and drops
exactly that image after a successful rebuild - never a shared image, and
never when the old ID is still used by a container.
"""

import unittest
from unittest import mock

from managers import docker_image_cleanup
from managers.wireguard_manager import WireGuardManager

OLD_ID = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
NEW_ID = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'


class ScriptedSSH:
    """Minimal SSH fake: answers by command prefix, records everything."""

    def __init__(self, answers=None):
        self.commands = []
        self.answers = answers or {}
        self.uploads = {}

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_script(self, script, timeout=120):
        self.commands.append(script)
        return '', '', 0

    def upload_file_sudo(self, content, path):
        self.uploads[path] = content

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        for prefix, answer in self.answers.items():
            if command.startswith(prefix):
                return answer(command, timeout) if callable(answer) else answer
        return '', '', 0


def inspector(current):
    """Answer `docker image inspect` with `current` (None = missing)."""
    def answer(command, timeout=60):
        return (current + '\n', '', 0) if current else ('', 'No such image', 1)
    return answer


class DropReplacedImageTests(unittest.TestCase):
    def test_removes_old_image_after_successful_rebuild(self):
        ssh = ScriptedSSH({
            'docker image inspect': inspector(NEW_ID),
            'docker ps -aq': ('', '', 0),
            'docker rmi': ('', '', 0),
        })
        self.assertTrue(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', OLD_ID))
        self.assertIn('docker rmi %s' % OLD_ID, ssh.commands)

    def test_no_previous_image_nothing_to_do(self):
        ssh = ScriptedSSH({'docker image inspect': inspector(NEW_ID)})
        self.assertFalse(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', None))
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))

    def test_skips_when_image_id_did_not_change(self):
        ssh = ScriptedSSH({
            'docker image inspect': inspector(OLD_ID),
            'docker rmi': ('', '', 0),
        })
        self.assertFalse(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', OLD_ID))
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))

    def test_skips_when_old_image_still_used_by_a_container(self):
        ssh = ScriptedSSH({
            'docker image inspect': inspector(NEW_ID),
            'docker ps -aq': ('deadbeef\n', '', 0),
            'docker rmi': ('', '', 0),
        })
        self.assertFalse(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', OLD_ID))
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))

    def test_failed_rmi_never_raises(self):
        ssh = ScriptedSSH({
            'docker image inspect': inspector(NEW_ID),
            'docker ps -aq': ('', '', 0),
            'docker rmi': ('', 'conflict', 1),
        })
        self.assertFalse(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', OLD_ID))

    def test_unknown_container_state_keeps_the_image(self):
        ssh = ScriptedSSH({
            'docker image inspect': inspector(NEW_ID),
            'docker ps -aq': ('', 'daemon error', 1),
        })
        self.assertFalse(docker_image_cleanup.drop_replaced_image(
            ssh, 'amnezia-wireguard', OLD_ID))
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))


class WireGuardRebuildTests(unittest.TestCase):
    def setUp(self):
        self._sleep = mock.patch('time.sleep', lambda seconds: None)
        self._sleep.start()

    def tearDown(self):
        self._sleep.stop()

    def _install(self, build_code=0, containers=''):
        ssh = ScriptedSSH({'docker ps -aq': (containers, '', 0),
                           'docker rmi': ('', '', 0)})
        state = {'built': False}

        def run_sudo_command(command, timeout=60):
            ssh.commands.append(command)
            if command.startswith('docker image inspect'):
                # old ID before the build, new ID once the tag moved
                return (OLD_ID if not state['built'] else NEW_ID) + '\n', '', 0
            if command.startswith('docker build'):
                state['built'] = build_code == 0
                return '', '' if build_code == 0 else 'build failed', build_code
            for prefix, answer in ssh.answers.items():
                if command.startswith(prefix):
                    return answer(command, timeout) if callable(answer) else answer
            return '', '', 0

        ssh.run_sudo_command = run_sudo_command
        manager = WireGuardManager(ssh)
        try:
            manager.install_protocol(port=55555)
        except RuntimeError:
            pass
        return ssh

    def test_successful_rebuild_drops_the_previous_image(self):
        ssh = self._install(build_code=0)
        self.assertIn('docker rmi %s' % OLD_ID, ssh.commands)
        self.assertLess(ssh.commands.index('docker build --no-cache --pull -t '
                                           'amnezia-wireguard /opt/amnezia/amnezia-wireguard'),
                        ssh.commands.index('docker rmi %s' % OLD_ID))

    def test_failed_build_keeps_the_previous_image(self):
        ssh = self._install(build_code=1)
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))

    def test_rebuild_keeps_image_used_by_another_container(self):
        ssh = self._install(build_code=0, containers='c0ffee\n')
        self.assertFalse(any(c.startswith('docker rmi') for c in ssh.commands))


if __name__ == '__main__':
    unittest.main()
