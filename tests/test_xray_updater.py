"""XrayManager.update_core: rebuild, recreate, verify, roll back.

No SSH and no Docker: every remote command is served by a fake that keeps
just enough state (the running container, its version, the node arch) for
the update flow to traverse. The tests pin the build arguments, the
container recreation parameters, the backup-tag lifecycle and the rollback.
"""

import json
import re
import unittest

from managers.xray_manager import XrayManager

SERVER_JSON = {
    'log': {'loglevel': 'error'},
    'inbounds': [
        {
            'port': 443,
            'protocol': 'vless',
            'tag': 'proxy',
            'settings': {'clients': [], 'decryption': 'none'},
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'dest': 'yahoo.com:443',
                    'serverNames': ['yahoo.com'],
                    'privateKey': 'priv',
                    'shortIds': ['abcd1234'],
                },
            },
        },
    ],
    'outbounds': [{'protocol': 'freedom'}],
}


def version_output(version):
    return (f"Xray {version} (Xray, Penetrates All Firewall) "
            f"Custom (go1.24 linux/amd64)\n"
            f"Announcement...\n")


class FakeSSH:
    """Stateful fake: a running container, its version, the node arch."""

    def __init__(self, container_version='26.10.31', arch='x86_64'):
        self.container_version = container_version
        self.image_version = container_version
        self.arch = arch
        self.container_running = True
        self.fail_new_start = False
        self.run_count = 0
        self.commands = []
        self.scripts = []
        self.uploads = []
        self.files = {
            '/opt/amnezia/xray/server.json': json.dumps(SERVER_JSON),
            '/opt/amnezia/xray/xray_private.key': 'priv\n',
            '/opt/amnezia/xray/xray_public.key': 'pub\n',
            '/opt/amnezia/xray/xray_short_id.key': 'abcd1234\n',
            '/opt/amnezia/xray/xray_uuid.key': '\n',
            '/opt/amnezia/xray/clientsTable': '[]',
        }

    def upload_file_sudo(self, content, remote_path):
        self.uploads.append((content, remote_path))
        self.files[remote_path] = content
        return True

    def run_sudo_script(self, script, **kwargs):
        self.scripts.append(script.strip())
        return '', '', 0

    def run_command(self, command, **kwargs):
        self.commands.append(command.strip())
        if 'uname' in command:
            return self.arch + '\n', '', 0
        return '', '', 0

    def run_sudo_command(self, command, **kwargs):
        cmd = command.strip()
        self.commands.append(cmd)
        if cmd.startswith('sleep'):
            return '', '', 0
        if 'docker run --rm' in cmd:
            # The freshly built image: the build args decide the version.
            match = re.search(r'XRAY_RELEASE=(\S+)', ' '.join(self.commands))
            target = (match.group(1) if match else self.image_version).lstrip('v')
            return version_output(target), '', 0
        if 'xray version' in cmd:
            return version_output(self.container_version), '', 0
        if 'docker ps --filter' in cmd:
            return ('Up 2 minutes', '', 0) if self.container_running else ('', '', 0)
        if 'docker build' in cmd:
            match = re.search(r'XRAY_RELEASE=(\S+)', cmd)
            if match:
                self.image_version = match.group(1).lstrip('v')
            return '', '', 0
        if cmd.startswith('docker run -d'):
            self.run_count += 1
            self.container_running = not self.fail_new_start
            self.container_version = self.image_version
            return '', '', 0
        if ' cat ' in cmd:
            path = cmd.rsplit(' cat ', 1)[-1].split(' 2>', 1)[0].strip()
            return (self.files.get(path, ''), '', 0)
        if cmd.startswith('ls -1'):
            dir_path = cmd.split()[2]
            names = [p[len(dir_path):].lstrip('/')
                     for p in self.files if p.startswith(dir_path + '/')]
            return ('\n'.join(sorted(names)), '', 0)
        return '', '', 0


class UpdateCoreTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.mgr = XrayManager(self.ssh)
        self.image = 'amneziavpn/amnezia-xray'

    def update(self, target='v26.11.7'):
        return self.mgr.update_core(target, progress=lambda s, m: None)

    def docker_cmd(self, marker):
        return [c for c in self.ssh.commands
                if c.startswith('docker') and marker in c]

    def bbr_scripts(self):
        return [script for script in self.ssh.scripts if 'tcp_bbr' in script]

    def test_core_version_is_parsed_from_container_output(self):
        self.assertEqual(self.mgr.get_core_version(), '26.10.31')

    def test_same_version_skips_the_rebuild(self):
        result = self.update('v26.10.31')
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['updated'])
        self.assertEqual(self.docker_cmd('docker build'), [])

    def test_update_rebuilds_and_recreates_the_container(self):
        result = self.update('v26.11.7')
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['updated'])
        self.assertEqual(result['version'], '26.11.7')
        self.assertEqual(result['previous'], '26.10.31')

        builds = self.docker_cmd('docker build')
        self.assertEqual(len(builds), 1)
        self.assertIn('--build-arg XRAY_RELEASE=v26.11.7', builds[0])
        self.assertIn('--build-arg XRAY_ARCH=64', builds[0])
        self.assertIn(self.image, builds[0])

        runs = [c for c in self.ssh.commands if c.startswith('docker run -d')]
        self.assertEqual(len(runs), 1)
        self.assertIn('-p 443:443/tcp', runs[0])
        self.assertIn('-v /opt/amnezia/xray:/opt/amnezia/xray', runs[0])
        self.assertIn('--name amnezia-xray', runs[0])
        self.assertIn(self.image, runs[0])

    def test_update_applies_host_bbr_tuning(self):
        # Installs from before the BBR change never tuned the host: the
        # update flow closes that gap idempotently.
        self.update('v26.11.7')
        self.assertEqual(len(self.bbr_scripts()), 1)

    def test_same_version_still_applies_host_bbr_tuning(self):
        # Even a no-op update heals a pre-BBR install.
        result = self.update('v26.10.31')
        self.assertFalse(result['updated'])
        self.assertEqual(len(self.bbr_scripts()), 1)

    def test_backup_tag_lives_until_the_new_core_is_verified(self):
        self.update('v26.11.7')
        tag_commands = [c for c in self.ssh.commands if 'docker tag' in c]
        rmi_commands = [c for c in self.ssh.commands if 'docker rmi' in c]
        self.assertEqual(tag_commands, [f'docker tag {self.image} {self.image}:previous'])
        self.assertEqual(rmi_commands, [f'docker rmi {self.image}:previous'])

    def test_uploaded_dockerfile_pins_the_target_release(self):
        self.update('v26.11.7')
        dockerfiles = [content for content, path in self.ssh.uploads
                       if path.endswith('/Dockerfile')]
        self.assertEqual(len(dockerfiles), 1)
        self.assertIn('ARG XRAY_RELEASE="v26.11.7"', dockerfiles[0])

    def test_rollback_when_the_new_core_does_not_start(self):
        self.ssh.fail_new_start = True
        result = self.update('v26.11.7')
        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['updated'])
        self.assertEqual(result['version'], '26.10.31')
        self.assertIn('26.10.31', result['message'])
        self.assertIn('running again', result['message'])
        # The old image is retagged as the current one and the container
        # is started again from it.
        self.assertIn(f'docker tag {self.image}:previous {self.image}',
                      self.ssh.commands)
        runs = [c for c in self.ssh.commands if c.startswith('docker run -d')]
        self.assertEqual(len(runs), 2)
        # No backup cleanup on a failed update.
        self.assertEqual(self.docker_cmd('docker rmi'), [])

    def test_arm64_node_gets_the_arm64_archive(self):
        self.ssh.arch = 'aarch64'
        self.update('v26.11.7')
        dockerfiles = [content for content, path in self.ssh.uploads
                       if path.endswith('/Dockerfile')]
        self.assertIn('ARG XRAY_ARCH="arm64-v8a"', dockerfiles[0])
        self.assertIn('--build-arg XRAY_ARCH=arm64-v8a',
                      self.docker_cmd('docker build')[0])

    def test_unknown_arch_falls_back_to_x64(self):
        self.ssh.arch = 'riscv64'
        self.update('v26.11.7')
        dockerfiles = [content for content, path in self.ssh.uploads
                       if path.endswith('/Dockerfile')]
        self.assertIn('ARG XRAY_ARCH="64"', dockerfiles[0])


class ArchMapTests(unittest.TestCase):
    def test_known_machines_map_to_xray_assets(self):
        from managers.xray_manager import XRAY_ARCH_ZIPS
        self.assertEqual(XRAY_ARCH_ZIPS['x86_64'], '64')
        self.assertEqual(XRAY_ARCH_ZIPS['aarch64'], 'arm64-v8a')
        self.assertEqual(XRAY_ARCH_ZIPS['armv7l'], 'arm32-v7a')


if __name__ == '__main__':
    unittest.main()
