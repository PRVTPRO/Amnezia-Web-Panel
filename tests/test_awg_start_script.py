import os
import shutil
import subprocess
import tempfile
import unittest

from managers.awg_manager import (
    AWG3_USERSPACE_GUARD,
    AWG_QUICK_FORCE_USERSPACE_PATCH,
    AWGManager,
)

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as f:
        return f.read()


class RecordingSSH:
    def __init__(self):
        self.uploads = {}
        self.commands = []

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'for p in ' in command:  # _resolve_config_path probe
            return self.resolved_config_path + '\n', '', 0
        return '', '', 0

    resolved_config_path = ''


class GoldenBuilderTests(unittest.TestCase):
    """The fixtures pin the generated container files byte for byte, so they
    change only on purpose (originally captured from the pre-builder code;
    refreshed when the image gained iproute2/conntrack-tools and the start
    script gained the entry-side exit-node block)."""

    def test_start_script_awg(self):
        self.assertEqual(AWGManager(None)._render_start_script('awg'), fixture('start_awg.sh'))

    def test_start_script_awg3_carries_userspace_guard(self):
        script = AWGManager(None)._render_start_script('awg3')
        self.assertEqual(script, fixture('start_awg3.sh'))
        self.assertIn(AWG3_USERSPACE_GUARD, script)

    def test_start_script_legacy_uses_wg_quick(self):
        script = AWGManager(None)._render_start_script('awg_legacy')
        self.assertEqual(script, fixture('start_awg_legacy.sh'))
        self.assertIn('wg-quick up /opt/amnezia/awg/wg0.conf', script)
        self.assertNotIn('awg-quick', script)

    def test_start_script_config_path_override(self):
        script = AWGManager(None)._render_start_script('awg_legacy', config_path='/opt/amnezia/awg/awg0.conf')
        self.assertIn('wg-quick up /opt/amnezia/awg/awg0.conf', script)
        self.assertNotIn('/opt/amnezia/awg/wg0.conf', script)

    def test_dockerfile_awg(self):
        content = AWGManager._dockerfile_content('amneziavpn/amneziawg-go:latest', AWG_QUICK_FORCE_USERSPACE_PATCH)
        self.assertEqual(content, fixture('dockerfile_awg.txt'))

    def test_dockerfile_legacy_has_no_userspace_patch(self):
        content = AWGManager._dockerfile_content('amneziavpn/amnezia-wg:latest', '')
        self.assertEqual(content, fixture('dockerfile_awg_legacy.txt'))
        self.assertNotIn('WG_FORCE_USERSPACE', content)

    def test_docker_run_drops_the_duplicated_name_flag(self):
        # The only intentional difference from the old output: `--name` was
        # emitted twice, the fixture keeps the old form.
        old = fixture('docker_run_awg.txt')
        self.assertEqual(old.count('--name amnezia-awg'), 2)
        expected = old.replace('--name amnezia-awg amnezia-awg', 'amnezia-awg')

        new = AWGManager._docker_run_cmd('amnezia-awg', 'amnezia-awg', '55424', False)

        self.assertEqual(new, expected)
        self.assertEqual(new.count('--name'), 1)

    def test_docker_run_ipv6_sysctls_only_when_enabled(self):
        old = fixture('docker_run_awg_ipv6.txt')
        expected = old.replace('--name amnezia-awg amnezia-awg', 'amnezia-awg')

        new = AWGManager._docker_run_cmd('amnezia-awg', 'amnezia-awg', '55424', True)

        self.assertEqual(new, expected)
        self.assertIn('net.ipv6.conf.all.disable_ipv6=0', new)
        self.assertNotIn('disable_ipv6', AWGManager._docker_run_cmd('amnezia-awg', 'amnezia-awg', '55424', False))

    @unittest.skipUnless(shutil.which('bash'), 'bash not available')
    def test_start_scripts_parse_as_bash(self):
        for proto in ('awg', 'awg3', 'awg_legacy'):
            with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
                f.write(AWGManager(None)._render_start_script(proto))
            try:
                result = subprocess.run(['bash', '-n', f.name], capture_output=True, text=True)
            finally:
                os.unlink(f.name)
            self.assertEqual(result.returncode, 0, f'{proto}: {result.stderr}')


class StartScriptDeliveryTests(unittest.TestCase):
    def test_write_start_script_copies_and_marks_executable_without_restart(self):
        ssh = RecordingSSH()
        manager = AWGManager(ssh)

        manager._write_start_script('awg2')

        self.assertEqual(ssh.uploads['/tmp/_amnz_start.sh'], manager._render_start_script('awg2'))
        self.assertEqual(ssh.commands, [
            'docker cp /tmp/_amnz_start.sh amnezia-awg2:/opt/amnezia/start.sh',
            'docker exec amnezia-awg2 chmod +x /opt/amnezia/start.sh',
            'rm -f /tmp/_amnz_start.sh',
        ])

    def test_upload_start_script_restarts_the_container(self):
        ssh = RecordingSSH()
        manager = AWGManager(ssh)
        import managers.awg_manager as awg_module
        real_sleep = awg_module.time.sleep
        awg_module.time.sleep = lambda seconds: None
        try:
            manager._upload_start_script('awg2')
        finally:
            awg_module.time.sleep = real_sleep

        self.assertEqual(ssh.commands[-1], 'docker restart amnezia-awg2')

    def test_save_server_config_regenerates_start_script_for_resolved_path(self):
        ssh = RecordingSSH()
        manager = AWGManager(ssh)
        # Legacy container whose config actually lives at awg0.conf: the probe
        # resolves it and the start script must follow the resolved path.
        ssh.resolved_config_path = '/opt/amnezia/awg/awg0.conf'

        manager.save_server_config('awg_legacy', '[Interface]\nAddress = 10.8.1.1/24\n')

        script = ssh.uploads['/tmp/_amnz_start.sh']
        self.assertEqual(script, manager._render_start_script('awg_legacy', '/opt/amnezia/awg/awg0.conf'))
        self.assertIn('docker cp /tmp/_amnz_edit_config.conf amnezia-awg-legacy:/opt/amnezia/awg/awg0.conf', ssh.commands)
        self.assertEqual(ssh.commands[-1], 'docker restart amnezia-awg-legacy')


if __name__ == '__main__':
    unittest.main()
