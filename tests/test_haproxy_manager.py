"""HaproxyManager: install, config edit with validation, status, dispatch.

No SSH and no Docker: every remote command is answered by a fake that keeps
an in-memory filesystem and tracks container state.
"""

import json
import unittest
from unittest import mock

from managers.haproxy_manager import HaproxyManager


class FakeSSH:
    """Command-substring driven fake with a small in-memory filesystem."""

    def __init__(self, haproxy_check_code=0, running=True):
        self.haproxy_check_code = haproxy_check_code
        self.container_running = running
        self.container_exists = running
        self.files = {}
        self.commands = []
        self.uploads = []
        self.restarts = 0
        self.runs = 0
        self.removed = 0

    def run_command(self, command, *args, **kwargs):
        self.commands.append(command)
        if 'docker --version' in command:
            return 'Docker version 24.0.0', '', 0
        return 'active', '', 0

    def run_sudo_command(self, command, *args, **kwargs):
        cmd = command.strip()
        self.commands.append(cmd)
        if cmd.startswith('docker run -d'):
            self.runs += 1
            self.container_running = True
            self.container_exists = True
            return '', '', 0
        if cmd.startswith('docker restart'):
            self.restarts += 1
            return '', '', 0
        if cmd.startswith('docker stop'):
            self.container_running = False
            return '', '', 0
        if cmd.startswith('docker rm -fv'):
            self.removed += 1
            self.container_exists = False
            return '', '', 0
        if 'haproxy -c -f' in cmd:
            err = 'config error' if self.haproxy_check_code != 0 else ''
            return err, err, self.haproxy_check_code
        if cmd.startswith('docker exec') and ' cat ' in cmd:
            path = cmd.rsplit(' cat ', 1)[-1].split(' 2>', 1)[0].strip()
            return (self.files.get(path, ''), '', 0)
        if cmd.startswith('cat '):
            path = cmd.split(' ', 1)[1].split(' 2>', 1)[0].strip()
            return (self.files.get(path, ''), '', 0)
        if 'docker ps -a --filter' in cmd:
            return ('amnezia-haproxy', '', 0) if self.container_exists else ('', '', 0)
        if 'docker ps --filter' in cmd:
            return ('Up 2 minutes', '', 0) if self.container_running else ('', '', 0)
        if cmd.startswith('mkdir -p'):
            return '', '', 0
        if cmd.startswith('rm -rf'):
            self.files = {k: v for k, v in self.files.items()
                          if not k.startswith('/opt/amnezia/haproxy')}
            return '', '', 0
        return '', '', 0

    def upload_file_sudo(self, content, remote_path):
        self.uploads.append((content, remote_path))
        self.files[remote_path] = content
        return True


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.mgr = HaproxyManager(self.ssh)

    def test_install_writes_config_runs_container_and_reports(self):
        result = self.mgr.install_protocol('haproxy', port=8080)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['port'], 8080)
        self.assertEqual(self.ssh.runs, 1)

        run = [c for c in self.ssh.commands if c.startswith('docker run -d')][0]
        self.assertIn('-p 8080:8080/tcp', run)
        self.assertIn('--name amnezia-haproxy', run)
        self.assertIn('-v /opt/amnezia/haproxy/conf:', run)

        cfg = self.ssh.files['/opt/amnezia/haproxy/conf/haproxy.cfg']
        self.assertIn('bind *:8080', cfg)
        meta = json.loads(self.ssh.files['/opt/amnezia/haproxy/metadata.json'])
        self.assertEqual(meta['port'], 8080)

    def test_install_replaces_an_existing_container(self):
        self.mgr.install_protocol('haproxy', port=8080)
        self.mgr.install_protocol('haproxy', port=8081)
        # One stop/rm cycle from the pre-install cleanup plus nothing else:
        # a single container is serving at the end.
        self.assertEqual(self.ssh.runs, 2)
        self.assertGreaterEqual(self.ssh.removed, 1)
        meta = json.loads(self.ssh.files['/opt/amnezia/haproxy/metadata.json'])
        self.assertEqual(meta['port'], 8081)

    def test_install_without_docker_is_an_error(self):
        self.ssh.commands = []
        with mock.patch.object(HaproxyManager, 'check_docker_installed',
                               return_value=False):
            result = self.mgr.install_protocol('haproxy', port=8080)
        self.assertEqual(result['status'], 'error')

    def test_remove_container_cleans_up(self):
        self.mgr.install_protocol('haproxy', port=8080)
        # install_protocol already tore down the pre-existing container once.
        self.assertEqual(self.ssh.removed, 1)
        self.mgr.remove_container('haproxy')
        self.assertEqual(self.ssh.removed, 2)
        self.assertFalse(self.ssh.container_exists)
        self.assertFalse([k for k in self.ssh.files
                          if k.startswith('/opt/amnezia/haproxy')])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.ssh.files['/opt/amnezia/haproxy/conf/haproxy.cfg'] = 'defaults\n    timeout connect 5s\n'
        self.ssh.files['/opt/amnezia/haproxy/metadata.json'] = json.dumps({'port': 8080})
        self.mgr = HaproxyManager(self.ssh)

    def test_save_rewrites_the_config_and_restarts_when_running(self):
        self.mgr.save_server_config('haproxy', 'global\n    daemon\n')
        self.assertEqual(self.ssh.files['/opt/amnezia/haproxy/conf/haproxy.cfg'],
                         'global\n    daemon\n')
        self.assertEqual(self.ssh.restarts, 1)
        validate = [c for c in self.ssh.commands if 'haproxy -c -f' in c]
        self.assertEqual(len(validate), 1)
        self.assertIn('docker exec amnezia-haproxy', validate[0])

    def test_invalid_config_is_rejected_and_restored(self):
        self.ssh.haproxy_check_code = 1
        with self.assertRaises(RuntimeError):
            self.mgr.save_server_config('haproxy', 'global\n    oops\n')
        self.assertEqual(self.ssh.files['/opt/amnezia/haproxy/conf/haproxy.cfg'],
                         'defaults\n    timeout connect 5s\n')
        self.assertEqual(self.ssh.restarts, 0)

    def test_save_while_stopped_skips_validation_and_restart(self):
        self.ssh.container_running = False
        self.mgr.save_server_config('haproxy', 'global\n    daemon\n')
        self.assertEqual(self.ssh.restarts, 0)
        self.assertEqual(self.ssh.files['/opt/amnezia/haproxy/conf/haproxy.cfg'],
                         'global\n    daemon\n')

    def test_get_config_falls_back_to_the_container_copy(self):
        self.ssh.files.pop('/opt/amnezia/haproxy/conf/haproxy.cfg')
        config = self.mgr.get_config('haproxy')
        cat = [c for c in self.ssh.commands
               if 'docker exec amnezia-haproxy cat' in c]
        self.assertEqual(len(cat), 1)
        self.assertIn('/usr/local/etc/haproxy/haproxy.cfg', cat[0])
        self.assertEqual(config, '')  # the fake filesystem has no container copy

    def test_status_reports_meta_port_and_running_state(self):
        status = self.mgr.get_server_status('haproxy')
        self.assertTrue(status['container_exists'])
        self.assertTrue(status['container_running'])
        self.assertEqual(status['port'], 8080)
        self.assertEqual(status['base_protocol'], 'haproxy')


class DispatchTests(unittest.TestCase):
    def test_haproxy_is_a_known_protocol_and_dispatches_to_its_manager(self):
        import app
        self.assertIn('haproxy', app.BASE_PROTOCOLS)
        manager = app.get_protocol_manager(mock.Mock(), 'haproxy')
        self.assertIsInstance(manager, HaproxyManager)
        self.assertEqual(app.protocol_container_name('haproxy'), 'amnezia-haproxy')
        self.assertEqual(app.INSTALL_PORT_TRANSPORT['haproxy'], 'tcp')
        self.assertIn('haproxy', app.PUBLIC_FORWARD_L4['tcp'])


if __name__ == '__main__':
    unittest.main()
