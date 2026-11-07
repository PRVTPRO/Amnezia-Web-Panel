"""Unit tests for AWGManager.enable_docker_ipv6.

No SSH and no network are used. The ssh handle is a Mock. Every remote
command is served by a dispatcher that answers from the command text.
The tests pin the failure order, the base64 daemon.json write and the
restart/recovery path.
"""
import base64
import json
import unittest
from unittest.mock import Mock, patch

from managers.awg_manager import AWGManager


def make_manager(docker_info=None, host_info=None):
    manager = AWGManager(Mock())
    manager._docker_ipv6_info = Mock(return_value=docker_info or {
        'flags_conflict': False, 'ip6tables_ok': True})
    manager._host_ipv6_info = Mock(return_value=host_info or {
        'disabled_by_sysctl': False})
    return manager


class EnableDockerIpv6Tests(unittest.TestCase):
    def _manager(self, version_out='20.10.24', version_code=0,
                 bridge_out='true', script_code=0, daemon='{}'):
        """Manager whose remote steps are scripted by command text."""
        manager = make_manager()
        calls = []

        def sudo(command, *args, **kwargs):
            calls.append(command)
            if 'cat /etc/docker/daemon.json' in command:
                return (daemon, '', 0)
            if "docker version --format" in command:
                return (version_out, '', version_code)
            if 'docker network inspect bridge' in command:
                return (bridge_out, '', 0)
            return ('', '', 0)

        manager.ssh.run_sudo_command.side_effect = sudo
        manager.ssh.run_sudo_script = Mock(return_value=('', '', script_code))
        return manager, calls

    def test_flags_conflict_raises_before_any_restart(self):
        manager = make_manager(docker_info={'flags_conflict': True})
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'docker_flags_conflict')
        manager.ssh.run_sudo_command.assert_not_called()
        manager.ssh.run_sudo_script.assert_not_called()

    def test_disabled_by_sysctl_raises_before_any_write(self):
        manager = make_manager(host_info={'disabled_by_sysctl': True})
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'ipv6_disabled_by_sysctl')
        manager.ssh.run_sudo_command.assert_not_called()
        manager.ssh.run_sudo_script.assert_not_called()

    def test_restart_false_returns_pending_and_writes_daemon_json(self):
        manager, calls = self._manager()
        result = manager.enable_docker_ipv6(restart=False)
        self.assertEqual(result, {'pending': True})
        self.assertEqual(manager.ssh.run_sudo_script.call_count, 1)
        script = manager.ssh.run_sudo_script.call_args[0][0]
        self.assertIn('base64 -d', script)
        encoded = script.split("printf '%s' '", 1)[1].split("' | base64 -d", 1)[0]
        config = json.loads(base64.b64decode(encoded).decode())
        self.assertTrue(config['ipv6'])
        self.assertTrue(config['experimental'])
        self.assertEqual(config['fixed-cidr-v6'], 'fd00:42::/64')
        self.assertTrue(config['ip6tables'])
        self.assertNotIn('systemctl restart docker', calls)

    def test_restart_true_happy_path_returns_pending_false(self):
        manager, calls = self._manager()
        with patch('managers.awg_manager.time.sleep') as sleep:
            result = manager.enable_docker_ipv6(restart=True)
        self.assertEqual(result, {'pending': False})
        sleep.assert_not_called()
        self.assertEqual(sum(1 for c in calls
                             if c == 'systemctl restart docker'), 1)
        self.assertTrue(any("docker version --format" in c for c in calls))
        self.assertTrue(any("docker network inspect bridge" in c
                            for c in calls))

    def test_docker_version_never_answers_restores_backup_and_raises(self):
        manager, calls = self._manager(version_out='', version_code=1)
        with patch('managers.awg_manager.time.sleep') as sleep:
            with self.assertRaises(RuntimeError) as ctx:
                manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'docker_recovery_failed')
        self.assertEqual(sleep.call_count, 10)
        self.assertTrue(any('cp -f /etc/docker/daemon.json.bak' in c
                            for c in calls))
        self.assertEqual(sum(1 for c in calls
                             if c == 'systemctl restart docker'), 2)

    def test_bridge_stays_false_raises(self):
        manager, _calls = self._manager(bridge_out='false')
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'docker_bridge_ipv6_missing')

    def test_run_sudo_script_failure_raises_without_restart(self):
        manager, calls = self._manager(script_code=1)
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=True)
        self.assertEqual(str(ctx.exception), 'daemon_json_invalid')
        self.assertNotIn('systemctl restart docker', calls)


if __name__ == '__main__':
    unittest.main()
