"""Multi-IP (key sharing) detection.

The same AmneziaWG key works on unlimited devices at once — WireGuard has no
single-session limit — so key sharing is detected by watching each peer's
public endpoint: if the endpoint IP changes while the previous endpoint was
still observed within MULTI_IP_WINDOW seconds, the same key is very likely
online from 2+ places simultaneously. A clean network switch (Wi-Fi -> LTE)
usually shows a gap between endpoints and must NOT alert.
"""
import json
import time
import unittest
from unittest import mock

from managers import awg_manager
from managers.awg_manager import AWGManager


def show_output(endpoints):
    """Build 'awg show' text for peers {tunnel_ip: endpoint_host or None}."""
    lines = ['interface: awg0', '  listening port: 55424', '']
    for ip, ep in endpoints.items():
        lines.append('peer: KEY_' + ip.replace('.', '_'))
        if ep:
            lines.append(f'  endpoint: {ep}:51820')
        lines.append(f'  allowed ips: {ip}/32')
        lines.append('  latest handshake: 30 seconds ago')
        lines.append('')
    return '\n'.join(lines)


def fake_ssh(show_out, state=None):
    """ssh mock: 'awg show' -> show_out; cat multi_ip.json -> state."""
    ssh = mock.Mock()

    def sudo(command, timeout=60):
        if 'awg show' in command:
            return show_out, '', 0
        if 'multi_ip.json' in command and command.strip().startswith('docker exec'):
            if state is None:
                return '', 'cat: No such file', 1
            return json.dumps(state), '', 0
        return '', '', 1

    def upload(content, remote):
        state['__uploaded__'] = json.loads(content)

    ssh.run_sudo_command = sudo
    ssh.upload_file = upload
    ssh.run_command = mock.Mock()
    return ssh


def manager(ssh):
    return AWGManager(ssh)


class MultiIpDetectionTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.patcher = mock.patch.object(awg_manager.time, 'time',
                                         return_value=self.now)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_first_observation_records_no_alert(self):
        ssh = fake_ssh(show_output({'10.8.1.5': '1.1.1.1'}))
        mgr = manager(ssh)
        saved = {}
        ssh.upload_file = lambda content, remote: saved.update(
            {'state': json.loads(content)})
        changed = mgr.detect_multi_ip_use('awg')
        self.assertTrue(changed)  # 'seen' was written
        self.assertEqual(saved['state']['seen']['10.8.1.5']['endpoint'],
                         '1.1.1.1')
        self.assertEqual(saved['state']['alerts'], {})

    def test_same_endpoint_no_alert(self):
        state = {'seen': {'10.8.1.5': {'endpoint': '1.1.1.1',
                                       'ts': self.now - 600}},
                 'alerts': {}}
        ssh = fake_ssh(show_output({'10.8.1.5': '1.1.1.1'}), state)
        mgr = manager(ssh)
        saved = {}
        ssh.upload_file = lambda content, remote: saved.update(
            {'state': json.loads(content)})
        changed = mgr.detect_multi_ip_use('awg')
        self.assertFalse(changed)
        self.assertEqual(saved.get('state', state)['alerts'], {})

    def test_endpoint_change_within_window_alerts(self):
        state = {'seen': {'10.8.1.5': {'endpoint': '1.1.1.1',
                                       'ts': self.now - 600}},
                 'alerts': {}}
        ssh = fake_ssh(show_output({'10.8.1.5': '2.2.2.2'}), state)
        mgr = manager(ssh)
        # capture what would be saved
        saved = {}
        ssh.upload_file = lambda content, remote: saved.update(
            {'state': json.loads(content)})
        changed = mgr.detect_multi_ip_use('awg')
        self.assertTrue(changed)
        self.assertEqual(saved['state']['alerts']['10.8.1.5'],
                         [{'ts': self.now, 'ips': ['1.1.1.1', '2.2.2.2']}])

    def test_endpoint_change_after_window_no_alert(self):
        state = {'seen': {'10.8.1.5': {'endpoint': '1.1.1.1',
                                       'ts': self.now - 7200}},
                 'alerts': {}}
        ssh = fake_ssh(show_output({'10.8.1.5': '2.2.2.2'}), state)
        mgr = manager(ssh)
        saved = {}
        ssh.upload_file = lambda content, remote: saved.update(
            {'state': json.loads(content)})
        changed = mgr.detect_multi_ip_use('awg')
        self.assertFalse(changed)
        self.assertEqual(saved.get('state', state)['alerts'], {})

    def test_coolown_merges_into_open_alert(self):
        state = {'seen': {'10.8.1.5': {'endpoint': '2.2.2.2',
                                       'ts': self.now - 600}},
                 'alerts': {'10.8.1.5': [{'ts': self.now - 1200,
                                          'ips': ['1.1.1.1', '2.2.2.2']}]}}

        def sudo(command, timeout=60):
            if 'awg show' in command:
                return show_output({'10.8.1.5': '3.3.3.3'}), '', 0
            if 'multi_ip.json' in command:
                return json.dumps(state), '', 0
            return '', '', 1

        ssh = mock.Mock()
        ssh.run_sudo_command = sudo
        saved = {}
        ssh.upload_file = lambda content, remote: saved.update(
            {'state': json.loads(content)})
        ssh.run_command = mock.Mock()
        changed = manager(ssh).detect_multi_ip_use('awg')
        self.assertTrue(changed)
        events = saved['state']['alerts']['10.8.1.5']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['ips'], ['1.1.1.1', '2.2.2.2', '3.3.3.3'])

    def test_show_failure_is_silent(self):
        ssh = fake_ssh('', None)
        self.assertFalse(manager(ssh).detect_multi_ip_use('awg'))

    def test_endpoint_parsing_strips_port_and_brackets(self):
        show = ('interface: awg0\n\n'
                'peer: K1\n'
                '  endpoint: [2001:db8::1]:51820\n'
                '  allowed ips: 10.8.1.5/32, fd42::5/128\n\n'
                'peer: K2\n'
                '  allowed ips: 10.8.1.6/32\n')
        ssh = fake_ssh(show)
        endpoints = manager(ssh)._collect_peer_endpoints('awg')
        self.assertEqual(endpoints, {'10.8.1.5': '2001:db8::1'})


if __name__ == '__main__':
    unittest.main()
