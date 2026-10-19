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
        # The endpoint rotated, so 'seen'/history were updated (changed=True)
        # but no alert may be recorded: the previous endpoint is stale.
        self.assertTrue(changed)
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


# conntrack lines as they appear on the hosts: no accounting (no
# packets=/bytes=), reply tuple right after the original one.
FLOW_LINE = ('ipv4     2 udp      17 {timeout} src={src} dst=46.183.21.61 '
             'sport={sport} dport=55424 src=46.183.21.61 dst={src} '
             'sport=55424 dport={sport} mark=0 zone=0 use=2')


def conntrack(flows):
    return '\n'.join(FLOW_LINE.format(**f) for f in flows) + '\n'


def sim_ssh(state, flows1, flows2, host='10.255.0.1'):
    """Scripted ssh: cat multi_ip.json -> state, then nf_conntrack greps."""
    ssh = mock.Mock()
    ssh.host = host
    samples = iter([flows1, flows2])

    def sudo(command, timeout=60):
        if 'multi_ip.json' in command:
            if state is None:
                return '', 'No such file', 1
            return json.dumps(state), '', 0
        if 'nf_conntrack' in command:
            return next(samples), '', 0
        return '', '', 1

    ssh.run_sudo_command = sudo
    saved = {}
    ssh.upload_file = lambda content, remote: saved.update(
        {'state': json.loads(content)})
    ssh.run_command = mock.Mock()
    ssh.__dict__['saved'] = saved
    return ssh


class SimultaneousUseTests(unittest.TestCase):
    """Per-peer attribution: two legit users online at once is NOT sharing.

    Regression for the instance-level bug: the detector used to count any
    two active flows on the instance port as key sharing, so every busy
    instance (two users with different keys online) would raise a false
    CONFIRMED event.
    """

    def setUp(self):
        self.now = int(time.time())
        self.patchers = [
            mock.patch.object(awg_manager.time, 'time',
                              return_value=self.now),
            mock.patch.object(awg_manager.time, 'sleep'),
        ]
        for p in self.patchers:
            p.start()
        awg_manager._sim_round_counters.clear()

    def tearDown(self):
        for p in self.patchers:
            p.stop()
        awg_manager._sim_round_counters.clear()

    def _due(self):
        awg_manager._sim_round_counters[('10.255.0.1', 'awg')] =             awg_manager.SIM_ROUND_FULL_EVERY - 1

    def _state(self, history=()):
        seen = {}
        if history:
            seen['10.8.1.5'] = {
                'endpoint': '1.1.1.1', 'ts': self.now - 60,
                'recent': [{'ep': ep, 'ts': self.now - ts}
                           for ep, ts in history],
            }
        return {'seen': seen, 'alerts': {}, 'sim': {}}

    def _two_flows(self):
        flows1 = conntrack([
            {'timeout': 120, 'src': '1.1.1.1', 'sport': 5000},
            {'timeout': 118, 'src': '2.2.2.2', 'sport': 6000},
        ])
        flows2 = conntrack([
            {'timeout': 119, 'src': '1.1.1.1', 'sport': 5000},
            {'timeout': 120, 'src': '2.2.2.2', 'sport': 6000},
        ])
        return flows1, flows2

    def test_two_users_different_keys_no_event(self):
        """THE BUG: two online users = two active flows = was a false CONFIRMED."""
        self._due()
        flows1, flows2 = self._two_flows()
        ssh = sim_ssh(self._state(), flows1, flows2)
        endpoints = {'10.8.1.5': '1.1.1.1:5000', '10.8.1.6': '2.2.2.2:6000'}
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints=endpoints, port='55424')
        self.assertFalse(changed)
        self.assertEqual(ssh.saved, {})

    def test_sharing_same_key_raise_event(self):
        """One key: primary device 1.1.1.1 active + orphan 2.2.2.2 whose IP
        is in the peer's endpoint history -> CONFIRMED for that peer."""
        self._due()
        flows1, flows2 = self._two_flows()
        state = self._state(history=[('1.1.1.1', 60), ('2.2.2.2', 300)])
        ssh = sim_ssh(state, flows1, flows2)
        endpoints = {'10.8.1.5': '1.1.1.1:5000'}
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints=endpoints, port='55424', public_port='8443')
        self.assertTrue(changed)
        events = ssh.saved['state']['sim']['10.8.1.5']
        self.assertEqual(events, [{'ts': self.now,
                                   'ips': ['1.1.1.1', '2.2.2.2'],
                                   'sessions': 2}])

    def test_handover_old_flow_dead_no_event(self):
        """Wi-Fi->LTE: old flow not refreshed -> not active -> no orphan."""
        self._due()
        flows1 = conntrack([
            {'timeout': 120, 'src': '1.1.1.1', 'sport': 5000},
            {'timeout': 118, 'src': '2.2.2.2', 'sport': 6000},
        ])
        flows2 = conntrack([
            {'timeout': 119, 'src': '2.2.2.2', 'sport': 6000},
            {'timeout': 58, 'src': '1.1.1.1', 'sport': 5000},
        ])
        ssh = sim_ssh(self._state(history=[('1.1.1.1', 120), ('2.2.2.2', 30)]),
                      flows1, flows2)
        endpoints = {'10.8.1.5': '2.2.2.2:6000'}
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints=endpoints, port='55424')
        self.assertFalse(changed)
        self.assertEqual(ssh.saved, {})

    def test_single_flow_never_alerts(self):
        self._due()
        flows1 = conntrack([{'timeout': 120, 'src': '1.1.1.1', 'sport': 5000}])
        flows2 = conntrack([{'timeout': 120, 'src': '1.1.1.1', 'sport': 5000}])
        ssh = sim_ssh(self._state(), flows1, flows2)
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints={'10.8.1.5': '1.1.1.1:5000'}, port='55424')
        self.assertFalse(changed)

    def test_unattributed_orphan_goes_to_star(self):
        """Orphan flow whose IP is in NO peer's history: stored under '*',
        never attached to a random peer."""
        self._due()
        flows1, flows2 = self._two_flows()
        ssh = sim_ssh(self._state(), flows1, flows2)
        endpoints = {'10.8.1.5': '1.1.1.1:5000'}
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints=endpoints, port='55424')
        self.assertTrue(changed)
        self.assertIn('*', ssh.saved['state']['sim'])
        self.assertNotIn('10.8.1.5', ssh.saved['state']['sim'])

    def test_not_due_round_skips_sampling(self):
        state = self._state()
        ssh = sim_ssh(state, '', '')
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints={}, port='55424')
        self.assertFalse(changed)
        self.assertEqual(ssh.saved, {})

    def test_recent_multi_ip_alert_makes_it_due(self):
        state = self._state(history=[('2.2.2.2', 300)])
        state['alerts'] = {'10.8.1.5': [{'ts': self.now - 60,
                                         'ips': ['1.1.1.1', '2.2.2.2']}]}
        flows1, flows2 = self._two_flows()
        ssh = sim_ssh(state, flows1, flows2)
        changed = manager(ssh).detect_simultaneous_use(
            'awg', endpoints={'10.8.1.5': '1.1.1.1:5000'}, port='55424')
        self.assertTrue(changed)

    def test_outer_flow_parsing(self):
        ssh = sim_ssh(None, '', '')
        mgr = manager(ssh)
        lines = ('ipv4     2 udp      17 120 src=1.1.1.1 dst=46.183.21.61 '
                 'sport=5000 dport=55424 packets=9 bytes=900 '
                 'src=46.183.21.61 dst=1.1.1.1 sport=55424 dport=5000 '
                 'packets=4 bytes=400 [ASSURED] mark=0 use=2\n'
                 'ipv4     2 tcp      6 100 src=1.1.1.1 dst=46.183.21.61 '
                 'sport=5001 dport=55424 src=46.183.21.61 dst=1.1.1.1 '
                 'sport=55424 dport=5001 mark=0 use=2\n')
        ssh.run_sudo_command = lambda command, timeout=60: (lines, '', 0)
        flows = mgr._collect_outer_flows(['55424', '8443'])
        self.assertEqual(flows, {'1.1.1.1:5000': 120})  # tcp line filtered


if __name__ == '__main__':
    unittest.main()
