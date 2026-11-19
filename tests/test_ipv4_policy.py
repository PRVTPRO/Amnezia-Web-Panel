"""Server IPv4 policy: egress SNAT pipeline and ingress port binding."""
import asyncio
import unittest
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import Mock, patch

import app as panel
from managers.xray_manager import XrayManager


def state():
    return {
        'servers': [dict(uid='node-a', host='192.0.2.1', name='node',
                         protocols={'xray': {'port': 443,
                                             'container_name': 'amnezia-xray'}})],
        'users': [dict(id='u', username='alice', role='admin')],
        'user_connections': [],
        'settings': {},
    }


def make_ssh(script):
    """A sudo/command SSH whose replies are selected by command substrings."""
    ssh = Mock()
    calls = []

    def run_sudo(command, **kwargs):
        calls.append(command)
        for needle, reply in script.items():
            if needle in command:
                return reply
        return ('', '', 0)

    def run_command(command, **kwargs):
        calls.append(command)
        for needle, reply in script.items():
            if needle in command:
                return reply
        return ('', '', 0)

    ssh.run_sudo_command = run_sudo
    ssh.run_command = run_command
    ssh.calls = calls
    uploads = []
    ssh.upload_file_sudo = lambda content, path: uploads.append((content, path))
    ssh.uploads = uploads
    return ssh


# The iptables list mirrors the production picture that produced the v3
# rework: a stale manual /24 SNAT inside docker0's /16, docker's own
# masquerades, and a foreign host-wide SNAT the panel must not touch.
BRIDGE_SCRIPT = {
    'network ls': ('bridge bridge\namnezia-selfsteal-net bridge\nhost host',
                   '', 0),
    'inspect bridge': ('172.17.0.0/16||br-536bd8016c01', '', 0),
    'inspect amnezia-selfsteal-net': ('172.18.0.0/16||br-2d95ecbe88ba', '', 0),
    'ip -4 addr show': ('inet 192.0.2.1/24 ens3\n    inet 198.51.100.7/24 secondary ens3', '', 0),
    'iptables -t nat -S POSTROUTING': (
        '-A POSTROUTING -s 172.17.0.0/24 -o ens3 -j SNAT --to-source 198.51.100.7\n'
        '-A POSTROUTING -s 172.18.0.0/16 ! -o br-2d95ecbe88ba -j MASQUERADE\n'
        '-A POSTROUTING -o ens3 -j SNAT --to-source 203.0.113.1\n'
        '-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE', '', 0),
    '--interface': ('198.51.100.7', '', 0),
    'docker exec': ('198.51.100.7', '', 0),
}


class EgressHelpersTests(unittest.TestCase):
    def test_assigned_checks_the_addr_output(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        self.assertTrue(panel._ipv4_assigned(ssh, '198.51.100.7'))
        self.assertFalse(panel._ipv4_assigned(ssh, '203.0.113.9'))

    def test_egress_verify_demands_the_ip_back(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        self.assertTrue(panel._egress_verify(ssh, '198.51.100.7'))
        ssh2 = make_ssh({'--interface': ('192.0.2.1', '', 0)})
        self.assertFalse(panel._egress_verify(ssh2, '198.51.100.7'))
        ssh3 = make_ssh({'--interface': ('', 0, 1)})
        self.assertFalse(panel._egress_verify(ssh3, '198.51.100.7'))

    def test_docker_subnets_enumerates_bridge_networks(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        self.assertEqual(panel._docker_subnets(ssh), [
            ('172.17.0.0/16', 'docker0'),
            ('172.18.0.0/16', 'br-2d95ecbe88ba')])

    def test_docker_subnets_skips_unusable_networks(self):
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'inspect bridge': ('garbage||br-536bd8016c01', '', 0),
                        'inspect amnezia-selfsteal-net': ('fd00::/8||br-2d', '', 0)})
        self.assertEqual(panel._docker_subnets(ssh), [])
        ssh2 = make_ssh({**BRIDGE_SCRIPT,
                         'network ls': ('bridge overlay\nawg bridge', '', 0)})
        self.assertEqual(panel._docker_subnets(ssh2), [])

    def test_docker_subnets_honors_the_custom_bridge_name(self):
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'inspect bridge': ('172.17.0.0/16|eth9|br-536bd8016c01', '', 0)})
        self.assertEqual(panel._docker_subnets(ssh), [
            ('172.17.0.0/16', 'eth9'),
            ('172.18.0.0/16', 'br-2d95ecbe88ba')])

    def test_container_probe_reads_the_ip_back(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        self.assertEqual(
            panel._egress_container_probe(ssh, ['amnezia-xray']),
            '198.51.100.7')
        ssh2 = make_ssh({**BRIDGE_SCRIPT, 'docker exec': ('', '', 1)})
        self.assertIsNone(panel._egress_container_probe(ssh2, ['amnezia-xray']))

    def test_probe_containers_lists_the_vpn_protocols(self):
        server = {'protocols': {'xray': {'container_name': 'amnezia-xray'},
                                'nginx': {'container_name': 'amnezia-nginx'},
                                'awg': {'container_name': 'amnezia-awg'}}}
        self.assertEqual(panel._egress_probe_containers(server),
                         ['amnezia-xray', 'amnezia-awg'])

    def test_snat_rules_own_everything_inside_docker_subnets(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        rules = panel._snat_rules_for(ssh, panel._docker_subnets(ssh))
        # the stale manual /24 rule inside docker0's /16 is managed;
        # the host-wide SNAT (no -s) and the masquerades are not
        self.assertEqual(len(rules), 1)
        self.assertIn('-s 172.17.0.0/24', rules[0])
        self.assertIn('--to-source 198.51.100.7', rules[0])


class EgressEndpointTests(unittest.TestCase):
    def request(self):
        return SimpleNamespace(cookies={}, headers={})

    def setUp(self):
        self.data = state()
        self.saved = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(
            panel, 'load_data', lambda: self.data))
        self.stack.enter_context(patch.object(panel, 'save_data',
            Mock(side_effect=lambda d: self.saved.append(d))))
        self.stack.enter_context(patch.object(panel, '_check_admin',
                                              lambda request: True))
        self.stack.enter_context(patch.object(panel, '_install_ops_load', Mock()))
        self.stack.enter_context(patch.object(panel, '_install_running',
                                              Mock(return_value=False)))
        self.ssh = make_ssh(BRIDGE_SCRIPT)
        self.stack.enter_context(patch.object(panel, 'get_ssh',
                                              return_value=self.ssh))

    def test_apply_sets_the_snat_rule_and_persists(self):
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result['status'], 'success')
        inserts = [c for c in self.ssh.calls
                   if 'iptables -t nat -I POSTROUTING' in c]
        self.assertEqual(len(inserts), 2)
        self.assertTrue(any('-s 172.17.0.0/16 ! -o docker0 ' in c
                            for c in inserts))
        self.assertTrue(any('-s 172.18.0.0/16 ! -o br-2d95ecbe88ba ' in c
                            for c in inserts))
        self.assertNotIn('-o ens3', ''.join(inserts))
        # the stale manual /24 rule was taken over and deleted
        deletes = [c for c in self.ssh.calls
                   if 'iptables -t nat -D POSTROUTING' in c]
        self.assertTrue(any('-s 172.17.0.0/24' in c for c in deletes))
        # the end-to-end check went through a VPN container
        self.assertTrue(any('docker exec' in c for c in self.ssh.calls))
        self.assertEqual(self.data['servers'][0]['egress_ip'], '198.51.100.7')
        # the boot unit was uploaded and enabled
        paths = [p for _, p in self.ssh.uploads]
        self.assertIn('/opt/amnezia/egress-snat.sh', paths)
        self.assertIn('/etc/systemd/system/amnezia-egress-snat.service', paths)
        self.assertTrue(any('systemctl enable amnezia-egress-snat' in c
                            for c in self.ssh.calls))

    def test_apply_rolls_back_when_the_container_keeps_the_main_ip(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, 'docker exec': ('192.0.2.1', '', 0)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result.status_code, 409)
        self.assertIn('192.0.2.1', json_error(result))
        inserts = [c for c in ssh.calls
                   if 'iptables -t nat -I POSTROUTING' in c]
        deletes = [c for c in ssh.calls
                   if 'iptables -t nat -D POSTROUTING' in c]
        self.assertEqual(len(inserts), 2)
        self.assertGreaterEqual(len(deletes), 2)
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))
        self.assertEqual([p for _, p in ssh.uploads], [])

    def test_apply_proceeds_when_no_container_answers_the_probe(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, 'docker exec': ('', '', 1)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result['status'], 'success')
        self.assertTrue(any('systemctl enable amnezia-egress-snat' in c
                            for c in ssh.calls))

    def test_status_reports_the_container_check(self):
        self.data['servers'][0]['egress_ip'] = '198.51.100.7'
        state = panel.api_ipv4_status(self.request(), 0)
        self.assertTrue(state['container_ok'])
        self.assertEqual(state['container_egress_ip'], '198.51.100.7')
        self.assertEqual(state['subnets'],
                         ['172.17.0.0/16', '172.18.0.0/16'])
        # only the managed /24 SNAT counts as a panel rule
        self.assertEqual(len(state['snat_rules']), 1)

    def test_apply_replaces_a_stale_rule(self):
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        deletes = [c for c in self.ssh.calls
                   if 'iptables -t nat -D POSTROUTING' in c]
        self.assertEqual(len(deletes), 1)
        self.assertIn('-s 172.17.0.0/24', deletes[0])

    def test_apply_refuses_an_unassigned_ip(self):
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='203.0.113.9')))
        self.assertEqual(result.status_code, 409)
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))
        self.assertEqual([c for c in self.ssh.calls
                          if 'iptables -t nat -I' in c], [])

    def test_apply_refuses_a_non_egressing_ip(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, '--interface': ('192.0.2.1', '', 0)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))
        self.assertEqual(result.status_code, 409)
        self.assertIn('does not egress', json_error(result))

    def test_clear_removes_rules_and_persistence(self):
        self.data['servers'][0]['egress_ip'] = '198.51.100.7'
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='')))

        self.assertEqual(result['status'], 'success')
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))
        deletes = [c for c in self.ssh.calls
                   if 'iptables -t nat -D POSTROUTING' in c]
        # the static fake always re-reports the stale rule; assert every
        # delete targets a docker-subnet SNAT and at least one happened
        self.assertGreaterEqual(len(deletes), 1)
        self.assertTrue(all('-s 172.17.0.0/24' in c for c in deletes))
        self.assertTrue(any('systemctl disable --now amnezia-egress-snat' in c
                            for c in self.ssh.calls))

    def test_endpoints_require_admin(self):
        with patch.object(panel, '_check_admin', lambda request: False):
            for call in (lambda: panel.api_ipv4_status(self.request(), 0),
                         lambda: asyncio.run(panel.api_ipv4_egress(
                             self.request(), 0, panel.Ipv4EgressRequest())),
                         lambda: asyncio.run(panel.api_ipv4_ingress(
                             self.request(), 0, panel.Ipv4IngressRequest())),
                         lambda: asyncio.run(panel.api_ipv4_ingress_recreate(
                             self.request(), 0))):
                self.assertEqual(call().status_code, 403)


def json_error(result):
    import json as _json
    return _json.loads(result.body)['error']


class IngressTests(unittest.TestCase):
    def request(self):
        return SimpleNamespace(cookies={}, headers={})

    def test_save_persists_and_validates(self):
        data = state()
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'save_data', Mock()):
            result = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='192.0.2.1')))
            self.assertEqual(result['status'], 'success')
            self.assertEqual(data['servers'][0]['ingress_ip'], '192.0.2.1')
            bad = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='not-an-ip')))
            self.assertEqual(bad.status_code, 400)

    def test_recreate_binds_and_restores_the_shared_network(self):
        data = state()
        data['servers'][0]['ingress_ip'] = '192.0.2.1'
        manager = Mock()
        manager.container_name = 'amnezia-xray'
        provisioned = []
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, '_install_ops_load', Mock()), \
             patch.object(panel, '_install_running', Mock(return_value=False)), \
             patch.object(panel, 'get_ssh', return_value=Mock()), \
             patch.object(panel, 'get_protocol_manager',
                          return_value=manager), \
             patch.object(panel, '_ensure_selfsteal_network',
                          Mock(side_effect=lambda ssh_, c: provisioned.append(c))):
            result = asyncio.run(panel.api_ipv4_ingress_recreate(self.request(), 0))
        self.assertEqual(result['recreated'], ['xray'])
        manager.recreate_container.assert_called_once_with(ingress_ip='192.0.2.1')
        self.assertEqual(provisioned, [['amnezia-xray']])


class ContainerRunCmdTests(unittest.TestCase):
    def _manager(self):
        manager = XrayManager.__new__(XrayManager)
        manager.protocol = 'xray'
        manager.instance = 1
        manager.base_protocol = 'xray'
        manager.container_name = 'amnezia-xray'
        manager.image_name = 'amneziavpn/amnezia-xray'
        manager._config_dir = lambda: '/opt/amnezia/xray'
        return manager

    def test_without_binding_ports_publish_on_all_addresses(self):
        cmd = self._manager()._container_run_cmd(443)
        self.assertIn('-p 443:443/tcp', cmd)
        self.assertIn('-p 443:443/udp', cmd)

    def test_with_ingress_ip_the_ports_bind_to_it(self):
        cmd = self._manager()._container_run_cmd(443, ingress_ip='192.0.2.1')
        self.assertIn('-p 192.0.2.1:443:443/tcp', cmd)
        self.assertIn('-p 192.0.2.1:443:443/udp', cmd)
        self.assertNotIn('-p 443:443/tcp', cmd)


if __name__ == '__main__':
    unittest.main()
