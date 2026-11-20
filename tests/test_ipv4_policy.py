"""Server IPv4 policy: egress SNAT pipeline and ingress port binding."""
import asyncio
import hashlib
import unittest
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import Mock, patch

import app as panel
from managers.xray_manager import XrayManager
from managers.awg_manager import AWGManager


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
    'inspect bridge': (
        '172.17.0.0/16||536bd8016c01d2b2b125d577c537fa7db2367fef4d31a65262f86132d78a3c17',
        '', 0),
    'inspect amnezia-selfsteal-net': (
        '172.18.0.0/16||2d95ecbe88baf79c8dce0f3ec8241d97d1265a3a54fdcfeadc21455cc451b579',
        '', 0),
    'ip -4 addr show': ('inet 192.0.2.1/24 ens3\n    inet 198.51.100.7/24 secondary ens3', '', 0),
    'nat -S POSTROUTING': (
        '-A POSTROUTING -s 172.17.0.0/24 -o ens3 -j SNAT --to-source 198.51.100.7\n'
        '-A POSTROUTING -s 172.18.0.0/16 ! -o br-2d95ecbe88ba -j MASQUERADE\n'
        '-A POSTROUTING -o ens3 -j SNAT --to-source 203.0.113.1\n'
        '-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE', '', 0),
    '--interface': ('198.51.100.7', '', 0),
    'docker exec': ('198.51.100.7', '', 0),
}

BOTH_BINS = '/usr/sbin/iptables-nft\n/usr/sbin/iptables-legacy'


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

    def test_iptables_bins_fall_back_to_the_plain_name(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, 'command -v': (BOTH_BINS, '', 0)})
        self.assertEqual(panel._iptables_bins(ssh),
                         ['/usr/sbin/iptables-nft', '/usr/sbin/iptables-legacy'])
        ssh2 = make_ssh(BRIDGE_SCRIPT)
        self.assertEqual(panel._iptables_bins(ssh2), ['iptables'])

    def test_docker_subnets_enumerates_bridge_networks(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        self.assertEqual(panel._docker_subnets(ssh), [
            ('172.17.0.0/16', 'docker0'),
            ('172.18.0.0/16', 'br-2d95ecbe88ba')])

    def test_docker_subnets_skips_unusable_networks(self):
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'inspect bridge': ('garbage||536bd8016c01', '', 0),
                        'inspect amnezia-selfsteal-net': ('fd00::/8||2d95ecbe88ba', '', 0)})
        self.assertEqual(panel._docker_subnets(ssh), [])
        ssh2 = make_ssh({**BRIDGE_SCRIPT,
                         'network ls': ('bridge overlay\nawg bridge', '', 0)})
        self.assertEqual(panel._docker_subnets(ssh2), [])

    def test_docker_subnets_honors_the_custom_bridge_name(self):
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'inspect bridge': (
                            '172.17.0.0/16|eth9|'
                            '536bd8016c01d2b2b125d577c537fa7db2367fef4d31a65262f86132d78a3c17',
                            '', 0)})
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

    def test_container_probe_falls_back_to_nsenter(self):
        # an image without curl: the host's curl runs inside the
        # container's network namespace
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'docker exec': ('', '', 127),
                        'State.Pid': ('12345\n', '', 0),
                        'nsenter': ('198.51.100.7', '', 0)})
        self.assertEqual(
            panel._egress_container_probe(ssh, ['amnezia-awg']),
            '198.51.100.7')

    def test_probe_containers_lists_the_vpn_protocols(self):
        server = {'protocols': {'xray': {'container_name': 'amnezia-xray'},
                                'nginx': {'container_name': 'amnezia-nginx'},
                                'awg': {'container_name': 'amnezia-awg'},
                                'awg2__1': {'container_name': 'amnezia-awg2'},
                                'wireguard': {'container_name': 'amnezia-wireguard'}}}
        self.assertEqual(panel._egress_probe_containers(server),
                         ['amnezia-xray', 'amnezia-awg', 'amnezia-awg2',
                          'amnezia-wireguard'])

    def test_snat_rules_own_everything_inside_docker_subnets(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        rules = panel._snat_rules_for(ssh, panel._docker_subnets(ssh))
        # the stale manual /24 rule inside docker0's /16 is managed;
        # the host-wide SNAT (no -s) and the masquerades are not; the
        # readback is a union over backends and deduplicates
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
                   if 'nat -I POSTROUTING' in c]
        self.assertEqual(len(inserts), 2)
        self.assertTrue(any('-s 172.17.0.0/16 ! -o docker0 ' in c
                            for c in inserts))
        self.assertTrue(any('-s 172.18.0.0/16 ! -o br-2d95ecbe88ba ' in c
                            for c in inserts))
        self.assertNotIn('-o ens3', ''.join(inserts))
        # the stale manual /24 rule was taken over and deleted
        deletes = [c for c in self.ssh.calls
                   if 'nat -D POSTROUTING' in c]
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

    def test_apply_writes_both_backends_when_present(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, 'command -v': (BOTH_BINS, '', 0)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result['status'], 'success')
        inserts = [c for c in ssh.calls if 'nat -I POSTROUTING' in c]
        self.assertEqual(len(inserts), 4)
        self.assertEqual(len([c for c in inserts if 'iptables-nft' in c]), 2)
        self.assertEqual(len([c for c in inserts if 'iptables-legacy' in c]), 2)
        # the stale rule is deleted once per backend, from the same spec
        deletes = [c for c in ssh.calls if 'nat -D POSTROUTING' in c]
        self.assertEqual(len(deletes), 2)

    def test_apply_reports_a_failed_insert(self):
        ssh = make_ssh(BRIDGE_SCRIPT)
        base = ssh.run_sudo_command

        def failing(command, **kwargs):
            out, err, code = base(command, **kwargs)
            if 'nat -I POSTROUTING' in command:
                return ('', 'iptables: Bad rule (does a matching rule '
                            'exist in that chain?)', 2)
            return (out, err, code)

        ssh.run_sudo_command = failing
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result.status_code, 409)
        error = json_error(result)
        self.assertIn('Bad rule', error)
        self.assertIn('172.17.0.0/16', error)
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))
        self.assertEqual([p for _, p in ssh.uploads], [])

    def test_apply_reports_when_the_rules_do_not_persist(self):
        ssh = make_ssh({**BRIDGE_SCRIPT,
                        'nat -S POSTROUTING': (
                            '-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 '
                            '-j MASQUERADE', '', 0)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result.status_code, 409)
        self.assertIn('did not persist', json_error(result))
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))

    def test_apply_rolls_back_when_the_container_keeps_the_main_ip(self):
        ssh = make_ssh({**BRIDGE_SCRIPT, 'docker exec': ('192.0.2.1', '', 0)})
        self.stack.enter_context(patch.object(panel, 'get_ssh', return_value=ssh))
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='198.51.100.7')))

        self.assertEqual(result.status_code, 409)
        self.assertIn('192.0.2.1', json_error(result))
        inserts = [c for c in ssh.calls
                   if 'nat -I POSTROUTING' in c]
        deletes = [c for c in ssh.calls
                   if 'nat -D POSTROUTING' in c]
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
                   if 'nat -D POSTROUTING' in c]
        self.assertEqual(len(deletes), 1)
        self.assertIn('-s 172.17.0.0/24', deletes[0])

    def test_apply_refuses_an_unassigned_ip(self):
        result = asyncio.run(panel.api_ipv4_egress(
            self.request(), 0, panel.Ipv4EgressRequest(ip='203.0.113.9')))
        self.assertEqual(result.status_code, 409)
        self.assertIsNone(self.data['servers'][0].get('egress_ip'))
        self.assertEqual([c for c in self.ssh.calls
                          if 'nat -I POSTROUTING' in c], [])

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
                   if 'nat -D POSTROUTING' in c]
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
        ssh = make_ssh(BRIDGE_SCRIPT)
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, 'save_data', Mock()), \
             patch.object(panel, 'get_ssh', return_value=ssh):
            result = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='192.0.2.1')))
            self.assertEqual(result['status'], 'success')
            self.assertEqual(data['servers'][0]['ingress_ip'], '192.0.2.1')
            unassigned = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='203.0.113.9')))
            self.assertEqual(unassigned.status_code, 409)
            bad = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='not-an-ip')))
            self.assertEqual(bad.status_code, 400)
            cleared = asyncio.run(panel.api_ipv4_ingress(
                self.request(), 0, panel.Ipv4IngressRequest(ip='')))
            self.assertEqual(cleared['status'], 'success')
            self.assertIsNone(data['servers'][0]['ingress_ip'])

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
             patch.object(panel, 'get_ssh', return_value=make_ssh(BRIDGE_SCRIPT)), \
             patch.object(panel, 'get_protocol_manager',
                          return_value=manager), \
             patch.object(panel, '_ensure_selfsteal_network',
                          Mock(side_effect=lambda ssh_, c: provisioned.append(c))):
            result = asyncio.run(panel.api_ipv4_ingress_recreate(self.request(), 0))
        self.assertEqual(result['recreated'], ['xray'])
        manager.recreate_container.assert_called_once_with(ingress_ip='192.0.2.1')
        self.assertEqual(provisioned, [['amnezia-xray']])

    def test_recreate_refuses_an_unassigned_ingress_ip(self):
        data = state()
        data['servers'][0]['ingress_ip'] = '203.0.113.9'
        manager = Mock()
        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, '_install_ops_load', Mock()), \
             patch.object(panel, '_install_running', Mock(return_value=False)), \
             patch.object(panel, 'get_ssh', return_value=make_ssh(BRIDGE_SCRIPT)), \
             patch.object(panel, 'get_protocol_manager',
                          return_value=manager):
            result = asyncio.run(
                panel.api_ipv4_ingress_recreate(self.request(), 0))
        self.assertEqual(result.status_code, 409)
        manager.recreate_container.assert_not_called()

    def test_recreate_covers_awg_instances(self):
        data = state()
        data['servers'][0]['protocols'] = {
            'xray': {'container_name': 'amnezia-xray'},
            'awg': {'container_name': 'amnezia-awg', 'port': 44337}}
        data['servers'][0]['ingress_ip'] = '192.0.2.1'
        xray_manager, awg_manager = Mock(), Mock()
        provisioned = []

        def pick_manager(ssh_, key):
            return xray_manager if key == 'xray' else awg_manager

        with patch.object(panel, 'load_data', return_value=data), \
             patch.object(panel, '_check_admin', lambda request: True), \
             patch.object(panel, '_install_ops_load', Mock()), \
             patch.object(panel, '_install_running', Mock(return_value=False)), \
             patch.object(panel, 'get_ssh', return_value=make_ssh(BRIDGE_SCRIPT)), \
             patch.object(panel, 'get_protocol_manager',
                          side_effect=pick_manager), \
             patch.object(panel, '_ensure_selfsteal_network',
                          Mock(side_effect=lambda ssh_, c: provisioned.append(c))):
            result = asyncio.run(
                panel.api_ipv4_ingress_recreate(self.request(), 0))
        self.assertEqual(result['recreated'], ['xray', 'awg'])
        xray_manager.recreate_container.assert_called_once_with(
            ingress_ip='192.0.2.1')
        awg_manager.recreate_container.assert_called_once_with(
            protocol_type='awg', ingress_ip='192.0.2.1')
        # the shared self-steal network is xray's concern only
        self.assertEqual(provisioned, [['amnezia-xray']])


class AwgRecreateDanceTests(unittest.TestCase):
    """The shared AWG recreate dance (IPv6-enable and ingress binding):
    the state copy must hop through a host temp dir - docker cp refuses
    container-to-container."""

    def _patched_manager(self, ssh):
        manager = AWGManager(ssh)
        source_sha = hashlib.sha256(b'ListenPort = 44337\n').hexdigest()

        def sha(container, path):
            return source_sha if path.endswith('.conf') else 'sha-other'

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(
            manager, '_container_name', return_value='amnezia-awg3'))
        stack.enter_context(patch.object(
            manager, '_resolve_config_path',
            return_value='/opt/amnezia/awg/awg0.conf'))
        stack.enter_context(patch.object(
            manager, '_get_server_config', return_value='ListenPort = 44337\n'))
        stack.enter_context(patch.object(
            manager, '_container_run_image', return_value='img'))
        stack.enter_context(patch.object(
            manager, '_container_file_sha', side_effect=sha))
        stack.enter_context(patch.object(
            manager, '_container_file_json_ok', return_value=True))
        stack.enter_context(patch.object(
            manager, '_container_peer_count', return_value=1))
        stack.enter_context(patch.object(manager, '_wait_container_running'))
        stack.enter_context(patch.object(manager, '_invalidate_config_cache'))
        stack.enter_context(patch.object(manager, '_tunnel_up',
                                         return_value=True))
        stack.enter_context(patch('managers.awg_manager.time.sleep'))
        return manager

    def test_ingress_recreate_hops_the_copy_through_the_host(self):
        ssh = make_ssh({'docker port ': ('44337/udp -> 192.0.2.1:44337\n', '', 0)})
        manager = self._patched_manager(ssh)

        result = manager.recreate_container('awg3', ingress_ip='192.0.2.1')

        self.assertEqual(result, 'amnezia-awg3')
        runs = [c for c in ssh.calls if 'docker run -d' in c]
        self.assertEqual(len(runs), 1)
        self.assertIn('-p 192.0.2.1:44337:44337/udp', runs[0])
        hops = [c for c in ssh.calls if 'docker cp' in c]
        self.assertEqual(len(hops), 1)
        self.assertIn('docker cp amnezia-awg3-ingressbak:/opt/amnezia/awg/. '
                      '/tmp/awg-recreate-amnezia-awg3/', hops[0])
        self.assertIn('docker cp /tmp/awg-recreate-amnezia-awg3/. '
                      'amnezia-awg3:/opt/amnezia/awg/', hops[0])
        self.assertIn('docker cp amnezia-awg3-ingressbak:/opt/amnezia/start.sh',
                      hops[0])
        # no direct container-to-container cp anywhere
        direct = [c for c in ssh.calls
                  if 'docker cp amnezia-awg3-ingressbak:' in c
                  and '/tmp/awg-recreate' not in c]
        self.assertEqual(direct, [])

    def test_a_failed_copy_hop_rolls_back(self):
        ssh = make_ssh({'docker cp': ('copying between containers is not '
                                      'supported', '', 1)})
        manager = self._patched_manager(ssh)

        with self.assertRaises(RuntimeError) as ctx:
            manager.recreate_container('awg3', ingress_ip='192.0.2.1')

        self.assertEqual(str(ctx.exception), 'state_unreadable')
        self.assertTrue(any(
            'docker rename amnezia-awg3-ingressbak amnezia-awg3' in c
            for c in ssh.calls))
        self.assertTrue(any('docker start amnezia-awg3' in c
                            for c in ssh.calls))
        self.assertTrue(any('rm -rf /tmp/awg-recreate-amnezia-awg3' in c
                            for c in ssh.calls))

    def test_a_silent_boot_gets_one_restart(self):
        # the container can boot before its networks settle and come up
        # without the tunnel; the dance restarts it once with the
        # networks attached instead of rolling back
        ssh = make_ssh({'docker port ': ('55424/udp -> 192.0.2.1:44337\n',
                                         '', 0)})
        manager = self._patched_manager(ssh)
        manager._tunnel_up = Mock(
            side_effect=[False] * 9 + [True])

        result = manager.recreate_container('awg3', ingress_ip='192.0.2.1')

        self.assertEqual(result, 'amnezia-awg3')
        self.assertTrue(any(c.startswith('docker restart amnezia-awg3')
                            for c in ssh.calls))

    def test_a_tunnel_that_never_comes_up_rolls_back(self):
        ssh = make_ssh({'docker port ': ('55424/udp -> 192.0.2.1:44337\n',
                                         '', 0)})
        manager = self._patched_manager(ssh)
        manager._tunnel_up = Mock(return_value=False)

        with self.assertRaises(RuntimeError) as ctx:
            manager.recreate_container('awg3', ingress_ip='192.0.2.1')

        self.assertEqual(str(ctx.exception), 'env_off')
        self.assertTrue(any(
            'docker rename amnezia-awg3-ingressbak amnezia-awg3' in c
            for c in ssh.calls))


class RunCmdBindingTests(unittest.TestCase):
    def _info(self, host_ip=''):
        return {'HostConfig': {'RestartPolicy': {'Name': 'always'},
                               'Privileged': True,
                               'PortBindings': {'44337/udp': [
                                   {'HostIp': host_ip, 'HostPort': '44337'}]}},
                'Config': {}}

    def test_without_override_the_bindings_are_kept(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._info(''), 'amnezia-awg', 'img')
        self.assertIn('-p 44337:44337/udp', cmd)
        cmd2 = AWGManager._run_cmd_from_inspect(
            self._info('198.51.100.1'), 'amnezia-awg', 'img')
        self.assertIn('-p 198.51.100.1:44337:44337/udp', cmd2)

    def test_host_ip_override_pins_every_binding(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._info(''), 'amnezia-awg', 'img', host_ip_override='192.0.2.1')
        self.assertIn('-p 192.0.2.1:44337:44337/udp', cmd)

    def test_empty_override_restores_all_address_publishing(self):
        cmd = AWGManager._run_cmd_from_inspect(
            self._info('198.51.100.1'), 'amnezia-awg', 'img',
            host_ip_override='')
        self.assertIn('-p 44337:44337/udp', cmd)
        self.assertNotIn('198.51.100.1', cmd)

    def test_docker_run_cmd_supports_the_binding(self):
        cmd = AWGManager._docker_run_cmd('amnezia-awg', 'img', '44337',
                                         False, host_ip='192.0.2.1')
        self.assertIn('-p 192.0.2.1:44337:44337/udp', cmd)
        plain = AWGManager._docker_run_cmd('amnezia-awg', 'img', '44337', False)
        self.assertIn('-p 44337:44337/udp', plain)


class RecreateContainerTests(unittest.TestCase):
    def _manager(self, ssh):
        manager = XrayManager.__new__(XrayManager)
        manager.protocol = 'xray'
        manager.instance = 1
        manager.base_protocol = 'xray'
        manager.container_name = 'amnezia-xray'
        manager.image_name = 'amneziavpn/amnezia-xray'
        manager.ssh = ssh
        manager._config_dir = lambda: '/opt/amnezia/xray'
        manager._get_meta_json = lambda: {'port': 443}
        manager.check_container_running = lambda: True
        return manager

    def _ssh(self, bound_code=0):
        ssh = Mock()
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if bound_code and '-p 192.0.2.1:' in command:
                return ('', 'driver failed programming external '
                            'connectivity: bind failed', bound_code)
            return ('', '', 0)

        ssh.run_sudo_command = run
        ssh.calls = calls
        return ssh

    def test_a_failed_bound_run_restores_the_service_without_binding(self):
        ssh = self._ssh(bound_code=1)
        manager = self._manager(ssh)
        with self.assertRaises(RuntimeError) as ctx:
            manager.recreate_container(ingress_ip='192.0.2.1')

        self.assertIn('restored', str(ctx.exception))
        self.assertIn('192.0.2.1', str(ctx.exception))
        runs = [c for c in ssh.calls if 'docker run -d' in c]
        self.assertEqual(len(runs), 2)
        self.assertTrue(any('-p 192.0.2.1:' in c for c in runs))
        self.assertTrue(any('-p 443:443/tcp' in c for c in runs))
        self.assertTrue(any('docker stop amnezia-xray' in c
                            for c in ssh.calls))

    def test_a_successful_bound_run_runs_once(self):
        ssh = self._ssh()
        manager = self._manager(ssh)
        result = manager.recreate_container(ingress_ip='192.0.2.1')

        self.assertEqual(result, {'port': 443})
        runs = [c for c in ssh.calls if 'docker run -d' in c]
        self.assertEqual(len(runs), 1)
        self.assertIn('-p 192.0.2.1:443:443/tcp', runs[0])
        self.assertTrue(any('amnezia-dns-net' in c for c in ssh.calls))

    def test_a_failed_plain_run_stays_a_plain_failure(self):
        ssh = Mock()
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if 'docker run -d' in command:
                return ('', 'no space left on device', 1)
            return ('', '', 0)

        ssh.run_sudo_command = run
        ssh.calls = calls
        manager = self._manager(ssh)
        with self.assertRaises(RuntimeError) as ctx:
            manager.recreate_container(ingress_ip='192.0.2.1')

        # the restore attempt happens even when it is hopeless; the
        # raised message carries the original binding error
        self.assertIn('Failed to run the container', str(ctx.exception))
        self.assertIn('no space left', str(ctx.exception))
        self.assertEqual(len([c for c in calls if 'docker run -d' in c]), 2)


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
