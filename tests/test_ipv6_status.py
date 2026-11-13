"""Unit tests for AWGManager.get_ip_status / _host_ipv6_info / _docker_ipv6_info.

No SSH and no network: every remote read is served by a fake ssh object or by
a patched manager method. The tests pin the IPv6 status contract the panel
header, the statistics page and /ip-status rely on.
"""
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager


class FakeSSH:
    """run_sudo_command driven by command-substring -> output/code maps."""

    def __init__(self, outputs=None, codes=None):
        self.outputs = outputs or {}
        self.codes = codes or {}
        self.commands = []

    def run_sudo_command(self, command, *args, **kwargs):
        self.commands.append(command)
        for key, out in self.outputs.items():
            if key in command:
                return out, '', self.codes.get(key, 0)
        for key, code in self.codes.items():
            if key in command:
                return '', '', code
        return '', '', 0


def host_info(address='2001:db8::1', ipv4='203.0.113.5',
              default_route=True, disabled=False):
    return {'address': address, 'ipv4': ipv4, 'default_route': default_route,
            'disabled_by_sysctl': disabled}


def instance(proto, ipv6_enabled=False, peers_v6=0, peers=0,
             subnet_v4='10.8.1.1'):
    return {'proto': proto, 'ipv6_enabled': ipv6_enabled,
            'peers_v6': peers_v6, 'peers': peers, 'subnet_v4': subnet_v4}


def status_manager(host, instances, docker=None):
    manager = AWGManager(Mock())
    manager._host_ipv6_info = Mock(return_value=host)
    manager._docker_ipv6_info = Mock(return_value=docker or {})
    manager.get_instance_ipv6_state = Mock(side_effect=list(instances))
    return manager


class HostIpv6InfoTests(unittest.TestCase):
    def _info(self, route_get='', default='', ipv4='', sysctl='', cmdline=''):
        ssh = FakeSSH({
            'ip -6 route get': route_get,
            'ip -6 route show default': default,
            'ip route get 1.1.1.1': ipv4,
            'disable_ipv6': sysctl,
            'ipv6.disable=1': cmdline,
        })
        return AWGManager(ssh)._host_ipv6_info()

    def test_ipv4_comes_from_route_get_src(self):
        info = self._info(
            route_get='2606:4700::1111 dev eth0 src 2001:db8::5',
            ipv4='1.1.1.1 via 10.0.0.1 dev eth0 src 203.0.113.5 uid 0')
        self.assertEqual(info['ipv4'], '203.0.113.5')
        self.assertEqual(info['address'], '2001:db8::5')

    def test_ula_address_is_not_the_host_address(self):
        info = self._info(route_get='2606:4700::1111 dev eth0 src fc00::1')
        self.assertEqual(info['address'], '')
        info = self._info(route_get='2606:4700::1111 dev eth0 src fd12:8::1')
        self.assertEqual(info['address'], '')

    def test_link_local_address_is_dropped(self):
        info = self._info(route_get='2606:4700::1111 dev eth0 src fe80::1')
        self.assertEqual(info['address'], '')

    def test_container_devices_are_dropped(self):
        for dev in ('docker0', 'br-1a2b3c', 'veth9', 'awg0', 'tun0', 'amn0'):
            info = self._info(
                route_get=f'2606:4700::1111 dev {dev} src 2001:db8::5')
            self.assertEqual(info['address'], '', dev)

    def test_default_route_flag(self):
        self.assertTrue(self._info(
            default='default via fe80::1 dev eth0')['default_route'])
        self.assertFalse(self._info()['default_route'])

    def test_disabled_by_sysctl(self):
        self.assertTrue(self._info(sysctl='1')['disabled_by_sysctl'])
        self.assertFalse(self._info(sysctl='0')['disabled_by_sysctl'])

    def test_disabled_by_kernel_cmdline(self):
        self.assertTrue(self._info(cmdline='yes')['disabled_by_sysctl'])


class DockerIpv6InfoTests(unittest.TestCase):
    def _info(self, installed='yes', present='yes', bridge='false',
              daemon_ipv6='', ip6tables='yes', version_code=0, flags=''):
        ssh = FakeSSH(
            outputs={
                'command -v docker': installed,
                'test -f /etc/docker/daemon.json': present,
                'docker network inspect bridge': bridge,
                '"ipv6"': daemon_ipv6,
                'ip6tables -t nat': ip6tables,
                'systemctl cat docker': flags,
            },
            codes={'docker version': version_code},
        )
        return AWGManager(ssh)._docker_ipv6_info()

    def test_not_installed_returns_safe_defaults(self):
        info = self._info(installed='')
        self.assertFalse(info['installed'])
        self.assertFalse(info['version_ok'])
        self.assertFalse(info['flags_conflict'])

    def test_dict_exposes_the_new_flags(self):
        info = self._info()
        self.assertIn('flags_conflict', info)
        self.assertIn('version_ok', info)

    def test_bridge_ipv6_enables_docker_ipv6(self):
        info = self._info(bridge='true')
        self.assertTrue(info['ipv6_enabled'])
        self.assertTrue(info['bridge_ipv6'])

    def test_restart_required_when_daemon_wants_ipv6_and_bridge_is_off(self):
        info = self._info(bridge='false', daemon_ipv6='"ipv6": true')
        self.assertTrue(info['restart_required'])

    def test_no_restart_when_bridge_already_has_ipv6(self):
        info = self._info(bridge='true', daemon_ipv6='"ipv6": true')
        self.assertFalse(info['restart_required'])

    def test_no_restart_when_daemon_json_is_silent(self):
        info = self._info(bridge='false', daemon_ipv6='')
        self.assertFalse(info['restart_required'])

    def test_no_restart_when_daemon_json_explicitly_disables_ipv6(self):
        # "ipv6": false is a deliberate IPv4-only setup the daemon already
        # runs; the card must not keep asking for a restart in that state.
        info = self._info(bridge='false', daemon_ipv6='"ipv6": false')
        self.assertFalse(info['restart_required'])

    def test_flags_conflict_comes_from_the_unit_file(self):
        self.assertTrue(self._info(flags='--ipv6').get('flags_conflict'))
        self.assertFalse(self._info(flags='').get('flags_conflict'))

    def test_version_ok_reflects_docker_version_exit_code(self):
        self.assertTrue(self._info(version_code=0)['version_ok'])
        self.assertFalse(self._info(version_code=1)['version_ok'])


class IpStatusStateTests(unittest.TestCase):
    def _status(self, host=None, instances=None, docker=None):
        host = host if host is not None else host_info()
        instances = instances if instances is not None else [instance('awg3')]
        manager = status_manager(host, instances, docker)
        return manager.get_ip_status(['awg3'])

    def test_disabled_by_sysctl(self):
        st = self._status(host=host_info(disabled=True))
        self.assertEqual(st['host']['ipv6_state'], 'disabled')
        self.assertTrue(st['host']['ipv6_disabled_by_sysctl'])

    def test_absent_when_no_address_and_no_route(self):
        st = self._status(host=host_info(address='', default_route=False))
        self.assertEqual(st['host']['ipv6_state'], 'absent')

    def test_no_route_when_address_exists_but_no_default_route(self):
        st = self._status(host=host_info(default_route=False))
        self.assertEqual(st['host']['ipv6_state'], 'no_route')

    def test_in_use_when_a_peer_has_ipv6(self):
        st = self._status(instances=[
            instance('awg3', ipv6_enabled=True, peers_v6=1)])
        self.assertEqual(st['host']['ipv6_state'], 'in_use')

    def test_enabled_no_peers_when_an_instance_uses_ipv6(self):
        st = self._status(instances=[
            instance('awg3', ipv6_enabled=True, peers_v6=0)])
        self.assertEqual(st['host']['ipv6_state'], 'enabled_no_peers')

    def test_host_only_when_no_instance_uses_ipv6(self):
        st = self._status(instances=[instance('awg3')])
        self.assertEqual(st['host']['ipv6_state'], 'host_only')

    def test_host_ipv4_is_reported_and_marks_ipv4_in_use(self):
        st = self._status(host=host_info(ipv4='203.0.113.9'))
        self.assertEqual(st['host']['ipv4'], '203.0.113.9')
        self.assertEqual(st['host']['ipv4_state'], 'in_use')
        self.assertEqual(st['host']['ipv4_counts'],
                         {'instances': 1, 'peers': 0})


class PortUsageTests(unittest.TestCase):
    """Host-port protocols (Xray) that have no AWG instance row."""

    def _status(self, instances=None, port_usage=None, protocols=None):
        manager = status_manager(host_info(), instances if instances is not None else [])
        return manager.get_ip_status(protocols or [], port_usage=port_usage)

    def test_running_xray_marks_ipv4_in_use_without_awg(self):
        st = self._status(port_usage=[{'running': True, 'clients': 4}])
        self.assertEqual(st['host']['ipv4_state'], 'in_use')
        self.assertEqual(st['host']['ipv4_counts'], {'instances': 1, 'peers': 4})

    def test_stopped_xray_does_not_count(self):
        st = self._status(port_usage=[{'running': False, 'clients': 0}])
        self.assertEqual(st['host']['ipv4_state'], 'host_only')
        self.assertEqual(st['host']['ipv4_counts'], {'instances': 0, 'peers': 0})

    def test_xray_clients_join_awg_counts(self):
        st = self._status(
            instances=[instance('awg3', peers=2)],
            port_usage=[{'running': True, 'clients': 4}],
            protocols=['awg3'])
        self.assertEqual(st['host']['ipv4_counts'], {'instances': 2, 'peers': 6})

    def test_xray_does_not_claim_ipv6_usage(self):
        st = self._status(port_usage=[{'running': True, 'clients': 4}])
        self.assertEqual(st['host']['ipv4_state'], 'in_use')
        self.assertEqual(st['host']['ipv6_state'], 'host_only')

    def test_omitting_port_usage_keeps_the_awg_only_contract(self):
        manager = status_manager(host_info(), [instance('awg3', peers=2)])
        st = manager.get_ip_status(['awg3'])
        self.assertEqual(st['host']['ipv4_counts'], {'instances': 1, 'peers': 2})


class DegradedStatusTests(unittest.TestCase):
    def test_peers_none_marks_the_status_degraded(self):
        manager = status_manager(host_info(), [instance('awg3', peers=None)])
        st = manager.get_ip_status(['awg3'])
        self.assertEqual(st['state'], 'degraded')
        self.assertEqual(st['error'], 'container_unreadable')

    def test_readable_instances_are_ok(self):
        manager = status_manager(host_info(), [instance('awg3')])
        st = manager.get_ip_status(['awg3'])
        self.assertEqual(st['state'], 'ok')
        self.assertIsNone(st['error'])

    def test_one_unreadable_instance_is_degraded_not_fatal(self):
        manager = AWGManager(Mock())
        manager._host_ipv6_info = Mock(return_value=host_info())
        manager._docker_ipv6_info = Mock(return_value={})
        manager.get_instance_ipv6_state = Mock(side_effect=RuntimeError('ssh down'))
        st = manager.get_ip_status(['awg3'])
        self.assertEqual(st['state'], 'degraded')
        self.assertEqual(st['error'], 'container_unreadable')
        self.assertIsNone(st['instances'][0]['peers'])
        self.assertEqual(st['instances'][0]['blocked_reason'], 'state_unreadable')

    def test_docker_block_is_forwarded_unchanged(self):
        docker = {'installed': True, 'flags_conflict': False, 'version_ok': True}
        manager = status_manager(host_info(), [instance('awg3')], docker)
        self.assertEqual(manager.get_ip_status(['awg3'])['docker'], docker)


class InstancePeersTests(unittest.TestCase):
    def test_peers_union_counts_config_peers(self):
        manager = AWGManager(Mock())
        manager._get_clients_table = Mock(return_value=[
            {'clientId': 'A', 'userData': {
                'enabled': True, 'clientIpv6': 'fd42:8:1::a'}}])
        manager._get_server_config = Mock(return_value='[Peer]\nPublicKey = A\n')
        manager._parse_peers_from_config = Mock(return_value={'A': {}, 'D': {}})
        peers, v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        self.assertEqual(peers, 2)
        self.assertEqual(v6, 1)

    def test_state_unreadable_keeps_peers_none(self):
        manager = AWGManager(Mock())
        manager._docker_ipv6_info = Mock(return_value={'ipv6_enabled': True})
        manager._peers_state = Mock(return_value=(0, 0, False))
        manager._container_state = Mock(return_value=(True, 'amnezia-awg3'))
        manager._get_subnet_ipv6_ip = Mock(return_value='')
        manager._get_subnet_ip = Mock(return_value='10.8.1.1')
        manager.exit_link_info = Mock(return_value=None)
        manager.ssh.run_sudo_command.return_value = ('0', '', 0)
        state = manager.get_instance_ipv6_state('awg3')
        self.assertEqual(state['blocked_reason'], 'state_unreadable')
        self.assertIsNone(state['peers'])
        self.assertFalse(state['can_enable'])
        self.assertFalse(state['can_disable'])


if __name__ == '__main__':
    unittest.main()
