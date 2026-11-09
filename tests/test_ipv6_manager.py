"""Unit tests for the IPv6 status and control methods of AWGManager.

No SSH is opened: every remote read is patched or served by a mock. The
tests pin the contract the API and the UI rely on: subnet index parsing,
dns6 only on dual-stack tunnels, peer counting, blocked_reason mapping and
the safe enable/disable sequence with rollback.
"""
import unittest
from unittest.mock import Mock

from managers.awg_manager import AWGManager, parse_subnet_indexes


def make_manager():
    ssh = Mock()
    ssh.run_sudo_command.return_value = ('', '', 0)
    ssh.docker_container_state.return_value = (True, True)
    return AWGManager(ssh)


class SubnetIndexParsingTests(unittest.TestCase):
    def test_ipv4_index_is_decimal(self):
        self.assertEqual(parse_subnet_indexes(['Address = 10.8.12.1/24']), {12})

    def test_decimal_ipv6_index_matches_ipv4(self):
        self.assertEqual(parse_subnet_indexes(['Address = fd42:8:12::1/64']), {12})

    def test_legacy_hex_ipv6_index_is_read_as_hex(self):
        self.assertEqual(parse_subnet_indexes(['Address = fd42:8:1a::1/64']), {26})

    def test_dual_stack_line_marks_the_same_index(self):
        used = parse_subnet_indexes(['Address = 10.8.3.1/24, fd42:8:3::1/64'])
        self.assertEqual(used, {3})


class DnsSixTests(unittest.TestCase):
    def test_ipv4_only_instance_has_no_ipv6_dns(self):
        manager = make_manager()
        manager._read_config_key = Mock(return_value='')
        manager._get_subnet_ipv6_ip = Mock(return_value='')
        self.assertEqual(manager._get_dns6('awg3'), '')

    def test_dual_stack_instance_falls_back_to_the_default(self):
        manager = make_manager()
        manager._read_config_key = Mock(return_value='')
        manager._get_subnet_ipv6_ip = Mock(return_value='fd42:8:1::1')
        self.assertTrue(manager._get_dns6('awg3'))

    def test_config_line_wins_over_the_default(self):
        manager = make_manager()
        manager._read_config_key = Mock(return_value='2001:db8::53')
        manager._get_subnet_ipv6_ip = Mock(return_value='fd42:8:1::1')
        self.assertEqual(manager._get_dns6('awg3'), '2001:db8::53')

    def test_per_client_override_wins(self):
        manager = make_manager()
        manager._read_config_key = Mock(return_value='2001:db8::53')
        manager._get_subnet_ipv6_ip = Mock(return_value='fd42:8:1::1')
        self.assertEqual(manager._get_dns6('awg3', {'dns6': '::1'}), '::1')


class PeerStateTests(unittest.TestCase):
    """clientsTable rows keep client fields inside `userData`.

    A mock with the fields on the row top level hides a defect no live
    instance can hit: the panel reports zero IPv6 peers on a server that
    has them, and the host chip stays orange. The real shape is first.
    """

    def test_counts_union_of_table_and_config(self):
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[
            {'clientId': 'KEY_A', 'userData': {
                'enabled': True, 'clientIp': '10.8.1.2',
                'clientIpv6': 'fd42:8:1::a'}},
            {'clientId': 'KEY_B', 'userData': {
                'enabled': True, 'clientIp': '10.8.1.3',
                'clientIpv6': ''}},
            {'clientId': 'KEY_C', 'userData': {
                'enabled': False, 'clientIp': '10.8.1.4',
                'clientIpv6': 'fd42:8:1::c'}},
        ])
        manager._get_server_config = Mock(return_value='[Peer]\nPublicKey = KEY_A\n')
        manager._parse_peers_from_config = Mock(return_value={'KEY_A': {}, 'KEY_D': {}})
        peers, v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        # KEY_C is disabled, so its clientsTable row is not a live peer.
        self.assertEqual(peers, 3)
        self.assertEqual(v6, 1)

    def test_live_row_with_ipv6_counts_even_when_absent_from_config(self):
        """A row the panel wrote itself, including its IPv6 address."""
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[
            {'clientId': 'JonInTMA7kQioR5gZw8D4mkEBLFOu1Z5EYPnwzS4BUI=',
             'userData': {
                 'clientName': 'kghf',
                 'clientPrivateKey': 'priv',
                 'clientIp': '10.8.1.2',
                 'clientIpv6': 'fd42:8:1::2',
                 'enabled': True,
                 'psk': 'psk'}},
        ])
        manager._get_server_config = Mock(return_value='[Peer]\n')
        manager._parse_peers_from_config = Mock(return_value={})
        peers, v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        self.assertEqual(peers, 1)
        self.assertEqual(v6, 1)

    def test_disabled_peer_does_not_make_ipv6_in_use(self):
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[
            {'clientId': 'KEY_C', 'userData': {
                'enabled': False, 'clientIp': '10.8.1.4',
                'clientIpv6': 'fd42:8:1::c'}},
        ])
        manager._get_server_config = Mock(return_value='[Peer]\nPublicKey = KEY_C\n')
        manager._parse_peers_from_config = Mock(return_value={'KEY_C': {}})
        peers, v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        self.assertEqual(peers, 1)
        self.assertEqual(v6, 0)

    def test_top_level_fields_still_work_for_old_rows(self):
        """Rows written without userData keep the legacy flat shape readable."""
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[
            {'clientId': 'KEY_A', 'enabled': True, 'clientIpv6': 'fd42:8:1::a'},
        ])
        manager._get_server_config = Mock(return_value='[Peer]\n')
        manager._parse_peers_from_config = Mock(return_value={})
        peers, v6, readable = manager._peers_state('awg3')
        self.assertTrue(readable)
        self.assertEqual(peers, 1)
        self.assertEqual(v6, 1)

    def test_unreadable_config_is_not_zero_peers(self):
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[])
        manager._get_server_config = Mock(side_effect=RuntimeError('ssh down'))
        peers, v6, readable = manager._peers_state('awg3')
        self.assertFalse(readable)
        self.assertEqual(peers, 0)

    def test_empty_config_is_not_zero_peers(self):
        manager = make_manager()
        manager._get_clients_table = Mock(return_value=[])
        manager._get_server_config = Mock(return_value='')
        _peers, _v6, readable = manager._peers_state('awg3')
        self.assertFalse(readable)


class InstanceStateTests(unittest.TestCase):
    def _state(self, running=True, readable=True, peers=0, v6count=0,
               gateway='', docker_on=True, capable=True, exit_linked=False):
        manager = make_manager()
        manager._docker_ipv6_info = Mock(return_value={'ipv6_enabled': docker_on,
                                                      'installed': True})
        address = 'Address = 10.8.1.1/24'
        if gateway:
            address += f', {gateway}/64'
        manager._get_server_config = Mock(
            return_value=f'[Interface]\n{address}\nListenPort = 55424\n')
        manager._host_ipv6_info = Mock(
            return_value={'disabled_by_sysctl': False})
        manager._peers_state = Mock(return_value=(peers, v6count, readable))
        manager._container_state = Mock(return_value=(running, 'c'))
        manager.exit_link_info = Mock(return_value={'exit_uid': 'e'} if exit_linked else None)
        manager.ssh.run_sudo_command.return_value = ('0', '', 0) if capable else ('1', '', 0)
        return manager.get_instance_ipv6_state('awg3')

    def test_stopped_container_is_server_off(self):
        self.assertEqual(self._state(running=False)['blocked_reason'], 'server_off')

    def test_unreadable_state_blocks(self):
        state = self._state(readable=False)
        self.assertEqual(state['blocked_reason'], 'state_unreadable')
        self.assertIsNone(state['peers'])
        self.assertFalse(state['can_enable'])
        self.assertFalse(state['can_disable'])

    def test_peers_block_both_directions(self):
        state = self._state(peers=3, gateway='fd42:8:1::1')
        self.assertEqual(state['blocked_reason'], 'peers')
        self.assertFalse(state['can_enable'])
        self.assertFalse(state['can_disable'])

    def test_exit_linked_instance_cannot_enable(self):
        state = self._state(exit_linked=True, capable=True)
        self.assertEqual(state['blocked_reason'], 'exit_link')
        self.assertFalse(state['can_enable'])

    def test_docker_off_blocks_enable(self):
        state = self._state(docker_on=False)
        self.assertEqual(state['blocked_reason'], 'docker_off')

    def test_old_container_needs_recreate(self):
        state = self._state(capable=False)
        self.assertEqual(state['blocked_reason'], 'needs_recreate')
        self.assertTrue(state['needs_recreate'])

    def test_ready_instance_can_enable(self):
        state = self._state(capable=True, docker_on=True)
        self.assertEqual(state['blocked_reason'], 'none')
        self.assertTrue(state['can_enable'])

    def test_enabled_instance_can_disable_without_peers(self):
        state = self._state(gateway='fd42:8:1::1')
        self.assertEqual(state['blocked_reason'], 'none')
        self.assertTrue(state['can_disable'])
        self.assertTrue(state['ipv6_enabled'])


class SetInstanceIpv6Tests(unittest.TestCase):
    def test_refuses_when_peers_exist(self):
        manager = make_manager()
        manager.get_instance_ipv6_state = Mock(
            return_value={'peers': 5, 'blocked_reason': 'peers',
                          'exit_linked': False, 'container': 'c'})
        with self.assertRaises(RuntimeError) as ctx:
            manager.set_instance_ipv6('awg3', True)
        self.assertEqual(str(ctx.exception), 'peers')

    def test_refuses_enable_on_exit_linked_instance(self):
        manager = make_manager()
        manager.get_instance_ipv6_state = Mock(
            return_value={'peers': 0, 'blocked_reason': 'none',
                          'exit_linked': True, 'container': 'c'})
        with self.assertRaises(RuntimeError) as ctx:
            manager.set_instance_ipv6('awg3', True)
        self.assertEqual(str(ctx.exception), 'exit_link')

class RecreateContainerTests(unittest.TestCase):
    def _manager(self, run_code=0, route='fe80::/64 dev eth0'):
        manager = make_manager()
        calls = []

        def sudo(command, *args, **kwargs):
            calls.append(command)
            if 'ip -6 route show default' in command:
                return route, '', 0
            if command.startswith('docker run'):
                return '', '', run_code
            return '', '', 0

        manager.ssh.run_sudo_command.side_effect = sudo
        manager.ssh.docker_ps_invalidate = Mock()
        manager._resolve_config_path = Mock(return_value='/opt/amnezia/awg0.conf')
        manager._get_server_config = Mock(
            return_value='[Interface]\nAddress = 10.8.1.1/24\nListenPort = 55424\n')
        manager._container_run_image = Mock(return_value='amnezia-awg3')
        manager._wait_container_running = Mock(return_value=True)
        manager._invalidate_config_cache = Mock()
        return manager, calls

    def test_recreate_keeps_a_backup_until_ipv6_works(self):
        manager, calls = self._manager()
        manager._recreate_container_ipv6('awg3')
        joined = ' | '.join(calls)
        self.assertIn('docker stop amnezia-awg3', joined)
        self.assertIn('docker rename amnezia-awg3 amnezia-awg3-ipv6bak', joined)
        run = [c for c in calls if c.startswith('docker run')][0]
        self.assertIn('--sysctl="net.ipv6.conf.all.disable_ipv6=0"', run)
        self.assertIn('-p 55424:55424/udp', run)
        self.assertIn('--name amnezia-awg3', run)
        self.assertIn('docker cp amnezia-awg3-ipv6bak:/opt/amnezia/awg0.conf', joined)
        # The backup goes away only after the route check passed.
        self.assertTrue(calls[-1].startswith('docker rm -f amnezia-awg3-ipv6bak'))
        self.assertEqual(manager.ssh.docker_ps_invalidate.call_count, 1)

    def test_failed_run_restores_the_old_container(self):
        manager, calls = self._manager(run_code=1)
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg3')
        self.assertEqual(str(ctx.exception), 'env_off')
        joined = ' | '.join(calls)
        self.assertIn('docker rename amnezia-awg3-ipv6bak amnezia-awg3', joined)
        self.assertIn('docker start amnezia-awg3', joined)
        self.assertFalse(any(c.startswith('docker cp') for c in calls))

    def test_missing_ipv6_route_restores_the_old_container(self):
        manager, calls = self._manager(route='')
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg3')
        self.assertEqual(str(ctx.exception), 'env_off')
        joined = ' | '.join(calls)
        self.assertIn('docker rename amnezia-awg3-ipv6bak amnezia-awg3', joined)
        self.assertFalse(calls[-1].startswith('docker rm -f amnezia-awg3-ipv6bak'))

    def test_unreadable_config_stops_before_touching_docker(self):
        manager, calls = self._manager()
        manager._get_server_config = Mock(return_value='')
        with self.assertRaises(RuntimeError) as ctx:
            manager._recreate_container_ipv6('awg3')
        self.assertEqual(str(ctx.exception), 'state_unreadable')
        self.assertEqual(calls, [])


def ready_manager():
    """Manager whose remote guards all pass, for switch-flow tests."""
    manager = make_manager()
    manager._used_subnet_indexes = Mock(return_value=set())
    manager._peers_state = Mock(return_value=(0, 0, True))
    manager._verify_interface_up = Mock()
    manager._get_subnet_ipv6_ip = Mock(return_value='')
    return manager


class SetInstanceIpv6RecreateTests(unittest.TestCase):
    def test_enable_recreates_an_old_container(self):
        manager = ready_manager()
        states = [
            {'peers': 0, 'blocked_reason': 'needs_recreate', 'exit_linked': False,
             'container': 'c', 'needs_recreate': True},
            {'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
             'container': 'c', 'needs_recreate': False},
            {'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
             'container': 'c', 'needs_recreate': False},
        ]
        manager.get_instance_ipv6_state = Mock(side_effect=states)
        manager._recreate_container_ipv6 = Mock(return_value='c')
        manager._subnet_ip = Mock(return_value='7')
        manager._set_config_address_ipv6 = Mock()
        manager._write_start_script = Mock()
        manager._invalidate_config_cache = Mock()
        manager.ssh.run_sudo_command.return_value = ('fe80::/64 dev eth0', '', 0)
        manager.set_instance_ipv6('awg3', True)
        manager._recreate_container_ipv6.assert_called_once_with('awg3')

    def test_enable_does_not_recreate_a_capable_container(self):
        manager = ready_manager()
        manager.get_instance_ipv6_state = Mock(return_value={
            'peers': 0, 'blocked_reason': 'none', 'exit_linked': False,
            'container': 'c', 'needs_recreate': False})
        manager._recreate_container_ipv6 = Mock()
        manager._subnet_ip = Mock(return_value='7')
        manager._set_config_address_ipv6 = Mock()
        manager._write_start_script = Mock()
        manager._invalidate_config_cache = Mock()
        manager.ssh.run_sudo_command.return_value = ('fe80::/64 dev eth0', '', 0)
        manager.set_instance_ipv6('awg3', True)
        manager._recreate_container_ipv6.assert_not_called()


class DockerDaemonWriteTests(unittest.TestCase):
    def _manager(self, write_code=0, existing='{}'):
        manager = make_manager()
        manager.ssh.run_sudo_command.return_value = (existing, '', 0)
        manager._docker_ipv6_info = Mock(return_value={'ip6tables_ok': True})
        captured = {}

        def run_script(script, timeout=120):
            captured['script'] = script
            return '', 'write failed', write_code

        manager.ssh.run_sudo_script = run_script
        return manager, captured

    def test_payload_is_base64_and_the_script_runs_as_root(self):
        import base64
        manager, captured = self._manager()
        self.assertEqual(manager.enable_docker_ipv6(restart=False),
                         {'pending': True})
        script = captured['script']
        self.assertIn('base64 -d', script)
        encoded = script.split("printf '%s' '", 1)[1].split("' | base64 -d", 1)[0]
        config = __import__('json').loads(base64.b64decode(encoded).decode())
        self.assertTrue(config['ipv6'])
        self.assertTrue(config['experimental'])
        self.assertTrue(config['fixed-cidr-v6'])

    def test_existing_keys_are_kept(self):
        import base64
        manager, captured = self._manager(
            existing='{"log-driver": "json-file", "ipv6": false}')
        manager.enable_docker_ipv6(restart=False)
        script = captured['script']
        encoded = script.split("printf '%s' '", 1)[1].split("' | base64 -d", 1)[0]
        config = __import__('json').loads(base64.b64decode(encoded).decode())
        self.assertEqual(config['log-driver'], 'json-file')
        self.assertTrue(config['ipv6'])

    def test_broken_daemon_json_is_refused(self):
        manager, _captured = self._manager(existing='{not json')
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=False)
        self.assertEqual(str(ctx.exception), 'daemon_json_invalid')

    def test_failed_write_is_not_reported_as_pending(self):
        manager, _captured = self._manager(write_code=1)
        with self.assertRaises(RuntimeError) as ctx:
            manager.enable_docker_ipv6(restart=False)
        self.assertEqual(str(ctx.exception), 'daemon_json_invalid')


class AddressRewriteTests(unittest.TestCase):
    def _manager(self, address_line, probe_code=0):
        """Fake every remote step the guarded rewrite performs."""
        manager = make_manager()
        manager._resolve_config_path = Mock(return_value='/opt/amnezia/awg0.conf')
        manager._read_config_key = Mock(return_value='')
        calls = []

        def sudo(command, *args, **kwargs):
            calls.append(command)
            if 'awp6probe' in command:
                return '', '', probe_code
            if 'sha256sum' in command:
                return 'abc123  /opt/amnezia/awg0.conf', '', 0
            if 'grep -m1' in command:
                return address_line + '\n', '', 0
            return '', '', 0

        manager.ssh.run_sudo_command.side_effect = sudo
        manager.calls = calls
        return manager

    def test_enable_writes_and_verifies_the_gateway(self):
        manager = self._manager('Address = 10.8.1.1/24, fd42:8:1::1/64')
        manager._set_config_address_ipv6('awg3', 'fd42:8:1::1/64')
        joined = ' | '.join(manager.calls)
        self.assertIn('cp -f /opt/amnezia/awg0.conf /opt/amnezia/awg0.conf.ipv6bak', joined)
        self.assertIn('sed -i -E', joined)
        self.assertIn('grep -m1', joined)
        self.assertIn('awp6probe', joined)
        self.assertNotIn('bash -c', joined)
        self.assertTrue(manager.calls[-1].endswith('.ipv6bak'))

    def test_enable_fails_when_the_line_did_not_change(self):
        manager = self._manager('Address = 10.8.1.1/24')
        with self.assertRaises(RuntimeError) as ctx:
            manager._set_config_address_ipv6('awg3', 'fd42:8:1::1/64')
        self.assertEqual(str(ctx.exception), 'state_unreadable')
        self.assertIn('cp -f /opt/amnezia/awg0.conf.ipv6bak',
                      ' '.join(manager.calls))

    def test_enable_fails_when_the_container_rejects_ipv6(self):
        manager = self._manager('Address = 10.8.1.1/24', probe_code=1)
        with self.assertRaises(RuntimeError) as ctx:
            manager._set_config_address_ipv6('awg3', 'fd42:8:1::1/64')
        self.assertEqual(str(ctx.exception), 'env_off')

    def test_disable_verifies_that_ipv6_is_gone(self):
        manager = self._manager('Address = 10.8.1.1/24')
        manager._set_config_address_ipv6('awg3', None)
        self.assertIn("sed -i '/^# DNS6/d'",
                      ' '.join(manager.calls))

    def test_disable_fails_when_ipv6_stayed_in_the_file(self):
        manager = self._manager('Address = 10.8.1.1/24, fd42:8:1::1/64')
        with self.assertRaises(RuntimeError) as ctx:
            manager._set_config_address_ipv6('awg3', None)
        self.assertEqual(str(ctx.exception), 'state_unreadable')


class SetInstanceIpv6RollbackTests(unittest.TestCase):
    def test_enable_rolls_back_when_container_has_no_ipv6_route(self):
        manager = ready_manager()
        manager.get_instance_ipv6_state = Mock(
            return_value={'peers': 0, 'blocked_reason': 'none',
                          'exit_linked': False, 'container': 'c'})
        manager._subnet_ip = Mock(return_value='7')
        manager._set_config_address_ipv6 = Mock()
        manager._write_start_script = Mock()
        manager._invalidate_config_cache = Mock()
        manager.ssh.run_sudo_command.return_value = ('', '', 0)
        with self.assertRaises(RuntimeError) as ctx:
            manager.set_instance_ipv6('awg3', True)
        self.assertEqual(str(ctx.exception), 'env_off')
        # enable, rollback, restart after rollback
        self.assertEqual(manager._set_config_address_ipv6.call_count, 2)
        self.assertIsNone(manager._set_config_address_ipv6.call_args_list[1][0][1])


if __name__ == '__main__':
    unittest.main()
