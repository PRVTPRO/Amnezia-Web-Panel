"""Пакетизация /ip-status: один композитный вызов вместо 30 SSH-кругов.

Тест держит два контракта: форма ответа не изменилась, а число SSH-команд
на один get_ip_status ограничено (host + docker + один batch на инстансы).
Фейк отвечает на композитные команды так же, как это делает оболочка:
значения секций плюс терминаторы с кодом возврата.
"""
import json
import re
import unittest

from managers.awg_manager import AWGManager


class BatchFakeSSH:
    def __init__(self, containers, composite_rc=0, docker_present=True):
        self.containers = containers
        self.composite_rc = composite_rc
        self.docker_present = docker_present
        self.commands = []

    def docker_container_state(self, name):
        exists = name in self.containers
        return (exists, exists)

    @staticmethod
    def _composite(sections):
        return '\n'.join(line for part in sections for line in part)

    def _direct(self, cmd):
        """Ответы на обычные (некомпозитные) docker exec команды."""
        name = next((item for item in self.containers if item in cmd), None)
        if not name:
            return '', '', 0
        data = self.containers[name]
        if 'disable_ipv6' in cmd:
            return data['disable'], '', 0
        if 'exit0.conf' in cmd:
            return data['exit'], '', data.get('exit_rc', 1)
        if 'clientsTable' in cmd:
            return data['clients'], '', 0
        if 'cat ' in cmd:
            return data['config'], '', 0
        return '', '', 0

    def run_sudo_command(self, command, *args, **kwargs):
        cmd = command or ''
        self.commands.append(cmd)
        host = re.search(r'@@HOST6_[0-9a-f]+@@', cmd)
        if host:
            marker = host.group(0)
            return self._composite([
                (text, '%s!%s %s' % (marker, name, code))
                for name, text, code in (
                    ('V6ROUTE', '2606:4700::1111 dev eth0 src 2001:db8::5', 0),
                    ('V6DEF', 'default via fe80::1 dev eth0', 0),
                    ('V4ROUTE', '1.1.1.1 via 10.0.0.1 dev eth0 src 203.0.113.5', 0),
                    ('SYSCTL', '0', 0),
                    ('CMDLINE', '', 1),
                )]), '', 0
        if 'command -v docker' in cmd:
            return ('yes' if self.docker_present else 'no'), '', 0
        docker = re.search(r'@@DOCKER6_[0-9a-f]+@@', cmd)
        if docker:
            marker = docker.group(0)
            return self._composite([
                (text, '%s!%s %s' % (marker, name, code))
                for name, text, code in (
                    ('DAEMON', 'yes', 0),
                    ('BRIDGE', 'true', 0),
                    ('DAEMONJSON', '{"ipv6": true}', 0),
                    ('IP6T', 'yes', 0),
                    ('VERSION', '', 0),
                    ('FLAGS', '', 0),
                )]), '', 0
        if '@@CONTAINER_' in cmd:
            if self.composite_rc != 0:
                return '', 'composite failed', self.composite_rc
            container = re.search(r'@@CONTAINER_[0-9a-f]+@@', cmd).group(0)
            disable = re.search(r'@@DISABLE_[0-9a-f]+@@', cmd).group(0)
            exit_marker = re.search(r'@@EXIT_[0-9a-f]+@@', cmd).group(0)
            clients = re.search(r'@@CLIENTS_[0-9a-f]+@@', cmd).group(0)
            out = []
            for name, data in self.containers.items():
                out.append(container + ' ' + name)
                out.append(data['disable'])
                out.append(disable + ' ' + str(data.get('disable_rc', 0)))
                out.append(data['exit'])
                out.append(exit_marker + ' ' + str(data.get('exit_rc', 1)))
                out.append(data.get('batch_config', data['config']))
                out.append(clients)
                out.append(data['clients'])
            return '\n'.join(out), '', 0
        if 'docker exec' in cmd:
            return self._direct(cmd)
        return '', '', 0


CONFIG = (
    '[Interface]\n'
    'Address = 10.8.1.1/24, fd42:8:1::1/64\n'
    'ListenPort = 55424\n'
    '\n[Peer]\n'
    'PublicKey = PEER1\n'
    'AllowedIPs = 10.8.1.2/32\n'
)
CLIENTS = json.dumps([{'clientId': 'PEER1',
                       'userData': {'clientIpv6': 'fd42:8:1::2',
                                    'enabled': True}}])
EXIT_CONF_TEXT = ('# ExitUid = exit-1\n'
                  '# ExitName = EXIT\n'
                  '# Obfuscation = on\n'
                  'Address = 10.9.0.2\n'
                  'Endpoint = 203.0.113.9:55520\n')


class IpStatusBatchingTests(unittest.TestCase):
    def _manager(self):
        ssh = BatchFakeSSH({'amnezia-awg3': {
            'disable': '0',
            'exit': EXIT_CONF_TEXT,
            'exit_rc': 0,
            'config': CONFIG,
            'clients': CLIENTS,
        }})
        return AWGManager(ssh), ssh

    def test_payload_shape_is_unchanged(self):
        manager, _ssh = self._manager()
        status = manager.get_ip_status(['awg3'])
        self.assertEqual(status['state'], 'ok')
        self.assertIsNone(status['error'])
        self.assertEqual(status['host']['ipv4'], '203.0.113.5')
        self.assertEqual(status['host']['ipv6'], '2001:db8::5')
        self.assertTrue(status['host']['ipv6_default_route'])
        self.assertTrue(status['host']['ipv4_state'])
        self.assertTrue(status['docker']['bridge_ipv6'])
        self.assertTrue(status['docker']['installed'])
        instance = status['instances'][0]
        self.assertEqual(instance['proto'], 'awg3')
        self.assertEqual(instance['container'], 'amnezia-awg3')
        self.assertEqual(instance['subnet_v4'], '10.8.1.1')
        self.assertEqual(instance['subnet_v6'], 'fd42:8:1::1')
        self.assertEqual(instance['peers'], 1)
        self.assertEqual(instance['peers_v6'], 1)
        self.assertTrue(instance['ipv6_enabled'])
        self.assertTrue(instance['container_ipv6_capable'])
        self.assertTrue(instance['exit_linked'])
        self.assertTrue(instance['can_disable'])

    def test_three_composite_calls_instead_of_thirty(self):
        manager, ssh = self._manager()
        manager.get_ip_status(['awg3'])
        # prefetch инстансов + host-пробы + docker (обнаружение и остальное)
        self.assertLessEqual(len(ssh.commands), 4, ssh.commands)

    def test_instance_without_exit_conf_is_not_exit_linked(self):
        manager, _ssh = self._manager()
        manager.ssh.containers['amnezia-awg3']['exit'] = ''
        manager.ssh.containers['amnezia-awg3']['exit_rc'] = 9
        instance = manager.get_ip_status(['awg3'])['instances'][0]
        self.assertFalse(instance['exit_linked'])
        # Без exit-линка и с пирами включить IPv6 нельзя.
        self.assertFalse(instance['can_enable'])
        self.assertEqual(instance['blocked_reason'], 'peers')

    def test_empty_batch_config_falls_back_to_a_direct_read(self):
        # legacy-инстанс держит конфиг в wg0.conf: пустая секция конфига в
        # батче не должна превращать живой инстанс в state_unreadable.
        manager, ssh = self._manager()
        manager.ssh.containers['amnezia-awg3']['batch_config'] = ''
        instance = manager.get_ip_status(['awg3'])['instances'][0]
        self.assertNotEqual(instance['blocked_reason'], 'state_unreadable')
        self.assertEqual(instance['subnet_v4'], '10.8.1.1')
        self.assertEqual(instance['peers'], 1)
        self.assertTrue(any('docker exec' in cmd and 'cat ' in cmd
                            for cmd in ssh.commands), ssh.commands)

    def test_failed_composite_falls_back_to_per_instance_reads(self):
        ssh = BatchFakeSSH({'amnezia-awg3': {
            'disable': '0',
            'exit': EXIT_CONF_TEXT,
            'exit_rc': 0,
            'config': CONFIG,
            'clients': CLIENTS,
        }}, composite_rc=1)
        status = AWGManager(ssh).get_ip_status(['awg3'])
        self.assertEqual(status['state'], 'ok')
        self.assertEqual(status['instances'][0]['peers'], 1)
        self.assertTrue(status['instances'][0]['exit_linked'])
        self.assertGreater(len(ssh.commands), 4, ssh.commands)

    def test_docker_absent_skips_the_docker_composite(self):
        ssh = BatchFakeSSH({'amnezia-awg3': {
            'disable': '0', 'exit': '', 'exit_rc': 9,
            'config': CONFIG, 'clients': CLIENTS,
        }}, docker_present=False)
        status = AWGManager(ssh).get_ip_status(['awg3'])
        self.assertFalse(status['docker']['installed'])
        self.assertFalse(any('@@DOCKER6_' in cmd for cmd in ssh.commands))


if __name__ == '__main__':
    unittest.main()
