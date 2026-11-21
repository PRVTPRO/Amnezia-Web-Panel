"""Тесты генератора конфига 3proxy и совместимости Socks5Manager."""

import re
import unittest

from managers.socks5_manager import Socks5Manager, _validate_log_format


LEGACY_CONFIG = """#!/bin/3proxy
config /etc/3proxy/3proxy.cfg
timeouts 1 5 30 60 180 1800 15 60
users proxy_user:CL:Secret123
log
auth strong
allow proxy_user
socks -p38080
"""


class FakeSSH:
    """Запоминает команды и загрузки, отдаёт заранее заданные конфиги."""

    def __init__(self, configs=None, log='', now='1795216380 +0000'):
        self.host = '203.0.113.10'
        self.configs = configs or {}
        self.log = log
        self.now = now
        self.commands = []
        self.uploads = []

    def run_command(self, command, *args, **kwargs):
        if 'systemctl' in command or 'service docker' in command:
            return 'active', '', 0
        return '', '', 0

    def run_sudo_command(self, command, *args, **kwargs):
        self.commands.append(command)
        # docker inspect используется для проверки живости контейнера.
        if command.startswith('docker inspect'):
            return 'true 0', '', 0
        if command.startswith('docker logs'):
            return '', '', 0
        if command.startswith('date +'):
            return self.now, '', 0
        if command.startswith('cat '):
            for path, text in self.configs.items():
                if path in command:
                    return text, '', 0
            return '', '', 0
        if '3proxy.log' in command and self.log:
            # Первая строка вывода контейнера — его `date +"%s %z"`.
            return self.now + '\n' + self.log, '', 0
        return '', '', 0

    def upload_file_sudo(self, content, remote_path):
        self.uploads.append((remote_path, content))
        return True

    def uploaded(self, suffix):
        return [text for path, text in self.uploads if path.endswith(suffix)]


class RunningSSH(FakeSSH):
    """Все контейнеры уже существуют и запущены."""

    def docker_container_state(self, name):
        return (True, True)


class HttpOnlySSH(FakeSSH):
    """HTTP-листенер работает, SOCKS-контейнера нет (listener_type=http)."""

    def docker_container_state(self, name):
        return (False, False) if 'socks5proxy' in name else (True, True)


class HttpCrashingSSH(RunningSSH):
    """SOCKS поднимается, HTTP-контейнер падает."""

    def run_sudo_command(self, command, *args, **kwargs):
        if command.startswith('docker inspect') and 'amnezia-httpproxy' in command:
            self.commands.append(command)
            return 'false 1', '', 0
        return super().run_sudo_command(command, *args, **kwargs)


class CrashingSSH(RunningSSH):
    """Контейнер есть, но 3proxy в нём падает на конфиге."""

    def run_sudo_command(self, command, *args, **kwargs):
        if command.startswith('docker inspect'):
            self.commands.append(command)
            return 'false 1', '', 0
        if command.startswith('docker logs'):
            self.commands.append(command)
            return 'fatal: invalid logformat', '', 0
        return super().run_sudo_command(command, *args, **kwargs)


def make_account(**overrides):
    account = {
        'login': 'alice',
        'password': 'Secret123',
        'type': 'socks5',
        'enabled': True,
        'acl_ips': [],
    }
    account.update(overrides)
    return account


def limited_account(**overrides):
    account = make_account(
        login='alice',
        password='pass1',
        acl_ips=['203.0.113.7/32'],
        max_conns=20,
        rate_in_mbps=80,
        rate_out_mbps=1.25,
        quota_mb=51200,
        quota_period='M',
        counter_in=11,
        counter_out=12,
        parent={
            'type': 'socks5', 'host': '10.0.0.5', 'port': 1080,
            'login': 'up_login', 'password': 'up_pass',
        },
    )
    account.update(overrides)
    return account


def manager(ssh=None):
    return Socks5Manager(ssh or FakeSSH())


class BuildConfigTest(unittest.TestCase):
    def test_socks_config_has_socks_listener_and_relevant_accounts(self):
        accounts = [
            make_account(login='alice', password='pa'),
            make_account(login='bob', password='pb', type='http'),
            make_account(login='carol', password='pc', type='both'),
            make_account(login='dave', password='pd', type='both', enabled=False),
        ]
        text = manager().build_config(accounts, 1080, 'socks')
        lines = text.splitlines()

        self.assertIn('socks -p1080', lines)
        self.assertFalse(any(line.startswith('proxy ') for line in lines))
        self.assertIn('auth strong', lines)

        users = [line for line in lines if line.startswith('users ')]
        self.assertEqual(len(users), 1)
        self.assertIn('alice:CL:pa', users[0])
        self.assertIn('carol:CL:pc', users[0])
        self.assertNotIn('bob', users[0])
        self.assertNotIn('dave', text)

    def test_http_config_has_proxy_listener_and_relevant_accounts(self):
        accounts = [
            make_account(login='alice', password='pa'),
            make_account(login='bob', password='pb', type='http'),
            make_account(login='carol', password='pc', type='both'),
        ]
        text = manager().build_config(accounts, 8312, 'http')
        lines = text.splitlines()

        self.assertIn('proxy -p8312', lines)
        self.assertFalse(any(line.startswith('socks ') for line in lines))
        users = '\n'.join(line for line in lines if line.startswith('users '))
        self.assertNotIn('alice', users)
        self.assertIn('bob:CL:pb', users)
        self.assertIn('carol:CL:pc', users)

    def test_empty_acl_becomes_allow_login(self):
        text = manager().build_config([make_account()], 1080, 'socks')
        self.assertIn('allow alice', text.splitlines())
        self.assertNotIn('allow alice *', text)

    def test_acl_is_joined_with_commas(self):
        account = make_account(
            acl_ips=['203.0.113.7/32', '198.51.100.0/24'])
        text = manager().build_config([account], 1080, 'socks')
        self.assertIn(
            'allow alice 203.0.113.7/32,198.51.100.0/24', text.splitlines())

    def test_ipv6_acl_is_written_without_brackets(self):
        account = make_account(acl_ips=['2001:db8::/32'])
        text = manager().build_config([account], 1080, 'socks')
        self.assertIn('allow alice 2001:db8::/32', text.splitlines())
        self.assertNotIn('allow alice [', text)

    def test_ipv6_parent_host_is_written_without_brackets(self):
        account = make_account(parent={
            'type': 'socks5', 'host': '2001:db8::1', 'port': 1080,
            'login': '', 'password': '',
        })
        text = manager().build_config([account], 1080, 'socks')
        self.assertIn('parent 1000 socks5 2001:db8::1 1080', text.splitlines())

    def test_ipv6_nameserver_keeps_brackets(self):
        text = manager().build_config(
            [make_account()], 1080, 'socks',
            {'dns_servers': ['2001:4860:4860::8888']})
        self.assertIn(
            'nserver [2001:4860:4860::8888]', text.splitlines())

    def test_parent_follows_its_own_allow(self):
        text = manager().build_config([limited_account()], 1080, 'socks')
        lines = text.splitlines()
        allow_idx = lines.index('allow alice 203.0.113.7/32')
        parent_idx = next(
            index for index, line in enumerate(lines) if line.startswith('parent '))
        self.assertEqual(parent_idx, allow_idx + 1)
        self.assertIn(
            'parent 1000 socks5 10.0.0.5 1080 up_login up_pass', lines)

    def test_no_parent_without_upstream(self):
        text = manager().build_config([make_account()], 1080, 'socks')
        self.assertFalse(any(
            line.startswith('parent ') for line in text.splitlines()))

    def test_connection_and_bandwidth_limits(self):
        text = manager().build_config([limited_account()], 1080, 'socks')
        lines = text.splitlines()
        self.assertIn('connlim 20 0 alice * * * * * *', lines)
        self.assertIn('bandlimin 80000000 alice * * * * * *', lines)
        self.assertIn('bandlimout 1250000 alice * * * * * *', lines)

    def test_quota_counters_are_written_and_unique(self):
        second = make_account(
            login='bob', password='pass2', quota_mb=1024, quota_period='D',
            counter_in=13, counter_out=14)
        text = manager().build_config(
            [limited_account(), second], 1080, 'socks')
        lines = text.splitlines()

        self.assertIn('countin 11 M 51200 alice * * * * * *', lines)
        self.assertIn('countout 12 M 51200 alice * * * * * *', lines)
        self.assertIn('countin 13 D 1024 bob * * * * * *', lines)
        self.assertIn('countout 14 D 1024 bob * * * * * *', lines)
        self.assertIn(
            'counter /var/lib/3proxy/counters M /var/lib/3proxy/report', lines)

        numbers = [int(match.group(1)) for match in (
            re.match(r'^count(?:in|out)\s+(\d+)\s', line) for line in lines)
            if match]
        self.assertEqual(len(numbers), 4)
        self.assertEqual(len(set(numbers)), 4)

    def test_options_are_applied(self):
        text = manager().build_config(
            [make_account()], 1080, 'socks', {
                'dns_servers': ['9.9.9.9', '1.0.0.1'],
                'maxconn': 321,
                'log_rotate_days': 7,
                'log_format': 'L%Y-%m-%d %U %I %O',
            })
        lines = text.splitlines()
        self.assertIn('nserver 9.9.9.9', lines)
        self.assertIn('nserver 1.0.0.1', lines)
        self.assertIn('maxconn 321', lines)
        self.assertIn('rotate 7', lines)
        self.assertIn('logformat "L%Y-%m-%d %U %I %O"', lines)

    def test_defaults_match_the_spec(self):
        lines = manager().build_config(
            [make_account()], 1080, 'socks').splitlines()
        for expected in (
                'nserver 8.8.8.8',
                'nserver 1.1.1.1',
                'nscache 65536',
                'timeouts 1 5 30 60 180 1800 15 60',
                'maxconn 200',
                'rotate 30',
                'logformat "L%Y-%m-%d %H:%M:%S %U %I %O %N"'):
            self.assertIn(expected, lines)

    def test_monthly_quota_raises_default_rotate_to_31(self):
        account = make_account(
            quota_mb=1024, quota_period='M', counter_in=1, counter_out=2)
        lines = manager().build_config([account], 1080, 'socks').splitlines()
        self.assertIn('rotate 31', lines)

    def test_explicit_rotate_wins_over_monthly_quota(self):
        account = make_account(
            quota_mb=1024, quota_period='M', counter_in=1, counter_out=2)
        lines = manager().build_config(
            [account], 1080, 'socks', {'log_rotate_days': 7}).splitlines()
        self.assertIn('rotate 7', lines)

    def test_daily_quota_keeps_default_rotate(self):
        account = make_account(
            quota_mb=1024, quota_period='D', counter_in=1, counter_out=2)
        lines = manager().build_config([account], 1080, 'socks').splitlines()
        self.assertIn('rotate 30', lines)

    def test_build_config_does_not_touch_ssh(self):
        ssh = FakeSSH()
        manager(ssh).build_config([make_account()], 1080, 'socks')
        self.assertEqual(ssh.commands, [])
        self.assertEqual(ssh.uploads, [])


class ValidationTest(unittest.TestCase):
    def test_invalid_login_raises(self):
        with self.assertRaises(ValueError):
            manager().build_config(
                [make_account(login='bad login!')], 1080, 'socks')

    def test_invalid_password_raises(self):
        with self.assertRaises(ValueError):
            manager().build_config(
                [make_account(password='pa;ss')], 1080, 'socks')

    def test_invalid_acl_raises(self):
        with self.assertRaises(ValueError):
            manager().build_config(
                [make_account(acl_ips=['300.1.1.1'])], 1080, 'socks')

    def test_invalid_parent_type_raises(self):
        account = make_account(parent={
            'type': 'ftp', 'host': '10.0.0.5', 'port': 21,
            'login': '', 'password': '',
        })
        with self.assertRaises(ValueError):
            manager().build_config([account], 1080, 'socks')

    def test_invalid_service_raises(self):
        with self.assertRaises(ValueError):
            manager().build_config([make_account()], 1080, 'dns')


class MigrationTest(unittest.TestCase):
    def test_parse_legacy_config_returns_one_socks5_account(self):
        accounts = manager().parse_accounts_from_config(LEGACY_CONFIG)
        self.assertEqual(len(accounts), 1)
        account = accounts[0]
        self.assertEqual(account['login'], 'proxy_user')
        self.assertEqual(account['password'], 'Secret123')
        self.assertEqual(account['type'], 'socks5')
        self.assertTrue(account['enabled'])
        self.assertTrue(account['legacy'])
        self.assertEqual(account['port'], 38080)

    def test_get_credentials_reads_first_account(self):
        ssh = FakeSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
        })
        self.assertEqual(
            manager(ssh).get_credentials(),
            {'port': 38080, 'username': 'proxy_user',
             'password': 'Secret123'})

    def test_parse_empty_config_returns_empty_list(self):
        self.assertEqual(manager().parse_accounts_from_config(''), [])
        self.assertEqual(manager().parse_accounts_from_config('socks -p1080'), [])


class UsageTest(unittest.TestCase):
    def test_read_usage_sums_in_and_out_bytes(self):
        log = (
            'L2026-11-20 12:00:00 alice 100 200 example.org\n'
            'L2026-11-20 12:00:01 bob 5 7 example.net\n'
            'L2026-11-20 12:00:02 alice 1 2 example.org\n'
        )
        usage = manager(FakeSSH(log=log)).read_usage(
            [make_account(login='alice')])
        self.assertEqual(usage, {'alice': 303})

    def test_read_usage_returns_empty_dict_on_error(self):
        class BrokenSSH(FakeSSH):
            def run_sudo_command(self, command, *args, **kwargs):
                raise RuntimeError('ssh is down')

        self.assertEqual(
            manager(BrokenSSH()).read_usage([make_account()]), {})

    def test_read_usage_includes_rotated_logs(self):
        ssh = FakeSSH(log='L2026-11-20 12:00:00 alice 1 2 host\n')
        self.assertEqual(
            manager(ssh).read_usage([make_account()]), {'alice': 3})
        command = next(
            cmd for cmd in ssh.commands if cmd.startswith('docker exec'))
        self.assertIn('sh -c', command)
        self.assertIn('3proxy.log*', command)


class ApplyTest(unittest.TestCase):
    def test_apply_creates_both_containers(self):
        ssh = FakeSSH()
        result = manager(ssh).apply(
            [make_account(login='alice', password='pw', type='both')],
            1080, http_port=8312, http_enabled=True)

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['socks_port'], 1080)
        self.assertEqual(result['http_port'], 8312)
        self.assertTrue(result['recreated'])
        self.assertFalse(result['restarted'])
        self.assertTrue(result['log'])

        uploaded = {path.rsplit('/', 1)[-1] for path, _ in ssh.uploads}
        self.assertIn('3proxy.cfg', uploaded)
        self.assertEqual(len(ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg')), 1)
        self.assertEqual(len(ssh.uploaded('/opt/amnezia/httpproxy/3proxy.cfg')), 1)

        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertEqual(len(runs), 2)
        self.assertTrue(any(
            '--name amnezia-socks5proxy' in cmd and '-p 1080:1080/tcp' in cmd
            for cmd in runs))
        self.assertTrue(any(
            '--name amnezia-httpproxy' in cmd and '-p 8312:8312/tcp' in cmd
            for cmd in runs))
        for cmd in runs:
            self.assertIn('/state:/var/lib/3proxy', cmd)
            self.assertIn('/logs:/var/log/3proxy', cmd)
            self.assertIn('/etc/3proxy:ro', cmd)
        self.assertTrue(any(
            '-v /opt/amnezia/socks5proxy:/etc/3proxy:ro' in cmd
            and '-v /opt/amnezia/socks5proxy/state:/var/lib/3proxy' in cmd
            for cmd in runs))
        self.assertTrue(any(
            '-v /opt/amnezia/httpproxy:/etc/3proxy:ro' in cmd
            and '-v /opt/amnezia/httpproxy/logs:/var/log/3proxy' in cmd
            for cmd in runs))

    def test_apply_without_http_writes_config_but_starts_only_socks(self):
        ssh = FakeSSH()
        result = manager(ssh).apply([make_account()], 1080)
        self.assertEqual(result['status'], 'success')
        self.assertIsNone(result['http_port'])
        self.assertEqual(len(
            ssh.uploaded('/opt/amnezia/httpproxy/3proxy.cfg')), 1)
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertEqual(len(runs), 1)
        self.assertIn('--name amnezia-socks5proxy', runs[0])

    def test_apply_restarts_when_ports_did_not_change(self):
        ssh = RunningSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
            '/opt/amnezia/httpproxy/3proxy.cfg': 'proxy -p8312\n',
        })
        result = manager(ssh).apply(
            [make_account()], 38080, http_port=8312, http_enabled=True)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['restarted'])
        self.assertFalse(result['recreated'])
        self.assertFalse(any(
            cmd.startswith('docker run') for cmd in ssh.commands))
        self.assertIn('docker restart amnezia-socks5proxy', ssh.commands)
        self.assertIn('docker restart amnezia-httpproxy', ssh.commands)

    def test_apply_recreates_when_port_changed(self):
        ssh = RunningSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
        })
        result = manager(ssh).apply([make_account()], 1080)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['recreated'])
        self.assertFalse(result['restarted'])
        self.assertTrue(any(
            cmd.startswith('docker rm -f amnezia-socks5proxy')
            for cmd in ssh.commands))
        self.assertTrue(any(
            cmd.startswith('docker run') and '-p 1080:1080/tcp' in cmd
            for cmd in ssh.commands))

    def test_apply_rejects_equal_ports(self):
        result = manager().apply(
            [make_account()], 1080, http_port=1080, http_enabled=True)
        self.assertEqual(result['status'], 'error')

    def test_apply_allows_http_on_disabled_socks_port(self):
        """Выключенный SOCKS-контейнер порт не занимает."""
        ssh = FakeSSH()
        result = manager(ssh).apply(
            [make_account(type='http')], 1080,
            http_port=1080, http_enabled=True, socks_enabled=False)
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['socks_enabled'])
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertEqual(len(runs), 1)
        self.assertIn('--name amnezia-httpproxy', runs[0])
        self.assertIn('-p 1080:1080/tcp', runs[0])

    def test_apply_failure_rolls_back_both_listeners(self):
        """SOCKS применён, HTTP упал → откатываем и SOCKS, а не только HTTP."""
        from unittest import mock
        ssh = HttpCrashingSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
            '/opt/amnezia/httpproxy/3proxy.cfg': 'proxy -p8312\n',
        })
        with mock.patch('managers.socks5_manager.time.sleep'):
            result = manager(ssh).apply(
                [make_account()], 38080, http_port=8312, http_enabled=True)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(
            ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg')[-1],
            LEGACY_CONFIG)
        self.assertIn('docker restart amnezia-socks5proxy', ssh.commands)

    def test_apply_rolls_back_config_when_container_dies(self):
        """Контейнер в цикле рестартов → ошибка и прежний конфиг на диске."""
        ssh = CrashingSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
        })
        result = manager(ssh).apply([make_account()], 38080)
        self.assertEqual(result['status'], 'error')
        self.assertIn('перезапускается', result['message'])
        self.assertEqual(
            ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg')[-1],
            LEGACY_CONFIG)
        # Контейнер существовал — откат возвращает его рестартом, не run.
        self.assertIn('docker restart amnezia-socks5proxy', ssh.commands)

    def test_remove_container_removes_both(self):
        ssh = FakeSSH()
        manager(ssh).remove_container()
        joined = '\n'.join(ssh.commands)
        for name in ('amnezia-socks5proxy', 'amnezia-httpproxy'):
            self.assertIn(f'docker stop {name}', joined)
            self.assertIn(f'docker rm -f {name}', joined)
        for path in ('/opt/amnezia/socks5proxy', '/opt/amnezia/httpproxy'):
            self.assertIn(f'rm -rf {path}', joined)

    def test_install_protocol_legacy_call_still_works(self):
        ssh = FakeSSH()
        result = manager(ssh).install_protocol(
            port=1080, username='u1', password='p1')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['port'], 1080)
        self.assertEqual(result['username'], 'u1')
        self.assertEqual(result['password'], 'p1')
        self.assertEqual(result['container_name'], 'amnezia-socks5proxy')
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertTrue(any('-p 1080:1080/tcp' in cmd for cmd in runs))

    def test_install_protocol_default_port_is_1080(self):
        ssh = FakeSSH()
        result = manager(ssh).install_protocol()
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['port'], 1080)
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertTrue(any('-p 1080:1080/tcp' in cmd for cmd in runs))

    def test_install_protocol_keeps_provided_accounts(self):
        ssh = FakeSSH()
        accounts = [
            make_account(login='alice', password='pa', type='both'),
            make_account(login='bob', password='pb'),
        ]
        result = manager(ssh).install_protocol(
            port=1080, http_port=8312, http_enabled=True, accounts=accounts)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['username'], 'alice')
        self.assertEqual(result['password'], 'pa')

        socks_config = '\n'.join(
            ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg'))
        self.assertIn('users alice:CL:pa bob:CL:pb', socks_config)
        self.assertNotIn('proxy_user', socks_config)

        http_config = '\n'.join(
            ssh.uploaded('/opt/amnezia/httpproxy/3proxy.cfg'))
        self.assertIn('alice:CL:pa', http_config)
        self.assertNotIn('bob:CL:pb', http_config)

    def test_update_credentials_rewrites_first_account(self):
        ssh = RunningSSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
        })
        result = manager(ssh).update_credentials(
            username='newuser', password='newpass')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['port'], 38080)
        uploaded = '\n'.join(
            ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg'))
        self.assertIn('users newuser:CL:newpass', uploaded)
        self.assertNotIn('proxy_user', uploaded)

    def test_update_credentials_keeps_http_only_instance_http_only(self):
        ssh = HttpOnlySSH({
            '/opt/amnezia/socks5proxy/3proxy.cfg': LEGACY_CONFIG,
            '/opt/amnezia/httpproxy/3proxy.cfg': 'users proxy_user:CL:Secret123\nproxy -p8312\n',
        })
        result = manager(ssh).update_credentials(username='newuser', password='newpass')
        self.assertEqual(result['status'], 'success')
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertFalse(any('--name amnezia-socks5proxy' in cmd for cmd in runs))
        http_config = '\n'.join(ssh.uploaded('/opt/amnezia/httpproxy/3proxy.cfg'))
        self.assertIn('newuser:CL:newpass', http_config)

    def test_apply_socks_disabled_removes_socks_and_starts_http(self):
        """listener_type=http: SOCKS-контейнер удалён, HTTP создан, один run."""
        ssh = FakeSSH()
        socks_name = 'amnezia-socks5proxy'
        original_state = getattr(ssh, 'docker_container_state', None)

        def state(name):
            if original_state:
                return original_state(name)
            # SOCKS-контейнер есть, HTTP-контейнера ещё нет.
            return (True, True) if name == socks_name else (False, False)

        ssh.docker_container_state = state
        result = manager(ssh).apply(
            [make_account(login='alice', password='pw', type='both')],
            1080, http_port=8312, http_enabled=True, socks_enabled=False)

        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['socks_enabled'])
        self.assertTrue(result['http_enabled'])
        joined = '\n'.join(ssh.commands)
        self.assertIn(f'docker stop {socks_name}', joined)
        self.assertIn(f'docker rm -f {socks_name}', joined)
        runs = [cmd for cmd in ssh.commands if cmd.startswith('docker run')]
        self.assertEqual(len(runs), 1)
        self.assertIn('--name amnezia-httpproxy', runs[0])
        self.assertIn('-p 8312:8312/tcp', runs[0])
        # Конфиг SOCKS остаётся на диске: включение позже не потребует записи.
        self.assertEqual(
            len(ssh.uploaded('/opt/amnezia/socks5proxy/3proxy.cfg')), 1)

    def test_apply_without_any_listener_raises(self):
        with self.assertRaises(ValueError):
            manager().apply([make_account()], 1080,
                            http_port=8312, http_enabled=False,
                            socks_enabled=False)

    def test_apply_http_disabled_removes_http_container(self):
        ssh = RunningSSH()
        result = manager(ssh).apply(
            [make_account()], 38080, http_port=8312, http_enabled=False,
            socks_enabled=True)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['socks_enabled'])
        self.assertFalse(result['http_enabled'])
        joined = '\n'.join(ssh.commands)
        self.assertIn('docker stop amnezia-httpproxy', joined)
        self.assertIn('docker rm -f amnezia-httpproxy', joined)

    def test_docker_ipv6_info_is_cheap_and_safe(self):
        self.assertEqual(
            manager()._docker_ipv6_info(),
            {'installed': True, 'ipv6_enabled': False})

    def test_second_instance_uses_suffixed_names(self):
        ssh = FakeSSH()
        m = Socks5Manager(ssh, 'socks5__2')
        self.assertEqual(m.container_name, 'amnezia-socks5proxy-2')
        self.assertEqual(m.config_dir, '/opt/amnezia/socks5proxy-2')
        self.assertEqual(m._http_container_name(), 'amnezia-httpproxy-2')
        self.assertEqual(m._http_config_dir(), '/opt/amnezia/httpproxy-2')



class LogFormatTest(unittest.TestCase):
    """logformat — шаблон с %-переменными, а не тип ротации D/L/E."""

    def test_rotation_letter_falls_back_to_default(self):
        for value in ('L', 'D', 'E', ''):
            self.assertEqual(
                _validate_log_format(value),
                'L%Y-%m-%d %H:%M:%S %U %I %O %N', value)

    def test_real_format_is_kept(self):
        self.assertEqual(_validate_log_format('L%Y %U'), 'L%Y %U')
        self.assertEqual(_validate_log_format('G%Y %U'), 'G%Y %U')

    def test_format_must_start_with_l_or_g(self):
        """3proxy принимает только форматы, начинающиеся с L или G."""
        with self.assertRaises(ValueError):
            _validate_log_format('%Y-%m-%d %U')

    def test_config_never_gets_bare_rotation_letter(self):
        text = Socks5Manager(FakeSSH()).build_config(
            [make_account(login='alice', password='pw', type='both')],
            1080, 'socks', {'log_format': 'L'})
        self.assertNotIn('logformat "L"', text)
        self.assertIn('%U', text)

class ActivityTest(unittest.TestCase):
    """Возраст активности для зелёной точки: локальное время лога + tz хоста."""

    def test_read_stats_reads_each_log_once(self):
        """Один вызов статуса: SOCKS+HTTP логи читаются по одному разу."""
        ssh = RunningSSH(log='2026-11-20 22:25:30 alice 10 20 SOCK5\n')
        usage, activity = manager(ssh).read_stats([make_account(login='alice')])
        self.assertIn('alice', usage)
        self.assertIn('alice', activity)
        log_calls = [c for c in ssh.commands if '3proxy.log' in c]
        self.assertEqual(len(log_calls), 2)  # два контейнера, по одному чтению

    def test_activity_uses_host_clock_and_timezone(self):
        from datetime import datetime, timezone
        epoch = int(datetime(2026, 11, 20, 22, 25, 30,
                             tzinfo=timezone.utc).timestamp())
        log = ('2026-11-20 22:25:30 alice 10 20 SOCK5\n'
               '2026-11-20 22:20:00 bob 1 2 SOCK5\n')
        ssh = FakeSSH(log=log)
        ssh.now = f'{epoch + 60} +0000'
        activity = manager(ssh).read_activity([
            make_account(login='alice'), make_account(login='bob')])
        self.assertEqual(activity['alice'], 60)
        self.assertEqual(activity['bob'], 390)

    def test_activity_respects_host_timezone(self):
        from datetime import datetime, timezone
        # Лог «22:25:30» на хосте +03:00 — это 19:25:30 UTC.
        epoch = int(datetime(2026, 11, 20, 22, 25, 30,
                             tzinfo=timezone.utc).timestamp())
        ssh = FakeSSH(log='2026-11-20 22:25:30 alice 10 20 SOCK5\n')
        ssh.now = f'{epoch + 60} +0300'
        activity = manager(ssh).read_activity([make_account(login='alice')])
        self.assertEqual(activity['alice'], 3 * 3600 + 60)

    def test_activity_empty_without_log(self):
        self.assertEqual(manager(FakeSSH()).read_activity([]), {})

if __name__ == '__main__':
    unittest.main()
