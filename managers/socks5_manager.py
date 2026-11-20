"""Менеджер прокси 3proxy: SOCKS5- и HTTP-листенер на одном сервере.

Историческое имя класса Socks5Manager сохранено: модуль вызывают app.py и
telegram_bot.py. Один инстанс — до двух контейнеров (amnezia-socks5proxy и
amnezia-httpproxy) с общим набором учёток из data.json. Конфиг 3proxy
генерируется целиком и никогда не собирается из непроверенных значений.
"""

import ipaddress
import logging
import re
import secrets
import shlex
import string
import time
import uuid
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# В конфиг попадают только эти символы: значения приходят из data.json,
# а 3proxy.cfg — исполняемый файл, а не текст.
_CREDENTIAL_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
_HOST_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
_PARENT_TYPES = ('socks5', 'http', 'connect')
_QUOTA_PERIODS = ('H', 'D', 'W', 'M')
_ACCOUNT_TYPES = ('socks5', 'http', 'both')
_SERVICES = {'socks': 'socks', 'http': 'proxy'}


def _generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _validate_credential(value, label):
    """Логин/пароль: только [A-Za-z0-9_.-], иначе ValueError."""
    text = str(value if value is not None else '').strip()
    if not text:
        raise ValueError(f'{label}: пустое значение')
    if not _CREDENTIAL_RE.fullmatch(text):
        raise ValueError(f'{label}: допустимы только A-Za-z0-9_.-')
    return text


def _validate_port(value, label='port'):
    if isinstance(value, bool):
        raise ValueError(f'{label}: ожидается целое число')
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f'{label}: ожидается целое число')
    if not 1 <= port <= 65535:
        raise ValueError(f'{label}: порт вне диапазона 1-65535')
    return port


def _optional_int(value, label, minimum=1):
    """None/пустая строка → None; иначе целое не меньше minimum."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ValueError(f'{label}: ожидается целое число')
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f'{label}: ожидается целое число')
    if number < minimum:
        raise ValueError(f'{label}: значение меньше {minimum}')
    return number


def _validate_mbps(value, label):
    """Мбит/с → биты/с (3proxy bandlim* принимает bps)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ValueError(f'{label}: ожидается число')
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{label}: ожидается число')
    if number < 0:
        raise ValueError(f'{label}: значение не может быть отрицательным')
    if number == 0:
        # Ноль в UI означает «без ограничения» — не пишем bandlim.
        return None
    return int(round(number * 1_000_000))


def _strip_ipv6_brackets(value):
    """Разбирает как голый IP, так и вид [2001:db8::1]/64."""
    text = str(value or '').strip()
    match = re.fullmatch(r'\[([^\]]+)\](?:/(\d{1,3}))?', text)
    if match:
        text = match.group(1) + (f'/{match.group(2)}' if match.group(2) else '')
    return text


def _format_acl_entry(value):
    text = _strip_ipv6_brackets(value)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f'ACL: некорректный IP/CIDR: {value!r}')
    # 3proxy разбирает ACL через afdetect()/getip46(): скобки там
    # недопустимы, IPv6 пишется голым адресом (в отличие от nserver).
    return f'{network.network_address}/{network.prefixlen}'


def _format_nameserver(value):
    text = _strip_ipv6_brackets(value)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f'nserver: некорректный IP-адрес: {value!r}')
    # У nserver отдельный парсер, для IPv6 он требует квадратные скобки.
    if address.version == 6:
        return f'[{address}]'
    return str(address)


def _validate_host(value):
    text = _strip_ipv6_brackets(value)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        if not _HOST_RE.fullmatch(text):
            raise ValueError(f'host: недопустимое значение {value!r}')
        return text
    # parent разбирается тем же getip46(), что и ACL: без скобок.
    return str(address)


def _dns_list(value):
    if value is None:
        return None
    if isinstance(value, str):
        return [part for part in re.split(r'[\s,]+', value) if part]
    return [str(part) for part in value if str(part).strip()]


def _is_enabled(account):
    value = account.get('enabled', True)
    if isinstance(value, str):
        return value.strip().lower() not in ('0', 'false', 'no', 'off')
    return bool(value)


def _has_monthly_quota(account):
    """Есть ли у учётки квота с месячным периодом (для срока хранения лога)."""
    quota = account.get('quota_mb')
    if quota is None or (isinstance(quota, str) and not quota.strip()):
        return False
    try:
        if int(quota) <= 0:
            return False
    except (TypeError, ValueError):
        return False
    return str(account.get('quota_period') or 'M').strip().upper() == 'M'


# Тип ротации (`log ... D`) — одна буква; формат строки (`logformat`) — шаблон
# с %-переменными. Раньше UI клал в logformat значение из списка D/L/E, и
# 3proxy писал `logformat "L"`: лог не заполнялся, расход квоты был нулевым.
_LOG_ROTATE_ONLY = {'D', 'L', 'E', 'H', 'W', 'M', 'Y', 'C'}
DEFAULT_LOG_FORMAT = 'L%Y-%m-%d %H:%M:%S %U %I %O %N'


def _validate_log_format(value):
    text = str(value if value is not None else '')
    if not text.strip():
        return DEFAULT_LOG_FORMAT
    if len(text) > 200 or any(ch in text for ch in ('"', chr(92), chr(10), chr(13))):
        raise ValueError('log_format: недопустимые символы')
    stripped = text.strip()
    # Голая буква типа ротации не содержит ни одной %-переменной — это
    # заведомо не формат строки, а старое значение из селекта. Мигрируем
    # молча; любой другой текст без % — ошибка ввода, а не повод угадывать.
    if stripped in _LOG_ROTATE_ONLY:
        return DEFAULT_LOG_FORMAT
    if '%' not in stripped:
        raise ValueError('log_format: нужна хотя бы одна %-переменная')
    # 3proxy принимает только форматы, начинающиеся с L (локальное время)
    # или G (GMT); иначе он отвергает конфиг целиком.
    if stripped[:1] not in ('L', 'G'):
        raise ValueError('log_format: формат должен начинаться с L или G')
    return stripped


class Socks5Manager:
    PROTOCOL = 'socks5'
    CONTAINER_NAME = 'amnezia-socks5proxy'
    HTTP_CONTAINER_NAME = 'amnezia-httpproxy'
    IMAGE_NAME = '3proxy/3proxy:0.9.5'
    IMAGE_VERSION = '0.9.5'
    CONFIG_DIR = '/opt/amnezia/socks5proxy'
    HTTP_CONFIG_DIR = '/opt/amnezia/httpproxy'
    CONFIG_PATH = '/etc/3proxy/3proxy.cfg'
    LOG_PATH = '/var/log/3proxy/3proxy.log'

    DEFAULT_PORT = 1080  # прежний дефолт Amnezia был 38080
    DEFAULT_HTTP_PORT = 8312
    DEFAULT_USERNAME = 'proxy_user'

    DEFAULT_DNS_SERVERS = ('8.8.8.8', '1.1.1.1')
    DEFAULT_MAXCONN = 200
    DEFAULT_LOG_ROTATE_DAYS = 30
    DEFAULT_LOG_FORMAT = 'L%Y-%m-%d %H:%M:%S %U %I %O %N'
    COUNTER_FILE = '/var/lib/3proxy/counters'
    COUNTER_REPORT = '/var/lib/3proxy/report'
    COUNTER_TYPE = 'M'

    def __init__(self, ssh, protocol='socks5'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.config_dir = self._config_dir(self.protocol)

    def _instance_index(self, protocol=None):
        parts = str(protocol or self.protocol or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.CONTAINER_NAME if idx <= 1 else f'{self.CONTAINER_NAME}-{idx}'

    def _config_dir(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.CONFIG_DIR if idx <= 1 else f'{self.CONFIG_DIR}-{idx}'

    def _http_container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.HTTP_CONTAINER_NAME if idx <= 1 else f'{self.HTTP_CONTAINER_NAME}-{idx}'

    def _http_config_dir(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.HTTP_CONFIG_DIR if idx <= 1 else f'{self.HTTP_CONFIG_DIR}-{idx}'

    # ===================== STATUS =====================

    def check_docker_installed(self):
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def _container_state(self, name):
        """(running, restart_count) контейнера; None, если его нет."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker inspect -f '{{{{.State.Running}}}} {{{{.RestartCount}}}}' "
            f"{name} 2>/dev/null")
        if code != 0:
            return None
        parts = (out or '').split()
        if len(parts) != 2:
            return None
        try:
            return parts[0].lower() == 'true', int(parts[1])
        except ValueError:
            return None

    def _wait_container_healthy(self, name, baseline_restarts, attempts=8, delay=0.5):
        """Ждать живой контейнер, у которого не выросло число рестартов.

        `--restart always` маскирует упавший 3proxy: docker run возвращает 0,
        контейнер тут же перезапускается, а прокси не слушает. Рост
        RestartCount относительно значения до действия — признак падения.
        """
        state = None
        for _ in range(attempts):
            state = self._container_state(name)
            if state and state[0] and state[1] <= baseline_restarts:
                return True, state[1]
            time.sleep(delay)
        return False, (state[1] if state else 0)

    def _container_log_tail(self, name, lines=8):
        out, _, _ = self.ssh.run_sudo_command(
            f'docker logs --tail {int(lines)} {name} 2>&1')
        return (out or '').strip()

    def _container_exists(self, name):
        state_fn = getattr(self.ssh, 'docker_container_state', None)
        if state_fn:
            state = state_fn(name)
            if state is not None:
                return bool(state[0])
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{name}$ --format '{{{{.Names}}}}'"
        )
        return name in (out or '').split()

    def _container_running(self, name):
        state_fn = getattr(self.ssh, 'docker_container_state', None)
        if state_fn:
            state = state_fn(name)
            if state is not None:
                return bool(state[1])
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in (out or '')

    def check_protocol_installed(self, protocol_type='socks5'):
        return self._container_exists(self._container_name(protocol_type))

    def check_container_running(self, protocol_type='socks5'):
        return self._container_running(self._container_name(protocol_type))

    def _docker_ipv6_info(self):
        return {'installed': self.check_docker_installed(), 'ipv6_enabled': False}

    def get_server_status(self, protocol_type='socks5'):
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type)
        creds = self.get_credentials() if exists else {}

        http_name = self._http_container_name(protocol_type)
        http_exists = self._container_exists(http_name)
        http_running = self._container_running(http_name) if http_exists else False
        http_port = None
        if http_exists:
            http_port = self._listener_port(
                self._read_config_file(self._http_config_dir(protocol_type)))

        image = self.IMAGE_NAME
        if exists:
            out, _, code = self.ssh.run_sudo_command(
                f"docker inspect --format '{{{{.Config.Image}}}}' "
                f"{self._container_name(protocol_type)} 2>/dev/null")
            if code == 0 and (out or '').strip():
                image = out.strip()

        return {
            'container_exists': exists,
            'container_running': running,
            'port': creds.get('port'),
            'username': creds.get('username'),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': self._instance_index(protocol_type),
            'container_name': self._container_name(protocol_type),
            'http_port': http_port,
            'http_container_running': http_running,
            'http_enabled': http_exists,
            # SOCKS-листенер: контейнер существует → он включён.
            'socks_enabled': exists,
            'image': image,
            'version': image.rsplit(':', 1)[-1] if ':' in image else self.IMAGE_VERSION,
        }

    # ===================== CONFIG I/O =====================

    @staticmethod
    def _listener_port(text):
        match = re.search(r'^\s*(?:socks|proxy)\s+-p\s*(\d+)', text or '', re.MULTILINE)
        return int(match.group(1)) if match else None

    def _read_config_file(self, config_dir):
        path = f'{config_dir}/3proxy.cfg'
        out, _, code = self.ssh.run_sudo_command(
            f"cat {shlex.quote(path)} 2>/dev/null")
        if code == 0 and (out or '').strip():
            return out
        return ''

    def _read_config(self):
        text = self._read_config_file(self.config_dir)
        if text:
            return text
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {self.CONFIG_PATH} 2>/dev/null")
        if code != 0:
            return ''
        return out or ''

    def _write_config(self, config_dir, config_text):
        self.ssh.run_sudo_command(f"mkdir -p {shlex.quote(config_dir)}")
        path = f'{config_dir}/3proxy.cfg'
        self.ssh.upload_file_sudo(config_text, path)
        self.ssh.run_sudo_command(f"chmod 0600 {shlex.quote(path)}")

    # ===================== CONFIG GENERATION =====================

    @staticmethod
    def _accounts_for_service(accounts, service):
        result = []
        for account in accounts or []:
            if not isinstance(account, dict):
                raise ValueError('accounts: каждая учётка должна быть словарём')
            if not _is_enabled(account):
                continue
            kind = str(account.get('type') or 'socks5').strip().lower()
            if kind not in _ACCOUNT_TYPES:
                raise ValueError(f'type: ожидается socks5/http/both, получено {kind!r}')
            if service == 'socks' and kind not in ('socks5', 'both'):
                continue
            if service == 'http' and kind not in ('http', 'both'):
                continue
            result.append(account)
        return result

    @staticmethod
    def _account_login(account):
        value = account.get('login')
        if value is None or not str(value).strip():
            value = account.get('username')
        return _validate_credential(value, 'login')

    @staticmethod
    def _parent_line(parent):
        if not parent:
            return ''
        if not isinstance(parent, dict):
            raise ValueError('parent: ожидается словарь')
        host = str(parent.get('host') or '').strip()
        if not host:
            return ''
        proxy_type = str(parent.get('type') or 'socks5').strip().lower()
        if proxy_type not in _PARENT_TYPES:
            raise ValueError('parent type: ожидается socks5/http/connect')
        port = _validate_port(parent.get('port'), 'parent port')
        host_text = _validate_host(host)
        login = str(parent.get('login') or '').strip()
        password = str(parent.get('password') or '').strip()
        tail = ''
        if login or password:
            if not (login and password):
                raise ValueError('parent: логин и пароль задаются вместе')
            tail = ' ' + _validate_credential(login, 'parent login')
            tail += ' ' + _validate_credential(password, 'parent password')
        return f'parent 1000 {proxy_type} {host_text} {port}{tail}'

    def build_config(self, accounts, port, service, options=None):
        """Собрать текст 3proxy.cfg. SSH не трогает — чистая функция.

        service: 'socks' (`socks -p…`) или 'http' (`proxy -p…`).
        accounts: список учёток из data.json (раздел 4.1 ТЗ).
        options: dns_servers, maxconn, log_rotate_days, log_format.
        """
        if service not in _SERVICES:
            raise ValueError("service: ожидается 'socks' или 'http'")
        port = _validate_port(port, 'port')
        if options is None:
            options = {}
        if not isinstance(options, dict):
            raise ValueError('options: ожидается словарь')

        dns_raw = _dns_list(options.get('dns_servers'))
        dns_servers = dns_raw if dns_raw is not None else list(self.DEFAULT_DNS_SERVERS)
        if not dns_servers:
            raise ValueError('dns_servers: пустой список')

        maxconn_raw = options.get('maxconn', self.DEFAULT_MAXCONN)
        if maxconn_raw is None or (isinstance(maxconn_raw, str) and not maxconn_raw.strip()):
            maxconn_raw = self.DEFAULT_MAXCONN
        maxconn = _optional_int(maxconn_raw, 'maxconn', minimum=0)

        active = self._accounts_for_service(accounts, service)

        # Месячный счётчик не должен обнулиться из-за суточной ротации:
        # при месячной квоте храним лог не меньше 31 дня (если срок не задан).
        rotate_default = self.DEFAULT_LOG_ROTATE_DAYS
        if any(_has_monthly_quota(account) for account in active):
            rotate_default = max(rotate_default, 31)

        rotate_raw = options.get(
            'log_rotate_days', options.get('rotate', rotate_default))
        if rotate_raw is None or (isinstance(rotate_raw, str) and not rotate_raw.strip()):
            rotate_raw = rotate_default
        rotate = _optional_int(rotate_raw, 'log_rotate_days', minimum=1)

        log_format = _validate_log_format(
            options.get('log_format') or self.DEFAULT_LOG_FORMAT)

        lines = []
        for server in dns_servers:
            lines.append(f'nserver {_format_nameserver(server)}')
        lines.append('nscache 65536')
        lines.append('timeouts 1 5 30 60 180 1800 15 60')
        if maxconn:
            lines.append(f'maxconn {maxconn}')
        lines.append(f'log {self.LOG_PATH} D')
        lines.append(f'rotate {rotate}')
        lines.append(f'logformat "{log_format}"')
        lines.append('auth strong')

        prepared = []
        users = []
        logins = set()
        for account in active:
            login = self._account_login(account)
            if login in logins:
                raise ValueError(f'login: повторяющаяся учётка {login!r}')
            logins.add(login)
            password = _validate_credential(
                account.get('password'), f'password ({login})')
            users.append(f'{login}:CL:{password}')
            prepared.append((account, login))
        if users:
            lines.append('users ' + ' '.join(users))

        counter_lines = []
        used_counters = set()
        for account, login in prepared:
            acl_raw = account.get('acl_ips') or []
            if isinstance(acl_raw, str):
                acl_raw = _dns_list(acl_raw) or []
            acl = [str(item).strip() for item in acl_raw if str(item).strip()]
            acl = [item for item in acl if item != '*']
            if acl:
                lines.append(
                    f'allow {login} ' + ','.join(_format_acl_entry(item) for item in acl))
            else:
                lines.append(f'allow {login}')

            parent_line = self._parent_line(account.get('parent'))
            if parent_line:
                lines.append(parent_line)

            max_conns = _optional_int(
                account.get('max_conns'), f'max_conns ({login})')
            if max_conns:
                lines.append(f'connlim {max_conns} 0 {login} * * * * * *')

            rate_in = _validate_mbps(
                account.get('rate_in_mbps'), f'rate_in_mbps ({login})')
            if rate_in:
                lines.append(f'bandlimin {rate_in} {login} * * * * * *')

            rate_out = _validate_mbps(
                account.get('rate_out_mbps'), f'rate_out_mbps ({login})')
            if rate_out:
                lines.append(f'bandlimout {rate_out} {login} * * * * * *')

            quota_mb = _optional_int(
                account.get('quota_mb'), f'quota_mb ({login})')
            if quota_mb:
                period = str(account.get('quota_period') or 'M').strip().upper()
                if period not in _QUOTA_PERIODS:
                    raise ValueError(
                        f'quota_period ({login}): ожидается H/D/W/M')
                counter_in = _optional_int(
                    account.get('counter_in'), f'counter_in ({login})')
                counter_out = _optional_int(
                    account.get('counter_out'), f'counter_out ({login})')
                if not counter_in or not counter_out:
                    raise ValueError(
                        f'counter_in/counter_out ({login}): обязательны при квоте')
                for number in (counter_in, counter_out):
                    if number in used_counters:
                        raise ValueError(
                            f'counter ({login}): номер {number} уже занят')
                    used_counters.add(number)
                counter_lines.append(
                    f'countin {counter_in} {period} {quota_mb} {login} * * * * * *')
                counter_lines.append(
                    f'countout {counter_out} {period} {quota_mb} {login} * * * * * *')

        if counter_lines:
            lines.append(
                f'counter {self.COUNTER_FILE} {self.COUNTER_TYPE} {self.COUNTER_REPORT}')
            lines.extend(counter_lines)

        lines.append(f'{_SERVICES[service]} -p{port}')
        return '\n'.join(lines) + '\n'

    # ===================== PARSING / MIGRATION =====================

    def parse_accounts_from_config(self, text):
        """Разобрать существующий одноучётный конфиг для миграции.

        Возвращает список из одной учётки типа socks5 (раздел 4.0 ТЗ).
        Порт листенера кладётся в поле port — вызывающий код сохраняет его
        в настройках инстанса.
        """
        accounts = self._parse_config_accounts(text)
        if not accounts:
            return []
        account = accounts[0]
        account['type'] = 'socks5'
        account['legacy'] = True
        return [account]

    def _parse_config_accounts(self, text):
        """Полный разбор сгенерированного конфига: users + лимиты + parent."""
        if not text:
            return []
        port = self._listener_port(text)
        accounts = []
        by_login = {}
        match = re.search(r'^\s*users\s+(.+)$', text, re.MULTILINE)
        if match:
            for token in match.group(1).split():
                parts = token.split(':')
                if len(parts) < 3 or parts[1].upper() != 'CL':
                    continue
                login = parts[0]
                password = ':'.join(parts[2:])
                if not login or login in by_login:
                    continue
                account = {
                    'id': str(uuid.uuid4()),
                    'name': login,
                    'login': login,
                    'password': password,
                    'type': 'socks5',
                    'enabled': True,
                    'user_id': None,
                    'acl_ips': [],
                    'max_conns': None,
                    'rate_in_mbps': None,
                    'rate_out_mbps': None,
                    'quota_mb': None,
                    'quota_period': 'M',
                    'counter_in': None,
                    'counter_out': None,
                    'parent': {
                        'type': 'socks5', 'host': '', 'port': '',
                        'login': '', 'password': '',
                    },
                    'created_at': datetime.now(timezone.utc).replace(
                        microsecond=0).isoformat(),
                    'port': port,
                }
                by_login[login] = account
                accounts.append(account)
        if not accounts:
            return []

        current = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            allow = re.match(r'^allow\s+(\S+)(?:\s+(\S+))?', line)
            if allow:
                current = by_login.get(allow.group(1))
                if (current is not None and allow.group(2)
                        and allow.group(2) != '*'):
                    current['acl_ips'] = [
                        part for part in allow.group(2).split(',') if part]
                continue
            parent = re.match(
                r'^parent\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)(?:\s+(\S+)\s+(\S+))?',
                line)
            if parent and current is not None:
                current['parent'] = {
                    'type': parent.group(1),
                    'host': _strip_ipv6_brackets(parent.group(2)),
                    'port': int(parent.group(3)),
                    'login': parent.group(4) or '',
                    'password': parent.group(5) or '',
                }
                continue
            connlim = re.match(r'^connlim\s+(\d+)\s+\S+\s+(\S+)', line)
            if connlim:
                account = by_login.get(connlim.group(2))
                if account is not None:
                    account['max_conns'] = int(connlim.group(1))
                continue
            band_in = re.match(r'^bandlimin\s+(\d+)\s+(\S+)', line)
            if band_in:
                account = by_login.get(band_in.group(2))
                if account is not None:
                    account['rate_in_mbps'] = int(band_in.group(1)) / 1_000_000
                continue
            band_out = re.match(r'^bandlimout\s+(\d+)\s+(\S+)', line)
            if band_out:
                account = by_login.get(band_out.group(2))
                if account is not None:
                    account['rate_out_mbps'] = int(band_out.group(1)) / 1_000_000
                continue
            count_in = re.match(
                r'^countin\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)', line)
            if count_in:
                account = by_login.get(count_in.group(4))
                if account is not None:
                    account['counter_in'] = int(count_in.group(1))
                    account['quota_period'] = count_in.group(2)
                    account['quota_mb'] = int(count_in.group(3))
                continue
            count_out = re.match(
                r'^countout\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)', line)
            if count_out:
                account = by_login.get(count_out.group(4))
                if account is not None:
                    account['counter_out'] = int(count_out.group(1))
                    if not account.get('quota_mb'):
                        account['quota_period'] = count_out.group(2)
                        account['quota_mb'] = int(count_out.group(3))
        return accounts

    def _parse_credentials(self, config_text):
        """Старый компактный формат {port, username, password}."""
        creds = {'port': self._listener_port(config_text), 'username': None,
                 'password': None}
        if not config_text:
            return creds
        match = re.search(
            r'^\s*users\s+([^:\s]+):CL:(\S+)', config_text, re.MULTILINE)
        if match:
            creds['username'] = match.group(1)
            creds['password'] = match.group(2)
        return creds

    def get_credentials(self):
        text = self._read_config()
        accounts = self._parse_config_accounts(text)
        if accounts:
            first = accounts[0]
            return {
                'port': self._listener_port(text),
                'username': first['login'],
                'password': first['password'],
            }
        return self._parse_credentials(text)

    # ===================== USAGE =====================

    @staticmethod
    def _account_logins(accounts):
        """Логины и признак HTTP-учёток: нужен набор контейнеров для лога."""
        logins = set()
        http_accounts = False
        for account in accounts or []:
            if not isinstance(account, dict):
                continue
            login = str(
                account.get('login') or account.get('username') or '').strip()
            if login:
                logins.add(login)
            kind = str(account.get('type') or 'socks5').strip().lower()
            if kind in ('http', 'both'):
                http_accounts = True
        return logins, http_accounts

    def _proxy_logs(self, accounts=None):
        """{container: строки вывода}; первая строка — `date +"%s %z"`.

        Часовой пояс берём у контейнера, а не у хоста: docker по умолчанию
        живёт в UTC, а хост может быть в +01:00 — иначе возраст активности
        уезжает на разницу зон.
        """
        names = [self.container_name]
        # HTTP-контейнер включаем по факту существования, а не по типам
        # учёток: при разошедшихся данных его лог всё равно нужен.
        http_name = self._http_container_name()
        if self._container_exists(http_name):
            names.append(http_name)
        logs = {}
        inner = f'date +"%s %z"; cat {self.LOG_PATH}* 2>/dev/null'
        for name in names:
            out, _, code = self.ssh.run_sudo_command(
                f'docker exec {name} sh -c {shlex.quote(inner)}')
            logs[name] = out.splitlines() if code == 0 and out else []
        return logs

    @staticmethod
    def _container_clock(lines):
        """(epoch, tz) из первой строки вывода контейнера."""
        if not lines:
            return None, None
        parts = lines[0].split()
        try:
            now_epoch = int(parts[0])
        except (IndexError, ValueError):
            return None, None
        tz = timezone.utc
        if len(parts) > 1 and re.fullmatch(r'[+-]\d{4}', parts[1]):
            sign = 1 if parts[1][0] == '+' else -1
            tz = timezone(sign * timedelta(hours=int(parts[1][1:3]),
                                           minutes=int(parts[1][3:5])))
        return now_epoch, tz

    def read_stats(self, accounts=None):
        """Расход и активность по одному чтению лога: ({login: байт}, {login: сек}).

        `/proxy/status` нужны оба показателя; читать логи дважды (на каждый
        листенер) дорого — ротированные логи бывают большими.
        """
        try:
            logs = self._proxy_logs(accounts)
            return (self._usage_from_logs(logs, accounts),
                    self._activity_from_logs(logs))
        except Exception as exc:
            logger.debug('3proxy log stats read failed: %s', exc)
            return {}, {}

    def read_usage(self, accounts=None):
        """Best-effort расход по логу 3proxy: {login: байт}. Ошибки → {}."""
        return self.read_stats(accounts)[0]

    def read_activity(self, accounts=None):
        """Возраст последней активности по логу: {login: секунд}. Ошибки → {}.

        Лог и «сейчас» берём из одного контейнера: 3proxy пишет локальное
        время контейнера, а не панели.
        """
        return self.read_stats(accounts)[1]

    def _usage_from_logs(self, logs, accounts=None):
        logins, _ = self._account_logins(accounts)
        usage = {}
        # Строка 3proxy: "2026-11-20 14:21:28 smoke_both 4544 1868 SOCK5".
        # "L" в logformat — это признак локального времени, а не символ
        # в выводе: требовать его нельзя.
        pattern = re.compile(
            r'^\S+\s+\S+\s+(\S+)\s+(\d+)\s+(\d+)(?:\s|$)')
        for lines in logs.values():
            for line in lines[1:]:
                match = pattern.match(line.strip())
                if not match:
                    continue
                login = match.group(1)
                if logins and login not in logins:
                    continue
                usage[login] = usage.get(login, 0) + int(match.group(2))
                usage[login] += int(match.group(3))
        return usage

    def _activity_from_logs(self, logs):
        pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s')
        activity = {}
        for lines in logs.values():
            now_epoch, tz = self._container_clock(lines)
            if now_epoch is None:
                continue
            for line in lines[1:]:
                match = pattern.match(line.strip())
                if not match:
                    continue
                try:
                    stamp = datetime.strptime(
                        match.group(1), '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    continue
                age = max(0, int(now_epoch - stamp.replace(tzinfo=tz).timestamp()))
                login = match.group(2)
                if login not in activity or age < activity[login]:
                    activity[login] = age
        return activity

    # ===================== CONTAINERS =====================

    def _invalidate_docker_cache(self):
        fn = getattr(self.ssh, 'docker_ps_invalidate', None)
        if fn:
            try:
                fn()
            except Exception:
                pass

    def _state_dirs(self, config_dir):
        state = f'{config_dir}/state'
        logs = f'{config_dir}/logs'
        self.ssh.run_sudo_command(
            f"mkdir -p {shlex.quote(state)} {shlex.quote(logs)}")
        self.ssh.run_sudo_command(
            f"chmod 0777 {shlex.quote(state)} {shlex.quote(logs)}")

    def _run_container(self, name, config_dir, port):
        self._state_dirs(config_dir)
        run_cmd = (
            'docker run -d --restart always '
            f'--name {name} '
            f'-p {int(port)}:{int(port)}/tcp '
            f'-v {config_dir}:/etc/3proxy:ro '
            f'-v {config_dir}/state:/var/lib/3proxy '
            f'-v {config_dir}/logs:/var/log/3proxy '
            f'{self.IMAGE_NAME}'
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd)
        self._invalidate_docker_cache()
        if code != 0:
            raise RuntimeError(err or 'Failed to start container')
        return True

    def _remove_quietly(self, name, stop=True):
        if stop:
            self.ssh.run_sudo_command(f'docker stop {name} 2>/dev/null || true')
        self.ssh.run_sudo_command(f'docker rm -f {name} 2>/dev/null || true')
        self._invalidate_docker_cache()

    def _apply_listener(self, name, config_dir, port, config_text, log, label):
        """Привести один контейнер к нужному состоянию. Возвращает (restarted, recreated).

        Прежний конфиг сохраняется: если новый не запускается, контейнер
        возвращается на прежний порт, а не остаётся лежать.
        """
        exists = self._container_exists(name)
        previous_text = self._read_config_file(config_dir) if exists else ''
        current_port = self._listener_port(previous_text)
        state = self._container_state(name) if exists else (False, 0)
        baseline_restarts = state[1] if state else 0
        recreated = False
        if not exists or current_port != port:
            if exists:
                self._remove_quietly(name)
                log.append(f'{label}: контейнер {name} пересоздаётся на порту {port}')
            else:
                log.append(f'{label}: создаётся контейнер {name} на порту {port}')
            self.ssh.run_sudo_command(f"mkdir -p {shlex.quote(config_dir)}")
            self._write_config(config_dir, config_text)
            self._run_container(name, config_dir, port)
            recreated = True
        else:
            self._write_config(config_dir, config_text)
            _, err, code = self.ssh.run_sudo_command(f'docker restart {name}')
            self._invalidate_docker_cache()
            if code != 0:
                raise RuntimeError(err or f'Failed to restart container {name}')
            log.append(f'{label}: конфиг обновлён, контейнер {name} перезапущен')
        healthy, restarts = self._wait_container_healthy(name, baseline_restarts)
        if not healthy:
            details = self._container_log_tail(name)
            reason = 'не запустился' if not restarts else 'перезапускается'
            raise RuntimeError(
                f'{label}: контейнер {name} {reason}' + (f': {details}' if details else ''))
        return (not recreated), recreated

    def _listener_snapshot(self, name, config_dir):
        """Состояние листенера до apply — для отката обоих, а не одного."""
        text = self._read_config_file(config_dir)
        return {
            'name': name,
            'dir': config_dir,
            'text': text,
            'port': self._listener_port(text),
            'exists': self._container_exists(name),
        }

    def _restore_listener(self, snap, log):
        """Вернуть листенер к снимку. Ошибки не глотаем: пишем в лог."""
        name = snap['name']
        try:
            if snap['text']:
                self._write_config(snap['dir'], snap['text'])
            if snap['exists'] and snap['port']:
                if self._container_exists(name):
                    self.ssh.run_sudo_command(f'docker restart {name}')
                else:
                    self._run_container(name, snap['dir'], snap['port'])
                log.append(f'{name}: откат к прежнему конфигу на порту {snap["port"]}')
            elif not snap['exists'] and self._container_exists(name):
                self._remove_quietly(name)
                log.append(f'{name}: контейнер удалён при откате')
        except Exception as exc:  # noqa: BLE001
            logger.warning('proxy rollback failed for %s: %s', name, exc)
            log.append(f'{name}: откат не удался: {exc}')

    def apply(self, accounts, socks_port, http_port=None, http_enabled=False,
              options=None, socks_enabled=True):
        """Сгенерировать конфиги и привести контейнеры к нужному состоянию.

        socks_enabled/http_enabled — какие листенеры держать поднятыми.
        Выключенный листенер останавливается и удаляется, его конфиг остаётся
        на диске: включение позже не требует повторной записи.
        """
        if not socks_enabled and not http_enabled:
            raise ValueError('listener_type: нужен хотя бы один листенер')
        log = []
        need_pull = False
        try:
            socks_port = _validate_port(socks_port, 'socks_port')
            if http_enabled:
                http_port = _validate_port(
                    http_port if http_port is not None else self.DEFAULT_HTTP_PORT,
                    'http_port')
                # Совпадение опасно только когда SOCKS-листенер работает:
                # выключенный контейнер порт не занимает.
                if socks_enabled and http_port == socks_port:
                    raise ValueError('http_port: совпадает с SOCKS5-портом')
            elif http_port is not None:
                http_port = _validate_port(http_port, 'http_port')

            socks_text = self.build_config(accounts, socks_port, 'socks', options)
            # HTTP-конфиг генерируется всегда: включение листенера позже не
            # требует повторного сохранения настроек инстанса.
            effective_http_port = http_port if http_enabled else (
                http_port or self.DEFAULT_HTTP_PORT)
            http_text = self.build_config(
                accounts, effective_http_port, 'http', options)
        except ValueError as exc:
            return {'status': 'error', 'message': str(exc), 'log': log}

        need_pull = False
        if socks_enabled and not self._container_exists(self.container_name):
            need_pull = True
        if http_enabled and not self._container_exists(self._http_container_name()):
            need_pull = True
        if need_pull:
            self.ssh.run_sudo_command(f'docker pull {self.IMAGE_NAME}')
        # Снимок обоих листенеров: если SOCKS применился, а HTTP упал,
        # откатываем оба, иначе контейнер и data.json разъедутся по портам.
        snapshots = [
            self._listener_snapshot(self.container_name, self.config_dir),
            self._listener_snapshot(self._http_container_name(), self._http_config_dir()),
        ]
        socks_restarted = socks_recreated = False
        http_restarted = http_recreated = False
        try:
            if socks_enabled:
                socks_restarted, socks_recreated = self._apply_listener(
                    self.container_name, self.config_dir, socks_port,
                    socks_text, log, 'SOCKS5')
            else:
                # Конфиг остаётся на диске: включение листенера позже не
                # потребует повторного сохранения настроек инстанса.
                self.ssh.run_sudo_command(
                    f"mkdir -p {shlex.quote(self.config_dir)}")
                self._write_config(self.config_dir, socks_text)
                if self._container_exists(self.container_name):
                    self._remove_quietly(self.container_name)
                    log.append('SOCKS5: контейнер остановлен и удалён (листенер выключен)')
                else:
                    log.append('SOCKS5: листенер выключен')
            http_dir = self._http_config_dir()
            if http_enabled:
                http_restarted, http_recreated = self._apply_listener(
                    self._http_container_name(), http_dir,
                    http_port, http_text, log, 'HTTP')
            else:
                self.ssh.run_sudo_command(f"mkdir -p {shlex.quote(http_dir)}")
                self._write_config(http_dir, http_text)
                if self._container_exists(self._http_container_name()):
                    self._remove_quietly(self._http_container_name())
                    log.append('HTTP: контейнер остановлен и удалён (листенер выключен)')
                else:
                    log.append('HTTP: листенер выключен')
        except (RuntimeError, ValueError) as exc:
            for snap in reversed(snapshots):
                self._restore_listener(snap, log)
            return {'status': 'error', 'message': str(exc), 'log': log}

        return {
            'status': 'success',
            'socks_port': socks_port,
            'http_port': http_port,
            'socks_enabled': bool(socks_enabled),
            'http_enabled': bool(http_enabled),
            'restarted': bool(socks_restarted or http_restarted),
            'recreated': bool(socks_recreated or http_recreated),
            'log': log,
        }

    # ===================== INSTALL / UPDATE / REMOVE =====================

    def install_protocol(self, protocol_type='socks5', port=None, username=None,
                         password=None, http_port=None, http_enabled=False,
                         accounts=None, socks_enabled=True):
        """Первичная установка. Старый вызов (port/username/password) работает.

        accounts: если передан — применяются эти учётки (переустановка их
        сохраняет); если нет — создаётся одна учётка из username/password.
        """
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}
        if not socks_enabled and not http_enabled:
            return {'status': 'error',
                    'message': 'listener_type: нужен хотя бы один листенер'}

        try:
            port = _validate_port(port if port is not None else self.DEFAULT_PORT)
            if accounts is None:
                username = _validate_credential(
                    str(username or '').strip() or self.DEFAULT_USERNAME, 'username')
                password = _validate_credential(
                    str(password or '').strip() or _generate_password(), 'password')
                install_accounts = [{
                    'login': username,
                    'password': password,
                    'type': ('both' if (socks_enabled and http_enabled)
                             else ('http' if http_enabled else 'socks5')),
                    'enabled': True,
                    'acl_ips': [],
                }]
            else:
                if not isinstance(accounts, (list, tuple)):
                    raise ValueError('accounts: ожидается список')
                install_accounts = list(accounts)
                first = install_accounts[0] if install_accounts else {}
                if not isinstance(first, dict):
                    raise ValueError('accounts: каждая учётка должна быть словарём')
                username = (str(first.get('login') or first.get('username') or '')
                            .strip() or None)
                password = str(first.get('password') or '').strip() or None
        except ValueError as exc:
            return {'status': 'error', 'message': str(exc)}

        install_protocol = protocol_type or self.protocol
        target = (self if install_protocol == self.protocol
                  else type(self)(self.ssh, install_protocol))

        result = target.apply(
            install_accounts, port,
            http_port=http_port, http_enabled=http_enabled,
            socks_enabled=socks_enabled)
        if result.get('status') != 'success':
            return result

        return {
            'status': 'success',
            'protocol': install_protocol,
            'base_protocol': self.PROTOCOL,
            'instance': target.instance,
            'container_name': target.container_name,
            'port': port,
            'http_port': result.get('http_port'),
            'socks_enabled': bool(socks_enabled),
            'http_enabled': bool(http_enabled),
            'username': username,
            'password': password,
            'message': 'SOCKS5 proxy installed',
            'log': [
                *([f'SOCKS5 proxy listening on port {port}/TCP']
                  if socks_enabled else []),
                *([f'HTTP proxy listening on port {result.get("http_port")}/TCP']
                  if http_enabled else []),
                *([f'Username: {username}'] if username else []),
                *([f'Password: {password}'] if password else []),
                *(['Save these credentials — the password can also be viewed later via "Change settings".']
                  if password else []),
                *(result.get('log') or []),
            ],
        }

    def update_credentials(self, port=None, username=None, password=None):
        """Изменить первую учётку, сохранив остальные. Порт → пересоздание."""
        if not (self.check_protocol_installed(self.protocol)
                or self._container_exists(self._http_container_name())):
            return {'status': 'error', 'message': 'SOCKS5 not installed'}

        try:
            socks_text = self._read_config_file(self.config_dir)
            http_dir = self._http_config_dir()
            http_text = self._read_config_file(http_dir)
            accounts = self._parse_config_accounts(socks_text)
            http_accounts = self._parse_config_accounts(http_text)
            if not accounts and http_accounts:
                accounts = http_accounts
                http_accounts = []
            if not accounts:
                return {'status': 'error', 'message': 'SOCKS5 config not found'}

            # Учётки, которые есть только в HTTP-конфиге, сохраняем при
            # перезаписи обоих конфигов; пересечение помечаем типом both.
            socks_logins = {a.get('login') for a in accounts}
            for account in accounts:
                if any(h.get('login') == account.get('login')
                       for h in http_accounts):
                    account['type'] = 'both'
            for account in http_accounts:
                if account.get('login') not in socks_logins:
                    account['type'] = 'http'
                    accounts.append(account)

            first = accounts[0]
            current_socks_port = self._listener_port(socks_text) or self.DEFAULT_PORT
            current_http_port = self._listener_port(http_text)
            socks_exists = self._container_exists(self.container_name)
            http_exists = self._container_exists(self._http_container_name())

            new_port = _validate_port(
                port if port is not None else current_socks_port, 'port')
            new_user = _validate_credential(
                username or first.get('login') or self.DEFAULT_USERNAME, 'username')
            new_pass = _validate_credential(
                password or first.get('password') or _generate_password(), 'password')
            old_login = first.get('login')
            first['login'] = new_user
            first['password'] = new_pass
            if first.get('name') in (None, '', old_login):
                first['name'] = new_user
        except ValueError as exc:
            return {'status': 'error', 'message': str(exc)}

        result = self.apply(
            accounts, new_port,
            http_port=current_http_port or self.DEFAULT_HTTP_PORT,
            http_enabled=http_exists,
            # Выключенный листенер не должен воскресать: у HTTP-only инстанса
            # SOCKS-контейнера нет, и update_credentials его не создаёт.
            socks_enabled=socks_exists)
        if result.get('status') != 'success':
            return result

        return {
            'status': 'success',
            'port': new_port,
            'username': new_user,
            'password': new_pass,
            'restarted': bool(result.get('restarted')),
            'recreated': bool(result.get('recreated')),
            'log': result.get('log') or [],
        }

    def remove_container(self, protocol_type='socks5'):
        """Удалить оба контейнера и оба каталога конфигов."""
        socks_name = self._container_name(protocol_type)
        http_name = self._http_container_name(protocol_type)
        socks_dir = self._config_dir(protocol_type)
        http_dir = self._http_config_dir(protocol_type)
        for name in (socks_name, http_name):
            self.ssh.run_sudo_command(f'docker stop {name} 2>/dev/null || true')
            self.ssh.run_sudo_command(f'docker rm -f {name} 2>/dev/null || true')
        self._invalidate_docker_cache()
        for directory in (socks_dir, http_dir):
            self.ssh.run_sudo_command(f'rm -rf {shlex.quote(directory)}')
        return True


# __APPEND__
