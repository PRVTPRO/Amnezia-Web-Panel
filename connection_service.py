import asyncio
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime

MAX_CONNECTION_NAME_LENGTH = 64
DISALLOWED_CONNECTION_NAME_CHARS = set('<>"\'&')

logger = logging.getLogger(__name__)

SELF_SERVICE_PROTOCOL_ORDER = (
    'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'wireguard',
)

SELF_SERVICE_PROTOCOLS = frozenset(SELF_SERVICE_PROTOCOL_ORDER)

_PROTOCOL_DISPLAY_NAMES = {
    'awg': 'AmneziaWG',
    'awg2': 'AmneziaWG 2.0',
    'awg3': 'AmneziaWG 3.1',
    'awg_legacy': 'AmneziaWG Legacy',
    'xray': 'Xray',
    'telemt': 'Telemt',
    'wireguard': 'WireGuard',
}


def protocol_base(protocol: str) -> str:
    return str(protocol or 'awg').split('__', 1)[0]


def protocol_instance(protocol: str) -> int:
    parts = str(protocol or '').split('__', 1)
    if len(parts) == 2:
        try:
            return max(1, int(parts[1]))
        except ValueError:
            return 1
    return 1


def sanitize_allowed_protocols(allowed) -> list:
    seen = set()
    result = []
    for proto in allowed or []:
        base = protocol_base(proto)
        if base in SELF_SERVICE_PROTOCOLS and base not in seen:
            seen.add(base)
            result.append(base)
    return result


def self_service_protocol_display_name(protocol: str) -> str:
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    name = _PROTOCOL_DISPLAY_NAMES.get(base, base)
    return name if idx <= 1 else f'{name} #{idx}'


def self_service_protocol_choices():
    return [
        {'id': proto, 'name': self_service_protocol_display_name(proto)}
        for proto in SELF_SERVICE_PROTOCOL_ORDER
    ]


def server_self_service_protocols(server, allowed_bases) -> list:
    allowed = set(sanitize_allowed_protocols(allowed_bases))
    if not allowed:
        return []
    return [
        proto
        for proto in (server.get('protocols') or {}).keys()
        if protocol_base(proto) in allowed
    ]


DEFAULT_SELF_SERVICE_SETTINGS = {
    'enabled': False,
    'web_enabled': True,
    'telegram_enabled': True,
    'max_connections_per_user': 5,
    'rate_limit_count': 3,
    'rate_limit_window_seconds': 60,
    'allowed_protocols': ['awg', 'awg2'],
}


class SelfServiceError(Exception):
    def __init__(self, message, status_code=400, forbidden=False):
        super().__init__(message)
        self.status_code = status_code
        self.forbidden = forbidden


class RateLimitError(SelfServiceError):
    def __init__(self, message='Rate limit exceeded'):
        super().__init__(message, status_code=429)


class ConnectionService:
    def __init__(
        self,
        *,
        load_data,
        save_data,
        data_lock,
        get_ssh,
        get_protocol_manager,
        manager_call,
        generate_vpn_link,
    ):
        self.load_data = load_data
        self.save_data = save_data
        self.data_lock = data_lock
        self.get_ssh = get_ssh
        self.get_protocol_manager = get_protocol_manager
        self.manager_call = manager_call
        self.generate_vpn_link = generate_vpn_link
        self._provision_locks = defaultdict(asyncio.Lock)
        self._rate_events = defaultdict(list)

    async def get_self_service_options(self, user_id, source):
        data = self.load_data()
        settings = self._settings(data)
        user = self._get_eligible_user(data, user_id)
        self._validate_channel(settings, source)
        user_connections = self._user_connections(data, user['id'])
        max_connections = int(settings.get('max_connections_per_user', 5))
        remaining = max(0, max_connections - len(user_connections))
        allowed_bases = sanitize_allowed_protocols(settings.get('allowed_protocols'))
        servers = []
        for server_id, server in enumerate(data.get('servers', [])):
            if not server.get('self_service_enabled', False):
                continue
            protocols = [
                {'protocol': protocol, 'name': self_service_protocol_display_name(protocol)}
                for protocol in server_self_service_protocols(server, allowed_bases)
            ]
            if protocols:
                servers.append({
                    'id': server_id,
                    'name': server.get('name') or server.get('host') or f'Server {server_id}',
                    'protocols': protocols,
                })
        return {
            'enabled': True,
            'max_connections_per_user': max_connections,
            'remaining_connections': remaining,
            'servers': servers,
        }

    async def create_user_connection(self, user_id, server_id, protocol, name, source):
        clean_name = self._validate_name(name)
        self._validate_protocol(protocol)
        lock = self._provision_locks[(server_id, protocol)]
        async with lock:
            async with self.data_lock:
                data = self.load_data()
                settings = self._settings(data)
                self._check_rate_limit(user_id, source, settings)
                self._record_rate_event(user_id, source)
                self._validate_create_request(data, settings, user_id, server_id, protocol, clean_name, source)
                server = dict(data['servers'][server_id])
                port = server.get('protocols', {}).get(protocol, {}).get('port', '55424')

            ssh = self.get_ssh(server)
            remote_client_id = None
            manager = None
            try:
                await asyncio.to_thread(ssh.connect)
                manager = self.get_protocol_manager(ssh, protocol)
                result = await asyncio.to_thread(
                    self.manager_call,
                    manager,
                    'add_client',
                    protocol,
                    clean_name,
                    server.get('host', ''),
                    port,
                )
                remote_client_id = result.get('client_id')
                if not remote_client_id:
                    raise RuntimeError('Remote client creation did not return client_id')

                try:
                    async with self.data_lock:
                        data = self.load_data()
                        settings = self._settings(data)
                        user = self._validate_create_request(data, settings, user_id, server_id, protocol, clean_name, source)
                        conn = {
                            'id': str(uuid.uuid4()),
                            'user_id': user['id'],
                            'server_id': server_id,
                            'protocol': protocol,
                            'client_id': remote_client_id,
                            'name': clean_name,
                            'created_at': datetime.now().isoformat(),
                            'created_by': 'self_service',
                            'created_source': source,
                        }
                        data.setdefault('user_connections', []).append(conn)
                        self.save_data(data)
                except Exception:
                    await self._rollback_client(manager, protocol, remote_client_id)
                    remote_client_id = None
                    raise

                response = {'status': 'success', 'connection': conn}
                if result.get('config'):
                    response['config'] = result['config']
                    response['vpn_link'] = self.generate_vpn_link(result['config'])
                return response
            except Exception:
                if remote_client_id:
                    await self._rollback_client(manager, protocol, remote_client_id)
                raise
            finally:
                try:
                    await asyncio.to_thread(ssh.disconnect)
                except Exception:
                    pass

    async def delete_user_connection(self, user_id, connection_id, source):
        data = self.load_data()
        settings = self._settings(data)
        self._check_rate_limit(user_id, source, settings)
        self._record_rate_event(user_id, source)
        self._validate_channel(settings, source)
        self._get_eligible_user(data, user_id)
        conn = self._get_connection(data, user_id, connection_id)
        server_id = conn.get('server_id')
        protocol = conn.get('protocol')
        lock = self._provision_locks[(server_id, protocol)]
        async with lock:
            async with self.data_lock:
                data = self.load_data()
                settings = self._settings(data)
                self._validate_channel(settings, source)
                self._get_eligible_user(data, user_id)
                conn = self._get_connection(data, user_id, connection_id)
                if conn.get('created_by') != 'self_service':
                    raise SelfServiceError('Only self-service connections can be deleted', status_code=403, forbidden=True)
                if server_id is None or server_id >= len(data.get('servers', [])):
                    raise SelfServiceError('Server not found', status_code=404)
                server = dict(data['servers'][server_id])

            ssh = self.get_ssh(server)
            try:
                await asyncio.to_thread(ssh.connect)
                manager = self.get_protocol_manager(ssh, protocol)
                await asyncio.to_thread(self.manager_call, manager, 'remove_client', protocol, conn.get('client_id'))
            finally:
                try:
                    await asyncio.to_thread(ssh.disconnect)
                except Exception:
                    pass

            async with self.data_lock:
                data = self.load_data()
                self._validate_channel(self._settings(data), source)
                conn = self._get_connection(data, user_id, connection_id)
                if conn.get('created_by') != 'self_service':
                    raise SelfServiceError('Only self-service connections can be deleted', status_code=403, forbidden=True)
                data['user_connections'] = [c for c in data.get('user_connections', []) if c.get('id') != connection_id]
                self.save_data(data)
            return {'status': 'success'}

    def _settings(self, data):
        settings = dict(DEFAULT_SELF_SERVICE_SETTINGS)
        settings.update(data.get('settings', {}).get('self_service') or {})
        return settings

    def _validate_channel(self, settings, source):
        if not settings.get('enabled', False):
            raise SelfServiceError('Self-service is disabled', status_code=403, forbidden=True)
        if source == 'web' and not settings.get('web_enabled', True):
            raise SelfServiceError('Web self-service is disabled', status_code=403, forbidden=True)
        if source == 'telegram' and not settings.get('telegram_enabled', True):
            raise SelfServiceError('Telegram self-service is disabled', status_code=403, forbidden=True)

    def _get_eligible_user(self, data, user_id):
        user = next((u for u in data.get('users', []) if u.get('id') == user_id), None)
        if not user:
            raise SelfServiceError('User not found', status_code=404)
        if not user.get('enabled', True):
            raise SelfServiceError('User is disabled', status_code=403, forbidden=True)
        expiration = user.get('expiration_date')
        if expiration:
            try:
                expires_at = datetime.fromisoformat(str(expiration).replace('Z', '+00:00'))
                now = datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now()
                if expires_at < now:
                    raise SelfServiceError('User is expired', status_code=403, forbidden=True)
            except SelfServiceError:
                raise
            except Exception as e:
                logger.warning("Failed to parse expiration_date '%s': %s", expiration, e)
                raise SelfServiceError('User expiration date is invalid', status_code=403, forbidden=True)
        limit = int(user.get('traffic_limit') or 0)
        used = int(user.get('traffic_used') or 0)
        if limit > 0 and used >= limit:
            raise SelfServiceError('User quota is exhausted', status_code=403, forbidden=True)
        return user

    def _validate_create_request(self, data, settings, user_id, server_id, protocol, name, source):
        self._validate_channel(settings, source)
        user = self._get_eligible_user(data, user_id)
        user_connections = self._user_connections(data, user_id)
        max_connections = int(settings.get('max_connections_per_user', 5))
        if len(user_connections) >= max_connections:
            raise SelfServiceError('Maximum self-service connections reached', status_code=403, forbidden=True)
        if any(c.get('name') == name for c in user_connections):
            raise SelfServiceError('Connection name must be unique for this user')
        if server_id is None or server_id < 0 or server_id >= len(data.get('servers', [])):
            raise SelfServiceError('Server not found', status_code=404)
        server = data['servers'][server_id]
        if not server.get('self_service_enabled', False):
            raise SelfServiceError('Server self-service is disabled', status_code=403, forbidden=True)
        allowed_bases = set(sanitize_allowed_protocols(settings.get('allowed_protocols')))
        if protocol_base(protocol) not in allowed_bases:
            raise SelfServiceError('Protocol is not allowed')
        if protocol not in server.get('protocols', {}):
            raise SelfServiceError('Protocol is not installed on this server')
        return user

    def _validate_name(self, name):
        clean = str(name or '').strip()
        if (
            not clean
            or len(clean) > MAX_CONNECTION_NAME_LENGTH
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in clean)
            or any(ch in DISALLOWED_CONNECTION_NAME_CHARS for ch in clean)
        ):
            raise SelfServiceError('Connection name must be 1-64 characters without control or HTML-sensitive characters')
        return clean

    def _validate_protocol(self, protocol):
        if protocol_base(protocol) not in SELF_SERVICE_PROTOCOLS:
            raise SelfServiceError('Protocol is not supported for self-service')

    def _user_connections(self, data, user_id):
        return [c for c in data.get('user_connections', []) if c.get('user_id') == user_id]

    def _get_connection(self, data, user_id, connection_id):
        conn = next(
            (c for c in data.get('user_connections', []) if c.get('id') == connection_id and c.get('user_id') == user_id),
            None,
        )
        if not conn:
            raise SelfServiceError('Connection not found', status_code=404)
        return conn

    def _check_rate_limit(self, user_id, source, settings):
        count = int(settings.get('rate_limit_count', 3))
        window = int(settings.get('rate_limit_window_seconds', 60))
        if count <= 0 or window <= 0:
            raise RateLimitError()
        key = user_id
        now = time.monotonic()
        self._rate_events[key] = [ts for ts in self._rate_events[key] if now - ts < window]
        if len(self._rate_events[key]) >= count:
            raise RateLimitError()

    def _record_rate_event(self, user_id, source):
        self._rate_events[user_id].append(time.monotonic())

    async def _rollback_client(self, manager, protocol, client_id):
        try:
            await asyncio.to_thread(self.manager_call, manager, 'remove_client', protocol, client_id)
        except Exception as e:
            logger.warning("Rollback failed for client %s: %s", client_id, e)

