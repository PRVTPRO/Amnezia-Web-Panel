"""Плагин «Защита от торрентов» — элемент магазина, ставится на каждый сервер.

Зачем отдельный модуль: пока плагин не установлен на сервере, в ядре панели
не должно быть НИЧЕГО от этой функции — ни разметки, ни JS, ни роутов
фильтра, ни фонового SSH-сбора. Иначе «лёгкая панель» для того, кто не
пользуется торрентами, остаётся тяжёлой.

Что здесь живёт:
  * стор установки/настроек рядом с data.json (atomic, RLock, ключ = uid|host);
  * состояние и здоровье фильтра (health — память процесса, как и раньше);
  * операции install/uninstall/enabled/mode/refresh;
  * журнал меток (общий формат с managers/torrent_events.py) и его TTL;
  * статус для бейджа, панели и плиток дашборда.

Движок правил — managers/torrent_guard.py. Модуль ничего не импортирует из
app.py: SSH и фабрику guard'а передаёт вызывающая сторона, поэтому цикла
импортов нет.
"""

import json
import logging
import os
import re
import tempfile
import threading
import time

from managers import torrent_events
from managers.torrent_guard import (
    DEFAULT_MODE,
    MODES,
    normalize_mode,
)

logger = logging.getLogger(__name__)

PLUGIN_ID = 'torrent_guard'
STATE_VERSION = 1

# Протоколы, где трафик на интерфейсе уже расшифрован: сигнатуры видны.
CAPABLE_PROTOCOLS = ('awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard')
AWG_FAMILY = ('awg', 'awg2', 'awg3')

POLL_STEPS = (0, 5, 15, 30, 60, 300)
MARKS_TTL_MIN = 7
MARKS_TTL_MAX = 90

DEFAULT_SETTINGS = {
    'default_mode': DEFAULT_MODE,
    'include_wireguard': True,
    'marks_ttl_days': 30,
    'clear_marks_on_disable': False,
    'poll_seconds': 60,
}


class PluginError(Exception):
    """Ошибка операции плагина с кодом для HTTP-ответа."""

    def __init__(self, code, message, status=400, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = list(details or [])

    def as_dict(self):
        payload = {'error': self.message, 'code': self.code}
        if self.details:
            payload['details'] = self.details
        return payload


def plugin_key(server):
    """Ключ стора и журнала: uid, иначе host (как в torrent_events)."""
    return torrent_events.server_key(server)


def validate_settings(patch):
    """Проверяет частичный набор настроек и возвращает нормализованный dict."""
    if not isinstance(patch, dict):
        raise PluginError('invalid_setting', 'Settings must be an object', 400)
    unknown = sorted(set(patch) - set(DEFAULT_SETTINGS))
    if unknown:
        raise PluginError('invalid_setting',
                          'Unknown setting: %s' % ', '.join(unknown), 400)
    out = {}
    for key, value in patch.items():
        if key == 'default_mode':
            mode = str(value or '').strip().lower()
            if mode not in MODES:
                raise PluginError('invalid_setting',
                                  'default_mode must be one of %s'
                                  % ', '.join(MODES), 400)
            out[key] = mode
        elif key in ('include_wireguard', 'clear_marks_on_disable'):
            if not isinstance(value, bool):
                raise PluginError('invalid_setting',
                                  '%s must be true or false' % key, 400)
            out[key] = value
        elif key == 'marks_ttl_days':
            try:
                days = int(value)
            except (TypeError, ValueError):
                raise PluginError('invalid_setting',
                                  'marks_ttl_days must be a number', 400)
            if days < MARKS_TTL_MIN or days > MARKS_TTL_MAX:
                raise PluginError(
                    'invalid_setting',
                    'marks_ttl_days must be %d..%d' % (MARKS_TTL_MIN,
                                                       MARKS_TTL_MAX), 400)
            out[key] = days
        elif key == 'poll_seconds':
            try:
                seconds = int(value)
            except (TypeError, ValueError):
                raise PluginError('invalid_setting',
                                  'poll_seconds must be a number', 400)
            if seconds not in POLL_STEPS:
                raise PluginError(
                    'invalid_setting',
                    'poll_seconds must be one of %s'
                    % '/'.join(str(s) for s in POLL_STEPS), 400)
            out[key] = seconds
    return out


def merge_settings(base, patch):
    merged = dict(DEFAULT_SETTINGS)
    if isinstance(base, dict):
        for key in DEFAULT_SETTINGS:
            if key in base:
                merged[key] = base[key]
    merged.update(validate_settings(patch or {}))
    # Значения из стора могли быть испорчены руками: нормализуем при чтении.
    try:
        merged = dict(merged, **validate_settings(
            {k: merged[k] for k in DEFAULT_SETTINGS if k in merged}))
    except PluginError:
        merged = dict(DEFAULT_SETTINGS)
    return merged


class TorrentPlugin:
    """Стор и операции плагина. Экземпляр создаётся в app.py один раз."""

    def __init__(self, data_file):
        # data_file — callable: тесты подменяют DATA_FILE, путь должен
        # вычисляться в момент обращения, а не на импорте модуля.
        self._data_file = data_file
        self._lock = threading.RLock()
        self._journal_cache = {'stamp': None, 'data': None}
        self._health = {}
        self._health_lock = threading.Lock()
        self._installed_cache = {'stamp': None, 'servers': {}}

    # ---------- пути и стор ----------

    @property
    def state_file(self):
        return os.path.abspath(os.path.expanduser(self._data_file())) + \
            '.plugins_state.json'

    @property
    def events_file(self):
        return os.path.join(os.path.dirname(
            os.path.abspath(os.path.expanduser(self._data_file()))),
            'torrent_events.json')

    def _empty(self):
        return {'version': STATE_VERSION, 'servers': {}}

    def load(self):
        with self._lock:
            try:
                with open(self.state_file, 'r', encoding='utf-8') as handle:
                    raw = json.load(handle)
            except (OSError, ValueError):
                return self._empty()
            if not isinstance(raw, dict) or raw.get('version') != STATE_VERSION:
                return self._empty()
            servers = raw.get('servers')
            if not isinstance(servers, dict):
                return self._empty()
            clean = {'version': STATE_VERSION, 'servers': {}}
            for key, entry in servers.items():
                if not isinstance(entry, dict):
                    continue
                record = entry.get(PLUGIN_ID)
                if isinstance(record, dict) and record.get('installed'):
                    clean['servers'][str(key)] = {PLUGIN_ID: dict(record)}
            return clean

    def save(self, state):
        path = self.state_file
        directory = os.path.dirname(path)
        with self._lock:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=os.path.basename(path) + '.', suffix='.tmp',
                dir=directory)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    json.dump(state, handle, ensure_ascii=False, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def record(self, server):
        key = plugin_key(server)
        if not key:
            return None
        record = (self.load().get('servers', {}).get(key) or {}).get(PLUGIN_ID)
        return record if isinstance(record, dict) else None

    def _save_record(self, key, record):
        """Чтение и запись стора под одним захватом: иначе две операции по
        разным серверам теряют запись друг друга."""
        with self._lock:
            state = self.load()
            if record is None:
                state.get('servers', {}).pop(key, None)
            else:
                state.setdefault('servers', {}).setdefault(key, {})[PLUGIN_ID] = record
            state['updated_at'] = int(time.time())
            self.save(state)
            self._installed_cache['stamp'] = None

    def write_record(self, server, record):
        """Публичная запись настроек из роута (стор + сброс кэша)."""
        key = plugin_key(server)
        if not key:
            raise PluginError('server_has_no_identity',
                              'Server has no uid/host', 400)
        if not record or not record.get('installed'):
            raise PluginError('plugin_not_installed',
                              'Torrent guard plugin is not installed', 409)
        self._save_record(key, record)

    def merge_settings(self, base, patch):
        return merge_settings(base, patch or {})

    def installed(self, server):
        """Быстрая проверка для рендера страниц (кэш по mtime файла)."""
        key = plugin_key(server)
        if not key:
            return False
        try:
            stat = os.stat(self.state_file)
            stamp = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            self._installed_cache = {'stamp': None, 'servers': {}}
            return False
        if self._installed_cache['stamp'] != stamp:
            servers = {k: True for k in self.load().get('servers', {})}
            self._installed_cache = {'stamp': stamp, 'servers': servers}
        return bool(self._installed_cache['servers'].get(key))

    def installed_any(self, servers):
        return any(self.installed(server) for server in (servers or []))

    # ---------- настройки и инстансы ----------

    def settings(self, server):
        record = self.record(server) or {}
        return merge_settings(record.get('settings') or {}, {})

    def capable(self, server, include_wireguard=None):
        """Инстансы сервера, где фильтр вообще может работать.

        Имя инстанса: ``awg3__2`` — база до ``__``. Сравниваем с точным
        списком протоколов, где трафик на интерфейсе расшифрован.
        """
        if include_wireguard is None:
            include_wireguard = self.settings(server)['include_wireguard']
        protocols = server.get('protocols') or {}
        out = []
        for proto, entry in protocols.items():
            if not isinstance(entry, dict) or entry.get('installed') is False:
                continue
            base = str(proto).split('__', 1)[0]
            if base not in CAPABLE_PROTOCOLS:
                continue
            if base == 'wireguard' and not include_wireguard:
                continue
            out.append(proto)
        return out

    def mode_of(self, server, proto):
        entry = (server.get('protocols') or {}).get(proto) or {}
        if not isinstance(entry, dict):
            return DEFAULT_MODE
        return normalize_mode(entry.get('torrent_guard') or DEFAULT_MODE)

    def modes(self, server):
        return {proto: self.mode_of(server, proto)
                for proto in self.capable(server)}

    # ---------- здоровье ----------

    def set_health(self, server, proto, result):
        key = plugin_key(server)
        if not key:
            return
        error = str((result or {}).get('error') or '')
        # Сколько пиров реально накрыто правилами: ответ apply/collect несёт
        # это число, и админу важно видеть его рядом с «правила на месте».
        # apply/read отдают список IP, collect — уже готовое число.
        peers = (result or {}).get('peers')
        if isinstance(peers, (list, tuple)):
            peers = len(peers)
        entry = {'ok': not error, 'error': error, 'ts': int(time.time())}
        if isinstance(peers, int) and not isinstance(peers, bool):
            entry['peers'] = peers
        with self._health_lock:
            bucket = self._health.setdefault(key, {})
            bucket[proto] = entry

    def clear_health(self, server):
        key = plugin_key(server)
        with self._health_lock:
            self._health.pop(key, None)

    def health_for(self, server):
        key = plugin_key(server)
        with self._health_lock:
            bucket = dict(self._health.get(key) or {})
        if not bucket:
            return {'state': 'unknown', 'ok': None, 'error': '',
                    'checked_at': None, 'protocols': {}}
        errors = [item['error'] for item in bucket.values() if item.get('error')]
        latest = max(int(item.get('ts') or 0) for item in bucket.values())
        return {'state': 'degraded' if errors else 'ok',
                'ok': not errors,
                'error': errors[0] if errors else '',
                'checked_at': latest or None,
                'protocols': bucket}

    # ---------- журнал меток ----------

    def journal(self):
        with self._lock:
            try:
                stat = os.stat(self.events_file)
                stamp = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                stamp = None
            if stamp is not None and self._journal_cache['stamp'] == stamp:
                return self._journal_cache['data']
            data = torrent_events.load(self.events_file)
            self._journal_cache = {'stamp': stamp, 'data': data}
            return data

    def summary(self, server):
        key = plugin_key(server)
        if not key:
            return {}
        return torrent_events.summary(self.journal(), key)

    def peer_buckets(self, server, proto):
        key = plugin_key(server)
        if not key:
            return {}
        return torrent_events.peer_buckets(self.journal(), key, proto)

    def clear_marks(self, server, proto='', client_id='', ip=''):
        key = plugin_key(server)
        if not key:
            raise PluginError('server_has_no_identity',
                              'Server has no uid/host', 400)
        with self._lock:
            journal = torrent_events.load(self.events_file)
            removed = torrent_events.clear(
                journal, key, proto, ip=ip, client_id=client_id)
            if removed:
                torrent_events.save(self.events_file, journal)
                self._journal_cache = {'stamp': None, 'data': None}
        return removed

    def clear_server_journal(self, server):
        key = plugin_key(server)
        if not key:
            return 0
        with self._lock:
            journal = torrent_events.load(self.events_file)
            entry = (journal.get('servers') or {}).pop(key, None)
            if not entry:
                return 0
            torrent_events.save(self.events_file, journal)
            self._journal_cache = {'stamp': None, 'data': None}
            return 1

    def record_events(self, server, proto, events, list_clients=None):
        """Пишет события коллектора в журнал (адрес -> client_id, если можно)."""
        key = plugin_key(server)
        events = list(events or ())
        if not key or not events:
            return 0
        ip_map = {}
        if list_clients is not None:
            try:
                for client in list_clients() or []:
                    user_data = client.get('userData') or {}
                    ip = user_data.get('clientIp') or ''
                    if not ip:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)',
                                          user_data.get('allowedIps') or '')
                        ip = match.group(1) if match else ''
                    if ip:
                        ip_map[ip] = client.get('clientId') or ''
            except Exception as exc:                    # noqa: BLE001
                logger.warning('torrent journal: client map failed: %s', exc)
        added = 0
        with self._lock:
            journal = torrent_events.load(self.events_file)
            torrent_events.prune(journal)
            for event in events:
                ip = event.get('ip')
                added += torrent_events.record(
                    journal, key, proto, ip, [event],
                    client_id=ip_map.get(ip, ''))
            if added:
                try:
                    torrent_events.save(self.events_file, journal)
                    self._journal_cache = {'stamp': None, 'data': None}
                except OSError as exc:
                    logger.warning('torrent journal save failed: %s', exc)
        return added

    def ttl_map(self, servers):
        """key -> секунды TTL по настройкам установленных серверов."""
        mapping = {}
        for server in servers or []:
            key = plugin_key(server)
            if not key or not self.installed(server):
                continue
            days = self.settings(server)['marks_ttl_days']
            mapping[key] = int(days) * 86400
        return mapping

    def prune(self, servers):
        """Снимает просроченные метки.

        Ветки серверов здесь НЕ удаляются: недоступный/потерянный стор не
        означает «плагина нет», и чистить чужой журнал из-за этого нельзя.
        Свою ветку удаляет uninstall — это единственный явный сигнал.
        """
        mapping = self.ttl_map(servers)
        with self._lock:
            journal = torrent_events.load(self.events_file)
            removed = torrent_events.prune(journal, ttl_by_key=mapping.get)
            if removed:
                try:
                    torrent_events.save(self.events_file, journal)
                    self._journal_cache = {'stamp': None, 'data': None}
                except OSError as exc:
                    logger.warning('torrent journal prune save failed: %s', exc)
            return removed

    def flags(self, servers):
        """Метки для плиток дашборда: только установленные серверы."""
        journal = self.journal()
        out = {}
        for idx, server in enumerate(servers or []):
            if not self.installed(server):
                continue
            key = plugin_key(server)
            if not key:
                continue
            summary = torrent_events.summary(journal, key)
            if summary:
                out[str(idx)] = summary
        return out

    # ---------- статус ----------

    def status(self, server):
        record = self.record(server) or {}
        installed = bool(record.get('installed'))
        settings = merge_settings(record.get('settings') or {}, {})
        protocols = self.capable(server, settings['include_wireguard']) \
            if installed else []
        modes = {proto: self.mode_of(server, proto) for proto in protocols}
        health = self.health_for(server) if installed else {
            'state': 'unknown', 'ok': None, 'error': '',
            'checked_at': None, 'protocols': {}}
        marks = self.summary(server) if installed else {}
        total = sum(int(item.get('events') or 0) for item in marks.values())
        last_at = max([int(item.get('last_ts') or 0) for item in marks.values()]
                      or [0]) or None
        enabled = bool(record.get('enabled')) if installed else False
        if not installed:
            state = 'not_installed'
        elif not protocols:
            state = 'unsupported'
        elif not enabled:
            state = 'off'
        elif health['state'] == 'degraded':
            state = 'degraded'
        elif any(mode == 'on' for mode in modes.values()):
            state = 'on'
        elif any(mode == 'count' for mode in modes.values()):
            state = 'count'
        elif health['state'] == 'unknown':
            # Правил нет ни в одном режиме и проверки ещё не было: «не
            # проверялось» честнее, чем «выключено».
            state = 'unknown'
        else:
            state = 'off'
        return {
            'id': PLUGIN_ID,
            'installed': installed,
            'enabled': enabled,
            'supported': bool(protocols),
            'protocols': list(protocols),
            'modes': modes,
            'health': health,
            'settings': settings,
            'events': total,
            'last_at': last_at,
            'state': state,
            'installed_at': record.get('installed_at'),
        }

    # ---------- операции ----------

    def _guard(self, guard_for, proto):
        guard = guard_for(proto)
        if guard is None:
            raise PluginError('unsupported_protocol',
                              'Protocol %s does not support torrent guard'
                              % proto, 400)
        return guard

    def _apply(self, server, wanted, guard_for):
        """Применяет режимы и пишет health по факту попытки.

        Health пишется здесь, а не только коллектором: иначе после установки
        при неудачном apply бейдж показывал бы «включено» без правил.
        """
        applied, errors = {}, []
        for proto, mode in wanted.items():
            try:
                report = self._guard(guard_for, proto).apply(mode) or {}
                error = str(report.get('error') or '')
            except PluginError:
                raise
            except Exception as exc:                    # noqa: BLE001
                error = str(exc) or exc.__class__.__name__
                report = {'error': error}
            if mode == 'off' and error and (
                    'is not running' in error.lower()
                    or 'no such container' in error.lower()):
                # В остановленном контейнере правил нет: снимать нечего.
                # Иначе удаление плагина навсегда упиралось бы в 502.
                error = ''
            self.set_health(server, proto, report)
            if error:
                errors.append('%s: %s' % (proto, error))
            else:
                applied[proto] = mode
        return applied, errors

    def install(self, server, guard_for, settings=None, reapply=False):
        key = plugin_key(server)
        if not key:
            raise PluginError('server_has_no_identity',
                              'Server has no uid/host', 400)
        record = self.record(server)
        if record and record.get('installed') and not reapply:
            result = self.status(server)
            result['changes'] = {}
            result['errors'] = []
            return result
        merged = merge_settings((record or {}).get('settings') or {},
                                settings or {})
        protocols = self.capable(server, merged['include_wireguard'])
        # После установки контроль ВЫКЛЮЧЕН: правил на хосте нет. Включает его
        # админ в панели плагина («Включить контроль»). Переустановка правил
        # сохраняет текущее состояние: выключено — снимаем, включено —
        # возвращаем настроенные режимы.
        enabled_now = bool(record and record.get('enabled')) if reapply else False
        wanted = {}
        for proto in protocols:
            if not enabled_now:
                wanted[proto] = 'off'
                continue
            entry = server.get('protocols', {}).get(proto) or {}
            stored = entry.get('torrent_guard') if isinstance(entry, dict) \
                else None
            wanted[proto] = normalize_mode(stored) if stored \
                else merged['default_mode']
        record = {
            'installed': True,
            'installed_at': (record or {}).get('installed_at') or int(time.time()),
            'enabled': enabled_now,
            'suspended_modes': {},
            'settings': merged,
            'pending': True,
        }
        # Запись «установлен» — ДО применения. Обрыв между apply и записью
        # оставил бы цепочки TGIN* на хосте без единого способа ими управлять
        # из UI. С pending-флагом запись уже есть, а статус досчитается после.
        self._save_record(key, record)
        applied, errors = self._apply(server, wanted, guard_for)
        for proto, mode in applied.items():
            server['protocols'][proto]['torrent_guard'] = mode
        record['pending'] = False
        self._save_record(key, record)
        result = self.status(server)
        result['errors'] = errors
        result['changes'] = dict(applied)
        return result

    def uninstall(self, server, guard_for, force=False):
        record = self.record(server)
        if not record or not record.get('installed'):
            result = self.status(server)
            result['changes'] = {}
            result['errors'] = []
            return result
        # Снимаем правила со ВСЕХ подходящих инстансов, включая WireGuard:
        # настройка include_wireguard могла быть выключена уже после того, как
        # на нём стояли правила, и «удалённый» плагин оставил бы DROP.
        protocols = self.capable(server, True)
        applied, errors = self._apply(
            server, {proto: 'off' for proto in protocols}, guard_for)
        if errors and not force:
            raise PluginError('apply_failed',
                              'Torrent guard rules were not removed',
                              502, errors)
        for proto in list((server.get('protocols') or {})):
            entry = (server.get('protocols') or {}).get(proto)
            if isinstance(entry, dict):
                entry.pop('torrent_guard', None)
        server.pop('torrent_guard_enabled', None)
        self.clear_server_journal(server)
        self.clear_health(server)
        self._save_record(plugin_key(server), None)
        result = self.status(server)
        result['errors'] = errors
        result['changes'] = {proto: None for proto in protocols}
        return result

    def excluded_wireguard(self, server, patch):
        """WireGuard-инстансы, с которых надо снять правила при смене настройки."""
        if not isinstance(patch, dict) or patch.get('include_wireguard') is not False:
            return []
        if not self.settings(server)['include_wireguard']:
            return []
        return [proto for proto in self.capable(server, True)
                if proto.split('__', 1)[0] == 'wireguard'
                and self.mode_of(server, proto) != 'off']

    def set_settings(self, server, guard_for, patch):
        record = self.record(server)
        if not record or not record.get('installed'):
            raise PluginError('plugin_not_installed',
                              'Torrent guard plugin is not installed', 409)
        merged = self.merge_settings(record.get('settings') or {}, patch)
        stop = self.excluded_wireguard(server, patch)
        applied, errors = {}, []
        if stop:
            if guard_for is None:
                raise PluginError('apply_failed',
                                  'SSH is required to stop WireGuard rules',
                                  502)
            applied, errors = self._apply(
                server, {proto: 'off' for proto in stop}, guard_for)
            for proto in applied:
                entry = (server.get('protocols') or {}).get(proto)
                if isinstance(entry, dict):
                    entry.pop('torrent_guard', None)
        record['settings'] = merged
        self._save_record(plugin_key(server), record)
        result = self.status(server)
        result['errors'] = errors
        result['changes'] = dict(applied)
        return result

    def set_enabled(self, server, guard_for, enabled):
        record = self.record(server)
        if not record or not record.get('installed'):
            raise PluginError('plugin_not_installed',
                              'Torrent guard plugin is not installed', 409)
        settings = self.settings(server)
        allowed = self.capable(server, settings['include_wireguard'])
        protocols = self.capable(server, True)
        if not protocols:
            record['enabled'] = bool(enabled)
            self._save_record(plugin_key(server), record)
            result = self.status(server)
            result['changes'] = {}
            result['errors'] = []
            return result
        if enabled:
            suspended = record.get('suspended_modes') or {}
            wanted = {proto: normalize_mode(
                suspended.get(proto)
                or (settings['default_mode'] if proto in allowed else 'off'))
                for proto in protocols}
        else:
            suspended = {proto: self.mode_of(server, proto)
                         for proto in protocols
                         if self.mode_of(server, proto) != 'off'}
            record['suspended_modes'] = suspended
            wanted = {proto: 'off' for proto in protocols}
        applied, errors = self._apply(server, wanted, guard_for)
        for proto, mode in applied.items():
            server['protocols'][proto]['torrent_guard'] = mode
        record['enabled'] = bool(enabled)
        if enabled:
            record['suspended_modes'] = {}
        self._save_record(plugin_key(server), record)
        if not enabled and settings['clear_marks_on_disable']:
            self.clear_server_journal(server)
        result = self.status(server)
        result['errors'] = errors
        result['changes'] = dict(applied)
        return result

    def set_mode(self, server, guard_for, proto, mode):
        record = self.record(server)
        if not record or not record.get('installed'):
            raise PluginError('plugin_not_installed',
                              'Torrent guard plugin is not installed', 409)
        if proto not in self.capable(server, True):
            raise PluginError('unsupported_protocol',
                              'Protocol %s does not support torrent guard'
                              % proto, 400)
        if proto not in self.capable(server):
            raise PluginError(
                'wireguard_disabled',
                'WireGuard is excluded by the plugin settings', 400)
        raw = str(mode or '').strip().lower()
        if raw not in MODES:
            raise PluginError('invalid_mode',
                              'Mode must be one of %s' % ', '.join(MODES), 400)
        previous = self.mode_of(server, proto)
        server['protocols'][proto]['torrent_guard'] = raw
        applied, errors = self._apply(server, {proto: raw}, guard_for)
        if errors:
            server['protocols'][proto]['torrent_guard'] = previous
            raise PluginError('apply_failed',
                              'Torrent guard rules were not applied',
                              502, errors)
        record['enabled'] = True
        record['suspended_modes'] = {}
        self._save_record(plugin_key(server), record)
        result = self.status(server)
        result['errors'] = []
        result['changes'] = dict(applied)
        return result

    def refresh(self, server, guard_for):
        record = self.record(server)
        if not record or not record.get('installed'):
            raise PluginError('plugin_not_installed',
                              'Torrent guard plugin is not installed', 409)
        errors = []
        for proto in self.capable(server):
            try:
                report = self._guard(guard_for, proto).read() or {}
            except PluginError:
                raise
            except Exception as exc:                    # noqa: BLE001
                report = {'error': str(exc) or exc.__class__.__name__}
            # Без хуков правила фактически сняты: `read` всё равно печатает
            # пиров интерфейса, и «пиров под правилами: N» было бы ложью.
            if isinstance(report, dict) and not report.get('hook'):
                report.pop('peers', None)
            self.set_health(server, proto, report)
            if report.get('error'):
                errors.append('%s: %s' % (proto, report['error']))
        result = self.status(server)
        result['errors'] = errors
        result['changes'] = {}
        return result

    def collect(self, server, proto, guard):
        """Один цикл коллектора для установленного сервера."""
        result = guard.collect(self.mode_of(server, proto))
        self.set_health(server, proto, result)
        return result


plugin = None  # экземпляр создаётся в app.py: путь зависит от DATA_FILE


def get_plugin():
    return plugin
