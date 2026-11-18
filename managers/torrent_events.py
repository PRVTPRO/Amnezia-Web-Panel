"""Журнал торрент-событий на стороне панели.

Живёт в JSON рядом с data.json: события должны переживать пересоздание
инстанса (правила в контейнере стираются, а факт нарушения — нет).
Хранится 30 дней и не больше 20 событий на пира: этого хватает на разбор
жалобы хостинга и не раздувает диск.

Записи лежат по tunnel-IP, а не по client_id: коллектор видит трафик и знает
только адрес пира, а соответствие «адрес → ключ» вычисляется в момент
показа (там уже есть clientsTable). Поэтому переименование ключа историю
не теряет.

Структура:
    {"version": 1,
     "servers": {"<uid|host>": {"protocols": {"awg2": {"peers": {
         "10.8.1.17": {"client_id": "…", "last_ts": 1760000000,
                       "events": [{"ts": 1760000000, "sig": "handshake",
                                   "count": 12}]}}}}}}}
"""

import json
import os
import time

TTL_SECONDS = 30 * 86400
MAX_EVENTS_PER_KEY = 20
VERSION = 1


def server_key(server):
    """Ключ сервера: uid, иначе host (uid есть не у всех старых записей)."""
    if not isinstance(server, dict):
        return ''
    return str(server.get('uid') or server.get('host') or '')


def empty():
    return {'version': VERSION, 'servers': {}}


def _sanitize(data):
    """Приводит журнал к ожидаемой форме.

    Файл может быть отредактирован руками или обрезан при сбое питания:
    `{"servers": {"x": null}}` раньше ронял `summary()` и отдавал 500 на
    странице подключений. Битые ветки выкидываем, а не падаем.
    """
    if not isinstance(data, dict):
        return empty()
    servers = data.get('servers')
    if not isinstance(servers, dict):
        return empty()
    clean = {'version': VERSION, 'servers': {}}
    for key, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        protocols = entry.get('protocols')
        if not isinstance(protocols, dict):
            continue
        clean_protos = {}
        for proto, pdata in protocols.items():
            if not isinstance(pdata, dict):
                continue
            peers = pdata.get('peers')
            if not isinstance(peers, dict):
                continue
            clean_peers = {}
            for ip, bucket in peers.items():
                if not isinstance(bucket, dict):
                    continue
                events = []
                for event in (bucket.get('events') or []):
                    if not isinstance(event, dict):
                        continue
                    try:
                        ts = int(event.get('ts') or 0)
                    except (TypeError, ValueError):
                        continue
                    events.append({'ts': ts,
                                   'sig': str(event.get('sig') or ''),
                                   'count': int(event.get('count') or 0)})
                if events:
                    clean_peers[str(ip)] = {
                        'client_id': str(bucket.get('client_id') or ''),
                        'events': events,
                        'last_ts': max(e['ts'] for e in events),
                    }
            if clean_peers:
                clean_protos[str(proto)] = {'peers': clean_peers}
        if clean_protos:
            clean['servers'][str(key)] = {'protocols': clean_protos}
    return clean


def load(path):
    """Читает журнал; битый файл не роняет панель — начинаем с пустого."""
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return empty()
    return _sanitize(data)


def save(path, data):
    """Атомарная запись: temp в том же каталоге + os.replace."""
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    os.makedirs(directory, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(',', ':'))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _peers(data, key, protocol):
    servers = data.setdefault('servers', {})
    entry = servers.setdefault(key, {})
    protocols = entry.setdefault('protocols', {})
    pdata = protocols.setdefault(protocol, {})
    return pdata.setdefault('peers', {})


def prune(data, now=None, ttl_by_key=None):
    """Снимает события старше TTL и пустые ветки. Возвращает число снятых.

    ``ttl_by_key`` — необязательная функция ``key -> секунды``: плагин
    «Защита от торрентов» хранит срок жизни меток в настройках каждого
    сервера, а не одну константу на весь файл. None — значение по умолчанию
    (TTL_SECONDS), как было до появления плагина.
    """
    now = int(time.time()) if now is None else int(now)
    removed = 0
    for key, entry in list((data.get('servers') or {}).items()):
        ttl = TTL_SECONDS
        if ttl_by_key is not None:
            value = ttl_by_key(key)
            if value is not None:
                ttl = int(value)
        cutoff = now - ttl
        protocols = entry.get('protocols') or {}
        for proto, pdata in list(protocols.items()):
            peers = pdata.get('peers') or {}
            for ip, bucket in list(peers.items()):
                events = [e for e in (bucket.get('events') or [])
                          if int(e.get('ts') or 0) >= cutoff]
                removed += len(bucket.get('events') or []) - len(events)
                if events:
                    bucket['events'] = events
                    bucket['last_ts'] = max(int(e.get('ts') or 0)
                                            for e in events)
                    peers[ip] = bucket
                else:
                    peers.pop(ip, None)
            if peers:
                pdata['peers'] = peers
            else:
                protocols.pop(proto, None)
        if protocols:
            entry['protocols'] = protocols
        else:
            data['servers'].pop(key, None)
    return removed


def record(data, key, protocol, ip, events=(), client_id='', now=None):
    """Добавляет события по одному адресу пира. Возвращает число добавленных."""
    events = list(events or ())
    ip = str(ip or '').strip()
    if not key or not protocol or not ip or not events:
        return 0
    now = int(time.time()) if now is None else int(now)
    peers = _peers(data, key, protocol)
    bucket = peers.get(ip) or {'client_id': '', 'events': []}
    # Tunnel-IP переиспользуется: удалили ключ, адрес выдали новому. Метка
    # старого владельца не должна достаться новому — при смене client_id
    # история этого адреса начинается заново.
    if (client_id and bucket.get('client_id')
            and bucket.get('client_id') != client_id):
        bucket = {'client_id': '', 'events': []}
    if client_id:
        bucket['client_id'] = str(client_id)
    items = bucket.get('events') or []
    for event in events:
        items.append({
            'ts': int(event.get('ts') or now),
            'sig': str(event.get('sig') or ''),
            'count': int(event.get('count') or 0),
        })
    bucket['events'] = items[-MAX_EVENTS_PER_KEY:]
    bucket['last_ts'] = max(int(e.get('ts') or 0) for e in bucket['events'])
    peers[ip] = bucket
    return len(events)


def clear(data, key, protocol='', ip='', client_id=''):
    """Снимает события: конкретного пира, протокола или всего сервера."""
    entry = (data.get('servers') or {}).get(key) or {}
    protocols = entry.get('protocols') or {}
    removed = 0
    for proto, pdata in list(protocols.items()):
        if protocol and proto != protocol:
            continue
        peers = pdata.get('peers') or {}
        for peer_ip, bucket in list(peers.items()):
            if ip:
                # Адрес пира однозначно указывает на ключ: чистим по нему,
                # даже если client_id в бакете не записан (он появляется
                # только после первого события).
                if peer_ip != ip:
                    continue
            elif client_id and (bucket.get('client_id') or '') != client_id:
                continue
            removed += len(bucket.get('events') or [])
            peers.pop(peer_ip, None)
        if peers:
            pdata['peers'] = peers
        else:
            protocols.pop(proto, None)
    if protocols:
        entry['protocols'] = protocols
    elif key in (data.get('servers') or {}):
        data['servers'].pop(key, None)
    return removed


def peer_buckets(data, key, protocol):
    """{ip: {'client_id', 'events', 'last_ts'}} для одного инстанса."""
    entry = (data.get('servers') or {}).get(key) or {}
    pdata = (entry.get('protocols') or {}).get(protocol) or {}
    return dict(pdata.get('peers') or {})


def summary(data, key):
    """Сводка по серверу: {protocol: {...}} для плитки и бейджей.

    Возвращает только протоколы, где есть события: пустые не нужны ни плитке,
    ни странице сервера.
    """
    entry = (data.get('servers') or {}).get(key) or {}
    out = {}
    for proto, pdata in ((entry.get('protocols') or {}).items()):
        peers = pdata.get('peers') or {}
        total = 0
        latest_ts = 0
        latest_ip = ''
        latest_cid = ''
        for ip, bucket in peers.items():
            bucket = bucket or {}
            total += len(bucket.get('events') or [])
            ts = int(bucket.get('last_ts') or 0)
            if ts >= latest_ts:
                latest_ts = ts
                latest_ip = ip
                latest_cid = bucket.get('client_id') or ''
        if total:
            out[proto] = {'peers': len(peers), 'events': total,
                          'latest_ts': latest_ts, 'ip': latest_ip,
                          'client_id': latest_cid}
    return out

