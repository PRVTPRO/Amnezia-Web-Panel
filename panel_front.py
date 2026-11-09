"""Public front for the panel port.

One TCP listener serves both schemes and is the only place that decides who
may reach the panel:

* TLS ClientHello is inspected: the client address and the SNI are checked
  against the panel access settings before anything is passed to the panel
  on 127.0.0.1. A denied TLS caller is reset before the handshake, so it
  never sees a certificate.
* A plain HTTP request is inspected the same way by its Host header; a
  denied caller gets the stock 404 of an empty nginx, an allowed one is
  passed through when the panel itself speaks HTTP.
* Anything else gets the stock 404 too, or a reset.

Why the checks live here: the panel is reached through a loopback hop, so
inside the app every caller looks like 127.0.0.1. Only this layer sees the
real peer address, and only it can tell an ordinary web server apart from a
panel with access rules.
"""
import asyncio
import json
import os
import socket
import struct

NOT_FOUND_BODY = (
    b'<html>\r\n<head><title>404 Not Found</title></head>\r\n'
    b'<body>\r\n<center><h1>404 Not Found</h1></center>\r\n'
    b'<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n'
)

_ACCESS = {
    'allowlist_enabled': False,
    'allowlist': [],
    'fleet': [],
    'domain_only': False,
    'domain': '',
    'backend_tls': True,
}
_ACCESS_STAMP = None


def _data_path():
    return os.environ.get('DATA_FILE') or os.path.join(os.getcwd(), 'data.json')


def load_access():
    """Panel access settings, re-read only when data.json changed."""
    global _ACCESS, _ACCESS_STAMP
    path = _data_path()
    try:
        stamp = os.path.getmtime(path)
    except OSError:
        return _ACCESS
    if stamp == _ACCESS_STAMP:
        return _ACCESS
    try:
        with open(path, encoding='utf-8') as source:
            data = json.load(source)
    except Exception:
        return _ACCESS
    settings = data.get('settings') or {}
    access = settings.get('panel_access') or {}
    ssl_conf = settings.get('ssl') or {}
    _ACCESS = {
        'allowlist_enabled': bool(access.get('ip_allowlist_enabled')),
        'allowlist': [str(e).strip() for e in (access.get('ip_allowlist') or [])
                      if str(e).strip()],
        'fleet': [str(s.get('host') or '').strip()
                  for s in (data.get('servers') or [])
                  if str(s.get('host') or '').strip()],
        'domain_only': bool(access.get('domain_only')),
        'domain': str(access.get('allowed_domain') or '').strip().lower(),
        'backend_tls': bool(ssl_conf.get('enabled')),
    }
    _ACCESS_STAMP = stamp
    return _ACCESS


def not_found_response():
    """Byte-exact stock 404: status, server header, body and length."""
    return (
        b'HTTP/1.1 404 Not Found\r\n'
        b'Server: nginx\r\n'
        b'Content-Type: text/html\r\n'
        b'Content-Length: ' + str(len(NOT_FOUND_BODY)).encode('ascii') + b'\r\n'
        b'Connection: close\r\n\r\n' + NOT_FOUND_BODY
    )


def _reset(writer):
    """Abort with an RST so a half-open peer sees a dead port, not a panel."""
    sock = writer.get_extra_info('socket')
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack('ii', 1, 0))
        except OSError:
            pass
    try:
        writer.transport.abort()
    except Exception:
        pass


def _looks_like_tls(head):
    # TLS record: content type 0x16 (handshake), major version 0x03.
    return len(head) >= 2 and head[0] == 0x16 and head[1] == 0x03


def parse_sni(hello):
    """Server name from a TLS ClientHello, or None when it cannot be read."""
    try:
        if len(hello) < 5 or hello[0] != 0x16:
            return None
        pos = 5
        if hello[pos] != 0x01:  # ClientHello
            return None
        pos += 4  # handshake type + 3-byte length
        pos += 2 + 32  # client version + random
        pos += 1 + hello[pos]  # session id
        pos += 2 + int.from_bytes(hello[pos:pos + 2], 'big')  # cipher suites
        pos += 1 + hello[pos]  # compression methods
        if pos + 2 > len(hello):
            return None
        end = min(len(hello), pos + 2 + int.from_bytes(hello[pos:pos + 2], 'big'))
        pos += 2
        while pos + 4 <= end:
            etype = int.from_bytes(hello[pos:pos + 2], 'big')
            elen = int.from_bytes(hello[pos + 2:pos + 4], 'big')
            pos += 4
            if etype == 0:  # server_name
                p = pos + 2
                if p + 3 > len(hello):
                    return None
                nlen = int.from_bytes(hello[p + 1:p + 3], 'big')
                p += 3
                if p + nlen > len(hello):
                    return None
                return hello[p:p + nlen].decode('ascii', 'ignore').lower()
            pos += elen
    except (IndexError, ValueError):
        return None
    return None


def parse_http_host(head):
    """Host header of a plain HTTP request head, lowercased, port stripped."""
    for line in head.split(b'\r\n')[1:]:
        if line.lower().startswith(b'host:'):
            value = line.split(b':', 1)[1].strip().decode('ascii', 'ignore')
            if value.startswith('['):
                close = value.find(']')
                return (value[1:close] if close != -1 else value).lower()
            return value.rsplit(':', 1)[0].lower() if ':' in value else value.lower()
    return ''


def _host_matches(host, allowed):
    return bool(allowed) and (host == allowed or host.endswith('.' + allowed))


def _ip_allowed(client_ip, entries):
    import ipaddress
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


async def _denied(head, writer, access):
    """Answer a denied caller exactly like an empty web server."""
    if _looks_like_tls(head):
        _reset(writer)
        return
    try:
        writer.write(not_found_response())
        await writer.drain()
    except Exception:
        pass
    writer.close()


def _allowed(head, client_ip, loopback, access):
    if not access.get('allowlist_enabled') and not access.get('domain_only'):
        return True
    if loopback:
        return True
    if access.get('allowlist_enabled'):
        if not _ip_allowed(client_ip, list(access.get('allowlist') or [])
                           + list(access.get('fleet') or [])):
            return False
    if access.get('domain_only'):
        allowed = access.get('domain') or ''
        if _looks_like_tls(head):
            if not _host_matches(parse_sni(head) or '', allowed):
                return False
        else:
            if not _host_matches(parse_http_host(head), allowed):
                return False
    return True


async def _pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle(reader, writer, backend):
    try:
        head = await asyncio.wait_for(reader.read(4096), timeout=15)
    except Exception:
        _reset(writer)
        return
    if not head:
        _reset(writer)
        return
    access = load_access()
    peer = writer.get_extra_info('peername') or ('', 0)
    client_ip = str(peer[0] or '')
    loopback = client_ip in ('127.0.0.1', '::1')
    if not _allowed(head, client_ip, loopback, access):
        await _denied(head, writer, access)
        return
    is_tls = _looks_like_tls(head)
    if not is_tls and access.get('backend_tls'):
        # A plain HTTP request against an HTTPS-only panel: the stock 404.
        await _denied(head, writer, access)
        return
    try:
        back_reader, back_writer = await asyncio.open_connection(*backend)
    except Exception:
        _reset(writer)
        return
    back_writer.write(head)
    try:
        await back_writer.drain()
    except Exception:
        _reset(writer)
        return
    await asyncio.gather(_pump(reader, back_writer), _pump(back_reader, writer))


def serve(host='0.0.0.0', port=5000, backend=('127.0.0.1', 5001)):
    """Run the front forever (blocking)."""

    async def main():
        server = await asyncio.start_server(
            lambda r, w: _handle(r, w, backend), host, port)
        async with server:
            await server.serve_forever()

    asyncio.run(main())
