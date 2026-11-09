"""Public front for the panel port.

One TCP listener serves both schemes without revealing what is behind it:

* a TLS ClientHello is passed through to the panel on 127.0.0.1, so HTTPS
  behaves exactly as before (the panel still decides who is allowed in and
  answers denied callers with the stock 404);
* anything else - a plain HTTP request, a scanner, a broken client - gets the
  same stock 404 of an empty nginx and the connection is closed.

The point is that opening the port looks like opening any ordinary web
server, and trying http:// against it does not produce a protocol error that
differs from the https:// path.
"""
import asyncio
import socket
import struct

NOT_FOUND_BODY = (
    b'<html>\r\n<head><title>404 Not Found</title></head>\r\n'
    b'<body>\r\n<center><h1>404 Not Found</h1></center>\r\n'
    b'<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n'
)


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


def _looks_like_tls(head):
    # TLS record: content type 0x16 (handshake), major version 0x03.
    return len(head) >= 2 and head[0] == 0x16 and head[1] == 0x03


async def _handle(reader, writer, backend):
    try:
        head = await asyncio.wait_for(reader.read(4096), timeout=15)
    except Exception:
        _reset(writer)
        return
    if not head:
        _reset(writer)
        return
    if _looks_like_tls(head):
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
        return
    try:
        writer.write(not_found_response())
        await writer.drain()
    except Exception:
        pass
    writer.close()


def serve(host='0.0.0.0', port=5000, backend=('127.0.0.1', 5001)):
    """Run the front forever (blocking)."""

    async def main():
        server = await asyncio.start_server(
            lambda r, w: _handle(r, w, backend), host, port)
        async with server:
            await server.serve_forever()

    asyncio.run(main())
