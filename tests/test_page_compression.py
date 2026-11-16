"""Сжатие ответов панели.

HTML страницы сервера ~800 КБ, и публичный порт (panel_front) ничего не
сжимает. Проверяем три контракта: текстовые ответы уходят с gzip (в том числе
потоковые), бинарные (PNG-капча, архивы бэкапа) проходят без сжатия, а сам
gzip не зависит от системных часов.
"""
import asyncio
import unittest
import zlib
from unittest import mock

import app as panel

GZIP_WBITS = 16 + zlib.MAX_WBITS


async def _echo_text(scope, receive, send):
    body = ('x' * 4096).encode()
    await send({'type': 'http.response.start',
                'headers': [(b'content-type', b'text/html; charset=utf-8'),
                            (b'content-length', str(len(body)).encode())],
                'status': 200})
    await send({'type': 'http.response.body', 'body': body})


async def _stream_text(scope, receive, send):
    await send({'type': 'http.response.start',
                'headers': [(b'content-type', b'text/css; charset=utf-8')],
                'status': 200})
    await send({'type': 'http.response.body', 'body': b'y' * 2048,
                'more_body': True})
    await send({'type': 'http.response.body', 'body': b'z' * 2048,
                'more_body': False})


def _call(app, path, accept_encoding='gzip, deflate, br'):
    """Статус, заголовки и склеенное тело ответа."""
    scope = {
        'type': 'http', 'method': 'GET', 'path': path, 'raw_path': path.encode(),
        'root_path': '', 'scheme': 'https', 'query_string': b'',
        'headers': [(b'host', b'panel'),
                    (b'accept-encoding', accept_encoding.encode())],
        'server': ('panel', 5000), 'client': ('127.0.0.1', 1234),
        'http_version': '1.1',
    }
    sent = []

    async def receive():
        return {'type': 'http.request', 'body': b'', 'more_body': False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m['type'] == 'http.response.start')
    headers = {name.decode().lower(): value.decode()
               for name, value in start['headers']}
    body = b''.join(m.get('body', b'') for m in sent
                    if m['type'] == 'http.response.body')
    return start['status'], headers, body


def build_stack(inner=_echo_text):
    return panel.CompressionGate(
        panel.TextGZipMiddleware(inner, minimum_size=1024, compresslevel=6))


def gunzip(data):
    decompressor = zlib.decompressobj(GZIP_WBITS)
    return decompressor.decompress(data) + decompressor.flush()


class GzipStreamTests(unittest.TestCase):
    def test_chunked_response_is_compressed_and_decodes(self):
        status, headers, body = _call(build_stack(_stream_text), '/server/6')
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('content-encoding'), 'gzip')
        self.assertNotIn('content-length', headers)
        self.assertEqual(gunzip(body), b'y' * 2048 + b'z' * 2048)

    def test_shifted_clock_does_not_break_gzip(self):
        # Stock GZipMiddleware пишет в gzip-заголовок текущее время и падает
        # на struct.pack, когда тесты двигают часы (mock.patch(time.time)).
        with mock.patch('time.time', return_value=10 ** 12):
            status, headers, body = _call(build_stack(), '/server/6')
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('content-encoding'), 'gzip')
        self.assertEqual(len(gunzip(body)), 4096)


class CompressionGateTests(unittest.TestCase):
    def test_text_response_is_gzipped(self):
        status, headers, body = _call(build_stack(), '/server/6')
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('content-encoding'), 'gzip')
        self.assertIn('Accept-Encoding', headers.get('vary', ''))
        self.assertEqual(len(gunzip(body)), 4096)

    def test_binary_path_passes_through_uncompressed(self):
        for path in ('/api/auth/captcha',
                     '/static/icons/apple-touch-icon-180.png',
                     '/api/settings/backup/archive',
                     '/api/servers/3/backups/download'):
            with self.subTest(path=path):
                _status, headers, body = _call(build_stack(), path)
                self.assertNotIn('content-encoding', headers)
                self.assertEqual(len(body), 4096)

    def test_client_without_gzip_gets_plain_text(self):
        _status, headers, body = _call(build_stack(), '/server/6',
                                       accept_encoding='identity')
        self.assertNotIn('content-encoding', headers)
        self.assertEqual(len(body), 4096)


class RealAppWiringTests(unittest.TestCase):
    def test_gzip_sits_inside_the_gate(self):
        classes = [entry.cls for entry in panel.app.user_middleware]
        self.assertIn(panel.TextGZipMiddleware, classes)
        self.assertIn(panel.CompressionGate, classes)
        # Порядок в user_middleware: 0 — самый внешний слой.
        self.assertLess(classes.index(panel.CompressionGate),
                        classes.index(panel.TextGZipMiddleware))

    def test_skip_list_covers_binary_responses(self):
        for path in ('/api/auth/captcha', '/api/settings/backup/archive',
                     '/static/icons/logo.png', '/api/servers/1/backups/download'):
            with self.subTest(path=path):
                scope = {'type': 'http', 'path': path}
                self.assertTrue(panel._compression_skipped(scope))
        self.assertFalse(panel._compression_skipped(
            {'type': 'http', 'path': '/server/6'}))
        self.assertFalse(panel._compression_skipped(
            {'type': 'http', 'path': '/api/servers/6/check'}))


if __name__ == '__main__':
    unittest.main()
