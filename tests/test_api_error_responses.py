"""/api/* must answer JSON even when a handler blows up, and the browser
helper must survive an answer that is not JSON at all.

Without both halves a proxy error page, a restart mid-request or an unhandled
exception surfaces in the UI as "JSON.parse: unexpected character at line 1
column 1 of the JSON data", which says nothing about what actually happened.
"""

import os
import re
import unittest
from unittest import mock

from fastapi.responses import JSONResponse, PlainTextResponse

import app as panel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def call_handler(path):
    request = mock.Mock()
    request.method = 'GET'
    request.url.path = path
    import asyncio
    return asyncio.run(panel.api_json_error_handler(request, RuntimeError('boom')))


class ApiErrorHandlerTests(unittest.TestCase):
    def test_handler_is_registered_for_unhandled_exceptions(self):
        self.assertIn(Exception, panel.app.exception_handlers)

    def test_api_paths_answer_json(self):
        response = call_handler('/api/servers/0/connections')
        self.assertIsInstance(response, JSONResponse)
        self.assertEqual(response.status_code, 500)
        self.assertIn(b'"error"', response.body)

    def test_pages_keep_plain_text(self):
        response = call_handler('/server/0')
        self.assertIsInstance(response, PlainTextResponse)
        self.assertEqual(response.status_code, 500)


class ApiCallHelperTests(unittest.TestCase):
    """Text-level checks of the fetch helper every page uses."""

    def setUp(self):
        with open(os.path.join(ROOT, 'templates', 'base.html'), encoding='utf-8') as f:
            page = f.read()
        start = page.index('async function apiCall(')
        self.helper = page[start:page.index('\n        }', start)]

    def test_reads_text_and_parses_defensively(self):
        self.assertIn('await res.text()', self.helper)
        self.assertIn('JSON.parse(text)', self.helper)
        self.assertNotIn('await res.json()', self.helper)
        self.assertRegex(self.helper, r'catch \(parseError\)')
        # the thrown message carries the status, not just the parser complaint
        self.assertIn('HTTP ${res.status}', self.helper)

    def test_still_redirects_on_an_expired_session(self):
        self.assertIn("res.status === 401", self.helper)
        self.assertIn("window.location.href = '/login'", self.helper)


if __name__ == '__main__':
    unittest.main()
