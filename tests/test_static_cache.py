"""Only fingerprinted static URLs may be cached forever.

`static_version()` appends ?v=<mtime> to the assets whose URL is built in a
template, but plenty of them are referenced without it - the favicon, the
icons, qrcode.min.js, searchable-select.js, the vendored CodeMirror bundles
and ReDoc. Those keep the same URL across deploys, so an `immutable` lifetime
would pin the old file in the browser for half a year.
"""

import unittest

from fastapi.testclient import TestClient

import app as panel


class StaticCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(panel.app)

    def test_fingerprinted_asset_is_immutable(self):
        res = self.client.get('/static/css/style.css?v=12345')
        self.assertEqual(res.status_code, 200)
        self.assertIn('immutable', res.headers['cache-control'])

    def test_plain_asset_is_revalidated(self):
        res = self.client.get('/static/js/qrcode.min.js')
        self.assertEqual(res.status_code, 200)
        cache_control = res.headers['cache-control']
        self.assertNotIn('immutable', cache_control)
        self.assertIn('must-revalidate', cache_control)


if __name__ == '__main__':
    unittest.main()
