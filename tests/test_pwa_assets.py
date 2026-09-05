"""Source assertions for service worker and PWA head tags."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SW = (ROOT / 'static' / 'sw.js').read_text(encoding='utf-8')
BASE = (ROOT / 'templates' / 'base.html').read_text(encoding='utf-8')
LOGIN = (ROOT / 'templates' / 'login.html').read_text(encoding='utf-8')
OFFLINE = ROOT / 'static' / 'offline.html'


class TestServiceWorker(unittest.TestCase):
    def test_version_from_script_url(self):
        self.assertIn("searchParams.get('v')", SW)
        self.assertIn('awp-static-', SW)

    def test_skip_waiting_claim_and_old_cache_eviction(self):
        self.assertIn('self.skipWaiting()', SW)
        self.assertIn('self.clients.claim()', SW)
        self.assertIn("k.startsWith('awp-static-')", SW)
        self.assertIn('caches.delete', SW)

    def test_no_ignore_search_for_versioned_static(self):
        """Versioned CSS/JS must match the exact URL, including ?v=."""
        self.assertNotRegex(SW, r'ignoreSearch\s*:')
        self.assertNotIn('caches.match(req, {', SW)
        self.assertNotIn("caches.match(req, {", SW)

    def test_css_js_network_first(self):
        self.assertIn(".endsWith('.css')", SW)
        self.assertIn(".endsWith('.js')", SW)
        css_idx = SW.find(".endsWith('.css')")
        self.assertGreater(css_idx, 0)
        branch = SW[css_idx:css_idx + 700]
        fetch_pos = branch.find('fetch(req)')
        match_pos = branch.find('caches.match(req)')
        self.assertGreater(fetch_pos, 0)
        self.assertGreater(match_pos, fetch_pos)

    def test_static_intercept_and_nav_not_cached(self):
        self.assertIn("pathname.startsWith('/static/')", SW)
        self.assertIn("pathname.startsWith('/api/')", SW)
        # Navigations fall back to offline.html; pages themselves are not cached.
        self.assertIn("req.mode === 'navigate'", SW)
        self.assertIn("/static/offline.html", SW)
        nav_block = SW.split("req.mode === 'navigate'")[1]
        self.assertNotIn('cache.put', nav_block)
        # Ensure API early-return precedes any caching of non-static paths.
        api_pos = SW.find("pathname.startsWith('/api/')")
        static_pos = SW.find("pathname.startsWith('/static/')")
        self.assertGreater(api_pos, 0)
        self.assertGreater(static_pos, api_pos)

    def test_offline_html_exists(self):
        self.assertTrue(OFFLINE.is_file())
        body = OFFLINE.read_text(encoding='utf-8')
        self.assertIn('Retry', body)
        self.assertIn('<style>', body)


class TestPwaHeadTags(unittest.TestCase):
    def test_base_and_login_share_pwa_meta(self):
        for name, src in (('base.html', BASE), ('login.html', LOGIN)):
            with self.subTest(template=name):
                self.assertIn('viewport-fit=cover', src)
                self.assertIn('rel="manifest"', src)
                self.assertIn('/manifest.webmanifest', src)
                self.assertIn('name="theme-color"', src)
                self.assertIn('apple-mobile-web-app-capable', src)
                self.assertIn('apple-mobile-web-app-status-bar-style', src)
                self.assertIn('black-translucent', src)
                self.assertIn('apple-touch-icon', src)
                self.assertRegex(
                    src,
                    re.compile(r"serviceWorker\.register\(\s*['\"]/sw\.js\?v=\{\{\s*static_v\s*\}\}['\"]"),
                )


if __name__ == '__main__':
    unittest.main()
