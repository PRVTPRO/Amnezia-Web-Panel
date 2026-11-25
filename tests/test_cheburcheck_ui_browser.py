"""Issue #415: the cheburcheck counter shows regions, not scanner answers.

The page block is extracted from templates/server.html and runs in Chromium
with a stubbed apiCall, so the per-server card and the per-target table are
checked on a real rendered DOM.
"""
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'templates' / 'server.html'


def _cheburcheck_block():
    source = TEMPLATE.read_text(encoding='utf-8')
    start = source.index('function cheburAge(')
    end = source.index('function openCheburcheckModal(', start)
    return source[start:end]


STUBS = """
const _ = key => key;
const escapeHtml = value => String(value == null ? '' : value);
window.SERVER_ID = 0;
window.__record = null;
const apiCall = async () => window.__record;
"""


class CheburcheckCounterBrowserTests(unittest.TestCase):
    def setUp(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        options = {}
        if os.environ.get('PANEL_BROWSER_EXECUTABLE'):
            options['executable_path'] = os.environ['PANEL_BROWSER_EXECUTABLE']
        self.browser = self._pw.chromium.launch(headless=True, **options)
        self.page = self.browser.new_page()
        self.errors = []
        self.page.on('pageerror', lambda error: self.errors.append(str(error)))
        self.page.set_content(
            '<div id="cheburcheck-summary"></div>'
            '<div id="cheburcheck-details" class="hidden"></div>'
            '<button id="cheburcheckBtn" type="button"></button>'
            '<table><tbody id="rows"></tbody></table>'
            '<script>' + STUBS + _cheburcheck_block() + '</script>')

    def tearDown(self):
        self.browser.close()
        self._pw.stop()

    def _record(self, **probe):
        return {'status': 'clean', 'checked_at': None,
                'probe': probe, 'remarks': 0, 'static_hit': False,
                'scan_mode': 'full', 'targets': {}}

    def test_card_uses_region_total_not_answer_count(self):
        self.page.evaluate("""record => { window.__record = record; return loadCheburcheck(); }""",
                           self._record(blocking_regions=0, total_regions=15,
                                        clear_regions=30, restricted_regions=0))
        text = self.page.locator('#cheburcheck-summary').inner_text()
        self.assertIn('0/15', text)
        self.assertNotIn('0/30', text)

    def test_old_record_falls_back_to_blocking_plus_clear(self):
        self.page.evaluate("""record => { window.__record = record; return loadCheburcheck(); }""",
                           self._record(blocking_regions=2, clear_regions=13,
                                        restricted_regions=0))
        text = self.page.locator('#cheburcheck-summary').inner_text()
        self.assertIn('2/15', text)

    def test_target_row_uses_region_total(self):
        row = self.page.evaluate("""record => cheburcheckTargetRow('1.2.3.4', record)""",
                                 self._record(blocking_regions=1, total_regions=7,
                                              clear_regions=20, restricted_regions=0))
        self.assertIn('1/7', row)
        self.assertNotIn('1/21', row)
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
