"""Exercise actual card-label JS through a 3.1 -> 3.x -> 2.0 transition."""
import os
from pathlib import Path
import re
import unittest


class ProtocolLabelsBrowserTests(unittest.TestCase):
    def test_refresh_replaces_old_labels_and_preserves_custom_names(self):
        from playwright.sync_api import sync_playwright
        source = (Path(__file__).resolve().parents[1] / 'templates/server.html').read_text(encoding='utf8')
        functions = '\n'.join(re.search(r'    function ' + name + r'\(.*?\n    }', source, re.S)[0]
                              for name in ('getProtoTitle', 'updateProtocolCard'))
        fixture = '''<div id="proto-awg2"><div class="protocol-name"></div></div><script>
            const PROTOCOL_LABELS = {}, CUSTOM_PROTO_NAMES = {};
            const DEFAULT_PROTOCOL_LABELS = {awg2: 'AmneziaWG 2.0'};
            const protoBase = p => p.split('__')[0], protoInstance = p => 1;
            const protoDomKey = p => p;
            function ensureProtocolCard() {}
        ''' + functions + '</script>'
        with sync_playwright() as pw:
            options = {'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}
            browser = pw.chromium.launch(headless=True, **options)
            try:
                page = browser.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.set_content(fixture)
                self.assertFalse(errors)
                for label in ('AmneziaWG 3.1 (amnezia-awg2)', 'AmneziaWG 3.x (amnezia-awg2)',
                              'AmneziaWG 2.0', 'AmneziaWG 3.1 (amnezia-awg2)'):
                    page.evaluate('(label) => updateProtocolCard("awg2", {display_name: label})', label)
                    self.assertEqual(page.locator('.protocol-name').inner_text(), label)
                page.evaluate('updateProtocolCard("awg2", {})')
                self.assertEqual(page.locator('.protocol-name').inner_text(), 'AmneziaWG 2.0')
                page.evaluate('CUSTOM_PROTO_NAMES.awg2 = "Personal name"')
                self.assertEqual(page.evaluate('getProtoTitle("awg2")'), 'Personal name')
            finally:
                browser.close()
