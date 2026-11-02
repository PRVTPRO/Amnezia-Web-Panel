"""Unavailable host probes must not look like successful zero readings."""
import os
from pathlib import Path
import re
import unittest


class HostStatsBrowserTests(unittest.TestCase):
    def test_partial_statistics_keep_valid_fields_visible(self):
        from playwright.sync_api import sync_playwright
        source = (Path(__file__).resolve().parents[1] / 'templates/server.html').read_text(encoding='utf8')
        function = re.search(r'    async function loadServerStats\(.*?\n    }', source, re.S)[0]
        with sync_playwright() as pw:
            options = {'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}
            browser = pw.chromium.launch(headless=True, **options)
            try:
                page = browser.new_page()
                page.set_content('<div id="serverStats"></div><div id="serverIpv6"></div><script>'
                    'const SERVER_ID = 0; const formatBytes = n => String(n || 0);'
                    'let stats = {}; const apiCall = async () => stats;' + function + '</script>')
                page.evaluate('''async () => {
                    stats = {cpu: 0, ram_percent: 25, disk_percent: 60, net_rx: 0, net_tx: 0,
                             errors: {cpu: 'unavailable', network: 'unavailable'}};
                    await loadServerStats();
                }''')
                text = page.locator('#serverStats').inner_text()
                self.assertIn('⚡ —', text)
                self.assertIn('🧠 25%', text)
                self.assertIn('💾 60%', text)
                self.assertIn('🌐 —', text)
                self.assertNotIn('0%', text.replace('60%', ''))
                page.evaluate('stats = {cpu: 0, ram_percent: 0, disk_percent: 0}; loadServerStats()')
                self.assertIn('⚡ 0%', page.locator('#serverStats').inner_text())
            finally:
                browser.close()
