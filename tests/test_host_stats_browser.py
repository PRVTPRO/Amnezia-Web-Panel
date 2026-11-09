"""Unavailable host probes must not look like successful zero readings."""
import os
from pathlib import Path
import unittest


class HostStatsBrowserTests(unittest.TestCase):
    def test_partial_statistics_keep_valid_fields_visible(self):
        from playwright.sync_api import sync_playwright
        source = (Path(__file__).resolve().parents[1] / 'templates/server.html').read_text(encoding='utf8')
        start = source.index('    const SERVER_STAT_ICONS')
        end = source.index('    async function loadServerStats', start)
        helpers = source[start:end]
        with sync_playwright() as pw:
            options = {'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}
            browser = pw.chromium.launch(headless=True, **options)
            try:
                page = browser.new_page()
                page.set_content(
                    '<div id="serverStatsBody"></div><div id="serverStatsFoot" hidden></div>'
                    '<span id="serverStatsTime"></span><script>'
                    'const _ = k => k; const formatBytes = n => String(n || 0);'
                    'const escapeHtml = s => String(s == null ? "" : s);'
                    + helpers + '</script>')
                page.evaluate('''() => {
                    renderServerStats({cpu: 0, ram_percent: 25, disk_percent: 60, net_rx: 0, net_tx: 0,
                        ram_used: 1, ram_total: 4, disk_used: 6, disk_total: 10, uptime: 'up 3 days',
                        errors: {cpu: 'unavailable', network: 'unavailable'}});
                }''')
                text = page.locator('#serverStatsBody').inner_text()
                self.assertIn('server_load_cpu', text)
                self.assertIn('—', text)
                self.assertIn('25%', text)
                self.assertIn('60%', text)
                self.assertNotIn('0%', text.replace('60%', ''))
                self.assertIn('server_load_net', text)
                page.evaluate('''() => renderServerStats({cpu: 0, ram_percent: 0, disk_percent: 0,
                    net_rx: 0, net_tx: 0, ram_used: 0, ram_total: 4, disk_used: 0, disk_total: 10, uptime: 'up'})''')
                self.assertIn('0%', page.locator('#serverStatsBody').inner_text())
            finally:
                browser.close()
