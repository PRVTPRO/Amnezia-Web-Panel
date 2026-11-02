"""A denied optional API must not navigate an authenticated page away."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import re
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ForbiddenNavigationBrowserTests(unittest.TestCase):
    def test_optional_forbidden_apis_keep_page_and_session_expiry_redirects(self):
        from playwright.sync_api import sync_playwright

        template = (ROOT / 'templates/base.html').read_text(encoding='utf-8')
        helper = re.search(r'        async function apiCall\(.*?\n        }', template, re.S)[0]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle(self):
                try:
                    super().handle()
                except ConnectionError:
                    # Chromium may cancel a favicon request when a page closes.
                    pass

            def do_GET(self):
                if self.path.startswith('/api/'):
                    expired = self.path == '/api/expired'
                    proxy = self.path == '/api/settings/tunnels/status'
                    self.send_response(401 if expired else 403)
                    self.send_header('Content-Type', 'text/html' if proxy else 'application/json')
                    self.end_headers()
                    self.wfile.write(b'<h1>403 Forbidden</h1>' if proxy else b'{"error":"Self-service is disabled"}')
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                if self.path == '/login':
                    self.wfile.write(b'<h1>Login</h1>')
                    return
                endpoint = '/api/settings/tunnels/status' if self.path == '/settings' else '/api/my/connections/options'
                if self.path == '/expired':
                    endpoint = '/api/expired'
                self.wfile.write((f'<h1>{self.path}</h1><div id="error"></div><script>' + helper +
                    f'\napiCall({endpoint!r}).catch(err => document.getElementById("error").textContent = err.message);'
                    '</script>').encode())

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as pw:
                options = {'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}
                browser = pw.chromium.launch(headless=True, **options)
                try:
                    for path in ('/settings', '/my'):
                        page = browser.new_page()
                        origin = f'http://127.0.0.1:{server.server_port}'
                        navigations = []
                        page.on('framenavigated', lambda frame: navigations.append(frame.url))
                        page.goto(origin + path)
                        page.wait_for_function('location.pathname === "/login" || document.getElementById("error")?.textContent.length > 0')
                        self.assertEqual(page.url, origin + path)
                        self.assertNotIn(origin + '/login', navigations)
                        self.assertIn('403' if path == '/settings' else 'Self-service is disabled', page.locator('#error').inner_text())
                        page.close()
                    page = browser.new_page()
                    page.goto(origin + '/expired')
                    page.wait_for_url(origin + '/login')
                    page.close()
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
