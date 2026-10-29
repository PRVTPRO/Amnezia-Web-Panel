"""Execute the real onboarding controls in Chromium with a synthetic backend."""
import json
import os
from pathlib import Path
import re
import unittest


class OnboardingBrowserTests(unittest.TestCase):
    def test_add_edit_trust_controls_and_stale_responses(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest('Playwright is not installed')
        from jinja2 import Environment, FileSystemLoader
        root = Path(__file__).resolve().parents[1]
        env = Environment(loader=FileSystemLoader(str(root / 'templates')), autoescape=True)
        strings = json.loads((root / 'translations/en.json').read_text(encoding='utf-8'))
        html = env.get_template('index.html').render(servers=[], user={'role': 'admin'},
            request=None, settings={}, site_settings={}, current_user={'role': 'admin'},
            _=lambda key: strings.get(key, key))
        source = (root / 'templates/index.html').read_text(encoding='utf-8')
        # Only actual onboarding handlers; no load-time polling or production URLs.
        match = re.search(r'    /\* Trust candidates.*?(?=    /\* ========== Ping indicators)', source, re.S)
        self.assertIsNotNone(match)
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}))
            except Exception as exc:
                self.skipTest(f'Chromium is not installed: {type(exc).__name__}')
            try:
                page = browser.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                # Strip scripts/assets: run selected real handlers with no network.
                html = re.sub(r'<script\b.*?</script>', '', html, flags=re.S)
                html = re.sub(r'<link[^>]+>', '', html)
                page.set_content(html)
                page.add_script_tag(content="""
const calls = [];
const messages = """ + json.dumps(strings) + """;
const _ = key => messages[key] || key;
let delayed = false, resolveInspect, fail = false;
const apiCall = async (url, method, body) => {
    calls.push({url, method, body});
    if (fail) throw new Error('synthetic network timeout');
    if (delayed && url.endsWith('/inspect')) await new Promise(resolve => {resolveInspect = resolve;});
    return url.endsWith('/inspect') ? {host:body.host,port:body.ssh_port,algorithm:'ssh-ed25519',fingerprint:'SHA256:synthetic',status:'unknown',old_fingerprints:[],token:'synthetic-signed-token'} : {status:'success',ssh_authenticated:false};
};
""" + match[0])
                for kind, host_id, port_id, password_id in [('add', 'serverHost', 'serverPort', 'serverPassword'),
                                                          ('edit', 'editServerHost', 'editServerPort', 'editServerPassword')]:
                    with self.subTest(kind=kind):
                        page.evaluate("""([kind, host, port, password]) => {
                            document.getElementById(host).value='node.example.test';
                            document.getElementById(port).value='2222';
                            document.getElementById(password).value='never-send-this';
                            document.getElementById('editServerForm').dataset.serverUid='uid-a';
                            document.getElementById(kind === 'add' ? 'addServerModal' : 'editServerModal').style.display='block';
                        }""", [kind, host_id, port_id, password_id])
                        page.evaluate(f"document.getElementById('{kind}-trust-inspect').click()")
                        page.wait_for_function(f"!document.getElementById('{kind}-trust-confirmation').hidden")
                        details = page.locator(f'#{kind}-trust-details').text_content()
                        self.assertIn('SHA256:synthetic', details)
                        self.assertIn('Unknown SSH key', details)
                        before = page.evaluate('calls.length')
                        page.evaluate(f"document.getElementById('{kind}-trust-save').click()")
                        self.assertEqual(page.evaluate('calls.length'), before)  # No checkbox, no confirmation.
                        page.evaluate(f"document.getElementById('{kind}-trust-verified').checked=true")
                        page.evaluate(f"document.getElementById('{kind}-trust-save').click(); document.getElementById('{kind}-trust-save').click()")
                        page.wait_for_function(f"document.getElementById('{kind}-trust-details').textContent.includes('authentication has not been tested')")
                        self.assertEqual(page.evaluate('calls.length'), before + 1)
                        self.assertEqual(page.locator('#' + password_id).input_value(), 'never-send-this')
                        body = page.evaluate('calls[calls.length-1].body')
                        self.assertNotIn('password', body)
                        self.assertNotIn('private_key', body)
                        self.assertEqual(body['host'], 'node.example.test')
                        if kind == 'edit':
                            self.assertEqual(body['server_uid'], 'uid-a')
                # Endpoint change invalidates both an existing token and an in-flight response.
                page.evaluate("delayed=true; void inspectOnboardingTrust('add')")
                page.wait_for_function('typeof resolveInspect === "function"')
                page.evaluate("document.getElementById('serverHost').value='different.example.test'; document.getElementById('serverHost').dispatchEvent(new Event('input')); resolveInspect()")
                self.assertTrue(page.locator('#add-trust-confirmation').evaluate('(el)=>el.hidden'))
                self.assertEqual(page.locator('#add-trust-details').text_content(), '')
                page.evaluate("delayed=false; fail=true; void inspectOnboardingTrust('add')")
                page.wait_for_function("document.getElementById('add-trust-details').textContent.includes('timeout')")
                self.assertFalse(page.locator('#add-trust-inspect').is_disabled())
                self.assertEqual(errors, [])
            finally:
                browser.close()
