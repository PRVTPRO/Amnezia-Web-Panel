"""Browser regressions for the dashboard's host-key warning on server cards.

The dashboard is rendered with Jinja, then only the card-trust script section
is re-attached to a synthetic DOM and fetch stub. The test verifies the compact
warning icon, the changed-key modal, the single confirmation checkbox, and the
fact that accepting a key calls the inventory-bound confirm endpoint.
"""
import json
import os
import re
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
START = '/* ========== Server card host-key warning ========== */'
END = '/* ========== Ping indicators ========== */'


HELPERS_JS = r"""
window._ = function (key) { return window.I18N[key] || key; };
window.__calls = [];
window.__toasts = [];
let __responses = [];
window.fetch = async function (url, options) {
    window.__calls.push({url: url, options: options || {}});
    const response = __responses.length ? __responses.shift() : {ok: true, body: {}};
    return {
        ok: response.ok !== false,
        status: response.status || (response.ok === false ? 409 : 200),
        json: async () => JSON.parse(JSON.stringify(response.body || {})),
    };
};
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }
function showToast(message, kind) { window.__toasts.push({message: message, kind: kind}); }
function pingServer(idx) { window.__pinged = idx; }
"""


class ServerCardTrustBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest('Playwright is not installed')

        cls._playwright = sync_playwright().start()
        launch_options = {'headless': True}
        if os.environ.get('PANEL_BROWSER_EXECUTABLE'):
            launch_options['executable_path'] = os.environ['PANEL_BROWSER_EXECUTABLE']
        try:
            cls.browser = cls._playwright.chromium.launch(**launch_options)
        except Exception as exc:
            cls._playwright.stop()
            raise unittest.SkipTest(f'Chromium is not installed: {type(exc).__name__}')

        cls.strings = json.loads((ROOT / 'translations' / 'en.json').read_text(encoding='utf-8'))
        env = Environment(loader=FileSystemLoader(str(ROOT / 'templates')), autoescape=True)
        servers = [{
            'uid': 'uid-0', 'name': 'Synthetic', 'host': '192.0.2.10',
            'ssh_port': 22, 'username': 'root', 'password': 'x',
            'private_key': '', 'protocols': {}, 'self_service_enabled': False,
        }]
        cls.html = env.get_template('index.html').render(
            request=None,
            lang='en',
            static_v='synthetic',
            site_settings={'title': 'Synthetic panel', 'subtitle': '', 'logo': ''},
            current_user={'username': 'admin', 'role': 'admin'},
            _=lambda key: cls.strings.get(key, key),
            translations_json=json.dumps(cls.strings),
            login_translations_json='{}',
            all_translations_json='{}',
            captcha_settings={},
            telegram_settings={},
            bot_running=False,
            servers=servers,
            connections=[],
            stats={},
        )
        scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', cls.html, re.S)
        script = next((item for item in scripts if START in item), None)
        if not script:
            raise AssertionError('the card trust script was not found in templates/index.html')
        cls.trust_js = script.split(START, 1)[1].split(END, 1)[0]
        cls.trust_js = START + cls.trust_js

    @classmethod
    def tearDownClass(cls):
        browser = getattr(cls, 'browser', None)
        if browser is not None:
            browser.close()
        playwright = getattr(cls, '_playwright', None)
        if playwright is not None:
            playwright.stop()

    def new_page(self):
        context = self.browser.new_context(viewport={'width': 1280, 'height': 900})
        self.addCleanup(context.close)
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        self.addCleanup(self.assertEqual, errors, [], 'uncaught JavaScript errors')

        html = re.sub(r'<script\b.*?</script>', '', self.html, flags=re.S)
        html = re.sub(r'<link[^>]+>', '', html)
        page.set_content(html)
        page.add_style_tag(path=str(ROOT / 'static' / 'css' / 'style.css'))
        page.add_script_tag(content='window.I18N = ' + json.dumps(self.strings) + ';\n' + HELPERS_JS)
        page.add_script_tag(content=self.trust_js)
        return page

    def respond(self, page, *responses):
        page.evaluate('(responses) => { __responses = responses; }', list(responses))

    def changed_body(self):
        return {
            'status': 'changed', 'host': '192.0.2.10', 'port': 22,
            'algorithm': 'ssh-ed25519', 'fingerprint': 'SHA256:new',
            'old_fingerprints': [{'algorithm': 'ssh-ed25519',
                                  'fingerprint': 'SHA256:old'}],
            'token': 'changed-token',
        }

    def test_changed_key_icon_opens_modal_and_requires_one_checkbox(self):
        page = self.new_page()
        self.respond(page, {'ok': True, 'body': self.changed_body()},
                     {'ok': True, 'body': {'status': 'success'}})

        self.assertTrue(page.locator('#ssh-trust-0').is_hidden())
        page.evaluate("setServerTrustIcon(0, 'changed')")
        self.assertTrue(page.locator('#ssh-trust-0').is_visible())
        self.assertIn('is-changed', page.get_attribute('#ssh-trust-0', 'class'))

        page.evaluate("document.getElementById('ssh-trust-0').click()")
        page.wait_for_function("document.getElementById('serverTrustModal').classList.contains('active')")
        page.wait_for_function("document.getElementById('serverTrustDetails').textContent.includes('SHA256:new')")

        inspect_call = page.evaluate('window.__calls[0]')
        self.assertEqual(inspect_call['url'], '/api/servers/0/ssh-trust/inspect?server_uid=uid-0')
        details = page.locator('#serverTrustDetails').text_content()
        self.assertIn('SHA256:new', details)
        self.assertIn('SHA256:old', details)
        self.assertTrue(page.locator('#serverTrustConfirmRow').is_visible())
        self.assertTrue(page.locator('#serverTrustAccept').is_disabled())

        page.evaluate(
            "() => { const c = document.getElementById('serverTrustVerified');"
            " c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); }")
        self.assertFalse(page.locator('#serverTrustAccept').is_disabled())

        page.evaluate("document.getElementById('serverTrustAccept').click()")
        page.wait_for_function("window.__calls.length === 2")
        page.wait_for_function("!document.getElementById('serverTrustModal').classList.contains('active')")

        confirm_call = page.evaluate('window.__calls[1]')
        self.assertEqual(confirm_call['url'], '/api/servers/0/ssh-trust/confirm?server_uid=uid-0')
        self.assertEqual(json.loads(confirm_call['options']['body']), {
            'token': 'changed-token', 'confirmed': True,
        })
        self.assertNotIn('password', confirm_call['options']['body'])
        self.assertTrue(page.locator('#ssh-trust-0').is_hidden())
        self.assertEqual(page.evaluate('window.__pinged'), 0)
        self.assertEqual(page.evaluate('window.__toasts')[0]['kind'], 'success')

    def test_trusted_key_does_not_offer_acceptance(self):
        page = self.new_page()
        self.respond(page, {'ok': True, 'body': {
            'status': 'trusted', 'host': '192.0.2.10', 'port': 22,
            'algorithm': 'ssh-ed25519', 'fingerprint': 'SHA256:trusted',
            'old_fingerprints': [],
        }})
        page.evaluate("document.getElementById('ssh-trust-0').click()")
        page.wait_for_function("document.getElementById('serverTrustDetails').textContent.includes('SHA256:trusted')")
        self.assertTrue(page.locator('#serverTrustConfirmRow').is_hidden())
        self.assertTrue(page.locator('#serverTrustAccept').is_disabled())

    def test_unknown_key_uses_the_same_explicit_confirmation(self):
        page = self.new_page()
        self.respond(page, {'ok': True, 'body': {
            'status': 'unknown', 'host': '192.0.2.10', 'port': 22,
            'algorithm': 'ssh-ed25519', 'fingerprint': 'SHA256:unknown',
            'old_fingerprints': [], 'token': 'unknown-token',
        }})
        page.evaluate("setServerTrustIcon(0, 'unknown')")
        self.assertTrue(page.locator('#ssh-trust-0').is_visible())
        page.evaluate("document.getElementById('ssh-trust-0').click()")
        page.wait_for_function("document.getElementById('serverTrustConfirmRow') && !document.getElementById('serverTrustConfirmRow').classList.contains('hidden')")
        self.assertTrue(page.locator('#serverTrustAccept').is_disabled())


if __name__ == '__main__':
    unittest.main()
