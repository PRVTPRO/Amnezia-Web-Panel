"""Browser regressions for the compact add-server enrollment form.

The page is rendered with Jinja, its production scripts and stylesheet are
removed, and only the enrollment script is re-attached to a synthetic DOM and
API stub. That keeps the test offline while still executing the handler code
that ships in ``templates/server_new.html``.

The flow under test is the compact one recommended in the upstream design
review: fill the form, test the connection (which pins an unknown host key),
and only then enable "Add server". A changed key blocks the flow until the
operator confirms it explicitly.
"""
import json
import os
import re
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
TEST = '/api/servers/test'
ADD = '/api/servers/add'
CONFIRM = '/api/ssh-trust/onboarding/confirm'


HELPERS_JS = r"""
window._ = function (key) { return window.I18N[key] || key; };

const TEST = '/api/servers/test';
const ADD = '/api/servers/add';
const CONFIRM = '/api/ssh-trust/onboarding/confirm';
const calls = [];
let testOutcomes = [];
let addErrorCode = null;
let delayedTest = false;
let pendingTest = null;

function clone(value) { return JSON.parse(JSON.stringify(value)); }

async function apiCall(url, method = 'GET', body = null) {
    calls.push({url: url, method: method,
                body: body ? clone(body) : null});
    if (url === TEST) {
        if (delayedTest) {
            delayedTest = false;
            await new Promise(resolve => {
                pendingTest = {resolve: () => { pendingTest = null; resolve(); }};
            });
        }
        const outcome = testOutcomes.length ? testOutcomes.shift() : null;
        if (outcome && outcome.error) {
            const error = new Error(outcome.error.error_code || 'error');
            error.payload = clone(outcome.error);
            throw error;
        }
        if (outcome) return clone(outcome.response);
        return {status: 'success', host_key: {
            host: 'node.example.test', port: 2222,
            algorithm: 'ssh-ed25519', fingerprint: 'SHA256:trusted',
            status: 'trusted'}};
    }
    if (url === CONFIRM) {
        return {status: 'success', ssh_authenticated: false};
    }
    if (url === ADD) {
        if (addErrorCode) {
            const error = new Error(addErrorCode);
            error.payload = {error: addErrorCode, error_code: addErrorCode};
            throw error;
        }
        return {status: 'success', server_id: 7, server_info: {}};
    }
    throw new Error('unexpected API call: ' + url);
}
"""


class CompactEnrollmentBrowserTests(unittest.TestCase):
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
        cls.html = env.get_template('server_new.html').render(
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
        )
        scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', cls.html, re.S)
        wizard_js = next((script for script in scripts if 'const enrollState' in script), None)
        if not wizard_js:
            raise AssertionError('the enrollment script was not found in templates/server_new.html')
        # The synthetic page has no real origin. Capture the post-add redirect
        # instead of letting it destroy the test page.
        wizard_js, replaced = re.subn(
            r"window\.location\.href = '/server/' \+ result\.server_id;",
            "window.__serverHref = '/server/' + result.server_id;",
            wizard_js)
        if replaced != 1:
            raise AssertionError('the post-add redirect was not found in the enrollment script')
        cls.wizard_js = wizard_js

    @classmethod
    def tearDownClass(cls):
        browser = getattr(cls, 'browser', None)
        if browser is not None:
            browser.close()
        playwright = getattr(cls, '_playwright', None)
        if playwright is not None:
            playwright.stop()

    def new_page(self, viewport=None):
        context = self.browser.new_context(viewport=viewport or {'width': 1280, 'height': 900})
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
        page.add_script_tag(content=self.wizard_js)
        return page

    def calls(self, page, path):
        return page.evaluate('(path) => calls.filter(call => call.url === path)', path)

    def click(self, page, selector):
        # Inline onclick handlers are what ships; dispatch the DOM click
        # directly so the synthetic about:blank page cannot make Playwright's
        # mouse hit-testing flaky when result panels resize the form.
        page.evaluate('(selector) => document.querySelector(selector).click()', selector)

    def configure_outcomes(self, page, *outcomes):
        page.evaluate('(outcomes) => { testOutcomes = outcomes; }', list(outcomes))

    def fill_valid(self, page, host='node.example.test', port='2222',
                   user='root', password='synthetic-password'):
        page.fill('#enrollHost', host)
        page.fill('#enrollPort', port)
        page.fill('#enrollUser', user)
        page.fill('#enrollPassword', password)

    def success_outcome(self, fingerprint='SHA256:trusted', status='trusted'):
        return {'response': {
            'status': 'success',
            'server_info': {'hostname': 'synthetic'},
            'host_key': {
                'host': 'node.example.test', 'port': 2222,
                'algorithm': 'ssh-ed25519', 'fingerprint': fingerprint,
                'status': status,
            },
        }}

    def changed_outcome(self, token='changed-token'):
        return {'error': {
            'error': 'Host key changed; verify and accept the new key',
            'error_code': 'host_key_changed',
            'host_key': {
                'host': 'node.example.test', 'port': 2222,
                'algorithm': 'ssh-ed25519', 'fingerprint': 'SHA256:new',
                'old_fingerprints': [{'algorithm': 'ssh-ed25519',
                                      'fingerprint': 'SHA256:old'}],
                'status': 'changed', 'token': token,
            },
        }}

    def test_add_is_disabled_until_a_successful_test(self):
        page = self.new_page()
        self.configure_outcomes(page, self.success_outcome())
        self.assertTrue(page.locator('#enrollAddBtn').is_disabled())

        self.fill_valid(page)
        self.assertTrue(page.locator('#enrollAddBtn').is_disabled())
        self.assertEqual(self.calls(page, TEST), [])

        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollSuccess').hidden === false")

        test_calls = self.calls(page, TEST)
        self.assertEqual(len(test_calls), 1)
        self.assertEqual(test_calls[0]['method'], 'POST')
        self.assertEqual(test_calls[0]['body'], {
            'name': '', 'host': 'node.example.test', 'ssh_port': 2222,
            'username': 'root', 'password': 'synthetic-password', 'private_key': '',
        })
        self.assertFalse(page.locator('#enrollAddBtn').is_disabled())
        self.assertIn('SHA256:trusted', page.locator('#enrollSuccessText').text_content())

        self.click(page, '#enrollAddBtn')
        page.wait_for_function('window.__serverHref !== undefined')
        self.assertEqual(page.evaluate('window.__serverHref'), '/server/7')
        self.assertEqual(len(self.calls(page, ADD)), 1)
        self.assertEqual(page.input_value('#enrollPassword'), '')

        # Credentials only go to the two enrollment endpoints.
        for path in (TEST, ADD):
            for call in self.calls(page, path):
                self.assertIn('password', call['body'])
        self.assertEqual(self.calls(page, CONFIRM), [])
        # Credentials live only in page memory; the shipped script must not
        # persist them in browser storage.
        self.assertNotIn('localStorage', self.wizard_js)
        self.assertNotIn('sessionStorage', self.wizard_js)

    def test_private_key_tab_sends_only_the_key(self):
        page = self.new_page()
        self.configure_outcomes(page, self.success_outcome())
        self.click(page, '#enrollKeyTab')
        self.assertTrue(page.locator('#authPassword').is_hidden())
        self.assertTrue(page.locator('#authKey').is_visible())

        page.fill('#enrollHost', 'node.example.test')
        page.fill('#enrollPort', '2222')
        page.fill('#enrollUser', 'root')
        page.fill('#enrollKey', '-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----')
        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollSuccess').hidden === false")

        body = self.calls(page, TEST)[0]['body']
        self.assertEqual(body['password'], '')
        self.assertIn('synthetic', body['private_key'])

    def test_changed_key_blocks_add_until_explicitly_accepted(self):
        page = self.new_page()
        self.configure_outcomes(
            page,
            self.changed_outcome(),
            self.success_outcome(fingerprint='SHA256:new'),
        )
        self.fill_valid(page)
        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollChanged').hidden === false")

        self.assertTrue(page.locator('#enrollAddBtn').is_disabled())
        self.assertTrue(page.locator('#enrollSuccess').is_hidden())
        details = page.locator('#enrollChangedDetails').text_content()
        self.assertIn('SHA256:new', details)
        self.assertIn('SHA256:old', details)
        self.assertTrue(page.locator('#enrollAcceptBtn').is_disabled())

        page.evaluate('acceptChangedKey()')
        page.wait_for_timeout(50)
        self.assertEqual(self.calls(page, CONFIRM), [])

        page.check('#enrollChangedVerified')
        self.assertTrue(page.locator('#enrollChanged').is_visible())
        self.assertFalse(page.locator('#enrollAcceptBtn').is_disabled())
        self.click(page, '#enrollAcceptBtn')
        page.wait_for_function("document.getElementById('enrollSuccess').hidden === false")
        page.wait_for_function('calls.filter(call => call.url === TEST).length === 2')

        confirm = self.calls(page, CONFIRM)
        self.assertEqual(len(confirm), 1)
        self.assertEqual(confirm[0]['body'], {
            'host': 'node.example.test', 'ssh_port': 2222,
            'token': 'changed-token', 'confirmed': True,
        })
        for field in ('username', 'password', 'private_key'):
            self.assertNotIn(field, confirm[0]['body'])
        self.assertFalse(page.locator('#enrollAddBtn').is_disabled())
        self.assertTrue(page.locator('#enrollChanged').is_hidden())

    def test_editing_the_form_invalidates_the_test(self):
        page = self.new_page()
        self.configure_outcomes(page, self.success_outcome(), self.success_outcome())
        self.fill_valid(page)
        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollSuccess').hidden === false")
        self.assertFalse(page.locator('#enrollAddBtn').is_disabled())

        page.fill('#enrollHost', 'other.example.test')
        self.assertTrue(page.locator('#enrollAddBtn').is_disabled())
        self.assertTrue(page.locator('#enrollSuccess').is_hidden())
        self.assertTrue(page.locator('#enrollTestHint').is_visible())

        page.evaluate('addServer()')
        page.wait_for_timeout(50)
        self.assertEqual(self.calls(page, ADD), [])

        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollSuccess').hidden === false")
        self.assertFalse(page.locator('#enrollAddBtn').is_disabled())

    def test_stale_test_response_cannot_enable_add(self):
        page = self.new_page()
        self.configure_outcomes(page, self.success_outcome(fingerprint='SHA256:stale'))
        page.evaluate('delayedTest = true')
        self.fill_valid(page)
        self.click(page, '#enrollTestBtn')
        page.wait_for_function('pendingTest !== null')

        page.fill('#enrollHost', 'other.example.test')
        page.evaluate('pendingTest.resolve()')
        page.wait_for_function('pendingTest === null')
        page.wait_for_timeout(100)

        self.assertTrue(page.locator('#enrollAddBtn').is_disabled())
        self.assertTrue(page.locator('#enrollSuccess').is_hidden())
        self.assertTrue(page.locator('#enrollTestHint').is_visible())

    def test_test_errors_are_mapped_to_readable_messages(self):
        cases = {
            'authentication_failed': 'enroll_error_auth',
            'network_error': 'enroll_error_network',
            'validation_error': 'enroll_error_validation',
        }
        for code, key in cases.items():
            with self.subTest(error_code=code):
                page = self.new_page()
                self.configure_outcomes(page, {'error': {'error': code, 'error_code': code}})
                self.fill_valid(page)
                self.click(page, '#enrollTestBtn')
                page.wait_for_function(
                    '(key) => { const el = document.getElementById("enrollError");'
                    ' return !el.hidden && el.textContent === window._(key); }',
                    arg=key)
                self.assertTrue(page.locator('#enrollAddBtn').is_disabled())
                self.assertEqual(self.calls(page, ADD), [])

    def test_mobile_layout_has_no_horizontal_overflow(self):
        page = self.new_page(viewport={'width': 375, 'height': 812})
        self.assertEqual(page.evaluate('window.innerWidth'), 375)
        self.configure_outcomes(page, self.changed_outcome())
        self.fill_valid(page)
        self.click(page, '#enrollTestBtn')
        page.wait_for_function("document.getElementById('enrollChanged').hidden === false")
        self.assert_no_horizontal_overflow(page)

    def assert_no_horizontal_overflow(self, page):
        widths = page.evaluate("""() => ({
            view: window.innerWidth,
            document: document.documentElement.scrollWidth,
            body: document.body.scrollWidth
        })""")
        self.assertLessEqual(max(widths['document'], widths['body']), widths['view'] + 1,
                             f'horizontal overflow: {widths}')


if __name__ == '__main__':
    unittest.main()
