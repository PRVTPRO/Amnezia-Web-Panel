"""Playwright regressions for the server IPv4/IPv6 surfaces.

The IPv6 block is extracted from templates/server.html and runs against the
real modal markup on a synthetic page. `apiCall` is a stub, so no SSH is used.
"""
import json
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'templates' / 'server.html'
STYLE = ROOT / 'static' / 'css' / 'style.css'
EN = json.loads((ROOT / 'translations' / 'en.json').read_text(encoding='utf-8'))


def _fragment(start, end):
    source = TEMPLATE.read_text(encoding='utf-8')
    first = source.index(start)
    chunk = source[first:source.index(end, first)]
    chunk = re.sub(r"\{\{\s*_\(\s*'([^']+)'\s*\)\s*\}\}",
                   lambda m: EN.get(m.group(1), m.group(1)), chunk)
    chunk = re.sub(r'\{\{\s*_\(\s*"([^"]+)"\s*\)\s*\}\}',
                   lambda m: EN.get(m.group(1), m.group(1)), chunk)
    assert '{{' not in chunk, chunk[:200]
    return chunk


def _js_block():
    source = TEMPLATE.read_text(encoding='utf-8')
    start = source.index('// ========== IPv4 / IPv6 ==========')
    end = source.index('// ========== Server Check ==========', start)
    return source[start:end]


def _element(pattern):
    match = re.search(pattern, TEMPLATE.read_text(encoding='utf-8'))
    assert match, pattern
    return match.group(0)


PAGE_HTML = (
    '<div class="ip-chips" id="serverIpChips" hidden></div>'
    + _fragment('<div class="modal-backdrop" id="ipSettingsModal">',
                '<div class="modal-backdrop" id="awgSettingsModal">')
    + _fragment('<div class="form-group" id="installAwgDns6Group">',
                '<div id="installAwgJunk">')
    + _element(r'<input[^>]*id="awgSetDns6"[^>]*>')
    + _fragment('<div class="seg-row" id="awgSetIpv6Row">',
                '<div class="form-group" id="awgSetJunkGroup">')
)

STUBS = """
const I18N = %s;
window._ = key => I18N[key] || key;
window.SERVER_ID = 0;
window.calls = [];
window.toasts = [];
window.responses = [];
window.apiCall = async (url, method, body) => {
    window.calls.push({url: url, method: method, body: body});
    const next = window.responses.length ? window.responses.shift() : {};
    if (next.throws) throw new Error(next.throws);
    return next.body === undefined ? next : next.body;
};
window.openModal = id => document.getElementById(id).classList.add('active');
window.closeModal = id => document.getElementById(id).classList.remove('active');
window.showToast = (message, kind) => window.toasts.push({message: message, kind: kind});
window.escapeHtml = value => String(value == null ? '' : value).replace(/[&<>"']/g,
    c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
window.protoBase = proto => String(proto || 'awg').split('__')[0];
window.confirmAnswer = true;
window.confirm = () => window.confirmAnswer !== false;
""" % json.dumps(EN, ensure_ascii=False)


def status(**overrides):
    data = {
        'preference': {'new_instances': None, 'env_override': 'auto'},
        'can_write': True,
        'host': {'ipv4': '203.0.113.7', 'ipv6': '2a0a:9300:1:5::1',
                 'ipv6_state': 'in_use', 'ipv6_default_route': True,
                 'ipv6_disabled_by_sysctl': False},
        'docker': {'installed': True, 'ipv6_enabled': True,
                   'restart_required': False, 'flags_conflict': False},
        'instances': [],
    }
    data.update(overrides)
    return data


def instance(**overrides):
    data = {
        'proto': 'awg3', 'subnet_v4': '10.8.3.1/24', 'peers': 0,
        'peers_v6': 0, 'ipv6_enabled': False, 'subnet_v6': None,
        'blocked_reason': 'none', 'can_enable': True, 'can_disable': True,
        'exit_linked': False, 'container_running': True,
    }
    data.update(overrides)
    return data


class Ipv6UiBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest('Playwright is not installed')
        cls._playwright = sync_playwright().start()
        options = {'headless': True}
        if os.environ.get('PANEL_BROWSER_EXECUTABLE'):
            options['executable_path'] = os.environ['PANEL_BROWSER_EXECUTABLE']
        try:
            cls.browser = cls._playwright.chromium.launch(**options)
        except Exception as exc:
            cls._playwright.stop()
            raise unittest.SkipTest(f'Chromium is not installed: {type(exc).__name__}')

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._playwright.stop()

    def _page(self, width=1280, theme=None, rtl=False):
        page = self.browser.new_page(viewport={'width': width, 'height': 900})
        page.set_content(PAGE_HTML)
        page.add_style_tag(content=STYLE.read_text(encoding='utf-8'))
        page.add_script_tag(content=STUBS + '\n' + _js_block())
        if theme:
            page.evaluate("value => { document.documentElement.dataset.theme = value; }", theme)
        if rtl:
            page.evaluate("() => { document.documentElement.dir = 'rtl'; }")
        # The real modal is hidden until opened; inner_text and click need it.
        page.evaluate("() => openModal('ipSettingsModal')")
        return page

    @staticmethod
    def _states(page):
        return page.eval_on_selector_all(
            '.ip-chip', 'els => els.map(el => el.dataset.state)')

    @staticmethod
    def _glyphs(page):
        return page.eval_on_selector_all(
            '.ip-chip .glyph', 'els => els.map(el => el.textContent)')

    def test_chips_show_ipv4_ipv6_and_docker_states(self):
        page = self._page()
        try:
            def render(**docker):
                page.evaluate('data => renderIpChips(data)', {
                    'host': {'ipv4': '203.0.113.7', 'ipv6': '2a0a:9300:1:5::1',
                             'ipv6_state': 'in_use'},
                    'docker': docker,
                })

            render(installed=True, ipv6_enabled=True, restart_required=False)
            self.assertEqual(self._states(page), ['on', 'on'])
            self.assertEqual(self._glyphs(page), ['✓', '✓'])
            self.assertIn('203.0.113.7', page.locator('.ip-chip').first.inner_text())

            page.evaluate("() => { renderIpChips({host: {ipv4: '1.2.3.4', "
                          "ipv6: null, ipv6_state: 'enabled_no_peers'}, "
                          "docker: {installed: true, ipv6_enabled: true}}); }")
            self.assertEqual(self._states(page), ['on', 'warn'])
            self.assertEqual(self._glyphs(page)[1], '!')

            page.evaluate("() => { renderIpChips({host: {ipv4: '1.2.3.4', "
                          "ipv6_state: 'absent'}, docker: "
                          "{installed: true, ipv6_enabled: true}}); }")
            self.assertEqual(self._states(page), ['on', 'bad'])
            self.assertEqual(self._glyphs(page)[1], '✕')

            page.evaluate("() => { renderIpChips({host: {ipv4: '1.2.3.4', "
                          "ipv6_state: 'unknown'}, docker: "
                          "{installed: true, ipv6_enabled: true}}); }")
            self.assertEqual(self._states(page), ['on', 'neutral'])
            self.assertEqual(self._glyphs(page)[1], '?')
            self.assertIn(EN['server_ipv6_state_unknown'],
                          page.locator('.ip-chip').nth(1).inner_text())

            render(installed=True, ipv6_enabled=False, restart_required=True)
            self.assertEqual(self._states(page), ['on', 'on', 'warn'])
            chip = page.locator('.ip-chip').nth(2)
            self.assertIn(EN['server_ipv6_chip_restart'], chip.inner_text())
            self.assertEqual(chip.get_attribute('title'),
                             EN['server_ipv6_after_docker_restart'])

            render(installed=True, ipv6_enabled=False, restart_required=False)
            self.assertEqual(self._states(page)[2], 'off')

            render(installed=True, ipv6_enabled=False, flags_conflict=True,
                   restart_required=False)
            self.assertEqual(self._states(page)[2], 'warn')
            self.assertIn(EN['server_ipv6_badge_flags_conflict'],
                          page.locator('.ip-chip').nth(2).inner_text())

            render(installed=False)
            self.assertEqual(self._states(page)[2], 'off')
            self.assertIn(EN['server_ipv6_state_unknown'],
                          page.locator('.ip-chip').nth(2).inner_text())
        finally:
            page.close()

    def test_chips_fit_a_phone_viewport(self):
        page = self._page(width=390)
        try:
            page.evaluate("""() => { renderIpChips({
                host: {ipv4: '203.0.113.123', ipv6: '2a0a:9300:1:5::1',
                       ipv6_state: 'enabled_no_peers'},
                docker: {installed: true, ipv6_enabled: false,
                         restart_required: true}}); }""")
            metrics = page.evaluate("""() => {
                const box = document.getElementById('serverIpChips');
                const rects = [...box.querySelectorAll('.ip-chip')]
                    .map(el => el.getBoundingClientRect().right);
                return {scroll: box.scrollWidth, client: box.clientWidth,
                        right: Math.max(...rects), width: window.innerWidth,
                        visible: !box.hidden};
            }""")
            self.assertTrue(metrics['visible'])
            self.assertLessEqual(metrics['scroll'], metrics['client'] + 1)
            self.assertLessEqual(metrics['right'], metrics['width'] + 1)
        finally:
            page.close()

    def test_modal_preference_tristate_env_lock_and_read_only(self):
        page = self._page()
        try:
            page.evaluate('data => renderIpSettings(data)', status())
            self.assertTrue(page.locator('#ipPrefAuto').is_checked())
            self.assertFalse(page.locator('#ipPrefAuto').is_disabled())

            page.evaluate('data => renderIpSettings(data)', status(
                preference={'new_instances': True, 'env_override': 'auto'}))
            self.assertTrue(page.locator('#ipPrefOn').is_checked())
            self.assertFalse(page.locator('#ipPrefOn').is_disabled())

            page.evaluate('data => renderIpSettings(data)', status(
                preference={'new_instances': False, 'env_override': 'auto'}))
            self.assertTrue(page.locator('#ipPrefOff').is_checked())

            page.evaluate('data => renderIpSettings(data)', status(
                preference={'new_instances': True, 'env_override': 'off'}))
            for key in ('#ipPrefAuto', '#ipPrefOn', '#ipPrefOff'):
                self.assertTrue(page.locator(key).is_disabled())
            self.assertIn(EN['server_ipv6_env_override'],
                          page.locator('#ipHostSummary').inner_text())

            page.evaluate('data => renderIpSettings(data)', status(
                can_write=False,
                docker={'installed': True, 'ipv6_enabled': False,
                        'restart_required': True, 'flags_conflict': False},
                instances=[instance(proto='awg3', peers=36,
                                    blocked_reason='peers',
                                    can_enable=False)]))
            for key in ('#ipPrefAuto', '#ipPrefOn', '#ipPrefOff'):
                self.assertTrue(page.locator(key).is_disabled())
            self.assertEqual(page.locator('#ipDockerNote').evaluate(
                'el => getComputedStyle(el).display'), 'none')
            self.assertEqual(page.locator('#ipInstancesBody .ip-action').count(), 0)
            self.assertIn(EN['server_ipv6_table_has_peers'],
                          page.locator('#ipInstancesBody').inner_text())
        finally:
            page.close()

    def test_docker_restart_needs_the_confirmation_checkbox(self):
        page = self._page()
        try:
            page.evaluate('data => renderIpSettings(data)', status(
                docker={'installed': True, 'ipv6_enabled': False,
                        'restart_required': True, 'flags_conflict': False}))
            self.assertNotEqual(page.locator('#ipDockerNote').evaluate(
                'el => getComputedStyle(el).display'), 'none')
            self.assertFalse(page.locator('#ipDockerApplyBtn').is_disabled())

            page.click('#ipDockerApplyBtn')
            self.assertEqual(page.evaluate('calls.length'), 0)
            self.assertEqual(page.evaluate('toasts.at(-1).kind'), 'error')
            self.assertEqual(page.evaluate('toasts.at(-1).message'),
                             EN['server_ipv6_restart_docker_confirm'])

            page.evaluate("waitOperation = async () => ({state: 'done'})")
            page.check('#ipDockerConfirm')
            page.click('#ipDockerApplyBtn')
            page.wait_for_function(
                "calls.some(c => c.url.endsWith('/docker/ipv6/apply'))")
            call = page.evaluate(
                "calls.find(c => c.url.endsWith('/docker/ipv6/apply'))")
            self.assertEqual(call['url'], '/api/servers/0/docker/ipv6/apply')
            self.assertEqual(call['method'], 'POST')
            self.assertEqual(call['body'], {'confirm': 'restart-docker'})
            page.wait_for_function("toasts.some(t => t.kind === 'success')")

            page.evaluate('data => renderIpSettings(data)', status(
                docker={'installed': True, 'ipv6_enabled': False,
                        'restart_required': True, 'flags_conflict': True}))
            self.assertTrue(page.locator('#ipDockerApplyBtn').is_disabled())
        finally:
            page.close()

    def test_instance_rows_reflect_peers_rebuild_and_subnet(self):
        rows = [
            instance(proto='awg3__2', peers=36, blocked_reason='peers',
                     can_enable=False),
            instance(proto='awg2', peers=0, blocked_reason='needs_recreate'),
            instance(proto='awg', peers=4, peers_v6=4, ipv6_enabled=True,
                     subnet_v6='fd42:8:3::1/64', blocked_reason='none'),
            instance(proto='awg3', peers=None, blocked_reason='state_unreadable',
                     can_enable=False),
        ]
        page = self._page()
        try:
            page.evaluate('data => renderIpSettings(data)', status(instances=rows))
            body = page.locator('#ipInstancesBody')
            self.assertEqual(body.locator('tr').count(), 4)

            first = body.locator('tr').nth(0)
            self.assertEqual(first.locator('button').inner_text(),
                             EN['server_ipv6_action_enable'])
            self.assertTrue(first.locator('button').is_disabled())
            self.assertIn(EN['server_ipv6_table_has_peers'], first.inner_text())

            second = body.locator('tr').nth(1)
            self.assertEqual(second.locator('button').inner_text(),
                             EN['server_ipv6_action_rebuild'])
            self.assertFalse(second.locator('button').is_disabled())
            self.assertIn('badge-info', second.locator('.badge').get_attribute('class'))

            third = body.locator('tr').nth(2)
            self.assertEqual(third.locator('button').inner_text(),
                             EN['server_ipv6_action_disable'])
            self.assertFalse(third.locator('button').is_disabled())
            self.assertIn('fd42:8:3::1/64', third.inner_text())

            fourth = body.locator('tr').nth(3)
            self.assertEqual(fourth.locator('td').nth(2).inner_text().strip(), '—')
        finally:
            page.close()

    def test_repair_button_disables_an_exit_linked_instance(self):
        row = instance(proto='awg3__2', peers=36, peers_v6=30,
                       ipv6_enabled=True, subnet_v6='fd42:8:2::1/64',
                       blocked_reason='peers', can_enable=False,
                       can_disable=True, exit_linked=True)
        page = self._page()
        try:
            page.evaluate('data => renderIpSettings(data)', status(instances=[row]))
            button = page.locator('#ipInstancesBody button')
            self.assertEqual(button.inner_text(), EN['server_ipv6_action_repair'])
            self.assertFalse(button.is_disabled())

            page.evaluate('confirmAnswer = false')
            button.click()
            self.assertEqual(page.evaluate('calls.length'), 0)

            page.evaluate('confirmAnswer = true')
            button.click()
            page.wait_for_function(
                "calls.some(c => c.url.endsWith('/protocol/awg3__2/ipv6'))")
            call = page.evaluate(
                "calls.find(c => c.url.endsWith('/protocol/awg3__2/ipv6'))")
            self.assertEqual(call['url'], '/api/servers/0/protocol/awg3__2/ipv6')
            self.assertEqual(call['body'], {'enabled': False, 'repair': True})

            page.evaluate('data => renderIpSettings(data)', status(instances=[
                instance(proto='awg3', peers=5, ipv6_enabled=True,
                         subnet_v6='fd42:8:3::1/64', blocked_reason='peers',
                         exit_linked=False, can_disable=True)]))
            self.assertEqual(page.locator('#ipInstancesBody button').inner_text(),
                             EN['server_ipv6_action_disable'])
            self.assertTrue(page.locator('#ipInstancesBody button').is_disabled())
        finally:
            page.close()

    def test_install_note_follows_the_server_preference(self):
        page = self._page()
        try:
            def note(pref, docker_on):
                page.evaluate("""item => {
                    ipStatusCache = {
                        preference: {new_instances: item.pref,
                                     env_override: 'auto'},
                        docker: {ipv6_enabled: item.dockerOn}};
                    renderInstallIpv6Note();
                }""", {'pref': pref, 'dockerOn': docker_on})
                return page.evaluate("""() => {
                    const note = document.getElementById('installIpv6Note');
                    const dns6 = document.getElementById('installAwgDns6Group');
                    return {text: note.textContent, kind: note.dataset.kind,
                            noteShown: getComputedStyle(note).display !== 'none',
                            dns6Shown: getComputedStyle(dns6).display !== 'none'};
                }""")

            result = note(False, True)
            self.assertTrue(result['noteShown'])
            self.assertEqual(result['text'], EN['server_ipv6_disabled_server'])
            self.assertEqual(result['kind'], 'warn')
            self.assertFalse(result['dns6Shown'])

            result = note(True, False)
            self.assertEqual(result['text'], EN['server_ipv6_after_docker_restart'])
            self.assertEqual(result['kind'], 'pending')
            self.assertTrue(result['dns6Shown'])

            result = note(True, True)
            self.assertEqual(result['text'], EN['server_ipv6_install_ipv6_auto_desc'])
            self.assertEqual(result['kind'], 'info')

            result = note(None, False)
            self.assertEqual(result['text'], EN['server_ipv6_auto_from_server'])
            self.assertEqual(result['kind'], 'info')
        finally:
            page.close()

    def test_instance_settings_row_legacy_dns6_and_hints(self):
        page = self._page()
        try:
            page.evaluate("() => renderAwgIpv6Row('awg3', false, false, 0)")
            row = page.locator('#awgSetIpv6Row')
            self.assertNotEqual(row.evaluate('el => getComputedStyle(el).display'), 'none')
            self.assertTrue(page.locator('#awgIpv6Off').is_checked())
            self.assertTrue(page.locator('#awgSetDns6').is_disabled())
            self.assertEqual(page.locator('#awgSetIpv6Hint').inner_text(),
                             EN['server_ipv6_unlock_hint'])

            page.evaluate("() => renderAwgIpv6Row('awg_legacy', false, false, 0)")
            self.assertEqual(row.evaluate('el => getComputedStyle(el).display'), 'none')

            page.evaluate("() => renderAwgIpv6Row('awg3', true, false, 36)")
            self.assertTrue(page.locator('#awgIpv6On').is_checked())
            self.assertFalse(page.locator('#awgSetDns6').is_disabled())
            self.assertEqual(page.locator('#awgSetIpv6Hint').inner_text(),
                             EN['server_ipv6_blocked_peers'])

            page.evaluate("() => renderAwgIpv6Row('awg3', false, true, 0)")
            self.assertTrue(page.locator('#awgIpv6On').is_disabled())
            self.assertEqual(page.locator('#awgSetIpv6Hint').inner_text(),
                             EN['server_ipv6_blocked_exit_link'])
        finally:
            page.close()

    def test_rtl_keeps_addresses_left_to_right(self):
        page = self._page(rtl=True)
        try:
            page.evaluate('data => renderIpSettings(data)', status(instances=[
                instance(proto='awg', ipv6_enabled=True,
                         subnet_v6='fd42:8:3::1/64', blocked_reason='none')]))
            directions = page.evaluate("""() => [
                getComputedStyle(document.querySelector('#ipInstancesBody tr td:nth-child(2)')).direction,
                getComputedStyle(document.querySelector('#ipInstancesBody tr td:nth-child(4) .badge')).direction,
                getComputedStyle(document.querySelector('#serverIpChips span[dir="ltr"]') || document.body).direction,
            ]""")
            self.assertEqual(directions[0], 'ltr')
            self.assertEqual(directions[1], 'ltr')
        finally:
            page.close()

    def test_light_theme_keeps_chip_text_readable(self):
        page = self._page(theme='light')
        try:
            page.evaluate("""() => { renderIpChips({
                host: {ipv4: '203.0.113.7', ipv6_state: 'in_use'},
                docker: {installed: true, ipv6_enabled: false,
                         restart_required: true}}); }""")
            result = page.evaluate("""() => {
                const luminance = value => {
                    const parts = value.match(/\\d+(\\.\\d+)?/g).slice(0, 3)
                        .map(Number).map(v => {
                            const s = v / 255;
                            return s <= 0.03928 ? s / 12.92
                                : Math.pow((s + 0.055) / 1.055, 2.4);
                        });
                    return 0.2126 * parts[0] + 0.7152 * parts[1] + 0.0722 * parts[2];
                };
                const chips = [...document.querySelectorAll('.ip-chip')];
                return {
                    theme: document.documentElement.dataset.theme,
                    body: getComputedStyle(document.body).backgroundColor,
                    contrast: chips.map(el => {
                        const style = getComputedStyle(el);
                        const a = luminance(style.backgroundColor);
                        const b = luminance(style.color);
                        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
                    }),
                };
            }""")
            self.assertEqual(result['theme'], 'light')
            self.assertEqual(len(result['contrast']), 3)
            for ratio in result['contrast']:
                self.assertGreaterEqual(ratio, 3.0)
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
