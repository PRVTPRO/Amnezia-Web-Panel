"""Stage S3b: Cloudflare WARP marketplace card and srv_warp_* i18n.

These checks guard the host-level `proto-warp` card (separate from the
panel-level WARP feature) and keep the five shipped locales in lockstep.
"""

import compileall
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import app as panel

ROOT = Path(__file__).resolve().parents[1]
TRANSLATIONS = ROOT / 'translations'
LOCALES = ('en', 'ru', 'fr', 'fa', 'zh')

# Full UI surface of the S3b card (task scope; panel-level warp_* keys are
# deliberately a different namespace).
SRV_WARP_KEYS = {
    'srv_warp_card_desc',
    'srv_warp_install',
    'srv_warp_delete',
    'srv_warp_update',
    'srv_warp_link',
    'srv_warp_unlink',
    'srv_warp_status_not_installed',
    'srv_warp_status_installed',
    'srv_warp_status_degraded',
    'srv_warp_status_unreachable',
    'srv_warp_state_connected',
    'srv_warp_state_connecting',
    'srv_warp_state_disconnected',
    'srv_warp_state_error',
    'srv_warp_state_stopped',
    'srv_warp_state_unreachable',
    'srv_warp_state_rate_limited',
    'srv_warp_tos_title',
    'srv_warp_tos_text',
    'srv_warp_tos_accept',
    'srv_warp_budget',
    'srv_warp_job_running',
    'srv_warp_link_hint',
    'srv_warp_err_xor',
    'srv_warp_err_tos',
    'srv_warp_err_job_busy',
    'srv_warp_err_generic',
    'srv_warp_err_no_awg',
    'srv_warp_err_registered',
    'srv_warp_err_link_failed',
    'srv_warp_err_register_failed',
    'srv_warp_err_budget',
    'srv_warp_err_install_failed',
    'srv_warp_err_repair_failed',
    'srv_warp_no_awg',
    'srv_warp_stage_start',
    'srv_warp_stage_download',
    'srv_warp_stage_register',
    'srv_warp_stage_profile',
    'srv_warp_stage_startsh',
    'srv_warp_stage_done',
    'srv_warp_instance_btn_title',
    'srv_warp_instance_title',
    'srv_warp_instance_hint',
    'srv_warp_instance_toggle',
    'srv_warp_instance_details',
    'srv_warp_instance_proto',
    'srv_warp_instance_state_label',
    'srv_warp_instance_mtu',
    'srv_warp_instance_dns',
    'srv_warp_instance_registered',
    'srv_warp_instance_quarantine',
    'srv_warp_instance_stale',
    'srv_warp_instance_not_available',
    'srv_warp_instance_busy',
    'srv_warp_instance_yes',
    'srv_warp_instance_no',
    'srv_warp_in_use_alert',
    'srv_warp_in_use_err',
    'srv_warp_stage_source',
    'srv_warp_stage_handshake',
    # WARP profile import from another panel server (SNI-filtered hosts).
    'srv_warp_import',
    'srv_warp_import_title',
    'srv_warp_import_hint',
    'srv_warp_import_no_sources',
    'srv_warp_import_source',
    'srv_warp_import_source_protocol',
    'srv_warp_import_target',
    'srv_warp_import_action',
    # Source capability check: tells the user which server can donate a
    # profile and which one the provider blocks.
    'srv_warp_import_check',
    'srv_warp_import_checking',
    'srv_warp_import_no_usable',
    'srv_warp_import_copy_hint',
    'srv_warp_source_status_ready',
    'srv_warp_source_status_can_register',
    'srv_warp_source_status_blocked',
    'srv_warp_source_status_unreachable',
    'srv_warp_source_status_no_instance',
    'srv_warp_source_status_unknown',
    'srv_warp_err_api_unreachable',
    'srv_warp_err_registered',
    'srv_warp_err_protocol_unsupported',
    'srv_warp_err_source_required',
    'srv_warp_err_source_self',
    'srv_warp_err_source_not_found',
    'srv_warp_err_source_no_targets',
    'srv_warp_err_source_unreachable',
    'srv_warp_err_source_register',
    'srv_warp_err_handshake',
    'srv_warp_err_quota',
}

WARP_STAGE_KEYS = {
    'srv_warp_stage_start',
    'srv_warp_stage_download',
    'srv_warp_stage_register',
    'srv_warp_stage_profile',
    'srv_warp_stage_startsh',
    'srv_warp_stage_done',
    'srv_warp_stage_source',
    'srv_warp_stage_handshake',
}

INLINE_SCRIPT_RE = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.S)


def inline_js(html):
    """Same neutralisation as tests/test_template_js.py."""
    js = '\n'.join(INLINE_SCRIPT_RE.findall(html))
    js = re.sub(r'\{\{.*?\}\}', 'JINJA', js, flags=re.S)
    return re.sub(r'\{%.*?%\}', '', js, flags=re.S)


def seed_servers():
    return [{
        'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22,
        'username': 'root', 'password': 'x', 'private_key': '',
        'server_info': {}, 'uid': 'warp-uid',
        'warp': {'installed': False},
        'protocols': {
            'awg2': {
                'installed': True, 'port': '55424', 'awg_params': {},
                'base_protocol': 'awg2', 'instance': 1,
                'display_name': 'AmneziaWG 2.0',
                'container_name': 'amnezia-awg2',
            },
        },
    }]


class WarpTemplateRenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({'servers': seed_servers(), 'users': [{'id': 'admin-id', 'username': 'admin', 'password_hash': panel.hash_password('admin'), 'role': 'admin', 'enabled': True}],
                       'user_connections': []}, handle)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_server_page_contains_warp_card_and_marketplace_entry(self):
        with TestClient(panel.app) as client:
            login = client.post('/api/auth/login',
                                json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(login.status_code, 200, login.text)
            response = client.get('/server/0')
            self.assertEqual(response.status_code, 200)
            page = response.text

        markers = (
            'id="proto-warp"',
            "proto: 'warp'",
            "category: 'services'",
            "descKey: 'srv_warp_card_desc'",
            'id="warp-status"',
            'id="warp-install-btn"',
            'id="warp-uninstall-btn"',
            'id="warp-protocol-select"',
            'id="warp-link-btn"',
            'id="warp-unlink-btn"',
            'id="warpTosModal"',
            'function installWarp',
            'function uninstallWarp',
            'function loadWarpStatus',
            'function renderWarpCard',
            'function linkWarp',
            'function unlinkWarp',
            'function warpPostWithTos',
        )
        for marker in markers:
            self.assertIn(marker, page, f'server page lacks {marker}')
        # The WARP host app must never fall through to the protocol install
        # wizard (rknblock-style direct call instead).
        self.assertNotIn("openInstallModal('warp'", page)


class WarpImportUiGlobalsTests(unittest.TestCase):
    """Every handler the WARP markup calls must be declared on the same page."""

    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')

    def test_warp_handlers_are_declared(self):
        handlers = set(re.findall(r'on(?:click|change)="(\w+)\(', self.page))
        warp_handlers = {name for name in handlers if 'arp' in name}
        self.assertTrue(warp_handlers, 'no WARP handlers found in markup')
        for name in sorted(warp_handlers):
            self.assertIn('function %s' % name, self.page,
                          '%s is called by markup but not declared' % name)

    def test_the_source_check_is_wired_up(self):
        self.assertIn('id="warp-import-check-btn"', self.page)
        self.assertIn('function checkWarpImportSources', self.page)
        self.assertIn('function renderWarpImportSources', self.page)
        self.assertIn('function onWarpImportSourceChange', self.page)
        # A failed install must be able to offer the import directly.
        self.assertIn('id="installWarpCta"', self.page)
        self.assertIn("'srv_warp_register_api_unreachable'", self.page)
        # The old closure-based handler is gone: a dangling onchange callback
        # throws a ReferenceError the moment the select changes.
        self.assertNotIn('syncWarpImportForm', self.page)

    def test_import_uses_the_import_stage_map(self):
        # Scope to importWarp's body: installWarp legitimately renders the
        # 'warp' map a few lines below, and must not be matched here.
        match = re.search(r'async function importWarp\(\)(.*?)\n    async function ',
                          self.page, re.S)
        self.assertIsNotNone(match, 'importWarp body not found')
        body = match.group(1)
        self.assertIn("renderInstallOpProgress(res.operation_id, 'warp_import')",
                      body)
        self.assertNotIn("renderInstallOpProgress(res.operation_id, 'warp')",
                         body)

    def test_poller_prefers_the_flow_from_the_payload(self):
        match = re.search(
            r'async function pollInstallOp\(\)(.*?)\n    (?:async )?function ',
            self.page, re.S)
        self.assertIsNotNone(match, 'pollInstallOp body not found')
        self.assertIn('if (data.flow) installOp.flow = data.flow;',
                      match.group(1))

    def test_the_import_stage_map_declares_source_and_handshake(self):
        block = re.search(r'\n        warp_import: \{(.*?)\n        \}',
                          self.page, re.S)
        self.assertIsNotNone(block, 'warp_import stage map not found')
        for entry in ("source: 'srv_warp_stage_source'",
                      "handshake: 'srv_warp_stage_handshake'"):
            self.assertIn(entry, block.group(1))


class WarpStoreInstallTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')

    def test_warp_import_flow_is_handled_like_warp_everywhere(self):
        """The import flow must not fall through the generic WARP branches.

        A flow value the page does not recognise silently skips the terminal
        handling: the card is never refreshed, `warpBusy` stays true and the
        error code is printed raw instead of translated.
        """
        page = self.page
        # Shared progress endpoint.
        self.assertIn("installOp.flow === 'warp' || installOp.flow === 'warp_import'",
                      page)
        # Terminal handling (success and error) + busy reset.
        self.assertIn("flow === 'warp' || flow === 'warp_import'", page)
        # Stage translations for the import-only stages.
        self.assertIn("source: 'srv_warp_stage_source'", page)
        self.assertIn("handshake: 'srv_warp_stage_handshake'", page)
        # The modal title must be the WARP one, not the protocol picker.
        self.assertIn("isWarpFlow", page)

    def test_warp_card_is_not_forced_visible(self):
        self.assertNotIn("warpCard.classList.remove('installed-app-hidden')",
                         self.page)
        self.assertNotIn("warpCard.classList.add('installed-app-visible')",
                         self.page)
        self.assertIn('const warpInstalled = warpIsInstalled();', self.page)
        self.assertIn("warpCard.classList.toggle('installed-app-hidden', "
                      "!warpInstalled);", self.page)
        self.assertIn("warpCard.classList.toggle('installed-app-visible', "
                      "warpInstalled);", self.page)

    def test_warp_install_uses_the_shared_staged_progress(self):
        self.assertIn('const INSTALL_STAGE_TRANSLATIONS = {', self.page)
        self.assertIn("warp: {\n            start: 'srv_warp_stage_start'",
                      self.page)
        self.assertIn('renderInstallOpProgress(res.operation_id, \'warp\')',
                      self.page)
        self.assertIn("installOp.flow === 'warp'", self.page)
        self.assertIn("install/progress?operation_id=", self.page)

    def test_only_installed_warp_is_counted(self):
        self.assertIn('if (warpInstalled) installedCount++;', self.page)
        self.assertNotIn('It stays on screen even when', self.page)

    def test_marketplace_refuses_install_without_an_awg_instance(self):
        # WARP is not a host-level binary: on a server without an AmneziaWG
        # instance (an exit-only node) the marketplace must say so and must not
        # offer an install the backend would refuse.
        self.assertIn('const SERVER_PROTOCOL_KEYS =', self.page)
        self.assertIn('function warpHasTargetInstance()', self.page)
        self.assertIn(
            "const warpNoTarget = isWarp && !installed && "
            "!warpHasTargetInstance();", self.page)
        self.assertIn('warpNoTarget ? _(\'srv_warp_no_awg\')', self.page)
        self.assertIn("srv_warp_no_targets: 'srv_warp_err_no_awg'", self.page)

    def test_instance_row_shows_a_failed_repair(self):
        # A repair runs in the background; its outcome is only visible in the
        # instance line, so both the payload field and the condition matter.
        self.assertIn('item.repair_state', self.page)
        self.assertIn("repair.state === 'error'", self.page)


class WarpInstanceExitTemplateTests(unittest.TestCase):
    """Per-instance cloud button + WARP egress popup on every AWG instance."""

    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')

    def test_cloud_button_markup_is_present(self):
        self.assertIn('class="modal-backdrop" id="warpInstanceModal"', self.page)
        self.assertIn('id="warpInstanceToggle"', self.page)
        self.assertIn('onchange="onWarpInstanceToggle(this)"', self.page)
        self.assertIn('data-warp-proto="${escapeHtml(proto)}"', self.page)
        self.assertIn('openWarpInstanceModal(\'${proto}\')', self.page)

    def test_cloud_button_uses_the_warp_protocol_set(self):
        # WARP registry only supports awg/awg2/awg3; AWG_PROTOCOLS also lists
        # awg_legacy, where /warp/link would answer 409.
        start = self.page.index('const warpExitBtn =')
        block = self.page[start:self.page.index(';', start) + 1]
        self.assertIn("['awg', 'awg2', 'awg3'].includes(protoBase(proto))", block)
        self.assertNotIn('AWG_PROTOCOLS', block)

    def test_cloud_button_state_is_refreshed_on_every_render(self):
        self.assertIn('function applyWarpInstanceButtons()', self.page)
        # renderWarpCard and updateProtocolCard rebuild the control row, so
        # both must re-apply the button state.
        self.assertGreaterEqual(self.page.count('applyWarpInstanceButtons();'), 2)
        self.assertIn("function renderWarpCard() {\n        // Buttons live",
                      self.page)

    def test_modal_functions_are_declared_in_this_page(self):
        for name in ('openWarpInstanceModal', 'onWarpInstanceToggle',
                     'renderWarpInstanceModal', 'applyWarpInstanceButtons'):
            self.assertIn('function %s(' % name, self.page)

    def test_plugin_delete_guard_wiring(self):
        self.assertIn("srv_warp_in_use: 'srv_warp_in_use_err'", self.page)
        self.assertIn("alert(_('srv_warp_in_use_alert'))", self.page)


class WarpTranslationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.locales = {
            lang: json.loads((TRANSLATIONS / f'{lang}.json').read_text(encoding='utf-8'))
            for lang in LOCALES
        }

    def test_srv_warp_keys_have_identical_sets_in_every_locale(self):
        for lang, table in self.locales.items():
            found = {key for key in table if key.startswith('srv_warp_')}
            with self.subTest(lang=lang):
                self.assertEqual(found, SRV_WARP_KEYS)

    def test_srv_warp_keys_do_not_shadow_panel_warp_keys(self):
        for lang, table in self.locales.items():
            panel_warp = {key for key in table
                          if key.startswith('warp_') and not key.startswith('srv_warp_')}
            with self.subTest(lang=lang):
                self.assertEqual(panel_warp & SRV_WARP_KEYS, set())

    def test_warp_stage_keys_are_present_in_every_locale(self):
        for lang, table in self.locales.items():
            with self.subTest(lang=lang):
                self.assertEqual(WARP_STAGE_KEYS - set(table), set())

    def test_every_mapped_error_code_has_a_translation(self):
        """WARP_ERROR_KEYS values must resolve, or the UI prints the raw key.

        Ten of these were mapped in the page while the catalogue had no such
        entry, so the card showed `srv_warp_err_source_unreachable` instead of
        a sentence.
        """
        """A mapped value that is missing prints the raw key in the card."""
        page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        block = re.search(r'const WARP_ERROR_KEYS = \{(.*?)\};', page, re.S)
        self.assertIsNotNone(block, 'WARP_ERROR_KEYS not found')
        keys = set(re.findall(r":\s*'(\w+)'", block.group(1)))
        self.assertTrue(keys)

        for lang, table in self.locales.items():
            with self.subTest(lang=lang):
                self.assertEqual(sorted(keys - set(table)), [])

    def test_per_instance_error_codes_are_mapped(self):
        page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        block = re.search(r'const WARP_ERROR_KEYS = \{(.*?)\};', page, re.S)
        self.assertIsNotNone(block, 'WARP_ERROR_KEYS not found')
        self.assertIn("srv_warp_install_failed: 'srv_warp_err_install_failed'",
                      block.group(1))
        self.assertIn("srv_warp_repair_failed: 'srv_warp_err_repair_failed'",
                      block.group(1))


class ProjectCompileTests(unittest.TestCase):
    def test_python_modules_compile(self):
        for name in ('app.py', 'warp_service.py', 'warp_runtime.py'):
            with self.subTest(module=name):
                self.assertTrue(
                    compileall.compile_file(str(ROOT / name), quiet=1),
                    f'{name} does not compile',
                )


@unittest.skipUnless(shutil.which('node'), 'node is not installed')
class WarpTemplateJsSyntaxTests(unittest.TestCase):
    def test_server_template_inline_js_parses(self):
        html = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        js = inline_js(html)
        self.assertIn('function installWarp', js)
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False,
                                         encoding='utf-8') as handle:
            handle.write(js)
            path = handle.name
        try:
            result = subprocess.run(['node', '--check', path],
                                    capture_output=True, text=True)
        finally:
            os.unlink(path)
        self.assertEqual(result.returncode, 0,
                         f'server.html does not parse:\n{result.stderr}')


if __name__ == '__main__':
    unittest.main()
