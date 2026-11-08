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
            json.dump({'servers': seed_servers(), 'users': [],
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
