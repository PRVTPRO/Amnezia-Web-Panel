"""Render/source checks for the Cheburcheck UI (T6, T9, T10, T12)."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient


ROOT = Path(__file__).resolve().parent.parent
SETTINGS_TEMPLATE = ROOT / 'templates' / 'settings.html'
SERVER_TEMPLATE = ROOT / 'templates' / 'server.html'
INDEX_TEMPLATE = ROOT / 'templates' / 'index.html'


def _seed(tmp, settings, servers=None):
    import app
    servers = servers or [
        {'name': 'FINN', 'host': '95.81.126.149', 'ssh_port': 54645, 'uid': 'u1',
         'protocols': {'awg': {'public_host': 'vpn.example.com'}}},
        {'name': 'EURO', 'host': '46.30.41.17', 'ssh_port': 1803, 'uid': 'u2',
         'protocols': {'xray': {}}},
    ]
    df = Path(tmp) / 'data.json'
    df.write_text(json.dumps({
        'servers': servers,
        'users': [{'id': 'a', 'username': 'admin',
                   'password_hash': app.hash_password('admin'),
                   'role': 'admin', 'enabled': True}],
        'settings': {'cheburcheck': settings},
    }), encoding='utf-8')
    return df


class CheburcheckRenderTests(unittest.TestCase):
    enabled = True

    def setUp(self):
        import app
        self.app = app
        self._tmp = tempfile.TemporaryDirectory()
        self.df = _seed(self._tmp.name, {
            'enabled': self.enabled, 'interval_hours': 2,
            'servers': {'u1': True, 'u2': False},
            'targets': {},
        })
        self._patch = patch.object(self.app, 'DATA_FILE', str(self.df))
        self._patch.start()
        with TestClient(self.app.app) as client:
            self.client = client
            r = client.post('/api/auth/login',
                            json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(r.status_code, 200, r.text)

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    # --- T6 ---------------------------------------------------------------
    def test_pages_render_without_500(self):
        for url in ('/', '/settings', '/server/0'):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, (url, r.text[:200]))

    def test_settings_block_has_one_closing_script_tag(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        start = text.index('window.CHEBURCHECK_TARGETS')
        segment = text[start:text.index('{% endblock %}', start)]
        self.assertEqual(segment.count('</script>'), 1)

    # --- T9 (master on) ---------------------------------------------------
    def test_settings_list_contains_targets(self):
        html = self.client.get('/settings').text
        self.assertIn('cb_targets_list', html)
        self.assertIn('window.CHEBURCHECK_TARGETS', html)
        self.assertIn('vpn.example.com', html)
        # No protocol/container names are mentioned anywhere in the block.
        self.assertNotIn('protocol_fallback', html)
        self.assertNotIn('cheburcheck_ssh_fallback_warning', html)
        self.assertIn('cheburcheck_override_toggle', html)
        self.assertIn('cb_master_off', html)
        # master on -> the off notice is hidden, the target list is visible
        off_line = [line for line in html.splitlines() if 'id="cb_master_off"' in line][0]
        self.assertIn('display:none', off_line)
        block_line = [line for line in html.splitlines()
                      if 'id="cb_targets_block"' in line][0]
        self.assertNotIn('display:none', block_line)

    def test_server_modal_renders_disclaimer(self):
        self.client.cookies.set('lang', 'ru')
        html = self.client.get('/server/0').text
        self.assertIn('cheburcheckModal', html)
        self.assertIn('VPN-подключения', html)

    # --- T10 (source level) -----------------------------------------------
    def test_badge_uses_probe_field_and_no_dead_anchor(self):
        text = INDEX_TEMPLATE.read_text(encoding='utf-8')
        self.assertNotIn('#cheburcheck-card', text)
        self.assertIn('probe.blocking_regions', text)

    def test_staleness_is_timestamp_based(self):
        text = SERVER_TEMPLATE.read_text(encoding='utf-8')
        start = text.index('async function loadCheburcheck')
        end = text.index('async function runCheburcheckNow', start)
        segment = text[start:end]
        self.assertNotIn("indexOf(_('cheburcheck_days_ago'))", segment)
        self.assertIn('new Date(checkedAt)', segment)
        self.assertIn('isNaN', segment)

    def test_target_list_is_rerendered_on_changes(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        self.assertIn("cb.addEventListener('change'", text)
        self.assertIn("toggle.addEventListener('change'", text)
        self.assertIn("inp.addEventListener('input', renderCheburcheckTargets)", text)
        self.assertIn('renderCheburcheckTargets();', text)

    def test_list_skips_servers_without_targets(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('if (!addresses.length) return;', text)
        self.assertIn('cbRowAddresses', text)

    def test_override_input_appears_only_after_its_checkbox(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('class="cb-override"', text)
        self.assertIn('cb-override-wrap', text)
        self.assertIn('cbSyncRow', text)
        self.assertIn("input.style.display = (serverOn && toggle.checked)", text)

    def test_long_target_lists_collapse_into_spoiler(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        self.assertIn("document.createElement('details')", text)
        self.assertIn("document.createElement('summary')", text)
        self.assertIn('rows.length > 3', text)
        self.assertIn('cheburcheck_targets_show', text)


class CheburcheckRenderDisabledTests(CheburcheckRenderTests):
    enabled = False

    def test_settings_list_contains_targets(self):
        html = self.client.get('/settings').text
        # Both states are in the DOM; the master-off notice is the visible one.
        self.assertIn('cb_targets_list', html)
        self.assertIn('window.CHEBURCHECK_TARGETS', html)
        self.assertIn('cb_master_off', html)

    def test_server_modal_renders_disclaimer(self):
        html = self.client.get('/server/0').text
        self.assertNotIn('id="cheburcheckModal"', html)

    def test_settings_block_has_one_closing_script_tag(self):
        text = SETTINGS_TEMPLATE.read_text(encoding='utf-8')
        start = text.index('window.CHEBURCHECK_TARGETS')
        segment = text[start:text.index('{% endblock %}', start)]
        self.assertEqual(segment.count('</script>'), 1)

    def test_settings_show_master_off_and_hide_list(self):
        html = self.client.get('/settings').text
        off_line = [line for line in html.splitlines() if 'id="cb_master_off"' in line][0]
        self.assertNotIn('display:none', off_line)
        block_line = [line for line in html.splitlines()
                      if 'id="cb_targets_block"' in line][0]
        self.assertIn('display:none', block_line)


class TranslationValuesTests(unittest.TestCase):
    def _load(self, locale):
        path = ROOT / 'translations' / f'{locale}.json'
        return json.loads(path.read_text(encoding='utf-8'))

    def test_ru_and_en_texts(self):
        ru = self._load('ru')
        en = self._load('en')
        self.assertIn('время серверное', ru['cheburcheck_quiet_hint'].lower())
        self.assertIn('server time', en['cheburcheck_quiet_hint'].lower())
        self.assertEqual(ru['cheburcheck_clean'], 'Ограничений не обнаружено')
        self.assertEqual(en['cheburcheck_clean'], 'No restrictions detected')
        self.assertIn('VPN-подключения', ru['cheburcheck_hint'])
        self.assertIn('VPN connection', en['cheburcheck_hint'])
        self.assertIn('{count}', ru['cheburcheck_targets_show'])
        self.assertEqual(ru['cheburcheck_override_toggle'], 'доп. адреса')
        self.assertIn('{count}', en['cheburcheck_targets_show'])
        self.assertEqual(ru['cheburcheck_override_toggle'], 'доп. адреса')