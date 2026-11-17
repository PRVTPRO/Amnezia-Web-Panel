"""Dashboard server cards expose the safe management workflow."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / 'templates' / 'index.html').read_text(encoding='utf-8')
DETAIL = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
MODAL = (ROOT / 'templates' / '_server_management_modal.html').read_text(encoding='utf-8') if (ROOT / 'templates' / '_server_management_modal.html').exists() else ''
SHARED = (ROOT / 'static' / 'js' / 'server-management.js').read_text(encoding='utf-8') if (ROOT / 'static' / 'js' / 'server-management.js').exists() else ''


class DashboardServerManagementTests(unittest.TestCase):
    def test_server_card_uses_secondary_svg_management_button_instead_of_direct_delete(self):
        actions = INDEX.split('<div class="server-actions">', 1)[1].split('</div>', 1)[0]
        self.assertIn('class="btn btn-secondary btn-sm btn-icon"', actions)
        self.assertIn('onclick="openServerManagement(this)"', actions)
        self.assertIn('title="{{ _(\'management\') }}"', actions)
        self.assertIn('class="btn-icon-svg"', actions)
        self.assertIn('<circle cx="12" cy="12" r="3"', actions)
        self.assertNotIn('⚙️', actions)
        self.assertNotIn('onclick="deleteServer(', actions)
        self.assertNotIn('btn-danger', actions)

    def test_both_pages_include_one_shared_management_modal(self):
        include = "{% include '_server_management_modal.html' %}"
        self.assertIn(include, INDEX)
        self.assertIn(include, DETAIL)
        self.assertIn('id="serverManagementModal"', MODAL)
        self.assertIn("{{ _('server_management') }}", MODAL)
        self.assertIn('id="serverManagementContent"', MODAL)

    def test_management_modal_rendering_and_actions_live_in_one_shared_script(self):
        self.assertIn('window.ServerManagement', SHARED)
        self.assertIn("_('check_server_services')", SHARED)
        self.assertIn("_('remove_server')", SHARED)
        self.assertNotIn('function renderServerManagementModal', INDEX)
        self.assertNotIn('function renderManagementModal', DETAIL)
        self.assertNotIn('async function removeDashboardServer', INDEX)
        self.assertNotIn('async function removeServer', DETAIL)

    def test_remove_action_supports_accounting_archive_retry(self):
        self.assertIn("extraParam(url, 'panel_only', 'true')", SHARED)
        self.assertNotIn('archive_blocking=true', SHARED)
        self.assertNotIn('traffic_finalization_required', SHARED)

    def test_management_requests_use_selected_server_identity(self):
        self.assertIn('ServerManagement.open({', INDEX)
        self.assertIn('serverId: card.dataset.idx', INDEX)
        self.assertIn('serverUid: card.dataset.uid', INDEX)
        self.assertIn('card.dataset.sshCooldown = value', INDEX)
        self.assertIn('card.dataset.peerPoll = value', INDEX)
        self.assertIn('ServerManagement.open({', DETAIL)
        self.assertIn('onCheck: () => checkServer(true)', DETAIL)
        self.assertNotIn('id="checkBtn"', DETAIL)
        self.assertIn('serverId: SERVER_ID', DETAIL)
        self.assertIn('/reboot', SHARED)
        self.assertIn('/clear', SHARED)
        self.assertIn('/delete', SHARED)
        # Идентичность сервера передаётся только когда uid известен: пустой
        # ?server_uid= бэкенд считает подменой сервера (409).
        self.assertIn('withServerUid(', SHARED)
        self.assertIn('server_uid=', SHARED)

    def test_rendered_dashboard_script_has_valid_javascript(self):
        import json
        import subprocess
        import tempfile
        from jinja2 import Environment, FileSystemLoader

        strings = json.loads((ROOT / 'translations' / 'en.json').read_text(encoding='utf-8'))
        html = Environment(loader=FileSystemLoader(str(ROOT / 'templates')), autoescape=True).get_template('index.html').render(
            request=None, lang='en', static_v='synthetic',
            site_settings={'title': 'Synthetic', 'subtitle': '', 'logo': ''},
            current_user={'username': 'admin', 'role': 'admin'},
            _=lambda key: strings.get(key, key), translations_json=json.dumps(strings),
            login_translations_json='{}', all_translations_json='{}', captcha_settings={},
            telegram_settings={}, bot_running=False,
            servers=[{'uid': 'node-a', 'name': 'Node', 'host': '192.0.2.1', 'ssh_port': 22,
                      'username': 'root', 'private_key': '', 'protocols': {}}],
            connections=[], stats={}, protocol_short_name=lambda *args: 'AWG',
        )
        scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', html, re.S)
        dashboard = next(script for script in scripts if 'openServerManagement' in script)
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as handle:
            handle.write(dashboard)
            script_path = handle.name
        try:
            result = subprocess.run(['node', '--check', script_path], capture_output=True, text=True)
        finally:
            Path(script_path).unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_script_has_valid_javascript(self):
        import subprocess
        result = subprocess.run(['node', '--check', str(ROOT / 'static' / 'js' / 'server-management.js')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    # --- Правило проекта: вёрстка без inline-стилей, иконки вместо эмодзи ---

    def test_modal_markup_has_no_inline_styles(self):
        self.assertNotIn('style="', MODAL)
        self.assertNotIn('style="', SHARED)
        # Записи вида state.style.color = ... тоже считаются inline-стилями.
        self.assertNotIn('.style.', SHARED)

    def test_modal_uses_icon_registry_instead_of_emoji(self):
        self.assertIn("ui_icon('settings'", MODAL)
        self.assertIn('window.SM_ICONS', MODAL)
        for emoji in ('🔄', '🔁', '🧹', '🛡', '💾', '⚙'):
            self.assertNotIn(emoji, MODAL, emoji)
            self.assertNotIn(emoji, SHARED, emoji)
        for name in ('refresh', 'power', 'eraser', 'trash', 'save', 'shield'):
            self.assertIn("icon('%s'" % name, SHARED)

    def test_torrent_guard_toggle_is_wired_on_open(self):
        # Регресс сборки на SERVERA: без этого вызова чекбокс остаётся disabled
        # навсегда и не нажимается ни при каком состоянии сервера.
        self.assertIn('refreshTorrentGuard();', SHARED)
        self.assertIn("data-server-management-action=\"check\"", SHARED)

    def test_layout_classes_exist_in_stylesheet(self):
        css = (ROOT / 'static' / 'css' / 'style.css').read_text(encoding='utf-8')
        for name in ('.sm-stack', '.sm-action', '.sm-section', '.sm-row',
                     '.sm-toggle', '.sm-state.is-error', '.sm-hint'):
            self.assertIn(name, css, name)

    def test_shared_script_behaviour_harness(self):
        import subprocess
        harness = ROOT / 'tests' / 'js' / 'server_management_modal.js'
        self.assertTrue(harness.exists())
        result = subprocess.run(['node', str(harness)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_modal_endpoints_are_registered(self):
        # Каждое действие модалки обязано иметь живой маршрут: обработчики в
        # static/js/server-management.js дергают именно эти пути.
        import app as panel
        paths = {getattr(route, 'path', '') for route in panel.app.routes}
        for path in ('/api/servers/{server_id}/check',
                     '/api/servers/{server_id}/reboot',
                     '/api/servers/{server_id}/clear',
                     '/api/servers/{server_id}/delete',
                     '/api/servers/{server_id}/ssh_cooldown',
                     '/api/servers/{server_id}/peer_poll_interval',
                     '/api/servers/{server_id}/torrent_guard'):
            self.assertIn(path, paths, path)

    def test_modal_template_renders_without_inline_styles(self):
        import json
        from jinja2 import Environment, FileSystemLoader

        strings = json.loads((ROOT / 'translations' / 'ru.json').read_text(encoding='utf-8'))
        env = Environment(loader=FileSystemLoader(str(ROOT / 'templates')), autoescape=True)
        html = env.get_template('_server_management_modal.html').render(
            static_v='synthetic', _=lambda key: strings.get(key, key),
        )
        self.assertIn('id="serverManagementModal"', html)
        self.assertIn('id="serverManagementContent"', html)
        self.assertIn('window.SM_ICONS', html)
        self.assertIn('<svg class="ui-icon"', html)
        self.assertIn('/static/js/server-management.js?v=synthetic', html)
        self.assertNotIn('style="', html)
        for emoji in ('🔄', '🔁', '🧹', '🛡', '💾', '⚙'):
            self.assertNotIn(emoji, html, emoji)


if __name__ == '__main__':
    unittest.main()
