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
        self.assertIn('panel_only=true', SHARED)
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
        self.assertIn('/clear?server_uid=', SHARED)
        self.assertIn('/delete?server_uid=', SHARED)

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


if __name__ == '__main__':
    unittest.main()
