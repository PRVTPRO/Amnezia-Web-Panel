"""Regression guards for the server-detail page's inline JavaScript and modal markup."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / "templates" / "server.html"


class TestServerTemplateIntegrity(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'node is not installed')
    def test_rendered_inline_scripts_have_valid_javascript(self):
        """A JS parse error prevents checkServer() from clearing the loading state."""
        import app
        from starlette.testclient import TestClient
        import json as _json

        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(app, 'DATA_FILE', str(Path(tmp) / 'data.json')):
            # Seed an empty data file so startup migrations create the default admin.
            Path(app.DATA_FILE).write_text(_json.dumps({'servers': [], 'users': []}), encoding='utf-8')
            with TestClient(app.app) as client:
                login = client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "admin", "captcha": None},
                )
                self.assertEqual(login.status_code, 200, login.text)
                page = client.get("/server/0")
                self.assertEqual(page.status_code, 200, page.text)

        scripts = re.findall(r"<script(?:[^>]*)>(.*?)</script>", page.text, re.S)
        inline_js = "\n".join(scripts)
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as f:
            f.write(inline_js)
            script_path = Path(f.name)
        try:
            result = subprocess.run(
                ["node", "--check", str(script_path)],
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            script_path.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wgeasy_modal_is_closed_before_the_next_modal(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        import_button = source.index('id="wgeasyImportGoBtn"')
        rename_modal = source.index('id="renameProtoModal"')
        between = source[import_button:rename_modal]
        self.assertIn("</div>\n    </div>\n</div>", between)

    def test_smartroute_probe_settles_before_the_grid_is_revealed(self):
        """The host-level Smart Route probe must start together with /check and
        settle before updateStatusCounts() reveals the grid. A serial probe
        after the reveal makes the card pop in a round-trip after every other
        badge (the owner-reported flicker)."""
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        start = source.index("async function checkServer()")
        end = source.index("function updateStatusCounts", start)
        body = source[start:end]

        probe = body.index("const smartRouteProbe = loadSmartRouteStatus()")
        check = body.index("await apiCall(")
        reveal = body.index("updateStatusCounts(data.protocols")
        settled = body.index("smartRouteStatus = await smartRouteProbe")
        self.assertLess(probe, check)
        self.assertLess(settled, reveal)
        # A second settle in `finally` would block error recovery on a slow probe.
        self.assertNotIn("smartRouteStatus = await smartRouteProbe", body[reveal:])
        self.assertNotIn("await loadSmartRouteStatus()", body)

    def test_wgeasy_preview_function_restores_button_state(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        start = source.index("async function wgeasyPreview()")
        end = source.index("function renderWgEasyPreview", start)
        function = source[start:end]
        self.assertIn("catch (err)", function)
        self.assertIn("finally", function)
        self.assertIn("btn.disabled = false", function)
        self.assertIn("btn.textContent = oldText", function)

    def test_awg_plugin_button_sits_next_to_the_server_actions(self):
        """The entry point must live in the existing header action row."""
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        header = source.index('class="page-header__actions"')
        check_btn = source.index('id="checkBtn"', header)
        plugin_btn = source.index('id="awgPluginBtn"', header)
        self.assertLess(plugin_btn, check_btn)
        self.assertIn('onclick="openAwgPluginModal()"', source[plugin_btn:check_btn])
        self.assertIn('class="awg-plugin-dot"', source[plugin_btn:check_btn])

    def test_awg_plugin_modal_uses_the_shared_modal_shell(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        start = source.index('<div class="modal-backdrop" id="awgPluginModal">')
        end = source.index('<script>', start)
        block = source[start:end]
        self.assertIn('class="modal-backdrop"', block)
        self.assertIn('class="modal"', block)
        self.assertIn('class="modal-header"', block)
        self.assertIn('class="modal-title"', block)
        self.assertIn('class="modal-footer"', block)

    def test_awg_plugin_button_only_pulses_while_an_update_exists(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn('.awg-plugin-btn.is-update .awg-plugin-dot', source)
        self.assertIn('@keyframes awgPluginPulse', source)
        self.assertIn('prefers-reduced-motion: reduce', source)
        self.assertIn("btn.classList.remove('is-update')", source)
        self.assertIn("btn.classList.add('is-update')", source)

    def test_awg_plugin_log_is_polled_with_offset(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        start = source.index('async function pollAwgPluginUpdate')
        body = source[start:start + 3000]
        self.assertIn('/awg-plugin/update/', body)
        self.assertIn('?offset=', body)
        self.assertIn('data.next_offset', body)
        self.assertIn('setTimeout', body)

    def test_awg_plugin_progress_shows_stage_numbers(self):
        """A slow DKMS build must show "step N of M" and a moving percentage."""
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn('awg-progress-fill', source)
        self.assertIn('awgProgressShimmer', source)
        self.assertIn("labelsStep(op.step, op.total)", source)
        self.assertIn("replace('{step}', step || 0)", source)
        self.assertIn("replace('{total}', total || 10)", source)
        self.assertIn('prefers-reduced-motion', source)
        self.assertIn('setAwgProgress(component, data.step, data.total, data.percent', source)

    def test_awg_plugin_translations_exist_in_every_locale(self):
        import json as _json
        keys = [
            'awg_plugin_button', 'awg_plugin_button_update', 'awg_plugin_button_ok',
            'awg_plugin_title', 'awg_plugin_intro', 'awg_plugin_loading',
            'awg_plugin_kernel_module', 'awg_plugin_kernel_module_desc',
            'awg_plugin_userspace', 'awg_plugin_userspace_desc',
            'awg_plugin_installed', 'awg_plugin_available', 'awg_plugin_whats_new',
            'awg_plugin_update', 'awg_plugin_update_running', 'awg_plugin_update_success',
            'awg_plugin_update_failed', 'awg_plugin_kept_working',
            'awg_plugin_requires_confirmation', 'awg_plugin_manual_step',
            'awg_plugin_no_update', 'awg_plugin_check_failed', 'awg_plugin_log',
            'awg_plugin_rollback_failed', 'awg_plugin_unknown_version', 'awg_plugin_close',
            'awg_plugin_cancel', 'awg_plugin_cancelling', 'awg_plugin_cancelled',
            'awg_plugin_step',
        ]
        for lang in ('en', 'ru', 'fr', 'zh', 'fa'):
            data = _json.loads((ROOT / 'translations' / ('%s.json' % lang)).read_text(encoding='utf-8'))
            missing = [key for key in keys if key not in data]
            self.assertEqual(missing, [], '%s misses %s' % (lang, missing))

    def test_awg_plugin_template_uses_only_known_translation_keys(self):
        source = SERVER_TEMPLATE.read_text(encoding="utf-8")
        used = set(re.findall(r"awg_plugin_[a-z_]+", source))
        import json as _json
        data = _json.loads((ROOT / 'translations' / 'en.json').read_text(encoding='utf-8'))
        unknown = sorted(key for key in used if key not in data)
        self.assertEqual(unknown, [], 'template uses unknown keys: %s' % unknown)


if __name__ == "__main__":
    unittest.main()
