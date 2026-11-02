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


if __name__ == "__main__":
    unittest.main()
