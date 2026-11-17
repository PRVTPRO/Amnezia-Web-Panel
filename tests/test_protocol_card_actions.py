"""Behaviour guard for the protocol cards on the server page.

v1.8.12 shipped a merge that emptied the running-protocol ``else`` branch of
``updateProtocolCard()``: a running AmneziaWG instance kept the initial Install
markup and its Connections/Backup/Uninstall row never appeared (issue #367).
The result is still valid JavaScript, so ``node --check`` and every markup
assertion passed. The only way to catch it is to execute the real function,
which is what ``tests/js/protocol_card_actions.js`` does through minimal DOM
stubs.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / "templates" / "server.html"
HARNESS = ROOT / "tests" / "js" / "protocol_card_actions.js"
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
PLACEHOLDER_RE = re.compile(r"\{\{(.*?)\}\}", re.S)
TRANSLATION_RE = re.compile(r"""^_\(\s*['"](.+?)['"]\s*\)$""", re.S)


def _placeholder_value(expression):
    """Turn a Jinja placeholder inside the inline script into a JS literal.

    The script only needs to load; the values are junk on purpose so the card
    renderer runs against a page that is not tied to a real server.
    """
    expression = " ".join(expression.split()).replace(" | ", "|")
    translated = TRANSLATION_RE.match(expression)
    if translated:
        return json.dumps(translated.group(1))
    if expression == "server_id":
        return "1"
    if expression == "server.host":
        return json.dumps("127.0.0.1")
    if "ssh_cooldown_base" in expression or "peer_poll_interval" in expression:
        return "30"
    if "keys()" in expression:
        return "[]"
    if "custom_name" in expression:
        return "null"
    # Object keys rendered from a Jinja loop; keeps the literal a plain object.
    if expression.startswith("proto|"):
        return json.dumps("proto")
    if expression.endswith("|tojson"):
        # Objects the renderer iterates or indexes must not become null.
        if "protocol_names" in expression or "protocol_labels" in expression:
            return "{}"
        return "null"
    return "null"


def render_inline_js(html):
    """Inline scripts with the Jinja tags neutralised into harmless literals."""
    js = "\n".join(INLINE_SCRIPT_RE.findall(html))
    js = re.sub(r"\{%.*?%\}", "", js, flags=re.S)

    def replace(match):
        value = _placeholder_value(match.group(1))
        # A placeholder can sit inside a JS string literal ("{{ server.host }}");
        # there the bare text belongs, not a second pair of quotes.
        before = js[match.start() - 1] if match.start() else ""
        after = js[match.end()] if match.end() < len(js) else ""
        if before and before == after and before in "'\"" and value.startswith('"'):
            return json.loads(value)
        return value

    return PLACEHOLDER_RE.sub(replace, js)


class ProtocolCardActionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_running_instances_render_their_action_row(self):
        js = render_inline_js(SERVER_TEMPLATE.read_text(encoding="utf-8"))
        # If the neutralisation ever stops producing the renderer, the harness
        # would fail with a confusing message; say it here instead.
        self.assertIn("function updateProtocolCard", js)
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tmp:
            tmp.write(js)
            script_path = Path(tmp.name)
        try:
            result = subprocess.run(
                ["node", str(HARNESS), str(script_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=120,
            )
        finally:
            script_path.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, (result.stdout or "") + (result.stderr or ""))

    def test_header_actions_are_not_statically_disabled(self):
        """Marketplace/Management must not start disabled: v1.8.12 shipped the
        attributes without the code that removed them, so both controls were
        dead on every server page (issue #353, same merge as #367)."""
        html = SERVER_TEMPLATE.read_text(encoding="utf-8")
        for element_id in ("marketplaceBtn", "managementBtn"):
            match = re.search(r"<button[^>]*id=\"%s\"[^>]*>" % element_id, html)
            self.assertIsNotNone(match, f"{element_id} is missing from the header")
            # Match the attribute itself: aria-disabled/data-disabled are fine.
            self.assertIsNone(
                re.search(r"\sdisabled(?=[\s>=])", match.group(0)),
                f"{element_id} is shipped disabled",
            )


if __name__ == "__main__":
    unittest.main()
