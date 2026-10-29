"""Execute the actual rendered marketplace button handlers, with no SSH/API."""
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def marketplace_script(installed=False, proto="rknblock", multi=False):
    source = (ROOT / "templates/server.html").read_text(encoding="utf-8")
    start = source.index("    function marketplaceAppStatus(")
    end = source.index("    function openMarketplaceModal(", start)
    return """
const MARKETPLACE_CATEGORIES = [{id: 'vpn', icon: '', titleKey: 'vpn'}];
const MARKETPLACE_APPS = [%s];
const rknBlockStatus = %s;
const calls = [];
function _(key) { return key; }
function baseInstalled(proto) { return proto !== 'rknblock' && %s; }
function isMultiInstanceBase() { return %s; }
function closeModal(name) { calls.push(['close', name]); }
function installRknBlock() { calls.push(['rknblock']); }
function installFromMarketplace(...args) { calls.push(['protocol', ...args]); }
""" % (json.dumps(dict(proto=proto, category="vpn", title=proto, icon="", descKey="description")),
       json.dumps(dict(installed=installed)), json.dumps(installed), json.dumps(multi)) + source[start:end]


class ButtonParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buttons = []
        self.badges = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "button":
            self.buttons.append(attrs)
        if tag == "span" and "badge" in attrs.get("class", ""):
            self.badges.append(attrs["class"])


@unittest.skipUnless(shutil.which("node"), "node is required")
class MarketplaceDispatchTests(unittest.TestCase):
    def render(self, **kwargs):
        script = marketplace_script(**kwargs)
        script += """
const target = {innerHTML: ''};
const document = {getElementById: () => target};
renderMarketplace();
console.log(JSON.stringify({html: target.innerHTML}));
"""
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
        html = json.loads(result.stdout)["html"]
        parser = ButtonParser()
        parser.feed(html)
        self.assertEqual(len(parser.buttons), 1)
        return parser, script.split("const target =", 1)[0]

    def click(self, parser, script):
        # Execute the rendered attribute, rather than looking for a function name.
        button = parser.buttons[0]
        handler = button.get("onclick", "") if "disabled" not in button else ""
        result = subprocess.run(["node", "-e", script + "\n" + handler +
                                 ";console.log(JSON.stringify(calls));"],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_rkn_install_uses_only_its_app_handler(self):
        parser, script = self.render()
        self.assertEqual(self.click(parser, script), [["close", "marketplaceModal"], ["rknblock"]])
        self.assertIn("badge badge-warn", parser.badges)

    def test_installed_rkn_is_disabled_and_has_installed_status(self):
        parser, script = self.render(installed=True)
        self.assertEqual(self.click(parser, script), [])
        self.assertIn("disabled", parser.buttons[0])
        self.assertIn("badge badge-success", parser.badges)

    def test_regular_protocol_routes_are_unchanged(self):
        for installed, multi in [(False, False), (True, False), (True, True)]:
            with self.subTest(installed=installed, multi=multi):
                parser, script = self.render(installed=installed, proto="awg", multi=multi)
                expected = [] if installed and not multi else [["protocol", "awg", installed and multi]]
                self.assertEqual(self.click(parser, script), expected)


class MarketplaceBrowserTests(unittest.TestCase):
    def test_actual_dom_clicks_and_disabled_state(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is not installed")
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({"executable_path": os.environ["PANEL_BROWSER_EXECUTABLE"]} if os.environ.get("PANEL_BROWSER_EXECUTABLE") else {}))
            except Exception as exc:
                self.skipTest(f"Chromium is not installed: {type(exc).__name__}")
            try:
                for proto, installed, multi in [("rknblock", False, False), ("rknblock", True, False), ("awg", False, False), ("awg", True, False), ("awg", True, True)]:
                    with self.subTest(proto=proto, installed=installed, multi=multi):
                        page = browser.new_page()
                        page.set_content('<div id="marketplaceContent"></div>')
                        page.add_script_tag(content=marketplace_script(installed, proto, multi))
                        page.evaluate("renderMarketplace()")
                        button = page.locator("button")
                        disabled = installed and not multi
                        self.assertEqual(button.is_disabled(), disabled)
                        # Native click() is ignored on a disabled button.
                        button.evaluate("button => button.click()")
                        expected = [] if disabled else ([["close", "marketplaceModal"], ["rknblock"]] if proto == "rknblock" else [["protocol", proto, installed and multi]])
                        self.assertEqual(page.evaluate("calls"), expected)
                        self.assertEqual(page.locator(".badge").inner_text(), "installed" if installed else "not_installed")
                        page.close()
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
