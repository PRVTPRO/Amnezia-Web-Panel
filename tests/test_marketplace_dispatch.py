"""Execute the actual rendered marketplace button handlers, with no SSH/API."""
import json
import os
import re
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
    def test_rkn_card_reload_outage_recovery_and_request_races(self):
        from playwright.sync_api import sync_playwright
        source = (ROOT / 'templates/server.html').read_text(encoding='utf-8')
        functions = []
        for name in ('renderMarketplace', 'applyInstalledAppsVisibility', 'loadRknBlock',
                     'renderRknBlockCard', 'checkServer', 'installRknBlock', 'uninstallRknBlock'):
            match = re.search(r'    (?:async )?function ' + name + r'\([^)]*\) \{.*?\n    \}', source, re.S)
            self.assertIsNotNone(match, name)
            functions.append(match[0])
        html = '''<style>.installed-app-hidden{display:none}</style><div id="protocols-grid"><div class="protocol-card" id="proto-rknblock">
            <div id="rknblock-status"></div><div id="rknblock-info"><div id="rknblock-info-grid"></div></div>
            <div id="rknblock-actions"><button id="rknblock-install-btn"></button></div><div id="rknblock-installed-actions">
            <button id="rknblock-toggle-btn"></button><button id="rknblock-uninstall-btn"></button></div></div></div>
            <div id="marketplaceContent"></div><button id="checkBtn"></button><span id="checkBtnText"></span><span id="checkSpinner"></span>
            <div id="serverStatus"></div><div id="statusBadges"></div><select id="connProtoSelect"></select>
            <div id="installModalTitle"></div><div id="installForm"></div><div id="installDone"></div><div id="installProgress"></div>
            <div id="installLog"></div><div id="installProgressFill"></div>'''
        prelude = '''
const SERVER_ID=0, calls=[], pending=[];
let rknBlockStatus={installed:true,available:false,agent_state:'unknown',running:false,healthy:false}, rknBlockLoadId=0, rknBlockBusy=false;
let smartRouteStatus=null, currentProtocolStatus={}, installedAppsLoading=false;
const MARKETPLACE_APPS=[{proto:'rknblock',category:'security',title:'RKN Block',descKey:'description',icon:''}];
const MARKETPLACE_CATEGORIES=[{id:'security',titleKey:'security',icon:''}];
document.body.dataset.serverUid='fixture-node';
const _=key=>key, escapeHtml=value=>String(value), protoDomKey=value=>value, protoBase=value=>value.split('__')[0], protoInstance=()=>1;
const isMultiInstanceBase=()=>false, isAppInstalled=()=>false, orderedProtocolEntries=()=>[], baseInstalled=()=>false;
const applyCustomTitles=()=>{},renderSmartRouteCard=()=>{},showToast=()=>{},openModal=()=>{},closeModal=()=>{},hideConnectionsSection=()=>{};
const setInstalledAppsLoading=()=>{},updateStatusCounts=()=>{},loadSmartRouteStatus=async()=>null;
window.confirm=()=>true;
const apiCall=(url,method='GET')=>{calls.push({url,method});
 if(method==='POST')return Promise.resolve({connection:'ok',protocols:{}});
 return new Promise((resolve,reject)=>pending.push({resolve,reject}));};
'''
        healthy = dict(installed=True, available=True, server_uid='fixture-node', running=True, healthy=True,
                       agent_state='on', sets={'in4': 1, 'in6': 1, 'out4': 1, 'out6': 1})
        absent = dict(installed=False, available=True, server_uid='fixture-node', agent_state='unknown')
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}))
            except Exception as exc:
                self.skipTest(f'Chromium is not installed: {type(exc).__name__}')
            try:
                for width in (375, 1440):
                    with self.subTest(width=width):
                        page = browser.new_page(viewport={'width': width, 'height': 900})
                        page.set_content(html)
                        page.add_script_tag(content=prelude + '\n'.join(functions))
                        page.evaluate('applyInstalledAppsVisibility(); renderMarketplace()')
                        self.assertTrue(page.locator('#proto-rknblock').is_visible())
                        page.evaluate('checkServer()')
                        self.assertEqual(page.evaluate('pending.length'), 1)
                        self.assertIn('server_uid=fixture-node', page.evaluate('calls[0].url'))
                        page.evaluate('data => pending.shift().resolve(data)', healthy)
                        page.wait_for_function("document.getElementById('rknblock-status').textContent.includes('rknblock_state_on')")
                        page.evaluate('() => {loadRknBlock();}')
                        page.evaluate("pending.shift().reject(new Error('SSH down'))")
                        page.wait_for_function('rknBlockStatus.available === false')
                        self.assertTrue(page.locator('#proto-rknblock').is_visible())
                        self.assertTrue(page.locator('#marketplaceContent button').is_disabled())
                        self.assertIn('unreachable', page.locator('#rknblock-status').inner_text())
                        page.evaluate('() => {loadRknBlock(); loadRknBlock();}')
                        page.evaluate('data => pending[1].resolve(data)', healthy)
                        page.wait_for_function('rknBlockStatus.available === true')
                        page.evaluate('data => pending[0].resolve(data)', absent)
                        self.assertTrue(page.evaluate('rknBlockStatus.installed'))
                        page.evaluate('() => {pending.length=0; loadRknBlock();}')
                        page.evaluate('() => {uninstallRknBlock();}')
                        page.wait_for_function('pending.length===2')
                        page.evaluate('data => pending[1].resolve(data)', absent)
                        page.wait_for_function('rknBlockStatus.installed === false && rknBlockStatus.available === true')
                        page.evaluate('data => pending[0].resolve(data)', healthy)
                        self.assertFalse(page.locator('#proto-rknblock').is_visible())
                        page.evaluate('pending.length=0')
                        page.locator('#marketplaceContent button').click()
                        page.wait_for_function('pending.length===1')
                        page.evaluate('data => pending[0].resolve(data)', healthy)
                        page.wait_for_function('rknBlockStatus.installed === true && rknBlockStatus.available === true')
                        self.assertTrue(page.locator('#proto-rknblock').is_visible())
                        self.assertTrue(page.locator('#marketplaceContent button').is_disabled())
                        self.assertEqual(page.evaluate("calls.filter(c=>c.url.includes('/rknblock/install')).length"), 1)
                        page.close()
            finally:
                browser.close()

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
