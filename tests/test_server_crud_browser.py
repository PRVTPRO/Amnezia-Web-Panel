"""Drive the actual dashboard handlers against a synthetic DOM, no API/SSH."""
import os
from pathlib import Path
import re
import unittest


class InventoryBrowserTests(unittest.TestCase):
    def test_config_editor_binds_uid_and_preserves_input_on_error_at_mobile_width(self):
        from playwright.sync_api import sync_playwright
        source = (Path(__file__).resolve().parents[1] / 'templates/server.html').read_text(encoding='utf-8')
        functions = []
        for name in ('showServerConfig', 'saveServerConfig'):
            match = re.search(r'    async function ' + name + r'\([^)]*\) \{.*?\n    \}', source, re.S)
            self.assertIsNotNone(match)
            functions.append(match[0])
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}))
            except Exception as exc:
                self.skipTest(f'Chromium is not installed: {type(exc).__name__}')
            try:
                for width in (375, 1440):
                    page = browser.new_page(viewport={'width': width, 'height': 800})
                    page.set_content('<div id="serverConfigModalTitle"></div><input id="serverConfigProto"><textarea id="serverConfigText"></textarea><button id="saveServerConfigBtn">Save</button>')
                    page.add_script_tag(content='''
    document.body.dataset.serverUid='fixture-node';
    const SERVER_ID=0,calls=[],toasts=[];let fail=false,serverConfigFilename='';
    const _=v=>v,getProtoTitle=v=>v,openModal=()=>{},closeModal=()=>{},refreshConfigEditor=()=>{},editorModeFor=()=>'';
    const showToast=(...args)=>toasts.push(args),setEditorValue=(id,text)=>document.getElementById(id).value=text,getEditorValue=id=>document.getElementById(id).value;
    const apiCall=async(url,method,body)=>{calls.push({url,method,body});if(fail)throw new Error('counter restart blocked');return {config:'synthetic-config',unchanged:true};};
    ''' + '\n'.join(functions))
                    page.evaluate("showServerConfig('awg3')")
                    page.evaluate('saveServerConfig()')
                    self.assertEqual(page.evaluate('calls.map(c=>c.url)'), [
                        '/api/servers/0/server_config?server_uid=fixture-node',
                        '/api/servers/0/server_config/save?server_uid=fixture-node'])
                    page.evaluate('fail=true')
                    page.evaluate('saveServerConfig()')
                    self.assertEqual(page.locator('#serverConfigText').input_value(), 'synthetic-config')
                    self.assertFalse(page.locator('#saveServerConfigBtn').is_disabled())
                    self.assertIn('counter restart blocked', page.evaluate('toasts.at(-1)[0]'))
                    page.close()
            finally:
                browser.close()

    def test_crud_controls_send_the_displayed_uids(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest('Playwright is not installed')
        source = (Path(__file__).resolve().parents[1] / 'templates/index.html').read_text(encoding='utf-8')
        functions = []
        for name in ['deleteServer', 'submitEditServer', 'persistServerOrder']:
            match = re.search(r'    async function ' + name + r'\([^)]*\) \{.*?\n    \}', source, re.S)
            self.assertIsNotNone(match)
            functions.append(match[0])
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, **({'executable_path': os.environ['PANEL_BROWSER_EXECUTABLE']} if os.environ.get('PANEL_BROWSER_EXECUTABLE') else {}))
            except Exception as exc:
                self.skipTest(f'Chromium is not installed: {type(exc).__name__}')
            try:
                page = browser.new_page()
                page.set_content('''<div id="grid"><div class="server-card" id="server-1" data-idx="1" data-uid="b"></div><div class="server-card" id="server-0" data-idx="0" data-uid="a"></div></div>
                    <form id="editServerForm" data-server-uid="a"></form>
                    <input id="editServerIdx" value="0"><input id="editServerName" value="renamed"><input id="editServerHost" value="a.example.test"><input id="editServerPort" value="22"><input id="editServerUser" value="fixture"><input id="editServerPassword"><input id="editServerKey"><input id="editServerSelfService" type="checkbox">
                    <button id="editServerBtn"></button><span id="editServerBtnText"></span><span id="editServerSpinner"></span>''')
                page.add_script_tag(content="""
const calls = [];
const apiCall = async (url, method, body) => {calls.push({url, method, body}); return {};};
const _ = key => key;
const showToast = () => {};
window.confirm = () => true;
window.setTimeout = () => 0;
""" + '\n'.join(functions))
                page.evaluate('deleteServer(0)')
                page.evaluate('submitEditServer({preventDefault(){}})')
                page.evaluate("persistServerOrder(document.getElementById('grid'))")
                calls = page.evaluate('calls')
                self.assertEqual(calls[0]['url'], '/api/servers/0/delete?server_uid=a')
                self.assertEqual(calls[1]['url'], '/api/servers/0/edit?server_uid=a')
                self.assertEqual(calls[2]['body'], {'order': [1, 0], 'server_uids': ['b', 'a']})
            finally:
                browser.close()
