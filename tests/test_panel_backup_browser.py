"""Execute the actual backup button handler and browser download, no network."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from test_panel_backup import StateFixture


class BackupBrowserTests(StateFixture, unittest.TestCase):
    def test_download_post_nonce_busy_error_and_mobile_card(self):
        from playwright.sync_api import sync_playwright
        from fastapi.testclient import TestClient
        from itsdangerous import TimestampSigner
        from starlette.middleware.sessions import SessionMiddleware
        import app as panel
        root=Path(panel.__file__).parent
        strings=json.loads((root/'translations/en.json').read_text(encoding='utf-8'))
        admin={'id':'admin','role':'admin'}
        with patch.object(panel,'DATA_FILE',str(self.data)), patch.object(panel,'_check_admin',return_value=admin), patch.object(panel,'get_current_user',return_value=admin):
            response=TestClient(panel.app).get('/settings')
        self.assertEqual(response.status_code,200)
        html=response.text
        secret=next(m.kwargs['secret_key']for m in panel.app.user_middleware if m.cls is SessionMiddleware)
        nonce=json.loads(base64.b64decode(TimestampSigner(secret).unsign(response.cookies.get('session'))))['backup_csrf']
        scripts=[m[2]for m in re.findall(r'(<script([^>]*)>)([\s\S]*?)</script>',html)if'src='not in m[1]]
        handler=re.search(r'    async function downloadFullBackup\(\).*?(?=    async function handleRestore)',html,re.S)
        self.assertIsNotNone(handler)
        archive=self.archive().read_bytes()
        html=re.sub(r'<script\b.*?</script>','',html,flags=re.S)
        html=re.sub(r'<link[^>]+>','',html)
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True,**({'executable_path':os.environ['PANEL_BROWSER_EXECUTABLE']}if os.environ.get('PANEL_BROWSER_EXECUTABLE')else{}))
            try:
                for width in [375,768,1440]:
                    page=browser.new_page(viewport={'width':width,'height':1000});page.route('**/*',lambda route:route.abort())
                    errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                    page.set_content(html);page.add_style_tag(content=(root/'static/css/style.css').read_text(encoding='utf-8'))
                    page.evaluate('(scripts)=>scripts.forEach(script=>new Function(script))',scripts)
                    page.add_script_tag(content='const messages='+json.dumps(strings)+';const _=k=>messages[k]||k;const toasts=[];const showToast=(message)=>toasts.push(message);'+
                        'const payload='+json.dumps(base64.b64encode(archive).decode())+';let requests=[];let finishFetch;let fail=false;'+
                        "window.fetch=(url,options)=>{requests.push({url,...options});return new Promise(resolve=>{finishFetch=()=>resolve(fail?new Response('{}',{status:503}):new Response(Uint8Array.from(atob(payload),c=>c.charCodeAt(0)),{headers:{'content-type':'application/zip'}}));});};"+handler[0])
                    page.locator('#downloadFullBackup').click()
                    self.assertTrue(page.locator('#downloadFullBackup').is_disabled())
                    page.evaluate('document.getElementById("downloadFullBackup").click()')
                    self.assertEqual(page.evaluate('requests.length'),1)
                    request=page.evaluate('requests[0]');self.assertEqual(request['method'],'POST');self.assertEqual(request['headers']['X-Backup-CSRF'],nonce)
                    with page.expect_download()as event:page.evaluate('finishFetch()')
                    self.assertEqual(hashlib.sha256(Path(event.value.path()).read_bytes()).digest(),hashlib.sha256(archive).digest())
                    self.assertFalse(page.locator('#downloadFullBackup').is_disabled())
                    self.assertEqual(page.locator('#downloadFullBackup').count(),1)
                    self.assertTrue(page.locator('#settings-backup').evaluate('(node)=>node.scrollWidth<=node.clientWidth+1'))
                    page.evaluate('fail=true');page.locator('#downloadFullBackup').click();page.evaluate('finishFetch()')
                    page.wait_for_function('!document.getElementById("downloadFullBackup").disabled')
                    self.assertIn(strings['full_backup_busy'],page.evaluate('toasts'))
                    self.assertEqual(errors,[]);page.close()
            finally:browser.close()
