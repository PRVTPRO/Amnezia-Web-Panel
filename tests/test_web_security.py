"""Regression tests for small web security fixes; never touch real panel data."""
import asyncio
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile

import app as panel


class LanguageSecurityTests(unittest.TestCase):
    def test_referer_cannot_redirect_off_site(self):
        client = TestClient(panel.app)
        for referer in ('https://evil.example/phishing', '//evil.example/',
                        '/\\evil.example/', 'javascript:alert(1)'):
            with self.subTest(referer=referer):
                response = client.get('/set_lang/ru', headers={'referer': referer},
                                      follow_redirects=False)
                self.assertEqual(response.status_code, 307)
                self.assertEqual(response.headers['location'], '/')

    def test_local_referer_keeps_path_and_query(self):
        client = TestClient(panel.app)
        for referer in ('/my?tab=configs', 'http://testserver/my?tab=configs'):
            response = client.get('/set_lang/ru', headers={'referer': referer},
                                  follow_redirects=False)
            self.assertEqual(response.headers['location'], '/my?tab=configs')

    def test_language_cookie_is_httponly_and_secure_on_https_only(self):
        for scheme in ('http', 'https'):
            with self.subTest(scheme=scheme):
                response = TestClient(panel.app, base_url=f'{scheme}://testserver').get(
                    '/set_lang/ru', follow_redirects=False)
                cookie = response.headers['set-cookie'].lower()
                self.assertIn('httponly', cookie)
                self.assertIn('samesite=lax', cookie)
                self.assertEqual('secure' in cookie, scheme == 'https')

    def test_unknown_language_is_rejected(self):
        response = TestClient(panel.app).get('/set_lang/not-a-language', follow_redirects=False)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('set-cookie', response.headers)


class BackupUploadSecurityTests(unittest.TestCase):
    def restore(self, content, allowed=True):
        upload = UploadFile(file=io.BytesIO(content), filename='data.json')
        with patch.object(panel, '_check_admin', return_value=allowed), \
             patch.object(panel, 'save_data') as save:
            response = asyncio.run(panel.api_backup_restore(None, upload))
        return response, save

    def test_non_admin_cannot_restore(self):
        response, save = self.restore(b'{}', allowed=False)
        self.assertEqual(response.status_code, 403)
        save.assert_not_called()

    def test_non_object_json_is_rejected(self):
        for content in (b'null', b'42', b'[]', b'"servers users"'):
            with self.subTest(content=content):
                response, save = self.restore(content)
                self.assertEqual(response.status_code, 400)
                save.assert_not_called()

    def test_invalid_utf8_is_rejected(self):
        response, save = self.restore(b'\xff')
        self.assertEqual(response.status_code, 400)
        save.assert_not_called()

    def test_large_backup_is_rejected_without_unbounded_read(self):
        class BoundedUpload:
            async def read(self, size=-1):
                self.requested = size
                if size < 0:
                    raise AssertionError('Unbounded backup read')
                return b' ' * size
        upload = BoundedUpload()
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'save_data') as save:
            response = asyncio.run(panel.api_backup_restore(None, upload))
        self.assertEqual(response.status_code, 413)
        self.assertLessEqual(upload.requested, 32 * 1024 * 1024 + 1)
        save.assert_not_called()

    def test_valid_backup_still_restores(self):
        # Recovery now snapshots/audits and atomically writes the real file.
        # Assert persisted state, not a mock call to the old writer.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.json'
            before = b'{"servers": [], "users": [], "marker": "before"}'
            path.write_bytes(before)
            upload = UploadFile(file=io.BytesIO(b'{"servers":[],"users":[]}'), filename='data.json')
            with patch.object(panel, 'DATA_FILE', str(path)), \
                 patch.object(panel, '_check_admin', return_value=True), \
                 patch.object(panel, 'get_current_user', return_value={'id': 'admin'}):
                response = asyncio.run(panel.api_backup_restore(None, upload))
            self.assertEqual(response, {'status': 'success'})
            restored = json.loads(path.read_bytes())
            self.assertEqual(restored['users'], [])
            self.assertNotIn('marker', restored)
            records = list(Path(str(path) + '.recovery').glob('*.json'))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_bytes())
            self.assertEqual(__import__('base64').b64decode(record['before_base64']), before)
            self.assertEqual(record['phase'], 'committed')


if __name__ == '__main__':
    unittest.main()
