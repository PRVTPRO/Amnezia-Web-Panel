"""Verify trust boundaries behind ScanGit path/HTTP/template findings."""
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as panel


class ScanAssumptionTests(unittest.TestCase):
    def test_tunnel_provider_cannot_supply_paths(self):
        for provider in ('../../outside', '/tmp/evil', 'ngrok/../../evil', 'unknown'):
            with self.subTest(provider=provider):
                with self.assertRaises(ValueError):
                    panel.get_tunnel_command_name(provider)
                with self.assertRaises(ValueError):
                    panel.get_tunnel_download(provider)
                with self.assertRaises(ValueError):
                    panel.get_tunnel_binary_path(provider)

    def test_zip_member_path_is_not_used_as_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'ngrok.exe'
            def download(url, filename):
                with zipfile.ZipFile(filename, 'w') as archive:
                    archive.writestr('../../ngrok.exe', b'test-binary')
                    archive.writestr('../../unexpected.txt', b'do-not-extract')
            with patch.object(panel, 'BIN_DIR', directory), \
                 patch.object(panel, 'is_tunnel_installed', return_value=False), \
                 patch.object(panel, 'get_tunnel_download', return_value=('https://example.test/bin', 'zip')), \
                 patch.object(panel, 'get_tunnel_command_name', return_value='ngrok.exe'), \
                 patch.object(panel.urllib.request, 'urlretrieve', side_effect=download):
                panel.install_tunnel_binary('ngrok')
            self.assertEqual(target.read_bytes(), b'test-binary')
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['ngrok.exe'])

    def test_backup_download_is_admin_only(self):
        with patch.object(panel, '_check_admin', return_value=False):
            response = TestClient(panel.app).get('/api/settings/backup/download')
        # Anonymous: 401 from api_auth_status_middleware; signed-in non-admin:
        # the handler's 403. Either code means the download stayed closed.
        self.assertIn(response.status_code, (401, 403))

    def test_jinja_autoescapes_untrusted_html(self):
        template = panel.templates.env.from_string('<p>{{ value }}</p>')
        self.assertEqual(template.render(value='<script>alert(1)</script>'),
                         '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>')


if __name__ == '__main__':
    unittest.main()
