"""Remote backup staging must be private and cleaned on every exit."""
import os
import unittest
from unittest.mock import MagicMock, patch

import app as panel


class BackupDownloadSecurityTests(unittest.TestCase):
    def run_download(self, failure=None):
        ssh = MagicMock()
        ssh._make_private_temp_dir.return_value = '/tmp/amnezia-private.ABC123def0'
        ssh.run_sudo_command.return_value = ('', '', 0)
        if failure == 'sftp':
            ssh.sftp_transfer.side_effect = OSError('sftp unavailable')
        with patch.object(panel, '_check_admin', return_value=True), \
             patch.object(panel, 'load_data', return_value={'servers': [{}]}), \
             patch.object(panel, 'get_ssh', return_value=ssh):
            if failure == 'local_temp':
                with patch.object(panel.tempfile, 'mkstemp', side_effect=OSError('disk full')):
                    result = panel.api_protocol_backup_download(None, 0, panel.BackupDownloadRequest(
                        protocol='awg', filename='backup.tar.gz'))
            else:
                result = panel.api_protocol_backup_download(None, 0, panel.BackupDownloadRequest(
                    protocol='awg', filename='backup.tar.gz'))
        return result, ssh

    def test_staging_uses_private_directory(self):
        result, ssh = self.run_download()
        try:
            self.assertEqual(result.status_code, 200)
            ssh._make_private_temp_dir.assert_called_once()
            sftp = ssh.sftp_transfer.return_value.__enter__.return_value
            self.assertEqual(sftp.get.call_args[0][0],
                             '/tmp/amnezia-private.ABC123def0/backup.tar.gz')
            self.assertIn('rm -rf -- /tmp/amnezia-private.ABC123def0',
                          [c.args[0] for c in ssh.run_sudo_command.call_args_list])
            ssh.disconnect.assert_called_once()
        finally:
            if hasattr(result, 'path') and os.path.exists(result.path):
                os.remove(result.path)

    def test_cleanup_on_local_temp_or_sftp_failure(self):
        for failure in ('local_temp', 'sftp'):
            with self.subTest(failure=failure):
                result, ssh = self.run_download(failure)
                self.assertEqual(result.status_code, 500)
                self.assertIn('rm -rf -- /tmp/amnezia-private.ABC123def0',
                              [c.args[0] for c in ssh.run_sudo_command.call_args_list])
                ssh.disconnect.assert_called_once()


if __name__ == '__main__':
    unittest.main()
