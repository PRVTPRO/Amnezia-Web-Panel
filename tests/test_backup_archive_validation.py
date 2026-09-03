import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from managers.backup_manager import BackupManager


class BackupArchiveValidationTests(unittest.TestCase):
    def _write_archive(self, members):
        fd, path = tempfile.mkstemp(suffix='.tar.gz')
        os.close(fd)
        with tarfile.open(path, 'w:gz') as archive:
            for name, payload in members:
                info = tarfile.TarInfo(name=name)
                if payload is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                    continue
                data = payload if isinstance(payload, bytes) else payload.encode('utf-8')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def _write_panel_style_archive(self):
        """Match server create_backup: tar -C work_dir -czf archive ."""
        work = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        with open(os.path.join(work, 'backup-info.json'), 'w', encoding='utf-8') as fh:
            json.dump({
                'protocol': 'awg3',
                'container': 'amnezia-awg3',
                'backup_format': BackupManager.BACKUP_FORMAT,
            }, fh)
        os.makedirs(os.path.join(work, 'host/opt/amnezia/awg'))
        with open(os.path.join(work, 'host/opt/amnezia/awg/awg0.conf'), 'w', encoding='utf-8') as fh:
            fh.write('PrivateKey = x\n')
        os.makedirs(os.path.join(work, 'container/opt/amnezia/awg'))
        with open(os.path.join(work, 'container/opt/amnezia/awg/clientsTable'), 'w', encoding='utf-8') as fh:
            fh.write('[]')
        os.makedirs(os.path.join(work, 'docker'))
        with open(os.path.join(work, 'docker/inspect.json'), 'w', encoding='utf-8') as fh:
            fh.write('{}')
        fd, path = tempfile.mkstemp(suffix='.tar.gz')
        os.close(fd)
        subprocess.check_call(['tar', '-C', work, '-czf', path, '.'])
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_accepts_panel_layout(self):
        info = {
            'protocol': 'awg3',
            'container': 'amnezia-awg3',
            'backup_format': BackupManager.BACKUP_FORMAT,
        }
        path = self._write_archive([
            ('backup-info.json', json.dumps(info)),
            ('host/opt/amnezia/awg/', None),
            ('host/opt/amnezia/awg/awg0.conf', 'PrivateKey = x\n'),
            ('container/opt/amnezia/awg/clientsTable', '[]'),
            ('docker/inspect.json', '{}'),
        ])
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['info']['protocol'], 'awg3')

    def test_accepts_real_tar_dot_archive(self):
        path = self._write_panel_style_archive()
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'success', result)
        self.assertEqual(result['info']['protocol'], 'awg3')

    def test_rejects_path_traversal(self):
        info = {
            'protocol': 'awg3',
            'backup_format': BackupManager.BACKUP_FORMAT,
        }
        path = self._write_archive([
            ('backup-info.json', json.dumps(info)),
            ('host/../../etc/cron.d/evil', 'evil'),
        ])
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'error')
        self.assertIn('unsafe', result['message'].lower())

    def test_rejects_absolute_member(self):
        info = {
            'protocol': 'awg3',
            'backup_format': BackupManager.BACKUP_FORMAT,
        }
        path = self._write_archive([
            ('backup-info.json', json.dumps(info)),
            ('/etc/passwd', 'root:x'),
        ])
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'error')

    def test_requires_backup_format(self):
        path = self._write_archive([
            ('backup-info.json', json.dumps({'protocol': 'awg3'})),
            ('host/opt/amnezia/awg/awg0.conf', 'x'),
        ])
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'error')
        self.assertIn('format', result['message'].lower())

    def test_rejects_symlink_escape(self):
        info = {
            'protocol': 'awg3',
            'backup_format': BackupManager.BACKUP_FORMAT,
        }
        fd, path = tempfile.mkstemp(suffix='.tar.gz')
        os.close(fd)
        with tarfile.open(path, 'w:gz') as archive:
            meta = json.dumps(info).encode('utf-8')
            meta_info = tarfile.TarInfo('backup-info.json')
            meta_info.size = len(meta)
            archive.addfile(meta_info, io.BytesIO(meta))
            link = tarfile.TarInfo('host/escape')
            link.type = tarfile.SYMTYPE
            link.linkname = '../../etc/passwd'
            archive.addfile(link)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        result = BackupManager.inspect_archive(path)
        self.assertEqual(result['status'], 'error')
        self.assertIn('unsafe', result['message'].lower())


if __name__ == '__main__':
    unittest.main()
