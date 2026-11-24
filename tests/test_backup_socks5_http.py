"""Бэкап socks5: оба каталога на хосте и конфиг из обоих контейнеров."""

import unittest

from managers.backup_manager import BackupManager


class FakeSSH:
    def __init__(self):
        self.scripts = []

    def run_sudo_script(self, script, timeout=120):
        self.scripts.append(script)
        return ('/opt/amnezia/backups/socks5/socks5-20260101T000000Z.tar.gz',
                '', 0)


class Socks5BackupTests(unittest.TestCase):
    def test_paths_include_both_config_dirs(self):
        """Оба каталога на хосте; в контейнере путей нет.

        `/etc/3proxy` — read-only bind-mount с хоста, поэтому
        `docker exec rm -rf /etc/3proxy` при восстановлении падает с
        «Device or resource busy». Конфиг восстанавливается через host-путь.
        """
        paths = BackupManager(FakeSSH())._paths_for(
            'socks5', 'amnezia-socks5proxy')
        self.assertEqual(paths['host'], [
            '/opt/amnezia/socks5proxy', '/opt/amnezia/httpproxy'])
        self.assertEqual(paths['container'], [])

    def test_script_archives_both_config_dirs(self):
        """Конфиги копируются с хоста; оба контейнера опрашиваются для docker-слоя."""
        ssh = FakeSSH()
        result = BackupManager(ssh).create_backup('socks5', 'amnezia-socks5proxy')
        self.assertEqual(result['status'], 'success')
        script = ssh.scripts[0]
        self.assertIn(
            'for p in /opt/amnezia/socks5proxy /opt/amnezia/httpproxy; do', script)
        self.assertIn(
            'for c in amnezia-socks5proxy amnezia-httpproxy; do', script)

    def test_other_protocols_keep_one_container(self):
        ssh = FakeSSH()
        BackupManager(ssh).create_backup('awg3', 'amnezia-awg3')
        script = ssh.scripts[0]
        self.assertNotIn('amnezia-httpproxy', script)
        self.assertIn('for c in amnezia-awg3; do', script)

    def test_container_paths_are_empty_for_socks5(self):
        """Причина: `/etc/3proxy` — read-only bind-mount с хоста.

        `docker exec rm -rf /etc/3proxy` при восстановлении падал с
        «Device or resource busy», поэтому socks5 восстановливается только
        через host-пути (проверено вживую на EUROBYTE 21.11).
        """
        paths = BackupManager(FakeSSH())._paths_for(
            'socks5', 'amnezia-socks5proxy')
        self.assertEqual(paths['container'], [])
        self.assertIn('/opt/amnezia/socks5proxy', paths['host'])
        self.assertIn('/opt/amnezia/httpproxy', paths['host'])

    def test_restore_restarts_http_container(self):
        """socks5: конфиг лежит в двух каталогах, перезапускать надо оба."""
        from unittest import mock
        ssh = FakeSSH()
        manager = BackupManager(ssh)
        with mock.patch.object(manager, '_fetch_remote_archive',
                               return_value=('/tmp/fake.tgz', None)),                 mock.patch.object(manager, 'inspect_archive',
                                  return_value={'status': 'success',
                                                'info': {'protocol': 'socks5'}}),                 mock.patch('os.remove'):
            result = manager.restore_backup(
                'socks5', 'amnezia-socks5proxy', 'socks5-20260101T000000Z.tar.gz')
        self.assertEqual(result['status'], 'success')
        script = ssh.scripts[-1]
        self.assertIn('docker restart amnezia-httpproxy', script)
        self.assertIn('/opt/amnezia/httpproxy', script)

    def test_restore_restarts_http_container_of_the_same_instance(self):
        """socks5__2: второй листенер называется amnezia-httpproxy-2."""
        from unittest import mock
        ssh = FakeSSH()
        manager = BackupManager(ssh)
        with mock.patch.object(manager, '_fetch_remote_archive',
                               return_value=('/tmp/fake.tgz', None)),                 mock.patch.object(manager, 'inspect_archive',
                                  return_value={'status': 'success',
                                                'info': {'protocol': 'socks5__2'}}),                 mock.patch('os.remove'):
            result = manager.restore_backup(
                'socks5__2', 'amnezia-socks5proxy-2', 'socks5-2-20260101T000000Z.tar.gz')
        self.assertEqual(result['status'], 'success')
        script = ssh.scripts[-1]
        self.assertIn('docker restart amnezia-httpproxy-2', script)
        self.assertNotIn('docker restart amnezia-httpproxy >', script)
        self.assertIn('/opt/amnezia/httpproxy-2', script)
if __name__ == '__main__':
    unittest.main()
