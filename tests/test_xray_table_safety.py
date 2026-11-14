"""clientsTable safety for the Xray manager (issue #182 pattern).

A transient SSH failure during a clientsTable read used to answer an empty
table, and the following read-modify-write wiped the real one. Now write
paths read strictly (raise instead of []), saves go through the shared
checked writer, and every read-modify-write holds a per-container lock.
"""

import json
import unittest
from unittest import mock

from managers.xray_manager import (
    XrayManager,
    _serialized_table_write,
    _xray_clients_table_lock,
)

SERVER_JSON = {
    'log': {'loglevel': 'error'},
    'inbounds': [
        {
            'port': 443,
            'protocol': 'vless',
            'tag': 'proxy',
            'settings': {'clients': [], 'decryption': 'none'},
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'dest': 'yahoo.com:443',
                    'serverNames': ['yahoo.com'],
                    'privateKey': 'priv',
                    'shortIds': ['abcd1234'],
                },
            },
        },
    ],
    'outbounds': [{'protocol': 'freedom'}],
}

TABLE_PATH = '/opt/amnezia/xray/clientsTable'


class FakeSSH:
    """Serves the native-layout config dir; table reads can fail on demand."""

    def __init__(self, table_content='[]', fail_table_read=False, container_running=True):
        self.container_running = container_running
        self.fail_table_read = fail_table_read
        self.files = {
            '/opt/amnezia/xray/server.json': json.dumps(SERVER_JSON),
            TABLE_PATH: table_content,
            '/opt/amnezia/xray/xray_private.key': 'priv\n',
            '/opt/amnezia/xray/xray_public.key': 'pub\n',
            '/opt/amnezia/xray/xray_short_id.key': 'abcd1234\n',
            '/opt/amnezia/xray/xray_uuid.key': '\n',
        }
        self.commands = []
        self.uploads = []

    def upload_file_sudo(self, content, remote_path):
        self.uploads.append((content, remote_path))
        self.files[remote_path] = content
        return True

    def run_sudo_command(self, command, *args, **kwargs):
        cmd = command.strip()
        self.commands.append(cmd)
        if 'docker ps --filter' in cmd:
            return ('Up 2 minutes', '', 0) if self.container_running else ('', '', 0)
        if cmd.startswith('ls -1'):
            dir_path = cmd.split()[2]
            names = [p[len(dir_path):].lstrip('/')
                     for p in self.files if p.startswith(dir_path + '/')]
            return ('\n'.join(sorted(names)), '', 0)
        if cmd.startswith('cat ') or ' cat ' in cmd:
            path = (cmd[4:] if cmd.startswith('cat ') else cmd.rsplit(' cat ', 1)[-1])
            path = path.split(' 2>', 1)[0].strip()
            if self.fail_table_read and path == TABLE_PATH:
                return ('', 'channel closed', 1)
            content = self.files.get(path)
            if content is None:
                return ('', 'No such file', 1)  # real cat on an absent file
            return (content, '', 0)
        return '', '', 0

    def run_command(self, command, *args, **kwargs):
        self.commands.append(command.strip())
        return '', '', 0


class StrictReadTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH(table_content=json.dumps([
            {'clientId': 'existing-1', 'userData': {'clientName': 'Phone'}}]))
        self.mgr = XrayManager(self.ssh)

    def test_unreadable_table_aborts_add_instead_of_wiping(self):
        self.ssh.fail_table_read = True
        with self.assertRaises(RuntimeError):
            self.mgr.add_client('xray', 'Laptop', '1.2.3.4', 443)
        # The old behaviour answered [] and wrote a single-client table.
        table_writes = [c for c in self.ssh.commands
                        if 'docker cp' in c and 'clientsTable' in c]
        self.assertEqual(table_writes, [])
        self.assertEqual([p for _, p in self.ssh.uploads
                          if 'clientsTable' in p], [])

    def test_unreadable_table_aborts_rename(self):
        self.ssh.fail_table_read = True
        with self.assertRaises(RuntimeError):
            self.mgr.rename_client('xray', 'existing-1', 'New name')

    def test_rename_on_a_stopped_instance_fails_with_a_clear_message(self):
        self.ssh.container_running = False
        with self.assertRaises(RuntimeError) as ctx:
            self.mgr.rename_client('xray', 'existing-1', 'New name')
        self.assertIn('not running', str(ctx.exception))
        # No table traffic at all: the guard fires before the read.
        table_ops = [c for c in self.ssh.commands if 'clientsTable' in c]
        self.assertEqual(table_ops, [])

    def test_malformed_table_aborts_toggle(self):
        self.ssh.files[TABLE_PATH] = 'not-json'
        with self.assertRaises(RuntimeError):
            self.mgr.toggle_client('xray', 'existing-1', False)

    def test_get_clients_raises_on_unreadable_table(self):
        self.ssh.fail_table_read = True
        with self.assertRaises(RuntimeError):
            self.mgr.get_clients('xray')

    def test_readable_table_still_serves_clients(self):
        clients = self.mgr.get_clients('xray')
        self.assertEqual([c['clientId'] for c in clients], ['existing-1'])


class SaveDelegationTests(unittest.TestCase):
    def test_save_goes_through_the_shared_checked_writer(self):
        ssh = FakeSSH()
        mgr = XrayManager(ssh)
        table = [{'clientId': 'a', 'userData': {}}]
        with mock.patch('managers.xray_manager.save_clients_table') as save:
            mgr._save_clients_table(table)
        save.assert_called_once_with(
            ssh, 'amnezia-xray', TABLE_PATH, table)


class LockTests(unittest.TestCase):
    def test_same_host_and_container_share_one_lock(self):
        first = _xray_clients_table_lock('host-a', 'amnezia-xray')
        second = _xray_clients_table_lock('host-a', 'amnezia-xray')
        other = _xray_clients_table_lock('host-b', 'amnezia-xray')
        self.assertIs(first, second)
        self.assertIsNot(first, other)

    def test_decorator_passes_through_when_free(self):
        calls = []

        class Holder:
            container_name = 'amnezia-xray'

            def __init__(self, ssh):
                self.ssh = ssh

            @_serialized_table_write
            def work(self, value):
                calls.append(value)
                return value

        holder = Holder(mock.Mock())
        self.assertEqual(holder.work(7), 7)
        self.assertEqual(calls, [7])


if __name__ == '__main__':
    unittest.main()
