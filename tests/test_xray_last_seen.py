"""lastSeen stamping from Xray traffic counter deltas.

The stats API only reports cumulative counters, so the panel derives last
activity by comparing them against the values persisted from the previous
poll. These tests pin the stamping, the persistence, and the re-baseline
after a counter reset (container restart).
"""

import json
import unittest

from managers.xray_manager import XrayManager

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

CLIENT_ID = '11111111-1111-1111-1111-111111111111'
OTHER_ID = '22222222-2222-2222-2222-222222222222'
TABLE_PATH = '/opt/amnezia/xray/clientsTable'


def table(*user_datas):
    names = ['Phone', 'Laptop']
    return [
        {
            'clientId': CLIENT_ID if i == 0 else OTHER_ID,
            'userData': {
                'clientName': names[i],
                'creationDate': '2026-11-12T00:00:00',
                'enabled': True,
                **extra,
            },
        }
        for i, extra in enumerate(user_datas)
    ]


def stats_for(client_id, rx, tx):
    return [
        {'name': f'user>>>{client_id}>>>traffic>>>downlink', 'value': str(rx)},
        {'name': f'user>>>{client_id}>>>traffic>>>uplink', 'value': str(tx)},
    ]


class FakeSSH:
    """In-memory stand-in serving the native-layout config directory."""

    def __init__(self):
        self.files = {
            '/opt/amnezia/xray/server.json': json.dumps(SERVER_JSON),
            TABLE_PATH: json.dumps(table()),
            '/opt/amnezia/xray/xray_private.key': 'priv\n',
            '/opt/amnezia/xray/xray_public.key': 'pub\n',
            '/opt/amnezia/xray/xray_short_id.key': 'abcd1234\n',
            '/opt/amnezia/xray/xray_uuid.key': '\n',
        }
        self.last_upload = None
        self.stats = {}

    def upload_file_sudo(self, content, remote_path):
        self.files[remote_path] = content
        self.last_upload = (content, remote_path)
        return True

    def run_sudo_command(self, command, **kwargs):
        cmd = command.strip()
        if cmd.startswith('ls -1'):
            dir_path = cmd.split()[2]
            names = [p[len(dir_path):].lstrip('/')
                     for p in self.files if p.startswith(dir_path + '/')]
            return ('\n'.join(sorted(names)), '', 0)
        if 'statsquery' in cmd:
            return (json.dumps({'stat': self.stats}), '', 0)
        if 'docker cp ' in cmd:
            dest = cmd.rsplit(':', 1)[-1].split()[0]
            if self.last_upload:
                self.files[dest] = self.last_upload[0]
            return ('', '', 0)
        if ' cat ' in cmd:
            path = cmd.rsplit(' cat ', 1)[-1].split(' 2>', 1)[0].strip()
            return (self.files.get(path, ''), '', 0)
        return ('', '', 0)

    def run_command(self, command, **kwargs):
        return ('', '', 0)


class LastSeenTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.mgr = XrayManager(self.ssh)

    def poll(self):
        return self.mgr.get_clients('xray')

    def persisted(self):
        return json.loads(self.ssh.files[TABLE_PATH])

    def test_first_activity_stamps_last_seen_and_persists(self):
        self.ssh.files[TABLE_PATH] = json.dumps(table({}))
        self.ssh.stats = stats_for(CLIENT_ID, 100, 50)

        clients = self.poll()
        user_data = clients[0]['userData']
        self.assertIn('lastSeen', user_data)
        self.assertEqual(user_data['dataReceivedBytes'], 100)
        self.assertEqual(user_data['dataSentBytes'], 50)
        self.assertEqual(user_data['dataReceived'], '100 B')
        # The stamp must survive panel restarts: it lands in clientsTable.
        self.assertIn('lastSeen', self.persisted()[0]['userData'])

    def test_idle_client_is_not_rewritten(self):
        self.ssh.files[TABLE_PATH] = json.dumps(table({
            'lastSeen': '2026-11-12T10:00:00',
            'dataReceivedBytes': 100,
            'dataSentBytes': 50,
        }))
        self.ssh.stats = stats_for(CLIENT_ID, 100, 50)
        before = self.ssh.files[TABLE_PATH]

        clients = self.poll()
        self.assertEqual(clients[0]['userData']['lastSeen'], '2026-11-12T10:00:00')
        self.assertEqual(self.ssh.files[TABLE_PATH], before)

    def test_growth_updates_last_seen(self):
        self.ssh.files[TABLE_PATH] = json.dumps(table({
            'lastSeen': '2026-11-12T10:00:00',
            'dataReceivedBytes': 100,
            'dataSentBytes': 50,
        }))
        self.ssh.stats = stats_for(CLIENT_ID, 400, 50)

        clients = self.poll()
        user_data = clients[0]['userData']
        self.assertNotEqual(user_data['lastSeen'], '2026-11-12T10:00:00')
        self.assertEqual(user_data['dataReceivedBytes'], 400)

    def test_counter_reset_rebaselines_without_touching_last_seen(self):
        # A container restart zeroes the counters: below the stored totals,
        # so lastSeen must not move and the baseline must shrink.
        self.ssh.files[TABLE_PATH] = json.dumps(table({
            'lastSeen': '2026-11-12T10:00:00',
            'dataReceivedBytes': 1000,
            'dataSentBytes': 500,
        }))
        self.ssh.stats = stats_for(CLIENT_ID, 100, 50)

        clients = self.poll()
        user_data = clients[0]['userData']
        self.assertEqual(user_data['lastSeen'], '2026-11-12T10:00:00')
        self.assertEqual(user_data['dataReceivedBytes'], 100)

        # Growth from the re-baselined totals registers as fresh activity.
        self.ssh.stats = stats_for(CLIENT_ID, 400, 50)
        clients = self.poll()
        self.assertNotEqual(clients[0]['userData']['lastSeen'], '2026-11-12T10:00:00')

    def test_unavailable_stats_change_nothing(self):
        self.ssh.files[TABLE_PATH] = json.dumps(table({
            'lastSeen': '2026-11-12T10:00:00',
        }))
        before = self.ssh.files[TABLE_PATH]

        clients = self.poll()
        self.assertEqual(clients[0]['userData']['lastSeen'], '2026-11-12T10:00:00')
        self.assertEqual(self.ssh.files[TABLE_PATH], before)

    def test_clients_without_stats_are_left_alone(self):
        self.ssh.files[TABLE_PATH] = json.dumps(table({}, {}))
        self.ssh.stats = stats_for(CLIENT_ID, 100, 50)

        clients = self.poll()
        self.assertIn('lastSeen', clients[0]['userData'])
        self.assertNotIn('lastSeen', clients[1]['userData'])
        self.assertNotIn('lastSeen', self.persisted()[1]['userData'])


if __name__ == '__main__':
    unittest.main()
