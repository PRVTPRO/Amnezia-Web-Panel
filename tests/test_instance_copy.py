"""Copy one AmneziaWG instance between servers.

Covers the pure helpers, archive patching, the rollback contract and the
panel-side merge into data.json. SSH is always faked: these tests must not
touch a real host.
"""
import asyncio
import io
import json
import os
import re
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from managers.instance_copy import (
    CopyCancelled,
    InstanceCopier,
    InstanceCopyError,
    container_name,
    next_instance,
    parse_listen_port,
    patch_listen_port,
    pick_port,
)

SERVER_CONFIG = """[Interface]
PrivateKey = abc=
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1330

[Peer]
PublicKey = peer1=
PresharedKey = psk1=
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = peer2=
AllowedIPs = 10.8.1.3/32
"""


class FakeSSH:
    """Records sudo commands and answers with a scripted handler."""

    def __init__(self, handler=None):
        self.commands = []
        self.handler = handler or (lambda command: ('', '', 0))
        self.client = None

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        return self.handler(command)

    def run_sudo_script(self, script, timeout=120):
        self.commands.append(script)
        return self.handler(script)

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return self.handler(command)

    def ensure_connected(self):
        return None

    def connect(self):
        return None

    def disconnect(self):
        return None


class CopyHelperTests(unittest.TestCase):
    def test_next_instance_starts_at_one_and_skips_used(self):
        self.assertEqual(next_instance({}, 'awg3'), 1)
        self.assertEqual(next_instance({'awg3': {}, 'awg3__2': {}}, 'awg3'), 3)
        self.assertEqual(next_instance({'awg2': {}, 'awg3__4': {}}, 'awg3'), 1)

    def test_container_name_follows_the_panel_convention(self):
        self.assertEqual(container_name('awg3', 1), 'amnezia-awg3')
        self.assertEqual(container_name('awg3', 6), 'amnezia-awg3-6')
        self.assertEqual(container_name('awg2', 2), 'amnezia-awg2-2')
        with self.assertRaises(InstanceCopyError):
            container_name('xray', 1)

    def test_parse_listen_port(self):
        self.assertEqual(parse_listen_port(SERVER_CONFIG), 55424)
        self.assertIsNone(parse_listen_port('ListenPort = nope'))

    def test_patch_listen_port_rewrites_only_the_port(self):
        patched = patch_listen_port(SERVER_CONFIG, 6000)
        self.assertIn('ListenPort = 6000', patched)
        self.assertNotIn('ListenPort = 55424', patched)
        # Everything else stays byte-identical: peers, keys, MTU.
        self.assertEqual(patched.replace('ListenPort = 6000', 'ListenPort = 55424'),
                         SERVER_CONFIG)

    def test_patch_listen_port_refuses_ambiguous_config(self):
        with self.assertRaises(InstanceCopyError) as caught:
            patch_listen_port('ListenPort = 1\nListenPort = 2\n', 3)
        self.assertEqual(caught.exception.code, 'config_invalid')

    def test_pick_port_prefers_the_source_port(self):
        self.assertEqual(pick_port(55424, {55551}), 55424)

    def test_pick_port_moves_up_when_busy(self):
        self.assertEqual(pick_port(55424, {55424, 55425}), 55426)

    def test_pick_port_wraps_when_the_tail_is_used(self):
        used = set(range(55424, 65536))
        self.assertEqual(pick_port(55424, used), 1024)


class CopyArchiveTests(unittest.TestCase):
    def make_archive(self, path, config=SERVER_CONFIG, extra=()):
        with tarfile.open(path, 'w') as archive:
            data = config.encode('utf-8')
            info = tarfile.TarInfo('awg/awg0.conf')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            for name, body in extra:
                blob = body.encode('utf-8')
                member = tarfile.TarInfo(name)
                member.size = len(blob)
                archive.addfile(member, io.BytesIO(blob))

    def test_patch_archive_rewrites_listen_port_in_place(self):
        copier = InstanceCopier(FakeSSH(), FakeSSH())
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = os.path.join(tmp, 'state.tar')
            self.make_archive(archive_path, extra=[('start.sh', '#!/bin/bash\n')])
            copier._patch_archive(archive_path, 6000, tmp)
            with tarfile.open(archive_path, 'r:') as archive:
                names = archive.getnames()
                self.assertIn('awg/awg0.conf', names)
                self.assertIn('start.sh', names)
                config = archive.extractfile('awg/awg0.conf').read().decode('utf-8')
            self.assertIn('ListenPort = 6000', config)
            self.assertEqual(config.count('[Peer]'), 2)


    def test_plan_refuses_a_container_that_already_exists(self):
        inspect_json = json.dumps([{
            'State': {'Running': True},
            'Config': {'Image': 'amnezia-awg3'},
            'HostConfig': {},
        }])

        def handler(command):
            if 'grep -c' in command:
                return ('2', '', 0)
            if 'docker exec' in command and 'cat' in command:
                return (SERVER_CONFIG, '', 0)
            if 'docker inspect' in command:
                return (inspect_json, '', 0)
            return ('', '', 0)

        copier = InstanceCopier(FakeSSH(handler), FakeSSH(handler))
        with self.assertRaises(InstanceCopyError) as caught:
            copier.plan('awg3', 'amnezia-awg3', {})
        self.assertEqual(caught.exception.code, 'name_taken')


class CopyStagingTests(unittest.TestCase):
    """The panel can run on the source host: local staging must not collide."""

    def test_image_staging_never_reuses_the_remote_temp_name(self):
        copier = InstanceCopier(FakeSSH(), FakeSSH())
        seen = {}
        copier._sudo = lambda ssh, command, timeout=120: ('', '', 0)
        copier._sftp_get = lambda ssh, remote, local: seen.update(remote=remote, local=local)
        copier._sftp_put = lambda ssh, local, remote: None

        copier._ensure_image({'image': 'img', 'image_present': False},
                             lambda stage, text: None)

        self.assertTrue(seen)
        self.assertNotEqual(seen['remote'], seen['local'])
        self.assertFalse(os.path.exists(os.path.dirname(seen['local'])))

    def test_tools_staging_never_reuses_the_remote_temp_name(self):
        copier = InstanceCopier(FakeSSH(), FakeSSH())
        seen = {}
        copier._sudo = lambda ssh, command, timeout=120: ('', '', 0)
        copier._sftp_get = lambda ssh, remote, local: seen.update(remote=remote, local=local)
        copier._sftp_put = lambda ssh, local, remote: None

        copier._copy_tools({'source_container': 'src', 'target_container': 'dst'})

        self.assertTrue(seen)
        self.assertNotEqual(seen['remote'], seen['local'])
        self.assertFalse(os.path.exists(os.path.dirname(seen['local'])))


class CopyRollbackTests(unittest.TestCase):
    def plan(self):
        return {
            'base': 'awg3',
            'source_key': 'awg3',
            'source_container': 'amnezia-awg3',
            'source_port': 55424,
            'target_index': 6,
            'target_key': 'awg3__6',
            'target_container': 'amnezia-awg3-6',
            'port': 6000,
            'peers': 2,
            'image': 'amnezia-awg3',
            'image_present': True,
        }

    def test_failure_removes_the_container_created_by_this_operation(self):
        target = FakeSSH()
        copier = InstanceCopier(FakeSSH(), target)
        copier._export_state = lambda plan, path: Path(path).write_bytes(b'x')
        copier._patch_archive = lambda path, port, workdir: None
        copier._ensure_image = lambda plan, log: None
        copier._create_container = lambda plan: None

        def explode(plan, path):
            raise InstanceCopyError('upload_failed', 'boom')

        copier._push_state = explode
        with self.assertRaises(InstanceCopyError):
            copier.execute(self.plan(), lambda stage, text: None)

        self.assertTrue(any('docker rm -f' in command and 'amnezia-awg3-6' in command
                            for command in target.commands),
                        target.commands)

    def test_cancel_before_any_side_effect_creates_nothing(self):
        target = FakeSSH()
        copier = InstanceCopier(FakeSSH(), target)

        def explode(plan, path):
            raise AssertionError('export must not run after a cancel request')

        copier._export_state = explode
        with self.assertRaises(CopyCancelled):
            copier.execute(self.plan(), lambda stage, text: None,
                           lambda: True)
        self.assertFalse(any('docker run' in command for command in target.commands))

    def test_verify_installs_missing_awg_tools_once(self):
        states = [(False, False, 2), (True, True, 2)]

        def tunnel_state(plan):
            return states.pop(0) if states else (True, True, 2)

        target = FakeSSH()
        copier = InstanceCopier(FakeSSH(), target)
        copier._tunnel_state = tunnel_state
        calls = []
        copier._copy_tools = lambda plan: calls.append('tools')
        copier._sudo = lambda ssh, command, timeout=120: (
            ('', '', 0) if 'docker restart' in command else ('', '', 0))

        logs = []
        with patch('managers.instance_copy.time.sleep', lambda seconds: None):
            copier._verify(self.plan(), lambda stage, text: logs.append(stage), lambda: False)

        self.assertEqual(calls, ['tools'])
        self.assertEqual([stage for stage in logs if stage == 'tools'], ['tools'])

    def test_verify_reports_a_peer_mismatch(self):
        target = FakeSSH()
        copier = InstanceCopier(FakeSSH(), target)
        copier._tunnel_state = lambda plan: (True, True, 1)
        copier._sudo = lambda ssh, command, timeout=120: ('', '', 0)
        with patch('managers.instance_copy.time.sleep', lambda seconds: None):
            with self.assertRaises(InstanceCopyError) as caught:
                copier._verify(self.plan(), lambda stage, text: None, lambda: False)
        self.assertEqual(caught.exception.code, 'peer_mismatch')


class PanelMergeTests(unittest.TestCase):
    def setUp(self):
        import app
        self.app = app
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_path = os.path.join(self.tmp.name, 'data.json')
        source = {
            'name': 'NATA',
            'host': '192.0.2.10',
            'protocols': {
                'awg3': {
                    'base_protocol': 'awg3',
                    'container_name': 'amnezia-awg3',
                    'instance': 1,
                    'port': '55424',
                    'awg_params': {'port': '55424', 'junk_packet_count': '2'},
                    'public_host': 'old.example.org',
                    'public_port': '60001',
                    'display_name': 'AmneziaWG 3.1',
                },
            },
        }
        target = {'name': 'MAMKAM', 'host': '192.0.2.20', 'protocols': {}}
        connections = [
            {'id': 'c1', 'user_id': 'u1', 'server_id': 0, 'protocol': 'awg3',
             'client_id': 'key1=', 'name': 'phone', 'created_at': '2026-01-01T00:00:00',
             'last_bytes': 123, 'last_rx_bytes': 100, 'last_tx_bytes': 23},
            {'id': 'c2', 'user_id': 'u2', 'server_id': 0, 'protocol': 'awg3',
             'client_id': 'key2=', 'name': 'laptop', 'created_at': '2026-01-02T00:00:00',
             'last_bytes': 456, 'last_rx_bytes': 400, 'last_tx_bytes': 56},
            {'id': 'c3', 'user_id': 'u1', 'server_id': 0, 'protocol': 'awg2',
             'client_id': 'other=', 'name': 'other', 'created_at': '2026-01-03T00:00:00'},
        ]
        Path(self.data_path).write_text(json.dumps({
            'servers': [source, target],
            'users': [],
            'user_connections': connections,
        }), encoding='utf-8')
        self.patch = patch.object(app, 'DATA_FILE', self.data_path)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def plan(self):
        return {'target_key': 'awg3__2', 'target_container': 'amnezia-awg3-2',
                'target_index': 2, 'port': 6000, 'base': 'awg3'}

    def test_apply_copies_the_protocol_and_zeroes_traffic(self):
        copied = self.app._instance_copy_apply(self.plan(), 0, 1, 'awg3')
        self.assertEqual(copied, 2)

        data = json.loads(Path(self.data_path).read_text(encoding='utf-8'))
        entry = data['servers'][1]['protocols']['awg3__2']
        self.assertEqual(entry['container_name'], 'amnezia-awg3-2')
        self.assertEqual(entry['instance'], 2)
        self.assertEqual(entry['port'], '6000')
        self.assertEqual(entry['awg_params']['port'], '6000')
        self.assertEqual(entry['awg_params']['junk_packet_count'], '2')
        self.assertIsNone(entry['public_host'])
        self.assertIsNone(entry['public_port'])
        self.assertEqual(entry['display_name'], 'AmneziaWG 3.1 #2')

        new_connections = [c for c in data['user_connections']
                           if c['server_id'] == 1 and c['protocol'] == 'awg3__2']
        self.assertEqual(len(new_connections), 2)
        self.assertEqual({c['client_id'] for c in new_connections}, {'key1=', 'key2='})
        self.assertEqual({c['user_id'] for c in new_connections}, {'u1', 'u2'})
        for connection in new_connections:
            self.assertEqual(connection['last_bytes'], 0)
            self.assertEqual(connection['last_rx_bytes'], 0)
            self.assertEqual(connection['last_tx_bytes'], 0)
            self.assertNotIn(connection['id'], ('c1', 'c2'))

    def test_apply_refuses_a_taken_instance_name(self):
        data = json.loads(Path(self.data_path).read_text(encoding='utf-8'))
        data['servers'][1]['protocols']['awg3__2'] = {'container_name': 'x'}
        Path(self.data_path).write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(InstanceCopyError) as caught:
            self.app._instance_copy_apply(self.plan(), 0, 1, 'awg3')
        self.assertEqual(caught.exception.code, 'name_taken')

    def test_rollback_removes_the_instance_and_its_connections(self):
        self.app._instance_copy_apply(self.plan(), 0, 1, 'awg3')
        self.app._instance_copy_rollback_panel(self.plan(), 1)
        data = json.loads(Path(self.data_path).read_text(encoding='utf-8'))
        self.assertNotIn('awg3__2', data['servers'][1]['protocols'])
        self.assertFalse([c for c in data['user_connections']
                          if c['server_id'] == 1 and c['protocol'] == 'awg3__2'])
        # The source bindings and the awg2 binding are untouched.
        self.assertEqual(len(data['user_connections']), 3)


class CopyEndpointTests(unittest.IsolatedAsyncioTestCase):
    """The HTTP layer: the start handler must create a journal entry, not blow up."""

    def setUp(self):
        import app
        self.app = app
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            patch.object(app, '_check_admin', return_value=True),
            patch.object(app, '_instance_copy_store_path',
                         return_value=os.path.join(self.tmp.name, 'ops.json')),
            patch.object(app, '_instance_copy_source',
                         return_value=({'name': 'SRC'}, {}, 'amnezia-awg3')),
            patch.object(app, '_run_instance_copy', new=self._worker),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        app._inst_copy_ops.clear()
        app._inst_copy_active['op_id'] = None
        app._inst_copy_loaded['done'] = False
        self.addCleanup(app._inst_copy_ops.clear)
        self.addCleanup(lambda: app._inst_copy_active.__setitem__('op_id', None))
        self.addCleanup(lambda: app._inst_copy_loaded.__setitem__('done', False))

    async def _worker(self, op_id):
        return None

    async def test_start_creates_an_operation_and_rejects_a_second_one(self):
        request = self.app.InstanceCopyRequest(protocol='awg3', target_server_id=1)
        first = await self.app.api_instance_copy_start(object(), 0, request)
        self.assertIn('operation_id', first)
        op_id = first['operation_id']
        self.assertEqual(self.app._inst_copy_active['op_id'], op_id)
        self.assertIn(op_id, self.app._inst_copy_ops)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, 'ops.json')))

        second = await self.app.api_instance_copy_start(object(), 0, request)
        self.assertEqual(getattr(second, 'status_code', None), 409)
        await asyncio.sleep(0)

    async def test_start_refuses_the_same_server(self):
        request = self.app.InstanceCopyRequest(protocol='awg3', target_server_id=0)
        response = await self.app.api_instance_copy_start(object(), 0, request)
        self.assertEqual(getattr(response, 'status_code', None), 400)

    async def test_status_returns_lines_after_the_offset_and_cancel_flags_it(self):
        op_id = 'op-under-test'
        self.app._inst_copy_ops[op_id] = {
            'id': op_id, 'state': 'running', 'step': 2, 'total': 8, 'percent': 25,
            'lines': [{'ts': 't1', 'stage': 'a', 'text': 'one'},
                      {'ts': 't2', 'stage': 'b', 'text': 'two'}],
            'cancel_requested': False, 'result': None, 'error': None,
        }
        status = await self.app.api_instance_copy_status(object(), 0, op_id, 1)
        self.assertEqual(status['next_offset'], 2)
        self.assertEqual([line['text'] for line in status['lines']], ['two'])

        cancelled = await self.app.api_instance_copy_cancel(object(), 0, op_id)
        self.assertEqual(cancelled['status'], 'cancelling')
        self.assertTrue(self.app._inst_copy_ops[op_id]['cancel_requested'])


class CopyTranslationTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_every_copy_key_used_in_the_template_exists_in_all_locales(self):
        source = (self.ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        used = set(re.findall(r"copy_instance_[a-z_]+", source))
        self.assertTrue(used, 'the template uses no copy_instance_* keys')
        for lang in ('en', 'ru', 'fr', 'zh', 'fa'):
            data = json.loads((self.ROOT / 'translations' / ('%s.json' % lang))
                              .read_text(encoding='utf-8'))
            missing = sorted(key for key in used if key not in data)
            self.assertEqual(missing, [], '%s misses %s' % (lang, missing))


if __name__ == '__main__':
    unittest.main()