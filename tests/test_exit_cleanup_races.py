"""Exit cleanup races against queued link changes, using synthetic managers."""
import asyncio
import ast
import json
import os
from pathlib import Path
import tempfile
import copy
import unittest
from unittest.mock import AsyncMock

from test_exit_link_service import Harness
from exit_link_service import ExitLinkError, peer_id_for


def link(exit_uid):
    return {'exit_uid': exit_uid, 'linked_at': 'synthetic', 'stale': None}


class ExitCleanupRaces(unittest.IsolatedAsyncioTestCase):
    async def launch_behind_lock(self, service, operation):
        lock = service._locks[('entry-uid', 'awg2')]
        await lock.acquire()
        started = asyncio.Event()
        async def run():
            started.set()
            return await operation()
        task = asyncio.create_task(run())
        await started.wait()  # operation has entered and must stop at the held lock
        return task, lock

    async def test_detach_cannot_remove_a_link_switched_to_another_exit(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        release_ssh = asyncio.Event()
        async def awg(server):
            await release_ssh.wait()
            return h.awg(server['host'])
        h.service._awg = AsyncMock(side_effect=awg)
        task, lock = await self.launch_behind_lock(h.service, lambda: h.service.detach_entries_for_exit('exit-a', 'deleted'))
        h.record()['exit_link'] = link('exit-b')
        lock.release()
        release_ssh.set()
        await task
        self.assertEqual(h.record()['exit_link']['exit_uid'], 'exit-b')
        self.assertEqual(h.awg().calls, [])

    async def test_forget_reads_current_link_after_its_lock(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        snapshot = copy.deepcopy(h.data['servers'][0])
        release_ssh = asyncio.Event()
        async def manager(server):
            await release_ssh.wait()
            return h.exit(server['host'])
        h.service._exit_manager = AsyncMock(side_effect=manager)
        task, lock = await self.launch_behind_lock(h.service, lambda: h.service.forget_entry_peers(snapshot))
        h.record()['exit_link'] = link('exit-b')
        lock.release()
        release_ssh.set()
        await task
        self.assertEqual(h.exit().calls, [])
        self.assertEqual(h.exit('203.0.113.9').calls,
                         [('remove_peer', None, peer_id_for('entry-uid', 'awg2'))])

    async def test_queued_link_cannot_create_peers_for_a_deleted_entry(self):
        h = Harness()
        task, lock = await self.launch_behind_lock(h.service, lambda: h.service.link(0, 'awg2', 'exit-a'))
        h.data['servers'].pop(0)
        lock.release()
        with self.assertRaises(ExitLinkError):
            await task
        self.assertEqual(h.events, [])
        self.assertEqual(h.exits, {})

    async def test_queued_unlink_uses_current_exit(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        task, lock = await self.launch_behind_lock(h.service, lambda: h.service.unlink(0, 'awg2'))
        h.record()['exit_link'] = link('exit-b')
        lock.release()
        await task
        self.assertEqual(h.exit().calls, [])
        self.assertEqual(h.exit('203.0.113.9').calls,
                         [('remove_peer', None, peer_id_for('entry-uid', 'awg2'))])
        self.assertNotIn('exit_link', h.record())

    async def test_failure_marks_only_the_matching_link_stale(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        h.record(protocol='awg_legacy')['exit_link'] = link('exit-b')
        h.unreachable.add('198.51.100.1')
        result = await h.service.detach_entries_for_exit('exit-a', 'deleted')
        self.assertEqual(result[0]['status'], 'error')
        self.assertEqual(h.record()['exit_link']['stale'], 'deleted')
        self.assertEqual(h.record(protocol='awg_legacy')['exit_link'], link('exit-b'))

    async def test_metadata_write_failure_preserves_persisted_links(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        before = copy.deepcopy(h.data)
        h.service.save_data = lambda data: (_ for _ in ()).throw(OSError('synthetic disk failure'))
        with self.assertRaises(OSError):
            await h.service.detach_entries_for_exit('exit-a', 'deleted')
        self.assertEqual(h.data, before)
        self.assertEqual(h.awg().calls, [('exit_unlink', 'awg2')])

    async def test_foreign_link_is_preserved_in_real_atomic_json(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.json'
            source = Path(__file__).resolve().parents[1] / 'app.py'
            tree = ast.parse(source.read_text(encoding='utf-8'))
            fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'save_data')
            ns = dict(DATA_FILE=str(path), os=os, json=json, tempfile=tempfile)
            exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec'), ns)
            save = ns['save_data']
            save(h.data)
            h.service.load_data = lambda: json.loads(path.read_text(encoding='utf-8'))
            h.service.save_data = save
            release_ssh = asyncio.Event()
            async def awg(server):
                await release_ssh.wait()
                return h.awg(server['host'])
            h.service._awg = awg
            task, lock = await self.launch_behind_lock(h.service, lambda: h.service.detach_entries_for_exit('exit-a', 'deleted'))
            latest = h.service.load_data()
            latest['servers'][0]['protocols']['awg2']['exit_link'] = link('exit-b')
            latest['users'] = [{'id': 'fixture', 'traffic_used': 77}]
            save(latest)
            lock.release()
            release_ssh.set()
            await task
            persisted = h.service.load_data()
            self.assertEqual(persisted, latest)
            self.assertEqual(persisted['servers'][0]['protocols']['awg2']['exit_link']['exit_uid'], 'exit-b')

    async def test_independent_entries_do_not_share_a_global_ssh_lock(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        other = copy.deepcopy(h.data['servers'][0])
        other.update(uid='other-entry', host='198.51.100.2', name='Other')
        other['protocols']['awg2']['exit_link'] = link('exit-b')
        h.data['servers'].append(other)
        started, release = asyncio.Event(), asyncio.Event()
        async def awg(server):
            started.set()
            await release.wait()
            return h.awg(server['host'])
        h.service._awg = awg
        task = asyncio.create_task(h.service.detach_entries_for_exit('exit-a', 'deleted'))
        await started.wait()
        self.assertFalse(h.service.data_lock.locked())
        try:
            result = await asyncio.wait_for(h.service.forget_entry_peers(other), 2)
            self.assertEqual(result[0]['status'], 'success')
            self.assertEqual(h.exit('203.0.113.9').calls, [('remove_peer', None, peer_id_for('other-entry', 'awg2'))])
        finally:
            release.set()
            await task

    async def test_link_cannot_publish_a_deleted_exit_after_ssh(self):
        h = Harness()
        started, release = asyncio.Event(), asyncio.Event()
        async def handshake(*args):
            started.set()
            await release.wait()
            return {'handshake_age': 1}
        h.service._wait_handshake = handshake
        task = asyncio.create_task(h.service.link(0, 'awg2', 'exit-a'))
        await started.wait()
        h.data['servers'].pop(1)
        release.set()
        with self.assertRaises(ExitLinkError):
            await task
        self.assertNotIn('exit_link', h.record())
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)
        self.assertIn(('remove_peer', None, peer_id_for('entry-uid', 'awg2')), h.exit().calls)

    async def test_link_cannot_publish_a_deleted_entry_after_ssh(self):
        h = Harness()
        started, release = asyncio.Event(), asyncio.Event()
        async def handshake(*args):
            started.set()
            await release.wait()
            return {'handshake_age': 1}
        h.service._wait_handshake = handshake
        task = asyncio.create_task(h.service.link(0, 'awg2', 'exit-a'))
        await started.wait()
        h.data['servers'].pop(0)
        release.set()
        with self.assertRaises(ExitLinkError):
            await task
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)
        self.assertIn(('remove_peer', None, peer_id_for('entry-uid', 'awg2')), h.exit().calls)

    async def test_link_save_failure_rolls_back_its_own_remote_peer(self):
        h = Harness()
        before = copy.deepcopy(h.data)
        h.service.save_data = lambda data: (_ for _ in ()).throw(OSError('synthetic disk failure'))
        with self.assertRaises(OSError):
            await h.service.link(0, 'awg2', 'exit-a')
        self.assertEqual(h.data, before)
        self.assertIn(('exit_unlink', 'awg2'), h.awg().calls)
        self.assertIn(('remove_peer', None, peer_id_for('entry-uid', 'awg2')), h.exit().calls)

    async def test_detach_resolves_metadata_by_uid_after_reorder(self):
        h = Harness()
        h.record()['exit_link'] = link('exit-a')
        started, release = asyncio.Event(), asyncio.Event()
        async def awg(server):
            started.set()
            await release.wait()
            return h.awg(server['host'])
        h.service._awg = awg
        task = asyncio.create_task(h.service.detach_entries_for_exit('exit-a', 'deleted'))
        await started.wait()
        h.data['servers'] = h.data['servers'][1:] + h.data['servers'][:1]
        release.set()
        await task
        self.assertNotIn('exit_link', h.record(2))
        self.assertEqual([s['uid'] for s in h.data['servers']], ['exit-a', 'exit-b', 'entry-uid'])


if __name__ == '__main__':
    unittest.main()
