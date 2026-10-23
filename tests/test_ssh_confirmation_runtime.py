"""Real trust storage and cancellation/concurrency regression coverage."""
import asyncio
import os
import threading
from unittest import mock
import paramiko
from starlette.requests import Request
import test_ssh_enrollment_http as http_tests
from managers import ssh_trust


class RuntimeTests(http_tests.EnrollmentHTTPTests):
    def test_real_trust_persistence(self):
        key = paramiko.RSAKey.generate(1024)
        with mock.patch.object(self.module, 'ssh_trust', ssh_trust), \
             mock.patch.object(ssh_trust, 'probe', return_value=key), \
             mock.patch.object(ssh_trust, 'system_keys', return_value=paramiko.HostKeys()):
            token = self.client.post('/api/servers/0/ssh-trust/inspect').json()['token']
            response = self.client.post('/api/servers/0/ssh-trust/confirm',
                                        json={'token': token, 'confirmed': True})
            self.assertEqual(response.status_code, 200, response.text)
            keys = paramiko.HostKeys(os.environ['SSH_KNOWN_HOSTS_FILE'])
            self.assertEqual(keys.lookup('example.test')['ssh-rsa'], key)
            self.drop.assert_called_once_with(self.server)

    def test_cancelled_confirmation_keeps_lock_and_finishes(self):
        started, release = threading.Event(), threading.Event()
        def enroll(*args, **kwargs):
            started.set()
            if not release.wait(5):
                raise TimeoutError('worker not released')
            return {'status': 'success'}
        self.trust.commit_enrollment.side_effect = enroll
        async def run():
            request = Request({'type': 'http', 'headers': []})
            task = asyncio.create_task(self.module.api_ssh_trust_confirm(request, 0,
                self.module.SSHTrustConfirmation(token='abc', confirmed=True)))
            waiter = None
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                waiter = asyncio.create_task(self.data_lock.acquire())
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(.02)
                    self.assertFalse(task.done())
                    self.assertFalse(waiter.done())
                self.assertTrue(self.data_lock.locked())
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                if waiter is not None:
                    await waiter
                    self.data_lock.release()
            self.drop.assert_called_once_with(self.server)
        asyncio.run(run())

    def test_edit_delete_wait_for_same_lock(self):
        self.server.update(username='root', password='test-only')
        data = {'servers': [self.server], 'user_connections': []}
        async def run(action):
            request = Request({'type': 'http', 'headers': []})
            async with self.data_lock:
                if action == 'edit':
                    coro = self.module.api_edit_server(request, 0,
                        self.module.EditServerRequest(name='renamed'))
                else:
                    coro = self.module.api_delete_server(request, 0)
                task = asyncio.create_task(coro)
                await asyncio.sleep(.05)
                self.assertFalse(task.done())
                save.assert_not_called()
            result = await task
            self.assertEqual(result['status'], 'success')
            save.assert_called_once()
        with mock.patch.object(self.module, 'load_data', return_value=data), \
             mock.patch.object(self.module, 'save_data') as save, \
             mock.patch.object(self.module, 'SSHManager') as ssh, \
             mock.patch.object(self.module.exit_link_svc, 'forget_entry_peers', new=mock.AsyncMock(return_value=[])):
            ssh.return_value.test_connection.return_value = {}
            asyncio.run(run('edit'))
            self.assertEqual(self.server['name'], 'renamed')
            save.reset_mock()
            self.data_lock = self.module.DATA_LOCK = asyncio.Lock()
            asyncio.run(run('delete'))
            self.assertEqual(data['servers'], [])
