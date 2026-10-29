"""Synthetic HTTP onboarding and deterministic inventory races; never real nodes."""
import asyncio
import contextlib
import importlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import paramiko
from fastapi.testclient import TestClient
from starlette.requests import Request
from managers import ssh_trust


@contextlib.contextmanager
def local_ssh(key, family=socket.AF_INET):
    """Multiple real KEX sessions, with an observable password-auth boundary."""
    listener = socket.socket(family)
    host = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    listener.bind((host, 0))
    listener.listen(8)
    listener.settimeout(.1)
    stop = threading.Event()
    threads, transports = [], []
    class Auth(paramiko.ServerInterface):
        calls = 0
        allowed = True
        def check_auth_password(self, username, password):
            self.calls += 1
            return paramiko.AUTH_SUCCESSFUL if self.allowed else paramiko.AUTH_FAILED
    auth = Auth()
    def session(conn):
        transport = paramiko.Transport(conn)
        transports.append(transport)
        try:
            transport.add_server_key(key)
            transport.start_server(server=auth)
            stop.wait(5)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()
    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=session, args=(conn,), daemon=True)
            threads.append(thread)
            thread.start()
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield {'host': host, 'ssh_port': listener.getsockname()[1]}, auth
    finally:
        stop.set()
        listener.close()
        for transport in transports:
            transport.close()
        worker.join(3)
        for thread in threads:
            thread.join(3)
        if worker.is_alive() or any(t.is_alive() for t in threads):
            raise AssertionError('local SSH fixture did not stop')


class OnboardingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other = paramiko.ECDSAKey.generate(), paramiko.ECDSAKey.generate()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'data.json'
        self.store = self.root / 'ssh_known_hosts'
        env = mock.patch.dict(os.environ, {'DATA_FILE': str(self.path),
            'TUNNEL_STATE_FILE': str(self.root / 'tunnels.json'),
            'SSH_KNOWN_HOSTS_FILE': str(self.store)})
        env.start()
        self.addCleanup(env.stop)
        self.app = importlib.import_module('app')
        self.user = {'role': 'admin'}
        self.endpoint = {'host': 'node.example.test', 'ssh_port': 2222}
        self.server = dict(self.endpoint, uid='a', username='synthetic', password='fixture',
                           protocols={'awg': {'installed': True, 'exit_node': {'server_uid': 'exit'}}})
        self.write([])
        self.drop = mock.Mock()
        self.probe = mock.patch.object(ssh_trust, 'probe', return_value=self.key)
        for patch in [mock.patch.object(self.app, 'DATA_FILE', str(self.path)),
                      mock.patch.object(self.app, 'DATA_LOCK', asyncio.Lock()),
                      mock.patch.object(self.app, '_check_admin', lambda request: self.user),
                      mock.patch.object(self.app, 'drop_ssh', self.drop),
                      mock.patch.object(ssh_trust, 'system_keys', return_value=paramiko.HostKeys()), self.probe]:
            patch.start()
            self.addCleanup(patch.stop)
        self.client = TestClient(self.app.app)
        self.addCleanup(self.client.close)

    def write(self, servers, **extra):
        self.path.write_text(json.dumps(dict(servers=servers, users=[], user_connections=[], **extra)))

    def read(self):
        return json.loads(self.path.read_text())

    def inspect(self, endpoint=None):
        return self.client.post('/api/ssh-trust/onboarding/inspect', json=endpoint or self.endpoint)

    def confirm(self, candidate, endpoint=None, **extra):
        return self.client.post('/api/ssh-trust/onboarding/confirm',
            json=dict(endpoint or self.endpoint, token=candidate['token'], confirmed=True, **extra))

    def candidate(self, endpoint=None):
        response = self.inspect(endpoint)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_unknown_add_real_handshake_enroll_then_authenticate(self):
        self.probe.stop()
        self.store.write_text('')
        with local_ssh(self.key) as (endpoint, auth), \
             mock.patch.object(self.app.SSHManager, 'test_connection', return_value={'os': 'synthetic'}):
            body = dict(endpoint, username='synthetic', password='fixture')
            rejected = self.client.post('/api/servers/add', json=body)
            self.assertEqual(rejected.status_code, 400)
            self.assertIn('known_hosts', rejected.json()['error'])
            self.assertEqual(auth.calls, 0)
            self.assertEqual(self.read()['servers'], [])
            # Legacy enrollment cannot inspect an absent inventory entry.
            self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect').status_code, 404)
            candidate = self.candidate(endpoint)
            self.assertEqual(candidate['status'], 'unknown')
            self.assertEqual(self.confirm(candidate, endpoint).status_code, 200)
            self.assertEqual(auth.calls, 0)  # Both probes never attempted auth.
            self.assertEqual(self.read()['servers'], [])
            response = self.client.post('/api/servers/add', json=body)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(auth.calls, 1)
            self.assertEqual(self.read()['servers'][0]['host'], endpoint['host'])

    def test_edit_new_endpoint_enrollment_preserves_uid_connections_and_links(self):
        self.write([dict(self.server, host='old.example.test')])
        data = self.read()
        data['user_connections'] = [{'user_id': 'u', 'server_id': 0, 'client_id': 'c'}]
        self.path.write_text(json.dumps(data))
        self.probe.stop()
        self.store.write_text('')
        with local_ssh(self.key) as (endpoint, auth), \
             mock.patch.object(self.app.SSHManager, 'test_connection', return_value={}):
            rejected = self.client.post('/api/servers/0/edit?server_uid=a', json=endpoint)
            self.assertEqual(rejected.status_code, 400)
            self.assertEqual(self.read()['servers'][0]['host'], 'old.example.test')
            draft = dict(endpoint, server_uid='a')
            self.assertEqual(self.confirm(self.candidate(draft), draft).status_code, 200)
            self.assertEqual(auth.calls, 0)
            result = self.client.post('/api/servers/0/edit?server_uid=a', json=endpoint)
            self.assertEqual(result.status_code, 200, result.text)
        current = self.read()
        self.assertEqual(current['servers'][0]['uid'], 'a')
        self.assertEqual(current['servers'][0]['protocols'], self.server['protocols'])
        self.assertEqual(current['user_connections'], data['user_connections'])
        self.drop.assert_called_with(mock.ANY)
        self.assertEqual(self.drop.call_args.args[0]['host'], 'old.example.test')

    def test_already_trusted_endpoint_reports_saved_trust_not_auth(self):
        candidate = self.candidate()
        result = self.confirm(candidate)
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.json()['ssh_authenticated'])
        self.assertEqual(self.candidate()['status'], 'trusted')

    def test_admin_origin_and_explicit_confirmation(self):
        candidate = self.candidate()
        for user in [None, {'role': 'support'}, {'role': 'user'}]:
            self.user = user
            self.assertEqual(self.inspect().status_code, 403)
            self.assertEqual(self.confirm(candidate).status_code, 403)
        self.user = {'role': 'admin'}
        for headers in [{'Origin': 'https://evil.example'}, {'Sec-Fetch-Site': 'cross-site'},
                        {'Origin': 'null'}, {'Sec-Fetch-Site': 'same-site'}]:
            self.assertEqual(self.client.post('/api/ssh-trust/onboarding/inspect',
                            json=self.endpoint, headers=headers).status_code, 403)
        response = self.client.post('/api/ssh-trust/onboarding/confirm',
            json=dict(self.endpoint, token=candidate['token'], confirmed=False))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.store.exists())

    def test_inspect_rejects_auth_material_and_invalid_endpoints(self):
        for extra in [{'password': 'fixture'}, {'private_key': 'fixture'}, {'username': 'fixture'}]:
            self.assertEqual(self.inspect(dict(self.endpoint, **extra)).status_code, 422)
        for host in ['', 'x\nline', 'x/y', 'x:22', '[::1]', '-bad', 'x..test', 'x\x00y']:
            with self.subTest(host=host):
                self.assertIn(self.inspect(dict(self.endpoint, host=host)).status_code, (409, 422))
        for port in [0, 65536, True, 22.5, '22']:
            self.assertEqual(self.inspect(dict(self.endpoint, ssh_port=port)).status_code, 422)

    def test_key_changed_after_inspect_and_expired_or_invalid_tokens(self):
        candidate = self.candidate()
        with mock.patch.object(ssh_trust, 'probe', return_value=self.other):
            self.assertEqual(self.confirm(candidate).status_code, 409)
        for token in ['bad', candidate['token'] + 'x']:
            self.assertEqual(self.confirm(dict(candidate, token=token)).status_code, 409)
        with mock.patch.object(ssh_trust.time, 'time', return_value=10**12):
            self.assertEqual(self.confirm(candidate).status_code, 409)
        self.assertFalse(self.store.exists())

    def test_endpoint_or_saved_settings_changed_after_inspect(self):
        candidate = self.candidate()
        self.assertEqual(self.confirm(candidate, dict(self.endpoint, host='other.example.test')).status_code, 409)
        self.write([self.server])
        draft = dict(self.endpoint, server_uid='a')
        candidate = self.candidate(draft)
        self.write([dict(self.server, password='new-fixture')])
        self.assertEqual(self.confirm(candidate, draft).status_code, 409)
        self.assertNotIn('fixture', candidate['token'])
        self.assertFalse(self.store.exists())

    def test_changed_key_rotation_and_system_conflict(self):
        keys = paramiko.HostKeys()
        name = ssh_trust.host_name(**{'host': self.endpoint['host'], 'port': self.endpoint['ssh_port']})
        keys.add(name, self.other.get_name(), self.other)
        keys.save(str(self.store))
        candidate = self.candidate()
        self.assertEqual(candidate['status'], 'changed')
        self.assertEqual(candidate['old_fingerprints'][0]['fingerprint'], ssh_trust.fingerprint(self.other))
        self.assertEqual(self.confirm(candidate).status_code, 200)
        self.assertTrue(paramiko.HostKeys(str(self.store)).check(name, self.key))
        with mock.patch.object(ssh_trust, 'system_keys', return_value=keys):
            candidate = self.candidate()
            self.assertEqual(candidate['status'], 'changed')
            self.assertEqual(self.confirm(candidate).status_code, 409)

    def test_same_endpoint_concurrent_confirmation_rejects_stale_trust_snapshot(self):
        first, second = self.candidate(), self.candidate()
        self.assertEqual(self.confirm(first).status_code, 200)
        before = self.store.read_bytes()
        self.assertEqual(self.confirm(second).status_code, 409)
        self.assertEqual(self.store.read_bytes(), before)

    def test_readonly_and_malformed_trust_preserve_inventory(self):
        self.store.write_text('')
        candidate = self.candidate()
        self.store.chmod(0o444)
        try:
            self.assertEqual(self.confirm(candidate).status_code, 409)
        finally:
            self.store.chmod(0o600)
        self.store.write_text('node ssh-rsa !invalid!\n')
        self.assertEqual(self.inspect().status_code, 409)
        self.assertEqual(self.read()['servers'], [])

    def test_bad_auth_keeps_inventory_and_explicit_trust(self):
        self.assertEqual(self.confirm(self.candidate()).status_code, 200)
        before = self.store.read_bytes()
        with mock.patch.object(self.app, 'SSHManager') as manager:
            manager.return_value.connect.side_effect = paramiko.AuthenticationException('Authentication failed')
            response = self.client.post('/api/servers/add', json=dict(self.endpoint, username='fixture', password='bad'))
            self.assertEqual(response.status_code, 400)
            manager.return_value.disconnect.assert_called_once()
        self.assertEqual(self.read()['servers'], [])
        # An independently approved pin survives an auth failure; it is not a
        # transactional credential and deleting it could erase another approval.
        self.assertEqual(self.store.read_bytes(), before)

    def test_persistent_default_path_and_unrelated_hashed_entries(self):
        name = ssh_trust.host_name(self.endpoint['host'], self.endpoint['ssh_port'])
        self.store.write_text(paramiko.HostKeys.hash_host('other.example.test') + ' ' +
                              self.other.get_name() + ' ' + self.other.get_base64() + '\n')
        self.assertEqual(self.confirm(self.candidate()).status_code, 200)
        keys = paramiko.HostKeys(str(self.store))
        self.assertTrue(keys.check(name, self.key))
        self.assertTrue(keys.check('other.example.test', self.other))
        with mock.patch.dict(os.environ) as env:
            env.pop('SSH_KNOWN_HOSTS_FILE', None)
            env['DATA_FILE'] = '/app/data/data.json'
            self.assertEqual(Path(ssh_trust.trust_path()).name, 'ssh_known_hosts')
            self.assertEqual(Path(ssh_trust.trust_path()).parent, Path('/app/data').absolute())

    def test_ipv6_real_inspection_without_auth_if_supported(self):
        self.probe.stop()
        try:
            with local_ssh(self.key, socket.AF_INET6) as (endpoint, auth):
                candidate = self.candidate(endpoint)
                self.assertEqual(self.confirm(candidate, endpoint).status_code, 200)
                self.assertEqual(auth.calls, 0)
        except OSError as exc:
            self.skipTest(f'IPv6 loopback unavailable: {type(exc).__name__}')

    def test_edit_stale_uid_and_missing_inventory_draft_rejected(self):
        self.write([self.server])
        self.assertEqual(self.inspect(dict(self.endpoint, server_uid='missing')).status_code, 409)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect?server_uid=stale').status_code, 409)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm?server_uid=stale',
                         json={'token': 'unused', 'confirmed': True}).status_code, 409)
        with mock.patch.object(self.app, 'SSHManager') as manager:
            result = self.client.post('/api/servers/0/edit?server_uid=other', json=self.endpoint)
            self.assertEqual(result.status_code, 409)
            manager.assert_not_called()

    def test_edit_during_probe_rejected_without_trust_write_and_lock_is_free(self):
        self.write([self.server])
        draft = dict(self.endpoint, server_uid='a')
        candidate = self.candidate(draft)
        def probe(*args):
            self.assertFalse(self.app.DATA_LOCK.locked())
            self.write([dict(self.server, host='changed.example.test')])
            return self.key
        with mock.patch.object(ssh_trust, 'probe', side_effect=probe):
            self.assertEqual(self.confirm(candidate, draft).status_code, 409)
        self.assertFalse(self.store.exists())

    def test_edit_and_reorder_merge_latest_state_without_holding_lock_for_ssh(self):
        self.write([self.server, dict(self.server, uid='b', host='b.example.test')])
        started, release = threading.Event(), threading.Event()
        def verify():
            self.assertFalse(self.app.DATA_LOCK.locked())
            started.set()
            if not release.wait(5):
                raise TimeoutError('fixture not released')
            return {}
        async def run():
            request = Request({'type': 'http', 'headers': []})
            task = asyncio.create_task(self.app.api_edit_server(request, 0,
                self.app.EditServerRequest(name='renamed'), server_uid='a'))
            reorder = None
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                reorder = asyncio.create_task(self.app.api_reorder_servers(request,
                    self.app.ReorderServersRequest(order=[1, 0])))
                await asyncio.sleep(0)  # Dispatch; #231 can serialize this behind edit.
                async with self.app.DATA_LOCK:
                    data = self.app.load_data()
                    data['users'] = [{'id': 'new-independent-user'}]
                    idx = next(i for i, s in enumerate(data['servers']) if s['uid'] == 'a')
                    data['user_connections'] = [{'server_id': idx, 'client_id': 'new'}]
                    self.app.save_data(data)
            finally:
                release.set()
            self.assertEqual((await task)['status'], 'success')
            self.assertEqual((await reorder)['status'], 'success')
        with mock.patch.object(self.app, 'SSHManager') as manager:
            manager.return_value.test_connection.side_effect = verify
            asyncio.run(run())
        data = self.read()
        self.assertEqual([s['uid'] for s in data['servers']], ['b', 'a'])
        self.assertEqual(data['servers'][1]['name'], 'renamed')
        self.assertEqual(data['servers'][1]['ssh_port'], 2222)
        self.assertEqual(data['user_connections'], [{'server_id': 1, 'client_id': 'new'}])
        self.assertEqual(data['users'], [{'id': 'new-independent-user'}])

    def test_cancelled_add_cannot_publish_late_inventory(self):
        started, release = threading.Event(), threading.Event()
        def connect():
            started.set()
            if not release.wait(5):
                raise TimeoutError('fixture not released')
        async def run():
            request = Request({'type': 'http', 'headers': []})
            task = asyncio.create_task(self.app.api_add_server(request,
                self.app.AddServerRequest(**self.endpoint, username='synthetic', password='fixture')))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                release.set()
        with mock.patch.object(self.app, 'SSHManager') as manager:
            manager.return_value.connect.side_effect = connect
            asyncio.run(run())  # Shuts down executor: verify/disconnect is finished.
            manager.return_value.disconnect.assert_called_once()
        self.assertEqual(self.read()['servers'], [])

    def test_failed_add_save_retains_inventory_and_disconnects(self):
        before = self.path.read_bytes()
        with mock.patch.object(self.app, 'SSHManager') as manager, \
             mock.patch.object(self.app, 'save_data', side_effect=OSError('synthetic disk failure')):
            response = self.client.post('/api/servers/add', json=dict(self.endpoint, username='synthetic', password='fixture'))
            self.assertEqual(response.status_code, 500)
            manager.return_value.disconnect.assert_called_once()
        self.assertEqual(self.path.read_bytes(), before)

    def test_edit_deleted_or_changed_during_auth_is_not_published(self):
        for replacement in [[], [dict(self.server, host='changed.example.test')]]:
            with self.subTest(replacement=replacement):
                self.write([self.server])
                def verify():
                    self.write(replacement)
                    return {}
                with mock.patch.object(self.app, 'SSHManager') as manager:
                    manager.return_value.test_connection.side_effect = verify
                    result = self.client.post('/api/servers/0/edit?server_uid=a', json=self.endpoint)
                    self.assertEqual(result.status_code, 409)
                    manager.return_value.disconnect.assert_called_once()
                self.assertEqual(self.read()['servers'], replacement)

    def test_expiry_is_checked_again_at_short_commit(self):
        endpoint = dict(self.endpoint, uid=None, enrollment_context='new-server')
        candidate = self.candidate()
        key = ssh_trust.prepare_enrollment(endpoint, candidate['token'])
        with mock.patch.object(ssh_trust.time, 'time', return_value=10**12):
            with self.assertRaisesRegex(ValueError, 'expired'):
                ssh_trust.commit_enrollment(endpoint, candidate['token'], key)
        self.assertFalse(self.store.exists())

    def test_inspect_rejects_inventory_changed_during_probe(self):
        self.write([self.server])
        def probe(*args):
            self.assertFalse(self.app.DATA_LOCK.locked())
            self.write([])
            return self.key
        with mock.patch.object(ssh_trust, 'probe', side_effect=probe):
            self.assertEqual(self.inspect(dict(self.endpoint, server_uid='a')).status_code, 409)
        self.assertFalse(self.store.exists())

    def test_cancelled_trust_commit_retains_lock_until_atomic_write_finishes(self):
        candidate = self.candidate()
        started, release = threading.Event(), threading.Event()
        original = ssh_trust.commit_enrollment
        def commit(*args, **kwargs):
            self.assertTrue(self.app.DATA_LOCK.locked())
            started.set()
            if not release.wait(5):
                raise TimeoutError('fixture not released')
            return original(*args, **kwargs)
        async def run():
            request = Request({'type': 'http', 'headers': []})
            req = self.app.SSHOnboardingConfirmation(**self.endpoint, token=candidate['token'], confirmed=True)
            task = asyncio.create_task(self.app.api_ssh_onboarding_confirm(request, req))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                task.cancel()
                # Event-loop barrier, not a timing-based concurrency assertion.
                await asyncio.sleep(0)
                self.assertTrue(self.app.DATA_LOCK.locked())
                self.assertFalse(task.done())
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        with mock.patch.object(ssh_trust, 'commit_enrollment', side_effect=commit):
            asyncio.run(run())
        self.assertTrue(self.store.exists())
        self.assertEqual(self.read()['servers'], [])
