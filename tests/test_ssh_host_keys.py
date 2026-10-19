"""Real loopback SSH handshakes: host trust must precede authentication."""
import contextlib
import io
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import paramiko

from managers.ssh_manager import SSHManager


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.auth_calls = 0

    def check_auth_password(self, username, password):
        self.auth_calls += 1
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.auth_calls += 1
        return paramiko.AUTH_SUCCESSFUL


@contextlib.contextmanager
def endpoint(key):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(4)
    port = listener.getsockname()[1]
    server = Server()
    stop = threading.Event()
    transports = []

    def serve():
        try:
            conn, _ = listener.accept()
            transport = paramiko.Transport(conn)
            transports.append(transport)
            transport.add_server_key(key)
            transport.start_server(server=server)
            stop.wait(4)
        except (OSError, EOFError, paramiko.SSHException):
            pass  # A rejected host key intentionally closes the transport.
        finally:
            for transport in transports:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, server
    finally:
        stop.set()
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(5)
        if thread.is_alive():
            raise AssertionError('loopback SSH fixture did not stop')


class HostKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.ECDSAKey.generate()
        cls.other = paramiko.ECDSAKey.generate()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Path(self.tmp.name) / 'known_hosts'
        self.store.write_text('')
        self.patch = mock.patch.dict(os.environ, {'SSH_KNOWN_HOSTS_FILE': str(self.store)})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def trust(self, port, key):
        keys = paramiko.HostKeys()
        keys.add('[127.0.0.1]:%d' % port, key.get_name(), key)
        keys.save(str(self.store))

    def manager(self, port, **kwargs):
        return SSHManager('127.0.0.1', port, 'synthetic', **kwargs)

    def test_unknown_key_rejected_before_auth_and_store_unchanged(self):
        before = self.store.read_bytes()
        with endpoint(self.key) as (port, server):
            manager = self.manager(port, password='synthetic')
            with self.assertRaises(paramiko.SSHException):
                manager.connect()
            self.assertEqual(server.auth_calls, 0)
            self.assertIsNone(manager.client)
            self.assertEqual(manager._connect_fail_count, 1)
        self.assertEqual(self.store.read_bytes(), before)

    def test_trusted_key_accepts_password_auth(self):
        with endpoint(self.key) as (port, server):
            self.trust(port, self.key)
            manager = self.manager(port, password='synthetic')
            try:
                self.assertTrue(manager.connect())
                self.assertGreater(server.auth_calls, 0)
            finally:
                manager.force_disconnect()

    def test_trusted_key_accepts_private_key_auth(self):
        auth_key = paramiko.RSAKey.generate(1024)
        buffer = io.StringIO()
        auth_key.write_private_key(buffer)
        with endpoint(self.key) as (port, server):
            self.trust(port, self.key)
            manager = self.manager(port, private_key=buffer.getvalue())
            try:
                self.assertTrue(manager.connect())
                self.assertGreater(server.auth_calls, 0)
            finally:
                manager.force_disconnect()

    def test_mitm_changed_key_rejected_before_auth(self):
        with endpoint(self.other) as (port, server):
            self.trust(port, self.key)
            before = self.store.read_bytes()
            manager = self.manager(port, password='synthetic')
            with self.assertRaises(paramiko.BadHostKeyException):
                manager.connect()
            self.assertEqual(server.auth_calls, 0)
            self.assertIsNone(manager.client)
            self.assertEqual(self.store.read_bytes(), before)

    def test_rotation_requires_explicit_trusted_store_update(self):
        with endpoint(self.other) as (port, server):
            self.trust(port, self.key)
            manager = self.manager(port, password='synthetic')
            with self.assertRaises(paramiko.BadHostKeyException):
                manager.connect()
            self.assertEqual(server.auth_calls, 0)
        # Operator independently verifies the replacement key before this edit.
        with endpoint(self.other) as (port, server):
            self.trust(port, self.other)
            manager = self.manager(port, password='synthetic')
            try:
                self.assertTrue(manager.connect())
                self.assertGreater(server.auth_calls, 0)
            finally:
                manager.force_disconnect()

    def test_missing_explicit_store_fails_before_connect(self):
        self.store.unlink()
        with mock.patch.object(paramiko.SSHClient, 'connect') as connect:
            with self.assertRaises(OSError):
                self.manager(2222, password='synthetic').connect()
            connect.assert_not_called()

    def test_malformed_store_fails_before_connect(self):
        self.store.write_text('synthetic ssh-rsa not-valid-base64!!!\n')
        with mock.patch.object(paramiko.SSHClient, 'connect') as connect:
            with self.assertRaises(paramiko.hostkeys.InvalidHostKey):
                self.manager(2222, password='synthetic').connect()
            connect.assert_not_called()

    def test_system_trust_and_persistent_default_are_loaded(self):
        data = Path(self.tmp.name) / 'data.json'
        default_store = data.with_name('ssh_known_hosts')
        default_store.write_text('')
        with mock.patch.dict(os.environ, {'DATA_FILE': str(data)}), \
                mock.patch.dict(os.environ) as env, \
                mock.patch('managers.ssh_manager.paramiko.SSHClient') as client:
            env.pop('SSH_KNOWN_HOSTS_FILE', None)
            manager = self.manager(2222, password='synthetic')
            manager.connect()
            client.return_value.load_system_host_keys.assert_called_once_with()
            client.return_value.load_host_keys.assert_called_once_with(str(default_store))
            policy = client.return_value.set_missing_host_key_policy.call_args.args[0]
            self.assertIsInstance(policy, paramiko.RejectPolicy)
            manager.force_disconnect()

    def test_connection_failure_keeps_store(self):
        before = self.store.read_bytes()
        with mock.patch.object(paramiko.SSHClient, 'connect', side_effect=OSError('synthetic reset')):
            manager = self.manager(2222, password='synthetic')
            with self.assertRaises(OSError):
                manager.connect()
            self.assertIsNone(manager.client)
            self.assertEqual(manager._connect_fail_count, 1)
        self.assertEqual(self.store.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
