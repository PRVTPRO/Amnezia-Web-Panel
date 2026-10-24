"""Enrollment never authenticates; confirmations bind endpoint and exact key."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import paramiko
from managers import ssh_trust
from tests.test_ssh_host_keys import endpoint


class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(1024)
        cls.other = paramiko.RSAKey.generate(1024)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'known_hosts'
        self.env = mock.patch.dict(os.environ, {'SSH_KNOWN_HOSTS_FILE': str(self.path)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.system = mock.patch.object(ssh_trust, 'system_keys', return_value=paramiko.HostKeys())
        self.system.start()
        self.addCleanup(self.system.stop)
        self.server = {'host': 'example.test', 'ssh_port': 2222, 'uid': 'one'}

    def candidate(self):
        with mock.patch.object(ssh_trust, 'probe', return_value=self.key):
            return ssh_trust.inspect(self.server)

    def confirm(self, candidate, server=None):
        with mock.patch.object(ssh_trust, 'probe', return_value=self.key):
            return ssh_trust.enroll(server or self.server, candidate['token'])

    def test_probe_real_handshake_without_auth(self):
        with endpoint(self.key) as (port, service):
            self.assertEqual(ssh_trust.probe('127.0.0.1', port), self.key)
            self.assertEqual(service.auth_calls, 0)

    def test_probe_matches_client_pinned_algorithm_preference(self):
        # ECDSA normally wins over RSA, but SSHClient prefers the stored RSA pin.
        preferred = paramiko.ECDSAKey.generate()
        with endpoint([self.key, preferred]) as (port, service):
            keys = paramiko.HostKeys()
            keys.add(f'[127.0.0.1]:{port}', 'ssh-rsa', self.key)
            keys.save(str(self.path))
            result = ssh_trust.inspect({'host': '127.0.0.1', 'ssh_port': port})
            self.assertEqual(result['status'], 'trusted')
            self.assertEqual(result['algorithm'], 'ssh-rsa')
            self.assertEqual(service.auth_calls, 0)

    def test_confirmation_rejects_concurrent_trust_change(self):
        candidate = self.candidate()
        keys = paramiko.HostKeys()
        keys.add('[example.test]:2222', 'ssh-rsa', self.other)
        keys.save(str(self.path))
        with self.assertRaisesRegex(ValueError, 'Trust changed'):
            self.confirm(candidate)
        self.assertEqual(paramiko.HostKeys(str(self.path)).lookup('[example.test]:2222')['ssh-rsa'], self.other)

    def test_list_status_never_contacts_server(self):
        with mock.patch.object(ssh_trust, 'probe', side_effect=AssertionError('network forbidden')):
            self.assertEqual(ssh_trust.saved_status(self.server), 'unknown')
            keys = paramiko.HostKeys()
            keys.add('[example.test]:2222', 'ssh-rsa', self.key)
            keys.save(str(self.path))
            self.assertEqual(ssh_trust.saved_status(self.server), 'trusted')

    def test_unknown_persistent_nonstandard_preserves_other_hosts(self):
        keys = paramiko.HostKeys()
        keys.add('unrelated', self.other.get_name(), self.other)
        keys.save(str(self.path))
        candidate = self.candidate()
        self.assertEqual(candidate['status'], 'unknown')
        self.assertEqual(candidate['old_fingerprints'], [])
        self.assertTrue(candidate['fingerprint'].startswith('SHA256:'))
        self.confirm(candidate)
        saved = paramiko.HostKeys(str(self.path))
        self.assertEqual(saved['unrelated'][self.other.get_name()], self.other)
        self.assertEqual(saved['[example.test]:2222'][self.key.get_name()], self.key)
        self.assertEqual(self.candidate()['status'], 'trusted')

    def test_changed_hashed_entry(self):
        keys = paramiko.HostKeys()
        keys.add(paramiko.HostKeys.hash_host('[example.test]:2222'), self.other.get_name(), self.other)
        keys.save(str(self.path))
        candidate = self.candidate()
        self.assertEqual(candidate['status'], 'changed')
        self.assertEqual(candidate['old_fingerprints'][0]['fingerprint'], ssh_trust.fingerprint(self.other))
        self.confirm(candidate)
        self.assertTrue(paramiko.HostKeys(str(self.path)).check('[example.test]:2222', self.key))

    def test_race_and_endpoint_change_rejected(self):
        candidate = self.candidate()
        with mock.patch.object(ssh_trust, 'probe', return_value=self.other):
            with self.assertRaises(ValueError):
                ssh_trust.enroll(self.server, candidate['token'])
        with self.assertRaises(ValueError):
            self.confirm(candidate, dict(self.server, host='elsewhere'))
        self.assertFalse(self.path.exists())

    def test_invalid_expired_token(self):
        with self.assertRaises(ValueError):
            ssh_trust.enroll(self.server, 'invalid')
        candidate = self.candidate()
        with mock.patch.object(ssh_trust.time, 'time', return_value=10**12):
            with self.assertRaises(ValueError):
                self.confirm(candidate)

    def test_endpoint_edited_during_probe_is_rejected(self):
        candidate = self.candidate()
        with mock.patch.object(ssh_trust, 'probe', return_value=self.key):
            with self.assertRaisesRegex(ValueError, 'endpoint'):
                ssh_trust.enroll(self.server, candidate['token'], validate_endpoint=lambda: False)
        self.assertFalse(self.path.exists())

    def test_system_conflict_and_read_only_fail(self):
        candidate = self.candidate()
        system = paramiko.HostKeys()
        system.add('[example.test]:2222', self.other.get_name(), self.other)
        with mock.patch.object(ssh_trust, 'system_keys', return_value=system):
            with self.assertRaisesRegex(ValueError, 'system'):
                self.confirm(candidate)
        self.path.touch()
        self.path.chmod(0o444)
        try:
            with self.assertRaises(PermissionError):
                self.confirm(candidate)
        finally:
            self.path.chmod(0o600)

    def test_malformed_endpoint(self):
        for host, port in [('x\nline', 22), ('', 22), ('x', 0), ('x', 65536)]:
            with self.assertRaises(ValueError):
                ssh_trust.inspect({'host': host, 'ssh_port': port})

    def test_concurrent_writes_preserve_hosts_and_aliases(self):
        from concurrent.futures import ThreadPoolExecutor
        self.path.write_text('example.test,alias ssh-rsa ' + self.other.get_base64() + '\n')
        servers = [dict(self.server, host='node' + str(i), ssh_port=22) for i in range(8)]
        with mock.patch.object(ssh_trust, 'probe', return_value=self.key):
            candidates = [ssh_trust.inspect(server) for server in servers]
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda pair: ssh_trust.enroll(pair[0], pair[1]['token']), zip(servers, candidates)))
            server = dict(self.server, ssh_port=22)
            ssh_trust.enroll(server, ssh_trust.inspect(server)['token'])
        saved = paramiko.HostKeys(str(self.path))
        self.assertEqual(saved['alias']['ssh-rsa'], self.other)
        for server in servers:
            self.assertTrue(saved.check(server['host'], self.key))

    def test_failed_atomic_replace_preserves_file(self):
        self.path.write_text('other ssh-rsa ' + self.other.get_base64() + '\n')
        before = self.path.read_bytes()
        with mock.patch.object(ssh_trust.os, 'replace', side_effect=PermissionError('read-only mount')):
            with self.assertRaises(PermissionError):
                self.confirm(self.candidate())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob('.ssh-trust-*')), [])

    def test_path_uses_application_data(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            ssh_trust.configure(str(Path(self.tmp.name) / 'custom' / 'data.json'))
            self.assertEqual(ssh_trust.trust_path(), str(Path(self.tmp.name) / 'custom' / 'ssh_known_hosts'))
