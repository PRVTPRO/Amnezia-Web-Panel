"""SSH credential encryption, migration and portability regressions."""
import json
from pathlib import Path
import tempfile
import unittest

from credential_store import (
    CredentialError,
    CredentialStore,
    contains_plaintext_ssh_credentials,
)


PASSWORD = 'SYNTHETIC-SSH-PASSWORD-DO-NOT-STORE'
PRIVATE_KEY = '-----BEGIN SYNTHETIC PRIVATE KEY-----\nsecret-key-body\n-----END SYNTHETIC PRIVATE KEY-----'


def document(password=PASSWORD, private_key=PRIVATE_KEY):
    return {
        'users': [],
        'user_connections': [],
        'settings': {},
        'servers': [{
            'uid': 'server-a', 'host': '192.0.2.10', 'ssh_port': 22,
            'username': 'root', 'password': password,
            'private_key': private_key, 'protocols': {},
        }],
    }


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'credential.key'
        self.store = CredentialStore(self.key)

    def test_legacy_document_is_sealed_without_plaintext_and_round_trips(self):
        data = document()
        changed = self.store.seal_document(data)
        self.assertTrue(changed)
        server = data['servers'][0]
        self.assertNotIn('password', server)
        self.assertNotIn('private_key', server)
        self.assertIn('ssh_credentials', server)
        raw = json.dumps(data)
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn('secret-key-body', raw)
        self.assertFalse(contains_plaintext_ssh_credentials(data))
        self.assertEqual(self.store.resolve(server), (PASSWORD, PRIVATE_KEY))

    def test_migration_is_idempotent_and_tamper_or_rebinding_fails_closed(self):
        data = document()
        self.store.seal_document(data)
        envelope = json.loads(json.dumps(data['servers'][0]['ssh_credentials']))
        self.assertFalse(self.store.seal_document(data))
        self.assertEqual(data['servers'][0]['ssh_credentials'], envelope)

        tampered = json.loads(json.dumps(data['servers'][0]))
        value = tampered['ssh_credentials']['ciphertext']
        tampered['ssh_credentials']['ciphertext'] = ('A' if value[0] != 'A' else 'B') + value[1:]
        with self.assertRaises(CredentialError):
            self.store.resolve(tampered)

        rebound = json.loads(json.dumps(data['servers'][0]))
        rebound['uid'] = 'server-b'
        with self.assertRaises(CredentialError):
            self.store.resolve(rebound)

    def test_existing_key_reopens_state_and_different_key_cannot(self):
        data = document()
        self.store.seal_document(data)
        reopened = CredentialStore(self.key)
        self.assertEqual(reopened.resolve(data['servers'][0]), (PASSWORD, PRIVATE_KEY))

        other = CredentialStore(self.root / 'other.key')
        with self.assertRaises(CredentialError):
            other.resolve(data['servers'][0])

    def test_key_file_is_not_created_until_encryption_is_needed(self):
        empty = document('', '')
        self.store.seal_document(empty)
        self.assertFalse(self.key.exists())
        self.store.seal_document(document())
        self.assertTrue(self.key.is_file())

    def test_legacy_server_without_uid_gets_stable_identity_before_sealing(self):
        data = document()
        data['servers'][0].pop('uid')
        self.assertTrue(self.store.seal_document(data))
        server = data['servers'][0]
        self.assertTrue(server['uid'])
        self.assertEqual(self.store.resolve(server), (PASSWORD, PRIVATE_KEY))

    def test_portable_export_rewraps_for_another_installation(self):
        data = document()
        self.store.seal_document(data)
        portable = self.store.export_portable_document(data)
        self.assertIn('password', portable['servers'][0])
        self.assertIn('private_key', portable['servers'][0])
        self.assertNotIn('ssh_credentials', portable['servers'][0])

        destination = CredentialStore(self.root / 'destination.key')
        destination.seal_document(portable)
        self.assertEqual(destination.resolve(portable['servers'][0]), (PASSWORD, PRIVATE_KEY))
        self.assertNotEqual(
            portable['servers'][0]['ssh_credentials'],
            data['servers'][0]['ssh_credentials'],
        )


if __name__ == '__main__':
    unittest.main()
