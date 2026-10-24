"""HTTP authorization and explicit confirmation, without loading real state."""
import asyncio
import importlib
import os
import tempfile

import unittest
from pathlib import Path

from unittest import mock

from fastapi.testclient import TestClient
from managers import ssh_trust


class EnrollmentHTTPTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        env = mock.patch.dict(os.environ, {'DATA_FILE': str(root / 'data.json'),
            'TUNNEL_STATE_FILE': str(root / 'tunnels.json'),
            'SSH_KNOWN_HOSTS_FILE': str(root / 'known_hosts')})
        env.start()
        self.addCleanup(env.stop)
        self.module = importlib.import_module('app')
        self.user = {'role': 'admin'}
        self.server = {'host': 'example.test', 'ssh_port': 22, 'uid': 'a'}
        self.trust = mock.Mock()
        self.trust.inspect.return_value = {'status': 'unknown', 'token': 'abc'}
        self.trust.enroll.return_value = {'status': 'success'}
        self.drop = mock.Mock()
        self.data_lock = asyncio.Lock()
        for name, value in [('DATA_LOCK', self.data_lock), ('ssh_trust', self.trust),
                            ('_check_admin', lambda request: self.user),
                            ('load_data', lambda: {'servers': [self.server]}),
                            ('drop_ssh', self.drop)]:
            patch = mock.patch.object(self.module, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.client = TestClient(self.module.app)
        self.addCleanup(self.client.close)

    def test_admin_only(self):
        for user in [None, {'role': 'support'}, {'role': 'user'}]:
            self.user = user
            for action in ['inspect', 'confirm']:
                response = self.client.post('/api/servers/0/ssh-trust/' + action,
                                            json={'token': 'abc', 'confirmed': True})
                self.assertEqual(response.status_code, 403)
        self.trust.inspect.assert_not_called()
        self.trust.enroll.assert_not_called()

    def test_confirmation_and_reset(self):
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect').status_code, 200)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': False}).status_code, 400)
        self.trust.enroll.assert_not_called()
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': True}).status_code, 200)
        self.drop.assert_called_once_with(self.server)

    def test_confirmation_serializes_endpoint_mutations(self):
        def enroll(*args, **kwargs):
            self.assertTrue(self.data_lock.locked())
            return {'status': 'success'}
        self.trust.enroll.side_effect = enroll
        response = self.client.post('/api/servers/0/ssh-trust/confirm',
                                    json={'token': 'abc', 'confirmed': True})
        self.assertEqual(response.status_code, 200, response.text)

    def test_errors(self):
        # Browser Fetch Metadata is not script-settable. TLS termination may
        # leave request.base_url as HTTP while the browser origin is HTTPS.
        response = self.client.post('/api/servers/0/ssh-trust/inspect',
                                    headers={'Origin': 'https://testserver', 'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.post('/api/servers/0/ssh-trust/inspect', headers={'Origin': 'https://evil.example'}).status_code, 403)
        self.assertEqual(self.client.post('/api/servers/-1/ssh-trust/inspect').status_code, 404)
        for body in [{}, {'token': '', 'confirmed': True}, {'token': 'abc', 'confirmed': 'yes'}]:
            self.assertEqual(self.client.post('/api/servers/0/ssh-trust/confirm', json=body).status_code, 422)
        self.trust.enroll.side_effect = ValueError('candidate changed')
        response = self.client.post('/api/servers/0/ssh-trust/confirm', json={'token': 'abc', 'confirmed': True})
        self.assertEqual(response.status_code, 409)
        self.drop.assert_not_called()
