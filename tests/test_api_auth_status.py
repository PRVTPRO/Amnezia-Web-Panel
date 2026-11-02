"""Real HTTP/session coverage for the panel's 401 versus 403 contract."""
import time
import hashlib
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import app as panel


class ApiAuthStatusTests(unittest.TestCase):
    def setUp(self):
        self.user = {'id': 'fixture-admin', 'username': 'fixture',
                     'password_hash': 'fixture', 'role': 'admin', 'enabled': True}
        self.data = {'users': [self.user], 'servers': [], 'user_connections': [],
                     'settings': {}}
        self.patch_data = patch.object(panel, 'load_data', return_value=self.data)
        self.patch_data.start()
        self.addCleanup(self.patch_data.stop)
        service_data = patch.object(panel.self_service_connections, 'load_data', return_value=self.data)
        service_data.start()
        self.addCleanup(service_data.stop)
        self.client = TestClient(panel.app)
        self.addCleanup(self.client.close)

    def login(self):
        with patch.object(panel, 'verify_password', return_value=True):
            response = self.client.post('/api/auth/login', json={
                'username': 'fixture', 'password': 'fixture'})
        self.assertEqual(response.status_code, 200)

    def test_missing_session_is_401_on_real_guarded_endpoints(self):
        for path in ('/api/settings/tunnels/status', '/api/my/connections/options'):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_expired_signed_session_is_401(self):
        # A correctly signed cookie whose timestamp exceeds SessionMiddleware's
        # default 14-day max_age; do not replace get_current_user with a stub.
        with patch.object(TimestampSigner, 'get_timestamp', return_value=int(time.time()) - 15 * 86400):
            self.login()
        self.assertEqual(self.client.get('/api/settings/tunnels/status').status_code, 401)

    def test_disabled_deleted_and_record_only_sessions_are_401(self):
        self.login()
        for change in ({'enabled': False}, {'enabled': True, 'role': 'none'}):
            self.user.update(change)
            self.assertEqual(self.client.get('/api/settings/tunnels/status').status_code, 401)
        self.data['users'] = []
        self.assertEqual(self.client.get('/api/settings/tunnels/status').status_code, 401)

    def test_authenticated_permission_and_disabled_feature_stay_403(self):
        self.login()
        self.assertEqual(self.client.get('/api/my/connections/options').status_code, 403)
        self.user['role'] = 'user'
        self.assertEqual(self.client.get('/api/settings/tunnels/status').status_code, 403)

    def test_bearer_denial_keeps_existing_contract(self):
        response = self.client.get('/api/settings/tunnels/status', headers={
            'Authorization': 'Bearer synthetic-invalid-token'})
        self.assertEqual(response.status_code, 403)

    def test_valid_bearer_still_authorizes_guarded_endpoint(self):
        token = 'synthetic-valid-token'
        self.data['api_tokens'] = [{'user_id': self.user['id'],
            'token_hash': hashlib.sha256(token.encode()).hexdigest()}]
        with patch.object(panel, '_touch_api_token', return_value=False):
            # The users inventory needs no SSH or optional tunnel process.
            response = self.client.get('/api/users', headers={
                'Authorization': 'Bearer ' + token})
        self.assertEqual(response.status_code, 200)

    def test_public_disabled_login_keeps_403(self):
        self.user['enabled'] = False
        with patch.object(panel, 'verify_password', return_value=True):
            response = self.client.post('/api/auth/login', json={
                'username': 'fixture', 'password': 'fixture'})
        self.assertEqual(response.status_code, 403)
