"""Regression tests for api_auth_status_middleware.

The middleware rewrites a denied /api/ 403 into 401 'Session expired' when the
caller has no browser session. The first version built a fresh JSONResponse
and dropped every header of the refused response. Sensitive denials (the
backup archive, for one) answer with 'Cache-Control: no-store, private' and
'X-Content-Type-Options: nosniff'; losing them lets a shared cache keep a
denial body and hides the nosniff hardening. A second defect hid in the same
rewrite: a signed-in admin request that the handler refused for a bad Origin
looked anonymous to the middleware, so a real 403 turned into 401.
"""
import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient


def load_panel():
    """Import the panel against throwaway state files.

    The environment is patched (not assigned) so the paths disappear with the
    cleanup: a leftover DATA_FILE pointing at a deleted directory changes the
    behaviour of every later test that imports app.
    """
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    env = mock.patch.dict(os.environ, {'DATA_FILE': str(root / 'data.json'),
                                       'TUNNEL_STATE_FILE': str(root / 'tunnels.json'),
                                       'SSH_KNOWN_HOSTS_FILE': str(root / 'known_hosts')})
    env.start()
    module = importlib.import_module('app')
    return module, temp, env


class MiddlewareHeaderTests(unittest.TestCase):

    def setUp(self):
        self.module, self._temp, self._env = load_panel()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._temp.cleanup)

    def test_denied_archive_keeps_private_headers(self):
        client = TestClient(self.module.app)
        self.addCleanup(client.close)
        response = client.post('/api/settings/backup/archive', json={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'error': 'Session expired'})
        self.assertIn('no-store', response.headers['cache-control'])
        self.assertIn('private', response.headers['cache-control'])
        self.assertIn('no-cache', response.headers['pragma'])
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')

    def test_signed_in_admin_keeps_403_for_cross_site_request(self):
        """A signed-in admin is not anonymous: the handler's 403 must survive.

        The rewrite only applies to callers with no valid browser user, so an
        admin whose request the handler refused for a cross-site Origin still
        sees the real status instead of a misleading 'Session expired'.
        """
        module = self.module
        user = {'role': 'admin'}
        with mock.patch.object(module, '_ssh_trust_admin', return_value=None), \
             mock.patch.object(module, 'get_current_user', return_value=user):
            client = TestClient(module.app)
            self.addCleanup(client.close)
            response = client.post('/api/settings/backup/archive',
                                   headers={'Origin': 'https://evil.example'},
                                   json={})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json(), {'error': 'Forbidden'})
        self.assertIn('no-store', response.headers['cache-control'])


if __name__ == '__main__':
    unittest.main()
