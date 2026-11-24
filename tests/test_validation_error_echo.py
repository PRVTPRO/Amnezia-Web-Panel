"""Validation errors must never echo the submitted value back to the caller.

FastAPI's stock 422 handler puts the rejected value into ``detail[].input``.
For a mistyped password, API token or private key that value then lands in the
response body, and from there into browser devtools, HAR captures, proxy logs
that record bodies and bug reports. The panel's own docstrings promise the
opposite ("токен ... в ответ не попадает"), so the detail array is scrubbed
while ``loc`` / ``msg`` / ``type`` stay in place for the UI.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MARKER = 'mock-super-secret-value-42'


def _seed(tmp):
    import app
    data_file = Path(tmp) / 'data.json'
    data_file.write_text(json.dumps({
        'servers': [],
        'users': [{'id': 'a', 'username': 'admin',
                   'password_hash': app.hash_password('admin'),
                   'role': 'admin', 'enabled': True}],
        'settings': {},
    }), encoding='utf-8')
    return data_file


class ValidationEchoTests(unittest.TestCase):
    def setUp(self):
        import app
        from starlette.testclient import TestClient
        self.app = app
        self._tmp = tempfile.TemporaryDirectory()
        self.df = _seed(self._tmp.name)
        self._patch = patch.object(self.app, 'DATA_FILE', str(self.df))
        self._patch.start()
        with TestClient(self.app.app) as client:
            self.client = client
            response = client.post('/api/auth/login',
                                   json={'username': 'admin', 'password': 'admin'})
            self.assertEqual(response.status_code, 200, response.text)

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def assert_marker_absent(self, response):
        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn(MARKER, response.text)
        self.assertNotIn('"input"', response.text)
        body = response.json()
        self.assertIsInstance(body.get('detail'), list)

    # --- sensitive endpoints named in the review ---------------------------
    def test_cheburcheck_token_is_not_echoed(self):
        for path in ('/api/settings/cheburcheck',
                     '/api/settings/cheburcheck/token_check'):
            with self.subTest(path=path):
                response = self.client.post(path, json={'api_token': [MARKER]})
                self.assert_marker_absent(response)

    def test_password_is_not_echoed(self):
        response = self.client.post('/api/auth/login',
                                    json={'username': 'admin',
                                          'password': {'nested': MARKER}})
        self.assert_marker_absent(response)

    def test_private_key_is_not_echoed(self):
        response = self.client.post('/api/servers/add',
                                    json={'name': 'srv', 'host': '198.51.100.7',
                                          'username': 'root',
                                          'private_key': [MARKER]})
        self.assert_marker_absent(response)

    # --- the contract that must survive -----------------------------------
    def test_detail_keeps_loc_msg_and_type(self):
        response = self.client.post('/api/settings/cheburcheck',
                                    json={'api_token': [MARKER]})
        self.assertEqual(response.status_code, 422, response.text)
        entry = response.json()['detail'][0]
        self.assertEqual(entry['loc'], ['body', 'api_token'])
        self.assertEqual(entry['type'], 'string_type')
        self.assertTrue(entry['msg'])

    def test_unrelated_validation_errors_keep_working(self):
        """Scrubbing must not turn 422 into 400 or drop the detail array."""
        response = self.client.post('/api/users/add', json={})
        self.assertEqual(response.status_code, 422, response.text)
        detail = response.json()['detail']
        self.assertIsInstance(detail, list)
        self.assertTrue(detail)
        self.assertTrue(all('loc' in entry for entry in detail))

    def test_ipv6_bad_body_still_answers_400(self):
        """The existing IPv6 remap keeps precedence over the scrub."""
        response = self.client.post('/api/servers/0/ipv6', json=[])
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['code'], 'bad_request')


if __name__ == '__main__':
    unittest.main()
