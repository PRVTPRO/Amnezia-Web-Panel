"""The API schema (/docs, /redoc, /openapi.json) is for admins only.

The OpenAPI document maps every endpoint and parameter of the panel;
serving it to anonymous visitors hands scanners a feature list. Only an
admin session (cookie) or admin Bearer token may open it.
"""
import json
import unittest

from fastapi.testclient import TestClient

import app as panel


class DocsAuthTests(unittest.TestCase):
    def setUp(self):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [], 'users': [], 'user_connections': []}, f)

    def login(self, client):
        response = client.post('/api/auth/login',
                               json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)

    def test_openapi_json_forbidden_anonymously(self):
        with TestClient(panel.app) as client:
            response = client.get('/openapi.json')
        self.assertEqual(response.status_code, 403)

    def test_docs_redirect_anonymous_to_login(self):
        with TestClient(panel.app) as client:
            response = client.get('/docs', follow_redirects=False)
        self.assertIn(response.status_code, (302, 307))
        self.assertIn('/login', response.headers.get('location', ''))

    def test_redoc_redirect_anonymous_to_login(self):
        with TestClient(panel.app) as client:
            response = client.get('/redoc', follow_redirects=False)
        self.assertIn(response.status_code, (302, 307))
        self.assertIn('/login', response.headers.get('location', ''))

    def test_openapi_json_served_to_admin(self):
        with TestClient(panel.app) as client:
            self.login(client)
            response = client.get('/openapi.json')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('paths', response.json())

    def test_docs_served_to_admin(self):
        with TestClient(panel.app) as client:
            self.login(client)
            response = client.get('/docs')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('swagger', response.text.lower())

    def test_healthish_routes_unaffected(self):
        # the middleware must not break genuinely public endpoints
        with TestClient(panel.app) as client:
            self.assertEqual(client.get('/robots.txt').status_code, 200)
            self.assertEqual(client.get('/login').status_code, 200)


if __name__ == '__main__':
    unittest.main()
