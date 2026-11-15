# -*- coding: utf-8 -*-
"""HTTP level checks for the I1 masking endpoints and their validation."""
import json
import os
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

import app as panel
from managers.awg_junk import DOMAIN_POOLS, parse_i1


class AwgI1ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='i1-api-')
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump({
                'servers': [{
                    'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22,
                    'username': 'root', 'password': 'x', 'private_key': '',
                    'server_info': {}, 'uid': 'entry-uid', 'protocols': {},
                }],
                'users': [{'id': 'admin-id', 'username': 'admin',
                           'password_hash': panel.hash_password('admin'),
                           'role': 'admin', 'enabled': True}],
                'user_connections': [],
            }, handle)
        self._monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.client = TestClient(panel.app)
        self.client.__enter__()
        login = self.client.post('/api/auth/login',
                                 json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(login.status_code, 200, login.text)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started = self._monitor
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_catalog_lists_domains_and_profiles(self):
        response = self.client.get('/api/awg/i1/catalog')
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        domains = {item['domain'] for item in body['domains']}
        self.assertEqual(domains, set(DOMAIN_POOLS))
        profiles = {item['key']: item['domains'] for item in body['device_profiles']}
        self.assertIn('any', profiles)
        self.assertTrue(set(profiles['apple']).issubset(domains))

    def test_preview_builds_a_parseable_packet(self):
        response = self.client.post('/api/awg/i1/preview',
                                    json={'domain': 'www.google.com'})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        parsed = body['parsed']
        self.assertEqual(parsed['domain'], 'www.google.com')
        self.assertTrue(parsed['in_pool'])
        self.assertFalse(parsed['default'])
        self.assertEqual(parse_i1(body['i1'])['size'], parsed['size'])

    def test_catalog_domain_rejects_a_foreign_pool(self):
        response = self.client.post('/api/awg/i1/preview',
                                    json={'domain': 'icloud.com',
                                          'pool': 'www.microsoft.com'})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('own address pool', response.json()['error'])

    def test_preview_picks_a_domain_when_none_given(self):
        response = self.client.post('/api/awg/i1/preview', json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(response.json()['parsed']['domain'], DOMAIN_POOLS)

    def test_custom_domain_requires_a_pool(self):
        response = self.client.post('/api/awg/i1/preview',
                                    json={'domain': 'example.org'})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['code'], 'bad_i1_domain')

    def test_custom_domain_with_pool_is_accepted(self):
        response = self.client.post('/api/awg/i1/preview',
                                    json={'domain': 'example.org', 'pool': 'github.com'})
        self.assertEqual(response.status_code, 200, response.text)
        parsed = response.json()['parsed']
        self.assertEqual(parsed['domain'], 'example.org')
        self.assertTrue(parsed['ip'].startswith('140.82.'))

    def test_preview_rejects_a_non_domain(self):
        response = self.client.post('/api/awg/i1/preview',
                                    json={'domain': 'http://example.com'})
        self.assertEqual(response.status_code, 400, response.text)

    def test_install_rejects_a_bad_domain_before_ssh(self):
        response = self.client.post('/api/servers/0/install', json={
            'protocol': 'awg3', 'awg_i1_domain': 'not a domain',
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['code'], 'bad_i1_domain')

    def test_settings_reject_kernel_only_tag_before_ssh(self):
        response = self.client.post('/api/servers/0/awg/settings/save', json={
            'protocol': 'awg3', 'i1': '<c>',
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('<c>', response.json()['error'])

    def test_preview_rejects_non_ascii_domain_with_400(self):
        for domain in ('пример.рф', 'іcloüd.com'):
            with self.subTest(domain=domain):
                response = self.client.post('/api/awg/i1/preview',
                                            json={'domain': domain, 'pool': 'github.com'})
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()['code'], 'bad_i1_domain')

    def test_install_rejects_non_ascii_domain_with_400(self):
        response = self.client.post('/api/servers/0/install', json={
            'protocol': 'awg3', 'awg_i1_domain': 'пример.рф',
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['code'], 'bad_i1_domain')

    def test_settings_reject_a_multiline_packet(self):
        response = self.client.post('/api/servers/0/awg/settings/save', json={
            'protocol': 'awg3', 'i1': '<t>\n<r 2>',
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn('line breaks', response.json()['error'])

    def test_settings_reject_bad_regenerate_domain_before_ssh(self):
        response = self.client.post('/api/servers/0/awg/settings/save', json={
            'protocol': 'awg3', 'regenerate_i1': True, 'i1_domain': 'example.org',
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()['code'], 'bad_i1_domain')


if __name__ == '__main__':
    unittest.main()
