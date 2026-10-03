"""DuckDNS settings card: domain normalization, IP updates, cert apply flow.

Everything external is faked -- no duckdns.org, no acme.sh -- because the
parts worth guarding are the decisions: token is never wiped by an empty
field, the domain is normalized to a full duckdns name, a failed IP update
or cert issue must not flip ssl settings, and a successful apply writes the
same ssl config the manual card edits.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel


class NormalizeDomainTests(unittest.TestCase):
    def test_bare_subdomain_gets_suffix(self):
        self.assertEqual(panel._duckdns_normalize_domain('myvpn'), 'myvpn.duckdns.org')

    def test_full_domain_and_case_whitespace(self):
        self.assertEqual(panel._duckdns_normalize_domain('  MyVPN.duckdns.org. '),
                         'myvpn.duckdns.org')

    def test_rejects_garbage(self):
        for bad in ('', 'a_b', 'evil.com', 'x' * 64, '-lead', 'trail-', 'a..b'):
            self.assertEqual(panel._duckdns_normalize_domain(bad), '', bad)


class UpdateIpTests(unittest.TestCase):
    class _Resp:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body.encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_ok_response(self):
        with mock.patch.object(panel.urllib.request, 'urlopen',
                               return_value=self._Resp('OK')) as m:
            ok, detail = panel._duckdns_update_ip('myvpn.duckdns.org', 'tok')
        self.assertTrue(ok)
        url = m.call_args[0][0]
        self.assertIn('domains=myvpn', url)
        self.assertIn('token=tok', url)
        # empty ip= -> duckdns uses the caller's (panel server's) address
        self.assertTrue(url.endswith('ip='))

    def test_ko_and_network_error(self):
        with mock.patch.object(panel.urllib.request, 'urlopen',
                               return_value=self._Resp('KO')):
            ok, _ = panel._duckdns_update_ip('myvpn.duckdns.org', 'bad')
        self.assertFalse(ok)
        with mock.patch.object(panel.urllib.request, 'urlopen',
                               side_effect=OSError('no route')):
            ok, detail = panel._duckdns_update_ip('myvpn.duckdns.org', 'tok')
        self.assertFalse(ok)
        self.assertIn('no route', detail)


class ApplyApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [], 'users': [], 'user_connections': []}, f)
        self._flags = (panel._conn_monitor_started, panel._duckdns_monitor_started)
        panel._conn_monitor_started = True
        panel._duckdns_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel._conn_monitor_started, panel._duckdns_monitor_started = self._flags
        shutil.rmtree(self.tmp, ignore_errors=True)

    def login(self, client):
        r = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(r.status_code, 200, r.text)

    def apply(self, client, **payload):
        return client.post('/api/settings/duckdns/apply', json=payload)

    def test_disabled_save_stores_settings_without_network(self):
        with TestClient(panel.app) as client:
            self.login(client)
            r = self.apply(client, enabled=False, domain='myvpn', token='t1')
            self.assertEqual(r.status_code, 200, r.text)
            stored = panel.load_data()['settings']['duckdns']
            self.assertEqual(stored, {'enabled': False,
                                      'domain': 'myvpn.duckdns.org', 'token': 't1'})
            # ssl untouched
            self.assertFalse(panel.load_data()['settings'].get('ssl', {}).get('enabled', False))

    def test_enabled_requires_domain_and_token(self):
        with TestClient(panel.app) as client:
            self.login(client)
            r = self.apply(client, enabled=True, domain='', token='')
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()['error'], 'duckdns_domain_token_required')

    def test_empty_token_keeps_the_stored_one(self):
        with TestClient(panel.app) as client:
            self.login(client)
            self.apply(client, enabled=False, domain='myvpn', token='s3cret')
            with mock.patch.object(panel, '_duckdns_update_ip',
                                   return_value=(True, 'OK')) as upd, \
                 mock.patch.object(panel, '_duckdns_issue_cert',
                                   return_value=(True, 'log')) as cert:
                r = self.apply(client, enabled=True, domain='myvpn', token='')
            self.assertEqual(r.status_code, 200, r.text)
            # both helpers were called with the STORED token
            self.assertEqual(upd.call_args[0][1], 's3cret')
            self.assertEqual(cert.call_args[0][1], 's3cret')
            self.assertEqual(panel.load_data()['settings']['duckdns']['token'], 's3cret')

    def test_successful_apply_writes_ssl_config(self):
        with TestClient(panel.app) as client:
            self.login(client)
            with mock.patch.object(panel, '_duckdns_update_ip', return_value=(True, 'OK')), \
                 mock.patch.object(panel, '_duckdns_issue_cert', return_value=(True, 'ok')):
                r = self.apply(client, enabled=True, domain='myvpn', token='t1')
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            # dev box is not systemd -> the UI must ask for a restart
            self.assertTrue(body.get('restart_required') or body.get('restarting'))
            ssl = panel.load_data()['settings']['ssl']
            self.assertTrue(ssl['enabled'])
            self.assertEqual(ssl['domain'], 'myvpn.duckdns.org')
            self.assertTrue(ssl['cert_path'].endswith('duckdns.cert.pem'))
            self.assertTrue(ssl['key_path'].endswith('duckdns.key.pem'))
            self.assertEqual(ssl['cert_text'], '')

    def test_ip_update_failure_does_not_touch_ssl(self):
        with TestClient(panel.app) as client:
            self.login(client)
            with mock.patch.object(panel, '_duckdns_update_ip',
                                   return_value=(False, 'KO')):
                r = self.apply(client, enabled=True, domain='myvpn', token='bad')
            self.assertEqual(r.status_code, 502)
            self.assertEqual(r.json()['error'], 'duckdns_ip_update_failed')
            self.assertFalse(panel.load_data()['settings'].get('ssl', {}).get('enabled', False))

    def test_cert_failure_does_not_touch_ssl(self):
        with TestClient(panel.app) as client:
            self.login(client)
            with mock.patch.object(panel, '_duckdns_update_ip', return_value=(True, 'OK')), \
                 mock.patch.object(panel, '_duckdns_issue_cert',
                                   return_value=(False, 'boom')):
                r = self.apply(client, enabled=True, domain='myvpn', token='t1')
            self.assertEqual(r.status_code, 502)
            self.assertEqual(r.json()['error'], 'duckdns_cert_failed')
            self.assertFalse(panel.load_data()['settings'].get('ssl', {}).get('enabled', False))


if __name__ == '__main__':
    unittest.main()
