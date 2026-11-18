# -*- coding: utf-8 -*-
"""The panel must keep its own copy of I1-I5 after they are edited.

PR #346 let an admin regenerate or paste the masking packet, but the save
endpoint wrote only MTU/DNS/DNS6 back to data.json, so the stored packet kept
its install-time value and quietly disagreed with the server. These checks pin
the write-back: what the manager reports is what the panel remembers.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
from managers.awg_junk import generate_i1


class AwgI1PersistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='i1-persist-')
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.write_data(protocols={
            'awg3': {
                'installed': True, 'port': 51111, 'base_protocol': 'awg3',
                'container_name': 'amnezia-awg3',
                'awg_params': {'junk_packet_count': '4', 'i1': 'old-packet'},
            },
        })
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

    # ------------------------------------------------------------------ helpers

    def write_data(self, protocols=None):
        payload = {
            'servers': [{
                'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22,
                'username': 'root', 'password': 'x', 'private_key': '',
                'server_info': {}, 'uid': 'entry-uid',
                'protocols': protocols if protocols is not None else {},
            }],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': panel.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [],
        }
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle)

    def read_proto(self):
        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            return json.load(handle)['servers'][0]['protocols']['awg3']

    def save(self, settings, protocol='awg3', payload=None):
        """POST the save endpoint with a stubbed manager returning `settings`."""
        ssh = mock.Mock()
        manager = mock.Mock()
        manager.update_awg_settings.return_value = settings
        if payload is None:
            # Echo back the reported packet so request validation passes; the
            # point of the test is what gets written to data.json.
            payload = {'protocol': protocol, 'i1': settings.get('i1') or ''}
            if not payload['i1']:
                payload.pop('i1')
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'AWGManager', return_value=manager):
            return self.client.post(
                '/api/servers/0/awg/settings/save', json=payload)

    @staticmethod
    def settings(i1=None, **extra):
        base = {
            'mtu': '1376', 'dns': '1.1.1.1', 'dns6': '2606:4700::1111',
            'supports_special_junk': True,
            'i1': i1, 'i2': '', 'i3': '', 'i4': '', 'i5': '',
        }
        base.update(extra)
        return base

    # -------------------------------------------------------------------- tests

    def test_regenerated_i1_is_written_back_to_data_json(self):
        packet = generate_i1('www.microsoft.com')
        response = self.save(self.settings(i1=packet, i1_parsed={'domain': 'www.microsoft.com'}))
        self.assertEqual(response.status_code, 200, response.text)

        stored = self.read_proto()
        self.assertEqual(stored['awg_params']['i1'], packet)
        # Other params are preserved: the packet is one field, not the record.
        self.assertEqual(stored['awg_params']['junk_packet_count'], '4')
        self.assertEqual(stored['mtu'], '1376')

    def test_cleared_packet_is_removed_not_stored_as_empty_string(self):
        response = self.save(self.settings(i1=''))
        self.assertEqual(response.status_code, 200, response.text)

        params = self.read_proto()['awg_params']
        self.assertNotIn('i1', params)
        self.assertEqual(params['junk_packet_count'], '4')

    def test_awg_params_is_created_when_the_record_has_none(self):
        self.write_data(protocols={'awg3': {'installed': True, 'port': 51111}})
        packet = generate_i1('cloudflare.com')
        response = self.save(self.settings(i1=packet))
        self.assertEqual(response.status_code, 200, response.text)

        stored = self.read_proto()
        self.assertEqual(stored['awg_params'], {'i1': packet})

    def test_legacy_protocol_does_not_gain_special_junk_fields(self):
        self.write_data(protocols={'awg_legacy': {'installed': True, 'port': 51000}})
        response = self.save(self.settings(i1='<r 2>', supports_special_junk=False),
                             protocol='awg_legacy',
                             payload={'protocol': 'awg_legacy', 'i1': '<r 2>'})
        self.assertEqual(response.status_code, 200, response.text)

        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            legacy = json.load(handle)['servers'][0]['protocols']['awg_legacy']
        self.assertNotIn('awg_params', legacy)

    def test_second_field_edit_keeps_the_previously_saved_packet(self):
        packet = generate_i1('github.com')
        self.save(self.settings(i1=packet))
        # A later MTU-only edit reports the same packet back; it must survive.
        response = self.save(self.settings(i1=packet, mtu='1300'),
                             payload={'protocol': 'awg3', 'mtu': '1300'})
        self.assertEqual(response.status_code, 200, response.text)

        stored = self.read_proto()
        self.assertEqual(stored['awg_params']['i1'], packet)
        self.assertEqual(stored['mtu'], '1300')

    def test_failed_apply_writes_nothing(self):
        before = self.read_proto()
        ssh = mock.Mock()
        manager = mock.Mock()
        manager.update_awg_settings.side_effect = RuntimeError('syncconf refused')
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'AWGManager', return_value=manager):
            response = self.client.post(
                '/api/servers/0/awg/settings/save',
                json={'protocol': 'awg3', 'mtu': '1300'})

        self.assertGreaterEqual(response.status_code, 400, response.text)
        self.assertEqual(self.read_proto(), before)

    def test_unknown_protocol_record_is_not_invented(self):
        self.write_data(protocols={})
        packet = generate_i1('yandex.ru')
        response = self.save(self.settings(i1=packet))
        self.assertEqual(response.status_code, 200, response.text)

        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            protocols = json.load(handle)['servers'][0]['protocols']
        self.assertEqual(protocols, {})

    def test_whitespace_only_packet_clears_the_key(self):
        packet = generate_i1('web.telegram.org')
        self.save(self.settings(i1=packet))
        response = self.save(self.settings(i1='   '))
        self.assertEqual(response.status_code, 200, response.text)

        self.assertNotIn('i1', self.read_proto()['awg_params'])

    def test_all_five_packets_are_written_back(self):
        packets = {
            'i1': generate_i1('cloudflare.com'),
            'i2': '<r 2><b 0x00>',
            'i3': '<r 3>',
            'i4': '<t>',
            'i5': '<r 4><t>',
        }
        response = self.save(self.settings(**packets))
        self.assertEqual(response.status_code, 200, response.text)

        params = self.read_proto()['awg_params']
        for key, packet in packets.items():
            with self.subTest(key=key):
                self.assertEqual(params[key], packet)

    def test_damaged_awg_params_is_left_untouched(self):
        # A hand-edited record must not be silently replaced by a mapping.
        damaged = 'not-a-mapping'
        self.write_data(protocols={'awg3': {
            'installed': True, 'port': 51111, 'awg_params': damaged}})
        packet = generate_i1('github.com')
        response = self.save(self.settings(i1=packet))
        self.assertEqual(response.status_code, 200, response.text)

        self.assertEqual(self.read_proto()['awg_params'], damaged)

    def test_legacy_ignores_a_packet_reported_by_the_manager(self):
        self.write_data(protocols={'awg_legacy': {'installed': True, 'port': 51000}})
        response = self.save(self.settings(i1=generate_i1('yandex.ru'),
                                          supports_special_junk=False),
                             protocol='awg_legacy',
                             payload={'protocol': 'awg_legacy'})
        self.assertEqual(response.status_code, 200, response.text)

        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            legacy = json.load(handle)['servers'][0]['protocols']['awg_legacy']
        self.assertNotIn('awg_params', legacy)


if __name__ == '__main__':
    unittest.main()
