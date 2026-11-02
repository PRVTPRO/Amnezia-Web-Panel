"""Keep installed config labels consistent across web, self-service and delivery."""
import asyncio
import json
import re
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as panel
import telegram_bot
from protocol_names import protocol_display_name
from connection_service import self_service_protocol_choices
from tests import test_connection_service as connection_tests
from tests.test_connection_service import base_data
from tests.test_exit_link_service import Harness
from tests.test_mail_service import base_data as mail_data, make_service


class ProtocolLabelSurfacesTests(unittest.TestCase):
    def record(self, version):
        return {'installed': True, 'header_protection': version != '2.0',
                'protocol_version': version, 'port': '55424'}

    def test_self_service_web_and_telegram_use_each_instances_metadata(self):
        for version in ('2.0', '3.x', '3.1'):
            data = base_data()
            server = data['servers'][0]
            server['protocols'] = {'awg2__2': self.record(version)}
            service, state, _ = connection_tests.ConnectionServiceTest().make_service(data)
            result = asyncio.run(service.get_self_service_options('user-1', 'web'))
            expected = protocol_display_name('awg2__2', version != '2.0', version)
            self.assertEqual(result['servers'][0]['protocols'][0]['name'], expected)
            self.assertEqual(telegram_bot._protocol_display_name('awg2__2', server), expected)

    def test_family_permission_does_not_claim_an_installed_minor(self):
        choice = next(c for c in self_service_protocol_choices() if c['id'] == 'awg2')
        self.assertEqual(choice['name'], 'AmneziaWG 2.0 / 3.x')

    def test_users_and_settings_receive_python_computed_instance_labels(self):
        admin = {'id': 'fixture', 'role': 'admin', 'enabled': True}
        data = base_data()
        data['users'] = [admin]
        data['servers'][0]['protocols'] = {'awg2__2': self.record('3.1')}
        # Use the real defaults migration, against a disposable file only.
        with tempfile.TemporaryDirectory() as root, patch.object(panel, 'DATA_FILE', root + '/data.json'):
            Path(panel.DATA_FILE).write_text(json.dumps(data), encoding='utf8')
            data = panel.load_data()
        with patch.object(panel, 'load_data', return_value=data), \
                patch.object(panel, 'get_current_user', return_value=admin):
            client = TestClient(panel.app)
            for path in ('/users', '/settings'):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, response.text[:200])
                labels = json.loads(re.search(r'const protocolLabels = (.*);', response.text)[1])
                self.assertEqual(labels[0]['awg2__2'], 'AmneziaWG 3.1 (amnezia-awg2) #2')
                self.assertNotIn("key === 'awg2' ? 'AmneziaWG 2.0'", response.text)

    def test_mail_uses_actual_version_for_protocol_and_default_connection_name(self):
        data = mail_data()
        conn = data['user_connections'][0]
        conn.update(protocol='awg2', name='')
        data['servers'][0]['protocols']['awg2'] = self.record('3.1')
        service, _ = make_service(data)
        service._protocol_display_name = protocol_display_name
        items, errors = service.collect_items(data, data['users'][0])
        self.assertFalse(errors)
        item = next(i for i in items if i['protocol'] == 'awg2')
        self.assertEqual(item['protocol_name'], 'AmneziaWG 3.1 (amnezia-awg2)')
        self.assertEqual(item['name'], item['protocol_name'])

    def test_exit_peer_label_uses_entry_protocol_version(self):
        harness = Harness()
        harness.data['servers'][0]['protocols']['awg2'].update(self.record('3.1'))
        harness.service.protocol_display_name = protocol_display_name
        asyncio.run(harness.service.link(0, 'awg2', 'exit-a'))
        call = next(c for c in harness.exit().calls if c[0] == 'add_peer')
        self.assertEqual(call[2], 'Paris / AmneziaWG 3.1 (amnezia-awg2)')
