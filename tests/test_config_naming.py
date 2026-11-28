"""Tests for per-instance client-facing config name templates."""
import base64
import json
import os
import shutil
import struct
import tempfile
import unittest
import urllib.parse
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import httpx

import app as panel
import config_naming
from mail_service import _safe_filename
import telegram_bot


ROOT = Path(__file__).resolve().parents[1]

SAMPLE_AWG_CONFIG = (
    "[Interface]\n"
    "PrivateKey = cPrivKey=\n"
    "Address = 10.8.1.2/32\n"
    "DNS = 1.1.1.1, 1.0.0.1\n"
    "Jc = 2\n"
    "Jmin = 10\n"
    "Jmax = 30\n"
    "\n"
    "[Peer]\n"
    "PublicKey = sPubKey=\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = 198.51.100.1:55424\n"
)

SAMPLE_VLESS = (
    "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443"
    "?type=tcp&security=reality&pbk=pub&sni=example.com&fp=chrome&sid=ab12&spx=%2F"
    "&flow=xtls-rprx-vision#raw-tag"
)


def decode_vpn_link(link: str) -> dict:
    assert link.startswith('vpn://')
    payload_b64 = link[len('vpn://'):]
    padded = payload_b64 + '=' * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(padded)
    size = struct.unpack('>I', raw[:4])[0]
    uncompressed = zlib.decompress(raw[4:])
    assert len(uncompressed) == size
    return json.loads(uncompressed.decode('utf-8'))


class ConfigNamingUnitTests(unittest.TestCase):
    def test_empty_template_preserves_legacy_display_name_and_filename(self):
        server = {
            'name': 'nl-01',
            'host': '198.51.100.1',
            'protocols': {'awg2': {'header_protection': True}},
        }
        self.assertEqual(panel.connection_display_name(server, 'awg2', client_name='Alice'), 'nl-01 AWG3')

        payloads = panel.config_payloads(SAMPLE_AWG_CONFIG, server, 'awg2', client_name='Alice')
        self.assertEqual(payloads['vpn_name'], 'nl-01 AWG3')
        self.assertNotIn('conf_filename', payloads)
        self.assertEqual(decode_vpn_link(payloads['vpn_link'])['description'], 'nl-01 AWG3')

    def test_template_substitutes_placeholders_and_cleans_empty_exit(self):
        server = {
            'name': 'Test node',
            'host': '198.51.100.11',
            'protocols': {
                'awg2': {
                    'header_protection': True,
                    'config_name_template': '{server} {protocol} ({exit}) - {client}',
                    'exit_link': {'exit_name': 'Exit node'},
                }
            },
        }
        name = panel.connection_display_name(server, 'awg2', client_name='Алексей')
        self.assertEqual(name, 'Test node AWG3 (Exit node) - Алексей')

        # Without an exit link, empty parentheses collapse cleanly.
        del server['protocols']['awg2']['exit_link']
        name_no_exit = panel.connection_display_name(server, 'awg2', client_name='Алексей')
        self.assertEqual(name_no_exit, 'Test node AWG3 - Алексей')

    def test_instance_label_and_warp_are_used_in_exported_names(self):
        record = {
            'custom_name': 'Mobile',
            'config_name_template': '{instance} | {protocol} | {exit}',
        }
        server = {'uid': 'test', 'name': 'Node', 'protocols': {'awg3__2': record}}
        with mock.patch.object(panel, 'srv_warp_ctx', return_value={'active': True}):
            payload = panel.config_payloads(SAMPLE_AWG_CONFIG, server, 'awg3__2')
        self.assertEqual(payload['vpn_name'], 'Mobile | AWG3#2 | WARP')
        self.assertEqual(decode_vpn_link(payload['vpn_link'])['description'], payload['vpn_name'])

        del record['custom_name']
        record['exit_link'] = {'exit_name': 'Exit'}
        self.assertEqual(panel.connection_display_name(server, 'awg3__2'),
                         'AmneziaWG 3.1 #2 | AWG3#2 | Exit')

    def test_unknown_braces_do_not_raise(self):
        rendered = config_naming.render_config_name(
            '{server} {unknown} {client}',
            server='Node',
            client='Bob',
        )
        self.assertEqual(rendered, 'Node {unknown} Bob')

    def test_sanitize_conf_filename_transliterates_and_bounds_length(self):
        self.assertEqual(
            config_naming.sanitize_conf_filename('RU AWG3 - Алексей!/?*'),
            'RU_AWG3_Aleksey.conf',
        )
        long_name = config_naming.sanitize_conf_filename('ОченьДлинноеНазваниеСервера_И_Клиента_Номер_Один')
        self.assertTrue(long_name.endswith('.conf'))
        stem = long_name[:-5]
        self.assertLessEqual(len(stem), config_naming.CONF_FILENAME_MAX_STEM)
        self.assertRegex(stem, r'^[A-Za-z0-9_-]+$')
        self.assertEqual(config_naming.sanitize_conf_filename('🚀🔥!!!'), 'tunnel.conf')
        self.assertEqual(config_naming.sanitize_conf_filename('CON'), 'CON_wg.conf')

    def test_payloads_apply_name_to_vpn_json_vless_fragment_and_conf_filename(self):
        server = {
            'name': 'МСК-1',
            'host': '198.51.100.1',
            'protocols': {
                'awg2': {
                    'header_protection': True,
                    'config_name_template': '{server} {protocol} [{client}]',
                },
                'xray': {
                    'config_name_template': '{server}-{client}-{protocol}',
                },
            },
        }
        awg_payloads = panel.config_payloads(SAMPLE_AWG_CONFIG, server, 'awg2', client_name='Иван')
        self.assertEqual(awg_payloads['vpn_name'], 'МСК-1 AWG3 [Иван]')
        self.assertEqual(awg_payloads['conf_filename'], 'MSK-1_AWG3_Ivan.conf')
        # Raw WireGuard/AWG text must remain untouched.
        self.assertEqual(awg_payloads['config'], SAMPLE_AWG_CONFIG)
        self.assertEqual(decode_vpn_link(awg_payloads['vpn_link'])['description'], 'МСК-1 AWG3 [Иван]')

        xray_payloads = panel.config_payloads(SAMPLE_VLESS, server, 'xray', client_name='Иван')
        self.assertEqual(xray_payloads['vpn_name'], 'МСК-1-Иван-Xray')
        self.assertNotIn('conf_filename', xray_payloads)
        self.assertTrue(xray_payloads['config'].endswith('#' + urllib.parse.quote('МСК-1-Иван-Xray')))
        self.assertEqual(decode_vpn_link(xray_payloads['vpn_link'])['description'], 'МСК-1-Иван-Xray')


class ConfigNameDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_telegram_uses_the_same_instance_and_warp_labels(self):
        server = {'uid': 'test', 'name': 'Node', 'protocols': {'awg3': {
            'custom_name': 'Mobile', 'config_name_template': '{instance}-{exit}',
        }}}
        api = SimpleNamespace(config_payloads=panel.config_payloads, send_message=mock.AsyncMock(),
                              send_document=mock.AsyncMock())
        with mock.patch.object(panel, 'srv_warp_ctx', return_value={'active': True}):
            await telegram_bot._send_config_text(
                api, 1, server, 'awg3', 'Alice', SAMPLE_AWG_CONFIG, panel.generate_vpn_link)
        self.assertEqual(api.send_document.await_args.kwargs['filename'], 'Mobile-WARP.conf')
        messages = [call.args[1] for call in api.send_message.await_args_list]
        link = next(line.split('<code>')[1].split('</code>')[0] for line in messages if 'vpn://' in line)
        self.assertEqual(decode_vpn_link(link)['description'], 'Mobile-WARP')


class ConfigNameAttachmentTests(unittest.TestCase):
    def test_attachment_names_stay_within_native_limit_after_deduplication(self):
        used = set()
        filenames = [_safe_filename('123456789012345', 'awg3', used, max_stem=15) for _ in range(2)]
        self.assertEqual(filenames, ['123456789012345.conf', '1234567890123_2.conf'])


class ConfigNameEndpointTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)
        self._monitor = panel._conn_monitor_started
        panel._conn_monitor_started = True
        self.addCleanup(setattr, panel, '_conn_monitor_started', self._monitor)

        data = {
            'servers': [{
                'uid': 'srv-0',
                'name': 'Node 1',
                'host': '198.51.100.10',
                'ssh_port': 22,
                'username': 'root',
                'password': 'secret',
                'private_key': '',
                'protocols': {
                    'awg2': {
                        'installed': True,
                        'port': '55424',
                        'header_protection': True,
                        'base_protocol': 'awg2',
                        'instance': 1,
                    },
                },
            }],
            'users': [
                {
                    'id': 'admin-1',
                    'username': 'admin',
                    'password_hash': panel.hash_password('admin'),
                    'role': 'admin',
                    'enabled': True,
                },
                {
                    'id': 'user-1',
                    'username': 'alice',
                    'password_hash': panel.hash_password('alice'),
                    'role': 'user',
                    'enabled': True,
                },
            ],
            'user_connections': [{
                'id': 'conn-1',
                'user_id': 'user-1',
                'server_id': 0,
                'protocol': 'awg2',
                'client_id': 'peer-pub-1',
                'name': 'Телефон Алисы',
            }],
        }
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=panel.app), base_url='http://testserver')

    async def login(self, client, username):
        r = await client.post('/api/auth/login', json={'username': username, 'password': username})
        self.assertEqual(r.status_code, 200, r.text)

    async def test_set_clear_and_auth_guards_without_ssh(self):
        async with self.client() as client:
            unauth = await client.post('/api/servers/0/protocol/config-name',
                                 json={'protocol': 'awg2', 'template': '{server}-{client}'})
            self.assertEqual(unauth.status_code, 401)

            await self.login(client, 'alice')
            forbidden = await client.post('/api/servers/0/protocol/config-name',
                                    json={'protocol': 'awg2', 'template': '{server}-{client}'})
            self.assertEqual(forbidden.status_code, 403)

        async with self.client() as client:
            await self.login(client, 'admin')
            with mock.patch.object(panel, 'get_ssh', side_effect=AssertionError('SSH must not be called')):
                res = await client.post('/api/servers/0/protocol/config-name',
                                  json={'protocol': 'awg2', 'template': ' {server} | {protocol} | {client} '})
                self.assertEqual(res.status_code, 200, res.text)
                self.assertEqual(res.json()['template'], '{server} | {protocol} | {client}')

                stored = panel.load_data()['servers'][0]['protocols']['awg2']
                self.assertEqual(stored['config_name_template'], '{server} | {protocol} | {client}')

                missing_proto = await client.post('/api/servers/0/protocol/config-name',
                                            json={'protocol': 'xray', 'template': '{client}'})
                self.assertEqual(missing_proto.status_code, 404)

                cleared = await client.post('/api/servers/0/protocol/config-name',
                                      json={'protocol': 'awg2', 'template': '   '})
                self.assertEqual(cleared.status_code, 200)
                self.assertEqual(cleared.json()['template'], '')
                self.assertNotIn('config_name_template', panel.load_data()['servers'][0]['protocols']['awg2'])

    async def test_preview_uses_saved_instance_name_without_writing_template(self):
        data = panel.load_data()
        data['servers'][0]['protocols']['awg2']['custom_name'] = 'Mobile'
        panel.save_data(data)

        async with self.client() as client:
            await self.login(client, 'admin')
            body = {'protocol': 'awg2', 'template': '{instance}-{client}',
                    'preview': True, 'server_uid': 'srv-0'}
            path = '/api/servers/0/protocol/config-name'
            with mock.patch.object(panel, 'get_ssh', side_effect=AssertionError('Unexpected SSH call')):
                response = await client.post(path, json=body)
                stale = await client.post(path, json={**body, 'server_uid': 'other'})

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {'vpn_name': 'Mobile-Alice', 'conf_filename': 'Mobile-Alice.conf'})
        self.assertEqual(stale.status_code, 409)
        record = panel.load_data()['servers'][0]['protocols']['awg2']
        self.assertNotIn('config_name_template', record)

    async def test_connection_config_endpoint_uses_template_and_client_name(self):
        async with self.client() as client:
            await self.login(client, 'admin')
            set_res = await client.post('/api/servers/0/protocol/config-name',
                                  json={'protocol': 'awg2', 'template': '{server} {protocol} — {client}'})
            self.assertEqual(set_res.status_code, 200)

            fake_ssh = mock.MagicMock()
            fake_mgr = mock.MagicMock()
            fake_mgr.get_client_config.return_value = SAMPLE_AWG_CONFIG
            with mock.patch.object(panel, 'get_ssh', return_value=fake_ssh), \
                 mock.patch.object(panel, 'get_protocol_manager', return_value=fake_mgr):
                res = await client.post('/api/servers/0/connections/config',
                                  json={'protocol': 'awg2', 'client_id': 'peer-pub-1'})

            self.assertEqual(res.status_code, 200, res.text)
            body = res.json()
            self.assertEqual(body['vpn_name'], 'Node 1 AWG3 — Телефон Алисы')
            self.assertEqual(body['conf_filename'], 'Node_1_AWG3_Tel.conf')
            self.assertEqual(decode_vpn_link(body['vpn_link'])['description'], 'Node 1 AWG3 — Телефон Алисы')
            self.assertEqual(body['config'], SAMPLE_AWG_CONFIG)


class ConfigNameUiWiringTests(unittest.TestCase):
    def test_server_page_and_download_templates_wire_config_name_feature(self):
        server_html = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        for needle in (
            'id="configNameModal"',
            'id="configNameTemplateInput"',
            'id="configNamePreviewDisplay"',
            'id="configNamePreviewFile"',
            'openConfigNameModal',
            "insertConfigNamePlaceholder('{instance}')",
            'preview: true',
            'saveConfigNameTemplate',
            '/protocol/config-name',
            'result.conf_filename',
        ):
            self.assertIn(needle, server_html)

        for tmpl in ('users.html', 'my_connections.html'):
            text = (ROOT / 'templates' / tmpl).read_text(encoding='utf-8')
            self.assertIn('result.conf_filename', text, tmpl)

        share_html = (ROOT / 'templates' / 'user_share.html').read_text(encoding='utf-8')
        self.assertIn('data.conf_filename', share_html)


if __name__ == '__main__':
    unittest.main()
