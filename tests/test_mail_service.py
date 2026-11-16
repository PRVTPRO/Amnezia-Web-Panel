"""Emailing configs and proxy links: settings, message shape, single and bulk sends.

Everything here runs against fakes -- no SMTP server, no SSH, no data.json --
because the parts worth guarding are the decisions: which users a mass send
skips and why, what ends up as an attachment versus a link, and that one dead
server or one refused address never takes the rest of the run with it.
"""

import copy
import json
import os
import shutil
import smtplib
import tempfile
import threading
import time
import unittest

from fastapi.testclient import TestClient

import app as panel
from mail_service import (
    DEFAULT_MAIL_SETTINGS,
    MailError,
    MailOptions,
    MailService,
    SmtpTransport,
    build_message,
    is_valid_email,
    merge_mail_settings,
    validate_mail_settings,
)

AWG_CONFIG = '[Interface]\nPrivateKey = aaa=\nAddress = 10.8.1.2/32\n\n[Peer]\nEndpoint = 198.51.100.1:55424\n'
XRAY_LINK = 'vless://uuid@198.51.100.1:443?type=tcp&security=reality#Phone'


# ===================== fakes =====================

class FakeSMTP:
    """The slice of smtplib the transport actually touches."""

    def __init__(self, fail_first_send=False, fail_recipients=()):
        self.sent = []
        self.started_tls = False
        self.login_as = None
        self.quit_called = False
        self._fail_first_send = fail_first_send
        self._fail_recipients = set(fail_recipients)

    def starttls(self, context=None):
        self.started_tls = True

    def ehlo(self):
        pass

    def login(self, username, password):
        self.login_as = (username, password)

    def send_message(self, message):
        if self._fail_first_send:
            self._fail_first_send = False
            raise smtplib.SMTPServerDisconnected('connection reset')
        if message['To'] in self._fail_recipients:
            raise smtplib.SMTPRecipientsRefused({message['To']: (550, b'no such user')})
        self.sent.append(message)

    def quit(self):
        self.quit_called = True


class FakeSSH:
    def __init__(self, host):
        self.host = host
        self.connects = 0

    def connect(self):
        self.connects += 1

    def disconnect(self):
        pass


class FakeManager:
    def __init__(self, configs):
        self.configs = configs

    def get_client_config(self, protocol, client_id, host, port):
        return self.configs.get(client_id, '')


def base_data():
    return {
        'settings': {
            'appearance': {'title': 'Amnezia', 'logo': 'AW'},
            'mail': dict(DEFAULT_MAIL_SETTINGS, enabled=True, host='smtp.example.test',
                         from_email='vpn@example.test', from_name='', username='vpn',
                         password='s3cret'),
        },
        'users': [
            {'id': 'u1', 'username': 'alice', 'email': 'alice@example.test', 'enabled': True},
            {'id': 'u2', 'username': 'bob', 'email': '', 'enabled': True},
            {'id': 'u3', 'username': 'carol', 'email': 'carol@example.test', 'enabled': False},
            {'id': 'u4', 'username': 'dave', 'email': 'dave@@example', 'enabled': True},
        ],
        'servers': [
            {'name': 'Paris', 'host': '198.51.100.1',
             'protocols': {'awg': {'port': '55424'}, 'xray': {'port': '443'}}},
            {'name': 'Berlin', 'host': '203.0.113.9', 'protocols': {'awg': {'port': '55424'}}},
        ],
        'user_connections': [
            {'id': 'c1', 'user_id': 'u1', 'server_id': 0, 'protocol': 'awg',
             'client_id': 'peer-1', 'name': 'Laptop'},
            {'id': 'c2', 'user_id': 'u1', 'server_id': 0, 'protocol': 'xray',
             'client_id': 'peer-2', 'name': 'Phone'},
            {'id': 'c3', 'user_id': 'u3', 'server_id': 0, 'protocol': 'awg',
             'client_id': 'peer-3', 'name': 'Tablet'},
        ],
    }


def make_service(data, smtp_client=None, dead_hosts=(), **kwargs):
    """A MailService wired to fakes. `dead_hosts` refuse SSH like a downed node."""
    client = smtp_client if smtp_client is not None else FakeSMTP()
    configs = {'peer-1': AWG_CONFIG, 'peer-2': XRAY_LINK, 'peer-3': AWG_CONFIG}

    def get_ssh(server):
        if server['host'] in dead_hosts:
            raise ConnectionError(f"SSH to {server['host']} recently failed")
        return FakeSSH(server['host'])

    service = MailService(
        load_data=lambda: copy.deepcopy(data),
        get_ssh=get_ssh,
        get_protocol_manager=lambda ssh, protocol: FakeManager(configs),
        manager_call=lambda manager, method, protocol, *a, **kw: getattr(manager, method)(protocol, *a, **kw),
        config_payloads=lambda config, server, protocol: {
            'config': config, 'vpn_link': 'vpn://KEY-' + protocol, 'vpn_qr_chunks': [],
            'vpn_name': protocol},
        protocol_display_name=lambda protocol, *metadata: protocol.upper(),
        protocol_base=lambda protocol: protocol.rstrip('0123456789') or protocol,
        translate=lambda key, lang='en': key,
        smtp_factory=lambda settings: client,
        **kwargs,
    )
    return service, client


def plain_text(message):
    return message.get_body(preferencelist=('plain',)).get_content()


def html_text(message):
    body = message.get_body(preferencelist=('html',))
    return body.get_content() if body else ''


def attachments(message):
    return [(part.get_filename(), part.get_content()) for part in message.iter_attachments()]


# ===================== settings =====================

class MailSettingsTests(unittest.TestCase):
    def test_blank_password_keeps_the_stored_one(self):
        """The settings page never echoes the password back, so an empty field
        in the payload means "unchanged" -- otherwise every unrelated save
        would silently wipe the SMTP credentials."""
        merged = merge_mail_settings({'password': 'stored'}, {'host': 'smtp.test', 'password': ''})
        self.assertEqual(merged['password'], 'stored')

    def test_whitespace_password_clears_it(self):
        merged = merge_mail_settings({'password': 'stored'}, {'password': '   '})
        self.assertEqual(merged['password'], '')

    def test_values_are_trimmed_and_clamped(self):
        merged = merge_mail_settings({}, {'host': '  smtp.test  ', 'port': 999999,
                                          'timeout_seconds': 1, 'from_email': ' vpn@example.test '})
        self.assertEqual(merged['host'], 'smtp.test')
        self.assertEqual(merged['from_email'], 'vpn@example.test')
        self.assertEqual(merged['port'], 65535)
        self.assertEqual(merged['timeout_seconds'], 5)

    def test_unknown_security_mode_is_ignored(self):
        merged = merge_mail_settings({'security': 'ssl'}, {'security': 'whatever'})
        self.assertEqual(merged['security'], 'ssl')

    def test_validation_names_the_missing_piece(self):
        with self.assertRaises(MailError) as ctx:
            validate_mail_settings(dict(DEFAULT_MAIL_SETTINGS))
        self.assertEqual(str(ctx.exception), 'mail_error_disabled')

        with self.assertRaises(MailError) as ctx:
            validate_mail_settings(dict(DEFAULT_MAIL_SETTINGS, enabled=True))
        self.assertEqual(str(ctx.exception), 'mail_error_no_host')

        with self.assertRaises(MailError) as ctx:
            validate_mail_settings(dict(DEFAULT_MAIL_SETTINGS, enabled=True, host='smtp.test'))
        self.assertEqual(str(ctx.exception), 'mail_error_no_sender')

    def test_address_check_rejects_the_unusable(self):
        self.assertTrue(is_valid_email('alice@example.test'))
        self.assertFalse(is_valid_email('alice@@example'))
        self.assertFalse(is_valid_email('alice at example.test'))
        self.assertFalse(is_valid_email(''))


# ===================== transport =====================

class SmtpTransportTests(unittest.TestCase):
    def settings(self, **kw):
        return dict(DEFAULT_MAIL_SETTINGS, enabled=True, host='smtp.test',
                    from_email='vpn@example.test', **kw)

    def test_starttls_and_login_run_once_per_session(self):
        client = FakeSMTP()
        with SmtpTransport(self.settings(username='vpn', password='pw'),
                           lambda settings: client) as transport:
            transport.send(build_stub_message('a@example.test'))
            transport.send(build_stub_message('b@example.test'))
        self.assertTrue(client.started_tls)
        self.assertEqual(client.login_as, ('vpn', 'pw'))
        self.assertEqual(len(client.sent), 2)
        self.assertTrue(client.quit_called)

    def test_no_login_without_a_username(self):
        client = FakeSMTP()
        with SmtpTransport(self.settings(security='none'), lambda settings: client) as transport:
            transport.send(build_stub_message('a@example.test'))
        self.assertIsNone(client.login_as)
        self.assertFalse(client.started_tls)

    def test_a_dropped_session_is_reopened_once(self):
        """Providers close idle sessions mid-run; the message must still go out."""
        clients = []

        def factory(settings):
            client = FakeSMTP(fail_first_send=not clients)
            clients.append(client)
            return client

        with SmtpTransport(self.settings(), factory) as transport:
            transport.send(build_stub_message('a@example.test'))
        self.assertEqual(len(clients), 2)
        self.assertEqual(len(clients[1].sent), 1)


def build_stub_message(recipient):
    message, _ = build_message(
        settings={'from_email': 'vpn@example.test', 'from_name': ''},
        recipient=recipient,
        username='alice',
        items=[],
        options=MailOptions(),
        translate=lambda key: key,
    )
    return message


# ===================== message =====================

class MessageBuildingTests(unittest.TestCase):
    def items(self):
        return [
            {'name': 'Laptop', 'protocol': 'awg', 'protocol_name': 'AWG', 'server_name': 'Paris',
             'config': AWG_CONFIG, 'link': 'vpn://KEY'},
            {'name': 'Phone', 'protocol': 'xray', 'protocol_name': 'XRAY', 'server_name': 'Paris',
             'config': '', 'link': XRAY_LINK},
        ]

    def build(self, options=None, appearance=None):
        return build_message(
            settings={'from_email': 'vpn@example.test', 'from_name': '', 'reply_to': 'help@example.test'},
            recipient='alice@example.test',
            username='alice',
            items=self.items(),
            options=options or MailOptions(),
            translate=lambda key: key,
            appearance=appearance if appearance is not None else {'title': 'Amnezia', 'logo': 'AW'},
        )

    def test_files_are_attached_and_links_are_in_the_body(self):
        message, attached = self.build()
        self.assertEqual(attached, 1)                       # only the AWG peer carries a file
        self.assertEqual(attachments(message), [('Laptop.conf', AWG_CONFIG)])
        text = plain_text(message)
        self.assertIn('vpn://KEY', text)
        self.assertIn(XRAY_LINK, text)
        self.assertIn('Laptop.conf', text)

    def test_the_html_half_carries_the_panel_appearance(self):
        message, _ = self.build()
        html = html_text(message)
        self.assertIn('AW Amnezia', html)
        self.assertIn('#7c3aed', html)                      # the panel's accent, inlined
        self.assertIn('vpn://KEY', html)

    def test_configs_can_be_left_out(self):
        message, attached = self.build(MailOptions(include_configs=False))
        self.assertEqual(attached, 0)
        self.assertEqual(attachments(message), [])
        self.assertIn('vpn://KEY', plain_text(message))

    def test_links_can_be_left_out(self):
        message, attached = self.build(MailOptions(include_links=False))
        self.assertEqual(attached, 1)
        self.assertNotIn('vpn://KEY', plain_text(message))
        self.assertNotIn(XRAY_LINK, plain_text(message))

    def test_asking_for_neither_is_refused(self):
        with self.assertRaises(MailError):
            MailOptions(include_configs=False, include_links=False)

    def test_subject_headers_and_reply_to(self):
        message, _ = self.build()
        self.assertEqual(message['Subject'], 'mail_default_subject — Amnezia')
        self.assertEqual(message['To'], 'alice@example.test')
        self.assertEqual(message['Reply-To'], 'help@example.test')
        self.assertEqual(message['Auto-Submitted'], 'auto-generated')

        message, _ = self.build(MailOptions(subject='Custom'))
        self.assertEqual(message['Subject'], 'Custom')

    def test_a_multiline_subject_is_folded_not_fatal(self):
        """Header values may not carry linefeeds and EmailMessage raises on
        them, so a subject pasted out of a chat must not fail the send."""
        options = MailOptions(subject='Your keys\nand links  ')
        self.assertEqual(options.subject, 'Your keys and links')
        message, _ = self.build(options)
        self.assertEqual(message['Subject'], 'Your keys and links')

    def test_filenames_are_sanitised_and_unique(self):
        items = [
            {'name': 'Laptop / home', 'protocol': 'awg', 'protocol_name': 'AWG', 'server_name': '',
             'config': AWG_CONFIG, 'link': ''},
            {'name': 'Laptop / home', 'protocol': 'awg', 'protocol_name': 'AWG', 'server_name': '',
             'config': AWG_CONFIG, 'link': ''},
        ]
        message, attached = build_message(
            settings={'from_email': 'vpn@example.test'}, recipient='alice@example.test',
            username='alice', items=items, options=MailOptions(), translate=lambda key: key)
        self.assertEqual(attached, 2)
        self.assertEqual([name for name, _ in attachments(message)],
                         ['Laptop_home.conf', 'Laptop_home_2.conf'])

    def test_an_admin_note_reaches_both_halves(self):
        message, _ = self.build(MailOptions(message='Line one\nLine two'))
        self.assertIn('Line one\nLine two', plain_text(message))
        self.assertIn('Line one<br>Line two', html_text(message))


# ===================== collecting and sending for one user =====================

class SendToUserTests(unittest.TestCase):
    def test_a_user_gets_every_connection_they_own(self):
        service, client = make_service(base_data())
        result = service.send_to_user('u1', MailOptions())
        self.assertEqual(result['status'], 'sent')
        self.assertEqual(result['email'], 'alice@example.test')
        self.assertEqual(result['connections'], 2)
        self.assertEqual(result['attachments'], 1)
        self.assertEqual(len(client.sent), 1)
        self.assertEqual(client.sent[0]['To'], 'alice@example.test')

    def test_a_link_protocol_travels_as_a_link_not_a_file(self):
        service, _ = make_service(base_data())
        data = base_data()
        items, errors = service.collect_items(data, data['users'][0])
        self.assertEqual(errors, [])
        by_name = {item['name']: item for item in items}
        self.assertEqual(by_name['Phone']['config'], '')
        self.assertEqual(by_name['Phone']['link'], XRAY_LINK)
        self.assertEqual(by_name['Laptop']['config'], AWG_CONFIG)

    def test_a_dead_server_costs_one_connection_not_the_message(self):
        data = base_data()
        data['user_connections'].append({'id': 'c4', 'user_id': 'u1', 'server_id': 1,
                                         'protocol': 'awg', 'client_id': 'peer-9', 'name': 'Berlin peer'})
        service, client = make_service(data, dead_hosts={'203.0.113.9'})
        result = service.send_to_user('u1', MailOptions())
        self.assertEqual(result['connections'], 2)
        self.assertEqual(len(result['warnings']), 1)
        self.assertIn('Berlin peer', result['warnings'][0])
        self.assertEqual(len(client.sent), 1)

    def test_the_recipient_can_be_overridden_for_one_send(self):
        service, client = make_service(base_data())
        service.send_to_user('u1', MailOptions(recipient='other@example.test'))
        self.assertEqual(client.sent[0]['To'], 'other@example.test')

    def test_a_user_without_an_address_is_refused(self):
        service, _ = make_service(base_data())
        with self.assertRaises(MailError) as ctx:
            service.send_to_user('u2', MailOptions())
        self.assertEqual(str(ctx.exception), 'mail_error_no_recipient')

    def test_a_user_without_connections_is_refused(self):
        data = base_data()
        data['user_connections'] = []
        service, _ = make_service(data)
        with self.assertRaises(MailError) as ctx:
            service.send_to_user('u1', MailOptions())
        self.assertEqual(str(ctx.exception), 'mail_error_no_connections')

    def test_an_unknown_user_is_a_404(self):
        service, _ = make_service(base_data())
        with self.assertRaises(MailError) as ctx:
            service.send_to_user('nobody', MailOptions())
        self.assertEqual(ctx.exception.status_code, 404)

    def test_settings_must_be_usable(self):
        data = base_data()
        data['settings']['mail']['enabled'] = False
        service, _ = make_service(data)
        with self.assertRaises(MailError) as ctx:
            service.send_to_user('u1', MailOptions())
        self.assertEqual(str(ctx.exception), 'mail_error_disabled')


# ===================== the mass send =====================

class BulkSendTests(unittest.TestCase):
    def run_bulk(self, data, client=None, **kwargs):
        service, client = make_service(data, smtp_client=client)
        service.start_bulk(MailOptions(**kwargs), background=False)
        return service.bulk_status(), client

    def test_counters_explain_every_user(self):
        """alice is sent to; bob has no address; carol is disabled; dave's
        address is malformed; a user with no connections is skipped, not failed."""
        data = base_data()
        data['users'].append({'id': 'u5', 'username': 'erin', 'email': 'erin@example.test',
                              'enabled': True})
        status, client = self.run_bulk(data)
        self.assertFalse(status['running'])
        self.assertEqual(status['total'], 5)
        self.assertEqual(status['sent'], 1)
        self.assertEqual(status['skipped'], 4)
        self.assertEqual(status['failed'], 0)
        reasons = {row['username']: row.get('reason') for row in status['results']
                   if row['status'] == 'skipped'}
        self.assertEqual(reasons['bob'], 'mail_skip_no_email')
        self.assertEqual(reasons['carol'], 'mail_skip_disabled')
        self.assertEqual(reasons['dave'], 'mail_skip_bad_email')
        self.assertEqual(reasons['erin'], 'mail_error_no_connections')
        self.assertEqual([m['To'] for m in client.sent], ['alice@example.test'])

    def test_disabled_users_are_included_when_asked(self):
        status, client = self.run_bulk(base_data(), only_enabled=False)
        self.assertEqual(status['sent'], 2)
        self.assertEqual(sorted(m['To'] for m in client.sent),
                         ['alice@example.test', 'carol@example.test'])

    def test_one_refused_address_does_not_stop_the_run(self):
        client = FakeSMTP(fail_recipients={'alice@example.test'})
        data = base_data()
        data['users'].append({'id': 'u5', 'username': 'erin', 'email': 'erin@example.test',
                              'enabled': True})
        data['user_connections'].append({'id': 'c5', 'user_id': 'u5', 'server_id': 0,
                                         'protocol': 'awg', 'client_id': 'peer-1', 'name': 'Desktop'})
        status, client = self.run_bulk(data, client=client)
        self.assertEqual(status['failed'], 1)
        self.assertEqual(status['sent'], 1)
        self.assertEqual([m['To'] for m in client.sent], ['erin@example.test'])

    def test_one_session_carries_the_whole_run(self):
        """Reconnecting per message is what gets a sending account throttled."""
        data = base_data()
        for index in range(3):
            uid = f'bulk-{index}'
            data['users'].append({'id': uid, 'username': uid, 'email': f'{uid}@example.test',
                                  'enabled': True})
            data['user_connections'].append({'id': f'conn-{index}', 'user_id': uid, 'server_id': 0,
                                             'protocol': 'awg', 'client_id': 'peer-1', 'name': 'PC'})
        opened = []

        def factory(settings):
            client = FakeSMTP()
            opened.append(client)
            return client

        service = make_service(data)[0]
        service._smtp_factory = factory
        service.start_bulk(MailOptions(), background=False)
        self.assertEqual(len(opened), 1)
        self.assertEqual(len(opened[0].sent), 4)
        self.assertTrue(opened[0].quit_called)

    def test_explicit_user_ids_narrow_the_run(self):
        service, client = make_service(base_data())
        service.start_bulk(MailOptions(), user_ids=['u2'], background=False)
        status = service.bulk_status()
        self.assertEqual(status['total'], 1)
        self.assertEqual(status['skipped'], 1)
        self.assertEqual(client.sent, [])

    def test_a_second_run_is_refused_while_one_is_in_flight(self):
        release = threading.Event()

        class BlockingSMTP(FakeSMTP):
            def send_message(self, message):
                release.wait(5)
                super().send_message(message)

        service, client = make_service(base_data(), smtp_client=BlockingSMTP())
        service.start_bulk(MailOptions())
        try:
            with self.assertRaises(MailError) as ctx:
                service.start_bulk(MailOptions())
            self.assertEqual(ctx.exception.status_code, 409)
        finally:
            release.set()
        deadline = time.time() + 5
        while service.bulk_status()['running'] and time.time() < deadline:
            time.sleep(0.02)
        self.assertFalse(service.bulk_status()['running'])
        self.assertEqual(service.bulk_status()['sent'], 1)

    def test_a_run_whose_settings_break_mid_flight_still_ends(self):
        """The worker thread re-reads the settings. If they went bad in between
        the job must finish with an error -- a job stuck on "running" would
        also block every later run with a 409."""
        data = base_data()
        reads = []

        def load_data():
            reads.append(1)
            snapshot = copy.deepcopy(data)
            if len(reads) > 1:              # start_bulk already validated once
                snapshot['settings']['mail']['enabled'] = False
            return snapshot

        service, _ = make_service(data)
        service._load_data = load_data
        service.start_bulk(MailOptions(), background=False)
        status = service.bulk_status()
        self.assertFalse(status['running'])
        self.assertEqual(status['error'], 'mail_error_disabled')

    def test_nobody_to_send_to_is_an_error_not_an_empty_run(self):
        data = base_data()
        data['users'] = []
        service, _ = make_service(data)
        with self.assertRaises(MailError) as ctx:
            service.start_bulk(MailOptions(), background=False)
        self.assertEqual(str(ctx.exception), 'mail_error_no_recipients')


# ===================== the API surface =====================

class MailApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        self._mail_svc = panel.mail_svc
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({'servers': [], 'users': [{'id': 'admin-id', 'username': 'admin', 'password_hash': panel.hash_password('admin'), 'role': 'admin', 'enabled': True}], 'user_connections': []}, f)
        self._monitor_flag = panel._conn_monitor_started
        panel._conn_monitor_started = True

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel.mail_svc = self._mail_svc
        panel._conn_monitor_started = self._monitor_flag
        shutil.rmtree(self.tmp, ignore_errors=True)

    def settings_payload(self, **mail):
        return {
            'appearance': {'title': 'Amnezia', 'logo': 'AW', 'subtitle': 'Web Panel'},
            'sync': {},
            'captcha': {'enabled': False},
            'telegram': {'token': '', 'enabled': False},
            'ssl': {'enabled': False},
            'mail': dict({'enabled': True, 'host': 'smtp.example.test',
                          'from_email': 'vpn@example.test', 'username': 'vpn',
                          'password': 's3cret'}, **mail),
        }

    def login(self, client):
        response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)

    def test_old_data_files_get_the_mail_block(self):
        self.assertEqual(panel.load_data()['settings']['mail'], dict(DEFAULT_MAIL_SETTINGS))

    def test_settings_round_trip_keeps_the_password(self):
        with TestClient(panel.app) as client:
            self.login(client)
            saved = client.post('/api/settings/save', json=self.settings_payload())
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(panel.load_data()['settings']['mail']['password'], 's3cret')

            # a later save with the field left empty must not wipe it
            again = client.post('/api/settings/save', json=self.settings_payload(password=''))
            self.assertEqual(again.status_code, 200, again.text)
            stored = panel.load_data()['settings']['mail']
            self.assertEqual(stored['password'], 's3cret')
            self.assertEqual(stored['host'], 'smtp.example.test')

    def test_every_mail_endpoint_needs_a_session(self):
        with TestClient(panel.app) as client:
            for method, url in (('post', '/api/settings/mail/test'),
                                ('post', '/api/users/u1/mail/send'),
                                ('post', '/api/users/mail/bulk'),
                                ('get', '/api/users/mail/bulk/status')):
                response = (client.get(url) if method == 'get'
                            else client.post(url, json={}))
                self.assertEqual(response.status_code, 401, f'{method} {url}: {response.text}')

    def test_sending_reports_the_error_in_the_admin_language(self):
        with TestClient(panel.app) as client:
            self.login(client)
            data = panel.load_data()
            data['users'].append({'id': 'u9', 'username': 'nomail', 'email': '',
                                  'role': 'none', 'enabled': True})
            panel.save_data(data)
            client.post('/api/settings/save', json=self.settings_payload())

            response = client.post('/api/users/u9/mail/send', json={})
            self.assertEqual(response.status_code, 400, response.text)
            body = response.json()
            self.assertEqual(body['code'], 'mail_error_no_recipient')
            self.assertNotEqual(body['error'], body['code'])     # translated, not the raw key

    def test_a_single_send_goes_out_through_the_configured_smtp(self):
        with TestClient(panel.app) as client:
            self.login(client)
            data = panel.load_data()
            data['servers'] = [{'name': 'Paris', 'host': '198.51.100.1', 'ssh_port': 22,
                                'username': 'root', 'password': 'x',
                                'protocols': {'awg': {'installed': True, 'port': '55424'}}}]
            data['users'].append({'id': 'u9', 'username': 'alice', 'email': 'alice@example.test',
                                  'role': 'none', 'enabled': True})
            data['user_connections'] = [{'id': 'c9', 'user_id': 'u9', 'server_id': 0,
                                         'protocol': 'awg', 'client_id': 'peer-1', 'name': 'Laptop'}]
            panel.save_data(data)
            client.post('/api/settings/save', json=self.settings_payload())

            service, smtp = make_service(panel.load_data())
            panel.mail_svc = service

            response = client.post('/api/users/u9/mail/send',
                                   json={'include_configs': True, 'include_links': True})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['email'], 'alice@example.test')
            self.assertEqual([m['To'] for m in smtp.sent], ['alice@example.test'])

            status = client.get('/api/users/mail/bulk/status')
            self.assertEqual(status.status_code, 200, status.text)
            self.assertFalse(status.json()['running'])


if __name__ == '__main__':
    unittest.main()
