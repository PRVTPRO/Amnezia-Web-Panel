import asyncio
import collections
import copy
import json
from pathlib import Path
import re
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import telegram_bot as tg_bot


class TestTelegramCommandMenu(unittest.IsolatedAsyncioTestCase):
    """Test Telegram slash-command suggestions."""

    async def test_command_menu_is_registered_for_every_panel_language(self):
        api = AsyncMock()
        api.call = AsyncMock(return_value={'ok': True})

        await tg_bot._set_default_commands(api)

        calls = api.call.await_args_list
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[0].args, ('setMyCommands',))
        self.assertNotIn('language_code', calls[0].kwargs)
        self.assertEqual(
            [call.kwargs.get('language_code') for call in calls[1:]],
            ['fa', 'fr', 'ru', 'zh'],
        )
        for call in calls:
            commands = call.kwargs['commands']
            self.assertEqual([item['command'] for item in commands], [
                'start', 'connections', 'connect', 'disconnect',
            ])
            self.assertTrue(all(item['description'].strip() for item in commands))
        self.assertEqual(calls[0].kwargs['commands'][0]['description'], 'Open bot menu')
        self.assertNotEqual(
            calls[-1].kwargs['commands'][0]['description'],
            calls[0].kwargs['commands'][0]['description'],
        )


class TestTelegramLanguagePreference(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.save_data = lambda data: self.data.update(copy.deepcopy(data))
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_first_start_shows_language_picker_before_greeting(self):
        msg = _text_message(chat_id=111, from_id=111, text='/start', language_code='ru')
        await tg_bot._dispatch(self.api, msg, self.load_data, lambda *args: 'vpn://x', self.save_data)
        text = self.api.send_message.call_args[0][1]
        markup = self.api.send_message.call_args.kwargs['reply_markup']
        buttons = [button for row in markup['inline_keyboard'] for button in row]
        self.assertIn(tg_bot._tt('ru', 'language_prompt'), text)
        self.assertNotIn('Choose language', text)
        self.assertNotIn('Привет', text)
        self.assertEqual({button['callback_data'] for button in buttons},
                         {'lang:en', 'lang:fa', 'lang:fr', 'lang:ru', 'lang:zh'})

    async def test_selected_language_is_saved_and_overrides_telegram_language(self):
        update = _callback_update(chat_id=111, from_id=111, data_str='lang:fr', language_code='ru')
        await tg_bot._dispatch(self.api, update, self.load_data, lambda *args: 'vpn://x', self.save_data)
        self.assertEqual(self.data['telegram_preferences']['111']['language'], 'fr')
        greeting = self.api.send_message.call_args[0][1]
        self.assertIn('Vous êtes enregistré', greeting)
        self.assertNotIn('Вы зарегистрированы', greeting)

        self.api.reset_mock()
        msg = _text_message(chat_id=111, from_id=111, text='/start', language_code='ru')
        await tg_bot._dispatch(self.api, msg, self.load_data, lambda *args: 'vpn://x', self.save_data)
        self.assertIn('Vous êtes enregistré', self.api.send_message.call_args[0][1])

    async def test_language_can_be_changed_from_personal_bot_menu(self):
        self.data['telegram_preferences'] = {'111': {'language': 'fr'}}
        msg = _text_message(chat_id=111, from_id=111, text='/start', language_code='ru')
        await tg_bot._dispatch(self.api, msg, self.load_data, lambda *args: 'vpn://x', self.save_data)
        markup = self.api.send_message.call_args.kwargs['reply_markup']
        buttons = [button for row in markup['inline_keyboard'] for button in row]
        language_button = next(button for button in buttons if button['callback_data'] == 'language_menu')
        self.assertIn('Langue', language_button['text'])

        self.api.reset_mock()
        update = _callback_update(chat_id=111, from_id=111, data_str='language_menu', language_code='ru')
        await tg_bot._dispatch(self.api, update, self.load_data, lambda *args: 'vpn://x', self.save_data)
        picker = self.api.edit_message.call_args.kwargs['reply_markup']
        self.assertEqual({button['callback_data'] for row in picker['inline_keyboard'] for button in row},
                         {'lang:en', 'lang:fa', 'lang:fr', 'lang:ru', 'lang:zh'})


class TestTelegramPanelPublicUrl(unittest.TestCase):
    def test_ssl_domain_uses_https_and_configured_panel_port(self):
        data = {'settings': {'ssl': {
            'enabled': True, 'domain': 'panel.example.com', 'panel_port': 5000,
        }}}
        self.assertEqual(
            tg_bot._panel_public_url(data),
            'https://panel.example.com:5000',
        )

    def test_standard_https_port_is_omitted(self):
        data = {'settings': {'ssl': {
            'enabled': True, 'domain': 'panel.example.com', 'panel_port': 443,
        }}}
        self.assertEqual(tg_bot._panel_public_url(data), 'https://panel.example.com')

    def test_duckdns_domain_is_used_when_ssl_domain_is_empty(self):
        data = {'settings': {
            'ssl': {'enabled': True, 'domain': '', 'panel_port': 8443},
            'duckdns': {'enabled': True, 'domain': 'my-panel.duckdns.org'},
        }}
        self.assertEqual(
            tg_bot._panel_public_url(data),
            'https://my-panel.duckdns.org:8443',
        )

    def test_domain_without_ssl_uses_http(self):
        data = {'settings': {'ssl': {
            'enabled': False, 'domain': 'panel.example.com', 'panel_port': 5000,
        }}}
        self.assertEqual(
            tg_bot._panel_public_url(data),
            'http://panel.example.com:5000',
        )

    def test_missing_public_domain_does_not_return_localhost(self):
        self.assertEqual(tg_bot._panel_public_url({'settings': {'ssl': {'enabled': True}}}), '')

    def test_credentials_message_contains_clickable_escaped_url(self):
        message = tg_bot._telegram_credentials_message(
            {'username': 'new-user', 'enabled': True},
            'secret', 'ru', 'https://panel.example.com:5000?a=1&b=2',
        )
        self.assertIn(
            '<a href="https://panel.example.com:5000?a=1&amp;b=2">',
            message,
        )
        self.assertIn('https://panel.example.com:5000?a=1&amp;b=2</a>', message)

    def test_credentials_message_explains_missing_panel_url(self):
        message = tg_bot._telegram_credentials_message(
            {'username': 'new-user', 'enabled': True}, 'secret', 'ru',
        )
        self.assertIn('Адрес панели не настроен', message)


class TestTelegramAutomaticRegistration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_first_start_creates_user_when_enabled(self):
        self.data['settings']['telegram'] = {
            'auto_create_users': True,
            'create_users_disabled': True,
        }
        msg = _text_message(chat_id=333, from_id=333, text='/start')
        msg['message']['from'].update({'first_name': 'Ivan', 'last_name': 'Petrov'})
        save = lambda data: self.data.update(copy.deepcopy(data))

        await tg_bot._dispatch(self.api, msg, lambda: self.data,
                               lambda *args: 'vpn://x', save)

        self.assertFalse(any(u.get('telegramId') == '333' for u in self.data['users']))
        callback = _callback_update(chat_id=333, from_id=333, data_str='lang:ru')
        callback['callback_query']['from'].update({'first_name': 'Ivan', 'last_name': 'Petrov'})
        await tg_bot._dispatch(self.api, callback, lambda: self.data,
                               lambda *args: 'vpn://x', save)

        created = next(u for u in self.data['users'] if u.get('telegramId') == '333')
        self.assertEqual(created['username'], 'Ivan Petrov')
        self.assertEqual(created['role'], 'user')
        self.assertIsNone(created['email'])
        self.assertIsNone(created['expiration_date'])
        self.assertFalse(created['enabled'])
        self.assertIn('manual', created['disable_reasons'])
        self.assertTrue(created['password_hash'])
        self.assertNotEqual(created['password_hash'], '')
        sent_texts = [call.args[1] for call in self.api.send_message.call_args_list
                      if len(call.args) > 1]
        credentials = next(text for text in sent_texts if 'Ваш аккаунт панели создан.' in text)
        self.assertIn('Логин:', credentials)
        self.assertIn('Пароль:', credentials)
        self.assertIn('обратитесь к администратору', credentials)

    async def test_first_start_does_not_create_user_by_default(self):
        msg = _text_message(chat_id=333, from_id=333, text='/start')
        save = lambda data: self.data.update(copy.deepcopy(data))

        await tg_bot._dispatch(self.api, msg, lambda: self.data,
                               lambda *args: 'vpn://x', save)

        self.assertFalse(any(u.get('telegramId') == '333' for u in self.data['users']))

    async def test_first_start_creates_enabled_user_when_disabled_option_is_off(self):
        self.data['settings']['telegram'] = {'auto_create_users': True}
        msg = _text_message(chat_id=444, from_id=444, text='/start')
        msg['message']['from'].update({'first_name': 'Jane', 'last_name': 'Doe'})
        save = lambda data: self.data.update(copy.deepcopy(data))

        await tg_bot._dispatch(self.api, msg, lambda: self.data,
                               lambda *args: 'vpn://x', save)

        callback = _callback_update(chat_id=444, from_id=444, data_str='lang:en')
        callback['callback_query']['from'].update({'first_name': 'Jane', 'last_name': 'Doe'})
        await tg_bot._dispatch(self.api, callback, lambda: self.data,
                               lambda *args: 'vpn://x', save)

        created = next(u for u in self.data['users'] if u.get('telegramId') == '444')
        self.assertEqual(created['username'], 'Jane Doe')
        self.assertTrue(created['enabled'])
        self.assertEqual(created['disable_reasons'], [])


class TestTelegramPublicEndpoint(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.api = AsyncMock()
        self.api.send_message = AsyncMock(return_value={'result': {'message_id': 10}})
        self.api.edit_message = AsyncMock()
        self.api.send_document = AsyncMock()
        self.api.call = AsyncMock()
        self.server = {
            'host': '10.0.0.10',
            'protocols': {
                'awg3': {
                    'port': '55424',
                    'public_host': '144.31.0.0',
                    'public_port': '443',
                },
            },
        }
        self.ssh = MagicMock()
        self.manager = MagicMock()
        self.endpoint = MagicMock(return_value=('144.31.0.0', '443'))

    async def test_reissued_awg_configs_use_protocol_public_host_and_port(self):
        self.manager.get_client_config.return_value = '[Peer]\nEndpoint = 144.31.0.0:443'
        for protocol in ('awg2', 'awg3'):
            with self.subTest(protocol=protocol):
                self.server['protocols'][protocol] = self.server['protocols']['awg3']
                self.endpoint.reset_mock()
                self.manager.reset_mock()
                self.manager.get_client_config.return_value = '[Peer]\nEndpoint = 144.31.0.0:443'
                with patch.object(tg_bot, '_get_ssh_and_manager',
                                  return_value=(self.ssh, self.manager)):
                    await tg_bot._send_config_by_client(
                        self.api, 111, self.server, protocol, 'peer', 'Phone',
                        lambda *args: 'vpn://config', public_endpoint_fn=self.endpoint,
                    )

                self.endpoint.assert_called_once_with(self.server, protocol)
                self.manager.get_client_config.assert_called_once_with(
                    protocol, 'peer', '144.31.0.0', '55424', public_port='443',
                )

    async def test_admin_creation_uses_protocol_public_host_and_port(self):
        self.manager.add_client.return_value = {
            'client_id': 'peer',
            'config': '[Peer]\nEndpoint = 144.31.0.0:443',
        }
        data = {'servers': [self.server], 'users': [], 'user_connections': []}
        save = MagicMock()
        with patch.object(tg_bot, '_get_ssh_and_manager',
                          return_value=(self.ssh, self.manager)):
            await tg_bot._admin_create_client(
                self.api, 111, 42, 0, 'awg3', 'Phone', None,
                lambda: data, save, lambda *args: 'vpn://config',
                public_endpoint_fn=self.endpoint,
            )

        self.endpoint.assert_called_once_with(self.server, 'awg3')
        self.manager.add_client.assert_called_once_with(
            'awg3', 'Phone', '144.31.0.0', '55424', public_port='443',
        )

    def test_public_endpoint_falls_back_to_management_host(self):
        server = {'host': '10.0.0.10', 'protocols': {'awg3': {'port': '55424'}}}
        self.assertEqual(tg_bot._resolve_public_endpoint(server, 'awg3'),
                         ('10.0.0.10', None))


class TestUserSlashCommands(unittest.IsolatedAsyncioTestCase):
    """Test user slash commands shown in Telegram suggestions."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_connect_command_starts_create_flow(self):
        self.data['servers'].append(dict(self.data['servers'][0], name='Server 3'))
        service = MagicMock()
        service.get_self_service_options = AsyncMock(return_value={'remaining_connections': 5})
        msg = _text_message(chat_id=111, from_id=111, text='/connect')

        await _dispatch_message_with_service(self.api, msg, self.load_data, service)

        service.get_self_service_options.assert_awaited_once_with('user-1', 'telegram')
        self.api.send_message.assert_called()
        text = self.api.send_message.call_args[0][1]
        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Create connection', text)
        self.assertIn('Choose a server', text)
        self.assertIn('Server 1', keyboard_text)

    async def test_connect_command_stops_immediately_when_connection_limit_is_reached(self):
        msg = _text_message(chat_id=111, from_id=111, text='/connect', language_code='ru')
        service = MagicMock()
        service.get_self_service_options = AsyncMock(return_value={
            'remaining_connections': 0,
        })

        await _dispatch_message_with_service(self.api, msg, self.load_data, service)

        text = self.api.send_message.call_args[0][1]
        self.assertIn('Достигнут лимит подключений', text)
        self.assertNotIn('Выберите сервер', text)
        self.assertNotIn('Choose a server', text)
        self.assertNotIn('reply_markup', self.api.send_message.call_args.kwargs)

    async def test_connect_command_is_rejected_in_group_chat(self):
        msg = _text_message(chat_id=-100, from_id=111, text='/connect', chat_type='group')

        await _dispatch_message_with_service(self.api, msg, self.load_data, MagicMock())

        text = self.api.send_message.call_args[0][1]
        self.assertIn('private', text.lower())

    async def test_disconnect_command_shows_connections_with_delete_buttons(self):
        self.data['user_connections'] = [{
            'id': 'conn-1',
            'user_id': 'user-1',
            'server_id': 0,
            'protocol': 'awg',
            'name': 'Phone',
            'created_by': 'self_service',
        }]
        msg = _text_message(chat_id=111, from_id=111, text='/disconnect')

        await _dispatch_message_with_service(self.api, msg, self.load_data, MagicMock())

        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Phone', keyboard_text)
        self.assertIn('🗑', keyboard_text)

    async def test_config_callback_is_rejected_in_group_chat(self):
        self.data['user_connections'] = [{
            'id': 'conn-1',
            'user_id': 'user-1',
            'server_id': 0,
            'protocol': 'awg',
            'client_id': 'client-1',
            'name': 'Phone',
            'created_by': 'self_service',
        }]
        msg = _callback_update(chat_id=-100, from_id=111, data_str='cfg:conn-1', chat_type='group')

        await _dispatch_callback(self.api, msg, self.load_data)

        text = self.api.send_message.call_args[0][1]
        self.assertIn('private', text.lower())


def base_data():
    return {
        'settings': {
            'self_service': {
                'enabled': True,
                'web_enabled': True,
                'telegram_enabled': True,
                'max_connections_per_user': 5,
                'rate_limit_count': 3,
                'rate_limit_window_seconds': 60,
                'allowed_protocols': ['awg', 'awg2'],
            }
        },
        'users': [
            {'id': 'user-1', 'username': 'alice', 'enabled': True, 'telegramId': '111'},
            {'id': 'user-2', 'username': 'bob', 'enabled': True, 'telegramId': '222', 'role': 'admin'},
        ],
        'servers': [
            {
                'name': 'Server 1',
                'host': 'vpn.example.test',
                'self_service_enabled': True,
                'protocols': {'awg': {'port': '55424'}, 'awg2': {'port': '55425'}, 'xray': {'port': '443'}},
            },
            {
                'name': 'Server 2',
                'host': 'vpn2.example.test',
                'self_service_enabled': False,
                'protocols': {'awg': {'port': '55424'}},
            },
        ],
        'user_connections': [],
    }


class TestUserCreateCallback(unittest.IsolatedAsyncioTestCase):
    """Test user_create shows self-service servers."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_user_create_shows_servers_for_eligible_user(self):
        self.data['servers'].append(dict(self.data['servers'][0], name='Server 3'))
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create')
        await _dispatch_callback(self.api, msg, self.load_data)
        self.api.edit_message.assert_called()
        call_kwargs = self.api.edit_message.call_args
        reply_markup = call_kwargs[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup)
        self.assertIn('Server 1', keyboard_text)
        self.assertIn('Server 3', keyboard_text)
        self.assertNotIn('Server 2', keyboard_text)
        # Verify there are callback buttons (resolved refs)
        self.assertIn('callback_data', keyboard_text)

    async def test_user_create_reports_disabled_account_before_showing_wizard(self):
        self.data['users'][0]['enabled'] = False
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create', language_code='ru')

        await _dispatch_callback(self.api, msg, self.load_data)

        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Аккаунт отключён', text)
        self.assertNotIn('Выберите сервер', text)
        self.assertIsNone(self.api.edit_message.call_args.kwargs.get('reply_markup'))

    async def test_user_create_skips_server_and_protocol_when_only_one_choice(self):
        self.data['settings']['self_service']['allowed_protocols'] = ['awg']
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create', language_code='ru')

        await _dispatch_callback(self.api, msg, self.load_data)

        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Отправьте имя устройства', text)
        self.assertNotIn('Выберите сервер', text)
        self.assertNotIn('Выберите протокол', text)
        self.assertEqual(
            tg_bot._pending_inputs[tg_bot._pending_key(111, '111')]['sid'], 0)
        self.assertEqual(
            tg_bot._pending_inputs[tg_bot._pending_key(111, '111')]['proto'], 'awg')

    async def test_user_create_server_skips_protocol_when_only_one_choice(self):
        self.data['settings']['self_service']['allowed_protocols'] = ['awg']
        ref_key = tg_bot._ref('user_create_server', {'sid': 0})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key, language_code='ru')

        await _dispatch_callback(self.api, msg, self.load_data)

        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Отправьте имя устройства', text)
        self.assertNotIn('Выберите протокол', text)

    async def test_user_create_stops_immediately_when_connection_limit_is_reached(self):
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create', language_code='ru')
        service = MagicMock()
        service.get_self_service_options = AsyncMock(return_value={
            'remaining_connections': 0,
        })

        await _dispatch_callback_with_service(self.api, msg, self.load_data, service)

        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Достигнут лимит подключений', text)
        self.assertNotIn('Выберите сервер', text)
        self.assertIsNone(self.api.edit_message.call_args.kwargs.get('reply_markup'))

    async def test_user_create_panel_uses_russian_when_telegram_language_is_ru(self):
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create', language_code='ru')
        await _dispatch_callback(self.api, msg, self.load_data)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Server 1', text)
        self.assertIn('Выберите протокол', text)
        self.assertNotIn('Выберите сервер', text)
        self.assertNotIn('Create connection', text)
        self.assertNotIn('Choose a server', text)

    async def test_user_create_shows_no_servers_message_when_self_service_disabled(self):
        self.data['settings']['self_service']['enabled'] = False
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create')
        await _dispatch_callback(self.api, msg, self.load_data)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('administrator', text.lower())

    async def test_user_create_shows_no_servers_message_when_user_not_linked(self):
        msg = _callback_update(chat_id=999, from_id=999, data_str='user_create')
        await _dispatch_callback(self.api, msg, self.load_data)
        self.api.answer_callback.assert_called()
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('denied', text.lower())


class TestUserCreateServerCallback(unittest.IsolatedAsyncioTestCase):
    """Test user_create_server shows protocol options."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_user_create_server_shows_protocols(self):
        payload = {'sid': 0}
        ref_key = tg_bot._ref('user_create_server', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback(self.api, msg, self.load_data)
        call_kwargs = self.api.edit_message.call_args
        reply_markup = call_kwargs[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup)
        self.assertIn('AmneziaWG', keyboard_text)
        self.assertIn('AmneziaWG 2.0', keyboard_text)

    async def test_user_create_server_shows_xray_when_allowed_and_installed(self):
        self.data['settings']['self_service']['allowed_protocols'] = ['awg', 'awg2', 'xray']
        payload = {'sid': 0}
        ref_key = tg_bot._ref('user_create_server', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback(self.api, msg, self.load_data)
        keyboard_text = json.dumps(self.api.edit_message.call_args[1].get('reply_markup', {}))
        self.assertIn('Xray', keyboard_text)

    async def test_user_create_server_shows_extra_protocol_instance(self):
        self.data['servers'][0]['protocols']['awg__2'] = {'port': '55426'}
        payload = {'sid': 0}
        ref_key = tg_bot._ref('user_create_server', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback(self.api, msg, self.load_data)
        keyboard_text = json.dumps(self.api.edit_message.call_args[1].get('reply_markup', {}))
        self.assertIn('AmneziaWG #2', keyboard_text)

    async def test_user_create_protocol_panel_uses_russian_when_telegram_language_is_ru(self):
        ref_key = tg_bot._ref('user_create_protocol', {'sid': 0, 'proto': 'awg2'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key, language_code='ru')
        await _dispatch_callback(self.api, msg, self.load_data)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Создать подключение', text)
        self.assertIn('Протокол', text)
        self.assertIn('Отправьте имя устройства', text)
        self.assertNotIn('Create connection', text)
        self.assertNotIn('Send the device name', text)


class TestUserCreateCancel(unittest.IsolatedAsyncioTestCase):
    """Test user_create_cancel returns to connections list."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_user_create_cancel_returns_to_connections(self):
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create_cancel')
        await _dispatch_callback(self.api, msg, self.load_data)
        self.api.send_message.assert_called()
        text = self.api.send_message.call_args[0][1]
        self.assertIn('connection', text.lower())


class TestUserSelfServiceCreation(unittest.IsolatedAsyncioTestCase):
    """Test full creation flow via ConnectionService."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock(return_value={"result": {"message_id": 100}})
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()
        self.api.send_document = AsyncMock()
        self.api.call = AsyncMock()

        self.mock_service = MagicMock()
        self.mock_service.create_user_connection = AsyncMock(return_value={
            'status': 'success',
            'config': '[Interface]\nPrivateKey = abc',
            'vpn_link': 'vpn://abc',
            'connection': {'id': 'conn-1', 'name': 'MyPhone'},
        })

    async def test_creation_succeeds_for_eligible_user(self):
        payload = {'sid': 0, 'proto': 'awg', 'name': 'MyPhone'}
        ref_key = tg_bot._ref('user_add_client', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        self.mock_service.create_user_connection.assert_called_once()
        self.api.send_message.assert_called()

    async def test_creation_fails_for_non_eligible_user(self):
        payload = {'sid': 0, 'proto': 'awg', 'name': 'MyPhone'}
        ref_key = tg_bot._ref('user_add_client', payload)
        msg = _callback_update(chat_id=999, from_id=999, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        self.mock_service.create_user_connection.assert_not_called()
        self.api.answer_callback.assert_called()
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('denied', text.lower())

    async def test_creation_fails_when_self_service_disabled(self):
        self.data['settings']['self_service']['enabled'] = False
        payload = {'sid': 0, 'proto': 'awg', 'name': 'MyPhone'}
        ref_key = tg_bot._ref('user_add_client', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        self.mock_service.create_user_connection.assert_not_called()

    async def test_creation_error_does_not_expose_exception_text(self):
        self.mock_service.create_user_connection = AsyncMock(side_effect=RuntimeError('secret host path'))
        payload = {'sid': 0, 'proto': 'awg', 'name': 'MyPhone'}
        ref_key = tg_bot._ref('user_add_client', payload)
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)

        with self.assertLogs(tg_bot.logger, level='ERROR'):
            await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)

        text = self.api.send_message.call_args[0][1]
        self.assertNotIn('secret host path', text)
        self.assertIn('error', text.lower())


class TestUserAddClientNameInputState(unittest.IsolatedAsyncioTestCase):
    """Test user_add_client_name pending input resolves user fresh."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock(return_value={"result": {"message_id": 100}})
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()
        self.api.send_document = AsyncMock()
        self.api.call = AsyncMock()

        self.mock_service = MagicMock()
        self.mock_service.create_user_connection = AsyncMock(return_value={
            'status': 'success',
            'config': '[Interface]\nPrivateKey = abc',
            'vpn_link': 'vpn://abc',
            'connection': {'id': 'conn-1', 'name': 'MyPhone'},
        })

    async def test_input_state_resolves_user_fresh(self):
        tg_bot._pending_inputs['111:111'] = {
            'kind': 'user_add_client_name',
            'sid': 0,
            'proto': 'awg',
            'ts': 0,
        }
        # _handle_pending_input expects the raw message dict (not wrapped in 'message' key)
        msg = {'chat': {'id': 111}, 'from': {'id': 111, 'first_name': 'Test'}, 'text': 'MyPhone'}
        handled = await tg_bot._handle_pending_input(
            self.api, msg, self.load_data, None, lambda c: 'vpn://x', self.mock_service
        )
        self.assertTrue(handled)
        self.mock_service.create_user_connection.assert_called_once()
        call_args = self.mock_service.create_user_connection.call_args
        self.assertEqual(call_args[0][0], 'user-1')

    async def test_input_state_creates_connection_for_admin(self):
        tg_bot._pending_inputs['222:222'] = {
            'kind': 'user_add_client_name',
            'sid': 0,
            'proto': 'awg',
            'ts': 0,
        }
        msg = {'chat': {'id': 222}, 'from': {'id': 222, 'first_name': 'Admin'}, 'text': 'AdminPhone'}

        handled = await tg_bot._handle_pending_input(
            self.api, msg, self.load_data, None, lambda c: 'vpn://x', self.mock_service
        )

        self.assertTrue(handled)
        self.mock_service.create_user_connection.assert_called_once()
        call_args = self.mock_service.create_user_connection.call_args
        self.assertEqual(call_args[0][0], 'user-2')
        self.assertEqual(call_args[0][3], 'AdminPhone')

    async def test_input_state_rejects_unlinked_user(self):
        tg_bot._pending_inputs['999:999'] = {
            'kind': 'user_add_client_name',
            'sid': 0,
            'proto': 'awg',
            'ts': 0,
        }
        msg = {'chat': {'id': 999}, 'from': {'id': 999, 'first_name': 'Test'}, 'text': 'MyPhone'}
        handled = await tg_bot._handle_pending_input(
            self.api, msg, self.load_data, None, lambda c: 'vpn://x', self.mock_service
        )
        self.assertTrue(handled)
        self.mock_service.create_user_connection.assert_not_called()
        self.api.send_message.assert_called()
        text = self.api.send_message.call_args[0][1]
        self.assertIn('denied', text.lower())

    async def test_pending_input_is_scoped_to_chat_and_user(self):
        tg_bot._pending_inputs['100:111'] = {
            'kind': 'user_add_client_name',
            'sid': 0,
            'proto': 'awg',
            'ts': 0,
        }
        msg = {'chat': {'id': 100, 'type': 'private'}, 'from': {'id': 222, 'first_name': 'Test'}, 'text': 'OtherPhone'}

        handled = await tg_bot._handle_pending_input(
            self.api, msg, self.load_data, None, lambda c: 'vpn://x', self.mock_service
        )

        self.assertFalse(handled)
        self.mock_service.create_user_connection.assert_not_called()
        self.assertIn('100:111', tg_bot._pending_inputs)


class TestUserDeleteConnection(unittest.IsolatedAsyncioTestCase):
    """Test self-service user can delete their own connection via Telegram."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.data['user_connections'] = [
            {'id': 'conn-1', 'user_id': 'user-1', 'server_id': 0, 'protocol': 'awg',
             'client_id': 'client-1', 'name': 'MyPhone', 'created_by': 'self_service'},
            {'id': 'conn-2', 'user_id': 'user-1', 'server_id': 0, 'protocol': 'awg',
             'client_id': 'client-2', 'name': 'AdminPhone', 'created_by': 'admin'},
        ]
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock(return_value={"result": {"message_id": 100}})
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()
        self.api.call = AsyncMock()
        self.mock_service = MagicMock()
        self.mock_service.delete_user_connection = AsyncMock(return_value={'status': 'success'})

    async def test_keyboard_shows_delete_only_for_self_service_connections(self):
        conns = [c for c in self.data['user_connections'] if c['user_id'] == 'user-1']
        kb = tg_bot._build_connections_keyboard(conns, self.data)
        delete_buttons = [
            btn for row in kb['inline_keyboard']
            for btn in row if btn.get('text') == '🗑'
        ]
        self.assertEqual(len(delete_buttons), 1)

    async def test_user_delete_shows_confirmation(self):
        ref_key = tg_bot._ref('user_delete', {'conn_id': 'conn-1', 'name': 'MyPhone'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('delete', text.lower())
        self.mock_service.delete_user_connection.assert_not_called()

    async def test_user_delete_confirmation_uses_russian_when_telegram_language_is_ru(self):
        ref_key = tg_bot._ref('user_delete', {'conn_id': 'conn-1', 'name': 'MyPhone'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key, language_code='ru')
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Удалить подключение', text)
        self.assertIn('Это действие нельзя отменить', text)
        self.assertNotIn('Delete connection', text)
        self.assertNotIn('This cannot be undone', text)

    async def test_user_delete_confirmation_cancel_button_keeps_cross_icon(self):
        ref_key = tg_bot._ref('user_delete', {'conn_id': 'conn-1', 'name': 'MyPhone'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key, language_code='ru')
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        reply_markup = self.api.edit_message.call_args[1].get('reply_markup', {})
        buttons = [btn for row in reply_markup.get('inline_keyboard', []) for btn in row]
        cancel_button = next(btn for btn in buttons if btn.get('callback_data') == 'refresh')
        self.assertEqual(cancel_button['text'], '❌ Отмена')

    async def test_user_delete_success_uses_russian_when_telegram_language_is_ru(self):
        async def delete_connection(user_id, conn_id, source):
            self.data['user_connections'] = [c for c in self.data['user_connections'] if c['id'] != conn_id]
            return {'status': 'success'}

        self.data['user_connections'] = [self.data['user_connections'][0]]
        self.mock_service.delete_user_connection = AsyncMock(side_effect=delete_connection)
        ref_key = tg_bot._ref('user_delete_confirm', {'conn_id': 'conn-1'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key, language_code='ru')
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Подключение удалено', text)
        self.assertIn('У вас нет подключений', text)
        self.assertNotIn('Connection deleted', text)
        self.assertNotIn('You have no connections', text)

    async def test_user_delete_confirm_calls_service(self):
        ref_key = tg_bot._ref('user_delete_confirm', {'conn_id': 'conn-1'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        self.mock_service.delete_user_connection.assert_called_once()
        args = self.mock_service.delete_user_connection.call_args
        self.assertEqual(args[0][0], 'user-1')
        self.assertEqual(args[0][1], 'conn-1')
        self.assertEqual(args[0][2], 'telegram')

    async def test_user_delete_rejects_unlinked_user(self):
        ref_key = tg_bot._ref('user_delete_confirm', {'conn_id': 'conn-1'})
        msg = _callback_update(chat_id=999, from_id=999, data_str=ref_key)
        await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)
        self.mock_service.delete_user_connection.assert_not_called()

    async def test_user_delete_error_does_not_expose_exception_text(self):
        self.mock_service.delete_user_connection = AsyncMock(side_effect=RuntimeError('secret host path'))
        ref_key = tg_bot._ref('user_delete_confirm', {'conn_id': 'conn-1'})
        msg = _callback_update(chat_id=111, from_id=111, data_str=ref_key)

        with self.assertLogs(tg_bot.logger, level='ERROR'):
            await _dispatch_callback_with_service(self.api, msg, self.load_data, self.mock_service)

        text = self.api.edit_message.call_args[0][2]
        self.assertNotIn('secret host path', text)
        self.assertIn('error', text.lower())


class TestFindUserNumericIdOnly(unittest.IsolatedAsyncioTestCase):
    """Telegram usernames are mutable and must not authenticate panel users."""

    def setUp(self):
        self.data = base_data()
        self.data['users'][0]['telegramId'] = '@alice'
        self.load_data = lambda: self.data

    def test_does_not_match_stored_username(self):
        user = tg_bot._find_user(self.load_data, '999', '@alice')
        self.assertIsNone(user)

    def test_still_matches_numeric_id(self):
        user = tg_bot._find_user(self.load_data, '222', None)
        self.assertIsNotNone(user)
        self.assertEqual(user['id'], 'user-2')

    def test_no_match_without_username(self):
        user = tg_bot._find_user(self.load_data, '999', None)
        self.assertIsNone(user)


class TestDispatchRejectsUsernameSpoof(unittest.IsolatedAsyncioTestCase):
    """A callback username must not resolve a panel account."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.data['users'][0]['telegramId'] = '@alice'
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()
        self.api.edit_message = AsyncMock()
        self.api.answer_callback = AsyncMock()

    async def test_user_create_rejects_username_match(self):
        msg = _callback_update(chat_id=999, from_id=999, data_str='user_create', username='alice')
        await _dispatch_callback(self.api, msg, self.load_data)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('denied', text.lower())


class TestTelegramLocalization(unittest.IsolatedAsyncioTestCase):
    """Test Telegram language_code based localization."""

    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.load_data = lambda: self.data
        self.api = AsyncMock()
        self.api.send_message = AsyncMock()

    def test_telegram_catalog_matches_panel_locales_and_placeholders(self):
        root = Path(__file__).resolve().parents[1] / 'translations'
        panel_locales = {path.stem for path in root.glob('*.json')}
        self.assertEqual(set(tg_bot.TG_TRANSLATIONS), panel_locales)
        reference = tg_bot.TG_TRANSLATIONS['en']
        for lang, catalog in tg_bot.TG_TRANSLATIONS.items():
            with self.subTest(lang=lang):
                self.assertEqual(set(catalog), set(reference))
                for key, value in catalog.items():
                    self.assertIsInstance(value, str)
                    self.assertTrue(value.strip())
                    self.assertEqual(
                        collections.Counter(re.findall(r'\{[^{}]*\}', value)),
                        collections.Counter(re.findall(r'\{[^{}]*\}', reference[key])),
                    )

    async def test_disabled_account_message_is_localized_for_every_language(self):
        expected = {
            'en': 'Account disabled',
            'fa': 'حساب کاربری غیرفعال است',
            'fr': 'Compte désactivé',
            'ru': 'Аккаунт отключён',
            'zh': '账户已被禁用',
        }
        for lang, phrase in expected.items():
            with self.subTest(lang=lang):
                self.api.reset_mock()
                await tg_bot._user_create_access(
                    self.api, 999, {'id': 'user-1', 'enabled': False},
                    self.load_data, None, lang,
                )
                self.assertEqual(
                    self.api.send_message.call_args.args[1],
                    f'❌ {phrase}',
                )

    def test_language_codes_are_normalized_to_panel_locales(self):
        samples = {'en-US': 'en', 'fa-IR': 'fa', 'fr-FR': 'fr', 'RU_ru': 'ru',
                   'zh-Hans': 'zh', 'de-DE': 'en', '': 'en'}
        for code, expected in samples.items():
            with self.subTest(code=code):
                self.assertEqual(tg_bot._tg_lang({'language_code': code}), expected)

    async def test_start_uses_every_supported_telegram_language(self):
        expected_phrases = {
            'en': 'Your Telegram account is not linked',
            'fa': 'حساب تلگرام',
            'fr': 'Votre compte Telegram',
            'ru': 'Ваш аккаунт Telegram',
            'zh': 'Telegram',
        }
        for lang, phrase in expected_phrases.items():
            with self.subTest(lang=lang):
                self.data['telegram_preferences'] = {'999': {'language': lang}}
                self.api.reset_mock()
                msg = _text_message(chat_id=999, from_id=999, text='/start', language_code=lang)
                await _dispatch_message(self.api, msg, self.load_data)
                text = self.api.send_message.call_args[0][1]
                self.assertIn(phrase, text)
                if lang != 'en':
                    self.assertNotIn('Your Telegram account is not linked', text)

    async def test_private_chat_rejection_is_localized(self):
        msg = _text_message(chat_id=-100, from_id=111, text='/connect',
                            language_code='fr-FR', chat_type='group')
        await _dispatch_message(self.api, msg, self.load_data)
        text = self.api.send_message.call_args[0][1]
        self.assertIn('discussion privée', text)
        self.assertNotIn('private chat', text)

    async def test_start_uses_russian_when_telegram_language_is_ru(self):
        self.data['telegram_preferences'] = {'999': {'language': 'ru'}}
        msg = _text_message(chat_id=999, from_id=999, text='/start', language_code='ru')
        await _dispatch_message(self.api, msg, self.load_data)
        text = self.api.send_message.call_args[0][1]
        self.assertIn('Ваш аккаунт Telegram не привязан', text)
        self.assertIn('Ваш Telegram ID', text)

    async def test_user_connection_buttons_use_russian_when_telegram_language_is_ru(self):
        self.data['telegram_preferences'] = {'111': {'language': 'ru'}}
        msg = _text_message(chat_id=111, from_id=111, text='/start', language_code='ru')
        await _dispatch_message(self.api, msg, self.load_data)
        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Создать подключение', keyboard_text)
        self.assertIn('Обновить список', keyboard_text)
        self.assertNotIn('Create connection', keyboard_text)
        self.assertNotIn('Refresh list', keyboard_text)

    async def test_admin_menu_buttons_use_russian_when_telegram_language_is_ru(self):
        self.data['telegram_preferences'] = {'222': {'language': 'ru'}}
        msg = _text_message(chat_id=222, from_id=222, text='/start', language_code='ru')
        await _dispatch_message(self.api, msg, self.load_data)
        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Серверы', keyboard_text)
        self.assertIn('Пользователи', keyboard_text)
        self.assertIn('Мои подключения', keyboard_text)
        self.assertIn('Как добавить сервер', keyboard_text)
        self.assertNotIn('Servers', keyboard_text)
        self.assertNotIn('Users', keyboard_text)


def _callback_update(chat_id, from_id, data_str, username=None, language_code=None, chat_type='private'):
    from_user = {'id': from_id}
    if username:
        from_user['username'] = username
    if language_code:
        from_user['language_code'] = language_code
    return {
        'callback_query': {
            'id': f'cb-{from_id}',
            'from': from_user,
            'message': {'chat': {'id': chat_id, 'type': chat_type}, 'message_id': 42},
            'data': data_str,
        }
    }


def _text_message(chat_id, from_id, text, language_code=None, chat_type='private'):
    from_user = {'id': from_id, 'first_name': 'Test'}
    if language_code:
        from_user['language_code'] = language_code
    return {
        'message': {
            'chat': {'id': chat_id, 'type': chat_type},
            'from': from_user,
            'text': text,
        }
    }


async def _dispatch_callback(api, update, load_data):
    generate_vpn_link_fn = lambda c: f'vpn://{c}'
    await tg_bot._dispatch(api, update, load_data, generate_vpn_link_fn, None)


async def _dispatch_callback_with_service(api, update, load_data, service):
    generate_vpn_link_fn = lambda c: f'vpn://{c}'
    await tg_bot._dispatch(api, update, load_data, generate_vpn_link_fn, None, self_service_svc=service)


async def _dispatch_message(api, update, load_data):
    generate_vpn_link_fn = lambda c: f'vpn://{c}'
    await tg_bot._dispatch(api, update, load_data, generate_vpn_link_fn, None)


async def _dispatch_message_with_service(api, update, load_data, service):
    generate_vpn_link_fn = lambda c: f'vpn://{c}'
    await tg_bot._dispatch(api, update, load_data, generate_vpn_link_fn, None, self_service_svc=service)


if __name__ == '__main__':
    unittest.main()
