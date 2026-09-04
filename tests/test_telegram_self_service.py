import asyncio
import copy
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import telegram_bot as tg_bot


class TestTelegramCommandMenu(unittest.IsolatedAsyncioTestCase):
    """Test Telegram slash-command suggestions."""

    async def test_default_command_menu_contains_user_commands_only(self):
        api = AsyncMock()
        api.call = AsyncMock(return_value={'ok': True})

        await tg_bot._set_default_commands(api)

        api.call.assert_awaited_once_with(
            'setMyCommands',
            commands=[
                {'command': 'start', 'description': 'Open bot menu'},
                {'command': 'connections', 'description': 'Show my connections'},
                {'command': 'connect', 'description': 'Create a new connection'},
                {'command': 'disconnect', 'description': 'Delete a connection'},
            ],
        )


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
        msg = _text_message(chat_id=111, from_id=111, text='/connect')

        await _dispatch_message_with_service(self.api, msg, self.load_data, MagicMock())

        self.api.send_message.assert_called()
        text = self.api.send_message.call_args[0][1]
        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Create connection', text)
        self.assertIn('Choose a server', text)
        self.assertIn('Server 1', keyboard_text)

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
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create')
        await _dispatch_callback(self.api, msg, self.load_data)
        self.api.edit_message.assert_called()
        call_kwargs = self.api.edit_message.call_args
        reply_markup = call_kwargs[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup)
        self.assertIn('Server 1', keyboard_text)
        # Verify there are callback buttons (resolved refs)
        self.assertIn('callback_data', keyboard_text)

    async def test_user_create_panel_uses_russian_when_telegram_language_is_ru(self):
        msg = _callback_update(chat_id=111, from_id=111, data_str='user_create', language_code='ru')
        await _dispatch_callback(self.api, msg, self.load_data)
        text = self.api.edit_message.call_args[0][2]
        self.assertIn('Создать подключение', text)
        self.assertIn('Выберите сервер', text)
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

    async def test_start_uses_russian_when_telegram_language_is_ru(self):
        msg = _text_message(chat_id=999, from_id=999, text='/start', language_code='ru')
        await _dispatch_message(self.api, msg, self.load_data)
        text = self.api.send_message.call_args[0][1]
        self.assertIn('Ваш аккаунт Telegram не привязан', text)
        self.assertIn('Ваш Telegram ID', text)

    async def test_user_connection_buttons_use_russian_when_telegram_language_is_ru(self):
        msg = _text_message(chat_id=111, from_id=111, text='/start', language_code='ru')
        await _dispatch_message(self.api, msg, self.load_data)
        reply_markup = self.api.send_message.call_args[1].get('reply_markup', {})
        keyboard_text = json.dumps(reply_markup, ensure_ascii=False)
        self.assertIn('Создать подключение', keyboard_text)
        self.assertIn('Обновить список', keyboard_text)
        self.assertNotIn('Create connection', keyboard_text)
        self.assertNotIn('Refresh list', keyboard_text)

    async def test_admin_menu_buttons_use_russian_when_telegram_language_is_ru(self):
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
