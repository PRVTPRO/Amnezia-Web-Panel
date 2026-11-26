"""The admin connections list of the Telegram bot (#414).

Since 7d5bb7b the header of that list named the protocol the way the
server records it, but took the server record from a scope it does not
exist in. Every server with connections answered "name 'server' is not
defined". Only servers without any connections escaped, through the
early return that never reaches the header."""
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import telegram_bot as tg_bot
from protocol_names import server_protocol_names
from test_telegram_self_service import _callback_update, _dispatch_callback, base_data

ADMIN = 222      # the admin of base_data()
CHAT = 111


class AdminConnectionsListTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tg_bot._callback_refs.clear()
        tg_bot._pending_inputs.clear()
        self.data = base_data()
        self.data['servers'][0]['protocols'] = {
            'awg2': {'port': '55425', 'protocol_version': '3.1'}}
        self.data['user_connections'].append({
            'id': 'link-1', 'server_id': 0, 'protocol': 'awg2',
            'client_id': 'peer-1', 'user_id': 'user-1'})
        self.api = AsyncMock()
        self.ssh, self.manager = MagicMock(), MagicMock()
        self.ssh.run_sudo_command.return_value = ('true', '', 0)
        self.manager.container_name = 'amnezia-awg2'
        self.manager.get_clients.return_value = [
            {'clientId': 'peer-1', 'userData': {'clientName': 'Phone'}}]
        self.server_side = MagicMock(return_value=(self.ssh, self.manager))

    async def press(self, data_str):
        """The admin presses a button: the server side is the mock pair."""
        with patch.object(tg_bot, '_get_ssh_and_manager', new=self.server_side):
            await _dispatch_callback(self.api, _callback_update(CHAT, ADMIN, data_str),
                                     lambda: self.data)

    def actions_offered(self):
        """What the buttons of the last message do: ('srv:0', a reference
        action with its payload, or another plain callback)."""
        markup = self.api.edit_message.call_args.kwargs['reply_markup']
        offered = []
        for row in markup['inline_keyboard']:
            for button in row:
                ref = tg_bot._resolve_ref(button['callback_data'])
                offered.append((ref['action'], ref['payload']) if ref
                               else button['callback_data'])
        return offered

    def shown_text(self):
        return self.api.edit_message.call_args.args[2]

    async def test_a_server_with_connections_lists_them(self):
        await self.press(tg_bot._ref('clients', {'sid': 0, 'proto': 'awg2'}))

        text = self.shown_text()
        # the header carries the label the way this server records it
        self.assertIn(server_protocol_names(self.data['servers'][0])['awg2'], text)
        self.assertIn('(1)', text)
        self.assertNotIn('❌', text)
        self.assertEqual([offered[0] for offered in self.actions_offered()],
                         ['client', 'add_client', 'proto'])
        self.assertEqual(self.actions_offered()[0][1]['client_id'], 'peer-1')
        self.manager.get_clients.assert_called_once_with('awg2')

    async def test_an_admin_reaches_the_list_through_server_and_protocol(self):
        # the way it was reported: servers, the server, its protocol
        await self.press('adm:servers')
        self.assertIn('srv:0', self.actions_offered())
        await self.press('srv:0')
        await self.press(tg_bot._ref('proto', {'sid': 0, 'proto': 'awg2'}))
        self.assertIn(('clients', {'sid': 0, 'proto': 'awg2'}), self.actions_offered())
        await self.press(tg_bot._ref('clients', {'sid': 0, 'proto': 'awg2'}))

        self.assertNotIn('❌', self.shown_text())
        self.assertIn('Phone', self.shown_text() + str(self.actions_offered()))

    async def test_a_server_without_connections_still_says_so(self):
        self.manager.get_clients.return_value = []
        await self.press(tg_bot._ref('clients', {'sid': 0, 'proto': 'awg2'}))

        self.assertNotIn('❌', self.shown_text())
        self.assertEqual([offered[0] for offered in self.actions_offered()],
                         ['add_client', 'proto'])

    async def test_the_list_is_loaded_from_the_chosen_server(self):
        await self.press(tg_bot._ref('clients', {'sid': 1, 'proto': 'awg'}))

        self.assertIn(server_protocol_names(self.data['servers'][1])['awg'],
                      self.shown_text())
        self.server_side.assert_called_once_with(self.data['servers'][1], 'awg')
        self.manager.get_clients.assert_called_once_with('awg')


if __name__ == '__main__':
    unittest.main()
