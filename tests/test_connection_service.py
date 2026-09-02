import asyncio
import copy
import unittest

from connection_service import ConnectionService, RateLimitError, SelfServiceError


class FakeSSH:
    def __init__(self):
        self.connected = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False


class FakeManager:
    def __init__(self, result=None):
        self.result = result or {'client_id': 'client-1', 'config': 'client config'}
        self.removed = []

    def add_client(self, protocol, name, host, port):
        return dict(self.result)

    def remove_client(self, protocol, client_id):
        self.removed.append((protocol, client_id))


class FailingManager(FakeManager):
    def add_client(self, protocol, name, host, port):
        raise RuntimeError('remote failed')


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
        'users': [{'id': 'user-1', 'username': 'alice', 'enabled': True}],
        'servers': [
            {
                'name': 'Server 1',
                'host': 'vpn.example.test',
                'self_service_enabled': True,
                'protocols': {'awg': {'port': '55424'}, 'xray': {'port': '443'}},
            },
            {
                'name': 'Server 2',
                'host': 'vpn2.example.test',
                'self_service_enabled': False,
                'protocols': {'awg': {'port': '55424'}, 'awg2': {'port': '55425'}},
            },
        ],
        'user_connections': [],
    }


class ConnectionServiceTest(unittest.IsolatedAsyncioTestCase):
    def make_service(self, data=None, manager=None, save_raises=False):
        state = copy.deepcopy(data or base_data())
        fake_manager = manager or FakeManager()

        def load_data():
            return state

        def save_data(new_data):
            if save_raises:
                raise RuntimeError('save failed')
            if new_data is not state:
                state.clear()
                state.update(new_data)

        service = ConnectionService(
            load_data=load_data,
            save_data=save_data,
            data_lock=asyncio.Lock(),
            get_ssh=lambda server: FakeSSH(),
            get_protocol_manager=lambda ssh, protocol: fake_manager,
            manager_call=lambda manager, method, protocol, *args: getattr(manager, method)(protocol, *args),
            generate_vpn_link=lambda config: f'vpn://{config}',
        )
        return service, state, fake_manager

    async def test_create_rejects_control_character_in_name(self):
        service, _, _ = self.make_service()

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'bad\nname', 'web')

        self.assertIn('name', str(ctx.exception).lower())

    async def test_create_rejects_html_sensitive_name_characters(self):
        service, _, _ = self.make_service()

        for name in ('bad<name', 'bad>name', 'bad"name', "bad'name", 'bad&name'):
            with self.subTest(name=name):
                with self.assertRaises(SelfServiceError) as ctx:
                    await service.create_user_connection('user-1', 0, 'awg', name, 'web')
                self.assertIn('name', str(ctx.exception).lower())

    async def test_create_rejects_when_global_self_service_disabled(self):
        data = base_data()
        data['settings']['self_service']['enabled'] = False
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertTrue(ctx.exception.forbidden)

    async def test_options_filters_disabled_servers_and_disallowed_protocols(self):
        service, _, _ = self.make_service()

        options = await service.get_self_service_options('user-1', 'web')

        self.assertEqual(options['max_connections_per_user'], 5)
        self.assertEqual(options['remaining_connections'], 5)
        self.assertEqual(
            options['servers'],
            [{'id': 0, 'name': 'Server 1', 'protocols': [{'protocol': 'awg', 'name': 'AmneziaWG'}]}],
        )

    async def test_create_rejects_when_user_reaches_max_connections(self):
        data = base_data()
        data['settings']['self_service']['max_connections_per_user'] = 1
        data['user_connections'].append({'id': 'existing', 'user_id': 'user-1', 'name': 'old'})
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertTrue(ctx.exception.forbidden)

    async def test_create_rejects_duplicate_name_for_user(self):
        data = base_data()
        data['user_connections'].append({'id': 'existing', 'user_id': 'user-1', 'name': 'Home'})
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'Home', 'web')

        self.assertIn('name', str(ctx.exception).lower())

    async def test_delete_rejects_admin_created_connection(self):
        data = base_data()
        data['user_connections'].append({
            'id': 'conn-1',
            'user_id': 'user-1',
            'server_id': 0,
            'protocol': 'awg',
            'client_id': 'client-1',
            'name': 'admin',
            'created_by': 'admin',
        })
        service, _, manager = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.delete_user_connection('user-1', 'conn-1', 'web')

        self.assertTrue(ctx.exception.forbidden)
        self.assertEqual(manager.removed, [])

    async def test_create_rolls_back_remote_peer_when_save_fails(self):
        service, _, manager = self.make_service(save_raises=True)

        with self.assertRaises(RuntimeError):
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertEqual(manager.removed, [('awg', 'client-1')])

    async def test_create_rate_limit_is_distinct(self):
        data = base_data()
        data['settings']['self_service']['rate_limit_count'] = 1
        service, _, _ = self.make_service(data)

        await service.create_user_connection('user-1', 0, 'awg', 'one', 'web')
        with self.assertRaises(RateLimitError):
            await service.create_user_connection('user-1', 0, 'awg', 'two', 'web')

    async def test_failed_create_attempt_consumes_rate_limit(self):
        data = base_data()
        data['settings']['self_service']['rate_limit_count'] = 1
        service, _, _ = self.make_service(data, manager=FailingManager())

        with self.assertRaises(RuntimeError):
            await service.create_user_connection('user-1', 0, 'awg', 'one', 'web')
        with self.assertRaises(RateLimitError):
            await service.create_user_connection('user-1', 0, 'awg', 'two', 'web')

    async def test_rate_limit_is_shared_across_sources(self):
        data = base_data()
        data['settings']['self_service']['rate_limit_count'] = 1
        service, _, _ = self.make_service(data)

        await service.create_user_connection('user-1', 0, 'awg', 'one', 'web')
        with self.assertRaises(RateLimitError):
            await service.create_user_connection('user-1', 0, 'awg', 'two', 'telegram')

    async def test_delete_is_rate_limited(self):
        data = base_data()
        data['settings']['self_service']['rate_limit_count'] = 1
        data['user_connections'].append({
            'id': 'conn-1',
            'user_id': 'user-1',
            'server_id': 0,
            'protocol': 'awg',
            'client_id': 'client-1',
            'name': 'phone',
            'created_by': 'self_service',
        })
        service, _, _ = self.make_service(data)

        await service.delete_user_connection('user-1', 'conn-1', 'web')
        with self.assertRaises(RateLimitError):
            await service.delete_user_connection('user-1', 'missing', 'web')

    async def test_zero_rate_limit_denies_requests(self):
        data = base_data()
        data['settings']['self_service']['rate_limit_count'] = 0
        service, _, _ = self.make_service(data)

        with self.assertRaises(RateLimitError):
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

    async def test_create_fails_for_expired_user(self):
        data = base_data()
        data['users'][0]['expiration_date'] = '2020-01-01T00:00:00+00:00'
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertIn('expir', str(ctx.exception).lower())

    async def test_create_fails_for_unparsable_expiration_date(self):
        data = base_data()
        data['users'][0]['expiration_date'] = 'not-a-date'
        service, _, _ = self.make_service(data)

        with self.assertLogs('connection_service', level='WARNING'):
            with self.assertRaises(SelfServiceError) as ctx:
                await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertTrue(ctx.exception.forbidden)

    async def test_create_fails_for_disabled_user(self):
        data = base_data()
        data['users'][0]['enabled'] = False
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertTrue(ctx.exception.forbidden)

    async def test_create_fails_when_traffic_limit_exceeded(self):
        data = base_data()
        data['users'][0]['traffic_limit'] = 1000
        data['users'][0]['traffic_used'] = 1000
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

        self.assertIn('quota', str(ctx.exception).lower())

    async def test_create_fails_for_invalid_server_id(self):
        service, _, _ = self.make_service()

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 99, 'awg', 'home', 'web')

        self.assertEqual(ctx.exception.status_code, 404)

    async def test_create_fails_when_server_self_service_disabled(self):
        service, _, _ = self.make_service()

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 1, 'awg', 'home', 'web')

        self.assertTrue(ctx.exception.forbidden)

    async def test_create_fails_when_protocol_not_on_server(self):
        data = base_data()
        data['servers'][0]['protocols'] = {'xray': {'port': '443'}}
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError):
            await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')

    async def test_create_succeeds_with_name_at_max_length(self):
        service, _, _ = self.make_service()

        result = await service.create_user_connection('user-1', 0, 'awg', 'a' * 64, 'web')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['connection']['name']), 64)

    async def test_create_fails_with_name_exceeding_max_length(self):
        service, _, _ = self.make_service()

        with self.assertRaises(SelfServiceError):
            await service.create_user_connection('user-1', 0, 'awg', 'a' * 65, 'web')

    async def test_delete_fails_for_nonexistent_connection(self):
        service, _, _ = self.make_service()

        with self.assertRaises(SelfServiceError) as ctx:
            await service.delete_user_connection('user-1', 'nonexistent', 'web')

        self.assertEqual(ctx.exception.status_code, 404)

    async def test_create_succeeds_for_user_with_zero_connections(self):
        service, state, manager = self.make_service()

        result = await service.create_user_connection('user-1', 0, 'awg', 'first', 'web')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len([c for c in state['user_connections'] if c['user_id'] == 'user-1']), 1)

    async def test_same_name_allowed_for_different_users(self):
        data = base_data()
        data['users'].append({'id': 'user-2', 'username': 'bob', 'enabled': True})
        service, state, _ = self.make_service(data)

        r1 = await service.create_user_connection('user-1', 0, 'awg', 'home', 'web')
        r2 = await service.create_user_connection('user-2', 0, 'awg', 'home', 'web')
        self.assertEqual(r1['status'], 'success')
        self.assertEqual(r2['status'], 'success')
        self.assertNotEqual(r1['connection']['id'], r2['connection']['id'])

    async def test_create_merges_connection_into_fresh_data_after_provisioning(self):
        state = base_data()
        state['settings']['self_service']['rate_limit_count'] = 10
        fake_manager = FakeManager()

        def load_data():
            return state

        def save_data(new_data):
            state.clear()
            state.update(new_data)

        class MutatingManager(FakeManager):
            def add_client(self, protocol, name, host, port):
                state['users'][0]['enabled'] = False
                return super().add_client(protocol, name, host, port)

        fake_manager = MutatingManager()
        service = ConnectionService(
            load_data=load_data,
            save_data=save_data,
            data_lock=asyncio.Lock(),
            get_ssh=lambda server: FakeSSH(),
            get_protocol_manager=lambda ssh, protocol: fake_manager,
            manager_call=lambda manager, method, protocol, *args: getattr(manager, method)(protocol, *args),
            generate_vpn_link=lambda config: f'vpn://{config}',
        )

        with self.assertRaises(SelfServiceError):
            await service.create_user_connection('user-1', 0, 'awg', 'first', 'web')

        self.assertFalse(state['users'][0]['enabled'])
        self.assertEqual(state['user_connections'], [])
        self.assertEqual(fake_manager.removed, [('awg', 'client-1')])

    async def test_options_includes_allowed_protocols_when_installed(self):
        data = base_data()
        data['settings']['self_service']['allowed_protocols'] = ['awg', 'xray', 'awg3']
        data['servers'][0]['protocols'] = {
            'awg': {'port': '55424'},
            'xray': {'port': '443'},
            'awg3': {'port': '55426'},
        }
        service, _, _ = self.make_service(data)

        options = await service.get_self_service_options('user-1', 'web')
        protos = [p['protocol'] for p in options['servers'][0]['protocols']]

        self.assertEqual(protos, ['awg', 'xray', 'awg3'])

    async def test_options_omits_protocols_not_in_allowlist(self):
        data = base_data()
        data['servers'][0]['protocols'] = {
            'awg': {'port': '55424'},
            'xray': {'port': '443'},
        }
        service, _, _ = self.make_service(data)

        options = await service.get_self_service_options('user-1', 'web')
        protos = [p['protocol'] for p in options['servers'][0]['protocols']]

        self.assertEqual(protos, ['awg'])
        self.assertNotIn('xray', protos)

    async def test_options_includes_extra_protocol_instances(self):
        data = base_data()
        data['servers'][0]['protocols'] = {
            'awg': {'port': '55424'},
            'awg__2': {'port': '55425'},
        }
        service, _, _ = self.make_service(data)

        options = await service.get_self_service_options('user-1', 'web')
        protos = [p['protocol'] for p in options['servers'][0]['protocols']]

        self.assertEqual(protos, ['awg', 'awg__2'])
        self.assertEqual(
            next(p['name'] for p in options['servers'][0]['protocols'] if p['protocol'] == 'awg__2'),
            'AmneziaWG #2',
        )

    async def test_options_excludes_infrastructure_protocols(self):
        data = base_data()
        data['settings']['self_service']['allowed_protocols'] = [
            'awg', 'dns', 'socks5', 'adguard', 'nginx',
        ]
        data['servers'][0]['protocols'] = {
            'awg': {'port': '55424'},
            'dns': {'port': '53'},
            'socks5': {'port': '1080'},
        }
        service, _, _ = self.make_service(data)

        options = await service.get_self_service_options('user-1', 'web')
        protos = [p['protocol'] for p in options['servers'][0]['protocols']]

        self.assertEqual(protos, ['awg'])

    async def test_create_succeeds_for_xray(self):
        data = base_data()
        data['settings']['self_service']['allowed_protocols'] = ['awg', 'xray']
        service, state, _ = self.make_service(data)

        result = await service.create_user_connection('user-1', 0, 'xray', 'laptop', 'web')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['connection']['protocol'], 'xray')

    async def test_create_succeeds_for_extra_awg_instance(self):
        data = base_data()
        data['servers'][0]['protocols']['awg__2'] = {'port': '55425'}
        service, state, _ = self.make_service(data)

        result = await service.create_user_connection('user-1', 0, 'awg__2', 'tablet', 'web')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['connection']['protocol'], 'awg__2')

    async def test_create_rejects_protocol_not_in_allowlist(self):
        data = base_data()
        data['servers'][0]['protocols']['xray'] = {'port': '443'}
        service, _, _ = self.make_service(data)

        with self.assertRaises(SelfServiceError) as ctx:
            await service.create_user_connection('user-1', 0, 'xray', 'home', 'web')

        self.assertIn('not allowed', str(ctx.exception).lower())


if __name__ == '__main__':
    unittest.main()
