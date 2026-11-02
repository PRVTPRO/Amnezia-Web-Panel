"""Execute real auth functions in isolation: no app startup, data files or SSH."""
import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fastapi.responses import JSONResponse


FUNCTIONS = {
    'get_current_user', '_check_admin', '_request_user', 'api_get_connection_config',
    '_hash_api_token', '_resolve_api_token', 'protocol_base', 'protocol_instance',
}


def isolated_panel():
    path = Path(__file__).resolve().parents[1] / 'app.py'
    tree = ast.parse(path.read_text(encoding='utf-8'))
    nodes = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert {node.name for node in nodes} == FUNCTIONS
    for node in nodes:
        node.decorator_list = []
    namespace = {
        'Request': object, 'ConnectionActionRequest': object,
        'JSONResponse': JSONResponse, 'hashlib': hashlib,
        'logger': Mock(), 'get_ssh': Mock(), 'get_protocol_manager': Mock(),
        '_manager_call': Mock(return_value='owned config'),
        'protocol_public_endpoint': Mock(return_value=('example.invalid', None)),
        'config_payloads': Mock(return_value={}),
        '_touch_api_token': Mock(return_value=False), 'save_data': Mock(),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


class AuthSecurityTests(unittest.TestCase):
    def setUp(self):
        self.panel = isolated_panel()
        self.user = {'id': 'owner', 'role': 'user', 'enabled': True}
        self.connection = {'user_id': 'owner', 'server_id': 0,
                           'client_id': 'shared-id', 'protocol': 'awg'}
        self.data = {'users': [self.user], 'servers': [{'protocols': {}}],
                     'user_connections': [self.connection]}
        self.panel['load_data'] = Mock(return_value=self.data)
        self.request = SimpleNamespace(session={'user_id': 'owner'}, headers={})

    def config(self, protocol='awg'):
        req = SimpleNamespace(client_id='shared-id', protocol=protocol)
        return self.panel['api_get_connection_config'](self.request, 0, req)

    def assert_forbidden_without_transport(self, response):
        self.assertIsInstance(response, JSONResponse)
        self.assertEqual(response.status_code, 403)
        self.panel['get_ssh'].assert_not_called()
        self.panel['get_protocol_manager'].assert_not_called()
        self.panel['_manager_call'].assert_not_called()

    def test_existing_disabled_sessions_are_rejected_centrally(self):
        for role in ('admin', 'support', 'user'):
            with self.subTest(role=role):
                self.user.update(role=role, enabled=True)
                self.assertIs(self.panel['get_current_user'](self.request), self.user)
                self.user['enabled'] = False
                self.assertIsNone(self.panel['get_current_user'](self.request))

    def test_disabled_admin_and_support_lose_privileged_cookie_access(self):
        for role in ('admin', 'support'):
            with self.subTest(role=role):
                self.user.update(role=role, enabled=False)
                self.assertIsNone(self.panel['_check_admin'](self.request))

    def test_disabled_sessions_cannot_download_configs(self):
        for role in ('admin', 'support', 'user'):
            with self.subTest(role=role):
                self.user.update(role=role, enabled=False)
                self.assert_forbidden_without_transport(self.config())

    def test_record_only_session_is_revoked(self):
        self.user['role'] = 'none'
        self.assertIsNone(self.panel['get_current_user'](self.request))
        self.assertIsNone(self.panel['_check_admin'](self.request))
        self.assert_forbidden_without_transport(self.config())

    def test_legacy_enabled_default_and_active_roles_still_work(self):
        del self.user['enabled']
        for role in ('admin', 'support', 'user'):
            with self.subTest(role=role):
                self.user['role'] = role
                self.assertIs(self.panel['get_current_user'](self.request), self.user)
                self.assertEqual(self.config()['config'], 'owned config')

    def test_missing_and_deleted_session_users_are_rejected(self):
        for session in ({}, {'user_id': 'deleted'}):
            with self.subTest(session=session):
                self.request.session = session
                self.assertIsNone(self.panel['get_current_user'](self.request))
                self.assert_forbidden_without_transport(self.config())

    def test_bearer_tokens_remain_revoked_on_disable_or_demotion(self):
        token = 'synthetic-token'
        self.data['api_tokens'] = [{'user_id': 'owner', 'token_hash':
                                   hashlib.sha256(token.encode()).hexdigest()}]
        self.request.session = {}
        self.request.headers = {'Authorization': 'Bearer ' + token}
        self.user['role'] = 'admin'
        self.assertIs(self.panel['_check_admin'](self.request), self.user)
        for role, enabled in (('admin', False), ('support', False),
                              ('user', True), ('none', True)):
            with self.subTest(role=role, enabled=enabled):
                self.user.update(role=role, enabled=enabled)
                self.assertIsNone(self.panel['_check_admin'](self.request))

    def test_duplicate_client_id_does_not_authorize_other_protocol_or_instance(self):
        for protocol in ('awg__2', 'awg2', 'awg3', 'awg_legacy', 'xray'):
            with self.subTest(protocol=protocol):
                self.data['user_connections'] = [self.connection, {
                    **self.connection, 'user_id': 'someone-else', 'protocol': protocol}]
                self.assert_forbidden_without_transport(self.config(protocol))

    def test_exact_owned_tuple_and_manager_aliases_work(self):
        # AWGManager._instance_index normalizes first and numeric instances.
        for owned, requested in (('awg', 'awg'), ('awg', 'awg__1'),
                                 ('awg__1', 'awg'), ('awg__2', 'awg__02'),
                                 ('awg2__2', 'awg2__2')):
            with self.subTest(owned=owned, requested=requested):
                self.connection['protocol'] = owned
                self.assertEqual(self.config(requested)['config'], 'owned config')
                self.assertEqual(self.panel['_manager_call'].call_args.args[2], requested)

    def test_missing_protocol_does_not_imply_awg_ownership(self):
        del self.connection['protocol']
        self.assert_forbidden_without_transport(self.config())

    def test_unknown_roles_do_not_bypass_ownership(self):
        self.user['role'] = 'unexpected-role'
        self.assert_forbidden_without_transport(self.config('awg__2'))

    def test_explicit_privileged_roles_can_access_unowned_protocols(self):
        self.data['user_connections'] = []
        for role in ('admin', 'support'):
            with self.subTest(role=role):
                self.user['role'] = role
                self.assertEqual(self.config('awg__2')['config'], 'owned config')


if __name__ == '__main__':
    unittest.main()
