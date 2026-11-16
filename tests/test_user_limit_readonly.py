"""Connection-limit defaults must not turn reads into state migrations."""
import ast
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from connection_service import ConnectionService
from pydantic import ValidationError
from tests.test_user_update_race import actual_code


SOURCE = Path(__file__).resolve().parents[1] / 'app.py'


class LimitReadOnly(unittest.TestCase):
    def test_legacy_and_explicit_limits_do_not_write_or_change_users(self):
        users = [
            {'id': 'legacy', 'enabled': True, 'traffic_used': 123,
             'disable_reasons': ['manual'], 'expiration_date': None},
            {'id': 'individual', 'max_connections': 2, 'traffic_used': 456},
        ]
        document = {'users': users, 'servers': [], 'user_connections': [
            {'id': 'owned', 'user_id': 'legacy', 'server_id': 0,
             'protocol': 'awg3', 'client_id': 'client-a'}]}
        node = next(n for n in ast.parse(SOURCE.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'load_data')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.json'
            path.write_text(json.dumps(document))
            before = path.read_bytes()
            save = Mock(side_effect=AssertionError('read attempted persistence'))
            ns = dict(os=os, json=json, DATA_FILE=str(path), save_data=save,
                      DEFAULT_MAIL_SETTINGS={}, DEFAULT_SELF_SERVICE_SETTINGS={})
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), ns)
            for _ in range(2):
                loaded = ns['load_data']()
                self.assertEqual(loaded['users'], users)
                self.assertEqual(loaded['user_connections'], document['user_connections'])
                self.assertEqual(path.read_bytes(), before)
            save.assert_not_called()

    def test_effective_limit_defaults_and_invalid_legacy_values_are_read_only(self):
        service = ConnectionService.__new__(ConnectionService)
        for user, expected in [({}, 5), ({'max_connections': 0}, 5),
                               ({'max_connections': 2}, 2),
                               ({'max_connections': 'invalid'}, 5)]:
            with self.subTest(user=user):
                before = copy.deepcopy(user)
                self.assertEqual(service._effective_max_connections(
                    user, {'max_connections_per_user': 5}), expected)
                self.assertEqual(user, before)

    def test_real_update_model_keeps_field_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = actual_code(SOURCE, Path(tmp) / 'data.json')['UpdateUserRequest']
            self.assertIsNone(model().max_connections)
            self.assertEqual(model(max_connections=0).max_connections, 0)
            self.assertEqual(model(max_connections=100).max_connections, 100)
            for invalid in (-1, 101, 'not-a-limit'):
                with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                    model(max_connections=invalid)
