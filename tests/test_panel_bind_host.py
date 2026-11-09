"""The panel binds to loopback unless an admin explicitly exposes it."""
import ast
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import app as panel


ROOT = Path(__file__).resolve().parents[1]


class PanelBindHostTests(unittest.TestCase):
    def test_ssl_model_defaults_to_loopback_only(self):
        settings = panel.SSLSettings()
        self.assertFalse(settings.bind_all_interfaces)
        self.assertEqual(panel.panel_bind_host(settings.model_dump()), '127.0.0.1')

    def test_explicit_setting_binds_all_interfaces(self):
        settings = panel.SSLSettings(bind_all_interfaces=True)
        self.assertEqual(panel.panel_bind_host(settings.model_dump()), '0.0.0.0')

    def test_legacy_data_gets_secure_default_without_losing_ssl_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.json'
            path.write_text(json.dumps({
                'settings': {'ssl': {'enabled': True, 'panel_port': 5443}},
            }), encoding='utf-8')
            with mock.patch.object(panel, 'DATA_FILE', str(path)):
                ssl = panel.load_data()['settings']['ssl']
        self.assertFalse(ssl['bind_all_interfaces'])
        self.assertTrue(ssl['enabled'])
        self.assertEqual(ssl['panel_port'], 5443)

    def test_runtime_uses_the_saved_bind_setting(self):
        source = (ROOT / 'app.py').read_text(encoding='utf-8')
        startup = next(node for node in ast.parse(source).body
                       if isinstance(node, ast.If)
                       and ast.unparse(node.test) == "__name__ == '__main__'")
        assignments = {node.targets[0].id: node for node in startup.body
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)}
        # Execute only bind selection/dict construction, never application startup,
        # threads, sockets, TLS files or a front/server process.
        setup = ast.Module(body=[assignments['front_enabled'], assignments['uvicorn_kwargs']],
                           type_ignores=[])
        code = compile(ast.fix_missing_locations(setup), str(ROOT / 'app.py'), 'exec')
        for front in (None, '0', '1'):
            for saved in (None, False, True):
                with self.subTest(front=front, bind_all_interfaces=saved):
                    ssl = {} if saved is None else {'bind_all_interfaces': saved}
                    bind = mock.Mock(wraps=panel.panel_bind_host)
                    namespace = {'__builtins__': {}, 'app': object(), 'ssl_conf': ssl,
                                 'internal_port': 5001, 'panel_bind_host': bind,
                                 'os': SimpleNamespace(environ={} if front is None else {'PANEL_FRONT': front})}
                    exec(code, namespace)
                    self.assertEqual(namespace['front_enabled'], front == '1')
                    expected = '127.0.0.1' if front == '1' else panel.panel_bind_host(ssl)
                    self.assertEqual(namespace['uvicorn_kwargs']['host'], expected)
                    if front == '1':
                        bind.assert_not_called()
                    else:
                        bind.assert_called_once_with(ssl)
        calls = [node for node in ast.walk(startup) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'run'
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == 'uvicorn']
        self.assertEqual(len(calls), 2, 'check backend launch in both modes')
        for call in calls:
            self.assertEqual(ast.unparse(call), 'uvicorn.run(**uvicorn_kwargs)')

    def test_settings_save_preserves_the_explicit_bind_choice(self):
        request = panel.SaveSettingsRequest(
            appearance=panel.AppearanceSettings(),
            sync=panel.SyncSettings(),
            captcha=panel.CaptchaSettings(),
            telegram=panel.TelegramSettings(),
            ssl=panel.SSLSettings(bind_all_interfaces=True),
        )
        self.assertTrue(request.ssl.model_dump()['bind_all_interfaces'])

    def test_settings_card_renders_and_submits_the_checkbox(self):
        template = (ROOT / 'templates' / 'settings.html').read_text(encoding='utf-8')
        self.assertIn('id="ssl_bind_all_interfaces"', template)
        self.assertIn("settings.get('ssl', {}).get('bind_all_interfaces', False)", template)
        self.assertIn("bind_all_interfaces: document.getElementById('ssl_bind_all_interfaces').checked", template)

    def test_every_locale_has_the_bind_label(self):
        for path in (ROOT / 'translations').glob('*.json'):
            with self.subTest(locale=path.stem):
                values = json.loads(path.read_text(encoding='utf-8'))
                self.assertTrue(values['enable_all_interfaces'].strip())


if __name__ == '__main__':
    unittest.main()
