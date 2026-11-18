"""Баннер жизненного цикла (#341): оператор видит сервер и операцию.

Проверяется контракт разметки и полнота переводов: баннер обязан называть
затронутый сервер, операцию и причину, а не оставлять панель «просто сломанной».
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANGS = ('ru', 'en', 'fr', 'zh', 'fa')
KEYS = ('lifecycle_fence_title', 'lifecycle_fence_how',
        'lifecycle_fence_steps', 'lifecycle_fence_scope_global',
        'lifecycle_fence_server', 'lifecycle_fence_operation',
        'lifecycle_fence_reason', 'lifecycle_fence_since')


class FenceBannerTests(unittest.TestCase):
    def setUp(self):
        self.base = (ROOT / 'templates/base.html').read_text(encoding='utf-8')

    def test_banner_exists_and_is_hidden_by_default(self):
        self.assertIn('id="lifecycleFence"', self.base)
        self.assertIn('id="lifecycleFenceMeta"', self.base)
        self.assertIn('id="lifecycleFenceSteps"', self.base)
        block = self.base[self.base.index('id="lifecycleFence"'):]
        self.assertIn('hidden', block[:120])

    def test_banner_asks_the_recovery_endpoint_and_names_the_operation(self):
        self.assertIn("fetch('/api/recovery/status'", self.base)
        self.assertIn('state.blocked', self.base)
        self.assertIn('state.scope', self.base)
        self.assertIn('state.operation', self.base)
        self.assertIn("lifecycle_fence_scope_global", self.base)

    def test_banner_offers_the_documented_recovery(self):
        self.assertIn("lifecycle_fence_steps", self.base)
        self.assertIn("lifecycle_fence_how", self.base)

    def test_script_never_references_undefined_helpers(self):
        # Скрытие/показ идёт через DOM, без toast/openModal: base.html
        # подключается и на страницах логина, где этих функций нет.
        script = self.base[self.base.index('Lifecycle fence banner'):]
        script = script[:script.index('</script>')]
        for helper in ('openModal(', 'showToast(', 'apiCall('):
            self.assertNotIn(helper, script)

    def test_every_locale_has_the_banner_keys(self):
        for lang in LANGS:
            with self.subTest(lang=lang):
                data = json.loads((ROOT / 'translations' / ('%s.json' % lang))
                                  .read_text(encoding='utf-8'))
                missing = [key for key in KEYS if key not in data]
                self.assertEqual(missing, [])
                for key in KEYS:
                    self.assertTrue(str(data[key]).strip(), key)

    def test_translations_are_used_through_the_localizer(self):
        for key in KEYS:
            self.assertIn("_('%s')" % key, self.base)


if __name__ == '__main__':
    unittest.main()
