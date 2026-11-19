"""Словарь переводов полон: UI не должен показывать сырые ключи вроде `diag_title`.

Основание — инцидент 2026-11-18: на прод были выложены файлы переводов целиком
из ветки, и 40 ключей (весь блок `diag_*`) пропали. `_t()` вернул сами ключи,
кнопка диагностики стала называться `diag_title`, и никакой тест этого не поймал.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from translation_keys import collect_used, missing


class TranslationCompletenessTest(unittest.TestCase):
    def test_keys_used_by_ui_exist_in_every_locale(self):
        gaps = missing(ROOT)
        detail = {locale: keys[:12] for locale, keys in gaps.items()}
        self.assertFalse(gaps, 'нет перевода в локалях: %s' % detail)

    def test_scan_sees_templates_and_js(self):
        # Защита от «зелёного» теста, который ничего не проверяет.
        used = collect_used(ROOT)
        self.assertGreater(len(used), 500)
        self.assertIn('cancel', used)
        self.assertIn('tp_name', used)


if __name__ == '__main__':
    unittest.main()
