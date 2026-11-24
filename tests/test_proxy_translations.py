"""Переводы раздела «3proxy»: одинаковый набор ключей во всех локалях."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ('ru', 'en', 'fr', 'zh', 'fa')


def translation(locale):
    return json.loads((ROOT / 'translations' / f'{locale}.json').read_text(encoding='utf-8'))


class ProxyTranslationsTests(unittest.TestCase):
    def test_proxy_keys_are_equal_and_not_empty_in_every_locale(self):
        catalogues = {locale: translation(locale) for locale in LOCALES}
        proxy_sets = {
            locale: {key for key in data if key.startswith('proxy_')}
            for locale, data in catalogues.items()
        }
        baseline = proxy_sets[LOCALES[0]]
        self.assertTrue(baseline, 'proxy translations missing')
        for locale in LOCALES[1:]:
            self.assertEqual(proxy_sets[locale], baseline, locale)
        for locale, data in catalogues.items():
            for key in sorted(baseline):
                self.assertTrue(str(data[key]).strip(), f'{key} пуст в {locale}')

    def test_protocol_description_names_3proxy(self):
        for locale in LOCALES:
            self.assertIn('3proxy', translation(locale)['socks5_desc'], locale)


if __name__ == '__main__':
    unittest.main()
