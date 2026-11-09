"""Checks for the server IPv6 i18n contract.

Read only: design/server-ipv6-i18n.json, translations/*.json,
templates/server.html, static/css/style.css.
"""

import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KEYS_FILE = os.path.join(ROOT, "design", "server-ipv6-i18n.json")
TEMPLATE_FILE = os.path.join(ROOT, "templates", "server.html")
CSS_FILE = os.path.join(ROOT, "static", "css", "style.css")

LOCALES = ("ru", "en", "fr", "zh", "fa")
NON_RU = ("en", "fr", "zh", "fa")

PLACEHOLDER_RE = re.compile(r"\{[A-Za-z0-9_]+\}")
KEY_USE_RE = re.compile(r"_\(\s*['\"](server_ipv6_[A-Za-z0-9_]+)['\"]\s*\)")
# Map literals such as IP_STATE_KEYS are never passed to _() at the call
# site, so they need their own scan.
KEY_LITERAL_RE = re.compile(r"(server_ipv6_[A-Za-z0-9_]+)")

CSS_TOKENS = ("--warning-border", "--info-border")
CSS_SELECTORS = (".ip-chip", ".seg-group", ".ip-note", ".ip-modal-table")


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_json(path):
    return json.loads(read_text(path))


def translation(locale):
    return load_json(os.path.join(ROOT, "translations", locale + ".json"))


def design():
    return load_json(KEYS_FILE)


def placeholders(value):
    return sorted(set(PLACEHOLDER_RE.findall(value)))


class TestDesignFile(unittest.TestCase):
    def test_design_file_has_all_locales_for_every_key(self):
        data = design()
        assert isinstance(data, dict)
        assert data, "design file is empty"
        for key, value in data.items():
            assert isinstance(value, dict), key
            for locale in LOCALES:
                assert locale in value, "%s missing locale %s" % (key, locale)


class TestKeySetPresent(unittest.TestCase):
    def test_key_set_present_in_every_locale(self):
        expected = design()
        for locale in LOCALES:
            data = translation(locale)
            for key in expected:
                assert key in data, "%s missing in %s" % (key, locale)
                value = data[key]
                assert isinstance(value, str), "%s not a string in %s" % (key, locale)
                assert value.strip(), "%s empty in %s" % (key, locale)


class TestPlaceholders(unittest.TestCase):
    def test_placeholders_match_across_locales(self):
        expected = design()
        for key in expected:
            base = placeholders(expected[key]["ru"])
            for locale in NON_RU:
                found = placeholders(expected[key][locale])
                assert found == base, "%s placeholders differ in %s: %s != %s" % (
                    key,
                    locale,
                    found,
                    base,
                )

    def test_translation_files_match_design_placeholders(self):
        for locale in LOCALES:
            data = translation(locale)
            for key, value in design().items():
                base = placeholders(value["ru"])
                found = placeholders(data[key])
                assert found == base, "%s placeholders differ in %s: %s != %s" % (
                    key,
                    locale,
                    found,
                    base,
                )


class TestNoCyrillicLeakage(unittest.TestCase):
    def test_no_cyrillic_leakage_in_non_russian_locales(self):
        for locale in NON_RU:
            data = translation(locale)
            for key in design():
                value = data[key]
                bad = [c for c in value if "\u0400" <= c <= "\u04ff"]
                assert not bad, "%s has Cyrillic in %s: %r" % (key, locale, bad)


def template_keys():
    template = read_text(TEMPLATE_FILE)
    keys = set(KEY_USE_RE.findall(template))
    keys.update(KEY_LITERAL_RE.findall(template))
    keys.update(re.findall(r"_\(\s*['\"](exit_link_ipv6)['\"]\s*\)", template))
    return keys


class TestTemplateKeys(unittest.TestCase):
    def test_template_uses_server_ipv6_keys(self):
        uses = KEY_LITERAL_RE.findall(read_text(TEMPLATE_FILE))
        assert uses, "template has no server_ipv6_* keys"

    def test_every_server_ipv6_key_used_by_template_exists_in_ru(self):
        ru = translation("ru")
        for key in template_keys():
            assert key in ru, "template uses unknown key %s" % key
            assert isinstance(ru[key], str), "ru value for %s is not a string" % key
            assert ru[key].strip(), "ru value for %s is empty" % key


class TestTemplateKeysAllLocales(unittest.TestCase):
    """Keys added after the design file shipped are checked here too."""

    def template_keys(self):
        return template_keys()

    def test_every_template_key_exists_in_all_locales(self):
        keys = self.template_keys()
        assert keys
        for locale in LOCALES:
            data = translation(locale)
            for key in keys:
                assert key in data, "%s missing in %s" % (key, locale)
                assert str(data[key]).strip(), "%s empty in %s" % (key, locale)
                assert data[key] != key, "%s is not translated in %s" % (key, locale)

    def test_template_keys_have_no_cyrillic_outside_russian(self):
        keys = self.template_keys()
        for locale in NON_RU:
            data = translation(locale)
            for key in keys:
                bad = [c for c in data[key] if "\u0400" <= c <= "\u04ff"]
                assert not bad, "%s has Cyrillic in %s: %r" % (key, locale, bad)

    def test_template_keys_keep_placeholders_in_sync(self):
        keys = self.template_keys()
        ru = translation("ru")
        for locale in NON_RU:
            data = translation(locale)
            for key in keys:
                assert placeholders(data[key]) == placeholders(ru[key]), \
                    "%s placeholders differ in %s" % (key, locale)


class TestCssTokens(unittest.TestCase):
    def test_css_defines_new_tokens_in_both_themes(self):
        css = read_text(CSS_FILE)
        for token in CSS_TOKENS:
            count = css.count(token)
            assert count >= 2, "%s found %d times, expected at least 2" % (token, count)

    def test_css_defines_new_components(self):
        css = read_text(CSS_FILE)
        for selector in CSS_SELECTORS:
            assert selector in css, "%s not found in stylesheet" % selector


if __name__ == "__main__":
    unittest.main()
