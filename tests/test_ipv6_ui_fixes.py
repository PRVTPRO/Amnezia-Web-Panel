"""Source-level regressions for the server IPv4/IPv6 UI fixes (C1-C7).

The checked artefacts are text only: templates/server.html,
static/css/style.css and translations/*.json. No browser and no server.
"""

import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_FILE = os.path.join(ROOT, "templates", "server.html")
CSS_FILE = os.path.join(ROOT, "static", "css", "style.css")
DESIGN_FILE = os.path.join(ROOT, "design", "server-ipv6-i18n.json")
I18N_TEST_FILE = os.path.join(ROOT, "tests", "test_ipv6_i18n.py")

LOCALES = ("ru", "en", "fr", "zh", "fa")
NON_RU = ("en", "fr", "zh", "fa")
KEY_LITERAL_RE = re.compile(r"(server_ipv6_[A-Za-z0-9_]+)")

NEW_KEYS = {
    "server_ipv6_state_env_off",
    "server_ipv6_state_env_on",
    "server_ipv6_badge_peer_lifecycle_busy",
    "server_ipv6_badge_ip6tables_unsupported",
    "server_ipv6_save_preference",
    "server_ipv6_cancel",
    "server_ipv6_discard_confirm",
    "server_ipv6_enable_docker_first",
    "server_ipv6_apply_or_revert_hint",
}

# +13 install stage keys (staged marketplace installs) on top of 1123.
# 1136 + 10 rknblock/smartroute stage keys from the store-install commit
# + 6 srv_warp_stage_* keys (WARP store install).
BASE_KEY_COUNT = 1146


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def load_json(path):
    return json.loads(read_text(path))


def region(start, end):
    template = read_text(TEMPLATE_FILE)
    first = template.index(start)
    return template[first:template.index(end, first)]


def translation(locale):
    return load_json(os.path.join(ROOT, "translations", locale + ".json"))


class TestC1ChipStates(unittest.TestCase):
    def setUp(self):
        self.chip = region("function ipHostChipStyle", "function renderIpSettings")

    def test_ipv4_uses_the_shared_state_mapping(self):
        self.assertIn("host.ipv4_state", self.chip)
        self.assertIn("absent", self.chip)
        self.assertIn("no_route", self.chip)
        self.assertIn("disabled", self.chip)
        self.assertIn("state: 'bad'", self.chip)
        self.assertIn("state: 'neutral'", self.chip)
        self.assertNotIn("ipChip('on', '✓', `IPv4", self.chip)

    def test_chip_carries_address_and_counts(self):
        self.assertIn("server_ipv6_state_in_use_desc", self.chip)
        self.assertIn("{n}", self.chip)
        self.assertIn("{m}", self.chip)
        self.assertIn("host.ipv4", self.chip)
        self.assertIn("host.ipv6", self.chip)


class TestC2PreferenceModal(unittest.TestCase):
    def setUp(self):
        self.modal = region(
            '<div class="modal-backdrop" id="ipSettingsModal">',
            '<div class="modal-backdrop" id="awgSettingsModal">',
        )
        self.script = read_text(TEMPLATE_FILE)

    def test_radios_mark_dirty_instead_of_saving(self):
        self.assertEqual(self.modal.count('onchange="markIpv6PrefDirty()"'), 3)
        self.assertNotIn('onchange="saveIpv6Preference()"', self.modal)

    def test_primary_save_and_cancel_exist(self):
        self.assertIn('id="ipPrefSave"', self.modal)
        self.assertIn('onclick="saveIpv6Preference()"', self.modal)
        self.assertIn('onclick="closeIpSettings()"', self.modal)
        self.assertIn("disabled", self.modal.split('id="ipPrefSave"', 1)[1][:120])

    def test_close_guards_dirty_state_and_restores(self):
        self.assertIn("function closeIpSettings", self.script)
        self.assertIn("server_ipv6_discard_confirm", self.script)
        self.assertIn("function restoreIpv6Preference", self.script)
        self.assertIn("if (ipv6PrefDirty", self.script)


class TestC3SingleWriter(unittest.TestCase):
    def setUp(self):
        self.row = region("function awgIpv6Changed", "async function saveInstanceIpv6")
        self.open_settings = region("async function openAwgSettings", "async function saveAwgSettings")
        self.save_settings = region("async function saveAwgSettings", "// ========== Exit node ==========")

    def test_enable_and_apply_follow_capabilities(self):
        self.assertIn("canEnable", self.row)
        self.assertIn("canWrite", self.row)
        self.assertIn("on.disabled = !!exitLinked || !enableAllowed", self.row)
        self.assertIn("applyBtn.disabled = !awgIpv6CanWrite", self.row)
        self.assertIn("blockedReason", self.row)

    def test_changed_ipv6_blocks_the_general_save(self):
        self.assertIn("awgSaveBtn", self.row)
        self.assertIn("server_ipv6_apply_or_revert_hint", self.row)
        self.assertIn("btn.disabled = awgIpv6Changed()", self.save_settings)

    def test_open_passes_can_enable_and_can_write(self):
        self.assertIn("ipInst.can_enable", self.open_settings)
        self.assertIn("ipStatusCache.can_write", self.open_settings)


class TestC4InstallGate(unittest.TestCase):
    def setUp(self):
        self.note = region("function setInstallIpv6Pending", "async function saveIpv6Preference")
        self.install = region("async function installProtocol", "function formatBackupTime")

    def test_pending_docker_blocks_install(self):
        self.assertIn("server_ipv6_after_docker_restart", self.note)
        self.assertIn("kind = 'pending'", self.note)
        self.assertIn("setInstallIpv6Pending(kind === 'pending')", self.note)
        self.assertIn("installBtn", self.note)
        self.assertIn("server_ipv6_enable_docker_first", self.note)

    def test_install_error_maps_docker_pending(self):
        self.assertIn("postErrorCode", self.install)
        self.assertIn("'docker_pending'", self.install)
        self.assertIn("server_ipv6_enable_docker_first", self.install)


class TestC5Styles(unittest.TestCase):
    def setUp(self):
        self.css = read_text(CSS_FILE)

    def test_switch_component_is_complete(self):
        self.assertIn(".switch {", self.css)
        self.assertIn(".switch .slider", self.css)
        self.assertIn(":focus-visible", self.css)
        self.assertIn(":disabled + .slider", self.css)
        self.assertIn("inset-inline-start", self.css)

    def test_rtl_and_red_states(self):
        self.assertIn("border-inline-start", self.css)
        self.assertIn("text-align: start", self.css)
        self.assertIn('data-state="bad"', self.css)

    def test_phone_table_becomes_cards(self):
        self.assertIn("@media (max-width: 640px)", self.css)
        self.assertIn(".ip-modal-table tr {", self.css)
        self.assertIn("attr(data-label)", self.css)


class TestC6Translations(unittest.TestCase):
    def test_key_sets_are_equal_and_keep_existing_keys(self):
        sets = {locale: set(translation(locale)) for locale in LOCALES}
        base = sets[LOCALES[0]]
        for locale in LOCALES[1:]:
            self.assertEqual(sets[locale], base, locale)
        self.assertEqual(len(base), BASE_KEY_COUNT + len(NEW_KEYS))

    def test_new_keys_present_in_every_locale(self):
        for locale in LOCALES:
            data = translation(locale)
            for key in NEW_KEYS:
                self.assertIn(key, data)
                self.assertTrue(str(data[key]).strip(), "%s empty in %s" % (key, locale))

    def test_new_keys_have_no_cyrillic_outside_russian(self):
        for locale in NON_RU:
            data = translation(locale)
            for key in NEW_KEYS:
                bad = [c for c in data[key] if "\u0400" <= c <= "\u04ff"]
                self.assertFalse(bad, "%s has Cyrillic in %s" % (key, locale))


class TestC7DesignParity(unittest.TestCase):
    def test_design_file_lists_every_template_key(self):
        design = load_json(DESIGN_FILE)
        used = set(KEY_LITERAL_RE.findall(read_text(TEMPLATE_FILE)))
        self.assertEqual(set(design), used)
        self.assertIn("server_ipv6_state_in_use_desc", design)

    def test_design_file_has_every_locale(self):
        for key, value in load_json(DESIGN_FILE).items():
            for locale in LOCALES:
                self.assertIn(locale, value, "%s missing %s" % (key, locale))

    def test_i18n_test_scans_map_literals(self):
        source = read_text(I18N_TEST_FILE)
        self.assertIn("KEY_LITERAL_RE", source)
        self.assertIn("KEY_LITERAL_RE.findall(template)", source)


if __name__ == "__main__":
    unittest.main()
