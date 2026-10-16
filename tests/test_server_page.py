import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class ExitNodeUiWiringTests(unittest.TestCase):
    """Text-level checks of the wiring that makes the exit-node UI appear at
    all (a card that is not in MARKETPLACE_APPS is never shown, an install
    branch that is missing falls through to the AWG form)."""

    def setUp(self):
        self.page = read('templates', 'server.html')

    def test_marketplace_and_static_card(self):
        self.assertRegex(self.page, r"\{ proto: 'exit', category: 'services'")
        self.assertIn('id="proto-exit"', self.page)
        for el in ('exit-ctrl', 'exit-status', 'exit-info-grid', 'exit-actions', 'exit-install-btn'):
            self.assertIn(f'id="{el}"', self.page)

    def test_protocol_sets(self):
        self.assertRegex(self.page, r"const SERVICE_PROTOS = \[.*'exit'.*\];")
        self.assertRegex(self.page, r"const UDP_INSTALL_PROTOS = new Set\(\[.*'exit'.*\]\);")
        self.assertIn("case 'exit': title = 'Exit Node'; break;", self.page)
        # never a client protocol
        self.assertNotRegex(self.page, r"const isVPN = \[[^\]]*'exit'")

    def test_install_modal_has_an_exit_branch_and_options(self):
        self.assertIn('id="exitOptions"', self.page)
        self.assertIn('id="installExitSubnet"', self.page)
        self.assertIn('id="installExitObfuscation"', self.page)
        self.assertIn("} else if (base === 'exit') {", self.page)
        self.assertIn("params.exit_subnet = ", self.page)
        self.assertIn("params.exit_obfuscation = ", self.page)
        # the exit branch must come before the trailing AWG form fallback
        self.assertLess(self.page.index("} else if (base === 'exit') {"),
                        self.page.index("awgOpts.style.display = 'block';"))

    def test_link_controls_only_on_awg_cards(self):
        idx = self.page.index("const exitBtn = AWG_PROTOCOLS.includes(protoBase(proto))")
        self.assertIn("openExitLinkModal('${proto}')", self.page[idx:idx + 400])
        for fn in ('openExitLinkModal', 'saveExitLink', 'removeExitLink', 'repairExitLink', 'showExitPeers',
                   'removeExitPeer', 'exitStatusBadge'):
            self.assertRegex(self.page, rf"function {fn}\(")
        self.assertIn('id="exitLinkModal"', self.page)
        self.assertIn('id="exitPeersModal"', self.page)
        self.assertIn("if (err.message !== 'exit_in_use') throw err;", self.page)
        # server-provided strings never reach innerHTML unescaped
        peers_table = self.page[self.page.index('function showExitPeers'):self.page.index('function removeExitPeer')]
        self.assertNotRegex(peers_table, r'\$\{p\.[a-z_]+( \|\| [^}]*)?\}')
        self.assertIn("document.body.dataset.serverUid = {{ (server.uid or '') | tojson }};", self.page)
        self.assertIn("{ protocol: proto, force: true }", self.page)

    def test_egress_check_is_wired_to_a_linked_instance_only(self):
        self.assertIn('id="exitEgressBtn"', self.page)
        self.assertIn('id="exitLinkEgress"', self.page)
        self.assertRegex(self.page, r"function checkExitEgress\(")
        self.assertIn("exit-link/check-egress", self.page)
        # the button appears only when the instance actually has a link
        self.assertIn("document.getElementById('exitEgressBtn').classList.toggle('hidden', !link);", self.page)
        # the probed address comes from the server, so it is escaped
        body = self.page[self.page.index('function checkExitEgress'):self.page.index('async function repairExitLink')]
        self.assertNotRegex(body, r'\$\{r\.[a-z_]+( \|\| [^}]*)?\}')
    def test_dns_via_exit_toggle_and_mtu_hint(self):
        self.assertIn('id="exitDnsGroup"', self.page)
        self.assertIn('id="exitDnsViaExit"', self.page)
        self.assertRegex(self.page, r"function saveExitDns\(")
        self.assertIn("exit-link/dns", self.page)
        # the toggle belongs to a linked instance only
        self.assertIn("document.getElementById('exitDnsGroup').classList.toggle('hidden', !link);", self.page)
        # AWG settings warn about the link ceiling
        self.assertIn('id="awgSetMtuExitHint"', self.page)
        self.assertIn("_('awg_mtu_exit_hint').replace('{exit_mtu}', data.exit_mtu)", self.page)

    def test_restore_reports_the_exit_link_outcome(self):
        body = self.page[self.page.index('backups/restore'):][:1600]
        for key in ('exit_entries_relinked', 'exit_link_restored'):
            self.assertIn(key, body, f'restore handler ignores {key}')
        for state in ('relinked', 'stale', 'removed', 'orphan'):
            self.assertIn(f"_('exit_restore_{state}')", body)

    def test_translations_carry_every_ui_key_in_all_languages(self):
        keys = set(re.findall(r"_\('(exit_[a-z0-9_]+)'\)", self.page))
        keys |= set(re.findall(r"\{\{ _\('(exit_[a-z0-9_]+)'\) \}\}", self.page))
        keys |= {'exit_dns_disabled_no_dns'}   # rendered through _(w) from the API warnings
        self.assertGreater(len(keys), 20)
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads(read('translations', f'{lang}.json'))
            missing = sorted(k for k in keys if k not in data)
            self.assertEqual(missing, [], f'{lang}: {missing}')


class RknBlockUiWiringTests(unittest.TestCase):
    """RKN Block is a host-level marketplace app: its card must bypass the
    protocol installer and every rknblock_* key must exist in all locales."""

    def setUp(self):
        self.page = read('templates', 'server.html')

    def test_marketplace_card_and_modal(self):
        self.assertRegex(self.page, r"\{ proto: 'rknblock', category: 'services'")
        # host-level app installs directly, never through the AWG installer
        self.assertNotIn("installFromMarketplace('rknblock'", self.page)
        self.assertIn("installRknBlock()", self.page)

    def test_rknblock_card_as_marketplace_app(self):
        self.assertIn('id="proto-rknblock"', self.page)
        self.assertIn('rknblock/install', self.page)
        self.assertIn('rknblock/uninstall', self.page)
        self.assertIn('rknblock/enable', self.page)
        # renderRknBlockCard must use the global escapeHtml, not the local
        # esc helpers defined inside other functions (ReferenceError at runtime)
        self.assertNotIn('esc(d.', self.page)
        self.assertIn('escapeHtml(d.agent_state)', self.page)
        self.assertIn('function renderRknBlockCard(', self.page)
        self.assertIn('function installRknBlock(', self.page)
        self.assertIn('function uninstallRknBlock(', self.page)
        self.assertIn('rknblock-toggle-btn', self.page)
        # scan count must be rendered straight into the badge row
        self.assertIn('rkn_scan_alert', self.page)
        # the legacy toggle card and endpoint are gone
        self.assertNotIn('id="rknBlockCard"', self.page)
        self.assertNotIn('/rkn_block`', self.page)
        self.assertNotIn('function toggleRknBlock(', self.page)

    def test_rknblock_translations_in_all_languages(self):
        keys = set(re.findall(r"_\('(rknblock_[a-z0-9_]+)'\)", self.page))
        keys |= set(re.findall(r"\{\{ _\('(rknblock_[a-z0-9_]+)'\) \}\}", self.page))
        self.assertGreaterEqual(len(keys), 10)
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads(read('translations', f'{lang}.json'))
            missing = sorted(k for k in keys if k not in data)
            self.assertEqual(missing, [], f'{lang}: {missing}')

    def test_card_not_shown_via_container_status(self):
        self.assertIn("if (app.proto === 'rknblock') return;", self.page)



if __name__ == '__main__':
    unittest.main()
