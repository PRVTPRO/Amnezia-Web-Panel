import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class PublicEndpointPortCheckTests(unittest.TestCase):
    """The public-endpoint modal gates Save behind a port check: the checker
    button and result element must exist, the JS must call the port-check API
    and disable Save until a verdict, and every public_endpoint_* key must
    exist in all locales."""

    def setUp(self):
        self.page = read('templates', 'server.html')

    def test_checker_controls_present(self):
        for el in ('publicEndpointCheckBtn', 'publicEndpointPortResult'):
            self.assertIn(f'id="{el}"', self.page)
        self.assertIn("onclick=\"checkPublicEndpointPort()\"", self.page)
        self.assertIn("/protocol/port-check?port=", self.page)

    def test_save_is_gated_by_the_check(self):
        self.assertIn('publicEndpointPortVerified', self.page)
        self.assertIn("btn.disabled = !!port && port !== publicEndpointSavedPort && !publicEndpointPortVerified",
                      self.page)
        self.assertIn("e.target.id === 'publicEndpointPort'", self.page)

    def test_translations_in_all_languages(self):
        keys = {'public_endpoint_check', 'public_endpoint_checking',
                'public_endpoint_port_free', 'public_endpoint_port_docker',
                'public_endpoint_port_busy', 'public_endpoint_port_invalid'}
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads(read('translations', f'{lang}.json'))
            missing = sorted(k for k in keys if k not in data)
            self.assertEqual(missing, [], f'{lang}: {missing}')


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


class HostAppsUiWiringTests(unittest.TestCase):
    """Smart Route and RKN Block are host-level marketplace apps: their cards
    bypass the protocol installer, and every smartroute_*/rknblock_* key must
    exist in all locales."""

    def setUp(self):
        self.page = read('templates', 'server.html')

    def test_only_confirmed_key_sharing_warning_is_rendered(self):
        self.assertIn('simAlerts', self.page)
        self.assertNotIn('multiIpAlerts', self.page)
        self.assertNotIn('multi_ip_alert_text', self.page)

    def test_marketplace_card_and_modal(self):
        self.assertRegex(self.page, r"\{ proto: 'smartroute', category: 'services'")
        self.assertIn('id="smartRouteModal"', self.page)
        self.assertIn("onclick=\"openSmartRouteModal()\"", self.page)
        # the card button must not fall through to the protocol installer
        self.assertNotIn("installFromMarketplace('smartroute'", self.page)
        # host-level apps install directly, never through the AWG installer
        self.assertNotIn("installFromMarketplace('rknblock'", self.page)
        self.assertIn("installRknBlock()", self.page)

    def test_exit_link_modal_wires_the_split_toggle(self):
        self.assertIn('id="smartRouteToggle"', self.page)
        self.assertIn('id="smartRouteCounters"', self.page)
        self.assertIn('smartroute/split', self.page)
        self.assertIn('smartroute/status', self.page)
        self.assertIn('smart_route_lost', self.page)

    def test_translations_carry_smartroute_keys_in_all_languages(self):
        keys = set(re.findall(r"_\('(smartroute_[a-z0-9_]+)'\)", self.page))
        keys |= set(re.findall(r"\{\{ _\('(smartroute_[a-z0-9_]+)'\) \}\}", self.page))
        keys |= {'app_not_installed', 'protocol_not_awg', 'invalid_cidr', 'invalid_dns',
                 'smartroute_paused', 'server_not_found'}
        self.assertGreater(len(keys), 25)
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads(read('translations', f'{lang}.json'))
            missing = sorted(k for k in keys if k not in data)
            self.assertEqual(missing, [], f'{lang}: {missing}')

    def test_server_page_card_with_global_toggle(self):
        self.assertIn('id="proto-smartroute"', self.page)
        self.assertIn('smartroute/enable', self.page)
        self.assertIn('function toggleSmartRoute(', self.page)
        self.assertIn('function renderSmartRouteCard(', self.page)
        self.assertIn('smartroute-toggle-btn', self.page)
        # the card must not be shown via the container-status path
        self.assertIn("if (app.proto === 'smartroute' || app.proto === 'rknblock') return;",
                      self.page)

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

    def test_rknblock_options_ui(self):
        # options button + modal + API wiring
        self.assertIn('rknblock-options-btn', self.page)
        self.assertIn('id="rknOptionsModal"', self.page)
        self.assertIn('function openRknOptionsModal(', self.page)
        self.assertIn('function saveRknOptions(', self.page)
        self.assertIn('/rknblock/options', self.page)
        for flag in ('BlockIn', 'BlockOut', 'LogIn', 'LogOut'):
            self.assertIn(f'id="rknOpt{flag}"', self.page)
        # rainbow icon on the card and in the marketplace list
        self.assertIn('<div class="protocol-icon">🌈</div>', self.page)
        self.assertIn("icon: '🌈'", self.page)

    def test_rknblock_translations_in_all_languages(self):
        keys = set(re.findall(r"_\('(rknblock_[a-z0-9_]+)'\)", self.page))
        keys |= set(re.findall(r"\{\{ _\('(rknblock_[a-z0-9_]+)'\) \}\}", self.page))
        self.assertGreaterEqual(len(keys), 10)
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads(read('translations', f'{lang}.json'))
            missing = sorted(k for k in keys if k not in data)
            self.assertEqual(missing, [], f'{lang}: {missing}')

    def test_card_not_shown_via_container_status(self):
        self.assertIn("if (app.proto === 'smartroute' || app.proto === 'rknblock') return;",
                      self.page)

    def test_card_dns_pair_inputs(self):
        self.assertIn('id="smartroute-direct-dns"', self.page)
        self.assertIn('id="smartroute-exit-dns"', self.page)
        self.assertIn('smartroute/dns-servers', self.page)
        self.assertIn('function saveSmartRouteDnsServers(', self.page)

    def test_exit_modal_respects_global_pause(self):
        self.assertIn('smartroute_paused_hint', self.page)
        self.assertIn('srGloballyOn', self.page)


class SmartRouteReadmeI18nTests(unittest.TestCase):
    """The Smart Route README (ack modal) must be fully translated in every
    panel language and must carry the security warnings raised in PR review."""

    DOC_KEYS = [
        'smartroute_doc_how_title', 'smartroute_doc_how',
        'smartroute_doc_why_title', 'smartroute_doc_why',
        'smartroute_doc_risk_title',
        'smartroute_doc_risk_1', 'smartroute_doc_risk_2',
        'smartroute_doc_risk_3', 'smartroute_doc_risk_4',
        'smartroute_doc_risk_5', 'smartroute_doc_risk_6',
        'smartroute_doc_security_title', 'smartroute_doc_security_intro',
        'smartroute_doc_security_1', 'smartroute_doc_security_2',
        'smartroute_doc_security_3', 'smartroute_doc_security_4',
        'smartroute_doc_fit_title', 'smartroute_doc_fit_ok',
        'smartroute_doc_fit_no',
        'smartroute_doc_fail_title', 'smartroute_doc_fail',
    ]

    def setUp(self):
        self.page = read('templates', 'server.html')
        start = self.page.index('id="smartRouteAckModal"')
        end = self.page.index('id="smartRouteModal"')
        self.modal = self.page[start:end]
        self.locales = {
            lang: json.loads(read('translations', f'{lang}.json'))
            for lang in ('ru', 'en', 'fr', 'zh', 'fa')
        }

    def test_modal_has_no_hardcoded_russian_text(self):
        for key in self.DOC_KEYS:
            self.assertIn("{{ _('%s') }}" % key, self.modal)
        for fragment in ('Как это работает', 'Российские сайты', 'Компромиссы',
                         'выходную ноду', 'Безопасность:'):
            self.assertNotIn(fragment, self.modal)

    def test_every_locale_has_the_doc(self):
        for lang, data in self.locales.items():
            missing = [k for k in self.DOC_KEYS if not data.get(k)]
            self.assertEqual(missing, [], f'{lang}: {missing}')

    def test_readme_label_is_localized(self):
        labels = {lang: data.get('smartroute_ack_readme')
                  for lang, data in self.locales.items()}
        self.assertEqual(len(set(labels.values())), 5, labels)

    def test_ack_controls_are_localized(self):
        en = self.locales['en']
        for lang in ('ru', 'fr', 'zh', 'fa'):
            data = self.locales[lang]
            for key in ('smartroute_ack_title', 'smartroute_ack_accept',
                        'smartroute_ack_close'):
                self.assertNotEqual(data[key], en[key], f'{lang}: {key}')

    def test_security_warnings_are_present(self):
        en = self.locales['en']
        self.assertIn('pure relay', en['smartroute_doc_security_1'])
        self.assertIn('split tunneling', en['smartroute_doc_security_2'])
        self.assertIn('VPN marker', en['smartroute_doc_risk_2'])
        self.assertIn('SORM', en['smartroute_doc_risk_5'])
        self.assertIn('standalone egress', en['smartroute_doc_risk_6'])
        ru = self.locales['ru']
        self.assertIn('СОРМ', ru['smartroute_doc_risk_5'])
        self.assertIn('split-tunneling', ru['smartroute_doc_security_2'])


if __name__ == '__main__':
    unittest.main()
