"""RKN Block must verify the live contour, not just the installer exit code."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'scripts' / 'rknblock' / 'rkn-extra-block.sh').read_text(encoding='utf-8')
INSTALL = (ROOT / 'scripts' / 'rknblock' / 'install-rkn-extra.sh').read_text(encoding='utf-8')
UNIT = (ROOT / 'scripts' / 'rknblock' / 'rkn-extra-block.service').read_text(encoding='utf-8')
SERVER_PAGE = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')


class ScriptVerificationTests(unittest.TestCase):
    def test_verify_command_checks_lists_and_jumps(self):
        self.assertIn('cmd_verify()', SCRIPT)
        for token in ('$IN_SET4', '$OUT_SET4', 'INPUT', 'OUTPUT', 'FORWARD',
                      'is empty', 'missing iptables'):
            self.assertIn(token, SCRIPT)

    def test_on_and_update_fail_instead_of_silently_succeeding(self):
        self.assertIn('if ! cmd_verify; then', SCRIPT)
        self.assertIn('UPDATE-FAIL', SCRIPT)
        self.assertIn('cannot enable: verification failed', SCRIPT)
        self.assertIn('cmd_update || exit $?', SCRIPT)
        self.assertIn('verify)', SCRIPT)

    def test_installer_propagates_on_failure(self):
        self.assertIn('if ! /usr/local/sbin/rkn-extra-block on; then', INSTALL)
        self.assertIn('exit 1', INSTALL)

    def test_boot_unit_can_be_enabled(self):
        # Without [Install] the service is not started after reboot, and the
        # ipset/iptables state (not persistent by itself) stays empty while
        # the state file still says "on".
        self.assertIn('[Install]', UNIT)
        self.assertIn('WantedBy=multi-user.target', UNIT)

    def test_status_exposes_machine_readable_health(self):
        self.assertIn('health: ok', SCRIPT)
        self.assertIn('health: failed', SCRIPT)
        self.assertIn("re.search(r'health:", (ROOT / 'app.py').read_text(encoding='utf-8'))


class UiHealthTests(unittest.TestCase):
    def test_card_uses_live_running_and_healthy(self):
        self.assertIn('const liveOn = d.running !== undefined', SERVER_PAGE)
        self.assertIn('d.healthy !== false', SERVER_PAGE)
        self.assertIn('rkn_block_not_ready', SERVER_PAGE)
        self.assertIn('rkn_block_sets_empty', SERVER_PAGE)

    def test_all_locales_have_not_ready_key(self):
        import json
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads((ROOT / 'translations' / f'{lang}.json').read_text(encoding='utf-8'))
            self.assertIn('rkn_block_not_ready', data, lang)


if __name__ == '__main__':
    unittest.main()
