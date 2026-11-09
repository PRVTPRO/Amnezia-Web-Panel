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

    def test_installer_reports_broken_dpkg_instead_of_apport_noise(self):
        # A half-configured package must fail with an actionable hint, and the
        # real apt error must not be swallowed.
        self.assertIn('export DEBIAN_FRONTEND=noninteractive', INSTALL)
        self.assertIn('dpkg --audit', INSTALL)
        self.assertIn("dpkg --configure -a", INSTALL)
        self.assertIn('util-linux >"$APT_LOG"', INSTALL)
        self.assertIn('tail -n 30 "$APT_LOG"', INSTALL)

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

    def test_install_progress_reports_real_stages(self):
        # The install is phased now: every stage is a real boundary reported by
        # the installer, not a fabricated client-side timer. Assert the engine
        # maps and the polling endpoints exist, and the labels ship everywhere.
        import json
        import app
        for name in ('PROTOCOL_INSTALL_STAGES', 'SMARTROUTE_INSTALL_STAGES',
                     'RKNBLOCK_INSTALL_STAGES'):
            stages = getattr(app, name)
            steps = list(stages.values())
            self.assertEqual(steps, sorted(steps), name)
            self.assertEqual(len(steps), len(set(steps)), name)
            self.assertIn('start', stages, name)
            self.assertIn('done', stages, name)
        self.assertEqual(set(app.FLOW_STAGES),
                         {'protocol', 'smartroute', 'rknblock'})
        source = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn('/api/servers/{server_id}/smartroute/install/{op_id}', source)
        self.assertIn('/api/servers/{server_id}/rknblock/install/{op_id}', source)
        self.assertIn('install_ops.json', source)
        self.assertIn('rknblock_install_wait', SERVER_PAGE)
        stage_keys = [f'smartroute_stage_{name}' for name in
                      ('prepare', 'script', 'units', 'activate', 'download', 'verify')]
        stage_keys += [f'rknblock_stage_{name}' for name in
                       ('preflight', 'packages', 'download', 'files',
                        'services', 'blocking', 'verify')]
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads((ROOT / 'translations' / f'{lang}.json').read_text(encoding='utf-8'))
            self.assertIn('rknblock_install_wait', data, lang)
            for key in stage_keys:
                self.assertIn(key, data, (lang, key))

    def test_all_locales_have_not_ready_key(self):
        import json
        for lang in ('en', 'ru', 'fr', 'fa', 'zh'):
            data = json.loads((ROOT / 'translations' / f'{lang}.json').read_text(encoding='utf-8'))
            self.assertIn('rkn_block_not_ready', data, lang)


if __name__ == '__main__':
    unittest.main()
