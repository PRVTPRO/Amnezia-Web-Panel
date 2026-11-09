import os
import shutil
import subprocess
import tempfile
import time
import unittest

from managers.awg_manager import AWGManager
from managers.exit_manager import ExitManager


ENTRY_CTX = {
    'active': True,
    'dns_via_warp': False,
    'client_mtu': 1220,
    'dns_ips': ['1.1.1.1', '8.8.8.8'],
    'transit_cidr': '',
    'transit_gateway': '',
    'prefix': '/opt/amnezia/awg/warp/awg',
    'protocol': 'awg',
    'entry_uid': 'uid-entry',
}

EXIT_CTX = {
    'active': True,
    'dns_via_warp': False,
    'client_mtu': 1220,
    'dns_ips': [],
    'transit_cidr': '10.9.0.0/24',
    'transit_gateway': '10.9.0.1',
    'prefix': '/opt/amnezia/exit/warp',
    'protocol': 'exit',
    'entry_uid': 'uid-exit',
}


class FakeSSH:
    def __init__(self, config=''):
        self.config = config
        self.commands = []

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'for p in ' in command:  # _resolve_config_path probe
            return '/opt/amnezia/awg/awg0.conf\n', '', 0
        if 'cat ' in command:
            return self.config, '', 0
        return '', '', 0


class EntryStartScriptTests(unittest.TestCase):
    def test_none_ctx_is_byte_identical_to_legacy_output(self):
        self.assertEqual(
            AWGManager(None)._render_start_script('awg', warp_ctx=None),
            AWGManager(None)._render_start_script('awg'),
        )

    def test_active_ctx_emits_warp_block(self):
        script = AWGManager(None)._render_start_script('awg', warp_ctx=ENTRY_CTX)

        self.assertIn('warp0', script)
        self.assertIn('default dev $WARP_IF', script)
        self.assertIn('  x_rule -4 181 ', script)
        self.assertIn('  x_rule -4 182 ', script)
        self.assertIn('  x_rule -4 210 ', script)
        self.assertIn('from $WARP_SUBNET lookup $WARP_TABLE', script)
        self.assertIn('conntrack -D -s $WARP_SUBNET', script)
        self.assertIn('warp-link', script)
        self.assertIn('strip "$WARP_CONF"', script)
        self.assertIn('setconf $WARP_IF', script)
        self.assertIn('amneziawg-go $WARP_IF', script)
        self.assertIn('MASQUERADE', script)

    def test_dns_via_warp_has_no_dns_exception_rules(self):
        ctx = dict(ENTRY_CTX, dns_via_warp=True)
        script = AWGManager(None)._render_start_script('awg', warp_ctx=ctx)

        self.assertNotIn('  x_rule -4 182 ', script)
        self.assertNotIn('  x_rule -4 183 ', script)
        self.assertIn('  x_rule -4 210 ', script)

    @unittest.skipUnless(shutil.which('bash'), 'bash not available')
    def test_active_script_parses_as_bash(self):
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
            f.write(AWGManager(None)._render_start_script('awg', warp_ctx=ENTRY_CTX))
        try:
            result = subprocess.run(['bash', '-n', f.name], capture_output=True, text=True)
        finally:
            os.unlink(f.name)
        self.assertEqual(result.returncode, 0, result.stderr)


class ExitStartScriptTests(unittest.TestCase):
    def test_none_ctx_keeps_legacy_output(self):
        self.assertEqual(
            ExitManager(None)._render_start_script(warp_ctx=None),
            ExitManager(None)._render_start_script(),
        )

    def test_active_ctx_uses_transit_selectors(self):
        script = ExitManager(None)._render_start_script(warp_ctx=EXIT_CTX)

        self.assertIn('warp0', script)
        self.assertIn('  x_rule -4 171 ', script)
        self.assertIn('  x_rule -4 210 ', script)
        self.assertIn('from $WARP_SUBNET lookup $WARP_TABLE', script)
        self.assertIn('blackhole default metric 1000 table $WARP_TABLE', script)
        self.assertIn('conntrack -D -s $WARP_SUBNET', script)
        self.assertIn('MASQUERADE', script)


class ReadConfigKeyLiveTests(unittest.TestCase):
    def test_last_mtu_line_wins_and_ignores_cache(self):
        ssh = FakeSSH('# MTU = 1376\nMTU = 1300\n# MTU = 1205\n')
        manager = AWGManager(ssh)
        manager._server_config_cache['awg'] = (time.time(), '# MTU = 9999\n')

        def forbidden(*_args, **_kwargs):
            raise AssertionError('cached config must not be used')

        manager._get_server_config = forbidden
        manager._batch_entry = forbidden

        self.assertEqual(manager._read_config_key_live('awg', 'MTU'), 1205)
        self.assertFalse(any('for p in ' not in cmd and 'cat ' not in cmd
                             for cmd in ssh.commands))

    def test_missing_or_invalid_value_is_none(self):
        manager = AWGManager(FakeSSH('# MTU = not-a-number\nMTU = \n'))
        self.assertIsNone(manager._read_config_key_live('awg', 'MTU'))


if __name__ == '__main__':
    unittest.main()
