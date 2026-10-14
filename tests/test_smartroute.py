"""Smart Route: pure helpers, script builders and the SSH-bound manager.

FakeSSH mirrors the pattern of tests/test_status_batch.py: record commands,
serve canned answers.
"""

import unittest

from managers.smartroute_manager import (
    CONTAINER_APPLY_SCRIPT, CONTAINER_DISABLE_SCRIPT, CONTAINER_ENABLE_SCRIPT,
    SMARTR_ACCT_CHAIN, SMARTR_INSTANCES, SMARTR_MIN_PREFIXES, SMARTR_TABLE,
    SmartRouteManager, SmartRouteError, build_install_script,
    build_remove_script, build_update_script, normalize_cidrs,
    parse_acct_counters, parse_ripe_delegated, render_container_script,
)


class FakeSSH:
    def __init__(self):
        self.commands = []
        self.uploads = []

    def upload_file(self, content, path):
        self.uploads.append((path, content))

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if 'iptables -t mangle -L' in cmd:
            return ('Chain SMARTR_ACCT (1 references)\n'
                    '    10     1000 RETURN  all -- * exit0 10.8.0.0/24  0.0.0.0/0\n'
                    '     5      500 RETURN  all -- * eth0 10.8.0.0/24  0.0.0.0/0\n'
                    '---\n37\n'), '', 0
        return '', '', 0

    def run_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if 'test -f' in cmd and 'smartroute-update.sh' in cmd:
            return 'yes', '', 0
        if 'cat /etc/smartroute/status.json' in cmd:
            return ('{"prefixes_v4": 8000, "prefixes_v6": 300, "source_v4": "ipdeny", '
                    '"updated_at": "2026-10-14T10:00:00", "error": null}'), '', 0
        if 'systemctl list-timers' in cmd:
            return 'Fri 2026-10-14 11:00:00 UTC  1h left', '', 0
        if 'ls /etc/smartroute/instances' in cmd:
            return 'amnezia-awg2\namnezia-awg3\n', '', 0
        if 'iptables -t mangle -L' in cmd:
            return ('Chain SMARTR_ACCT (1 references)\n'
                    '    10     1000 RETURN  all -- * exit0 10.8.0.0/24  0.0.0.0/0\n'
                    '     5      500 RETURN  all -- * eth0  10.8.0.0/24  0.0.0.0/0\n'
                    '---\n37\n'), '', 0
        return '', '', 0


RIPE_SAMPLE = """\
2.0.0.0|ripencc|1288099200|1289760000|assigned|3eed4a31-b2f3-4de6-be32-4c0f67bca2c4
#
ripencc|FR|ipv4|2.0.0.0|1048576|20100712|assigned|
ripencc|RU|ipv4|83.172.0.0|131072|20130912|allocated|
ripencc|RU|ipv4|85.140.0.0|65536|20130912|available|
ripencc|RU|ipv6|2001:1b00::|32|20030912|allocated|
ripencc|RU|asn|12345|1|20030912|allocated|
ripencc|RU|ipv4|91.200.0.0|2048|20130912|assigned|
"""


class RipeParsingTests(unittest.TestCase):
    def test_ipv4_start_count_folded_to_cidrs(self):
        nets = parse_ripe_delegated(RIPE_SAMPLE, family='ipv4')
        self.assertIn('83.172.0.0/15', nets)          # 131072 = 2^17 = /15
        self.assertIn('91.200.0.0/21', nets)          # 2048 = /21
        self.assertNotIn('85.140.0.0/16', nets)       # status "available" skipped
        self.assertNotIn('2.0.0.0/12', nets)          # France skipped
        self.assertTrue(all('/' in n for n in nets))

    def test_ipv6_prefix_length_direct(self):
        nets = parse_ripe_delegated(RIPE_SAMPLE, family='ipv6')
        self.assertEqual(nets, ['2001:1b00::/32'])

    def test_country_filter(self):
        self.assertEqual(parse_ripe_delegated(RIPE_SAMPLE, country='FR'),
                         ['2.0.0.0/12'])
        self.assertEqual(parse_ripe_delegated('', family='ipv4'), [])


class NormalizeCidrsTests(unittest.TestCase):
    def test_dedupe_sort_and_comments(self):
        out = normalize_cidrs(['10.0.0.1/8', '# note', '', '9.0.0.0/8', '10.0.0.0/8'])
        self.assertEqual(out, ['9.0.0.0/8', '10.0.0.0/8'])

    def test_wrong_family_rejected(self):
        with self.assertRaises(ValueError):
            normalize_cidrs(['2001:db8::/32'], family='ipv4')

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            normalize_cidrs(['not-a-cidr'])


class AcctParsingTests(unittest.TestCase):
    def test_rows_mapped_by_out_iface(self):
        text = ('Chain SMARTR_ACCT (1 references)\n'
                '    10     1000 RETURN  all -- * exit0 10.8.0.0/24  0.0.0.0/0\n'
                '     5      500 RETURN  all -- * eth0 10.8.0.0/24  0.0.0.0/0\n')
        out = parse_acct_counters(text)
        self.assertEqual(out['via_exit_bytes'], 1000)
        self.assertEqual(out['direct_bytes'], 500)
        self.assertEqual(out['via_exit_pkts'], 10)

    def test_missing_chain_is_zero(self):
        out = parse_acct_counters('')
        self.assertEqual(out['via_exit_bytes'], 0)
        self.assertEqual(out['direct_bytes'], 0)


class UpdateScriptTests(unittest.TestCase):
    def setUp(self):
        self.script = build_update_script()

    def test_guard_and_sources(self):
        self.assertIn(f'MIN_PREFIXES={SMARTR_MIN_PREFIXES}', self.script)
        self.assertIn('ipdeny.com', self.script)
        self.assertIn('herrbischoff', self.script)
        self.assertIn('delegated-ripencc-latest', self.script)

    def test_guard_applies_to_file_not_zeroing(self):
        # a failed fetch must keep the old file: no truncate/write on failure
        self.assertIn('old list kept', self.script)
        self.assertNotIn('> "$V4_FILE"', self.script)

    def test_own_subnets_merged(self):
        self.assertIn('OWN_FILE', self.script)
        self.assertIn('cat "$V4_FILE" 2>/dev/null > "$merged"', self.script)

    def test_lock_and_status(self):
        self.assertIn('flock -n 9', self.script)
        self.assertIn('status.json', self.script)

    def test_container_apply_only_touches_throws(self):
        # never a blanket table flush: default/blackhole must survive
        self.assertIn('route del throw', self.script)
        self.assertNotIn('route flush table', self.script)
        self.assertIn('docker cp', self.script)
        self.assertIn('smartr_v4.cidr', self.script)


class InstallRemoveScriptTests(unittest.TestCase):
    def test_install_writes_everything_and_enables_timer(self):
        script = build_install_script()
        for needle in ('/usr/local/sbin/smartroute-update.sh',
                       'smartroute.service', 'smartroute.timer',
                       'systemctl enable --now smartroute.timer',
                       'RandomizedDelaySec=900', 'Persistent=true'):
            self.assertIn(needle, script)
        self.assertIn('smartroute-update.sh', script)  # first run at install

    def test_remove_cleans_all(self):
        script = build_remove_script()
        for needle in ('disable --now smartroute.timer smartroute.service',
                       'rm -rf /etc/smartroute',
                       'route del throw',
                       'iptables -t mangle -D POSTROUTING',
                       'systemctl daemon-reload'):
            self.assertIn(needle, script)
        # no blanket table flush anywhere
        self.assertNotIn('route flush table', script)
        # never touches blocker chains/ipset
        self.assertNotIn('AMNEZIA_BLOCK', script)
        self.assertNotIn('ipset', script)

    def test_container_scripts_never_touch_forward_output(self):
        for tpl in (CONTAINER_APPLY_SCRIPT, CONTAINER_ENABLE_SCRIPT,
                    CONTAINER_DISABLE_SCRIPT):
            for bad in ('FORWARD', 'OUTPUT', 'ipset'):
                self.assertNotIn(bad, tpl)
        self.assertIn(f'table $TABLE', CONTAINER_APPLY_SCRIPT)

    def test_render_substitutes_constants(self):
        rendered = render_container_script(
            CONTAINER_ENABLE_SCRIPT, config_path='/opt/amnezia/awg/awg0.conf',
            subnet_default='10.8.0.0/24')
        self.assertNotIn('__TABLE__', rendered)
        self.assertIn(str(SMARTR_TABLE), rendered)
        self.assertIn(SMARTR_ACCT_CHAIN, rendered)
        self.assertIn('/opt/amnezia/awg/awg0.conf', rendered)


class ManagerFlowTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeSSH()
        self.mgr = SmartRouteManager(self.ssh)

    def test_install_uploads_and_runs(self):
        self.mgr.install()
        paths = [p for p, _ in self.ssh.uploads]
        self.assertIn('/tmp/_smartr.sh', paths)
        self.assertIn('bash /tmp/_smartr.sh', self.ssh.commands)
        self.assertIn('rm -f /tmp/_smartr.sh', self.ssh.commands)

    def test_install_failure_raises(self):
        class FailSSH(FakeSSH):
            def run_sudo_command(self, cmd, timeout=60):
                super().run_sudo_command(cmd, timeout)
                return 'boom', '', 1
        with self.assertRaises(SmartRouteError):
            SmartRouteManager(FailSSH()).install()

    def test_enable_marks_and_configures_container(self):
        self.mgr.enable_instance('amnezia-awg2', '/opt/amnezia/awg/awg0.conf', '10.8.0.0/24')
        cmds = ' '.join(self.ssh.commands)
        self.assertIn(f'{SMARTR_INSTANCES}/amnezia-awg2', cmds)
        self.assertIn('docker cp /tmp/_smartr_c.sh amnezia-awg2', cmds)
        self.assertIn('docker exec amnezia-awg2 bash /tmp/_smartr_c.sh', cmds)
        # accounting chain setup inside the container script
        uploaded = '\n'.join(c for _, c in self.ssh.uploads)
        self.assertIn(f'iptables -t mangle -A $CH -s "$X_SUBNET" -o exit0', uploaded)
        self.assertIn('conntrack -D -s "$X_SUBNET"', uploaded)

    def test_disable_removes_marker_and_tears_down(self):
        self.mgr.disable_instance('amnezia-awg2', '/opt/amnezia/awg/awg0.conf', '10.8.0.0/24')
        cmds = ' '.join(self.ssh.commands)
        self.assertIn(f'rm -f {SMARTR_INSTANCES}/amnezia-awg2', cmds)
        uploaded = '\n'.join(c for _, c in self.ssh.uploads)
        self.assertIn('iptables -t mangle -D POSTROUTING -j $CH', uploaded)
        self.assertIn('route del throw', uploaded)
        self.assertNotIn('route flush table', uploaded)

    def test_own_subnets_uploaded_to_host_file(self):
        self.mgr.set_own_subnets(['192.168.0.0/16'])
        _, content = self.ssh.uploads[-1]
        self.assertIn('192.168.0.0/16', content)

    def test_host_status(self):
        status = self.mgr.host_status()
        self.assertTrue(status['installed'])
        self.assertEqual(status['status']['prefixes_v4'], 8000)
        self.assertEqual(status['instances'], ['amnezia-awg2', 'amnezia-awg3'])

    def test_counters_read(self):
        out = self.mgr.instance_counters('amnezia-awg2', '/opt/amnezia/awg/awg0.conf', '10.8.0.0/24')
        self.assertEqual(out['via_exit_bytes'], 1000)
        self.assertEqual(out['direct_bytes'], 500)
        self.assertEqual(out['throw_routes'], 37)


if __name__ == '__main__':
    unittest.main()
