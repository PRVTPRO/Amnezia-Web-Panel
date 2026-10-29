"""Smart Route: pure helpers, script builders and the SSH-bound manager.

FakeSSH mirrors the pattern of tests/test_status_batch.py: record commands,
serve canned answers.
"""

import unittest

from managers.smartroute_manager import (
    CONTAINER_APPLY_FINAL, CONTAINER_APPLY_SCRIPT,
    CONTAINER_DISABLE_SCRIPT, CONTAINER_ENABLE_SCRIPT,
    SMARTR_ACCT_CHAIN, SMARTR_ACCT_CHAIN_IN,
    SMARTR_INSTANCES, SMARTR_MIN_PREFIXES, SMARTR_TABLE,
    SmartRouteManager, SmartRouteError, SOURCES_V4, SOURCES_V6,
    build_install_script, build_remove_script, build_update_script,
    normalize_cidrs, parse_acct_counters, parse_ripe_delegated,
    render_container_script,
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
                    'Chain SMARTR_ACCT_IN (1 references)\n'
                    '     3      300 RETURN  all -- exit0 * 0.0.0.0/0  10.8.0.0/24\n'
                    '     2      200 RETURN  all -- eth0 * 0.0.0.0/0  10.8.0.0/24\n'
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
                    'Chain SMARTR_ACCT_IN (1 references)\n'
                    '     3      300 RETURN  all -- exit0 * 0.0.0.0/0  10.8.0.0/24\n'
                    '     2      200 RETURN  all -- eth0 * 0.0.0.0/0  10.8.0.0/24\n'
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
    def test_rows_mapped_by_iface_direction(self):
        text = ('Chain SMARTR_ACCT (1 references)\n'
                '    10     1000 RETURN  all -- * exit0 10.8.0.0/24  0.0.0.0/0\n'
                '     5      500 RETURN  all -- * eth0 10.8.0.0/24  0.0.0.0/0\n'
                'Chain SMARTR_ACCT_IN (1 references)\n'
                '     3      300 RETURN  all -- exit0 * 0.0.0.0/0  10.8.0.0/24\n'
                '     2      200 RETURN  all -- eth0 * 0.0.0.0/0  10.8.0.0/24\n')
        out = parse_acct_counters(text)
        # totals = egress + ingress per path
        self.assertEqual(out['via_exit'], {'pkts': 13, 'bytes': 1300})
        self.assertEqual(out['direct'], {'pkts': 7, 'bytes': 700})
        # direction split
        self.assertEqual(out['via_exit_out'], {'pkts': 10, 'bytes': 1000})
        self.assertEqual(out['via_exit_in'], {'pkts': 3, 'bytes': 300})
        self.assertEqual(out['direct_out'], {'pkts': 5, 'bytes': 500})
        self.assertEqual(out['direct_in'], {'pkts': 2, 'bytes': 200})

    def test_missing_chain_is_zero(self):
        out = parse_acct_counters('')
        for key in ('via_exit', 'direct', 'via_exit_out', 'direct_out',
                    'via_exit_in', 'direct_in'):
            self.assertEqual(out[key], {'pkts': 0, 'bytes': 0}, key)


class RipeHeredocRegressionTests(unittest.TestCase):
    """Bug 1 regression: the python parser embedded in the update script must
    join CIDRs with REAL newlines (escape fix) and read the delegated file
    from argv[2] - `python3 - <heredoc` would consume stdin as the program
    and parse nothing (live-found on MAMKAM: output was a single empty line).
    The test mirrors the real ripe_parse invocation: program file + data path.
    """

    def _run_embedded_parser(self, family='ipv4'):
        import subprocess
        import sys
        import tempfile
        import os
        from managers.smartroute_manager import _RIPE_PARSE_PY
        with tempfile.TemporaryDirectory() as td:
            prog = os.path.join(td, 'ripe_parse.py')
            data = os.path.join(td, 'delegated')
            with open(prog, 'w', encoding='utf-8') as f:
                f.write(_RIPE_PARSE_PY)
            with open(data, 'w', encoding='utf-8') as f:
                f.write(RIPE_SAMPLE)
            return subprocess.run([sys.executable, prog, family, data],
                                  capture_output=True)

    def test_embedded_parser_outputs_one_cidr_per_line(self):
        proc = self._run_embedded_parser()
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        lines = proc.stdout.decode().splitlines()
        self.assertGreater(len(lines), 1, 'RIPE output must be multi-line')
        self.assertIn('83.172.0.0/15', lines)
        self.assertIn('91.200.0.0/21', lines)

    def test_embedded_parser_ipv6(self):
        proc = self._run_embedded_parser('ipv6')
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn('2001:1b00::/32', proc.stdout.decode().splitlines())

    def test_update_script_carries_working_newline_join(self):
        # the generated update script must contain print("\n".join(...))
        self.assertIn('print("\\n".join(sorted(out)))', build_update_script())

    def test_update_script_ripe_parse_uses_file_program_and_stdin_path(self):
        script = build_update_script()
        self.assertIn('python3 "$prog" "$1" /dev/stdin', script)
        self.assertNotIn('python3 - "$1" <<', script)


class UpdateScriptTests(unittest.TestCase):
    def setUp(self):
        self.script = build_update_script()

    def test_guard_and_sources(self):
        self.assertIn(f'MIN_PREFIXES={SMARTR_MIN_PREFIXES}', self.script)
        self.assertIn('ipdeny.com', self.script)
        self.assertIn('herrbischoff', self.script)
        self.assertIn('delegated-ripencc-latest', self.script)

    def test_v6_first_source_is_a_real_v6_zone(self):
        # bug 2 regression: the first v6 source must be an IPv6 list, not the
        # v4 zone (it would always yield 0 prefixes and waste a fetch)
        self.assertIn('/ipv6/', SOURCES_V6[0])
        self.assertNotEqual(SOURCES_V6[0], SOURCES_V4[0])
        self.assertTrue(all('/ipv6/' in u or 'delegated' in u for u in SOURCES_V6))

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
        # first run is background: worst-case fallback walk exceeds any SSH timeout
        self.assertIn('nohup', script)
        self.assertIn('running in background', script)

    def test_remove_cleans_all(self):
        script = build_remove_script()
        for needle in ('disable --now smartroute.timer smartroute.service',
                       'rm -rf /etc/smartroute',
                       'route del throw',
                       'iptables -t mangle -D POSTROUTING',
                       'iptables -t mangle -D PREROUTING',
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
        self.assertNotIn('__CHAIN_IN__', rendered)
        self.assertIn(str(SMARTR_TABLE), rendered)
        self.assertIn(SMARTR_ACCT_CHAIN, rendered)
        self.assertIn(SMARTR_ACCT_CHAIN_IN, rendered)
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
        # accounting chain setup inside the container script (egress + ingress)
        uploaded = '\n'.join(c for _, c in self.ssh.uploads)
        self.assertIn(f'iptables -t mangle -A $CH -s "$X_SUBNET" -o exit0', uploaded)
        self.assertIn('iptables -t mangle -A $CHI -i exit0 -d "$X_SUBNET"', uploaded)
        self.assertIn('iptables -t mangle -A PREROUTING -j $CHI', uploaded)
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
        # totals (egress 10/1000 + ingress 3/300) and direction split
        self.assertEqual(out['via_exit'], {'pkts': 13, 'bytes': 1300})
        self.assertEqual(out['direct'], {'pkts': 7, 'bytes': 700})
        self.assertEqual(out['via_exit_in'], {'pkts': 3, 'bytes': 300})
        self.assertEqual(out['direct_out'], {'pkts': 5, 'bytes': 500})
        self.assertEqual(out['throw_routes'], 37)

    def test_disable_keeps_marker_when_container_cleanup_fails(self):
        # Retryable state (review hardening): the marker must survive a
        # failed container cleanup — while it exists the hourly update keeps
        # refreshing the still-applied routes and a retry stays possible.
        class FailSSH(FakeSSH):
            def run_sudo_command(self, cmd, timeout=60):
                super().run_sudo_command(cmd, timeout)
                if 'docker exec' in cmd:
                    return 'boom', '', 1
                return '', '', 0

        ssh = FailSSH()
        with self.assertRaises(SmartRouteError):
            SmartRouteManager(ssh).disable_instance(
                'amnezia-awg2', '/opt/amnezia/awg/awg0.conf', '10.8.0.0/24')
        cmds = ' '.join(ssh.commands)
        self.assertNotIn(f'rm -f {SMARTR_INSTANCES}/amnezia-awg2', cmds)


class ApplyHardeningTests(unittest.TestCase):
    """Regression tests for partial route-application failures (review feedback)."""

    def test_apply_snapshots_routes_before_delete(self):
        # last-known-good snapshot must exist BEFORE the del batch runs,
        # otherwise a restore has nothing to fall back to
        self.assertIn('/tmp/smartr_lkg.cidr', CONTAINER_APPLY_SCRIPT)
        self.assertLess(CONTAINER_APPLY_SCRIPT.index('smartr_lkg.cidr'),
                        CONTAINER_APPLY_SCRIPT.index('smartr_del.batch'))

    def test_apply_add_errors_are_not_swallowed(self):
        # the old script masked add failures with `|| true`, leaving the
        # kernel in a half-applied state; the verdict must drive a restore
        self.assertNotIn('smartr_add.batch 2>&1 || true', CONTAINER_APPLY_SCRIPT)
        self.assertIn('restoring last-known-good', CONTAINER_APPLY_SCRIPT)
        self.assertIn('restore incomplete', CONTAINER_APPLY_SCRIPT)

    def test_apply_verdict_reaches_the_caller(self):
        # standalone apply must exit non-zero (2 = restored, 1 = unknown)
        # so docker exec reports failure and callers never record success
        self.assertTrue(CONTAINER_APPLY_FINAL.rstrip().endswith('exit $APPLY_RC'))
        self.assertIn('exit $APPLY_RC', CONTAINER_ENABLE_SCRIPT)

    def test_update_script_checks_apply_result(self):
        script = build_update_script()
        self.assertIn('retrying on the next update', script)

    def test_remove_script_aborts_on_container_cleanup_failure(self):
        # host cleanup must not mask a failed container cleanup: markers
        # and timer stay so the next uninstall can retry
        script = build_remove_script()
        self.assertIn('CLEANUP_FAILED=1', script)
        self.assertIn('markers kept, retry uninstall', script)
        self.assertLess(script.index('markers kept, retry uninstall'),
                        script.index('rm -rf /etc/smartroute'))

    def test_enable_guards_on_apply_failure(self):
        # accounting chains must not be configured when the route apply
        # failed - the guard exits before the iptables part
        self.assertLess(CONTAINER_ENABLE_SCRIPT.index('[ "$APPLY_RC" = 0 ] || exit $APPLY_RC'),
                        CONTAINER_ENABLE_SCRIPT.index('iptables -t mangle -N $CH'))

    def test_disable_script_post_checks_cleanup(self):
        # leftover throw routes or still-attached accounting chains must make
        # the disable exit non-zero so docker exec reports the failure
        self.assertIn('disable incomplete', CONTAINER_DISABLE_SCRIPT)
        self.assertIn('exit 1', CONTAINER_DISABLE_SCRIPT)
        self.assertLess(CONTAINER_DISABLE_SCRIPT.index('disable incomplete'),
                        CONTAINER_DISABLE_SCRIPT.index('exit 1'))

    def test_disable_script_stays_within_throws_and_mangle(self):
        for bad in ('FORWARD', 'OUTPUT', 'ipset', 'route flush table'):
            self.assertNotIn(bad, CONTAINER_DISABLE_SCRIPT)


if __name__ == '__main__':
    unittest.main()
