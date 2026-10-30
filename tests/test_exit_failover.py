"""Pure failover policy: health, thresholds, hysteresis, uid sanitizing."""
import unittest

import exit_failover as policy


class NormalizeTests(unittest.TestCase):
    def test_defaults_are_disabled(self):
        cfg = policy.normalize_config(None)
        self.assertFalse(cfg['enabled'])
        self.assertEqual(cfg['backup_uids'], [])
        self.assertEqual(cfg['check_interval_seconds'], 45)
        self.assertEqual(cfg['failure_threshold'], 3)
        self.assertTrue(cfg['auto_failback'])
        self.assertTrue(cfg['probe_egress'])

    def test_clamps_and_ignores_junk(self):
        cfg = policy.normalize_config({
            'enabled': 1,
            'backup_uids': ['a', '', None, 'a', 'b'],
            'check_interval_seconds': 2,
            'failure_threshold': 99,
            'failback_stable_seconds': 1,
            'handshake_max_age_seconds': 5,
            'garbage': True,
        })
        self.assertTrue(cfg['enabled'])
        self.assertEqual(cfg['backup_uids'], ['a', 'a', 'b'])
        self.assertEqual(cfg['check_interval_seconds'], policy.CHECK_INTERVAL_MIN)
        self.assertEqual(cfg['failure_threshold'], policy.FAILURE_THRESHOLD_MAX)
        self.assertEqual(cfg['failback_stable_seconds'], policy.FAILBACK_STABLE_MIN)
        self.assertEqual(cfg['handshake_max_age_seconds'], policy.HANDSHAKE_MAX_AGE_MIN)
        self.assertNotIn('garbage', cfg)


class SanitizeUidTests(unittest.TestCase):
    def test_drops_self_primary_unknown_and_duplicates_keeps_order(self):
        got = policy.sanitize_backup_uids(
            ['exit-c', 'entry-uid', 'exit-a', 'gone', 'exit-c', 'exit-b', 3],
            entry_uid='entry-uid',
            primary_uid='exit-a',
            known_exit_uids={'exit-a', 'exit-b', 'exit-c'},
        )
        self.assertEqual(got, ['exit-c', 'exit-b'])

    def test_empty_and_missing_known_fail_closed(self):
        self.assertEqual(policy.sanitize_backup_uids(['exit-a'], entry_uid='e',
                                                     primary_uid='', known_exit_uids=[]), [])


class ActiveHealthTests(unittest.TestCase):
    def test_handshake_none_or_stale_is_down(self):
        ok, reason = policy.evaluate_active_health(
            handshake_age=None, probe_egress=False)
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_NO_HANDSHAKE)
        ok, reason = policy.evaluate_active_health(
            handshake_age=500, probe_egress=False, handshake_max_age=240)
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_HANDSHAKE_STALE)

    def test_fresh_handshake_without_probe_is_up(self):
        ok, reason = policy.evaluate_active_health(
            handshake_age=12, probe_egress=False)
        self.assertTrue(ok)
        self.assertEqual(reason, policy.REASON_OK)

    def test_egress_leak_and_unknown_fail_when_probe_on(self):
        ok, reason = policy.evaluate_active_health(
            handshake_age=3, probe_egress=True,
            egress={'via_exit': '198.51.100.1', 'direct': '198.51.100.1', 'leaks': True})
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_EGRESS_LEAK)
        ok, reason = policy.evaluate_active_health(
            handshake_age=3, probe_egress=True, egress={'via_exit': '', 'direct': ''})
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_EGRESS_UNKNOWN)

    def test_nat_mismatch_is_still_healthy(self):
        ok, reason = policy.evaluate_active_health(
            handshake_age=3, probe_egress=True,
            egress={'via_exit': '203.0.113.99', 'direct': '198.51.100.1', 'leaks': False})
        self.assertTrue(ok)
        self.assertEqual(reason, policy.REASON_OK)

    def test_probe_error_and_status_missing(self):
        ok, reason = policy.evaluate_active_health(
            handshake_age=3, probe_egress=True, egress={'error': 'curl failed'})
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_EGRESS_ERROR)
        ok, reason = policy.evaluate_active_health(
            handshake_age=None, status_missing=True, probe_egress=False)
        self.assertFalse(ok)
        self.assertEqual(reason, policy.REASON_NO_HANDSHAKE)


class CandidateHealthTests(unittest.TestCase):
    def test_container_must_be_running(self):
        self.assertEqual(policy.evaluate_candidate_health(container_running=True)[0], True)
        self.assertEqual(policy.evaluate_candidate_health(container_running=False)[1],
                         policy.REASON_CONTAINER_STOPPED)
        self.assertEqual(policy.evaluate_candidate_health(ssh_error='down')[1],
                         policy.REASON_SSH_ERROR)


class DecideTests(unittest.TestCase):
    def setUp(self):
        self.cfg = policy.normalize_config({
            'enabled': True,
            'backup_uids': ['exit-c'],
            'failure_threshold': 3,
            'failback_stable_seconds': 60,
            'auto_failback': True,
        })
        self.state = policy.normalize_state({
            'primary_uid': 'exit-a',
            'active_uid': 'exit-a',
        })

    def decide(self, **kw):
        args = dict(config=self.cfg, state=self.state, now=1_000.0,
                    active_ok=True, active_reason=policy.REASON_OK,
                    primary_ok=True, healthy_uids={'exit-a', 'exit-c'})
        args.update(kw)
        return policy.decide(**args)

    def test_disabled_is_noop(self):
        self.cfg['enabled'] = False
        d = self.decide()
        self.assertEqual(d['action'], policy.ACTION_NOOP)

    def test_threshold_switches_to_next_healthy_backup(self):
        self.state['consecutive_failures'] = 2
        d = self.decide(active_ok=False, active_reason=policy.REASON_NO_HANDSHAKE,
                        primary_ok=False, healthy_uids={'exit-c'})
        self.assertEqual(d['action'], policy.ACTION_FAILOVER)
        self.assertEqual(d['target_uid'], 'exit-c')
        self.assertEqual(d['state']['consecutive_failures'], 3)

    def test_below_threshold_stays(self):
        d = self.decide(active_ok=False, active_reason=policy.REASON_NO_HANDSHAKE,
                        primary_ok=False, healthy_uids={'exit-c'})
        self.assertEqual(d['action'], policy.ACTION_STAY)
        self.assertEqual(d['state']['consecutive_failures'], 1)

    def test_success_resets_failures(self):
        self.state['consecutive_failures'] = 2
        d = self.decide(active_ok=True)
        self.assertEqual(d['action'], policy.ACTION_STAY)
        self.assertEqual(d['state']['consecutive_failures'], 0)
        self.assertEqual(d['state']['consecutive_successes'], 1)

    def test_no_healthy_target_stays(self):
        self.state['consecutive_failures'] = 2
        d = self.decide(active_ok=False, healthy_uids=set(), primary_ok=False)
        self.assertEqual(d['action'], policy.ACTION_STAY)
        self.assertEqual(d['reason'], policy.REASON_NO_TARGET)

    def test_failback_requires_stable_period(self):
        self.state['active_uid'] = 'exit-c'
        d = self.decide(active_ok=True, primary_ok=True, healthy_uids={'exit-a', 'exit-c'})
        self.assertEqual(d['action'], policy.ACTION_STAY)
        self.assertIsNotNone(d['state']['primary_healthy_since'])
        since = policy.parse_ts(d['state']['primary_healthy_since'])
        d2 = policy.decide(
            config=self.cfg, state=d['state'], now=since + 59,
            active_ok=True, active_reason=policy.REASON_OK,
            primary_ok=True, healthy_uids={'exit-a', 'exit-c'})
        self.assertEqual(d2['action'], policy.ACTION_STAY)
        d3 = policy.decide(
            config=self.cfg, state=d2['state'], now=since + 60,
            active_ok=True, active_reason=policy.REASON_OK,
            primary_ok=True, healthy_uids={'exit-a', 'exit-c'})
        self.assertEqual(d3['action'], policy.ACTION_FAILBACK)
        self.assertEqual(d3['target_uid'], 'exit-a')

    def test_failback_resets_when_primary_drops(self):
        self.state['active_uid'] = 'exit-c'
        self.state['primary_healthy_since'] = policy.isoformat(1_000.0)
        d = self.decide(now=1_200.0, active_ok=True, primary_ok=False,
                        healthy_uids={'exit-c'})
        self.assertEqual(d['action'], policy.ACTION_STAY)
        self.assertIsNone(d['state']['primary_healthy_since'])

    def test_auto_failback_off_never_returns(self):
        self.cfg['auto_failback'] = False
        self.state['active_uid'] = 'exit-c'
        self.state['primary_healthy_since'] = policy.isoformat(1.0)
        d = self.decide(now=10_000.0, active_ok=True, primary_ok=True,
                        healthy_uids={'exit-a', 'exit-c'})
        self.assertEqual(d['action'], policy.ACTION_STAY)

    def test_due_for_check(self):
        self.assertTrue(policy.due_for_check({}, 45, 10))
        st = {'last_check_at': policy.isoformat(100.0)}
        self.assertFalse(policy.due_for_check(st, 45, 144.0))
        self.assertTrue(policy.due_for_check(st, 45, 145.0))


class EventLogTests(unittest.TestCase):
    def test_prepends_and_caps(self):
        events = []
        for i in range(55):
            events = policy.append_event(
                events, now=float(i), action='failover',
                from_uid='a', to_uid='b', reason='x', limit=50)
        self.assertEqual(len(events), 50)
        self.assertEqual(events[0]['from_uid'], 'a')
        self.assertEqual(policy.parse_ts(events[0]['at']), 54.0)


if __name__ == '__main__':
    unittest.main()
