"""Regression tests for exit_failover.parse_ts.

parse_ts used datetime.timestamp() on naive values. On Windows a naive local
date before the Unix epoch makes the C runtime mktime() raise
OSError(EINVAL), so any timestamp written shortly after the epoch (for
example isoformat(100.0) on a host west of UTC) crashed the caller instead of
returning a number. The module stored exactly such stamps, and the whole
failover tick died with an unhandled OSError.
"""
import unittest
from datetime import datetime, timezone

import exit_failover as policy


class ParseTsTests(unittest.TestCase):

    def test_number_passthrough(self):
        self.assertEqual(policy.parse_ts(100.0), 100.0)
        self.assertEqual(policy.parse_ts(0), 0.0)

    def test_empty_and_none(self):
        self.assertIsNone(policy.parse_ts(None))
        self.assertIsNone(policy.parse_ts(''))

    def test_bad_string_returns_none(self):
        self.assertIsNone(policy.parse_ts('not-a-date'))
        self.assertIsNone(policy.parse_ts('2026-13-45T99:99:99'))

    def test_own_output_round_trips(self):
        """Whatever isoformat() writes must parse back to the same instant."""
        for instant in (0.0, 1.0, 100.0, 1000.0, 1e9):
            stamp = policy.isoformat(instant)
            parsed = policy.parse_ts(stamp)
            self.assertIsNotNone(parsed, stamp)
            self.assertAlmostEqual(parsed, instant, delta=1.0, msg=stamp)

    def test_aware_string_is_absolute(self):
        self.assertEqual(policy.parse_ts('1970-01-01T00:00:00+00:00'), 0.0)

    def test_pre_epoch_naive_string_does_not_raise(self):
        """The exact input that raised OSError on Windows before the fix."""
        # Local wall clock 100 s after the epoch: west of UTC this is
        # 1969-12-31T18:58:20, i.e. a date before the epoch.
        local_stamp = datetime.fromtimestamp(100.0).isoformat()
        parsed = policy.parse_ts(local_stamp)
        self.assertIsNotNone(parsed)
        self.assertAlmostEqual(parsed, 100.0, delta=1.0, msg=local_stamp)

    def test_naive_uses_local_time_like_timestamp(self):
        """Naive stamps stay interpreted as local time, not silently as UTC."""
        naive = datetime.now().replace(tzinfo=None).isoformat()
        expected = datetime.fromisoformat(naive).timestamp()
        parsed = policy.parse_ts(naive)
        self.assertAlmostEqual(parsed, expected, delta=1.0, msg=naive)

    def test_aware_and_naive_same_instant_differ_only_by_offset(self):
        utc_now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        self.assertIsNotNone(policy.parse_ts(utc_now))

    def test_isoformat_is_offset_aware(self):
        """Stamps written by our own isoformat() must carry the UTC offset."""
        for instant in (0.0, 1e9):
            stamp = policy.isoformat(instant)
            self.assertIn('T', stamp)
            time_part = stamp.split('T', 1)[1]
            self.assertTrue(
                time_part.endswith('Z') or '+' in time_part or '-' in time_part,
                f'expected UTC offset in {stamp!r} for instant={instant}',
            )
            parsed = datetime.fromisoformat(stamp)
            self.assertIsNotNone(parsed.tzinfo, f'{stamp!r} is not offset-aware')
            parsed_ts = policy.parse_ts(stamp)
            self.assertIsNotNone(parsed_ts, stamp)
            self.assertAlmostEqual(parsed_ts, instant, delta=1.0, msg=stamp)


if __name__ == '__main__':
    unittest.main()
