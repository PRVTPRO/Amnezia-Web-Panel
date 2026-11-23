"""Circuit breaker for dead SSH servers.

A dead server must not be re-dialed on every API request (each attempt costs
up to the 15s connect timeout and used to freeze the whole panel). The breaker
fails fast after a failure and backs off exponentially: 30s -> 60s -> 120s ->
... capped at 300s. The first successful connect resets the streak and the
cooldown. Failures from the reconnect-and-retry path in `_run_command_locked`
feed the same breaker because `connect()` records them itself.
"""

import time
import unittest
from unittest import mock

from managers.ssh_manager import SSHManager


def make_manager():
    return SSHManager(host='203.0.113.1', port=22, username='root', password='x')


class CircuitBreakerTests(unittest.TestCase):
    def test_failed_connects_grow_the_cooldown(self):
        ssh = make_manager()
        with mock.patch.object(SSHManager, '_connect_once',
                               side_effect=OSError('timed out')):
            expected = [30.0, 60.0, 120.0, 240.0, 300.0, 300.0]
            for want in expected:
                with self.assertRaises(OSError):
                    ssh.connect()
                self.assertEqual(ssh._connect_cooldown, want)
            self.assertEqual(ssh._connect_fail_count, len(expected))

    def test_successful_connect_resets_streak_and_cooldown(self):
        ssh = make_manager()
        ssh._connect_fail_count = 4
        ssh._connect_cooldown = 240.0
        ssh._last_connect_fail = time.time()
        with mock.patch.object(SSHManager, '_connect_once', return_value=None):
            self.assertTrue(ssh.connect())
        self.assertEqual(ssh._connect_fail_count, 0)
        self.assertEqual(ssh._connect_cooldown, 30.0)
        self.assertEqual(ssh._last_connect_fail, 0.0)

    def test_ensure_connected_fails_fast_during_cooldown(self):
        ssh = make_manager()
        ssh._connect_fail_count = 1
        ssh._last_connect_fail = time.time()
        with mock.patch.object(SSHManager, 'connect') as connect:
            with self.assertRaises(ConnectionError) as ctx:
                ssh.ensure_connected()
        connect.assert_not_called()
        self.assertIn('backing off 30s', str(ctx.exception))

    def test_failed_reconnect_in_run_command_feeds_the_breaker(self):
        ssh = make_manager()
        ssh.ensure_connected = lambda: True
        ssh.client = mock.Mock()
        ssh.client.exec_command.side_effect = EOFError()  # dead transport
        with mock.patch.object(SSHManager, '_connect_once',
                               side_effect=OSError('still down')):
            out, err, code = ssh._run_command_locked('whoami', 10, False)
        self.assertEqual((out, code), ('', -1))
        self.assertEqual(ssh._connect_fail_count, 1)
        self.assertEqual(ssh._connect_cooldown, 30.0)
        self.assertGreater(ssh._last_connect_fail, 0)

    def test_retry_still_tries_twice_per_connect(self):
        # The two-attempt retry for links with SYN loss must survive: a single
        # connect() call costs one breaker failure, not two.
        ssh = make_manager()
        with mock.patch.object(SSHManager, '_connect_once',
                               side_effect=OSError('timed out')) as once:
            with self.assertRaises(OSError):
                ssh.connect()
        self.assertEqual(once.call_count, 2)
        self.assertEqual(ssh._connect_fail_count, 1)

    def test_custom_cooldown_base_scales_the_ladder(self):
        ssh = SSHManager(host='203.0.113.1', port=22, username='root',
                         password='x', connect_cooldown_base=10)
        self.assertEqual(ssh._connect_cooldown, 10.0)
        with mock.patch.object(SSHManager, '_connect_once',
                               side_effect=OSError('timed out')):
            expected = [10.0, 20.0, 40.0, 80.0, 160.0, 300.0]
            for want in expected:
                with self.assertRaises(OSError):
                    ssh.connect()
                self.assertEqual(ssh._connect_cooldown, want)
        with mock.patch.object(SSHManager, '_connect_once', return_value=None):
            ssh.connect()
        self.assertEqual(ssh._connect_cooldown, 10.0)


if __name__ == '__main__':
    unittest.main()
