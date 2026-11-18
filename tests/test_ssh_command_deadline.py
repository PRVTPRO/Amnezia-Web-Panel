"""A dead SSH route must fail a command, not the whole panel.

Reported in issue #347: after the route to a managed node changed, the existing
SSH session became invalid and the panel stopped answering HTTP at all (TCP
connected, no response, container alive, restart helped). The transport stays
`is_active()` forever when packets are blackholed, and paramiko waits without a
timeout: `recv_exit_status()` blocks on an Event, SFTP has none at all. Each
such call held uvicorn's worker thread, every later request parked on the same
per-server lock, and the 40-thread pool used for sync endpoints ran out.

These tests pin the three guarantees:
- a lost exit status ends as an error within the command timeout;
- output is drained before the exit status is awaited (no window deadlock);
- waiters on the exec lock give up instead of queueing forever.
"""

import threading
import time
import unittest
from unittest import mock

import managers.ssh_manager as ssh_module
from managers.ssh_manager import SSHManager


class FakeChannel:
    def __init__(self, status=True, exit_code=0):
        self.timeout = None
        self.closed = False
        self.read_done = False
        self.exit_code = exit_code
        self.status_event = threading.Event()
        if status:
            self.status_event.set()

    def settimeout(self, value):
        self.timeout = value

    def close(self):
        self.closed = True

    def recv_exit_status(self):
        if not self.read_done:
            raise AssertionError('exit status awaited before the output was read')
        return self.exit_code


class FakeStream:
    def __init__(self, channel, data=b''):
        self.channel = channel
        self.data = data

    def read(self):
        self.channel.read_done = True
        return self.data


class PairedStream:
    """Fails unless another stream is being read at the same time."""

    def __init__(self, channel, data, wait_for, announce):
        self.channel = channel
        self.data = data
        self.wait_for = wait_for
        self.announce = announce

    def read(self):
        self.channel.read_done = True
        self.announce.set()
        if not self.wait_for.wait(2):
            raise TimeoutError('the streams were read one after another')
        return self.data


class SlowStream:
    """Produces data after a delay, like a command that keeps making progress."""

    def __init__(self, channel, data, delay):
        self.channel = channel
        self.data = data
        self.delay = delay

    def read(self):
        self.channel.read_done = True
        time.sleep(self.delay)
        return self.data


def make_manager(channel, stdout_data=b'', stderr_data=b'out'):
    ssh = SSHManager.__new__(SSHManager)
    ssh.host = '203.0.113.10'
    ssh.port = 22
    ssh._exec_lock = threading.RLock()
    ssh._conn_lock = threading.RLock()
    ssh._is_root = True
    ssh.ensure_connected = lambda: None
    ssh.client = mock.Mock()
    ssh.client.exec_command.return_value = (
        FakeStream(channel), FakeStream(channel, stdout_data),
        FakeStream(channel, stderr_data))
    return ssh


def hold_lock(lock):
    """Hold a lock from another thread so RLock re-entrancy cannot bypass it."""
    ready = threading.Event()
    release = threading.Event()

    def worker():
        lock.acquire()
        ready.set()
        release.wait(10)
        lock.release()

    threading.Thread(target=worker, daemon=True).start()
    assert ready.wait(5), 'the helper thread did not take the lock'
    return release


class CommandDeadlineTests(unittest.TestCase):
    def test_lost_exit_status_returns_an_error(self):
        channel = FakeChannel(status=False)
        ssh = make_manager(channel)
        client = ssh.client

        started = time.monotonic()
        out, err, code = ssh.run_command('sleep 300', timeout=0.2)
        elapsed = time.monotonic() - started

        self.assertEqual(code, -1)
        self.assertEqual(out, '')
        self.assertIn('timed out', err)
        self.assertLess(elapsed, 5.0, 'the command must not wait forever')
        self.assertTrue(channel.closed)
        # A slow command on a link that still looks alive keeps the pooled
        # transport: only a transport that is really gone is dropped.
        self.assertIsNotNone(ssh.client)

    def test_a_dead_transport_is_dropped(self):
        channel = FakeChannel(status=False)
        ssh = make_manager(channel)
        ssh.client.get_transport.return_value.is_active.return_value = False
        client = ssh.client

        out, err, code = ssh.run_command('sleep 300', timeout=0.2)

        self.assertEqual(code, -1)
        self.assertTrue(client.close.called)
        self.assertIsNone(ssh.client)

    def test_output_is_read_before_the_exit_status(self):
        channel = FakeChannel()
        ssh = make_manager(channel, stdout_data=b'ok', stderr_data=b'')

        out, err, code = ssh.run_command('echo ok', timeout=5)

        self.assertEqual((out, code), ('ok', 0))
        self.assertTrue(channel.read_done)

    def test_missing_exit_status_on_a_live_link_keeps_the_output(self):
        # paramiko does not decode exit-signal: a signal-killed command leaves
        # the status at -1 on a perfectly healthy transport.
        channel = FakeChannel(exit_code=-1)
        ssh = make_manager(channel, stdout_data=b'saved', stderr_data=b'')

        out, err, code = ssh.run_command('docker restart x', timeout=5)

        self.assertEqual(code, -1)
        self.assertEqual(out, 'saved')
        self.assertIn('killed before reporting', err)

    def test_missing_exit_status_on_a_dead_link_is_reported_as_lost(self):
        channel = FakeChannel(exit_code=-1)
        ssh = make_manager(channel, stdout_data=b'')
        ssh.client.get_transport.return_value.is_active.return_value = False
        client = ssh.client

        out, err, code = ssh.run_command('docker restart x', timeout=5)

        self.assertEqual(code, -1)
        self.assertIn('exit status was not received', err)
        self.assertTrue(client.close.called)
        self.assertIsNone(ssh.client)

    def test_no_timeout_means_the_default_budget(self):
        ssh = make_manager(FakeChannel(), stdout_data=b'ok', stderr_data=b'')

        out, err, code = ssh.run_command('echo ok', timeout=None)

        self.assertEqual((out, code), ('ok', 0))

    def test_large_output_does_not_deadlock(self):
        channel = FakeChannel()
        payload = b'x' * 300_000
        ssh = make_manager(channel, stdout_data=payload, stderr_data=b'')

        out, err, code = ssh.run_command('cat big', timeout=5)

        self.assertEqual(code, 0)
        self.assertEqual(len(out), len(payload))

    def test_waiting_for_the_exec_lock_is_bounded(self):
        ssh = make_manager(FakeChannel())
        with mock.patch.object(ssh_module, '_EXEC_LOCK_SLACK', 0.1):
            release = hold_lock(ssh._exec_lock)
            try:
                started = time.monotonic()
                out, err, code = ssh.run_command('echo hi', timeout=0.2)
                elapsed = time.monotonic() - started
            finally:
                release.set()

        self.assertEqual(code, -1)
        self.assertIn('busy', err)
        self.assertLess(elapsed, 5.0)
        self.assertFalse(ssh.client.exec_command.called,
                         'a busy server must not queue another SSH call')

    def test_busy_lock_fails_an_sftp_call_too(self):
        ssh = make_manager(FakeChannel())
        with mock.patch.object(ssh_module, '_EXEC_LOCK_SLACK', 0.1), \
                mock.patch.object(ssh_module, '_SFTP_TIMEOUT', 0.2):
            release = hold_lock(ssh._exec_lock)
            try:
                started = time.monotonic()
                with self.assertRaises(RuntimeError):
                    ssh.upload_file('data', '/tmp/x')
                elapsed = time.monotonic() - started
            finally:
                release.set()

        self.assertLess(elapsed, 5.0)
        self.assertFalse(ssh.client.open_sftp.called)

    def test_a_slow_but_flowing_command_is_not_cut_by_the_inactivity_timeout(self):
        # `timeout` on a command bounds inactivity, not total runtime: a pull
        # that keeps printing must not die just because it runs longer.
        channel = FakeChannel()
        ssh = make_manager(channel)
        ssh.client.exec_command.return_value = (
            FakeStream(channel),
            SlowStream(channel, b'progress', 0.3),
            SlowStream(channel, b'', 0.3))

        out, err, code = ssh.run_command('docker pull', timeout=0.1)

        self.assertEqual((out, code), ('progress', 0))

    def test_the_wait_budget_is_capped(self):
        # A 900s transfer must not make an ordinary request queue for its own
        # budget; the caller gets "busy" as soon as the cap expires.
        ssh = make_manager(FakeChannel())
        with mock.patch.object(ssh_module, '_EXEC_LOCK_SLACK', 0.1), \
                mock.patch.object(ssh_module, '_EXEC_WAIT_MAX', 0.2):
            release = hold_lock(ssh._exec_lock)
            try:
                started = time.monotonic()
                with ssh._exec_slot(600) as slot:
                    self.assertFalse(slot)
                elapsed = time.monotonic() - started
            finally:
                release.set()
        self.assertLess(elapsed, 5.0)

    def test_stdout_and_stderr_are_drained_concurrently(self):
        # Reading stdout to EOF first deadlocks when a chatty command fills the
        # shared window with stderr: both streams must move at the same time.
        channel = FakeChannel()
        out_ready, err_ready = threading.Event(), threading.Event()
        ssh = make_manager(channel)
        ssh.client.exec_command.return_value = (
            FakeStream(channel),
            PairedStream(channel, b'out', err_ready, out_ready),
            PairedStream(channel, b'err', out_ready, err_ready))

        out, err, code = ssh.run_command('chatty', timeout=3)

        self.assertEqual((out, err, code), ('out', 'err', 0))

    def test_upload_sets_the_sftp_inactivity_timeout(self):
        ssh = make_manager(FakeChannel())
        sftp = ssh.client.open_sftp.return_value = mock.MagicMock()
        ssh.upload_file('data', '/tmp/x')
        sftp.get_channel.return_value.settimeout.assert_called_once_with(
            ssh.SFTP_INACTIVITY_TIMEOUT)

    def test_the_command_budget_covers_start_and_reads(self):
        # A slow-but-healthy command gets 2*timeout + grace, and the exec call
        # itself (Channel._wait_for_event has no timeout) is inside a switch.
        ssh = make_manager(FakeChannel(), stdout_data=b'ok', stderr_data=b'')
        seen = []
        real = ssh._kill_switch

        def record(seconds, what='call'):
            seen.append((seconds, what))
            return real(seconds, what)

        ssh._kill_switch = record
        ssh.run_command('echo ok', timeout=0.5)

        self.assertIn('command start', [what for _, what in seen])
        self.assertIn(2 * 0.5 + ssh_module._KILL_SWITCH_GRACE,
                      [seconds for seconds, what in seen if what == 'command'])

    def test_jump_channel_open_is_bounded(self):
        ssh = SSHManager.__new__(SSHManager)
        ssh.host, ssh.port, ssh.username = '10.0.0.2', 22, 'root'
        ssh.password, ssh.private_key = 'x', None
        ssh.jump_manager = mock.Mock()
        ssh.jump_manager.client.get_transport.return_value.is_active.return_value = True
        client = mock.MagicMock()

        with mock.patch('paramiko.SSHClient', return_value=client):
            ssh._connect_once()

        open_channel = ssh.jump_manager.client.get_transport.return_value.open_channel
        self.assertEqual(open_channel.call_args.kwargs.get('timeout'),
                         ssh_module._CHANNEL_OPEN_TIMEOUT)


class KillSwitchTests(unittest.TestCase):
    def test_the_transport_is_closed_when_a_call_outlives_its_budget(self):
        ssh = make_manager(FakeChannel())
        client = ssh.client
        with ssh._kill_switch(0.1, 'test'):
            time.sleep(0.3)
        self.assertTrue(client.close.called)

    def test_a_call_that_finishes_in_time_is_not_interrupted(self):
        ssh = make_manager(FakeChannel())
        client = ssh.client
        with ssh._kill_switch(5, 'test'):
            time.sleep(0.05)
        self.assertFalse(client.close.called)

    def test_a_client_connected_during_the_call_is_the_one_closed(self):
        # ensure_connected() may replace self.client while the call is blocked:
        # closing only the client captured at entry would leave the live one.
        ssh = make_manager(FakeChannel())
        ssh.client = None
        with ssh._kill_switch(0.1, 'test'):
            live = mock.Mock()
            ssh.client = live
            time.sleep(0.3)
        self.assertTrue(live.close.called)


class SftpTransferTests(unittest.TestCase):
    def test_transfer_sets_an_inactivity_timeout_and_closes(self):
        ssh = make_manager(FakeChannel())
        sftp = ssh.client.open_sftp.return_value
        with ssh.sftp_transfer(budget=5, inactivity=3):
            pass
        sftp.get_channel.return_value.settimeout.assert_called_once_with(3.0)
        self.assertTrue(sftp.close.called)

    def test_transfer_closes_the_session_when_the_body_fails(self):
        ssh = make_manager(FakeChannel())
        sftp = ssh.client.open_sftp.return_value
        with self.assertRaises(OSError):
            with ssh.sftp_transfer(budget=5):
                raise OSError('upload failed')
        self.assertTrue(sftp.close.called)

    def test_transfer_refuses_to_queue_on_a_busy_server(self):
        ssh = make_manager(FakeChannel())
        with mock.patch.object(ssh_module, '_EXEC_LOCK_SLACK', 0.1):
            release = hold_lock(ssh._exec_lock)
            try:
                with self.assertRaises(RuntimeError):
                    with ssh.sftp_transfer(budget=0.2):
                        pass
            finally:
                release.set()
        self.assertFalse(ssh.client.open_sftp.called)


if __name__ == '__main__':
    unittest.main()
