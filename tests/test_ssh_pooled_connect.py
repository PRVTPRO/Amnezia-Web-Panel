"""Pooled SSH-соединение: идемпотентность и восстановление после отказа канала."""
import unittest
from unittest.mock import Mock

import paramiko

from managers.ssh_manager import SSHManager


class PooledConnectTests(unittest.TestCase):
    def test_connect_reuses_live_pooled_transport(self):
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        manager.client = Mock()
        manager.client.get_transport.return_value = transport
        manager._disconnect_locked = Mock()
        manager._connect_once = Mock()

        self.assertTrue(manager.connect())

        manager._disconnect_locked.assert_not_called()
        manager._connect_once.assert_not_called()

    def test_connect_replaces_dead_pooled_transport(self):
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = False
        manager.client = Mock()
        manager.client.get_transport.return_value = transport
        manager._disconnect_locked = Mock()
        manager._connect_once = Mock()

        self.assertTrue(manager.connect())

        manager._disconnect_locked.assert_called_once_with()
        manager._connect_once.assert_called_once_with()

    def test_connect_force_replaces_live_pooled_transport(self):
        """force=True обязателен, когда is_active() врёт о пригодности сессии."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        manager.client = stale
        manager._connect_once = Mock()

        self.assertTrue(manager.connect(force=True))

        stale.close.assert_called_once_with()
        self.assertIsNone(manager.client)
        manager._connect_once.assert_called_once_with()

    def test_exec_channel_failure_forces_reconnect_and_retries(self):
        """Issue #408: active-транспорт с исчерпанным MaxSessions заменяется.

        Без force reconnect ничего не закрывает, повтор уходит в старую сессию
        и падает второй раз. Проверяем, что закрыт именно старый клиент, создан
        новый и команда выполнена повторно.
        """
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        old_transport = Mock()
        old_transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = old_transport
        stale.exec_command.side_effect = paramiko.ChannelException(
            2, 'Connect failed')
        fresh = Mock()

        def new_connection():
            manager.client = fresh

        manager.client = stale
        manager._connect_once = Mock(side_effect=new_connection)
        manager.run_command = Mock(return_value=('ok', '', 0))

        out, err, code = manager._run_command_locked('whoami', 10, False)

        self.assertEqual((out, err, code), ('ok', '', 0))
        stale.close.assert_called_once_with()
        manager._connect_once.assert_called_once_with()
        self.assertIs(manager.client, fresh)
        manager.run_command.assert_called_once_with(
            'whoami', timeout=10, _retried=True, stdin_input=None)

    def test_non_channel_exec_failure_keeps_live_pooled_transport(self):
        """Обычная ошибка exec не должна рвать здоровую pooled-сессию."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        stale.exec_command.side_effect = TimeoutError('exec timeout')
        manager.client = stale
        manager._connect_once = Mock()
        manager.run_command = Mock(return_value=('', 'busy', -1))

        manager._run_command_locked('whoami', 10, False)

        stale.close.assert_not_called()
        manager._connect_once.assert_not_called()
        self.assertIs(manager.client, stale)

    def test_no_more_sessions_marker_forces_reconnect(self):
        """Текст 'no more sessions' — тот же отказ канала, даже без ChannelException."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        stale.exec_command.side_effect = OSError('error: no more sessions')
        fresh = Mock()
        manager.client = stale
        manager._connect_once = Mock(side_effect=lambda: setattr(manager, 'client', fresh))
        manager.run_command = Mock(return_value=('ok', '', 0))

        out, err, code = manager._run_command_locked('whoami', 10, False)

        self.assertEqual((out, code), ('ok', 0))
        stale.close.assert_called_once_with()
        manager._connect_once.assert_called_once_with()

    def test_generic_ssh_exception_keeps_pooled_transport(self):
        """SSHException без признаков отказа канала не должен рвать сессию."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        stale.exec_command.side_effect = paramiko.SSHException('bad auth type')
        manager.client = stale
        manager._connect_once = Mock()
        manager.run_command = Mock(return_value=('', 'err', -1))

        manager._run_command_locked('whoami', 10, False)

        stale.close.assert_not_called()
        manager._connect_once.assert_not_called()
        self.assertIs(manager.client, stale)

    def test_protocol_banner_ssh_error_does_not_force_reconnect(self):
        """SSHException без маркера канала — не повод рвать живую сессию."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        stale.exec_command.side_effect = paramiko.SSHException(
            'Error reading SSH protocol banner')
        manager.client = stale
        manager._connect_once = Mock()
        manager.run_command = Mock(return_value=('', 'err', -1))

        manager._run_command_locked('whoami', 10, False)

        stale.close.assert_not_called()
        manager._connect_once.assert_not_called()

    def test_bare_eof_error_does_not_force_reconnect(self):
        """Пустой EOFError также не содержит признаков отказа канала."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        transport = Mock()
        transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = transport
        stale.exec_command.side_effect = EOFError()
        manager.client = stale
        manager._connect_once = Mock()
        manager.run_command = Mock(return_value=('', 'err', -1))

        manager._run_command_locked('whoami', 10, False)

        stale.close.assert_not_called()
        manager._connect_once.assert_not_called()

    def test_disconnect_clears_transport_bound_caches(self):
        """После смены transports старые docker/AWG-снапшоты недействительны."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.client = Mock()
        manager._docker_ps_cache = (1.0, {'amnezia-awg3': 'running'})
        manager._awg_batch = {'_ts': 1.0, 'containers': {}}

        manager._disconnect_locked()

        self.assertIsNone(manager._docker_ps_cache)
        self.assertIsNone(manager._awg_batch)

    def test_channel_is_closed_after_successful_command(self):
        """Канал должен закрываться в finally, чтобы не занимать MaxSessions."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.ensure_connected = Mock(return_value=True)
        channel = Mock()
        channel.recv_exit_status.return_value = 0
        channel.status_event.wait.return_value = True
        stdout = Mock()
        stdout.channel = channel
        stdout.read.return_value = b'ok'
        stderr = Mock()
        stderr.channel = Mock()
        stderr.read.return_value = b''
        manager.client = Mock()
        manager.client.exec_command.return_value = (Mock(), stdout, stderr)

        out, err, code = manager._run_command_locked('echo ok', 10, False)

        self.assertEqual((out.strip(), code), ('ok', 0))
        channel.close.assert_called_once_with()

    def test_channel_is_closed_on_read_failure(self):
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.ensure_connected = Mock(return_value=True)
        channel = Mock()
        channel.status_event.wait.return_value = True
        stdout = Mock()
        stdout.channel = channel
        stdout.read.side_effect = OSError('broken pipe')
        stderr = Mock()
        stderr.channel = Mock()
        stderr.read.return_value = b''
        manager.client = Mock()
        manager.client.exec_command.return_value = (Mock(), stdout, stderr)

        out, err, code = manager._run_command_locked('echo ok', 10, False)

        self.assertEqual((out, code), ('', -1))
        self.assertGreaterEqual(channel.close.call_count, 1)

    def test_second_failed_exec_does_not_reconnect_again(self):
        """Один реконнект на команду: повторный отказ отдаёт -1, без цикла."""
        manager = SSHManager('example.test', 22, 'root', password='secret')
        manager.pooled = True
        stale_transport = Mock()
        stale_transport.is_active.return_value = True
        stale = Mock()
        stale.get_transport.return_value = stale_transport
        stale.exec_command.side_effect = paramiko.ChannelException(
            2, 'Connect failed')
        fresh_transport = Mock()
        fresh_transport.is_active.return_value = True
        fresh = Mock()
        fresh.get_transport.return_value = fresh_transport
        fresh.exec_command.side_effect = paramiko.ChannelException(
            2, 'Connect failed')

        def new_connection():
            manager.client = fresh

        manager.client = stale
        manager._connect_once = Mock(side_effect=new_connection)

        out, err, code = manager._run_command_locked('whoami', 10, False)

        self.assertEqual((out, code), ('', -1))
        self.assertIn('Connect failed', err)
        manager._connect_once.assert_called_once_with()
        stale.exec_command.assert_called_once()
        fresh.exec_command.assert_called_once()


if __name__ == '__main__':
    unittest.main()
