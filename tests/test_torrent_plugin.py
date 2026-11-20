"""Плагин «Защита от торрентов»: стор, операции, гейтинг ядра и вёрстка.

Главное правило, которое здесь проверяется: пока плагин не установлен на
сервере, в ядре нет ни разметки, ни роутов, ни фонового SSH-сбора, а
`GET /connections` не отдаёт торрент-полей.
"""

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import app as panel
import torrent_plugin_service as service
from managers import torrent_events

ROOT = Path(__file__).resolve().parents[1]


def server(uid='srv-uid', protocols=None):
    return {'name': 'Node', 'host': '192.0.2.10', 'ssh_port': 22,
            'username': 'root', 'uid': uid,
            'protocols': protocols if protocols is not None else
            {'awg3': {'installed': True}}}


class FakeGuard:
    """Заглушка движка: пишет вызовы и умеет падать."""

    def __init__(self, fail=False, events=None):
        self.fail = fail
        self.events = list(events or [])
        self.applied = []

    def apply(self, mode):
        self.applied.append(mode)
        return {'error': 'iptables: boom' if self.fail else ''}

    def collect(self, mode):
        return {'error': '', 'events': list(self.events), 'peers': 1}

    def read(self):
        return {'error': 'iptables: boom' if self.fail else ''}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._data_file = panel.DATA_FILE
        self._plugin = panel.torrent_plugin
        self._monitor = panel._conn_monitor_started
        panel.DATA_FILE = os.path.join(self.tmp, 'data.json')
        panel._conn_monitor_started = True
        self.plugin = service.TorrentPlugin(lambda: panel.DATA_FILE)
        panel.torrent_plugin = self.plugin
        self.write_data({'servers': [server()],
                         'users': [{'id': 'admin-id', 'username': 'admin',
                                    'password_hash': panel.hash_password('admin'),
                                    'role': 'admin', 'enabled': True}],
                         'user_connections': []})

    def tearDown(self):
        panel.DATA_FILE = self._data_file
        panel.torrent_plugin = self._plugin
        panel._conn_monitor_started = self._monitor
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_data(self, data):
        with open(panel.DATA_FILE, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)

    def data(self):
        with open(panel.DATA_FILE, encoding='utf-8') as handle:
            return json.load(handle)

    def login(self, client):
        response = client.post('/api/auth/login',
                               json={'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)


class StoreAndInstallTests(Base):
    def test_install_is_disabled_until_enabled_explicitly(self):
        # После установки контроля нет: правила снимаются, состояние off.
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {}, 'wireguard': {}}
        guards = {}

        def factory(proto):
            guards[proto] = FakeGuard()
            return guards[proto]

        result = self.plugin.install(node, factory)
        self.assertTrue(result['installed'])
        self.assertFalse(result['enabled'])
        self.assertEqual(result['state'], 'off')
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'off')
        self.assertEqual(guards['awg3'].applied, ['off'])
        self.assertTrue(os.path.exists(self.plugin.state_file))
        self.assertTrue(self.plugin.installed(node))
        # «Включить контроль» применяет default_mode.
        guard = FakeGuard()
        enabled = self.plugin.set_enabled(node, lambda proto: guard, True)
        self.assertTrue(enabled['enabled'])
        self.assertEqual(enabled['state'], 'on')
        self.assertEqual(guard.applied, ['on', 'on'])
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'on')

    def test_install_is_idempotent_without_reapply(self):
        node = self.data()['servers'][0]
        calls = []
        factory = lambda proto: calls.append(proto) or FakeGuard()
        self.plugin.install(node, factory)
        calls.clear()
        result = self.plugin.install(node, factory)
        self.assertTrue(result['installed'])
        self.assertEqual(calls, [])

    def test_install_clears_leftover_rules(self):
        # Установка снимает возможные остатки правил старой фичи: включённым
        # плагин после установки не считается.
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {'torrent_guard': 'count'}}
        guard = FakeGuard()
        result = self.plugin.install(node, lambda proto: guard)
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'off')
        self.assertEqual(guard.applied, ['off'])
        self.assertEqual(result['state'], 'off')

    def test_install_without_capable_instances_is_allowed(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'xray': {}}
        result = self.plugin.install(node, lambda proto: FakeGuard())
        self.assertTrue(result['installed'])
        self.assertFalse(result['supported'])
        self.assertEqual(result['state'], 'unsupported')

    def test_install_failure_keeps_record_so_rules_are_manageable(self):
        # Правила могли частично встать: запись «установлен» нужна, иначе
        # цепочки TGIN* остались бы без способа ими управлять.
        node = self.data()['servers'][0]
        result = self.plugin.install(node, lambda proto: FakeGuard(fail=True))
        self.assertTrue(result['installed'])
        self.assertTrue(result['errors'])
        self.assertNotIn('torrent_guard', node['protocols']['awg3'])
        self.assertEqual(self.plugin.health_for(node)['state'], 'degraded')

    def test_partial_apply_reports_errors_and_health(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {}, 'awg2': {}}
        healthy = FakeGuard()

        def factory(proto):
            return healthy if proto == 'awg3' else FakeGuard(fail=True)

        self.plugin.install(node, lambda proto: FakeGuard())
        result = self.plugin.set_enabled(node, factory, True)
        self.assertTrue(result['enabled'])
        self.assertTrue(result['errors'])
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'on')
        self.assertEqual(self.plugin.health_for(node)['state'], 'degraded')

    def test_reapply_keeps_per_instance_mode(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        self.plugin.set_enabled(node, lambda proto: FakeGuard(), True)
        self.plugin.set_mode(node, lambda proto: FakeGuard(), 'awg3', 'count')
        guard = FakeGuard()
        self.plugin.install(node, lambda proto: guard, reapply=True)
        self.assertEqual(guard.applied, ['count'])
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'count')

    def test_capable_skips_removed_instances(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {'installed': False}, 'awg2': {}}
        self.assertEqual(self.plugin.capable(node, True), ['awg2'])

    def test_settings_disable_wireguard_turns_rules_off(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {}, 'wireguard': {}}
        self.plugin.install(node, lambda proto: FakeGuard())
        self.plugin.set_enabled(node, lambda proto: FakeGuard(), True)
        stop = self.plugin.excluded_wireguard(node, {'include_wireguard': False})
        self.assertEqual(stop, ['wireguard'])
        guard = FakeGuard()
        result = self.plugin.set_settings(node, lambda proto: guard,
                                          {'include_wireguard': False})
        self.assertEqual(guard.applied, ['off'])
        self.assertEqual(result['changes'], {'wireguard': 'off'})
        self.assertNotIn('torrent_guard', node['protocols']['wireguard'])

    def test_uninstall_removes_rules_keys_marks_and_record(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        journal = torrent_events.empty()
        torrent_events.record(journal, 'srv-uid', 'awg3', '10.0.0.5',
                              [{'ts': 1760000000, 'sig': 'handshake',
                                'count': 1}])
        torrent_events.save(self.plugin.events_file, journal)
        guard = FakeGuard()
        result = self.plugin.uninstall(node, lambda proto: guard)
        self.assertFalse(result['installed'])
        self.assertEqual(guard.applied, ['off'])
        self.assertNotIn('torrent_guard', node['protocols']['awg3'])
        self.assertFalse(self.plugin.installed(node))
        self.assertEqual(self.plugin.summary(node), {})

    def test_uninstall_keeps_record_when_rules_cannot_be_removed(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        with self.assertRaises(service.PluginError) as ctx:
            self.plugin.uninstall(node, lambda proto: FakeGuard(fail=True))
        self.assertEqual(ctx.exception.status, 502)
        self.assertTrue(self.plugin.installed(node))

    def test_uninstall_ignores_stopped_containers(self):
        node = self.data()['servers'][0]

        class Stopped(FakeGuard):
            def apply(self, mode):
                return {'error': 'Error response from daemon: container x is not running'}

        self.plugin.install(node, lambda proto: FakeGuard())
        result = self.plugin.uninstall(node, lambda proto: Stopped())
        self.assertFalse(result['installed'])
        self.assertEqual(result['errors'], [])

    def test_force_uninstall_removes_record_despite_errors(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        result = self.plugin.uninstall(node, lambda proto: FakeGuard(fail=True),
                                       force=True)
        self.assertFalse(result['installed'])
        self.assertTrue(result['errors'])

    def test_master_switch_preserves_count_mode(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        self.plugin.set_enabled(node, lambda proto: FakeGuard(), True)
        self.plugin.set_mode(node, lambda proto: FakeGuard(), 'awg3', 'count')
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'count')
        guard = FakeGuard()
        self.plugin.set_enabled(node, lambda proto: guard, False)
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'off')
        self.assertEqual(self.plugin.record(node)['suspended_modes'],
                         {'awg3': 'count'})
        guard2 = FakeGuard()
        self.plugin.set_enabled(node, lambda proto: guard2, True)
        self.assertEqual(node['protocols']['awg3']['torrent_guard'], 'count')

    def test_wireguard_can_be_excluded_by_settings(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {}, 'wireguard': {}}
        self.plugin.install(node, lambda proto: FakeGuard(),
                            settings={'include_wireguard': False})
        self.assertIn('torrent_guard', node['protocols']['awg3'])
        self.assertNotIn('torrent_guard', node['protocols']['wireguard'])
        with self.assertRaises(service.PluginError) as ctx:
            self.plugin.set_mode(node, lambda proto: FakeGuard(),
                                 'wireguard', 'on')
        self.assertEqual(ctx.exception.code, 'wireguard_disabled')

    def test_uninstall_turns_off_wireguard_even_if_now_excluded(self):
        node = self.data()['servers'][0]
        node['protocols'] = {'awg3': {}, 'wireguard': {}}
        self.plugin.install(node, lambda proto: FakeGuard())
        record = self.plugin.record(node)
        record['settings']['include_wireguard'] = False
        self.plugin.write_record(node, record)
        guards = {}

        def factory(proto):
            guards[proto] = FakeGuard()
            return guards[proto]

        self.plugin.uninstall(node, factory)
        self.assertEqual(guards['wireguard'].applied, ['off'])
        self.assertNotIn('torrent_guard', node['protocols']['wireguard'])

    def test_settings_validation(self):
        for bad in ({'poll_seconds': 7}, {'marks_ttl_days': 1},
                    {'default_mode': 'disable'}, {'nope': True},
                    {'include_wireguard': 'yes'}):
            with self.assertRaises(service.PluginError, msg=bad) as ctx:
                service.validate_settings(bad)
            self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(service.validate_settings({'marks_ttl_days': 7}),
                         {'marks_ttl_days': 7})

    def test_health_states(self):
        node = self.data()['servers'][0]
        self.assertEqual(self.plugin.health_for(node)['state'], 'unknown')
        self.plugin.set_health(node, 'awg3', {'error': ''})
        self.assertEqual(self.plugin.health_for(node)['state'], 'ok')
        self.plugin.set_health(node, 'awg3', {'error': 'denied'})
        self.assertEqual(self.plugin.health_for(node)['state'], 'degraded')

    def test_refresh_hides_peer_count_without_hooks(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())

        class ReadGuard(FakeGuard):
            def __init__(self, hook):
                super().__init__()
                self.hook = hook

            def read(self):
                return {'error': '', 'hook': self.hook,
                        'peers': ['10.8.1.2', '10.8.1.3']}

        self.plugin.refresh(node, lambda proto: ReadGuard(0))
        entry = self.plugin.health_for(node)['protocols']['awg3']
        self.assertNotIn('peers', entry)
        self.plugin.refresh(node, lambda proto: ReadGuard(3))
        entry = self.plugin.health_for(node)['protocols']['awg3']
        self.assertEqual(entry['peers'], 2)

    def test_health_keeps_peer_count(self):
        node = self.data()['servers'][0]
        self.plugin.set_health(node, 'awg3', {'error': '', 'peers': 4})
        entry = self.plugin.health_for(node)['protocols']['awg3']
        self.assertEqual(entry['peers'], 4)
        self.plugin.set_health(node, 'awg3',
                               {'error': '', 'peers': ['10.8.1.2', '10.8.1.3']})
        entry = self.plugin.health_for(node)['protocols']['awg3']
        self.assertEqual(entry['peers'], 2)
        self.plugin.set_health(node, 'awg3', {'error': '', 'peers': True})
        self.assertNotIn('peers',
                         self.plugin.health_for(node)['protocols']['awg3'])


class MarksTests(Base):
    def test_prune_uses_per_server_ttl_and_keeps_unknown_branches(self):
        # Недоступный стор не должен означать «плагина нет»: чужие ветки
        # журнала не удаляются, чистит только uninstall.
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard(),
                            settings={'marks_ttl_days': 7})
        old = 1760000000
        now = int(__import__('time').time())
        journal = torrent_events.empty()
        torrent_events.record(journal, 'srv-uid', 'awg3', '10.0.0.5',
                              [{'ts': old, 'sig': 'handshake', 'count': 2}])
        torrent_events.record(journal, 'gone-uid', 'awg3', '10.0.0.6',
                              [{'ts': now, 'sig': 'handshake', 'count': 1}])
        torrent_events.save(self.plugin.events_file, journal)
        self.plugin.prune(self.data()['servers'])
        saved = torrent_events.load(self.plugin.events_file)
        self.assertNotIn('srv-uid', saved['servers'])
        self.assertIn('gone-uid', saved['servers'])

    def test_flags_only_for_installed_servers(self):
        proto = {'installed': True}
        node = self.data()['servers'][0]
        other = server(uid='other-uid', protocols=dict(proto))
        journal = torrent_events.empty()
        for key in ('srv-uid', 'other-uid'):
            torrent_events.record(journal, key, 'awg3', '10.0.0.5',
                                  [{'ts': 1760000000, 'sig': 'handshake',
                                    'count': 1}])
        torrent_events.save(self.plugin.events_file, journal)
        self.plugin.install(node, lambda proto_name: FakeGuard())
        flags = self.plugin.flags([node, other])
        self.assertEqual(list(flags), ['0'])

    def test_record_events_maps_peer_ip_to_client(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        added = self.plugin.record_events(
            node, 'awg3',
            [{'ts': 1760000100, 'sig': 'handshake', 'count': 3,
              'ip': '10.8.1.17'}],
            lambda: [{'clientId': 'peer-1',
                      'userData': {'clientIp': '10.8.1.17'}}])
        self.assertEqual(added, 1)
        buckets = self.plugin.peer_buckets(node, 'awg3')
        self.assertEqual(buckets['10.8.1.17']['client_id'], 'peer-1')


class RouteTests(Base):
    def test_state_is_available_without_installation_and_mutations_are_409(self):
        with TestClient(panel.app) as client:
            self.login(client)
            state = client.get('/api/servers/0/plugins/torrent_guard')
            self.assertEqual(state.status_code, 200, state.text)
            self.assertFalse(state.json()['installed'])
            for path in ('/enabled', '/mode', '/settings', '/refresh',
                         '/marks/clear'):
                response = client.post('/api/servers/0/plugins/torrent_guard' + path,
                                       json={'enabled': True, 'protocol': 'awg3',
                                             'mode': 'on', 'settings': {}})
                self.assertEqual(response.status_code, 409, path)
                self.assertEqual(response.json()['code'], 'plugin_not_installed')

    def test_install_and_uninstall_through_api(self):
        guard = FakeGuard()
        manager = mock.Mock()
        manager.torrent_guard = lambda proto: guard
        ssh = mock.Mock()
        with mock.patch.object(panel, 'get_ssh', return_value=ssh), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            with TestClient(panel.app) as client:
                self.login(client)
                installed = client.post(
                    '/api/servers/0/plugins/torrent_guard/install',
                    json={'settings': {}})
                self.assertEqual(installed.status_code, 200, installed.text)
                self.assertTrue(installed.json()['installed'])
                state = client.get('/api/servers/0/plugins/torrent_guard').json()
                # Установка ничего не блокирует: контроль включается отдельно.
                self.assertEqual(state['state'], 'off')
                enabled = client.post(
                    '/api/servers/0/plugins/torrent_guard/enabled',
                    json={'enabled': True})
                self.assertEqual(enabled.status_code, 200, enabled.text)
                self.assertEqual(enabled.json()['state'], 'on')
                flags = client.get('/api/plugins/torrent_guard/flags')
                self.assertEqual(flags.status_code, 200)
                self.assertEqual(flags.json(), {'flags': {}})
                removed = client.post(
                    '/api/servers/0/plugins/torrent_guard/uninstall', json={})
                self.assertEqual(removed.status_code, 200, removed.text)
                self.assertFalse(removed.json()['installed'])

    def test_install_persists_only_modes_and_keeps_concurrent_writes(self):
        # Регресс: SSH длится минуты, и сохранение старого снимка data.json
        # затирало параллельные изменения. Проверяем, что запись режима идёт
        # в свежий файл, а чужая правка остаётся.
        def slow_run(server, action):
            fresh = self.data()
            fresh['users'].append({'id': 'late-id', 'username': 'late',
                                   'password_hash': 'x', 'role': 'user',
                                   'enabled': True})
            self.write_data(fresh)
            return {'changes': {'awg3': 'on'}, 'errors': []}

        with mock.patch.object(panel, '_torrent_plugin_run', slow_run),                 TestClient(panel.app) as client:
            self.login(client)
            response = client.post('/api/servers/0/plugins/torrent_guard/install',
                                   json={'settings': {}})
        self.assertEqual(response.status_code, 200, response.text)
        saved = self.data()
        self.assertIn('late-id', [u['id'] for u in saved['users']])
        self.assertEqual(saved['servers'][0]['protocols']['awg3']['torrent_guard'],
                         'on')

    def test_mode_and_settings_validate_before_ssh(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())

        def boom(server):
            raise AssertionError('SSH must not be opened before validation')

        with mock.patch.object(panel, '_torrent_plugin_guards', boom),                 TestClient(panel.app) as client:
            self.login(client)
            bad_mode = client.post('/api/servers/0/plugins/torrent_guard/mode',
                                   json={'protocol': 'awg3', 'mode': 'disable'})
            self.assertEqual(bad_mode.status_code, 400, bad_mode.text)
            self.assertEqual(bad_mode.json()['code'], 'invalid_mode')
            bad_proto = client.post('/api/servers/0/plugins/torrent_guard/mode',
                                    json={'protocol': 'xray', 'mode': 'on'})
            self.assertEqual(bad_proto.status_code, 400, bad_proto.text)
            bad_setting = client.post(
                '/api/servers/0/plugins/torrent_guard/settings',
                json={'settings': {'marks_ttl_days': 1}})
            self.assertEqual(bad_setting.status_code, 400, bad_setting.text)

    def test_core_torrent_endpoints_are_gone(self):
        with TestClient(panel.app) as client:
            self.login(client)
            for path in ('/api/servers/torrent_flags',
                         '/api/servers/0/torrent_guard'):
                self.assertEqual(client.get(path).status_code, 404, path)
            for path in ('/api/servers/0/connections/torrent_guard',
                         '/api/servers/0/connections/torrent_clear'):
                self.assertEqual(client.post(path, json={}).status_code, 404,
                                 path)

    def test_connections_has_no_torrent_fields_without_plugin(self):
        manager = mock.Mock()
        manager.get_clients = mock.Mock(return_value=[
            {'clientId': 'c1', 'userData': {'clientIp': '10.8.1.17'}}])
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            with TestClient(panel.app) as client:
                self.login(client)
                payload = client.get('/api/servers/0/connections?protocol=awg3').json()
        self.assertIn('clients', payload)
        for key in ('torrent_guard', 'torrent_guard_health'):
            self.assertNotIn(key, payload)
        for client_row in payload['clients']:
            for key in ('torrentEvents', 'torrentIp', 'torrentGuard'):
                self.assertNotIn(key, client_row)


class CollectorTests(Base):
    def test_collector_keeps_flood_and_skips_guard_without_plugin(self):
        node = self.data()['servers'][0]
        manager = mock.Mock()
        manager.collect_conn_stats = mock.Mock()
        guard = FakeGuard()
        manager.torrent_guard = lambda proto: guard
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            panel._conn_monitor_once({'servers': [node]})
        manager.collect_conn_stats.assert_called_once_with('awg3')
        self.assertEqual(guard.applied, [])

    def test_collector_runs_guard_when_installed(self):
        node = self.data()['servers'][0]
        self.plugin.install(node, lambda proto: FakeGuard())
        manager = mock.Mock()
        manager.collect_conn_stats = mock.Mock()
        guard = FakeGuard()
        manager.torrent_guard = lambda proto: guard
        with mock.patch.object(panel, 'get_ssh', return_value=mock.Mock()), \
                mock.patch.object(panel, 'get_protocol_manager', return_value=manager):
            panel._conn_monitor_once({'servers': [node]})
        manager.collect_conn_stats.assert_called_once_with('awg3')
        self.assertEqual(self.plugin.health_for(node)['state'], 'ok')


class TemplateTests(unittest.TestCase):
    def read(self, name):
        return (ROOT / name).read_text(encoding='utf-8')

    def test_server_page_renders_plugin_only_when_installed(self):
        page = self.read('templates/server.html')
        self.assertIn('{% if torrent_plugin and torrent_plugin.installed %}', page)
        self.assertIn("{% include '_torrent_plugin_modal.html' %}", page)
        self.assertNotIn('torrentGuardSelect', page)
        self.assertNotIn('torrentGuardHealth', page)
        self.assertNotIn('/api/servers/${SERVER_ID}/connections/torrent_guard', page)
        self.assertNotIn("clearTorrentEvents", page)
        # Отдельной кнопки в шапке нет: плагин выглядит как инстанс в сетке.
        self.assertNotIn('id="torrentPluginBtn"', page)
        self.assertIn('id="torrent-plugin-card"', page)
        self.assertIn('id="torrentPluginCardStatus"', page)
        # Статус плитки рисуется Jinja при загрузке, а не только из JS.
        self.assertIn("_('tp_state_' ~ (torrent_plugin.state or 'not_installed'))", page)
        self.assertIn('window.renderTorrentPluginCard = renderTorrentPluginCard', page)
        # В магазине установленное приложение — «Установлен», без «Открыть».
        self.assertIn("const action = installed ? 'disabled' : 'onclick=\"installTorrentPlugin()\"';", page)
        self.assertIn("const buttonLabel = installed ? _('installed') : _('tp_install');", page)

    def test_installed_apps_show_installed_instead_of_open(self):
        # Правки владельца: у установленного приложения кнопка «Установлен»,
        # а не «Открыть» — «Открыть» закрывала модалку и скроллила наверх.
        page = self.read('templates/server.html')
        self.assertIn("isSmart ? (installed ? _('installed') : _('smartroute_open'))", page)
        self.assertIn("const action = installed ? 'disabled' : 'onclick=\"installTorrentPlugin()\"';", page)
        # Диагностика (Speedtest / Ping-MTR) есть только в прод-дереве: в
        # upstream-шаблоне карточек `diagnostics` нет, поэтому проверяем по
        # файлу прода отдельно (см. HANDOFF, раздел про выкладку).
        css = self.read('static/css/style.css')
        self.assertNotIn('.tp-header', css)

    def test_tile_is_last_and_has_controls(self):
        page = self.read('templates/server.html')
        # Плитка плагина — после последнего инстанса (HAProxy) в сетке.
        self.assertLess(page.index('id="proto-haproxy"'), page.index('id="torrent-plugin-card"'))
        self.assertIn("const pluginCard = document.getElementById('torrent-plugin-card');", page)
        for marker in ('id="torrentPluginOpen"', 'id="torrentPluginStart"',
                       'id="torrentPluginStop"', 'id="torrentPluginUninstall"'):
            self.assertIn(marker, page)
        self.assertIn("TorrentPlugin.setEnabled(true)", page)
        self.assertIn("TorrentPlugin.setEnabled(false)", page)
        self.assertIn("TorrentPlugin.uninstall()", page)

    def test_plugin_script_reads_server_id_lazily(self):
        js = self.read('static/js/torrent-plugin.js')
        self.assertIn('function apiBase()', js)
        self.assertNotIn("const BASE = '/api/servers/' + SERVER_ID", js)
        self.assertIn("_('tp_degraded_title')", self.read('templates/server.html'))
        self.assertIn('setEnabled, uninstall', js)

    def test_dashboard_renders_alerts_only_when_installed(self):
        page = self.read('templates/index.html')
        self.assertIn('{% if torrent_plugin_servers and torrent_plugin_servers[loop.index0] %}', page)
        self.assertIn('{% if torrent_plugin_any %}', page)
        self.assertIn('torrent-plugin-flags.js', page)
        self.assertNotIn("'/api/servers/torrent_flags'", page)

    def test_new_markup_has_no_inline_styles_or_emoji(self):
        for name in ('templates/_torrent_plugin_modal.html',
                     'static/js/torrent-plugin.js',
                     'static/js/torrent-plugin-flags.js'):
            text = self.read(name)
            self.assertNotIn('style="', text, name)
            self.assertNotRegex(text, r'[\U0001F300-\U0001FAFF\u2600-\u27BF]', name)
        markup = self.read('templates/_torrent_plugin_modal.html')
        self.assertIn("ui_icon('shield'", markup)
        self.assertIn('window.TORRENT_PLUGIN_STATE', markup)

    def test_install_shim_reports_partial_errors(self):
        page = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')
        self.assertIn('res.errors', page)
        self.assertIn('tp_install_done', page)

    def test_plugin_modal_template_renders(self):
        from jinja2 import Environment, FileSystemLoader
        strings = json.loads((ROOT / 'translations' / 'ru.json').read_text(encoding='utf-8'))
        env = Environment(loader=FileSystemLoader(str(ROOT / 'templates')),
                          autoescape=True)
        html = env.get_template('_torrent_plugin_modal.html').render(
            static_v='synthetic', _=lambda key: strings.get(key, key),
            torrent_plugin={'installed': True, 'state': 'on', 'modes': {},
                            'settings': {}, 'health': {}, 'protocols': []})
        self.assertIn('id="torrentPluginModal"', html)
        self.assertIn('/static/js/torrent-plugin.js?v=synthetic', html)
        self.assertIn('window.TORRENT_PLUGIN_STATE', html)
        self.assertNotIn('style="', html)

    def test_js_harness_exists_and_passes(self):
        import subprocess
        harness = ROOT / 'tests' / 'js' / 'torrent_plugin.js'
        self.assertTrue(harness.exists())
        result = subprocess.run(['node', str(harness)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
