"""Штатная смена набора обфускации транзита (2.0 <-> 3.1) без потери пиров."""

import asyncio
import copy
import unittest

from managers.awg_manager import (
    AWGManager,
    generate_transit_params,
    is_awg31_params,
    rewrite_transit_conf,
    transit_mtu,
)
from managers.exit_manager import ExitManager
from exit_link_service import ExitLinkService


EXIT_CONF_20 = """[Interface]
# Managed by Amnezia Web Panel - exit node transit endpoint
# Subnet = 10.9.0.0/24
# Obfuscation = on
# ProtocolVersion = 2.0
PrivateKey = EXITPRIVATEKEY=
Address = 10.9.0.1/24
ListenPort = 55520
MTU = 1420
Jc = 12
Jmin = 18
Jmax = 40
S1 = 40
S2 = 31
H1 = 506974031
H2 = 1102047096
H3 = 2738397746
H4 = 3487245949

[Peer]
# peerId = entry-uid:awg3
PublicKey = ENTRYKEY=
PresharedKey = PSK=
AllowedIPs = 10.9.0.2/32
"""

ENTRY_CONF_20 = """[Interface]
# Managed by Amnezia Web Panel - exit node link
# ExitUid = exit-a
# Obfuscation = on
# ProtocolVersion = 2.0
PrivateKey = ENTRYPRIVATEKEY=
Address = 10.9.0.2/24
MTU = 1420
Table = off
Jc = 12
Jmin = 13
Jmax = 47
S1 = 30
S2 = 21
H1 = 1068291849
H2 = 4098549485
H3 = 3903281421
H4 = 3980167000

[Peer]
PublicKey = EXITPUB=
PresharedKey = PSK=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.5:55520
PersistentKeepalive = 25
"""


def _peer_part(text):
    return text.split('[Peer]', 1)[1]


class RewriteTransitConfTests(unittest.TestCase):
    def test_upgrade_keeps_key_peers_and_updates_mtu(self):
        params = generate_transit_params(awg3=True)
        out = rewrite_transit_conf(EXIT_CONF_20, params)
        self.assertTrue(is_awg31_params(params))
        self.assertIn('PrivateKey = EXITPRIVATEKEY=', out)
        self.assertIn('ListenPort = 55520', out)
        self.assertIn('MTU = 1400', out)
        self.assertNotIn('MTU = 1420', out)
        self.assertIn('# ProtocolVersion = 3.1', out)
        self.assertIn('HeaderProtectionKey', out)
        self.assertIn('RandomTrailers = on', out)
        self.assertIn('S3 = 12', out)
        self.assertNotIn('S3 = 12\nS3', out)
        self.assertEqual(_peer_part(out), _peer_part(EXIT_CONF_20))

    def test_downgrade_drops_31_keys_only(self):
        up = rewrite_transit_conf(EXIT_CONF_20, generate_transit_params(awg3=True))
        down = rewrite_transit_conf(up, generate_transit_params(awg3=False))
        for key in ('HeaderProtectionKey', 'ContentPaddingAddition',
                    'RandomTrailers', 'DisableCookies', 'RekeyAfterTime',
                    'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
                    'MaxHandshakeAttempts', 'S3 =', 'S4 =', 'I1 ='):
            self.assertNotIn(key, down, key)
        self.assertIn('MTU = 1420', down)
        self.assertIn('# ProtocolVersion = 2.0', down)
        self.assertEqual(_peer_part(down), _peer_part(EXIT_CONF_20))

    def test_entry_conf_keeps_table_and_endpoint(self):
        out = rewrite_transit_conf(ENTRY_CONF_20, generate_transit_params(awg3=True))
        self.assertIn('Table = off', out)
        self.assertIn('Endpoint = 203.0.113.5:55520', out)
        self.assertIn('PersistentKeepalive = 25', out)
        self.assertIn('MTU = 1400', out)
        self.assertEqual(_peer_part(out), _peer_part(ENTRY_CONF_20))

    def test_plain_wireguard_renders_no_params(self):
        out = rewrite_transit_conf(EXIT_CONF_20, None)
        self.assertNotIn('Jc =', out)
        self.assertIn('MTU = 1420', out)
        self.assertIn('# ProtocolVersion = wireguard', out)
        self.assertEqual(_peer_part(out), _peer_part(EXIT_CONF_20))

    def test_conf_without_address_is_rejected(self):
        with self.assertRaises(RuntimeError):
            rewrite_transit_conf('[Interface]\nPrivateKey = x\n', {})


class FakeSSH:
    def __init__(self, conf):
        self.conf = conf
        self.uploads = {}
        self.commands = []
        self.sync_code = (0, '', 0)

    def run_sudo_command(self, command, timeout=None):
        self.commands.append(command)
        if 'cat /opt' in command or 'cat ' in command and 'exit0.conf' in command:
            return self.conf, '', 0
        if command.startswith('docker exec') and 'syncconf' in command:
            self.commands.append('SYNCCONF')
            return self.sync_code
        return '', '', 0

    def run_command(self, command, timeout=None):
        self.commands.append(command)
        return '', '', 0

    def upload_file(self, content, path):
        self.uploads[path] = content

    def upload_file_sudo(self, content, path):
        self.uploads[path] = content


class ExitUpdateParamsTests(unittest.TestCase):
    def _manager(self, conf, sync_code=(0, '', 0)):
        ssh = FakeSSH(conf)
        ssh.sync_code = sync_code
        mgr = AWGManager(ssh)
        mgr._container_name = lambda protocol_type: 'amnezia-awg3'
        mgr._quick_binary = lambda protocol_type: 'awg-quick'
        mgr._wg_binary = lambda protocol_type: 'awg'
        mgr.exit_link_backend = lambda protocol_type: 'kernel'
        calls = []
        mgr._exit_apply = lambda protocol_type, teardown=False: calls.append(protocol_type)
        mgr.recreated = calls
        return mgr, ssh

    def test_writes_new_conf_and_applies_with_syncconf(self):
        mgr, ssh = self._manager(ENTRY_CONF_20)
        result = mgr.exit_update_params('awg3', generate_transit_params(awg3=True))
        self.assertEqual(result['applied'], 'syncconf')
        written = ssh.uploads['/tmp/_amnz_exit0.conf']
        self.assertIn('HeaderProtectionKey', written)
        self.assertIn('MTU = 1400', written)
        self.assertEqual(_peer_part(written), _peer_part(ENTRY_CONF_20))
        self.assertIn('SYNCCONF', ssh.commands)
        self.assertEqual(mgr.recreated, [])

    def test_kernel_refusal_falls_back_to_recreate(self):
        mgr, _ = self._manager(ENTRY_CONF_20, sync_code=(1, 'Invalid argument', 1))
        result = mgr.exit_update_params('awg3', generate_transit_params(awg3=False))
        self.assertEqual(result['applied'], 'recreate')
        self.assertEqual(mgr.recreated, ['awg3'])

    def test_missing_link_file_raises(self):
        ssh = FakeSSH('')
        mgr = AWGManager(ssh)
        mgr._container_name = lambda p: 'amnezia-awg3'
        with self.assertRaises(RuntimeError):
            mgr.exit_update_params('awg3', {})


class ApplyTransitParamsTests(unittest.TestCase):
    def _manager(self, module='3.1.20260906', sync_error=None):
        mgr = ExitManager.__new__(ExitManager)
        mgr.PROTOCOL = 'exit'
        mgr.written = []
        mgr.synced = 0
        mgr.restarted = 0
        mgr.get_info = lambda: {'port': '55520', 'subnet': '10.9.0.0/24',
                                'awg_params': generate_transit_params(awg3=False),
                                'mtu': 1420, 'protocol_version': '2.0'}
        mgr._configure_exit_container = lambda port, net, params: mgr.written.append((port, str(net), params))
        def sync(protocol_type):
            mgr.synced += 1
            if sync_error:
                raise RuntimeError(sync_error)
            return ''
        mgr._sync_server_config = sync
        mgr._restart_container = lambda p: setattr(mgr, 'restarted', mgr.restarted + 1)
        mgr._verify_interface_up = lambda p: None
        mgr._host_awg_module_version = lambda: module
        mgr._module_supports_awg3 = lambda v: str(v).startswith('3.')
        mgr.transit_backend = lambda: 'kernel'
        return mgr

    def test_switch_keeps_peers_via_configure(self):
        mgr = self._manager()
        result = mgr.apply_transit_params(awg3=True)
        self.assertEqual(len(mgr.written), 1)
        port, net, params = mgr.written[0]
        self.assertEqual(port, '55520')
        self.assertEqual(net, '10.9.0.0/24')
        self.assertTrue(is_awg31_params(params))
        self.assertEqual(transit_mtu(params), 1400)
        self.assertEqual(mgr.synced, 1)
        self.assertEqual(mgr.restarted, 0)
        self.assertEqual(result['applied'], 'syncconf')

    def test_old_module_is_refused(self):
        mgr = self._manager(module='2.9.0')
        with self.assertRaises(RuntimeError):
            mgr.apply_transit_params(awg3=True)
        self.assertEqual(mgr.written, [])

    def test_sync_failure_recreates_interface(self):
        mgr = self._manager(sync_error='Unable to modify interface: Invalid argument')
        result = mgr.apply_transit_params(awg3=False)
        self.assertEqual(result['applied'], 'recreate')
        self.assertEqual(mgr.restarted, 1)


class FakeExitMgr:
    def __init__(self):
        self.called_with = []
        self.info = {'awg_params': generate_transit_params(awg3=True), 'mtu': 1400,
                     'protocol_version': '3.1', 'applied': 'syncconf', 'backend': 'kernel'}

    def apply_transit_params(self, awg3):
        self.called_with.append(awg3)
        return dict(self.info)


class FakeEntryMgr:
    def __init__(self):
        self.calls = []

    def exit_update_params(self, protocol, params):
        self.calls.append((protocol, dict(params)))
        return {'applied': 'syncconf', 'backend': 'kernel'}


class SetTransitVersionTests(unittest.TestCase):
    def test_updates_exit_entries_and_records(self):
        data = {
            'servers': [
                {'name': 'Entry', 'uid': 'entry-uid', 'protocols': {
                    'awg3': {'installed': True, 'exit_link': {
                        'exit_uid': 'exit-uid', 'awg_params': {'old': '1'}, 'mtu': 1420,
                        'transit_ip': '10.9.0.2', 'exit_public_key': 'PUB'}}}},
                {'name': 'Exit', 'uid': 'exit-uid', 'protocols': {
                    'exit': {'installed': True, 'port': '55520',
                             'awg_params': {'old': '1'}, 'protocol_version': '2.0'}}},
            ],
            'users': [],
            'user_connections': [],
        }
        state = {'data': copy.deepcopy(data)}
        exit_mgr = FakeExitMgr()
        entry_mgr = FakeEntryMgr()

        async def noop(*a, **kw):
            return None

        svc = ExitLinkService(
            load_data=lambda: copy.deepcopy(state['data']),
            save_data=lambda d: state.update(data=copy.deepcopy(d)),
            data_lock=asyncio.Lock(),
            get_ssh=lambda srv: None,
            awg_manager_factory=lambda host: entry_mgr,
            exit_manager_factory=lambda host: exit_mgr,
            protocol_base=lambda p: p,
            awg_protocols=('awg', 'awg2', 'awg3'),
            protocol_display_name=lambda p, *m: p,
            find_server_by_uid=lambda d, uid: next(
                (i, s) for i, s in enumerate(d['servers']) if s.get('uid') == uid),
        )
        result = asyncio.run(svc.set_transit_version('exit-uid', True))
        self.assertEqual(exit_mgr.called_with, [True])
        self.assertEqual(len(entry_mgr.calls), 1)
        self.assertEqual(entry_mgr.calls[0][0], 'awg3')
        self.assertTrue(is_awg31_params(entry_mgr.calls[0][1]))
        self.assertEqual(result['protocol_version'], '3.1')
        link = state['data']['servers'][0]['protocols']['awg3']['exit_link']
        self.assertEqual(link['mtu'], 1400)
        self.assertTrue(is_awg31_params(link['awg_params']))
        exit_rec = state['data']['servers'][1]['protocols']['exit']
        self.assertEqual(exit_rec['protocol_version'], '3.1')


if __name__ == '__main__':
    unittest.main()


class FakeDowngradeExitMgr:
    def __init__(self):
        self.calls = []
        self.info = {'awg_params': generate_transit_params(awg3=False), 'mtu': 1420,
                     'protocol_version': '2.0', 'applied': 'recreate', 'backend': 'kernel'}

    def apply_transit_params(self, awg3):
        self.calls.append(awg3)
        return dict(self.info)


class DowngradeExitTests(unittest.TestCase):
    """Вход со старым ядром: выход и остальные входы переезжают на 2.0."""

    def test_moves_exit_and_other_entries_to_20(self):
        data = {
            'servers': [
                {'name': 'OldEntry', 'uid': 'old-uid', 'protocols': {
                    'awg3': {'installed': True, 'exit_link': {
                        'exit_uid': 'exit-uid', 'awg_params': {'x': '1'}}}}},
                {'name': 'OtherEntry', 'uid': 'other-uid', 'protocols': {
                    'awg3': {'installed': True, 'exit_link': {
                        'exit_uid': 'exit-uid', 'awg_params': {'x': '1'}, 'mtu': 1400}}}},
                {'name': 'Exit', 'uid': 'exit-uid', 'protocols': {
                    'exit': {'installed': True, 'awg_params': {'x': '1'},
                             'protocol_version': '3.1', 'mtu': '1400'}}},
            ],
            'users': [],
            'user_connections': [],
        }
        state = {'data': copy.deepcopy(data)}
        exit_mgr = FakeDowngradeExitMgr()
        entry_mgrs = {}

        def entry_factory(host):
            return entry_mgrs.setdefault(host, FakeEntryMgr())

        svc = ExitLinkService(
            load_data=lambda: copy.deepcopy(state['data']),
            save_data=lambda d: state.update(data=copy.deepcopy(d)),
            data_lock=asyncio.Lock(),
            get_ssh=lambda srv: None,
            awg_manager_factory=entry_factory,
            exit_manager_factory=lambda host: exit_mgr,
            protocol_base=lambda p: p,
            awg_protocols=('awg', 'awg2', 'awg3'),
            protocol_display_name=lambda p, *m: p,
            find_server_by_uid=lambda d, uid: next(
                (i, s) for i, s in enumerate(d['servers']) if s.get('uid') == uid),
        )
        params = asyncio.run(svc._downgrade_exit('exit-uid', skip=(0, 'awg3')))
        self.assertEqual(exit_mgr.calls, [False])
        self.assertNotIn('header_protection_key', params)
        self.assertIn('junk_packet_count', params)
        # текущий (линкующийся) вход не трогаем, остальные переводим
        self.assertEqual(len(entry_mgrs), 1)
        other = list(entry_mgrs.values())[0]
        self.assertEqual(len(other.calls), 1)
        rec = state['data']['servers'][1]['protocols']['awg3']['exit_link']
        self.assertEqual(rec['protocol_version'], '2.0')
        self.assertEqual(rec['mtu'], 1420)
        exit_rec = state['data']['servers'][2]['protocols']['exit']
        self.assertEqual(exit_rec['protocol_version'], '2.0')
