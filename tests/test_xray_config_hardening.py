"""Generated-config hardening: sniffing on the vless inbound and IPv4-pinned
freedom egress, applied to fresh installs and migrated into older configs."""
import json
import unittest
from unittest.mock import Mock

from managers.xray_manager import XrayManager


OLD_CONFIG = {
    'inbounds': [{
        'protocol': 'vless',
        'tag': 'proxy',
        'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {'network': 'tcp', 'security': 'reality',
                           'realitySettings': {'dest': 'yahoo.com:443'}},
    }],
    'outbounds': [{'protocol': 'freedom'}],
}

SNIFFING = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}


def make_upgrade_manager(config):
    manager = XrayManager(Mock())
    manager._get_server_json = lambda: config
    written = []
    manager._write_server_json = lambda data, restart=True: written.append((data, restart))
    manager.written = written
    return manager


class InstallHardeningTests(unittest.TestCase):
    def test_install_writes_sniffing_and_ipv4_egress(self):
        manager = XrayManager(Mock())
        manager.check_docker_installed = lambda: True
        manager.check_protocol_installed = lambda: False
        manager._config_dir = lambda: '/opt/amnezia/xray'
        manager.ssh.run_sudo_command = lambda *a, **k: ('', '', 0)
        manager.ssh.run_command = lambda *a, **k: ('', '', 0)
        uploads = []
        manager.ssh.upload_file_sudo = lambda content, path: uploads.append((content, path))

        manager.install_protocol(port=443)

        raw = next(content for content, path in uploads if path.endswith('/server.json'))
        server_json = json.loads(raw)
        inbound = next(ib for ib in server_json['inbounds'] if ib['protocol'] == 'vless')
        self.assertEqual(inbound['sniffing'], SNIFFING)
        freedom = next(ob for ob in server_json['outbounds'] if ob['protocol'] == 'freedom')
        self.assertEqual(freedom['domainStrategy'], 'UseIPv4')
        api_inbound = next(ib for ib in server_json['inbounds'] if ib.get('tag') == 'api')
        self.assertNotIn('sniffing', api_inbound)


class UpgradeHardeningTests(unittest.TestCase):
    def test_upgrade_fills_sniffing_and_ipv4_egress_into_old_configs(self):
        config = json.loads(json.dumps(OLD_CONFIG))
        manager = make_upgrade_manager(config)

        dirty = manager._upgrade_config_for_stats(config, restart=False)

        inbound = next(ib for ib in config['inbounds'] if ib['protocol'] == 'vless')
        self.assertEqual(inbound['sniffing'], SNIFFING)
        self.assertEqual(config['outbounds'][0]['domainStrategy'], 'UseIPv4')
        self.assertTrue(dirty)
        self.assertEqual(manager.written, [(config, False)])

    def test_upgrade_is_idempotent(self):
        config = json.loads(json.dumps(OLD_CONFIG))
        manager = make_upgrade_manager(config)
        manager._upgrade_config_for_stats(config, restart=False)
        manager.written.clear()

        dirty = manager._upgrade_config_for_stats(config, restart=False)

        self.assertFalse(dirty)
        self.assertEqual(manager.written, [])

    def test_upgrade_respects_explicit_user_choices(self):
        config = json.loads(json.dumps(OLD_CONFIG))
        config['inbounds'][0]['sniffing'] = {'enabled': False}
        config['outbounds'][0]['domainStrategy'] = 'UseIPv6'
        manager = make_upgrade_manager(config)

        manager._upgrade_config_for_stats(config, restart=False)

        self.assertEqual(config['inbounds'][0]['sniffing'], {'enabled': False})
        self.assertEqual(config['outbounds'][0]['domainStrategy'], 'UseIPv6')


if __name__ == '__main__':
    unittest.main()
