"""Security guards for the NGINX marketplace app.

Both CVE-2026-123633 (HTTP/2 connection use-after-free) and CVE-2026-123007
(HTTP/2 send_window integer underflow) are unauthenticated RCEs that require
HTTP/2; the plugin must never ship a config that enables it and must never
install an affected build.
"""

import unittest

from managers.nginx_manager import NginxManager


class FakeSSH:
    def __init__(self, files=None, outputs=None):
        self.files = dict(files or {})
        self.outputs = dict(outputs or {})
        self.commands = []

    def run_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        for needle, result in self.outputs.items():
            if needle in cmd:
                return result
        return '', '', 0

    def run_sudo_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        for needle, result in self.outputs.items():
            if needle in cmd:
                return result
        if cmd.startswith('cat '):
            path = cmd.split('cat ', 1)[1].split(' ', 1)[0].strip("'\"")
            if path in self.files:
                return self.files[path], '', 0
            return '', '', 1
        return '', '', 0

    def upload_file_sudo(self, content, path):
        self.commands.append('upload %s' % path)
        self.files[path] = content
        return True

    def docker_container_state(self, name):
        return (True, True)


class ImagePinTests(unittest.TestCase):
    def test_image_is_pinned_to_a_fixed_release(self):
        image = NginxManager.IMAGE_NAME
        self.assertNotEqual(image, 'nginx:alpine')
        self.assertTrue(image.startswith('nginx:1.30.7'), image)
        version = tuple(int(p) for p in image.split(':')[1].split('-')[0].split('.'))
        self.assertTrue(NginxManager.is_http2_fixed(version))
        self.assertGreater(version, NginxManager.HTTP2_FIRST_AFFECTED_VERSION)

    def test_mainline_1318_is_still_affected(self):
        self.assertFalse(NginxManager.is_http2_fixed((1, 31, 8)))
        self.assertTrue(NginxManager.is_http2_fixed((1, 31, 9)))
        self.assertFalse(NginxManager.is_http2_fixed((1, 30, 6)))
        self.assertFalse(NginxManager.is_http2_fixed(None))


class GeneratedConfigTests(unittest.TestCase):
    def setUp(self):
        self.manager = NginxManager(FakeSSH())

    def test_ssl_config_has_no_http2(self):
        config = self.manager._build_ssl_config('example.com', 443)
        self.assertIn('listen 443 ssl;', config)
        self.assertNotIn('http2', config)

    def test_initial_config_has_no_http2(self):
        self.assertNotIn('http2', self.manager._build_initial_config('example.com'))

    def test_install_writes_configs_without_http2(self):
        ssh = FakeSSH(outputs={
            'docker --version': ('Docker version 27.0.0', '', 0),
            'systemctl is-active docker': ('active', '', 0),
            'exec amnezia-nginx nginx -v': ('', "nginx version: nginx/1.30.7", 1),
        })
        manager = NginxManager(ssh)
        result = manager.install_protocol(domain='example.com', email='a@b.co')
        self.assertEqual(result['status'], 'success', result)
        conf = ssh.files[manager.NGINX_CONF_PATH]
        self.assertNotIn('http2', conf)
        self.assertIn('listen 443 ssl;', conf)


class StripHttp2Tests(unittest.TestCase):
    def test_listen_token_is_removed(self):
        text, changed = NginxManager.strip_http2(
            'server {\n  listen 443 ssl http2;\n}\n')
        self.assertTrue(changed)
        self.assertIn('listen 443 ssl;', text)
        self.assertNotIn('http2', text)

    def test_directive_is_removed(self):
        text, changed = NginxManager.strip_http2('http2 on;\nserver { listen 443 ssl; }\n')
        self.assertTrue(changed)
        self.assertNotIn('http2 on', text)

    def test_http2_off_is_dropped_without_breaking_config(self):
        text, changed = NginxManager.strip_http2('server {\n  http2 off;\n}\n')
        self.assertTrue(changed)
        self.assertNotIn('http2', text)
        self.assertIn('server {', text)

    def test_clean_config_is_unchanged(self):
        source = 'server {\n  listen 443 ssl;\n}\n'
        text, changed = NginxManager.strip_http2(source)
        self.assertFalse(changed)
        self.assertEqual(text, source)

    def test_comments_are_kept(self):
        source = '# http2 is disabled on purpose\nserver { listen 443 ssl; }\n'
        text, changed = NginxManager.strip_http2(source)
        self.assertFalse(changed)
        self.assertEqual(text, source)

    def test_save_rejects_user_supplied_http2(self):
        ssh = FakeSSH(files={NginxManager.NGINX_CONF_PATH: 'server { listen 443 ssl; }\n'})
        manager = NginxManager(ssh)
        manager.save_server_config(
            config_text='server {\n  listen 443 ssl http2;\n  http2 on;\n}\n')
        saved = ssh.files[manager.NGINX_CONF_PATH]
        self.assertNotIn('http2', saved)
        self.assertIn('listen 443 ssl;', saved)


class SecurityStateTests(unittest.TestCase):
    def setUp(self):
        self.manager = NginxManager(FakeSSH())

    def test_vulnerable_version_with_http2_is_flagged(self):
        state = self.manager.security_state(
            'listen 443 ssl http2;', (1, 31, 8))
        self.assertTrue(state['http2_enabled'])
        self.assertFalse(state['http2_fixed'])
        self.assertEqual(state['nginx_version'], '1.31.8')
        self.assertIn('http2_enabled', state['security_warnings'])
        self.assertIn('http2_vulnerable_version', state['security_warnings'])

    def test_clean_config_on_fixed_version_has_no_warnings(self):
        state = self.manager.security_state('listen 443 ssl;', (1, 30, 7))
        self.assertFalse(state['http2_enabled'])
        self.assertTrue(state['http2_fixed'])
        self.assertEqual(state['security_warnings'], [])

    def test_mainline_before_the_fix_branch_is_not_flagged_as_fixed(self):
        state = self.manager.security_state('listen 443 ssl;', (1, 31, 8))
        self.assertFalse(state['http2_fixed'])
        self.assertEqual(state['security_warnings'], ['http2_vulnerable_version'])

    def test_version_below_first_affected_is_not_flagged(self):
        state = self.manager.security_state('listen 443 ssl;', (1, 18, 0))
        self.assertEqual(state['security_warnings'], [])

    def test_http2_off_directive_is_not_treated_as_enabled(self):
        self.assertFalse(NginxManager.http2_enabled('http2 off;\nlisten 443 ssl;\n'))

    def test_commented_http2_is_not_treated_as_enabled(self):
        self.assertFalse(NginxManager.http2_enabled('# listen 443 ssl http2;\n'))


class HardenTests(unittest.TestCase):
    def test_harden_rewrites_live_config_and_reloads(self):
        ssh = FakeSSH(files={
            NginxManager.NGINX_CONF_PATH: 'server {\n  listen 443 ssl http2;\n}\n',
        })
        manager = NginxManager(ssh)
        result = manager.harden_http2()
        self.assertTrue(result['changed'])
        self.assertNotIn('http2', ssh.files[manager.NGINX_CONF_PATH])
        self.assertTrue(any('nginx -s reload' in cmd for cmd in ssh.commands))

    def test_harden_is_a_noop_on_a_clean_config(self):
        ssh = FakeSSH(files={
            NginxManager.NGINX_CONF_PATH: 'server {\n  listen 443 ssl;\n}\n',
        })
        manager = NginxManager(ssh)
        result = manager.harden_http2()
        self.assertFalse(result['changed'])
        self.assertFalse(any('nginx -s reload' in cmd for cmd in ssh.commands))

    def test_harden_rolls_back_on_invalid_config(self):
        ssh = FakeSSH(
            files={NginxManager.NGINX_CONF_PATH: 'server {\n listen 443 ssl http2;\n}\n'},
            outputs={'nginx -t': ('', 'emerg: bad', 1)},
        )
        manager = NginxManager(ssh)
        result = manager.harden_http2()
        self.assertEqual(result['status'], 'error')
        self.assertIn('http2', ssh.files[manager.NGINX_CONF_PATH])


if __name__ == '__main__':
    unittest.main()
