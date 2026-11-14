"""Tests for the pinned Xray-core version used by new installs."""

import re
import unittest

from managers.xray_manager import XrayManager, XRAY_CORE_VERSION


class FakeSSH:
    """Minimal SSH stub that records uploads and never fails."""

    def __init__(self):
        self.uploads = []
        self.commands = []

    def upload_file_sudo(self, content, remote_path):
        self.uploads.append((content, remote_path))
        return True

    def run_sudo_script(self, script, **kwargs):
        return ("", "", 0)

    def run_sudo_command(self, command, **kwargs):
        self.commands.append(command)
        return ("", "", 0)

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        return ("", "", 0)


class XrayVersionTests(unittest.TestCase):
    def test_version_format(self):
        self.assertRegex(XRAY_CORE_VERSION, r'^v\d+\.\d+\.\d+$')

    def test_version_not_older_than_mptcp_fix(self):
        parsed = tuple(int(p) for p in XRAY_CORE_VERSION.lstrip('v').split('.'))
        self.assertGreaterEqual(parsed, (26, 10, 31))

    def test_dockerfile_uses_arg_and_latest_pin(self):
        mgr = XrayManager.__new__(XrayManager)
        mgr.protocol = 'xray'
        mgr.instance = 1
        mgr.base_protocol = 'xray'
        mgr.container_name = 'amnezia-xray'
        mgr.image_name = 'amneziavpn/amnezia-xray'
        text = mgr._dockerfile_content()
        self.assertIn('ARG XRAY_RELEASE="v26.10.31"', text)
        self.assertIn('releases/download/${XRAY_RELEASE}/Xray-linux-64.zip', text)
        self.assertNotIn('v26.3.27', text)

    def test_install_uploads_dockerfile_with_new_version(self):
        ssh = FakeSSH()
        mgr = XrayManager(ssh)
        mgr.install_protocol(port=443)
        dockerfile_uploads = [
            content for content, path in ssh.uploads if str(path).endswith('/Dockerfile')
        ]
        self.assertTrue(dockerfile_uploads, "Dockerfile was not uploaded")
        self.assertTrue(
            any(XRAY_CORE_VERSION in content for content in dockerfile_uploads),
            "Uploaded Dockerfile does not pin XRAY_CORE_VERSION",
        )

    def test_second_instance_uses_its_own_config_dir(self):
        ssh = FakeSSH()
        mgr = XrayManager(ssh, 'xray__2')
        mgr.install_protocol(port=443)

        uploaded_paths = [path for _, path in ssh.uploads]
        for name in ('xray_private.key', 'xray_public.key', 'xray_short_id.key',
                     'xray_uuid.key', 'clientsTable', 'server.json'):
            self.assertIn('/opt/amnezia/xray-2/' + name, uploaded_paths, name)
            self.assertNotIn('/opt/amnezia/xray/' + name, uploaded_paths, name)
        run = [c for c in ssh.commands if c.startswith('docker run -d')][0]
        self.assertIn('-v /opt/amnezia/xray-2:/opt/amnezia/xray-2', run)


if __name__ == '__main__':
    unittest.main()
