"""Console help for a host-key pin the panel deliberately refuses to repair.

Two guarantees are checked here:
1. `managers/ssh_trust.remediation()` builds copy-ready commands from the real
   endpoint and from this installation's paths (any host, any port, any dir).
2. A changed key carries those commands in the API payload, and the panel's
   refusal to overwrite a system pin is reported with a stable error code.
"""
import base64
import os
import shutil
import tempfile
import unittest
from unittest import mock

import paramiko

from managers import ssh_trust


def _key(seed):
    """Deterministic-ish host key; only its public material is compared."""
    key = paramiko.ECDSAKey.generate()
    return key


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.panel_file = os.path.join(self.tmp, 'data dir', 'ssh_known_hosts')
        patcher = mock.patch.object(ssh_trust, 'trust_path', return_value=self.panel_file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_commands_use_endpoint_and_resolved_paths(self):
        import shlex
        result = ssh_trust.remediation({'host': '192.0.2.10', 'ssh_port': 22})
        self.assertEqual(result['endpoint'], '192.0.2.10')
        self.assertEqual(
            result['remove_system'],
            "ssh-keygen -R 192.0.2.10 -f %s"
            % shlex.quote(ssh_trust.system_trust_path()))
        self.assertEqual(result['panel_file'], self.panel_file)
        self.assertTrue(result['panel_host'])
        self.assertEqual(result['service_user'], __import__('getpass').getuser())
        # `ssh-keygen -l -f` accepts exactly one file, so the hint must loop
        # over the glob instead of passing many arguments.
        self.assertIn("ssh_host_*_key.pub", result['verify_command'])
        self.assertIn('-exec ssh-keygen -lf {}', result['verify_command'])

    def test_non_default_port_uses_bracketed_name(self):
        result = ssh_trust.remediation({'host': '192.0.2.10', 'ssh_port': 2222})
        self.assertEqual(result['endpoint'], '[192.0.2.10]:2222')
        self.assertIn("'[192.0.2.10]:2222'", result['remove_system'])

    def test_paths_with_spaces_are_shell_quoted(self):
        result = ssh_trust.remediation({'host': '192.0.2.10', 'ssh_port': 22})
        self.assertIn("'%s'" % self.panel_file, result['remove_panel'])

    def test_readonly_panel_file_adds_chmod_hint(self):
        os.makedirs(os.path.dirname(self.panel_file))
        with open(self.panel_file, 'w', encoding='utf-8') as handle:
            handle.write('')
        os.chmod(self.panel_file, 0o444)
        self.addCleanup(os.chmod, self.panel_file, 0o644)
        result = ssh_trust.remediation({'host': '192.0.2.10', 'ssh_port': 22},
                                       'trust_readonly')
        self.assertTrue(result['panel_readonly'])
        self.assertTrue(result['chmod_panel'].startswith('chmod u+w '))

    def test_command_generation_survives_missing_identity(self):
        # getpass/socket can fail in slim containers; a hint must not 500.
        with mock.patch('getpass.getuser', side_effect=OSError('no uid')), \
                mock.patch('socket.gethostname', side_effect=OSError('no name')):
            result = ssh_trust.remediation({'host': '192.0.2.10', 'ssh_port': 22})
        self.assertEqual(result['service_user'], 'root')
        self.assertEqual(result['panel_host'], 'the panel host')

    def test_rejects_invalid_host_before_building_commands(self):
        with self.assertRaises(ValueError):
            ssh_trust.remediation({'host': 'bad host; rm -rf /', 'ssh_port': 22})


class InspectRemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.object(
            ssh_trust, 'trust_path',
            return_value=os.path.join(self.tmp, 'ssh_known_hosts'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.live, self.stale = _key(1), _key(2)
        self.server = {'host': '192.0.2.10', 'ssh_port': 22, 'uid': None,
                       'enrollment_context': 'new-server'}

    def _inspect(self, system):
        with mock.patch.object(ssh_trust, 'probe', return_value=self.live), \
                mock.patch.object(ssh_trust, 'system_keys', return_value=system), \
                mock.patch.object(ssh_trust, 'panel_keys', return_value=paramiko.HostKeys()):
            return ssh_trust.inspect(self.server)

    def test_changed_key_from_system_store_carries_commands(self):
        system = paramiko.HostKeys()
        system.add('192.0.2.10', self.stale.get_name(), self.stale)
        result = self._inspect(system)
        self.assertEqual(result['status'], 'changed')
        self.assertEqual(result['remediation']['reason'], 'system_conflict')
        self.assertIn('ssh-keygen -R', result['remediation']['remove_system'])

    def test_trusted_key_has_no_remediation_block(self):
        system = paramiko.HostKeys()
        system.add('192.0.2.10', self.live.get_name(), self.live)
        result = self._inspect(system)
        self.assertEqual(result['status'], 'trusted')
        self.assertNotIn('remediation', result)

    def test_unknown_key_has_no_remediation_block(self):
        result = self._inspect(paramiko.HostKeys())
        self.assertEqual(result['status'], 'unknown')
        self.assertNotIn('remediation', result)


class TrustErrorResponseTests(unittest.TestCase):
    """The 409 body must name the cause and carry the commands."""

    @classmethod
    def setUpClass(cls):
        import app as panel
        cls.panel = panel

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.object(
            ssh_trust, 'trust_path',
            return_value=os.path.join(self.tmp, 'ssh_known_hosts'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server = {'host': '192.0.2.10', 'ssh_port': 22}

    def body(self, exc, server='auto'):
        target = self.server if server == 'auto' else server
        response = self.panel._trust_error_response(exc, target)
        import json
        return response.status_code, json.loads(response.body)

    def test_unresolved_endpoint_still_answers_409(self):
        # The handler used to pass an unbound local when validation failed
        # before the endpoint existed, turning a clean 409 into a 500.
        status, body = self.body(ssh_trust.TrustChanged('Trust changed'), server=None)
        self.assertEqual(status, 409)
        self.assertEqual(body['error_code'], 'trust_changed')
        self.assertNotIn('remediation', body)

    def test_system_conflict_maps_to_code_and_commands(self):
        status, body = self.body(ssh_trust.SystemTrustConflict('conflict'))
        self.assertEqual(status, 409)
        self.assertEqual(body['error_code'], 'system_trust_conflict')
        self.assertIn('remove_system', body['remediation'])

    def test_readonly_maps_to_its_own_code(self):
        status, body = self.body(ssh_trust.TrustFileReadOnly('read-only'))
        self.assertEqual(status, 409)
        self.assertEqual(body['error_code'], 'trust_file_readonly')
        self.assertIn('chmod_panel', body['remediation'])

    def test_stale_snapshot_maps_without_commands(self):
        status, body = self.body(ssh_trust.TrustChanged('Trust changed; probe again'))
        self.assertEqual(status, 409)
        self.assertEqual(body['error_code'], 'trust_changed')
        self.assertNotIn('remediation', body)

    def test_unknown_error_keeps_generic_code(self):
        status, body = self.body(ValueError('boom'))
        self.assertEqual(status, 409)
        self.assertEqual(body['error_code'], 'trust_error')
        self.assertNotIn('remediation', body)


if __name__ == '__main__':
    unittest.main()
