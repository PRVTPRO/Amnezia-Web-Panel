"""Recovery controls must not depend on successful SSH stats loading."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class TrustUITests(unittest.TestCase):
    def test_recovery_is_in_static_server_page(self):
        source = (ROOT / 'templates/server.html').read_text(encoding='utf-8')
        self.assertIn('id="ssh-trust-panel"', source)
        self.assertIn('id="sshTrustBtn"', source)
        self.assertIn('id="sshTrustModal"', source)
        self.assertIn('ssh-trust/status', source)
        self.assertIn('loadSSHTrustStatus', source)
        self.assertIn('setSSHTrustButton', source)
        self.assertIn('ssh-trust/inspect', source)
        self.assertIn('ssh-trust/confirm', source)
        self.assertIn('ssh_trust_warning', source)
        self.assertIn('confirmed:', source)
        self.assertIn('location.reload()', source)

    def test_status_endpoint_uses_saved_status_only(self):
        app_source = (ROOT / 'app.py').read_text(encoding='utf-8')
        marker = "@app.get('/api/servers/{server_id}/ssh-trust/status'"
        idx = app_source.index(marker)
        block = app_source[idx:app_source.index('\nasync def', idx)]
        self.assertIn('ssh-trust/status', block)
        self.assertIn('ssh_trust.saved_status(servers[server_id])', block)
        self.assertNotIn('ssh_trust.inspect(', block)
        # Non-status endpoints keep using the network probe.
        self.assertIn('ssh_trust.inspect(', app_source)

    def test_listing_does_not_call_tcp_ping_ssh_success(self):
        app_source = (ROOT / 'app.py').read_text(encoding='utf-8')
        marker = "@app.get('/api/servers/{server_id}/ping'"
        idx = app_source.index(marker)
        block = app_source[idx:app_source.index('\n@app.', idx)]
        # Cards need a live changed/unknown signal, so ping performs a key-only
        # probe. It must not authenticate or open an SSH session.
        self.assertIn('ssh_trust.inspect', block)
        self.assertIn("'ssh_trust_detail': inspection", block)
        self.assertNotIn('SSHManager', block)
        source = (ROOT / 'templates/index.html').read_text(encoding='utf-8')
        self.assertIn('data.ssh_trust_detail', source)
        self.assertIn('ssh_trust_unknown', source)
        self.assertIn('ssh_trust_changed', source)
