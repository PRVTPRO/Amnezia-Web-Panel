"""Recovery controls must not depend on successful SSH stats loading."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class TrustUITests(unittest.TestCase):
    def test_recovery_is_in_static_server_page(self):
        source = (ROOT / 'templates/server.html').read_text(encoding='utf-8')
        self.assertIn('id="ssh-trust-panel"', source)
        self.assertIn('ssh-trust/inspect', source)
        self.assertIn('ssh-trust/confirm', source)
        self.assertIn('ssh_trust_warning', source)
        self.assertIn('confirmed:', source)
        self.assertIn('location.reload()', source)

    def test_listing_does_not_call_tcp_ping_ssh_success(self):
        app_source = (ROOT / 'app.py').read_text(encoding='utf-8')
        self.assertIn('asyncio.to_thread(ssh_trust.saved_status, server)', app_source)
        self.assertNotIn('asyncio.to_thread(ssh_trust.inspect, server)', app_source)
        source = (ROOT / 'templates/index.html').read_text(encoding='utf-8')
        self.assertIn('data.ssh_trust', source)
        self.assertIn('ssh_trust_unknown', source)
        self.assertIn('ssh_trust_changed', source)
