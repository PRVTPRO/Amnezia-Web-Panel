"""Connection counts must ignore peers whose VPN session is offline.

Conntrack entries (TCP ESTABLISHED) survive the peer's disconnect for
hours/days, so a raw per-IP conntrack count attributes stale flows to
offline peers and the flood warning fires for users who are not even
connected. _count_connections_by_ip must only count peers with a fresh
handshake.
"""
import unittest
from unittest import mock

from managers.awg_manager import AWGManager

AWG_SHOW = """interface: awg0
  public key: SERVERPUB
  private key: (hidden)
  listening port: 55424

peer: KEY_LIVE
  endpoint: 37.0.0.1:5000
  allowed ips: 10.8.1.17/32
  latest handshake: 45 seconds ago
  transfer: 1.2 MiB received, 3.4 MiB sent

peer: KEY_IDLE
  allowed ips: 10.8.1.4/32
  latest handshake: 1 hour, 2 minutes ago
  transfer: 0 B received, 0 B sent

peer: KEY_OFFLINE
  allowed ips: 10.8.1.20/32
  transfer: 0 B received, 0 B sent
"""

CONNTRACK_COUNTS = """    897 10.8.1.17
     42 10.8.1.4
    905 10.8.1.20
     11 34.225.159.174
"""


def fake_ssh(conntrack_out=CONNTRACK_COUNTS, show_out=AWG_SHOW, show_code=0):
    ssh = mock.Mock()

    def sudo(command, timeout=60):
        if 'nf_conntrack' in command:
            return conntrack_out, '', 0
        if 'awg show' in command:
            return show_out, '', show_code
        return '', '', 1

    ssh.run_sudo_command = sudo
    return ssh


def manager(ssh):
    mgr = AWGManager(ssh)
    mgr._get_subnet_ip = mock.Mock(return_value='10.8.1.0')
    mgr._get_subnet_cidr = mock.Mock(return_value='24')
    return mgr


class ConnCountLivenessTests(unittest.TestCase):
    def test_stale_entries_of_offline_peers_are_not_counted(self):
        counts = manager(fake_ssh())._count_connections_by_ip('awg')
        # 10.8.1.20 is in conntrack with 905 flows but has no live handshake;
        # 10.8.1.4's handshake is hours old; only 10.8.1.17 qualifies.
        self.assertEqual(counts, {'10.8.1.17': 897})

    def test_counts_empty_when_liveness_cannot_be_determined(self):
        ssh = fake_ssh(show_out='', show_code=1)
        counts = manager(ssh)._count_connections_by_ip('awg')
        self.assertEqual(counts, {})

    def test_external_ips_never_counted(self):
        counts = manager(fake_ssh())._count_connections_by_ip('awg')
        self.assertNotIn('34.225.159.174', counts)

    def test_handshake_age_parsing(self):
        p = AWGManager._parse_handshake_age
        self.assertEqual(p('45 seconds ago'), 45)
        self.assertEqual(p('1 minute, 51 seconds ago'), 111)
        self.assertEqual(p('2 hours, 3 minutes ago'), 7380)
        self.assertEqual(p('3 days, 1 hour ago'), 262800)
        self.assertIsNone(p(''))
        self.assertIsNone(p('no handshake'))

    def test_connected_peer_ips_parses_show_output(self):
        mgr = manager(fake_ssh())
        self.assertEqual(mgr._connected_peer_ips('awg'), {'10.8.1.17'})


if __name__ == '__main__':
    unittest.main()
