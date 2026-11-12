"""Regression tests for connection-list sorting controls and protocol support."""
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SORT_KEYS = (
    'sort', 'sort_by', 'sort_direction', 'sort_ascending', 'sort_descending',
    'sort_name', 'sort_created', 'sort_handshake', 'sort_rx', 'sort_tx',
    'sort_max_speed', 'sort_total_traffic', 'sort_ip', 'sort_quota', 'sort_expiry',
)


class ConnectionSortingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, 'templates', 'server.html'), encoding='utf-8') as f:
            cls.template = f.read()

    def test_sort_menu_and_all_criteria_are_present(self):
        for element in ('connSortField', 'connSortDirection', 'connectionsListInner'):
            self.assertIn('id="%s"' % element, self.template)
        for field in ('name', 'created', 'handshake', 'rx', 'tx',
                      'maxspeed', 'total', 'ip', 'quota', 'expiry'):
            self.assertIn('<option value="%s">' % field, self.template)

    def test_protocol_availability_is_explicit(self):
        start = self.template.index('function connectionSortAvailable(')
        end = self.template.index('function updateConnectionSortOptions(', start)
        body = self.template[start:end]
        for fragment in ("case 'created': return proto !== 'telemt'",
                         "case 'handshake': return proto !== 'telemt' && proto !== 'xray'",
                         "case 'maxspeed':", "case 'quota':", "case 'expiry':"):
            self.assertIn(fragment, body)

    def test_default_sort_and_refresh_reapplication(self):
        self.assertIn('<option value="name">', self.template)
        self.assertIn('<option value="asc">', self.template)
        start = self.template.index('async function loadConnections(')
        end = self.template.index('// Deep link from the users page', start)
        body = self.template[start:end]
        self.assertIn('updateConnectionSortOptions(proto);', body)
        self.assertIn('applyConnectionSort();', body)

    def test_missing_numeric_values_are_zero_and_name_is_tiebreaker(self):
        start = self.template.index('function applyConnectionSort()')
        end = self.template.index('function escapeHtml(', start)
        body = self.template[start:end]
        self.assertIn('(Number(av) || 0) - (Number(bv) || 0)', body)
        self.assertIn('data-sort-name', self.template)
        self.assertIn('sensitivity: \'base\'', body)
        self.assertNotIn('localStorage', body)

    def test_all_sort_labels_exist_in_every_locale(self):
        for lang in ('ru', 'en', 'fr', 'fa', 'zh'):
            path = os.path.join(ROOT, 'translations', lang + '.json')
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            missing = [key for key in SORT_KEYS if not data.get(key)]
            self.assertEqual(missing, [], '%s misses %s' % (lang, missing))


if __name__ == '__main__':
    unittest.main()
