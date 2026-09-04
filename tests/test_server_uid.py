import re
import unittest

from app import backfill_server_uids, find_server_by_uid


def servers():
    return [
        {'name': 'a', 'host': '10.0.0.1', 'protocols': {}},
        {'name': 'b', 'host': '10.0.0.2', 'protocols': {}, 'uid': 'f' * 32},
        {'name': 'c', 'host': '10.0.0.3', 'protocols': {}},
    ]


class BackfillServerUidsTests(unittest.TestCase):
    def test_mints_distinct_uids_only_where_missing(self):
        items = servers()

        self.assertTrue(backfill_server_uids(items))

        uids = [s['uid'] for s in items]
        self.assertEqual(uids[1], 'f' * 32)  # existing value untouched
        self.assertEqual(len(set(uids)), 3)
        for uid in uids:
            self.assertRegex(uid, r'^[0-9a-f]{32}$')

    def test_is_idempotent(self):
        items = servers()
        backfill_server_uids(items)
        before = [s['uid'] for s in items]

        self.assertFalse(backfill_server_uids(items))
        self.assertEqual([s['uid'] for s in items], before)

    def test_tolerates_missing_list(self):
        self.assertFalse(backfill_server_uids(None))
        self.assertFalse(backfill_server_uids([]))


class FindServerByUidTests(unittest.TestCase):
    def setUp(self):
        self.data = {'servers': servers()}
        backfill_server_uids(self.data['servers'])

    def test_resolves_index_and_record(self):
        target = self.data['servers'][2]

        idx, server = find_server_by_uid(self.data, target['uid'])

        self.assertEqual(idx, 2)
        self.assertIs(server, target)

    def test_empty_or_unknown_uid_resolves_to_nothing(self):
        self.assertEqual(find_server_by_uid(self.data, ''), (None, None))
        self.assertEqual(find_server_by_uid(self.data, None), (None, None))
        self.assertEqual(find_server_by_uid(self.data, 'no-such-uid'), (None, None))
        self.assertEqual(find_server_by_uid({}, 'x'), (None, None))

    def test_survives_reorder_and_delete(self):
        target = self.data['servers'][2]
        uid = target['uid']

        # /api/servers/reorder rebuilds the list from a permutation of indices
        order = [2, 0, 1]
        self.data['servers'] = [self.data['servers'][i] for i in order]
        idx, server = find_server_by_uid(self.data, uid)
        self.assertEqual(idx, 0)
        self.assertIs(server, target)

        # /api/servers/{id}/delete pops a record and shifts the ones after it
        self.data['servers'].pop(0)
        self.assertEqual(find_server_by_uid(self.data, uid), (None, None))
        other = self.data['servers'][1]
        self.assertEqual(find_server_by_uid(self.data, other['uid']), (1, other))


if __name__ == '__main__':
    unittest.main()
