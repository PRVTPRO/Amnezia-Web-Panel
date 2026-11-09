"""Unit tests for the persistent IPv6 operation store.

ipv6_operations.OperationStore keeps the status of long IPv6 operations in a
small JSON file, so the UI can poll it and the status survives a panel
restart. The tests pin the contract the API relies on: field shape of a fresh
operation, update/get semantics, persistence across store instances, the
startup cleanup of interrupted operations, the 100 record cap and safe file
handling (corrupt file, atomic replace).

No real panel, SSH or Docker is involved: every test works on a temporary
directory from tempfile.
"""
import json
import os
import tempfile
import unittest

from ipv6_operations import MAX_OPERATIONS, OperationStore


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, 'ipv6_operations.json')

    def store(self):
        return OperationStore(self.path)

    def write_raw(self, text):
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(text)


class CreateTests(StoreTestCase):
    def test_create_returns_running_queued_operation(self):
        operation = self.store().create('srv-1', 'enable', proto='wireguard')

        self.assertTrue(operation['id'])
        self.assertEqual(operation['server_uid'], 'srv-1')
        self.assertEqual(operation['kind'], 'enable')
        self.assertEqual(operation['proto'], 'wireguard')
        self.assertEqual(operation['state'], 'running')
        self.assertEqual(operation['step'], 'queued')
        self.assertIsNone(operation['reason'])

    def test_create_sets_created_and_updated_timestamps(self):
        operation = self.store().create('srv-1', 'disable')

        self.assertIsInstance(operation['created'], float)
        self.assertIsInstance(operation['updated'], float)
        self.assertEqual(operation['created'], operation['updated'])

    def test_proto_defaults_to_none(self):
        operation = self.store().create('srv-1', 'disable')

        self.assertIsNone(operation['proto'])

    def test_create_uses_unique_ids(self):
        store = self.store()
        first = store.create('srv-1', 'enable')
        second = store.create('srv-1', 'enable')

        self.assertNotEqual(first['id'], second['id'])


class UpdateTests(StoreTestCase):
    def test_update_changes_fields(self):
        store = self.store()
        created = store.create('srv-1', 'enable')

        updated = store.update(created['id'], state='done', step='finished')

        self.assertEqual(updated['state'], 'done')
        self.assertEqual(updated['step'], 'finished')
        # Untouched fields survive the update.
        self.assertEqual(updated['server_uid'], 'srv-1')
        self.assertEqual(updated['kind'], 'enable')

    def test_update_bumps_updated_timestamp(self):
        store = self.store()
        created = store.create('srv-1', 'enable')
        # Force a clearly different clock value so the assertion cannot flake.
        with open(self.path, encoding='utf-8') as handle:
            data = json.load(handle)
        data[created['id']]['updated'] = created['updated'] - 10
        with open(self.path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)

        updated = store.update(created['id'], state='done')

        self.assertGreater(updated['updated'], created['updated'] - 10)

    def test_update_unknown_id_returns_none(self):
        store = self.store()
        store.create('srv-1', 'enable')

        self.assertIsNone(store.update('does-not-exist', state='done'))


class GetAndPersistenceTests(StoreTestCase):
    def test_get_returns_stored_record(self):
        store = self.store()
        created = store.create('srv-1', 'enable', proto='awg')

        fetched = store.get(created['id'])

        self.assertEqual(fetched, created)

    def test_get_unknown_id_returns_none(self):
        self.assertIsNone(self.store().get('missing'))

    def test_get_returns_a_copy_from_disk(self):
        store = self.store()
        created = store.create('srv-1', 'enable')

        fetched = store.get(created['id'])
        fetched['state'] = 'mutated-by-caller'
        fetched['extra'] = 'not persisted'

        again = store.get(created['id'])
        self.assertEqual(again['state'], 'running')
        self.assertNotIn('extra', again)

    def test_new_store_instance_sees_record(self):
        first = self.store()
        created = first.create('srv-1', 'enable', proto='wireguard')

        second = OperationStore(self.path)

        self.assertEqual(second.get(created['id']), created)

    def test_new_store_instance_sees_updates(self):
        first = self.store()
        created = first.create('srv-1', 'enable')
        first.update(created['id'], state='done', step='finished')

        second = OperationStore(self.path)

        self.assertEqual(second.get(created['id'])['state'], 'done')


class MarkInterruptedTests(StoreTestCase):
    def test_running_operation_becomes_failed_interrupted(self):
        store = self.store()
        running = store.create('srv-1', 'enable')

        store.mark_interrupted()

        marked = store.get(running['id'])
        self.assertEqual(marked['state'], 'failed')
        self.assertEqual(marked['reason'], 'interrupted')
        self.assertGreaterEqual(marked['updated'], running['updated'])

    def test_finished_operation_is_left_untouched(self):
        store = self.store()
        done = store.create('srv-1', 'enable')
        store.update(done['id'], state='done', step='finished')
        snapshot = store.get(done['id'])

        store.mark_interrupted()

        self.assertEqual(store.get(done['id']), snapshot)

    def test_mixed_records_only_running_changes(self):
        store = self.store()
        running = store.create('srv-1', 'enable')
        done = store.create('srv-2', 'disable')
        store.update(done['id'], state='done', step='finished')

        store.mark_interrupted()

        self.assertEqual(store.get(running['id'])['state'], 'failed')
        self.assertEqual(store.get(running['id'])['reason'], 'interrupted')
        self.assertEqual(store.get(done['id'])['state'], 'done')
        self.assertIsNone(store.get(done['id'])['reason'])

    def test_mark_interrupted_on_empty_store_does_not_create_file(self):
        store = self.store()

        store.mark_interrupted()

        self.assertFalse(os.path.exists(self.path))


class PruneTests(StoreTestCase):
    def _seed(self, count):
        """Write `count` records with strictly increasing `updated` values."""
        data = {}
        for index in range(count):
            op_id = 'op-%03d' % index
            data[op_id] = {
                'id': op_id,
                'server_uid': 'srv-%d' % index,
                'kind': 'enable',
                'proto': None,
                'state': 'done',
                'step': 'finished',
                'reason': None,
                'created': float(index),
                'updated': float(index),
            }
        with open(self.path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        return data

    def test_prune_keeps_at_most_max_operations(self):
        store = self.store()
        self._seed(MAX_OPERATIONS)

        store.create('srv-new', 'enable')

        with open(self.path, encoding='utf-8') as handle:
            data = json.load(handle)
        self.assertEqual(len(data), MAX_OPERATIONS)

    def test_prune_removes_oldest_first(self):
        store = self.store()
        self._seed(MAX_OPERATIONS)

        created = store.create('srv-new', 'enable')

        # The seed with the smallest `updated` (op-000) is the oldest record.
        self.assertIsNone(store.get('op-000'))
        self.assertIsNotNone(store.get('op-001'))
        self.assertIsNotNone(store.get('op-099'))
        self.assertIsNotNone(store.get(created['id']))

    def test_below_limit_no_records_are_dropped(self):
        store = self.store()
        self._seed(MAX_OPERATIONS - 1)

        store.create('srv-new', 'enable')

        self.assertIsNotNone(store.get('op-000'))


class FileHandlingTests(StoreTestCase):
    def test_corrupt_file_is_treated_as_empty(self):
        self.write_raw('{ this is not valid json ')

        store = self.store()
        self.assertIsNone(store.get('anything'))
        created = store.create('srv-1', 'enable')
        self.assertEqual(store.get(created['id'])['state'], 'running')

    def test_non_object_json_is_treated_as_empty(self):
        self.write_raw('["not", "a", "mapping"]')

        created = self.store().create('srv-1', 'enable')

        self.assertEqual(self.store().get(created['id']), created)

    def test_missing_file_is_treated_as_empty(self):
        store = self.store()

        self.assertIsNone(store.get('missing'))
        self.assertTrue(store.create('srv-1', 'enable')['id'])

    def test_write_is_atomic_and_leaves_no_tmp_file(self):
        store = self.store()
        created = store.create('srv-1', 'enable')

        self.assertFalse(os.path.exists(self.path + '.tmp'))
        self.assertTrue(os.path.exists(self.path))

        store.update(created['id'], state='done')
        self.assertFalse(os.path.exists(self.path + '.tmp'))

    def test_stored_file_is_valid_json(self):
        store = self.store()
        created = store.create('srv-1', 'enable')

        with open(self.path, encoding='utf-8') as handle:
            data = json.load(handle)
        self.assertEqual(data[created['id']]['server_uid'], 'srv-1')


if __name__ == '__main__':
    unittest.main()
