"""The operational WARP state file is part of the panel backup allowlist."""

import unittest
from pathlib import Path

import panel_backup as backup
from tests.test_panel_backup import StateFixture

WARP_STATE = 'state/data.json.srv_warp_state.json'


class WarpStateBackupTests(StateFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.warp_state = Path(str(self.data) + '.srv_warp_state.json')

    def test_warp_state_member_is_exported_byte_for_byte(self):
        payload = b'{"version":1,"servers":{},"exit":{"registered":false}}'
        self.warp_state.write_bytes(payload)

        manifest, files, _ = backup.read_archive(self.archive())

        self.assertIn(WARP_STATE, files)
        self.assertEqual(files[WARP_STATE], payload)
        self.assertNotIn(WARP_STATE, manifest['absent'])
        # The member passes both allowlist points.
        self.assertEqual(backup._member(WARP_STATE).as_posix(), WARP_STATE)
        backup._validate_content(WARP_STATE, payload)

    def test_missing_warp_state_is_reported_as_absent(self):
        manifest, files, _ = backup.read_archive(self.archive())

        self.assertNotIn(WARP_STATE, files)
        self.assertIn(WARP_STATE, manifest['absent'])

    def test_invalid_warp_state_structure_is_rejected(self):
        self.warp_state.write_text('[]')
        with self.assertRaises(backup.BackupError):
            self.create()

    def test_unrelated_json_member_is_rejected(self):
        with self.assertRaises(backup.BackupError):
            backup._member('state/evil.json')
        with self.assertRaises(backup.BackupError):
            backup._member('state/data.json.srv_warp_ops.json')


if __name__ == '__main__':
    unittest.main()
