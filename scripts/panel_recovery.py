"""Offline administrator recovery. Never imports/starts the panel or contacts SSH.

Stop the panel gracefully and independently verify outstanding remote commands
have stopped first. Run as the DATA_FILE owner (or root), with private storage.
See PEER_RECOVERY.md. A restored baseline is explicitly unverified, not final.
"""
import argparse
import getpass
import os
from pathlib import Path
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from peer_recovery import (PanelLease, RecoveryStore, RecoveryError, file_hash,
                           digest, validate_backup, MAX_BACKUP_BYTES)
from peer_recovery import check_create_journal
from peer_recovery import DISASTER_HOLD

CONFIRM = 'RESTORE PANEL; REMOTE OPERATIONS STOPPED; COUNTERS MAY REWIND'
FINISH_CONFIRM = 'NODES RECONCILED; UNVERIFIED COUNTERS ACCEPTED'


def restore(data_file, backup, operation_id, expected_sha256, confirmation):
    data_file = Path(data_file).resolve()
    if confirmation != CONFIRM or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
        raise RecoveryError('explicit_confirmation_required')
    if data_file.exists() and hasattr(os, 'geteuid') and os.geteuid() not in (0, data_file.stat().st_uid):
        raise RecoveryError('storage_owner_required')
    with open(backup, 'rb') as source:
        raw = source.read(MAX_BACKUP_BYTES + 1)
    validated = validate_backup(raw)
    actor = 'offline:' + getpass.getuser()
    intent = digest({'backup_sha256': file_hash(raw), 'expected_sha256': expected_sha256})
    with PanelLease(data_file, recovery=True):
        store = RecoveryStore(data_file)
        replay = store.replay(operation_id, actor, 'disaster_restore', intent)
        if replay:
            return replay
        current = data_file.read_bytes() if data_file.exists() else b''
        if file_hash(current) != expected_sha256:
            raise RecoveryError('recovery_state_changed')
        for server in validated['servers']:
            if not server.get('uid'):
                server['uid'] = str(uuid.uuid4())
        check_create_journal(data_file, replacement=validated)
        # Restoring JSON cannot reconcile keys still present on remote nodes.
        # Refuse automatic startup until an operator explicitly completes that
        # independent reconciliation. Hold and restored data are one atomic write.
        validated[DISASTER_HOLD] = operation_id
        return store.commit(operation_id, actor, 'disaster_restore', intent, current, validated)


def complete_restore(data_file, restore_id, operation_id, expected_sha256, confirmation):
    data_file = Path(data_file).resolve()
    if confirmation != FINISH_CONFIRM or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
        raise RecoveryError('explicit_confirmation_required')
    if hasattr(os, 'geteuid') and os.geteuid() not in (0, data_file.stat().st_uid):
        raise RecoveryError('storage_owner_required')
    actor = 'offline:' + getpass.getuser()
    intent = digest({'restore_id': restore_id, 'expected_sha256': expected_sha256})
    with PanelLease(data_file, recovery=True):
        store = RecoveryStore(data_file)
        replay = store.replay(operation_id, actor, 'complete_disaster_restore', intent)
        if replay:
            return replay
        before = data_file.read_bytes()
        if file_hash(before) != expected_sha256:
            raise RecoveryError('recovery_state_changed')
        data = validate_backup(before)
        if data.get(DISASTER_HOLD) != restore_id:
            raise RecoveryError('disaster_hold_changed')
        if Path(str(data_file) + '.lifecycle-uncertain.json').exists():
            raise RecoveryError('ssh_result_still_unknown')
        check_create_journal(data_file, replacement=data)
        del data[DISASTER_HOLD]
        return store.commit(operation_id, actor, 'complete_disaster_restore', intent, before, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-file', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--backup')
    mode.add_argument('--finish-restore', help='Original disaster restore operation ID; requires node reconciliation')
    parser.add_argument('--operation-id', required=True, help='32 lowercase hex characters; retain on retry')
    parser.add_argument('--expected-sha256', required=True, help='SHA256 of current data.json (or empty bytes if absent)')
    parser.add_argument('--confirm', required=True)
    args = parser.parse_args()
    try:
        import json
        if args.finish_restore:
            result = complete_restore(args.data_file, args.finish_restore, args.operation_id,
                                      args.expected_sha256, args.confirm)
        else:
            result = restore(args.data_file, args.backup, args.operation_id,
                             args.expected_sha256, args.confirm)
        print(json.dumps(result))
    except (RecoveryError, OSError, ValueError):
        # Avoid exposing private paths/content in automated logs.
        print('Recovery not completed. Inspect the private journal and retry the same operation ID after resolving the cause.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
