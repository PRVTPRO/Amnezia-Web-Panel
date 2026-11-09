# Accounting recovery (administrator only)

For complete state archives and safe offline staging, see
[PANEL_BACKUP.md](PANEL_BACKUP.md). The legacy JSON export does not include trust
or all sidecar journals. Archives never bypass the recovery restrictions below.

Self-service and ordinary workflows still fail closed for linked peers. A
disabled flag, SSH scrape, Stop/Down, or userspace AWG removal is **not** a
final-counter receipt, so self-service deletion cannot recover bytes already
lost before a checkpoint. No counter is reset to make recovery succeed.

## Online JSON backup restore

Ordinary JSON restore accepts backups with unchanged servers, connection
configuration/ownership, user policy and accounting archive. Current user
traffic totals, reset timestamps, synchronization revisions and complete
connection rows are retained, not restored from the backup. Settings can be
restored without rewinding usage. The recovery generation and disaster hold
are retained as well. No SSH commands are executed by this operation.

Backups that change these protected records still return HTTP 409 and require
the offline disaster-recovery workflow below. This includes backups made before
a peer was added, reassigned or deleted. A fresh installation without accounting
records can still import a backup normally.

## Admin finalization of linked peers

Administrators have a dedicated finalization flow. It is the normal path for
removing a linked peer or unlinking an owner; the orphan-recovery section below
is for edge cases only.

**Deleting a peer** (`POST /api/servers/{server_id}/connections/remove`) no
longer hard-blocks when the peer is linked. The endpoint attempts to read a
final counter from the remote peer, commits the resulting delta, removes the
peer, removes the link, and writes a tombstone row to `accounting_recoveries`
marked `counters_verified_final: false`. If the final counter cannot be read,
the request fails closed with 409 `final_counter_read_failed` and
`can_force: true`; the UI may retry with `allow_unverified: true` to remove the
peer without verified final usage.

**Unlinking an owner** (`POST /api/users/{user_id}/connections/unlink`) allows
direct unlink of disabled or absent peers. Active peers require the caller to
pass `stop: true` ("stop and unlink") — the peer is stopped on the node before
the link is removed. The endpoint also accepts `allow_unverified: true` under
the same conditions as the delete endpoint: only when the final counter cannot
be read.

## Orphaned ownership (edge cases only)

Ordinary admin peer deletion and owner unlinking now use the **Admin
finalization of linked peers** flow above. The orphan-recovery API below is for
the remaining edge cases: records whose user no longer exists (dangling
ownership), situations where ownership needs repair to another user, and
archiving rows for peers that are verifiably absent from the node
(`archive_absent`).

Use the authenticated admin API. Browser requests must be same-origin. Neither
self-service nor Telegram accepts recovery options.

1. `GET /api/recovery/orphans/{connection_id}` returns the exact server UID,
   physical protocol instance, client ID, local digest and observed peer digest.
   No config/private key is returned. Review the identity independently.
2. Prefer `POST /api/recovery/orphans` with `mode: "repair"`, an existing
   `target_user_id`, both digests, the connection ID, a new random 32-character
   lowercase hex `operation_id`, and this exact `confirmation`:
   `RESTORE OWNERSHIP; USAGE IS UNVERIFIED`.
   The peer must be found again, unchanged. This changes only its owner plus
   recovery metadata. The destination must have eligible access; manually
   blocked, expired, exhausted or uncertain targets are refused. User quotas/status/expiration, all existing counters and
   connection baselines are preserved. It does not enable a user or peer.
3. If repair is impossible, `mode: "archive_absent"` requires confirmation
   `ARCHIVE ABSENT PEER; FINAL USAGE IS UNKNOWN`. This **does not remove a remote
   peer**. It is available only for verified-absent AWG instances: successful
   reads must exclude the key from clientsTable, both supported persisted config
   paths and native `show all peers`. Failed, incomplete or unsupported backend
   reads are not absence. A present peer is rejected even when disabled.

Immediately before local mutation the full inventory digest and the UID / exact
instance / client tuple are rechecked under the data lock. Managed create,
restore, raw config and ownership operations share the lifecycle interlock.
External unmanaged edits cannot be fenced by the panel: stop such automation
before recovery. A changing peer observation requires a new preview.

Every operation first durably writes an owner-only snapshot of the complete
original JSON and an audit event. Snapshot/audit failure forbids mutation. Local
archival retains the original row, baseline, observed counters and UID in
`accounting_recoveries`, explicitly marked `counters_verified_final: false`.
Old protocol/full backups and raw config replacement remain guarded against
silently reintroducing the archived key. Other unowned peers remain removable.

Keep the operation ID/body unchanged on retry. An ambiguous local commit is
recovered from its journal/hash/generation without overwriting later writes.
Unknown historical usage needs administrator reconciliation; archival never
asserts an exact monthly or lifetime total for a missing owner.

## Full-panel disaster restore

The ordinary `/api/settings/backup/restore` remains backward compatible (optional
multipart `operation_id` for retries). It validates the backup and snapshots the
current file, but refuses to rewind owned or archived accounting. There is no
HTTP `force` switch. A whole-panel restore changes authentication, inventory,
background intent and baselines together; doing it online without fencing all
old SSH/control workers would be unsafe.

For disaster recovery:

1. Stop the panel **gracefully**. Independently verify outstanding remote
   commands have stopped. A lost SSH transport does not prove this.
2. As the data-file OS owner/root, use private storage and compute SHA256 of the
   current file (or empty bytes if it is absent). Corrupt current bytes are also
   snapshotted exactly; they are not parsed or silently discarded.
3. Run locally, substituting paths/IDs/hashes (never put credentials in argv):

   ```sh
   python scripts/panel_recovery.py --data-file /private/data.json \
     --backup /private/backup.json --operation-id RANDOM_32_LOWERCASE_HEX \
     --expected-sha256 CURRENT_FILE_SHA256 \
     --confirm 'RESTORE PANEL; REMOTE OPERATIONS STOPPED; COUNTERS MAY REWIND'
   ```

4. The running panel and recovery tool take the same exclusive runtime lease.
   A PID marker also refuses recovery while the former runtime process is alive,
   even after ASGI shutdown closes its lease handle (SSH threads may still run).
   Recovery refuses while the panel/another recovery is running. The complete
   file is replaced atomically only after validation, fsynced snapshot/audit and
   a last current-hash check. There is no partial table-by-table restore.
5. On interruption retry the same command/operation ID; inspect the private
   journal if concurrent manual changes prevent proof of commit. Do not restore
   a second time over newer data. Snapshots are at `DATA_FILE.recovery/ID.json`,
   with original bytes in `before_base64` and their `before_sha256`. For rollback,
   decode/verify those bytes offline, then use the same validated recovery tool
   with a new operation ID (a corrupt original requires another valid backup).
6. The atomic replacement includes a durable disaster-recovery hold: panel
   startup refuses to launch monitors/background tasks until node reconciliation
   is explicitly completed. Reconcile restored peers, ownership and counters
   against nodes, including keys absent from the backup, before admitting use.
   Keep endpoints quiesced during this work. Then run with a new operation ID
   and current SHA256:

   ```sh
   python scripts/panel_recovery.py --data-file /private/data.json \
     --finish-restore ORIGINAL_RESTORE_ID --operation-id NEW_32_LOWERCASE_HEX \
     --expected-sha256 CURRENT_FILE_SHA256 \
     --confirm 'NODES RECONCILED; UNVERIFIED COUNTERS ACCEPTED'
   ```

   The tool snapshots/audits hold release; it does not independently prove the
   operator's cross-node verification. Restored usage/baselines can rewind and
   remain **unverified**. This tool
   does not deploy remote configs, restore SSH trust, stop remote peers, or
   provide cross-node rollback. Keep the panel offline if that cannot be done.

Snapshots can contain SSH credentials/configuration. Never publish/download
them through user APIs. POSIX uses 0700 directories/0600 files; on Windows use
equivalent owner-only NTFS ACLs. Retain the journal and snapshot for recovery.
One panel process and a local filesystem with atomic rename/fsync are required.
When #242's `DATA_FILE.peer-creates.json` is present, it is also included in the
private snapshot and left unchanged. Unfinished create intents block restore;
completed/blocked intents require the restored backup to retain their exact
owner, peer, server UID and SSH endpoint. Orphan repair/archive refuses a peer
still owned by that journal. Reconcile the journal first; never delete it to
make a restore pass. This is a deliberate fail-closed limitation, not automatic
recovery of unknown remote outcomes.

## Cancellation and uncertain SSH

Lifecycle queue admission waits at most 10 seconds. HTTP response waiting is
limited to 120 seconds; neither deadline kills an admitted SSH worker. Cancelled
queued requests never execute. Started workers keep the interlock until their
network work and commit finish, without holding `DATA_LOCK` over SSH.

`GET /api/recovery/status` gives admins operation names/age and fence status,
without commands, credentials or internal paths. A response deadline returns
503 `peer_lifecycle_still_running`; it is not a success or automatic retry.
Unexpected detached errors log a traceback with exception values, locals and
source lines omitted (these may contain secrets).

A lost command reply persists `DATA_FILE.lifecycle-uncertain.json`; it is a
logical admission fence even after the local worker exits/restarts. Subsequent
lifecycle/SSH work fails closed. Do not clear it on a timer or HTTP disconnect.
An administrator must independently establish remote quiescence, stop the panel,
retain this marker as incident evidence, and only then archive it before restart.
If the marker could not be persisted, keep the panel offline after shutdown.
Transport timeouts cannot guarantee when a remote shell actually stops; no
automatic finalization/unlock or accurate final-counter claim is made.
