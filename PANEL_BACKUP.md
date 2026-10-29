# Complete panel-state backup

The settings **Download backup** button downloads one ZIP. It requires an enabled
administrator (not support), same-origin browser metadata and a session CSRF
nonce. Admin Bearer clients can POST JSON to `/api/settings/backup/archive`.
There is no public archive URL; responses are non-cacheable. Archives contain
private VPN/SSH credentials and recovery snapshots. Store/encrypt them privately;
do not attach them to issues or send them to users.

`manifest.json` records the format, panel version, UTC time, every member's size
and SHA256, missing optional sidecars, and the configured data/trust paths. Paths
inside the archive are logical, never instructions to overwrite host paths:

- `state/data.json`: exact bytes of custom `DATA_FILE`;
- `state/data.json.peer-creates.json`: durable create intents/receipts;
- `state/data.json.lifecycle-uncertain.json`: unknown SSH outcome fence;
- `state/data.json.recovery/…`: private recovery snapshots and audit;
- `trust/ssh_known_hosts`: configured `SSH_KNOWN_HOSTS_FILE`, or its DATA_FILE-relative default;
- `trust/system_known_hosts`: the process owner's system pins, if present.

Missing optional files are recorded explicitly. An unreadable, corrupt, changing,
oversized or unsafe critical file fails the entire download. No partial archive
is returned. Symlinks/junctions, hard-linked sources and special files are refused.
Only these configured/scoped locations are read, never the entire DATA_FILE parent
or arbitrary host directories. Bounds: 32 MiB/file, 128 MiB total, 2048 files.

One running panel process on a local atomic-rename/fsync filesystem is required.
The snapshot takes the lifecycle admission interlock, then DATA_LOCK, then
STATE_FILE_LOCK, create-journal lock and trust lock. No SSH is performed. Existing
confirmation commits also acquire DATA_LOCK before trust, so there is no reverse
lock order. Already-started work finishes first; bounded admission returns busy.
HTTP cancellation retains locks until the disk worker ends and closes its
anonymous private tempfile. Streaming disconnect/error also closes it; the OS
reclaims an anonymous tempfile on process exit. External, unmanaged writers must
be stopped: stat/identity checks detect changes but cannot fence another program.

A lifecycle fence may be archived under the read-only interlock, but is never
cleared. This is a consistent **local panel-state** snapshot, not a node backup,
proof of remote quiescence, or a guaranteed final traffic-counter receipt.

On v1.8.2, admin peer finalization uses the same lifecycle admission and data
commit boundaries. The archive waits for its commit and includes the resulting
`accounting_recoveries` tombstones, baselines, recovery snapshots and audit.
Downloading or staging a backup never calls finalization or upgrades an
unverified counter to a verified one. Existing compatible JSON restore still
preserves current usage/baselines; incompatible topology and unknown SSH outcomes
remain blocked by their existing protections.

## Save deployment material separately

The web process gets no root privileges. Compose/systemd/run flags, `.env` and
`SECRET_KEY`, reverse-proxy configuration, external TLS/DuckDNS certificates,
separately managed SSH key files and actual VPN-node configurations/backups are
outside this archive. Save them with a host-level cold backup. Docker mounts must
persist DATA_FILE, all its sidecars and custom trust paths.

Runtime PID leases (`DATA_FILE.runtime.lock`), tunnel process/PID/cache state,
downloaded binaries, normal application logs, atomic-write scratch files and
historical JSON exports are not durable accounting state and are excluded.
Restoring a stale runtime PID can block recovery or target an unrelated process.

## Offline recovery, never HTTP force restore

The old JSON GET `/api/settings/backup/download` and ordinary JSON restore API
are unchanged. JSON alone is not a complete backup. Ordinary restore retains all
ownership/counter/journal protections. The ZIP is deliberately not accepted by
ordinary restore. See [PEER_RECOVERY.md](PEER_RECOVERY.md).

1. Stop the panel gracefully and independently establish that outstanding SSH,
   AWG and unmanaged operations have stopped. Do not kill a worker or erase an
   uncertain/create/recovery journal. Take a full cold backup of the **current**
   state and deployment material before any activation/rollback.
2. Independently check the archive's trusted checksum/provenance. Member hashes
   prove integrity, not authenticity. Using the matching panel source/dependencies,
   as the storage owner, verify it:
   ```sh
   python scripts/panel_backup.py --archive /private/panel-backup.zip
   ```
3. Stage into a **new**, private directory, never over the existing live tree:
   ```sh
   python scripts/panel_backup.py --archive /private/panel-backup.zip \
     --stage-to /private/restored-panel \
     --confirm 'STAGE OFFLINE; NODES MUST BE RECONCILED; COUNTERS MAY REWIND'
   ```
   Validation precedes writes. All source journals/trust/snapshots are retained.
   The complete tree is published by rename, with a new audited disaster hold
   already in data.json. Failure is not success; partial staging is cleaned up.
   If parent-directory fsync fails after publication, the complete held tree
   remains for inspection, but the tool reports failure, not success.
   An existing destination is always refused, including on retry; it is never
   overwritten. An interrupted process may leave a private staging directory or
   `.restore-claim` fence: inspect it offline, do not automatically clear it.
   On Windows the parent/destination must have owner-only NTFS ACLs.
4. The new DATA_FILE is `restored-panel/state/data.json`; configure the matching
   journal/recovery directory beside it. Panel trust is
   `restored-panel/trust/ssh_known_hosts`. Independently reconcile any archived
   system pins; the tool never overwrites `~/.ssh/known_hosts`. Restore deployment
   secrets/certificates separately. Do not start a second panel on the same nodes.
5. Reconcile peers, ownership, baselines and monthly/lifetime counters against
   actual VPN nodes, including peers absent from this archive. Resolve unfinished
   create intents and unknown SSH results using PEER_RECOVERY.md; preserve their
   evidence. Staging does not replay creates, delete peers, enable users, reset
   traffic, or claim that a restored counter is current/final.
6. Only after reconciliation use the existing audited `scripts/panel_recovery.py
   --finish-restore` workflow with the returned restore_id, a new operation ID,
   current data.json SHA256 and `NODES RECONCILED; UNVERIFIED COUNTERS ACCEPTED`.
   Fences/unfinished create intents/invalid ownership still block completion.
   Do this before starting a process in the new tree. Then activate the whole
   prepared tree and corresponding trust/configuration while still offline.

There is no automatic multi-filesystem/live rollback or one-click full restore.
If node state or cross-file activation cannot be established safely, keep the
panel offline and preserve both complete trees. No archive makes a userspace AWG
delete counter exact.
