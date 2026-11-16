# S3 storage for panel state

`PANEL_STORAGE=s3` lets the panel run where there is no persistent volume, for
example in Kubernetes with an `emptyDir`. The panel still reads and writes an
ordinary local directory. `panel_storage.py` fills that directory from an
S3-compatible bucket before the panel reads it, and then keeps copying it back
as encrypted, all-or-nothing snapshots. A lease stored in the bucket stops a
second panel from writing to the same place.

All settings come from environment variables (in Kubernetes, a Secret and a
ConfigMap). They cannot live in `data.json`, because `data.json` itself is
stored in the bucket.
With `PANEL_STORAGE` unset or `local`, nothing changes: the S3 client is never
loaded and the panel behaves exactly as before.

Use it when:

- the panel runs in Kubernetes (or another orchestrator) without a reliable
  persistent volume, and the pod may be moved to another node at any time.

Do not use it when:

- a normal disk or Docker volume is available. A volume is simpler and has no
  loss window. Keep using it.
- you want more than one replica or high availability. Exactly one panel
  process may write to a prefix.
- you run the standalone PyInstaller binaries. They do not include the S3
  client and work with local storage only.

This is a live mirror, not a backup. It keeps earlier snapshots for
`PANEL_S3_HISTORY_DAYS` days. Keep downloading the complete backup ZIP
([PANEL_BACKUP.md](PANEL_BACKUP.md)) and keep the encryption key outside the
cluster.

## What is mirrored

The state directory `D` is the directory that holds `DATA_FILE` (`/app/data` in
the examples below). The mirror contains:

- every regular file under `D`, recursively: `data.json`, the credential key
  `data.json.credential.key`, the `data.json.peer-creates.json` journal, the
  `data.json.recovery/` snapshots, the `data.json.lifecycle-uncertain.json`
  fence, WARP state, `ssh_known_hosts`, operation journals, caches and
  `torrent_events.json`;
- `CREDENTIAL_KEY_FILE` and `SSH_KNOWN_HOSTS_FILE`, when they are set and point
  outside `D`. They are stored as `@env/CREDENTIAL_KEY_FILE` and
  `@env/SSH_KNOWN_HOSTS_FILE` and restored to the configured paths.

Not mirrored:

- any path whose part below `D` starts with `.`. This covers the scratch files
  of atomic writes (`.recovery-*`, `.peer-create-*`, `.credential-key-*`,
  `.ssh-trust-*`) and the storage bookkeeping described below;
- names ending in `.tmp`, `.temp` or `.runtime.lock`. The runtime lock holds a
  PID; a restored copy would block offline recovery;
- symlinks and special files. Each one is skipped with a warning;
- `TUNNEL_STATE_FILE`, `TUNNEL_BIN_DIR` (downloaded `cloudflared`/`ngrok`
  binaries are downloaded again) and `ssl_temp/` (recreated from `data.json` at
  every start), even when they are inside `D`. The same holds for a `TMPDIR`
  inside `D` that does not exist yet at startup; an existing one is refused
  (see [Configuration](#configuration));
- everything outside `D`: DuckDNS certificates in `/etc/amnezia`, `~/.acme.sh`,
  certificate files referenced by **Settings → SSL** paths, `~/.ssh/known_hosts`,
  `/var/lib/cloudflare-warp` in the WARP image, and `SECRET_KEY`.

A warning is logged above 5000 files or 256 MiB. Mirroring still works, but a
cold start takes longer. The panel never prunes `data.json.recovery/`, so it
only grows.

Each snapshot describes the whole directory. A file removed locally is missing
from the next snapshot, so removals reach the bucket too. The guards below stop
accidental mass removals. A restore never deletes local files; it moves them
aside.

Bookkeeping files in `D` stay local and are never uploaded:

| Name | Purpose |
| --- | --- |
| `.s3-owner.lock` | Lock held for the process lifetime; a second panel on the same directory refuses to start. |
| `.s3-sync-state.json` | Endpoint (scheme, host and port only), bucket, prefix, generation, ID and file list of the last committed snapshot. It lets a restarted container continue without a full download and shows when the bucket went back to an older generation. A state file written for another endpoint, bucket or prefix counts as foreign. |
| `.s3-restore-pending` | Present only while a restore runs; an interrupted restore resumes. |
| `.s3-displaced-<UTC time>/` | Local files that a restore replaced or that are absent from the snapshot. Inspect and delete them yourself. |

## Bucket layout and encryption

Everything lives under `<bucket>/<prefix>`:

| Object | Content |
| --- | --- |
| `manifest` | The current snapshot: generation number, commit ID, owner, time, panel version, lease, and for every file its blob name, SHA256 and size. |
| `blobs/<name>` | File contents, compressed and encrypted. Identical content is stored once. |
| `history/<generation>-<commit>` | Snapshots of the manifest, at most one per hour, kept for `PANEL_S3_HISTORY_DAYS`. The generation is padded to 12 digits. |
| `probe/<random>` | Short-lived objects used by the conditional-write check at startup and before `push`. |

Encryption happens in the panel, before upload. Two keys are derived with
HKDF-SHA256 from `PANEL_S3_ENCRYPTION_KEY`: one for AES-256-GCM, one for naming
blobs. A blob is named by an HMAC-SHA256 of its content, so names reveal nothing
without the key. Every object uses a fresh random nonce. The authenticated data
ties each blob to its name, the manifest to its prefix, and each history
snapshot to its own name. A forged or changed object, or one copied to another
name, fails authentication; this includes a history snapshot copied over the
manifest. The provider sees object sizes, counts and timing, and the generation
numbers in history names. Server-side encryption (SSE) may be enabled as well,
but it is not required.

With a wrong key the manifest fails authentication and the panel refuses to
start (`encryption key does not match bucket`). The same refusal, whose message
also names a replaced manifest as a possible cause, happens when the manifest
was overwritten with another object, for example a copied history snapshot.
Nothing is overwritten. A running panel notices such a manifest at its next
commit and exits with code 3, like a fenced one.

Authentication cannot tell an older, genuine manifest from the current one. What
is detected in that case is described under
[Limitations and security](#limitations-and-security).

## How it works

### Startup

Startup runs in `python app.py` before the panel reads any state:

1. Check the configuration and `D`, and take the local owner lock.
2. Check whether the provider supports conditional writes (see
   [Provider notes](#provider-notes)). This is the first request to the bucket,
   so a wrong bucket, region or access key usually stops the start here, with
   the same hints as in the next step.
3. Read the manifest. Temporary errors are retried for up to
   `PANEL_S3_STARTUP_TIMEOUT` seconds. Errors that retrying cannot fix stop the
   start at once, with a hint for the common ones: `NoSuchBucket`,
   `AccessDenied`, `InvalidAccessKeyId`, `SignatureDoesNotMatch`, a wrong region
   (`AuthorizationHeaderMalformed`), `InvalidBucketName`, `ExpiredToken` and
   similar. The panel never starts with empty state because the bucket was not
   reachable.
   - **No manifest, empty prefix**: first start. The first snapshot is taken
     from the current local directory: empty for a fresh install, or your
     existing files when migrating.
   - **No manifest, but `blobs/` or `history/` objects exist**: the manifest was
     deleted or the prefix is wrong. The panel refuses to start unless
     `PANEL_S3_ALLOW_REINIT=1`.
   - **The manifest has an older generation than this directory already
     synced** (its state file says so): an older manifest was put back, from
     bucket versioning or by someone with write access to the bucket. The panel
     logs CRITICAL (`the S3 manifest went back from generation X to Y`) and
     refuses to start. `PANEL_S3_RESTORE_OVERWRITE=1` accepts the older
     manifest for one start and always restores it with a cold restore, even
     when this directory wrote that manifest: local files that differ are moved
     to `D/.s3-displaced-<UTC time>/`, so the newer local state is not committed
     on top of the rollback. The same check runs again after a lease wait.
   - **The manifest was written by this same directory** (the container
     restarted inside the same pod and the `emptyDir` survived): warm start.
     Local files are kept, because they may hold changes that were not uploaded
     yet.
   - **Otherwise**: wait until the previous owner released its lease or the
     lease is stale, then do a cold restore.
4. If `data.json` or any recovery snapshot contains sealed credentials, the
   credential key must be present and must open them. Otherwise the panel
   refuses to start. Without this check the panel would silently create a new
   key and every sealed SSH credential would become unreadable.
5. Claim the prefix: commit a new generation that records this process as the
   lease owner. Then the panel starts as usual.

The `SIGTERM` handler is installed before step 1: in a container Python runs as
PID 1, and the kernel drops a `SIGTERM` that has no handler. A `SIGTERM` during
startup, for example a rollout while the pod waits for a lease, ends the process
with exit code 0 without claiming the prefix. It takes effect at once while the
panel waits or retries, otherwise after the file being downloaded or just before
the claim. An interrupted cold restore resumes at the next start. If the signal
arrives while the claim is being written, the panel releases the lease right
after it and exits.

### Cold restore

A cold restore never deletes anything:

- files whose content already matches are skipped, so an interrupted restore
  resumes where it stopped;
- other files are downloaded, checked against their SHA256 and size, and
  written atomically. Files get mode `0600`, directories `0700`, as the panel
  requires;
- local files that differ from the snapshot or are absent from it are moved to
  `D/.s3-displaced-<UTC time>/` and logged.

The restore refuses to run when `D` already holds a `data.json` that did not
come from this bucket: there is no sync state for this endpoint, bucket and
prefix (the state file is missing, unreadable or written for another endpoint,
bucket or prefix), no interrupted restore, and its content differs from the
snapshot. This catches migrating into a non-empty prefix, a changed prefix over
an old volume, a volume moved to another provider whose bucket has the same name
and prefix, and a staged backup tree. `PANEL_S3_RESTORE_OVERWRITE=1` allows it;
the local files are moved aside, not deleted.

### Continuous sync

Every `PANEL_S3_SYNC_INTERVAL` seconds a background thread:

1. scans `D` (size, times and inode of every file);
2. reads and hashes files that changed, and uploads new blobs;
3. scans again. If anything changed during the upload, it repeats the round;
4. replaces the manifest with one PUT.

The manifest PUT is the commit. A reader sees either the previous snapshot or
the new one, never a mix. Nothing is uploaded when nothing changed. If no commit
happened for `PANEL_S3_LEASE_INTERVAL` seconds, the next round makes a heartbeat
commit with the same files to renew the lease. Heartbeats come from this same
loop, so `PANEL_S3_LEASE_INTERVAL` must be at least 3 × `PANEL_S3_SYNC_INTERVAL`;
otherwise the panel refuses to start, because a running panel could look stale
to the next one.

S3 errors are retried with a growing pause (up to 60 seconds). The panel keeps
working locally meanwhile, and the status shows the last error. Changes since
the last successful commit are what you lose if the node dies.

Guards refuse a commit that looks like data loss:

- `data.json` disappeared;
- users plus servers dropped from more than zero to zero;
- a recovery snapshot (a `.json` file under a `*.recovery/` directory)
  disappeared;
- the credential key changed or disappeared after it existed (the panel has no
  key rotation);
- the snapshot would contain `data.json` or recovery snapshots with sealed
  credentials, but no credential key.

A refused commit is logged as CRITICAL and the status shows `guard:<name>`. The
bucket keeps the last good snapshot and heartbeats continue. If the change is
intended, apply it offline with `push --allow-shrink`
([Offline maintenance](#offline-maintenance-and-recovery)), or set
`PANEL_S3_ALLOW_SHRINK=1` and make the change again. The variable lets one
guarded commit through per start. In Kubernetes, changing the variable starts a
new pod, which restores the last good snapshot, so the change has to be
repeated. Remove the variable afterwards.

If the manifest disappears from the bucket while the panel runs, the panel logs
CRITICAL, uploads every file again and recreates the manifest.

### Lease and fencing

The manifest records the lease owner and whether the lease was released. Every
commit is a conditional write: it succeeds only if the manifest is still the one
this process wrote last. If another process wrote in between, the panel is
**fenced**: it logs CRITICAL with the other owner and exits with code 3. The
restarted container sees a live foreign lease and waits instead of overwriting.

A network error does not make the panel fence itself. Before each PUT the
commit ID is saved locally. After a timeout or a conflict, the panel reads the
manifest back and checks whether its write already landed.

A new process that does not continue this directory waits while the lease is
held and younger than three lease intervals of its owner (90 seconds by
default). The age is measured with the server's clock (`Date` minus
`Last-Modified`), so pod clocks do not need to agree. After a graceful stop the
lease is released and the next pod starts at once. After a crash or `SIGKILL`
it waits up to the stale limit. The wait itself has no time limit and is logged
every interval: if a pod keeps waiting, another panel is writing to the same
prefix.

The lease does not replace `replicas: 1` with the `Recreate` strategy. With
`RollingUpdate`, the new pod waits behind the old pod's lease and the rollout
never finishes.

### Shutdown

On `SIGTERM` (and on a normal shutdown) the panel makes a final commit that
releases the lease. First it lets running requests finish writing:

- By default uvicorn handles the signal: it stops accepting connections and
  waits for open requests, at most 20 seconds in S3 mode. Then the shutdown hook
  asks for the final commit. It asks at once and does not queue behind slow SSH
  calls in the panel's thread pool.
- With `PANEL_FRONT=1` uvicorn runs without signal handling, so the panel's own
  `SIGTERM` handler waits instead: until the mirrored files have not changed for
  3 seconds, at most 15 seconds. The front passes on no new requests meanwhile,
  and the sync keeps committing as usual. Then the handler asks for the final
  commit.

The shutdown hook, the `SIGTERM` handler and the exit handler all wait for the
same final commit, with one 25-second deadline counted from the first request.
The worst case is therefore 20 + 25 = 45 seconds (15 + 25 = 40 seconds with
`PANEL_FRONT=1`). Give the pod `terminationGracePeriodSeconds: 60` or more. The
final commit is best effort; the continuous sync is the main guarantee. If it
does not finish in time, the lease stays held and the next pod waits until it is
stale.

### History and cleanup

After a commit that changed files, at most once per hour, a snapshot of the
manifest is written to `history/`. It is sealed under its own name, so it cannot
pass as the current manifest, and it is never modified. History is kept for
`PANEL_S3_HISTORY_DAYS` days. An earlier generation can be downloaded with
`pull --generation N` and pushed back as the current state
([Offline maintenance](#offline-maintenance-and-recovery)). Besides the current
generation, only generations that have a snapshot can be pulled. Their numbers
are part of the object names under `history/`, which any S3 client can list.

Once an hour the panel deletes blobs that neither the current manifest nor the
kept history uses and that are older than one hour by the server's clock. Before
each batch it checks that the manifest still belongs to it. A fenced process,
and a process that created the prefix, never delete anything. Cleanup errors
are logged but not shown as sync errors.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PANEL_STORAGE` | `local` | `local` keeps state on disk only. `s3` enables everything below. Any other value stops the start. |
| `PANEL_S3_BUCKET` | required | Bucket name. |
| `PANEL_S3_PREFIX` | `amnezia-panel/` | Key prefix inside the bucket. A leading `/` is removed and a trailing `/` added; `.` and `..` segments are rejected. One panel per prefix. |
| `PANEL_S3_ENDPOINT_URL` | AWS | `http(s)://` URL of an S3-compatible service. User info (`user:pass@`), query strings and fragments are rejected. `AWS_ENDPOINT_URL*` settings are ignored. Keep the spelling stable: a different host alias or an explicit `:443` for the same service counts as another endpoint, so the next start does a cold restore (and refuses while the local `data.json` has unsynced changes). |
| `PANEL_S3_REGION` | required | Signing (SigV4) region, for example `us-east-1` for MinIO, `ru-msk` for VK Cloud, `ru-central1` for Yandex Object Storage. |
| `PANEL_S3_ACCESS_KEY_ID`, `PANEL_S3_SECRET_ACCESS_KEY` | unset | Required when `PANEL_S3_ENDPOINT_URL` is set. On AWS without them the standard credential chain is used (IRSA, EKS Pod Identity, instance profile). `PANEL_S3_ACCESS_KEY_ID_FILE` and `PANEL_S3_SECRET_ACCESS_KEY_FILE` read the value from a file. |
| `PANEL_S3_ADDRESSING_STYLE` | `path` with an endpoint, otherwise `auto` | `auto`, `path` or `virtual`. |
| `PANEL_S3_ENCRYPTION_KEY` | required | Base64 of exactly 32 random bytes. `PANEL_S3_ENCRYPTION_KEY_FILE` reads it from a file. Losing it means losing the bucket state. |
| `PANEL_S3_SYNC_INTERVAL` | `5` | Seconds between local scans (at least 0.01). |
| `PANEL_S3_LEASE_INTERVAL` | `30` | Heartbeat in whole seconds. A lease is stale after three intervals. Must be at least 3 × `PANEL_S3_SYNC_INTERVAL`, otherwise the panel refuses to start. |
| `PANEL_S3_STARTUP_TIMEOUT` | `120` | Seconds to keep retrying an unreachable bucket at startup. Waiting for a lease is separate. |
| `PANEL_S3_FENCING` | `auto` | `auto` uses conditional writes when the provider passes the startup check, and otherwise runs unfenced with a loud warning. `required` refuses to start without them. |
| `PANEL_S3_HISTORY_DAYS` | `7` | Days to keep the hourly manifest snapshots for `pull --generation`. `0` keeps none. |
| `PANEL_S3_ALLOW_REINIT` | unset | `1` allows a new first snapshot although `blobs/` or `history/` objects exist. |
| `PANEL_S3_RESTORE_OVERWRITE` | unset | `1` allows a cold restore over a foreign local `data.json` (moved aside, not deleted) and accepts a manifest whose generation went back, restoring it with a cold restore (see [Startup](#startup)). |
| `PANEL_S3_ALLOW_SHRINK` | unset | `1` lets one guarded commit through per start. |

The three `ALLOW`/`OVERWRITE` switches are meant for a single start. Every use
is logged. Remove them again after that start.

Existing variables that matter in S3 mode:

- `DATA_FILE` must be set explicitly. `D` must not be `/`, and must not be the
  application directory, the temp directory (`TMPDIR` when that directory
  exists, otherwise usually `/tmp`) or `$HOME`, or a parent of any of them. The
  file name must not start with `.`. `D` is created with mode `0700` if it is
  missing. These rules exist because the whole of `D` is mirrored and restored.
- Set `SECRET_KEY`; otherwise every restart logs all users out.
- `PANEL_BIND_ALL_INTERFACES=1` makes the container port reachable.

After reading them, the panel removes the access keys and the encryption key
(and their `_FILE` variants) from its own environment, so tunnel binaries and
`acme.sh` started by the panel do not inherit them.

### Generating the encryption key

```sh
openssl rand -base64 32
# or, without openssl:
python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Store the key in a password manager or offline, **outside the cluster** and
separately from the bucket credentials. Without it nobody can read the bucket,
including you. A different key on an existing prefix makes the panel refuse to
start. There is no built-in key rotation.

## Kubernetes example

This is an **example**. Adjust names, the image tag, bucket settings and sizes.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: amnezia-panel
type: Opaque
stringData:
  SECRET_KEY: "<output of: openssl rand -hex 32>"
  PANEL_S3_ACCESS_KEY_ID: "<access key id>"
  PANEL_S3_SECRET_ACCESS_KEY: "<secret access key>"
  PANEL_S3_ENCRYPTION_KEY: "<output of: openssl rand -base64 32>"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: amnezia-panel
data:
  DATA_FILE: /app/data/data.json
  PANEL_BIND_ALL_INTERFACES: "1"
  PANEL_STORAGE: s3
  PANEL_S3_BUCKET: my-panel-bucket
  PANEL_S3_PREFIX: amnezia-panel/
  PANEL_S3_ENDPOINT_URL: https://storage.yandexcloud.net   # omit on AWS
  PANEL_S3_REGION: ru-central1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amnezia-panel
  labels:
    app: amnezia-panel
spec:
  replicas: 1              # one writer per prefix; never scale above 1
  strategy:
    type: Recreate         # the old pod must stop (and release the lease) first
  selector:
    matchLabels:
      app: amnezia-panel
  template:
    metadata:
      labels:
        app: amnezia-panel
    spec:
      terminationGracePeriodSeconds: 60   # final commit + uvicorn drain
      automountServiceAccountToken: false # the panel does not use the Kubernetes API
      containers:
        - name: panel
          image: ghcr.io/prvtpro/amnezia-panel:latest   # pin a version tag
          ports:
            - name: http
              containerPort: 5000  # Settings -> SSL panel port; keep in sync
          envFrom:
            - configMapRef:
                name: amnezia-panel
            - secretRef:
                name: amnezia-panel
          volumeMounts:
            - name: data
              mountPath: /app/data
            - name: tmp
              mountPath: /tmp
          # TCP probes: with an access allowlist or domain-only mode the panel
          # answers unknown HTTP requests with a 404, which would fail httpGet.
          startupProbe:
            tcpSocket:
              port: http
            periodSeconds: 10
            failureThreshold: 60   # 10 min: S3 retries + lease wait + restore
          readinessProbe:
            tcpSocket:
              port: http
            periodSeconds: 10
          livenessProbe:
            tcpSocket:
              port: http
            periodSeconds: 20
            failureThreshold: 6
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 1Gi         # state plus displaced copies
        - name: tmp
          emptyDir:
            sizeLimit: 2Gi         # protocol backups and instance-copy images
---
apiVersion: v1
kind: Service
metadata:
  name: amnezia-panel
spec:
  selector:
    app: amnezia-panel
  ports:
    - name: http
      port: 80
      targetPort: http
```

Notes:

- **Startup budget.** The port opens only after the bucket was read, the lease
  waited for and the files restored. The startup probe must cover
  `PANEL_S3_STARTUP_TIMEOUT` (120 s), a stale lease (90 s) and the download.
  Raise `failureThreshold` for large states or slow storage.
- **TLS.** Terminate TLS at the Ingress (for example with cert-manager) and
  keep the panel's own HTTPS off. Certificate files referenced by path in
  **Settings → SSL** and DuckDNS certificates are not mirrored; after a move to
  another node the panel would fall back to HTTP.
- **Disks.** Use disk-backed `emptyDir` volumes. `medium: Memory` counts against
  the pod's memory and gains nothing. Copying an instance can put hundreds of MB
  into `/tmp`.
- **Credential key.** Do not mount `CREDENTIAL_KEY_FILE` from a Secret volume.
  Secret volumes are symlinks with group-readable modes, and the panel refuses
  such a key. Leave the key at its default place in `D`; it is mirrored
  encrypted with the S3 encryption key.
- **Secret files.** Instead of environment variables you can mount the Secret
  as a volume (`defaultMode: 0400`) and use the `PANEL_S3_*_FILE` variables.
- **Entrypoint.** Keep the image's `python3 app.py`. In S3 mode the panel
  refuses to start under `uvicorn app:app` or with several workers.
- A StatefulSet with one replica also works, but it is not needed.

## Bucket and credentials

Use a private bucket, ideally a dedicated one, and a dedicated access key.
Least-privilege policy (AWS IAM; replace the bucket and prefix):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PanelObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::my-panel-bucket/amnezia-panel/*"
    },
    {
      "Sid": "PanelListing",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-panel-bucket",
      "Condition": {"StringLike": {"s3:prefix": ["amnezia-panel/*"]}}
    }
  ]
}
```

- `s3:ListBucket` is required. S3 reports a missing object as `404 NoSuchKey`
  only to callers that may list the bucket; everyone else gets
  `403 AccessDenied`. The panel must tell "no manifest yet" from "forbidden",
  and refuses to start on `AccessDenied`. If the very first start against an
  empty prefix stops with `AccessDenied` although the keys are right, your
  provider does not apply the prefix condition to that check: grant
  `s3:ListBucket` on the (dedicated) bucket without the condition.
- Do **not** add a lifecycle rule that expires objects under the prefix. A blob
  of a file that has not changed for months is still in use; expiring it breaks
  the next restore. The panel cleans up after itself.
- Do **not** enable Object Lock or retention on the bucket. They block cleanup
  and can reject the panel's uploads.
- Versioning is optional extra protection. The heartbeat alone rewrites the
  manifest about 2880 times a day with the default `PANEL_S3_LEASE_INTERVAL`,
  so add a `NoncurrentVersionExpiration` rule of a few days. Old versions are genuine
  manifests: whoever can write to the bucket can put one back (see
  [Limitations and security](#limitations-and-security)).
- S3-compatible providers have their own policy formats (bucket ACLs, service
  accounts with roles, MinIO policies). Grant the same actions: get, put and
  delete objects under the prefix, and list the bucket.

## Provider notes

| Provider | `PANEL_S3_ENDPOINT_URL` | `PANEL_S3_REGION` | Notes |
| --- | --- | --- | --- |
| AWS S3 | unset | bucket region | Supports conditional writes. Without access keys the standard credential chain is used. |
| MinIO | e.g. `http://minio.minio.svc:9000` | `us-east-1` unless MinIO is configured otherwise | Use path-style addressing, the default when an endpoint is set. |
| VK Cloud | `https://hb.ru-msk.vkcloud-storage.ru` | `ru-msk` | The endpoint must match the account's region. |
| Yandex Object Storage | `https://storage.yandexcloud.net` | `ru-central1` | |
| Others (Ceph RGW, Selectel, …) | the provider's S3 endpoint | the region the provider documents | |

**Conditional writes.** Fencing depends on `If-Match` / `If-None-Match` on PUT.
Support differs between providers and versions, so the panel checks at every
start, and before every `push`, by writing one object under `<prefix>probe/`
three times. The status shows the result as `fencing: enforced` or
`fencing: unfenced`.

A provider counts as unsupported when it ignores the conditions, answers
`501 NotImplemented`, or rejects a conditional header with a 400 error. Errors
that point to a wrong configuration stop the start at once, in both modes, with
the hints listed under [Startup](#startup): a wrong region
(`AuthorizationHeaderMalformed`), `InvalidBucketName`, `AccessDenied`,
`ExpiredToken` and similar. Any other 400 error on the first probe write (except
temporary ones such as `RequestTimeout`) is checked once more: the panel writes
the same probe object again without the conditional header.

- If that plain write succeeds, the provider rejects only the conditional
  header, so it counts as unsupported (see the two modes below).
- If it fails as well, the problem is not the header. The start stops with an
  error that names the first error code, and the second one if it differs.

The probe object is deleted afterwards in both cases.

- `PANEL_S3_FENCING=auto` (default): an unsupported provider is used anyway,
  with a loud warning. Each commit then reads the manifest before writing. This
  narrows, but does not close, the window in which two panels could overwrite
  each other, so `replicas: 1` with `Recreate` is essential.
- `PANEL_S3_FENCING=required`: the panel refuses to start without conditional
  writes.

The panel never switches from enforced to unfenced while running.

**Compatibility.** Some S3-compatible services reject the checksum headers that
newer AWS SDKs add by default, and some MinIO and Ceph versions reject batch
deletes sent with them. The panel therefore sends checksums only when an
operation requires them and deletes objects one by one.

## Migrating from a Docker Compose volume

The first start against an **empty** prefix takes its snapshot from whatever is
in `D`. So migrating means starting the existing volume once in S3 mode:

1. Download a complete backup ZIP (the download button of the backup card in
   **Settings**, see [PANEL_BACKUP.md](PANEL_BACKUP.md)) and keep it with your
   deployment secrets.
2. Create the bucket, the access key and the encryption key.
3. Put the S3 variables in a private file next to `docker-compose.yml`, for
   example `panel-s3.env` with mode `0600`:

   ```
   PANEL_STORAGE=s3
   PANEL_S3_BUCKET=my-panel-bucket
   PANEL_S3_PREFIX=amnezia-panel/
   PANEL_S3_ENDPOINT_URL=https://storage.yandexcloud.net
   PANEL_S3_REGION=ru-central1
   PANEL_S3_ACCESS_KEY_ID=...
   PANEL_S3_SECRET_ACCESS_KEY=...
   PANEL_S3_ENCRYPTION_KEY=...
   ```

   and an override `docker-compose.s3.yml`:

   ```yaml
   services:
     amnezia_panel:
       env_file: panel-s3.env
       stop_grace_period: 60s
   ```

   The bundled Compose file already sets `DATA_FILE=/app/data/data.json` on the
   `amnezia_data` volume. Use an image version that includes S3 storage.
4. Restart with the override. The first start uploads the volume as the first
   generation:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
   docker compose logs -f amnezia_panel
   ```

   Check the **Settings** storage card: generation, number of files and last
   sync.
5. Stop it gracefully, so the lease is released:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.s3.yml stop -t 60
   ```

6. Start the Kubernetes Deployment. The new pod restores the snapshot into its
   `emptyDir`.
7. Keep the old volume until the new panel is verified, but do not start the
   Compose panel again. With S3 enabled it would wait for the pod's lease;
   without S3 it would silently drift away from the bucket.

If the prefix already has a manifest, the start with a non-empty volume is
refused (see [Cold restore](#cold-restore)). Use a new prefix for the migration.

## Offline maintenance and recovery

Some work must happen while the panel is stopped: clearing a disaster hold,
archiving a `lifecycle-uncertain` fence, a JSON disaster restore with
`scripts/panel_recovery.py`, restoring a complete backup ZIP, or going back to an
earlier generation. Without a persistent volume this works as
**scale to 0 → pull → offline tools → push → scale to 1**. `aws s3 cp` cannot
help, because every object is encrypted.

The pulled directory holds plaintext secrets (SSH credentials, the credential
key, WireGuard private keys in the peer-creates journal). Work in a temporary
pod, as below, and delete it afterwards.

1. Stop the panel and wait until its pod is gone:

   ```sh
   kubectl scale deployment/amnezia-panel --replicas=0
   kubectl wait --for=delete pod -l app=amnezia-panel --timeout=180s
   ```

   ("no matching resources found" means the pod is already gone.)

   A graceful stop releases the lease. After a crash, wait
   3 × `PANEL_S3_LEASE_INTERVAL` before pushing.
2. Start a maintenance pod from the **same image tag** and the same
   configuration, without starting the panel:

   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: amnezia-panel-maint
   spec:
     restartPolicy: Never
     automountServiceAccountToken: false
     containers:
       - name: maint
         image: ghcr.io/prvtpro/amnezia-panel:latest   # same tag as the Deployment
         command: ["sleep", "infinity"]
         envFrom:
           - configMapRef:
               name: amnezia-panel
           - secretRef:
               name: amnezia-panel
         volumeMounts:
           - name: work
             mountPath: /work
     volumes:
       - name: work
         emptyDir: {}
   ```

   ```sh
   kubectl apply -f maint-pod.yaml
   kubectl exec -it amnezia-panel-maint -- sh
   ```

3. Inside the pod, check the bucket and download a snapshot into a new
   directory. `status` does not change anything. `pull` never takes the lease;
   it writes files with mode `0600`, directories `0700`, the same layout as `D`,
   files from outside `D` under `@env/`, and `.s3-pull.json` with the snapshot
   it came from:

   ```sh
   cd /app
   python panel_storage.py status
   python panel_storage.py pull /work/state                   # current snapshot
   # python panel_storage.py pull /work/state --generation N  # an earlier one
   export DATA_FILE=/work/state/data.json
   ```

   If the Deployment sets `CREDENTIAL_KEY_FILE` or `SSH_KNOWN_HOSTS_FILE`
   outside `D`, point them at `/work/state/@env/CREDENTIAL_KEY_FILE` and
   `/work/state/@env/SSH_KNOWN_HOSTS_FILE` for the offline tools.
4. Run the offline tools on `/work/state` exactly as described in
   [PEER_RECOVERY.md](PEER_RECOVERY.md) and [PANEL_BACKUP.md](PANEL_BACKUP.md).
   For example, to finish a reconciled disaster restore:

   ```sh
   python scripts/panel_recovery.py --data-file /work/state/data.json \
     --finish-restore ORIGINAL_RESTORE_ID --operation-id NEW_32_LOWERCASE_HEX \
     --expected-sha256 "$(sha256sum /work/state/data.json | cut -d' ' -f1)" \
     --confirm 'NODES RECONCILED; UNVERIFIED COUNTERS ACCEPTED'
   ```

   To archive a `lifecycle-uncertain` fence, move
   `/work/state/data.json.lifecycle-uncertain.json` out of the tree and copy it
   off the pod as incident evidence (`kubectl cp`).
5. Upload the result as a new generation:

   ```sh
   python panel_storage.py push /work/state
   ```

   `push` refuses when `.s3-pull.json` is missing, when someone committed after
   your pull, or when the lease is neither released nor stale. It runs the same
   guards as the panel. If a guard refuses a removal you made on purpose (for
   example pushing an earlier generation or an older backup that lacks newer
   recovery snapshots), repeat with `--allow-shrink`. Archiving the
   `lifecycle-uncertain` fence trips no guard and needs no flag. A refused
   `push` prints the reason and exits with code 2; the current snapshot stays as
   it was. The pushed snapshot has a released lease, so the next pod restores it
   at once.
6. Copy out anything you need, then clean up and start the panel:

   ```sh
   kubectl delete pod amnezia-panel-maint
   kubectl scale deployment/amnezia-panel --replicas=1
   ```

The same commands work from a workstation with a checkout of the same panel
version, `pip install -r requirements.txt` and the same `PANEL_STORAGE=s3` and
`PANEL_S3_*` variables exported.

### Restoring a complete backup ZIP into the bucket

Copy the archive into the maintenance pod (`kubectl cp`), then verify and stage
it into a new directory as described in [PANEL_BACKUP.md](PANEL_BACKUP.md).
Reconcile the nodes and run `--finish-restore` on
`/work/restored-panel/state/data.json` before going on. Then build the tree to
push on top of the current snapshot's pull record:

```sh
python panel_storage.py pull /work/current
mkdir -m 700 /work/new
cp /work/current/.s3-pull.json /work/new/
cp -a /work/restored-panel/state/. /work/new/
cp /work/restored-panel/trust/ssh_known_hosts /work/new/ssh_known_hosts
python panel_storage.py push /work/new --allow-shrink
```

`--allow-shrink` is usually needed, because an older archive lacks recovery
snapshots that the current state has. The commands assume the default layout.
If the Deployment sets `CREDENTIAL_KEY_FILE` or `SSH_KNOWN_HOSTS_FILE` outside
`D`, put the key at `/work/new/@env/CREDENTIAL_KEY_FILE` and the trust file at
`/work/new/@env/SSH_KNOWN_HOSTS_FILE` instead. `trust/system_known_hosts` is
not part of the panel state; reconcile it separately.

## Status and logs

In S3 mode, administrators see a read-only **Storage (S3)** card in
**Settings**, below the backup card: bucket, prefix, endpoint, region, fencing,
generation, files and size, last sync, last error, and a warning when the
process is fenced. The card is hidden in local mode and from support accounts.
Settings come only from the environment and cannot be edited there.

The same data is available as JSON to administrators (session or API token):

```sh
curl -H "Authorization: Bearer $TOKEN" http://your-panel:5000/api/settings/storage
```

```json
{
  "backend": "s3",
  "bucket": "my-panel-bucket",
  "prefix": "amnezia-panel/",
  "endpoint": "https://storage.yandexcloud.net",
  "region": "ru-central1",
  "fencing": "enforced",
  "generation": 1842,
  "files": 57,
  "bytes": 3145728,
  "last_commit_at": "2026-11-16T10:21:05Z",
  "last_error": null,
  "last_error_at": null,
  "fenced": false,
  "pending": false,
  "lease_owner": "amnezia-panel-6d5f8b7c9-x2k4q-1-1a2b3c4d"
}
```

(Values are illustrative.) `endpoint` contains only scheme, host and port.
`last_commit_at` and `last_error_at` are UTC times in the form
`2026-11-16T10:21:05Z`. `generation` is `null` until the prefix is claimed.
`last_error` is short: an error code such as `AccessDenied (403)`,
`guard:<name>` or `fenced`, or a one-line message, never secrets. In local mode
the answer is `{"backend": "local", "path": "<D>"}`.

The container log shows every startup decision (first start, warm start, lease
wait, cold restore, displaced files), the fencing result, guard refusals and
S3 errors. A refused start ends the process with exit code 1, and the last line
of its output names the reason. What to look for:

- CRITICAL lines: a refused commit (guard), a fenced process, a refused
  re-initialisation, a manifest that went back to an older generation, a
  manifest that disappeared while the panel was running;
- a pod that keeps logging a lease wait: another panel writes to the prefix;
- exit code 3 in `kubectl describe pod`: the process was fenced;
- a warning that fencing is unsupported: see [Provider notes](#provider-notes).

## Limitations and security

- **Keep the encryption key outside the cluster.** It is the only way to read
  the bucket. Whoever has the key and read access to the bucket has every
  secret of the panel: the credential key (and so all sealed SSH credentials),
  SMTP, Telegram and Remnawave tokens, `ssl.key_text`, and WireGuard private
  keys. In the bucket all of it is protected by this one key.
- **Limit write access to the bucket.** Authenticated encryption stops forged,
  changed or swapped objects, including a history snapshot copied over the
  manifest. It cannot stop someone with write access from putting back an
  older, genuine manifest: one captured earlier, or an old version kept by
  bucket versioning. A pod that still has its state file notices that the
  generation went back and refuses to start. A fresh pod (a new `emptyDir`) has
  no state file, cannot tell, and restores that older state. Give write access
  to the prefix only to the panel's own key.
- **Loss window.** Changes made after the last successful commit are lost if
  the node dies. Normally that is a few seconds; during an S3 outage it grows.
  The status shows the last commit time.
- **One writer per prefix.** Never run two panels on one prefix (staging and
  production need different prefixes). Keep `replicas: 1` and `Recreate`.
- **Not high availability.** A pod moved to another node waits for the lease
  and downloads the whole state before it opens the port.
- **TLS belongs at the Ingress.** DuckDNS / `acme.sh` certificates and their
  renewal, and certificate files referenced by path, are not covered.
- **The WARP image's own state** (`/var/lib/cloudflare-warp`) is not covered.
  Register WARP again after the pod moves, or keep that directory on a volume.
- **PyInstaller builds** are local-only. They do not bundle the S3 client.
- Anyone who can read the Secret or exec into the pod can read the S3 keys,
  even though the panel removes them from its own environment. Restrict RBAC.
- Displaced copies (`D/.s3-displaced-*`) disappear with the `emptyDir`. Copy
  them out with `kubectl cp` if you need them.
