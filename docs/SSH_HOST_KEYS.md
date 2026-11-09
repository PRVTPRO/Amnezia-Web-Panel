# Trusted SSH host keys

## Server onboarding and endpoint changes

**Add Server** and **Edit Server** include **Inspect SSH key**. Enter the exact
hostname/IP (unbracketed IPv6) and SSH port, inspect, then compare the displayed
algorithm and SHA256 fingerprint through an independent trusted console. A
changed key can indicate interception: investigate before explicitly confirming.
Inspection and confirmation only perform SSH key exchange, never authentication.
After confirming, click **Connect / Save** to test the SSH credentials. Only a
successful authenticated connection adds/edits the inventory entry. A bad password
or cancelled add leaves inventory unchanged; the independently approved pin stays
trusted. It is not removed as an implicit rollback of a credential failure.

Draft enrollment does not require a temporary server in `data.json`. Five-minute
signed tokens bind the exact endpoint, algorithm, public key, previous trust
snapshot and (for edits) saved connection settings and stable server UID. Changing
an endpoint or saved credentials requires re-inspection. Confirmation re-probes,
then checks expiry, inventory and trust again before atomic persistence. A
reordered inventory is resolved by UID; a deleted/edited target is rejected.
Browser endpoint edits discard pending tokens and obsolete asynchronous results.
Only administrators may inspect/confirm; same-origin restrictions also apply.

No inventory lock is held during key exchange or add/edit SSH authentication.
Short trust commits are serialized with inventory writes, including on request
cancellation. These are in-process locks: use one panel writer per data/trust file.
The existing server-page recovery controls continue to use the same trust code.
A saved pin, TCP reachability and a successful authenticated SSH connection are
different states; saving trust does not claim authentication succeeded. Trust-file
errors, authentication failures and network/cooldown errors remain failures and
never trigger automatic trust or credential fallback.

## v1.7.8 — web enrollment and migration

Administrators can open a server page and use **SSH host key → Inspect SSH key**,
including when statistics/protocol loading fails. Unknown and changed keys have
distinct warnings; the server list no longer equates TCP reachability with trusted
SSH. Inspection performs SSH key exchange only: no username, password, private
key or agent authentication is sent.

Server-list refreshes check TCP reachability and local pin presence only, not
live SSH identity (`ssh_verified: false`); use **Inspect SSH key** to check the
current fingerprint. Refreshing a list never starts an extra SSH key exchange.
Inspection uses the same pinned-algorithm preference as Paramiko SSHClient,
so an existing RSA pin is not falsely reported changed merely because the
server also offers Ed25519 or ECDSA.

Compare the displayed algorithm and SHA256 fingerprint with an independent VPS
console (use the matching `/etc/ssh/ssh_host_*_key.pub`, not necessarily Ed25519).
For replacement, investigate why the old fingerprint changed. Tick the explicit
verification checkbox, then **Trust key and retry**. The page reloads and retries
normal operations with a fresh connection and reset cooldown. No VPN clients,
VPN keys or configurations are changed.

Confirmation is signed, expires after five minutes, binds the server UID,
host, port and exact candidate key, and re-probes before saving. Restarting the
panel invalidates outstanding confirmations. A changed candidate or endpoint
requires a fresh inspection. Only admins (not support users) may use these POST
endpoints; session/Bearer access controls and same-origin browser checks apply.

Confirmations also bind the previous trust entries: a concurrent administrator
change requires re-inspection rather than silently overwriting that decision.
Endpoint edits are serialized with confirmation in the panel process. Modern
browsers' same-origin Fetch Metadata permits TLS-terminating reverse proxies;
older browsers require the proxy to preserve the external request origin.

The default file is `ssh_known_hosts` beside the resolved `DATA_FILE`: beside
`app.py` for source installs, beside the executable for frozen installs, and
`/app/data/ssh_known_hosts` for the supplied Docker Compose deployment. Override
with `SSH_KNOWN_HOSTS_FILE`. A missing file can be created by enrollment; its
parent must be writable. Read-only mounts/files produce an explicit error; make
the persistent trust location writable if web enrollment is desired.

Updates are serialized within the panel process and use atomic file replacement.
Other endpoints (including aliases on shared lines) are preserved; hashed entries
and nonstandard ports are supported. Conflicting system `~/.ssh/known_hosts`
entries are never silently overridden: correct them independently as the panel
OS user, then inspect again. Run one panel writer per trust file; external editors
or multiple processes are not coordinated by the in-process lock.

Existing manually enrolled entries keep working. The manual procedure below is
still supported for read-only/operator-managed trust. `RejectPolicy` remains in
force; there is no automatic trust-on-first-use fallback.

SSH connections reject unknown or changed host keys before password/public-key
authentication. There is no automatic first-use enrollment. Existing SSH user
keys and passwords are still supported; server host trust is a separate check.

**Upgrade prerequisite:** enroll every managed SSH endpoint manually before upgrade
or use the administrator recovery controls after upgrade. Until enrollment,
operations fail closed. Do not restore `AutoAddPolicy` as a workaround.

Paramiko loads the panel process user's `~/.ssh/known_hosts` and a persistent
panel trust file, defaulting to `ssh_known_hosts` beside `DATA_FILE` (normally
`/app/data/ssh_known_hosts` in Docker). Set `SSH_KNOWN_HOSTS_FILE` to use another
file. An explicitly configured missing, unreadable or malformed file is an error.
Bind-mount an operator-managed file read-only, or place it in the existing
persistent data volume; do not rely on an ephemeral container layer. Restrict
write access to trusted operators and ensure the panel user can read it.

## Initial enrollment

1. Obtain the endpoint's public host key and SHA256 fingerprint using an
   independent trusted channel, such as the VPS provider console or an existing
   independently verified administrative SSH session. On the endpoint:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   cat /etc/ssh/ssh_host_ed25519_key.pub
   ```

   These are **public host keys**, never client private keys.
2. Confirm the fingerprint independently. `ssh-keyscan` can collect a candidate
   but cannot authenticate it: never pipe its output directly into trusted
   known_hosts without comparing fingerprints through the independent channel.
3. Add an OpenSSH known_hosts line to a private candidate trust file:

   ```text
   node.example.test ssh-ed25519 <verified-public-key-base64>
   [node.example.test]:2222 ssh-ed25519 <verified-public-key-base64>
   ```

   Use the exact configured SSH hostname/IP and port. A non-default port requires
   `[host]:port`. Enroll all aliases actually used by the panel. Hostnames do not
   replace fingerprint verification; DNS changes cannot enroll another key.
4. Validate with `ssh-keygen -lf <candidate> -E sha256`, preserve a backup, and
   install the verified file atomically with restricted permissions. Mount or
   configure it for the panel, then test a read-only SSH operation.

## Controlled rotation and failures

A changed key is rejected; do not approve it based on the error message alone.
Verify the new fingerprint independently, schedule rotation, back up the trust
file, replace the relevant verified entry atomically, and reconnect/restart the
panel during the agreed window. Existing pooled SSH transports keep the host
identity verified at their original handshake until disconnected; changing the
file does not revoke an already-open transport. Paramiko reloads trust on each
new handshake. Remove stale entries from both system and panel trust stores;
system entries can take precedence over the panel file.

If verification fails or the endpoint is unavailable, the operation fails and
the normal connection backoff applies. No trust file is rewritten by the panel.
Restore only a previously verified backup when rolling back trust configuration.
No VPN configuration, host key or user SSH key is regenerated by this feature.
