# Live traffic accounting

WG/AWG accounting uses `get_traffic_snapshot()`, not `get_clients()`. The
latter intentionally retains human-readable and clientsTable fallbacks for
the UI. Those values are not evidence of a successful live counter read.

The collector requests exact integer RX/TX using `wg/awg show <interface>
transfer`. It never requests private keys, preshared keys or configurations.
Missing peers, failed commands, malformed/partial output and missing epoch
metadata produce no sample: existing baselines and totals are retained.
An explicitly observed zero is valid. Other protocol adapters must also
provide both non-negative integer counters; absent values are not zero.

All installed protocol instances are enumerated. Aliases for the same
physical container are queried once. Samples retain the connection ID,
full protocol key, client ID and server identity. Ambiguous duplicate owners
of one physical peer are logged and skipped instead of charging two users.
Such pre-existing ownership conflicts require administrator investigation.

## Epochs, restarts and limits of polling

An epoch hash combines container ID/start time/PID, host boot ID, interface
ifindex and the inode/ctime of a detected userspace UAPI socket. Metadata is
checked before and after the counter query. A changed epoch counts the new
generation's observed counters once even when they exceed the old baseline.
A counter decrease within one epoch is treated as an observable peer reset.
Epoch and RX/TX baselines survive panel restart in the existing data file.
Legacy sum-only baselines adopt the first epoch without recharging history.
Compatible online restore retains the live epoch, directional baselines and
gap diagnostic alongside the existing usage counters, including for older
JSON backups without these fields.

On an observed reset/epoch change, the connection retains a
`traffic_accounting_gap` diagnostic with the previous observed baseline and
`counters_verified_final=false`. This is **not** a final-counter receipt.
It is not automatically cleared by a later successful sample.

Polling cannot recover bytes transmitted after the last successful read
and erased before the next read. A peer remove/re-add may also be invisible
if its new counters exceed the old counters within the same observable
interface epoch. Unavailable UAPI socket metadata is explicitly represented
as `no-socket`, not proof of a kernel backend or a stable userspace process.
This change does not promise lossless deletion, arbitrary backend restarts,
or exact attribution of a sampling interval across a calendar boundary.
Durable node-side receipts/counters are required for those guarantees.

Calendar reset retains raw peer baselines and lifetime totals. Existing
manual/legacy disable reasons, access reconciliation and lifecycle guards
are unchanged. An SSH outage within an unchanged epoch catches up at the
next successful read, without resetting or replaying the baseline.
