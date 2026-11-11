# Non-secret integration inventory

`GET /api/integration/inventory` provides control-plane metadata without using
the disabled plaintext backup export or a credential-bearing backup archive.
It requires an enabled admin/support session or an API token whose current
owner has one of those roles. Ordinary users cannot enumerate other owners.
Responses, including denials, have private/no-store cache headers.

The `integration-inventory-v1` contract contains:

* `complete: true` and `expected_server_uid: true`;
* an ordered `servers` list with stable `uid`, display `name`, and protocol
  instance records containing only `installed` and `base_protocol`;
* `users` containing only IDs;
* `user_connections` containing ID, owner ID, mutable server index, full
  protocol instance, client identity, and optional name/create-operation ID.

SSH credentials, private keys, configurations, tokens, user profile fields,
traffic counters and arbitrary future protocol fields are excluded. The
projection reads one snapshot under `DATA_LOCK`, performs no SSH/discovery,
and does not save it. Existing authentication may independently record a
Bearer token's last-used timestamp. Invalid/ambiguous identities return 503;
they must not be interpreted as an empty catalog or deleted ownership.

Indices are not durable identities. Resolve by UID, retain the full protocol
instance (for example `awg3__2`), and send optional `server_uid` with native
user-connection creation or configuration reads. A mismatched UID rejects
before SSH. Configuration reads also discard a result if the server endpoint
or instance changes during SSH. The existing role/ownership checks remain.
Older callers omitting the optional field retain their previous behavior.

This contract does not prove live capacity, VPN reachability, traffic freshness,
or support for creating a particular protocol. Those require their own APIs
and guards. It does not re-enable `/api/settings/backup/download`, which
intentionally continues to reject plaintext state export with HTTP 410.
