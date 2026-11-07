# IPv6 feature: what the code does now

## Status endpoint

`GET /api/servers/{id}/ip-status`

- Cached per server uid for 20 s. Install, uninstall, preference change,
  Docker apply and an instance switch drop the entry.
- A dead host is a state, not an error: `state: unknown`, `error: ssh_failed`,
  HTTP 200. The page shows a grey chip.
- `state` is `ok` or `degraded` (an instance could not be read).
- `preference` is `{new_instances, env_override}`.
- `host` has `ipv4`, `ipv6`, `ipv6_state`, `ipv6_default_route`,
  `ipv6_disabled_by_sysctl`.
- `docker` has `installed`, `ipv6_enabled`, `bridge_ipv6`,
  `daemon_json_present`, `restart_required`, `ip6tables_ok`,
  `flags_conflict`, `version_ok`.

## Preference

`POST /api/servers/{id}/ipv6` with `{enabled: true|false|null}`.

- Returns `{status, changed, preference}`. An identical repeat returns
  `changed: false` and does not write data.json.
- A wrong type returns 400 `bad_request`.
- `AWG_IPV6=off|on` wins over the stored preference. `/ip-status` reports it
  as `env_override` and the UI locks the control.

## Instance switch

`POST /api/servers/{id}/protocol/{proto}/ipv6` with
`{enabled: bool, repair: bool}`.

- Names `awg`, `awg2`, `awg3` and `awg3__2`...`awg3__5` are accepted.
  `awg_legacy` is refused with 400 `not_awg`.
- A plain switch is synchronous and returns 200.
- `needs_recreate` returns 202 `{op_id, state: running}` and rebuilds the
  container in the background.
- `repair: true` allows a disable on an exit-linked instance with peers.
  `peers_appeared` during a rebuild is reported as a failed operation.

The manager refuses a switch when the config is unreadable, when peers
appear, when the IPv6 subnet is taken by a neighbour, when the container
cannot take an address (dummy0 probe fails), or when the tunnel interface
does not come back.

## Guarded config edit

`_set_config_address_ipv6`:

1. copies the config to `<path>.ipv6bak` and compares sha256;
2. probes `ip link add awp6probe type dummy` + `ip -6 addr add <prefix>`;
3. rewrites the `Address` line with `sed` and reads it back;
4. adds or removes the `# DNS6` comment;
5. on any mismatch restores the copy and raises `state_unreadable`.

## Container rebuild

`_recreate_container_ipv6`:

1. `docker inspect` of the old container builds the new run command:
   restart policy, privileged, caps, binds, extra hosts, ulimits, network,
   sysctls, port bindings; the two IPv6 sysctls are forced;
2. old container is renamed to `<name>-ipv6bak`, a new one is created;
3. the DNS network is joined and the config plus `start.sh` are copied;
4. the copied config sha256 must equal the source;
5. the container must run and answer `ip -6 route show default`;
6. on any failure the new container is removed, the backup is renamed back
   and started;
7. on success the backup is removed and a failure to remove it is logged.

## Docker IPv6

`POST /api/servers/{id}/docker/ipv6/apply` with
`{confirm: "restart-docker"}` returns 202 `{op_id}`.

- The request is accepted first, so a refusal is an operation that ends
  `failed` with reason `docker_flags_conflict` when the unit passes
  `--ipv6`/`--ip6tables`, or reason `ipv6_disabled_by_sysctl` when the host
  kernel has IPv6 off. The UI polls `/operations/{op_id}` and shows the
  translated reason.
- `daemon.json` is merged, never overwritten; a broken file is refused with
  `daemon_json_invalid`.
- The write runs as root through a script, with the payload in base64.
- After `systemctl restart docker` the daemon must answer `docker version`
  within 20 s, else the backup is restored and `docker_recovery_failed` is
  reported.
- The bridge must then report `EnableIPv6=true`, else
  `docker_bridge_ipv6_missing`.

## Operations

`GET /api/servers/{id}/operations/{op_id}` returns the stored record:
`state` (`running|done|failed`), `step`, `reason`, timestamps.

Records live in `<data file>.operations.json`, survive a panel restart, and a
running record found at startup becomes `failed` with reason `interrupted`.

The operation lock is one in-process lock per server uid. A second long
operation answers 409 `operation_busy`.

## Exit link

`link()` refuses an instance whose `Address` has an IPv6 gateway with
`exit_link_ipv6`, at any peer count. The error text is localized.

## Deviations from spec v3

- The status read uses separate SSH calls, not one batch script. The 20 s
  cache keeps the page cheap.
- There is no `curl -6` egress probe; the IPv6 route inside the container is
  the check.
- The operation lock is in-process, like the existing peer lock. One panel
  process per data file is required.
- A Docker restart interrupted by a panel restart is not resumed: the record
  is marked `interrupted` and the next status read shows the real state.
- The `AWG_IPV6` override is reported and enforced for new instances, but
  there is no separate `env_off`/`env_on` blocked reason on an existing
  instance.
- `/ip-status` emits only `ssh_failed` in `error`. `container_unreadable` and
  `docker_unavailable` from spec v3 are not produced: a failed Docker probe
  is reported as `docker.installed = false`.