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

The server page polls `/ip-status` every 60 s while the tab is visible and
again on `visibilitychange` when the tab regains focus.

## Preference

`POST /api/servers/{id}/ipv6` with `{enabled: true|false|null}`.

- Returns `{status, changed, preference}`. An identical repeat returns
  `changed: false` and does not write data.json.
- A wrong type returns 400 `bad_request`.
- `AWG_IPV6=off|on` wins over the stored preference. `/ip-status` reports it
  as `env_override` (`off`, `on` or `auto`). The UI locks the control.
- The settings block disables all three preference radios when
  `env_override` is `off` or `on`, and prints the override beside the host
  line.
- The install gate in `api_install_protocol` applies the same rule: `off`
  forces the new instance to IPv4-only, `on` forces IPv6. `auto` and an unset
  variable keep the preference and the auto-detection.
- The Docker IPv6 probe runs only when the effective preference is `True`
  and `env_override` is not `off`. With `AWG_IPV6=off` the install never
  returns 409 `docker_pending`.
- The install modal note reads `preference.env_override`: `off` shows the
  "disabled on the server" warning and hides the DNS6 field, `on` always
  shows the automatic-IPv6 note, whatever the stored preference is.

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
- A failed `docker restart` after the `Address` write restores the IPv4-only
  `Address` and retries the restart once. If the restore itself fails it is
  logged, and the call still raises `server_off`.
- `can_disable` requires a running container: a stopped container cannot be
  reconfigured. `can_enable` needs readable state, zero peers and no exit
  link.

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

`update_awg_settings` validates `DNS` and `DNS6` before any write.
`_validate_dns_value` splits the value on commas and whitespace and requires
every token to parse as an IPv4 or IPv6 address; a bad token raises
`bad_request`. An empty value is valid and clears the setting. The config
writer passes `dns6` through `shlex.quote`, so a value cannot break out of
the `# DNS6` line.

## Container rebuild

`_recreate_container_ipv6`:

1. `docker inspect` of the old container builds the new run command:
   restart policy, privileged, caps, binds, extra hosts, ulimits, network,
   sysctls, port bindings; `Config.Env` (deduplicated by key),
   `Config.Entrypoint`, `Config.Cmd` and `Config.Labels` are copied too; the
   two IPv6 sysctls are forced;
2. `-p` bindings are skipped for `host` and `container:*` network modes,
   because Docker rejects them there; the rest of the command is kept;
3. old container is renamed to `<name>-ipv6bak`, a new one is created;
4. the DNS network is joined and the config plus `start.sh` are copied;
5. the copied config sha256 must equal the source;
6. the container must run and answer `ip -6 route show default`;
7. on any failure the new container is removed and the backup is renamed back
   and started; the rename and the start are checked by return code, and a
   failed rollback raises `recreate_rollback_failed` (the backup is then
   started under its own name as a best effort);
8. on success the backup is removed and a failure to remove it is logged.

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
- The backup is unconditional: every apply runs `cp -f` over
  `/etc/docker/daemon.json.bak` before the write, so the backup is always the
  state before the latest apply, not the state before the first one. If
  `daemon.json` is absent, no backup is made.
- The write runs as root through a script, with the payload in base64.
- After `systemctl restart docker` the daemon must answer `docker version`
  within 20 s, else the backup is restored and `docker_recovery_failed` is
  reported.
- The bridge must then report `EnableIPv6=true`, else
  `docker_bridge_ipv6_missing`.
- The background worker is started in a guarded block. If the thread cannot
  start, the operation is marked `failed` with reason `internal_error` and
  the operation lock is released, so the server is not left busy.
- Docker presence is probed with `sh -c 'command -v docker'`. `command` is a
  shell builtin, and a plain `sudo command -v docker` fails on a non-root SSH
  host because sudo cannot execute a builtin. The `sh -c` wrapper runs the
  probe in a shell, so `docker.installed` is correct on both root and
  password-sudo hosts.

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

## Server page rendering

`escapeHtml` in `templates/server.html` escapes `&`, `<`, `>`, `"` and `'`.
Proto names, block reasons, IPv6 subnets and other `/ip-status` values are
therefore safe in HTML text and in quoted attributes.

## Deviations from spec v3

- The status read uses separate SSH calls, not one batch script. The 20 s
  cache keeps the page cheap.
- There is no `curl -6` egress probe; the IPv6 route inside the container is
  the check.
- The operation lock is in-process, like the existing peer lock. One panel
  process per data file is required.
- A Docker restart interrupted by a panel restart is not resumed: the record
  is marked `interrupted` and the next status read shows the real state.
- The `AWG_IPV6` override is enforced on the instance switch too:
  `set_instance_ipv6` raises `env_off` for an enable and `env_on` for a
  disable before any write.
- Spec v3 asks for one composite Save that writes settings and the IPv6
  switch together. The panel keeps two controls, but they cannot race: while
  the instance IPv6 selection differs from the loaded value, the general AWG
  Save is disabled and a hint asks to apply or revert IPv6 first.
- `/ip-status` reports `ssh_failed` when both host route probes fail and sets
  `state = unknown` with grey `ipv4_state`/`ipv6_state`. A failed Docker
  probe is still reported as `docker.installed = false`.

## Review hardening (commit `a599fc4`)

- Recreate rebuilds the full entrypoint: `--entrypoint` takes the first
  element and the remaining elements are prepended to `Config.Cmd`. The old
  code kept only `dumb-init`, so the new container exited.
- Recreate copies the whole `/opt/amnezia/awg` directory, not one config
  file, and verifies the config sha, all key files, `clientsTable` JSON and
  the `[Peer]` count before `docker start`. The backup container is removed
  only after those checks pass.
- `amnezia-dns-net` is connected only when the new container is not already
  on that network.
- `set_instance_ipv6` captures the previous gateway and restores it on any
  write, start-script, restart or verification failure. A repeat enable or
  disable is a no-op with no restart.
- `prepare_host(allow_ipv6=False)` skips the Docker IPv6 block when the
  admin chose IPv4-only or `AWG_IPV6=off`.
- `enable_docker_ipv6` writes mode 0644 and returns
  `ip6tables_unsupported` on an apply when NAT66 is not available.
- `/ip-status` caches healthy payloads for 20 s and degraded or failed ones
  for 3 s.
- A malformed body on the IPv6 mutation endpoints returns 400
  `bad_request`, not the FastAPI 422 detail array.
- `api_instance_ipv6` takes `@serialize_peer_lifecycle`, so a peer add cannot
  interleave with the Address rewrite.