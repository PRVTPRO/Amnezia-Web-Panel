# IPv6 feature: rollback

Every change is local to code, one `data.json` key, one file on the host and
one container name. No database migration runs.

## 1. Code

```powershell
git revert <commit>
```

Or restore the touched files from the last good commit:

```powershell
git checkout <commit> -- app.py exit_link_service.py managers/awg_manager.py `
  templates/server.html static/css/style.css translations tests
```

New files to delete after a revert:

- `tests/test_ipv6_manager.py`
- `tests/test_ipv6_api.py`
- `tests/test_ipv6_i18n.py`
- `design/ipv6-*`

## 2. Panel data

No migration. One optional key appears:

```json
"servers": [{ "ipv6_new_instances": true }]
```

To return to the legacy behaviour, delete the key from every server. The
panel then uses `Авто` (auto detection). A restart is not needed.

## 3. Docker daemon

The panel copies `/etc/docker/daemon.json` to `/etc/docker/daemon.json.bak`
before the first write. To roll back:

```bash
sudo cp /etc/docker/daemon.json.bak /etc/docker/daemon.json
sudo systemctl restart docker
```

If no backup exists, delete the keys the panel added: `ipv6`, `experimental`,
`fixed-cidr-v6`, `ip6tables`. Then restart Docker.

Docker restart drops every VPN session for 10-30 seconds.

## 4. One instance

Disabling IPv6 from the panel restores the `Address` line to IPv4 only and
rewrites `start.sh`. No manual step is needed when the instance has no peers.

Manual rollback inside the container:

```bash
docker exec <container> sed -i -E \
  's|^(Address = [^,]+)(, *[0-9a-fA-F:]+/[0-9]+)+|\1|' /opt/amnezia/awg0.conf
docker exec <container> /opt/amnezia/start.sh   # or: docker restart <container>
```

## 5. Rebuilt container

The recreate path keeps the old container as `<name>-ipv6bak` until the new
one answers on IPv6. After a successful switch the copy is removed.

If you must go back by hand:

```bash
docker rm -f <name>
docker rename <name>-ipv6bak <name>
docker start <name>
```

The image is never removed, so this step is fast.

## 6. Exit-node link

`link()` refuses an instance that has an IPv6 gateway. Such an instance has no
`exit_link` record, so nothing to clean after a rollback.

## 7. Check after rollback

1. `/login` works and the panel loads.
2. `servers` and `user_connections` in `data.json` are unchanged.
3. `docker ps` shows the same containers as before.
4. Clients still connect over IPv4.
5. `pytest tests -q -p no:playwright` shows only the known Windows
   `test_exit_failover.py` failures.