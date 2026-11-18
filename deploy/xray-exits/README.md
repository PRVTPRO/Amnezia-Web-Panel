# AmneziaWG exits for a systemd-managed Xray entry

This adapter manages an existing VLESS REALITY entry with AmneziaWG egress. Clients retain their entry address and credentials when the exit changes. The Docker-managed Xray and native AWG Exit Node workflows continue to use their existing managers.

## Entry host prerequisites

- The existing entry runs `vless-awg-xray.service` with `/opt/vless-awg/xray` and one VLESS REALITY inbound in `/etc/vless-awg/xray/server.json`. The VLESS outbound uses `sockopt.mark` 512 (`0x200`). Its current policy route stays in table 512.
- The original AmneziaWG client uses `awg-vless` with one IPv4 address. Its configuration is in `/etc/vless-awg/awg-vless.conf`. The service `vless-awg-tunnel.service` establishes the original route and loads the persistent nftables guard before Xray.
- The existing AWG binaries are `/opt/vless-awg/amneziawg-go` and `/opt/vless-awg/awg`, with the loader at `/opt/vless-awg/ld-musl-x86_64.so.1`. The host needs Python 3.11+, iproute2, nftables and curl.
- For user management, enable Xray's `HandlerService` on `127.0.0.1:10085` and give the VLESS inbound a tag and its clients unique email labels. `managers/systemd_xray_control.py` can initialize this with an input JSON file containing `{"operation":"enable_api"}`. Initialization validates the candidate and restarts the Xray service once. Plan this during a maintenance window and back up the original configuration.

## Installing the exit manager

Back up the routing and nftables configuration. Reserve tables 513–514 and rule priorities 10510–10511 for the manager.

1. Install `managers/xray_exit_control.py` at `/opt/vless-awg/xray-exit-control.py`. Install the two unit files from this directory under `/etc/systemd/system`. Install `egress.conf` as a drop-in for `vless-awg-xray.service`.
2. Adjust the entry's persistent nftables output guard for marks `0x200` and `0x201`. Permit them only on `awg-vless`, `awg-exit0` and `awg-exit1`, and retain rejection of marked IPv6 and private destinations. Check and apply the guard atomically. The ordinary SSH and WAN traffic stays on the existing routes.
3. Run `systemctl daemon-reload` and start `vless-awg-exit-restore.service`. This service restores the selected managed exit after boot. If the selected interface fails to come up, the marked route remains unreachable.
4. Register the entry host in AWP over SSH and run its protocol check. Open the server page as an administrator to see **Xray exit servers**.

## Operating the exits

Import an AWG client `.conf` with one peer, a public IPv4 endpoint or hostname, a tunnel IPv4 address and an IPv4 default route. A private key already in use on another configured exit is rejected so that a test cannot displace its live session. Shell hooks are unsupported. Imported DNS settings are not applied to the host. The entry's existing Xray DNS configuration remains authoritative.

**Test** starts a temporary managed interface and checks the handshake and public IPv4 through a loopback-only VLESS connection. **Activate** tests again before switching the marked Xray traffic. Choosing **Original exit VPS** restores the initial route. Inventory and imported private keys are stored on the entry under `/etc/vless-awg/exits` with root-only permissions.
