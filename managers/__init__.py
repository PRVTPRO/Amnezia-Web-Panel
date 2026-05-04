"""Protocol/service/SSH managers used by the web panel.

Modules in this package are imported either directly (`from managers.ssh_manager import SSHManager`)
or lazily by name through `app.get_protocol_manager`. Keeping them in a dedicated package
makes the project root easier to scan and prevents accidental name collisions with the
generic stdlib (e.g. `socks5_manager`, `dns_manager`).
"""
