"""AWP adapter for the independently provisioned entry Xray service."""

import base64
import json
from pathlib import Path
import shlex
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from managers.systemd_xray_control import CONFIG, META, UNIT, XRAY
from managers.xray_manager import XrayManager


class SystemdXrayManager(XrayManager):
    @classmethod
    def matches(cls, ssh, protocol):
        if protocol != "xray":
            return False
        out, _, code = ssh.run_sudo_command(
            f"if test -r {CONFIG} && test -x {XRAY}; then systemctl show -p LoadState --value {UNIT}; fi"
        )
        return code == 0 and out.strip() == "loaded"

    def _config_dir(self):
        return str(CONFIG.parent)

    def _read_remote_file(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {shlex.quote(path)} 2>/dev/null")
        return out if code == 0 else None

    def _detect_layout(self):
        return "native"

    def _get_server_json(self):
        raw = self._read_remote_file(str(CONFIG))
        if not raw:
            raise RuntimeError("Unable to read the systemd Xray configuration.")
        return json.loads(raw)

    def _get_meta_json(self):
        inbound = self._get_vless_inbound(self._get_server_json())
        reality = inbound["streamSettings"]["realitySettings"]
        encoded = reality["privateKey"]
        raw_key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        public_key = X25519PrivateKey.from_private_bytes(raw_key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        return {
            "public_key": base64.urlsafe_b64encode(public_key).decode().rstrip("="),
            "short_id": reality["shortIds"][0],
            "site_name": reality["serverNames"][0],
            "port": inbound["port"],
        }

    def check_protocol_installed(self):
        return True

    def check_container_running(self):
        out, _, code = self.ssh.run_sudo_command(f"systemctl is-active {UNIT}")
        return code == 0 and out.strip() == "active"

    def get_server_status(self, protocol):
        return dict(super().get_server_status(protocol), backend="systemd")

    def _get_clients_table(self, strict=False):
        config = self._get_server_json()
        metadata = config.get(META, {})
        inbound = self._get_vless_inbound(config)
        accounts = {user["id"]: user for user in inbound["settings"]["clients"]}
        return [
            {"clientId": uid, "userData": {
                "clientName": metadata.get(uid, {}).get("name")
                              or accounts.get(uid, {}).get("email") or "VLESS",
                "enabled": uid in accounts,
            }}
            for uid in dict.fromkeys([*accounts, *metadata])
        ]

    def get_clients(self, protocol=None, strict=True):
        return self._get_clients_table()

    def _change(self, operation, **fields):
        temporary = self.ssh._make_private_temp_dir()
        try:
            control = temporary + "/control.py"
            request = temporary + "/request.json"
            self.ssh.upload_file(Path(__file__).with_name("systemd_xray_control.py").read_text(), control)
            self.ssh.upload_file(json.dumps({"operation": operation, **fields}), request)
            _, error, code = self.ssh.run_sudo_command(
                f"python3 {shlex.quote(control)} {shlex.quote(request)}"
            )
            if code:
                raise RuntimeError(error.strip() or "Systemd Xray operation failed.")
        finally:
            self.ssh.run_command(f"rm -rf -- {shlex.quote(temporary)}")

    def manage_exits(self, request):
        temporary = self.ssh._make_private_temp_dir()
        try:
            path = temporary + "/exit-request.json"
            self.ssh.upload_file(json.dumps(request), path)
            out, error, code = self.ssh.run_sudo_command(
                f"python3 /opt/vless-awg/xray-exit-control.py {shlex.quote(path)}", timeout=100,
            )
            if code:
                raise ValueError(error.strip() or "Entry VPS could not manage exits.")
            return json.loads(out)
        finally:
            self.ssh.run_command(f"rm -rf -- {shlex.quote(temporary)}")

    def get_client_config(self, protocol, client_id, server_host, port, public_port=None,
                          fingerprint=None):
        result = super().get_client_config(protocol, client_id, server_host, port,
                                           public_port=public_port, fingerprint=fingerprint)
        return result.replace("?type=raw&", "?type=tcp&", 1) if result else result

    def add_client(self, protocol, client_name, server_host, port, public_port=None,
                   warp_ctx=None, fingerprint=None):
        if warp_ctx and warp_ctx.get("active"):
            raise RuntimeError("Configure the exit through the systemd Xray exit manager.")
        uid = str(uuid.uuid4())
        self._change("add", id=uid, name=client_name)
        return {"client_id": uid, "config": self.get_client_config(
            protocol, uid, server_host, port, public_port=public_port, fingerprint=fingerprint,
        )}

    def toggle_client(self, protocol, client_id, enable):
        self._change("enable" if enable else "disable", id=client_id)

    def remove_client(self, protocol, client_id):
        self._change("remove", id=client_id)
        return True

    def rename_client(self, protocol, client_id, new_name):
        self._change("rename", id=client_id, name=new_name)
        return {"status": "success", "name": new_name}

    def install_protocol(self, *args, **kwargs):
        raise RuntimeError("This Xray service is installed independently of AWP.")

    def remove_container(self):
        raise RuntimeError("The systemd Xray service cannot be uninstalled from AWP.")

    def get_core_version(self):
        out, _, code = self.ssh.run_sudo_command(f"{XRAY} version")
        if code == 0 and out.startswith("Xray "):
            return out.split()[1]
        return None

    def update_core(self, target_release, progress=None):
        raise RuntimeError("Update the Xray binary on the systemd entry server.")

    def _write_server_json(self, data, restart=True):
        raise RuntimeError("Use the entry server to edit the systemd Xray configuration.")

    def apply_selfsteal(self, domain, dest):
        raise RuntimeError("Configure REALITY directly on the systemd Xray entry server.")

    def set_vless_encryption(self, enable):
        raise RuntimeError("Configure VLESS directly on the systemd Xray entry server.")
