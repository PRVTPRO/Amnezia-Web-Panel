"""Run on the entry VPS to update its systemd-managed Xray configuration."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


CONFIG = Path("/etc/vless-awg/xray/server.json")
XRAY = "/opt/vless-awg/xray"
UNIT = "vless-awg-xray.service"
API = "127.0.0.1:10085"
META = "awpManagedClients"


def invoke(args, message):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode:
        raise RuntimeError(message)
    return result.stdout


def api(command, *args):
    return invoke([XRAY, "api", command, f"-server={API}", *args], "Xray API request failed.")


def inbound(config):
    matches = [item for item in config["inbounds"] if item.get("protocol") == "vless"]
    if len(matches) != 1:
        raise RuntimeError("Expected a single VLESS inbound.")
    return matches[0]


def atomic_config(raw):
    current = CONFIG.stat()
    with tempfile.NamedTemporaryFile(dir=CONFIG.parent, suffix=".json", delete=False) as pending:
        temporary = Path(pending.name)
        try:
            pending.write(raw)
            pending.flush()
            os.fchown(pending.fileno(), current.st_uid, current.st_gid)
            os.fchmod(pending.fileno(), current.st_mode & 0o777)
            os.fsync(pending.fileno())
            invoke([XRAY, "run", "-test", "-c", str(temporary)], "Xray rejected the candidate configuration.")
            temporary.replace(CONFIG)
        finally:
            temporary.unlink(missing_ok=True)


def read_users(tag):
    data = json.loads(api("inbounduser", "-tag=" + tag))
    return {user["email"] for user in data.get("users", [])}


def restart(tag):
    invoke(["systemctl", "restart", UNIT], "Xray restart failed.")
    for attempt in range(5):
        try:
            read_users(tag)
            return
        except RuntimeError:
            if attempt == 4:
                raise
            time.sleep(0.2)


def enable_api(config, before):
    ib = inbound(config)
    if (config.get("api") or {}).get("listen") == API and ib.get("tag"):
        read_users(ib["tag"])
        return
    if config.get("api") is not None:
        raise RuntimeError("Existing Xray API configuration needs review.")

    ib.setdefault("tag", "vless-awg")
    config["api"] = {"tag": "awp-api", "listen": API, "services": ["HandlerService"]}
    atomic_config(serialize(config))
    try:
        restart(ib["tag"])
    except Exception:
        atomic_config(before)
        invoke(["systemctl", "restart", UNIT], "Xray rollback restart failed.")
        raise


def sync_user(ib, account, enabled):
    tag = ib["tag"]
    email = account["email"]
    if (email in read_users(tag)) == enabled:
        return
    if enabled:
        payload = {"inbounds": [{
            "tag": tag, "port": ib["port"], "protocol": "vless",
            "settings": {"clients": [account], "decryption": "none"},
        }]}
        with tempfile.NamedTemporaryFile(dir=CONFIG.parent, suffix=".json") as draft:
            draft.write(serialize(payload))
            draft.flush()
            api("adu", draft.name)
    else:
        api("rmu", "-tag=" + tag, email)
    if (email in read_users(tag)) != enabled:
        raise RuntimeError("Xray did not apply the requested user change.")


def serialize(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def update_user(config, before, request):
    mode, uid = request["operation"], request["id"]
    ib = inbound(config)
    if (config.get("api") or {}).get("listen") != API or not ib.get("tag"):
        raise RuntimeError("Enable the loopback Xray API first.")
    members = ib["settings"]["clients"]
    metadata = config.setdefault(META, {})
    active = next((user for user in members if user["id"] == uid), None)
    record = metadata.get(uid) or {}
    account = active or record.get("disabled")
    previously_enabled = active is not None
    if mode == "add":
        if account:
            raise RuntimeError("Xray user already exists.")
        account = {"id": uid, "email": uid, "flow": "xtls-rprx-vision"}
        record["name"] = request["name"]
    elif not account:
        raise RuntimeError("Xray user was not found.")
    if mode == "rename":
        record["name"] = request["name"]
        metadata[uid] = record
        atomic_config(serialize(config))
        return

    enabled = mode in ("add", "enable")
    members[:] = [user for user in members if user["id"] != uid]
    if enabled:
        members.append(account)
        record.pop("disabled", None)
        metadata[uid] = record
    elif mode == "disable":
        record["disabled"] = account
        metadata[uid] = record
    elif mode == "remove":
        metadata.pop(uid, None)
    else:
        raise RuntimeError("Unsupported Xray user operation.")
    if any(user["email"] == account["email"] and user["id"] != uid for user in members):
        raise RuntimeError("Xray user authentication labels must be unique.")
    atomic_config(serialize(config))
    try:
        sync_user(ib, account, enabled)
    except Exception:
        atomic_config(before)
        sync_user(ib, account, previously_enabled)
        raise


def main():
    request = json.loads(Path(sys.argv[1]).read_bytes())
    with CONFIG.with_name(".awp-edit.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = CONFIG.read_bytes()
        config = json.loads(before)
        if request["operation"] == "enable_api":
            enable_api(config, before)
        else:
            update_user(config, before, request)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, RuntimeError) else "Xray management operation failed.", file=sys.stderr)
        sys.exit(1)
