#!/usr/bin/env python3
"""Manage AWG egress profiles on the systemd Xray entry server."""

import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid


STATE = Path("/etc/vless-awg/exits")
RUNTIME = Path("/run/vless-awg-exits")
SLOTS = ("awg-exit0", "awg-exit1")
ORIGINAL = "awg-vless"
VLESS_TABLE, VLESS_MARK, VLESS_PRIORITY = 513, "0x200", "10511"
PROBE_TABLE, PROBE_MARK, PROBE_PRIORITY = 514, "0x201", "10510"
BASE = "/opt/vless-awg"
AWG = [BASE + "/ld-musl-x86_64.so.1", BASE + "/awg"]
NAME = re.compile(r"^[a-zA-Z0-9.-]+$")
AWG_PARAMS = set("Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 CPS HeaderProtectionKey RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies".split())


def fail(message):
    raise ValueError(message)


def parse_config(text):
    entries = {}
    section = None
    for line in text.lstrip("\ufeff").splitlines():
        line = line.partition("#")[0].strip()
        if not line:
            continue
        if line in ("[Interface]", "[Peer]"):
            section = line[1:-1]
            if section in entries:
                fail("The configuration must have one Interface and one Peer.")
            entries[section] = {}
            continue
        key, equals, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not section or not equals or not value or key in entries[section]:
            fail("Invalid or duplicate AmneziaWG configuration entry.")
        entries[section][key] = value
    if set(entries) != {"Interface", "Peer"}:
        fail("The configuration must have one Interface and one Peer.")
    interface, peer = entries["Interface"], entries["Peer"]
    if set(interface) - (AWG_PARAMS | {"Address", "DNS", "MTU", "PrivateKey", "Table", "ListenPort"}) or (
        set(peer) - {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
    ):
        fail("Unsupported configuration option. Shell hooks are not accepted.")
    key_fields = [(interface, "PrivateKey"), (peer, "PublicKey")]
    if "PresharedKey" in peer:
        key_fields.append((peer, "PresharedKey"))
    for fields, key in key_fields:
        try:
            valid = len(base64.b64decode(fields[key], validate=True)) == 32
        except (KeyError, ValueError):
            valid = False
        if not valid:
            fail("The AmneziaWG key fields are missing or invalid.")
    try:
        addresses = [ipaddress.ip_interface(i.strip()) for i in interface["Address"].split(",")]
        ipv4 = [str(a.ip) for a in addresses if a.version == 4]
        routed = {ipaddress.ip_network(a.strip()) for a in peer["AllowedIPs"].split(",")}
        host, port = peer["Endpoint"].rsplit(":", 1)
        port = int(port)
        mtu = int(interface.get("MTU", 1280))
        keepalive = int(peer.get("PersistentKeepalive", 25)) or 25
    except (KeyError, ValueError):
        fail("Address, AllowedIPs, Endpoint or MTU is invalid.")
    if len(ipv4) != 1 or ipaddress.ip_network("0.0.0.0/0") not in routed:
        fail("The exit must supply one tunnel IPv4 address and an IPv4 default route.")
    if not NAME.fullmatch(host) or not 1 <= port <= 65535 or not 576 <= mtu <= 1420 or not 1 <= keepalive <= 65535:
        fail("Endpoint, keepalive or MTU is outside the supported range.")
    return {
        "address": ipv4[0],
        "endpoint": host,
        "port": port,
        "mtu": mtu,
        "interface": {k: v for k, v in interface.items() if k in AWG_PARAMS or k == "PrivateKey"},
        "peer": {k: v for k, v in peer.items() if k in {"PublicKey", "PresharedKey"}} |
                {"AllowedIPs": "0.0.0.0/0", "PersistentKeepalive": str(keepalive)},
    }


def atom(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        pending = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            pending.replace(path)
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            pending.unlink(missing_ok=True)


def write(path, state):
    atom(path, (json.dumps(state, indent=2, ensure_ascii=False)+"\n").encode())


def command(parts, message, timeout=12, check=True):
    try:
        proc = subprocess.run(parts, capture_output=True, timeout=timeout, text=True)
    except (OSError, subprocess.TimeoutExpired):
        fail(message)
    if check and proc.returncode:
        fail(message)
    return proc.stdout


def ip(*args, check=True):
    return command(["/usr/sbin/ip", *map(str, args)], "Could not apply the exit routing table.", check=check)


def table_route(table, interface, source):
    ip("-4", "route", "replace", "default", "dev", interface, "src", source, "table", table, "metric", 50)


def route_rule(family, table, mark, priority):
    ip(family, "route", "replace", "unreachable", "default", "table", table, "metric", 32760)
    found = ip(family, "rule", "show", "priority", priority).strip()
    if not found:
        ip(family, "rule", "add", "priority", priority, "fwmark", mark, "lookup", table)
    elif found.split()[-4:] != ["fwmark", mark, "lookup", str(table)]:
        fail("The exit policy routing priority is already in use.")


def remove_live_route():
    found = ip("-4", "rule", "show", "priority", VLESS_PRIORITY).strip().split()
    if found[-4:] == ["fwmark", VLESS_MARK, "lookup", str(VLESS_TABLE)]:
        ip("-4", "rule", "del", "priority", VLESS_PRIORITY, "fwmark", VLESS_MARK, "lookup", VLESS_TABLE)


def slot_unit(slot, action, check=True):
    command(["systemctl", action, f"vless-awg-managed@{slot}.service"],
            "The managed AWG interface could not start or stop.", timeout=27, check=check)


def endpoint(profile):
    host, port = profile["endpoint"], profile["port"]
    try:
        candidates = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        fail("Unable to resolve the AWG endpoint to IPv4.")
    for row in candidates:
        address = ipaddress.ip_address(row[4][0])
        if address.is_global:
            return f"{address}:{port}"
    fail("The AWG endpoint must use a public IPv4 address.")


def start_slot(slot, profile):
    destination = endpoint(profile)
    slot_unit(slot, "stop", check=False)
    write(RUNTIME / (slot+".json"), profile)
    peer = profile["peer"] | {"Endpoint": destination}
    text = "[Interface]\n" + "".join(f"{k} = {v}\n" for k, v in profile["interface"].items())
    text += "\n[Peer]\n" + "".join(f"{k} = {v}\n" for k, v in peer.items())
    atom(RUNTIME / (slot+".conf"), text.encode())
    slot_unit(slot, "start")


def configure(slot):
    if slot not in SLOTS:
        fail("Invalid managed AWG interface.")
    profile = json.loads((RUNTIME / (slot+".json")).read_bytes())
    socket_path = Path("/run/amneziawg") / (slot+".sock")
    for _ in range(40):
        if socket_path.is_socket():
            break
        time.sleep(.1)
    command(AWG+["setconf",slot,str(RUNTIME/(slot+".conf"))], "The AWG version rejected this configuration.")
    ip("-4", "address", "replace", profile["address"]+"/32", "dev", slot)
    ip("link", "set", "dev", slot, "mtu", profile["mtu"], "up")


def original_source():
    interfaces = json.loads(ip("-j", "-4", "address", "show", "dev", ORIGINAL))
    addresses = {address["local"] for interface in interfaces
                 for address in interface.get("addr_info", []) if address.get("family") == "inet"}
    if len(addresses) != 1:
        fail("The original AWG interface must have one IPv4 address.")
    return addresses.pop()


def handshake(interface):
    raw = command(AWG+["show",interface,"latest-handshakes"], "Could not query AWG.", check=False)
    timestamps = [int(line.split()[-1]) for line in raw.splitlines() if line.split()[-1].isdigit()]
    return max(timestamps, default=0)


def allocate_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check_egress(interface, source):
    route_rule("-4", PROBE_TABLE, PROBE_MARK, PROBE_PRIORITY)
    route_rule("-6", PROBE_TABLE, PROBE_MARK, PROBE_PRIORITY)
    table_route(PROBE_TABLE, interface, source)
    user, socks, vless = str(uuid.uuid4()), allocate_port(), allocate_port()
    if socks == vless:
        fail("Could not allocate test ports. Retry the check.")
    config = {
        "log": {"loglevel":"none"},
        "inbounds": [
            {"listen":"127.0.0.1","port":socks,"tag":"probe","protocol":"socks","settings":{"auth":"noauth"}},
            {"listen":"127.0.0.1","port":vless,"tag":"test-vless","protocol":"vless",
             "settings":{"decryption":"none","clients":[{"id":user}]}},
        ],
        "outbounds": [
            {"tag":"relay","protocol":"vless","settings":{"vnext":[
                {"address":"127.0.0.1","port":vless,"users":[{"id":user,"encryption":"none"}]}]}},
            {"tag":"exit","protocol":"freedom","streamSettings":{"sockopt":{"mark":int(PROBE_MARK,16)}}},
        ],
        "routing":{"rules":[
            {"type":"field","inboundTag":["probe"],"outboundTag":"relay"},
            {"type":"field","inboundTag":["test-vless"],"outboundTag":"exit"},
        ]},
    }
    try:
        with tempfile.NamedTemporaryFile(dir=RUNTIME, suffix=".json") as file:
            file.write(json.dumps(config).encode())
            file.flush()
            proc = subprocess.Popen([BASE+"/xray","run","-c",file.name], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(20):
                    if proc.poll() is not None:
                        fail("Could not start the isolated VLESS test.")
                    try:
                        with socket.create_connection(("127.0.0.1",socks),timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                result = command(
                    ["curl","-fsS","--noproxy","","--max-time","10","--proxy",f"socks5h://127.0.0.1:{socks}",
                     "https://1.1.1.1/cdn-cgi/trace"],
                    "No public IPv4 was reached through the selected AWG exit.", timeout=12)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
    finally:
        ip("-4", "route", "del", "default", "table", PROBE_TABLE, "metric", 50, check=False)
    egress = next((l[3:] for l in result.splitlines() if l.startswith("ip=")), "")
    try:
        address = ipaddress.ip_address(egress)
    except ValueError:
        fail("The egress probe did not return a valid public address.")
    recent = handshake(interface)
    if address.version != 4 or not address.is_global or not recent or time.time()-recent>180:
        fail("The egress probe did not confirm a fresh AWG handshake.")
    return {"ip":str(address),"handshake":recent,"checked_at":int(time.time())}


def state_view(state):
    active = state.get("active")
    rows = [{"id":"original","name":"Исходный зарубежный VPS","endpoint":"Текущий AWG",
             "active":not active, "check":state.get("original_check")}]
    rows += [
        {"id":uid, "name":item["name"], "endpoint":item["endpoint"]+":"+str(item["port"]),
         "active":active==uid, "check":item.get("check")}
        for uid,item in state["profiles"].items()
    ]
    return {"profiles":rows}


def operation(state, req):
    mode = req["operation"]
    uid = req.get("id")
    active, slot = state.get("active"), state.get("slot")
    if mode == "list":
        return state_view(state)
    if mode == "import":
        name = req["name"].strip()
        if not 1 <= len(name) <= 80:
            fail("Name must contain 1–80 characters.")
        profile = parse_config(req["config"])
        key = profile["interface"]["PrivateKey"]
        original = (STATE.parent/"awg-vless.conf").read_text()
        if any(k.strip() == "PrivateKey" and v.strip() == key for k,_,v in
               (line.partition("=") for line in original.splitlines())) or any(
            p["interface"]["PrivateKey"] == key for p in state["profiles"].values()
        ):
            fail("This AWG client key already belongs to an existing exit.")
        state["profiles"][uuid.uuid4().hex] = profile | {"name":name}
    elif mode == "remove":
        if uid == "original" or uid == active or uid not in state["profiles"]:
            fail("Only an inactive imported exit can be removed.")
        del state["profiles"][uid]
    elif mode in {"test","activate"}:
        if uid == "original":
            state["original_check"] = check_egress(ORIGINAL, original_source())
            if mode == "activate":
                remove_live_route()
                state.update(active=None,slot=None)
        elif uid in state["profiles"]:
            profile = state["profiles"][uid]
            if uid == active:
                profile["check"] = check_egress(slot, profile["address"])
            else:
                candidate = next(s for s in SLOTS if s != slot)
                switched = False
                try:
                    start_slot(candidate, profile)
                    profile["check"] = check_egress(candidate, profile["address"])
                    if mode == "activate":
                        route_rule("-4", VLESS_TABLE, VLESS_MARK, VLESS_PRIORITY)
                        try:
                            table_route(VLESS_TABLE, candidate, profile["address"])
                        except ValueError:
                            if not active:
                                remove_live_route()
                            raise
                        state.update(active=uid,slot=candidate)
                        switched = True
                finally:
                    if not switched:
                        slot_unit(candidate,"stop",check=False)
        else:
            fail("Unknown exit profile.")
    else:
        fail("Unsupported exit operation.")
    try:
        write(STATE/"inventory.json", state)
    except OSError:
        if mode == "activate":
            if active:
                table_route(VLESS_TABLE,slot,state["profiles"][active]["address"])
                route_rule("-4",VLESS_TABLE,VLESS_MARK,VLESS_PRIORITY)
            else:
                remove_live_route()
            if state.get("slot") not in (None,slot):
                slot_unit(state["slot"],"stop",check=False)
        raise
    if slot and slot != state.get("slot"):
        slot_unit(slot,"stop",check=False)
    return state_view(state)


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700,exist_ok=True)
    RUNTIME.mkdir(mode=0o700,exist_ok=True)
    if sys.argv[1] == "interface":
        configure(sys.argv[2])
        return
    with (STATE/"lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        inventory = STATE/"inventory.json"
        state = json.loads(inventory.read_bytes()) if inventory.exists() else {"profiles":{}}
        if sys.argv[1] == "restore":
            if state.get("active"):
                profile = state["profiles"][state["active"]]
                slot = state["slot"]
                route_rule("-4",VLESS_TABLE,VLESS_MARK,VLESS_PRIORITY)
                start_slot(slot, profile)
                table_route(VLESS_TABLE,slot,profile["address"])
        else:
            req = json.loads(Path(sys.argv[1]).read_bytes())
            print(json.dumps(operation(state,req),ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, ValueError) else "The Xray exit operation failed.", file=sys.stderr)
        sys.exit(1)
