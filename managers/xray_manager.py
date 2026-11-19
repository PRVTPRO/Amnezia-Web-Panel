import json
import os
import random
import uuid
import logging
import base64
import functools
import re
import shlex
import threading
from datetime import datetime
import urllib.parse
from managers import docker_image_cleanup

from managers.awg_manager import AWGManager

from managers.awg_manager import AWGManager
from managers.clients_table import save_clients_table

logger = logging.getLogger(__name__)

XRAY_CORE_VERSION = "v26.11.9"


def _random_range(low_min, low_max, span_min, span_max):
    """A "low-high" range string whose bounds are drawn per install."""
    low = random.randint(low_min, low_max)
    return f"{low}-{low + random.randint(span_min, span_max)}"


def _xhttp_extra():
    """XHTTP tuning per the XTLS guidance: express every knob the core
    accepts as a range, and shift the bounds per install so servers do
    not share one padding/multiplexing profile. hKeepAlivePeriod is the
    one field that rejects ranges; maxConnections conflicts with
    maxConcurrency and stays off."""
    return {
        "xPaddingBytes": _random_range(50, 300, 500, 1200),
        "scStreamUpServerSecs": _random_range(10, 30, 40, 60),
        "xmux": {
            "maxConcurrency": _random_range(8, 16, 4, 16),
            "maxConnections": 0,
            "cMaxReuseTimes": 0,
            "hMaxRequestTimes": _random_range(400, 800, 200, 400),
            "hMaxReusableSecs": _random_range(1200, 2400, 600, 1200),
            "hKeepAlivePeriod": 0,
        },
    }


def _client_flow(inbound):
    """Vision flow for the client entry: on raw TCP (legacy), or with
    VLESS Encryption on XHTTP (Vision rides any transport when VLESS
    Encryption is on)."""
    if not inbound:
        return ""
    stream = inbound.get('streamSettings', {}) or {}
    settings = inbound.get('settings', {}) or {}
    network = stream.get('network', 'tcp')
    decryption = settings.get('decryption')
    encryption_on = isinstance(decryption, str) and decryption not in ('', 'none')
    if encryption_on or network == 'tcp':
        return "xtls-rprx-vision"
    return ""

# uname -m -> asset suffix of the Xray-core Linux release archive
XRAY_ARCH_ZIPS = {'x86_64': '64', 'aarch64': 'arm64-v8a', 'armv7l': 'arm32-v7a'}

# Panel-side serialization for clientsTable read-modify-write: the page polls
# get_clients while add/toggle/rename run, and the last save wins with a
# stale snapshot unless the whole RMW holds one lock (see wireguard_manager).
_XRAY_TABLE_LOCKS = {}
_XRAY_TABLE_LOCKS_GUARD = threading.Lock()


def _xray_clients_table_lock(host, container_name):
    with _XRAY_TABLE_LOCKS_GUARD:
        return _XRAY_TABLE_LOCKS.setdefault((host, container_name), threading.Lock())


def _serialized_table_write(method):
    """Hold the per-container table lock for the whole read-modify-write."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        host = getattr(self.ssh, 'host', '') or 'unknown'
        with _xray_clients_table_lock(host, self.container_name):
            return method(self, *args, **kwargs)
    return wrapper
# uTLS client hello fingerprints a VLESS link may request. The Reality server
# does not pin this value, so it is a per-link property, not a container
# setting; chrome stays the historical default.
XRAY_FINGERPRINTS = ('chrome', 'firefox', 'safari', 'ios', 'android', 'edge',
                     '360', 'qq', 'random', 'randomized')
XRAY_DEFAULT_FINGERPRINT = 'chrome'
# Key pair minted by `xray vlessenc` for the VLESS Encryption layer:
# server-side decryption string + client-side encryption string.
VLESS_ENC_KEY_FILE = 'xray_vlessenc.key'
# firefox over chrome: since October 2026 uTLS-chrome handshakes are
# actively filtered by Russian censors, while firefox stays lenient
# (field-tested; see the 2026 censorship-research synthesis).
XRAY_DEFAULT_FINGERPRINT = 'firefox'

class XrayManager:
    """Manages Xray (VLESS-Reality) protocol installation and client management."""
    
    PROTOCOL = 'xray'
    CONTAINER_NAME = 'amnezia-xray'
    IMAGE_NAME = 'amneziavpn/amnezia-xray' # or we can build it
    
    def __init__(self, ssh_manager, protocol='xray'):
        self.ssh = ssh_manager
        self.protocol = protocol or self.PROTOCOL
        self.base_protocol = str(self.protocol).split('__', 1)[0]
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.image_name = self._image_name(self.protocol)

    def _instance_index(self, protocol):
        parts = str(protocol or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        base_name = self.CONTAINER_NAME
        return base_name if idx <= 1 else f'{base_name}-{idx}'

    def _image_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        base_name = self.IMAGE_NAME
        return base_name if idx <= 1 else f'{base_name}-{idx}'

    def _config_dir(self):
        return '/opt/amnezia/xray' if self.instance <= 1 else f'/opt/amnezia/xray-{self.instance}'

    def _config_path(self):
        return f'{self._config_dir()}/server.json'

    def _list_xray_files(self):
        """List filenames in the on-disk Xray config directory."""
        out, _, code = self.ssh.run_sudo_command(f"ls -1 {self._config_dir()} 2>/dev/null")
        if code != 0:
            return []
        return [f for f in out.strip().split('\n') if f]

    def _detect_layout(self):
        """Pick which on-disk layout this installation uses.

        'native' — official Amnezia client layout: xray_private.key,
        xray_public.key, xray_short_id.key, xray_uuid.key plus a clientsTable
        file without an extension.
        'panel'  — legacy web-panel layout: meta.json + clientsTable.json.

        On a fresh node with no Xray files yet, defaults to 'native' so new
        installs produce the same artifacts as the official client.
        """
        if hasattr(self, '_cached_layout'):
            return self._cached_layout
        files = set(self._list_xray_files())
        if {'xray_private.key', 'xray_public.key'} & files:
            layout = 'native'
        elif 'meta.json' in files:
            layout = 'panel'
        else:
            layout = 'native'
        self._cached_layout = layout
        return layout

    def _clients_table_filename(self):
        return 'clientsTable' if self._detect_layout() == 'native' else 'clientsTable.json'

    def _clients_table_path(self):
        return f'{self._config_dir()}/{self._clients_table_filename()}'

    def _read_remote_file(self, path):
        """Read a remote text file, preferring the running container's view."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {path} 2>/dev/null"
        )
        if code != 0 or not out:
            out, _, code = self.ssh.run_sudo_command(f"cat {path} 2>/dev/null")
        if code != 0 or not out.strip():
            return None
        return out

    def _derive_pubkey_from_priv(self, priv_key):
        """Derive the Reality public key from a private key via the xray binary.
        Used as a fallback when xray_public.key is missing or unreadable.
        """
        if not priv_key:
            return ''
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} /usr/bin/xray x25519 -i {priv_key}"
        )
        if code != 0 or not out.strip():
            out, _, code = self.ssh.run_sudo_command(
                f"docker run --rm --entrypoint=\"\" {self.image_name} /usr/bin/xray x25519 -i {priv_key}"
            )
        if code != 0 or not out:
            return ''
        for line in out.split('\n'):
            if 'Public' in line and ':' in line:
                return line.split(':', 1)[1].strip()
        return ''

    def _get_default_xray_uuid(self):
        """UUID of the install-time default client (xray_uuid.key) — meaningful only
        for native-layout installs. Imports skip this UUID, mirroring the official
        Amnezia client behaviour (see usersController.cpp::getXrayClients).
        """
        if self._detect_layout() != 'native':
            return ''
        out = self._read_remote_file(f"{self._config_dir()}/xray_uuid.key")
        return (out or '').strip()

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0: return False
        out2, _, code2 = self.ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        return 'active' in out2 or 'running' in out2.lower()

    def check_container_running(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.container_name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self):
        _st_fn = getattr(self.ssh, 'docker_container_state', None)
        if _st_fn:
            _st = _st_fn(self.container_name)
            if _st is not None:
                return _st[0]
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.container_name}$ --format '{{{{.Names}}}}'"
        )
        return self.container_name in out.strip().split('\n')

    def get_server_status(self, protocol):
        exists = self.check_protocol_installed()
        running = self.check_container_running()
        clients = self.get_clients() if exists else []
        meta = self._get_meta_json() if exists else {}
        return {
            'container_exists': exists,
            'container_running': running,
            'clients_count': len(clients),
            'port': meta.get('port')
        }

    def get_core_version(self):
        """Xray-core version the running container reports, or None."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} /usr/bin/xray version 2>/dev/null")
        if code != 0:
            return None
        match = re.search(r'^Xray\s+(\S+)', out or '', re.MULTILINE)
        return match.group(1) if match else None

    def get_node_arch(self):
        """Machine architecture of the node, for the release archive name."""
        out, _, _ = self.ssh.run_command("uname -m")
        return (out or '').strip() or 'x86_64'

    def update_core(self, target_release, progress=None, ingress_ip=None):
        """Rebuild the image with ``target_release`` and recreate the container.

        The config, keys and clientsTable live in the config_dir volume and
        survive the recreation untouched. The previous image is kept under a
        ``:previous`` tag until the new container is seen running the target
        version; a failed start rolls the container back to it.

        ``progress(stage, message)`` mirrors the stages to an install op.
        """

        def report(stage, message):
            if progress:
                progress(stage, message)

        # Older installs predate the host-tuning call in install_protocol:
        # bring the host up to BBR on the way (idempotent, silent fallback).
        report('host', 'applying host network tuning (BBR)')
        AWGManager(self.ssh).setup_host_tuning()

        current = self.get_core_version()
        report('version', f"current core: {current or 'unknown'}")
        if current and current.lstrip('v') == target_release.lstrip('v'):
            return {'status': 'success', 'updated': False,
                    'version': current, 'log': [f"core is already {current}"]}

        arch = XRAY_ARCH_ZIPS.get(self.get_node_arch(), '64')
        report('arch', f"node architecture: {self.get_node_arch()} (asset: {arch})")

        # Keep the running image until the new one is proven working.
        self.ssh.run_sudo_command(
            f"docker tag {self.image_name} {self.image_name}:previous")

        dockerfile_folder = f"/opt/amnezia/{self.container_name}"
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(
            self._dockerfile_content(release=target_release, arch=arch),
            f"{dockerfile_folder}/Dockerfile")
        report('build', f"building the image with Xray-core {target_release}")
        _, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache "
            f"--build-arg XRAY_RELEASE={target_release} "
            f"--build-arg XRAY_ARCH={arch} "
            f"-t {self.image_name} {dockerfile_folder}", timeout=600)
        if code != 0:
            raise RuntimeError(f"Failed to build the new image: {err}")

        report('verify', 'checking the new binary inside the image')
        out, _, code = self.ssh.run_sudo_command(
            f"docker run --rm --entrypoint=\"\" {self.image_name} "
            f"/usr/bin/xray version")
        if code != 0 or f"Xray {target_release.lstrip('v')}" not in (out or ''):
            raise RuntimeError("the new image does not run the target Xray-core")

        # The live server.json is authoritative for the port.
        meta = self._get_meta_json() or {}
        port = meta.get('port')
        if not port:
            raise RuntimeError("Xray port is unknown; cannot recreate the container")
        config_dir = self._config_dir()
        run_cmd = self._container_run_cmd(port, ingress_ip)

        report('swap', f"recreating {self.container_name} (a few seconds of downtime)")
        self.ssh.run_sudo_command(f"docker stop {self.container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {self.container_name}")
        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run the new container: {err}")

        def running_target_version():
            self.ssh.run_sudo_command("sleep 3")
            if not self.check_container_running():
                return None
            return self.get_core_version()

        report('check', 'waiting for the core to start')
        version_now = running_target_version()
        if (version_now or '').lstrip('v') != target_release.lstrip('v'):
            report('error', f"the new core did not start (got {version_now or 'nothing'}); rolling back")
            self.ssh.run_sudo_command(f"docker rm -fv {self.container_name}")
            self.ssh.run_sudo_command(
                f"docker tag {self.image_name}:previous {self.image_name}")
            _, err, code = self.ssh.run_sudo_command(run_cmd)
            if code != 0:
                raise RuntimeError(f"rollback failed: {err}")
            return {
                'status': 'error',
                'message': (f"Xray-core {target_release} did not start; "
                            f"the previous core ({current or 'unknown'}) is running again"),
                'version': current,
                'updated': False,
            }

        # Success: retire the backup tag (the old image becomes dangling).
        self.ssh.run_sudo_command(f"docker rmi {self.image_name}:previous")
        report('done', f"Xray-core is now {target_release}")
        return {
            'status': 'success',
            'updated': True,
            'version': target_release.lstrip('v'),
            'previous': current,
            'log': [f"updated {current or '?'} -> {target_release}"],
        }

    def get_port_usage(self):
        """Running state and client count for the server header IP chips.

        A light probe: no stats query and no meta/key reads.
        """
        running = self.check_container_running()
        return {'running': running,
                'clients': len(self._get_clients_table()) if running else 0}

    def _dockerfile_content(self, release=None, arch='64'):
        config_dir = self._config_dir()
        release = release or XRAY_CORE_VERSION
        return f"""FROM alpine:3.15
RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz iptables ip6tables
RUN apk --update upgrade --no-cache
RUN mkdir -p {config_dir}
ARG XRAY_RELEASE="{release}"
ARG XRAY_ARCH="{arch}"
RUN curl -L -H "Cache-Control: no-cache" -o /root/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${{XRAY_RELEASE}}/Xray-linux-${{XRAY_ARCH}}.zip" && \\
    unzip /root/xray.zip -d /usr/bin/ && \\
    chmod a+x /usr/bin/xray && \\
    rm /root/xray.zip

# Tune network
RUN echo "fs.file-max = 51200" >> /etc/sysctl.conf && \\
    echo "net.core.rmem_max = 67108864" >> /etc/sysctl.conf && \\
    echo "net.core.wmem_max = 67108864" >> /etc/sysctl.conf && \\
    echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf && \\
    echo "net.core.somaxconn = 4096" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_tw_recycle = 0" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf && \\
    echo "net.ipv4.ip_local_port_range = 10000 65000" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_mem = 25600 51200 102400" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_rmem = 4096 87380 67108864" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_wmem = 4096 65536 67108864" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf

RUN mkdir -p /etc/security && \\
    echo "* soft nofile 51200" >> /etc/security/limits.conf && \\
    echo "* hard nofile 51200" >> /etc/security/limits.conf

RUN echo '#!/bin/bash' > /opt/amnezia/start.sh && \\
    echo 'sysctl -p /etc/sysctl.conf 2>/dev/null' >> /opt/amnezia/start.sh && \\
    echo '/usr/bin/xray -config {config_dir}/server.json' >> /opt/amnezia/start.sh && \\
    chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
"""

    def _container_run_cmd(self, port, ingress_ip=None):
        """The docker run command for the xray container. ingress_ip pins
        the published ports to one host address, so the egress address
        stops exposing the VPN listener."""
        bind = f"{ingress_ip}:" if ingress_ip else ""
        return f"""docker run -d \\
--restart always \\
--privileged \\
--cap-add=NET_ADMIN \\
-p {bind}{port}:{port}/tcp \\
-p {bind}{port}:{port}/udp \\
-v {self._config_dir()}:{self._config_dir()} \\
--name {self.container_name} \\
{self.image_name}"""

    def recreate_container(self, ingress_ip=None):
        """Recreate the container in place (same image, config volume
        survives) - applies the ingress binding without a full core
        update. Brief downtime. If the bound run fails (e.g. the address
        is not on the host), the container is restored without the
        binding first, then the error is raised - the VPN must not stay
        down because of a failed publish."""
        meta = self._get_meta_json() or {}
        port = meta.get('port')
        if not port:
            raise RuntimeError("Xray port is unknown; cannot recreate the container")
        self.ssh.run_sudo_command(f"docker stop {self.container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {self.container_name}")
        _, err, code = self.ssh.run_sudo_command(
            self._container_run_cmd(port, ingress_ip))
        if code != 0 and ingress_ip:
            _, plain_err, plain_code = self.ssh.run_sudo_command(
                self._container_run_cmd(port))
            if plain_code != 0:
                raise RuntimeError(f"Failed to run the container: {err}")
            raise RuntimeError(
                f"Failed to publish the ports on {ingress_ip} ({err}) - "
                "the container was restored without the binding")
        if code != 0:
            raise RuntimeError(f"Failed to run the container: {err}")
        self.ssh.run_sudo_command(
            f"docker network connect amnezia-dns-net {self.container_name} || true")
        self.ssh.run_sudo_command("sleep 3")
        if not self.check_container_running():
            raise RuntimeError("the container did not start after the recreation")
        return {'port': int(port)}

    def install_protocol(self, port=443, site_name='yahoo.com', transport='tcp',
                         ingress_ip=None):
        """Full installation of Xray.

        transport: 'tcp' keeps the legacy TCP+Vision preset, 'xhttp' moves
        the traffic onto the XHTTP transport (plain HTTP/2 requests).
        """
        if transport not in ('tcp', 'xhttp'):
            raise ValueError(f"Unsupported Xray transport: {transport}")
        results = []

        if not self.check_docker_installed():
            results.append("Installing Docker...")
            # Using same install method as AWGManager or assume it's installed
            pass

        results.append("Removing old container if exists...")
        if self.check_protocol_installed():
            self.remove_container()

        results.append("Building Docker image...")
        config_dir = self._config_dir()
        dockerfile_folder = f"/opt/amnezia/{self.container_name}"
        dockerfile_content = self._dockerfile_content()
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")
        
        old_image_id = docker_image_cleanup.image_id(self.ssh, self.image_name)
        _, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache -t {self.image_name} {dockerfile_folder}", timeout=300
        )
        if code != 0: raise RuntimeError(f"Failed to build container: {err}")
        # The tag now points at the new build; the previous image of this very
        # instance would otherwise stay behind as <none>:<none>.
        docker_image_cleanup.drop_replaced_image(
            self.ssh, self.image_name, old_image_id)

        results.append("Generating keys and config...")
        # We generate a base config using a temp container or directly if host has openssl
        
        # Xray keypair generation using a temporary run overriding the entrypoint
        keypair_cmd = f"docker run --rm --entrypoint=\"\" {self.image_name} /usr/bin/xray x25519"
        out_kp, err_kp, code_kp = self.ssh.run_sudo_command(keypair_cmd)
        if code_kp != 0: raise RuntimeError(f"Failed to generate x25519 keys: {err_kp}")
        
        priv_key = ""
        pub_key = ""
        for line in out_kp.split('\n'):
            if "Private" in line: priv_key = line.split(":", 1)[1].strip()
            if "Public" in line: pub_key = line.split(":", 1)[1].strip()

        short_id_cmd = f"docker run --rm --entrypoint=\"\" {self.image_name} openssl rand -hex 8"
        out_sid, _, _ = self.ssh.run_sudo_command(short_id_cmd)
        short_id = out_sid.strip()

        # Generate initial server.json with Stats and API enabled
        reality_settings = {
            "dest": f"{site_name}:443",
            "serverNames": [site_name],
            "privateKey": priv_key,
            "shortIds": [short_id]
        }
        # XHTTP presents the traffic as ordinary HTTP/2 requests instead of
        # a raw TCP stream; the path is randomized per install as well.
        if transport == 'xhttp':
            stream_settings = {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "path": '/' + uuid.uuid4().hex[:16],
                    "host": site_name,
                    "mode": "auto",
                    "extra": _xhttp_extra(),
                },
                "realitySettings": reality_settings,
            }
        else:
            stream_settings = {
                "network": "tcp",
                "security": "reality",
                "realitySettings": reality_settings,
            }
        server_json = {
            "log": {"loglevel": "error"},
            "stats": {},
            "api": {
                "services": ["StatsService", "LoggerService", "HandlerService"],
                "tag": "api"
            },
            "policy": {
                "levels": {
                    "0": {"statsUserUplink": True, "statsUserDownlink": True}
                },
                "system": {
                    "statsInboundUplink": True, "statsInboundDownlink": True,
                    "statsOutboundUplink": True, "statsOutboundDownlink": True
                }
            },
            "inbounds": [
                {
                    "port": int(port),
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                        "clients": [],
                        "decryption": "none"
                    },
                    "streamSettings": stream_settings,
                    # routeOnly: the sniffed domain feeds routing rules only,
                    # the connection still dials the original destination.
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True
                    },
                },
                {
                    "listen": "127.0.0.1",
                    "port": 10085,
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                    "tag": "api"
                }
            ],
            # Pin egress to IPv4: on a dual-stack host a silent AAAA route
            # leaks the server's second address.
            "outbounds": [{"protocol": "freedom", "domainStrategy": "UseIPv4"}],
            "routing": {
                "rules": [
                    {
                        "inboundTag": ["api"],
                        "outboundTag": "api",
                        "type": "field"
                    }
                ]
            }
        }
        
        self.ssh.run_sudo_command(f"mkdir -p {config_dir}")
        self.ssh.upload_file_sudo(json.dumps(server_json, indent=2), f"{config_dir}/server.json")
        # Native layout — separate key files matching the official Amnezia client install.
        # Everything lands in THIS instance's config_dir: a second instance
        # (xray__2 -> /opt/amnezia/xray-2) must not share the base keys.
        # See client/server_scripts/xray/configure_container.sh for the canonical layout.
        self.ssh.upload_file_sudo(priv_key + '\n', f"{config_dir}/xray_private.key")
        self.ssh.upload_file_sudo(pub_key + '\n', f"{config_dir}/xray_public.key")
        self.ssh.upload_file_sudo(short_id + '\n', f"{config_dir}/xray_short_id.key")
        # xray_uuid.key marks the install-time "default" client whose ID gets skipped on
        # auto-import. Panel installs do not reserve such a client, so we leave it empty.
        self.ssh.upload_file_sudo('\n', f"{config_dir}/xray_uuid.key")
        self.ssh.upload_file_sudo("[]", f"{config_dir}/clientsTable")

        # Host-level BBR (same routine as AWG installs): the container's own
        # start.sh sets congestion control in its network namespace, but that
        # only works when the tcp_bbr module is loaded on the host — and the
        # host qdisc stays cubic without this.
        results.append("Applying host network tuning (BBR)...")
        AWGManager(self.ssh).setup_host_tuning()
        results.append("Host network tuning applied")

        results.append("Starting container...")
        run_cmd = self._container_run_cmd(port, ingress_ip)

        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0: raise RuntimeError(f"Failed to run container: {err}")

        # Try to connect to network if needed
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.container_name} || true")

        results.append("Xray configured and running")
        return {'status': 'success', 'protocol': self.protocol, 'port': port, 'log': results}

    def remove_container(self):
        commands = (
            (f"docker stop {self.container_name}", 'no such container'),
            (f"docker rm -fv {self.container_name}", 'no such container'),
        )
        for command, absent_marker in commands:
            out, err, code = self.ssh.run_sudo_command(command)
            detail = (err or out or '').strip()
            if code != 0 and absent_marker not in detail.lower():
                raise RuntimeError(f"Xray uninstall failed: {detail or f'exit code {code}'}")
        # Images are named per instance (amnezia-xray, amnezia-xray-2, ...), so
        # the image belongs to this instance and must go with it. Re-tagged or
        # shared images are still safe: never remove one another container uses.
        if not self._image_in_use():
            out, err, code = self.ssh.run_sudo_command(f"docker rmi {self.image_name}")
            detail = (err or out or '').strip().lower()
            if (code != 0 and 'no such image' not in detail
                    and 'image is being used' not in detail):
                raise RuntimeError(
                    f"Xray uninstall failed: {detail or f'exit code {code}'}")
        # The build context carries a single generated Dockerfile; the next
        # install recreates it from scratch (--no-cache --pull). Drop it so an
        # uninstalled instance leaves no /opt/amnezia/<container> directory.
        self.ssh.run_sudo_command(f"rm -rf /opt/amnezia/{self.container_name}")
        return True

    def _image_in_use(self):
        """True when some container on the host still runs/uses our image."""
        out, _, code = self.ssh.run_sudo_command(
            "docker ps -a --format '{{.Image}}'")
        if code != 0:
            return False
        return self.image_name in (out or '').split()

    # ===================== CLIENT MANAGEMENT =====================

    def _get_server_json(self):
        """Read server.json — tries inside container first, falls back to host path."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {self._config_path()}"
        )
        if code != 0:
            out, _, code = self.ssh.run_sudo_command(f"cat {self._config_path()}")
        if code != 0 or not out.strip():
            return None
        return json.loads(out)

    def _save_server_json(self, data):
        return self._write_server_json(data, restart=True)

    def _write_server_json(self, data, restart=True):
        """Write server.json into container via docker cp AND sync to host path."""
        tmp_file = "/tmp/_xray_server.json"
        self.ssh.upload_file_sudo(json.dumps(data, indent=2), tmp_file)
        self.ssh.run_sudo_command(
            f"docker cp {tmp_file} {self.container_name}:{self._config_path()}"
        )
        # Also keep host copy in sync (handles both volume-mount and no-mount installs)
        self.ssh.run_sudo_command(
            f"cp {tmp_file} {self._config_path()} 2>/dev/null || true"
        )
        if restart:
            self.ssh.run_sudo_command(f"docker restart {self.container_name}")

    def _get_vless_inbound(self, config):
        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'vless':
                return inbound
        return None

    def _get_vless_inbound_tag(self, config):
        inbound = self._get_vless_inbound(config)
        return inbound.get('tag') if inbound else None

    def _run_xray_api_json(self, subcommand, payload):
        tmp_name = f"/tmp/_xray_api_{uuid.uuid4().hex}.json"
        container_tmp = tmp_name
        try:
            self.ssh.upload_file_sudo(json.dumps(payload, indent=2), tmp_name)
            _, err, code = self.ssh.run_sudo_command(
                f"docker cp {tmp_name} {self.container_name}:{container_tmp}"
            )
            if code != 0:
                return False, err
            out, err, code = self.ssh.run_sudo_command(
                f"docker exec -i {self.container_name} /usr/bin/xray api {subcommand} "
                f"-server=127.0.0.1:10085 {container_tmp}"
            )
            return code == 0, err or out
        finally:
            self.ssh.run_sudo_command(f"rm -f {tmp_name}")
            self.ssh.run_sudo_command(f"docker exec -i {self.container_name} rm -f {container_tmp} 2>/dev/null || true")

    def _xray_api_add_user(self, config, client):
        tag = self._get_vless_inbound_tag(config)
        if not tag:
            return False
        _ib = self._get_vless_inbound(config) or {}
        payload = {
            "inbounds": [{
                "tag": tag,
                "port": _ib.get('port', 443),
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "clients": [client],
                    "decryption": "none",
                }
            }]
        }
        ok, message = self._run_xray_api_json('adu', payload)
        if not ok or 'Added 0 user' in (message or ''):
            logger.warning(f"Xray API add user failed: {message}")
            return False
        return True

    def _xray_api_remove_user(self, config, client_id):
        tag = self._get_vless_inbound_tag(config)
        if not tag:
            return False
        cmd = (
            f"docker exec -i {self.container_name} /usr/bin/xray api rmu "
            f"-server=127.0.0.1:10085 "
            f"-tag={shlex.quote(tag)} {shlex.quote(client_id)}"
        )
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0:
            logger.warning(f"Xray API remove user failed: {err or out}")
            return False
        return True

    def _get_meta_json(self):
        """Read protocol metadata. Supports both layouts.

        Native layout pulls keys from xray_*.key files. Panel layout reads
        meta.json. Either way, port and site_name come from server.json since
        that is the authoritative runtime config — meta.json may go stale if
        the user edits server.json directly via the panel.
        """
        config = self._get_server_json() or {}

        port = None
        site_name = None
        rs = {}
        try:
            ib = next(b for b in config.get('inbounds', []) if b.get('protocol') == 'vless')
            port = ib.get('port')
            rs = ib.get('streamSettings', {}).get('realitySettings', {}) or {}
            names = rs.get('serverNames') or []
            if names:
                site_name = names[0]
        except StopIteration:
            pass

        if self._detect_layout() == 'native':
            priv = (self._read_remote_file(f"{self._config_dir()}/xray_private.key") or '').strip()
            pub = (self._read_remote_file(f"{self._config_dir()}/xray_public.key") or '').strip()
            sid = (self._read_remote_file(f"{self._config_dir()}/xray_short_id.key") or '').strip()
            if not priv:
                priv = rs.get('privateKey', '')
            if not sid:
                sids = rs.get('shortIds') or []
                sid = sids[0] if sids else ''
            if not pub:
                pub = self._derive_pubkey_from_priv(priv)
            pair = self._read_vlessenc_pair()
            return {
                'private_key': priv,
                'public_key': pub,
                'short_id': sid,
                'port': port,
                'site_name': site_name or 'yahoo.com',
                'vless_client_encryption': pair.get('encryption', ''),
            }

        # Panel (legacy) layout
        out = self._read_remote_file(f"{self._config_dir()}/meta.json")
        meta = {}
        if out:
            try:
                meta = json.loads(out)
            except Exception:
                meta = {}
        if port is not None:
            meta['port'] = port
        if site_name:
            meta['site_name'] = site_name
        if not meta.get('private_key'):
            meta['private_key'] = rs.get('privateKey', '')
        if not meta.get('short_id'):
            sids = rs.get('shortIds') or []
            if sids:
                meta['short_id'] = sids[0]
        if not meta.get('public_key') and meta.get('private_key'):
            meta['public_key'] = self._derive_pubkey_from_priv(meta['private_key'])
        pair = self._read_vlessenc_pair()
        meta.setdefault('vless_client_encryption', pair.get('encryption', ''))
        return meta

    def _read_vlessenc_pair(self):
        """The matched decryption/encryption strings minted by vlessenc."""
        raw = self._read_remote_file(f"{self._config_dir()}/{VLESS_ENC_KEY_FILE}")
        if not (raw or '').strip():
            return {}
        try:
            pair = json.loads(raw)
        except ValueError:
            return {}
        return pair if isinstance(pair, dict) else {}

    def _write_vlessenc_pair(self, decryption, encryption):
        self.ssh.upload_file_sudo(
            json.dumps({'decryption': decryption,
                        'encryption': encryption}, indent=2),
            f"{self._config_dir()}/{VLESS_ENC_KEY_FILE}")

    def _get_clients_table(self, strict=False):
        """Read clientsTable, trying both layout filenames.

        Strict recovery reads distinguish a valid empty table from an unreadable
        or malformed one; ordinary UI reads retain the legacy empty fallback.
        """
        layout = self._detect_layout()
        primary = 'clientsTable' if layout == 'native' else 'clientsTable.json'
        fallback = 'clientsTable.json' if layout == 'native' else 'clientsTable'
        if strict:
            for fname in dict.fromkeys((primary, fallback)):
                path = f"{self._config_dir()}/{fname}"
                out, _, code = self.ssh.run_sudo_command(
                    f"docker exec {self.container_name} cat {path} 2>/dev/null")
                if code != 0:
                    out, _, code = self.ssh.run_sudo_command(f"cat {path} 2>/dev/null")
                if code != 0:
                    continue
                if not (out or '').strip():
                    return []
                try:
                    table = json.loads(out)
                except (TypeError, ValueError) as error:
                    raise RuntimeError('Xray clients table is not valid JSON') from error
                if not isinstance(table, list):
                    raise RuntimeError('Xray clients table has an invalid structure')
                return table
            raise RuntimeError('Xray clients table is unavailable')
        for fname in (primary, fallback):
            out = self._read_remote_file(f"{self._config_dir()}/{fname}")
            if not out or not out.strip():
                continue
            try:
                return json.loads(out)
            except Exception:
                continue
        return []

    def _save_clients_table(self, data):
        """Write clientsTable to the file matching the current layout, in the
        container and on the host bind-mount.

        Delegated to the shared checked writer (private host staging, atomic
        rename inside the container, one previous snapshot kept as
        <path>.panel-backup). Callers hold the per-container table lock.
        """
        save_clients_table(self.ssh, self.container_name, self._clients_table_path(), data)

    def _upgrade_config_for_stats(self, config, restart=True):
        """Injects API/Stats blocks and connection hardening into older
        Xray configs transparently."""
        dirty = False
        if 'stats' not in config:
            config['stats'] = {}
            dirty = True
        if 'api' not in config:
            config['api'] = {"services": ["StatsService", "LoggerService", "HandlerService"], "tag": "api"}
            dirty = True
        else:
            services = config['api'].setdefault('services', [])
            if 'HandlerService' not in services:
                services.append('HandlerService')
                dirty = True
        if 'policy' not in config:
            config['policy'] = {
                "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                "system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True}
            }
            dirty = True
        if 'routing' not in config:
            config['routing'] = {"rules": [{"inboundTag": ["api"], "outboundTag": "api", "type": "field"}]}
            dirty = True
            
        has_api_inbound = any(ib.get('tag') == 'api' for ib in config.get('inbounds', []))
        if not has_api_inbound:
            config.setdefault('inbounds', []).append({
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api"
            })
            dirty = True
            
        for ib in config.get('inbounds', []):
            if ib.get('protocol') == 'vless':
                if not ib.get('tag'):
                    ib['tag'] = 'proxy'
                    dirty = True
                for c in ib.get('settings', {}).get('clients', []):
                    if 'email' not in c:
                        c['email'] = c['id']
                        dirty = True

        # Hardening for older installs: sniffing gives domain-based routing
        # rules the real destination even for TUN clients that dial IPs, and
        # pinning the freedom egress to IPv4 stops a silent AAAA leak on
        # dual-stack hosts. A sniffing block or strategy the user already
        # set is left untouched.
        for ib in config.get('inbounds', []):
            if ib.get('protocol') == 'vless' and not isinstance(ib.get('sniffing'), dict):
                ib['sniffing'] = {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True
                }
                dirty = True
        for ob in config.get('outbounds', []):
            if ob.get('protocol') == 'freedom' and 'domainStrategy' not in ob:
                ob['domainStrategy'] = 'UseIPv4'
                dirty = True

        if dirty:
            self._write_server_json(config, restart=restart)
        return dirty

    def _query_xray_stats(self):
        """Query Xray API for traffic stats using xray api command."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.container_name} /usr/bin/xray api statsquery -server=127.0.0.1:10085"
        )
        if code != 0 or not out.strip():
            return {}
        
        try:
            stats_raw = json.loads(out)
        except Exception:
            return {}

        results = {}
        # Output format: {"stat": [{"name": "user>>>uid>>>traffic>>>downlink", "value": "123"}, ...]}
        for item in stats_raw.get('stat', []):
            name_parts = item.get('name', '').split('>>>')
            if len(name_parts) == 4 and name_parts[0] == 'user':
                uid = name_parts[1]
                t_type = name_parts[3] # uplink or downlink
                val = int(item.get('value', 0))
                
                if uid not in results:
                    results[uid] = {'rx': 0, 'tx': 0}
                
                if t_type == 'downlink':
                    results[uid]['rx'] = val
                elif t_type == 'uplink':
                    results[uid]['tx'] = val
                    
        return results

    def _format_bytes(self, size):
        # Format bytes to string like AWG (e.g., 1.50 MiB)
        power = 2**10
        n = 0
        powers = {0: 'B', 1: 'KiB', 2: 'MiB', 3: 'GiB', 4: 'TiB'}
        while size > power:
            size /= power
            n += 1
        v = round(size, 2)
        if v == int(v):
            v = int(v)
        return f"{v} {powers.get(n, 'B')}"

    @_serialized_table_write
    def get_clients(self, protocol=None, strict=True):
        # strict by default: this read feeds auto-import and lastSeen
        # persistence, and a transient SSH failure answered with an empty
        # table would be written back over the real one (issue #182).
        config = self._get_server_json()
        if not config:
            if strict:
                raise RuntimeError('Xray live config is unavailable')
            return []

        self._upgrade_config_for_stats(config, restart=False)

        # Collect all client IDs currently registered in the Xray server config
        xray_clients = []
        for ib in config.get('inbounds', []):
            if ib.get('protocol') == 'vless':
                xray_clients.extend(ib.get('settings', {}).get('clients', []))

        clients_table = self._get_clients_table(strict=strict)
        table_ids = {c['clientId'] for c in clients_table}

        # Auto-import clients present in server.json but missing from clientsTable
        # (e.g. added via the native Amnezia phone/desktop app). Skip the install-time
        # default UUID for native-layout installs — the official client treats it as
        # the device of the user who installed the server, not a manageable client.
        default_uuid = self._get_default_xray_uuid()
        updated = False
        for xc in xray_clients:
            uid = xc.get('id')
            if not uid or uid in table_ids or uid == default_uuid:
                continue
            clients_table.append({
                'clientId': uid,
                'userData': {
                    'clientName': f'Imported_{uid[:8]}',
                    'creationDate': datetime.now().isoformat(),
                    'enabled': True
                }
            })
            table_ids.add(uid)
            updated = True
            logger.info(f"Auto-imported Xray client {uid[:8]} from server.json")

        if updated:
            self._save_clients_table(clients_table)

        stats = self._query_xray_stats()

        # The stats API only reports cumulative per-client counters, so "last
        # activity" is derived here: counters that grew since the previous
        # poll mean the client exchanged traffic in between. The counters are
        # persisted alongside the stamped lastSeen; when they shrink (a
        # container restart resets them), they are re-baselined instead so
        # growth from zero registers as fresh activity later on.
        stats_dirty = False
        for c in clients_table:
            uid = c.get('clientId', '')
            if uid not in stats:
                continue
            user_data = c.setdefault('userData', {})
            rx = stats[uid]['rx']
            tx = stats[uid]['tx']
            prev_total = ((user_data.get('dataReceivedBytes') or 0)
                          + (user_data.get('dataSentBytes') or 0))
            if rx + tx > prev_total:
                user_data['lastSeen'] = datetime.now().isoformat()
                stats_dirty = True
            if rx > 0 or tx > 0:
                if (user_data.get('dataReceivedBytes') != rx
                        or user_data.get('dataSentBytes') != tx):
                    user_data['dataReceived'] = self._format_bytes(rx)
                    user_data['dataSent'] = self._format_bytes(tx)
                    user_data['dataReceivedBytes'] = rx
                    user_data['dataSentBytes'] = tx
                    stats_dirty = True
            elif rx + tx < prev_total:
                user_data['dataReceivedBytes'] = rx
                user_data['dataSentBytes'] = tx
                stats_dirty = True

        if stats_dirty:
            self._save_clients_table(clients_table)

        return clients_table


    def get_client_config(self, protocol, client_id, server_host, port, public_port=None,
                          fingerprint=None):
        clients = self._get_clients_table()
        client = next((c for c in clients if c['clientId'] == client_id), None)
        if not client: return None

        meta = self._get_meta_json()
        if not meta: return None

        config = self._get_server_json()
        sni = meta.get('site_name', 'yahoo.com')
        stream = {}
        settings_node = {}
        runtime_flow = ''
        if config:
            try:
                inbound = config['inbounds'][0]
                stream = inbound.get('streamSettings', {}) or {}
                sni = stream['realitySettings']['serverNames'][0]
                settings_node = inbound.get('settings', {}) or {}
                runtime_flow = next((c.get('flow', '') for c in settings_node.get('clients', [])
                                     if c.get('id') == client_id), '')
            except (StopIteration, KeyError, TypeError, IndexError):
                pass

        # The link is derived from the live server.json streamSettings, so a
        # transport the panel did not install (hand-edited config) still
        # produces a usable link. The flow comes from the runtime client
        # entry: with the VLESS Encryption layer Vision rides XHTTP too.
        network = stream.get('network', 'tcp')
        # The instance-level fingerprint chosen in the panel beats the default;
        # an unknown value (hand-edited data.json) falls back instead of
        # reaching the link.
        fp = fingerprint if fingerprint in XRAY_FINGERPRINTS else XRAY_DEFAULT_FINGERPRINT
        params = [
            "security=reality",
            f"pbk={meta['public_key']}",
            f"sni={urllib.parse.quote(sni, safe='')}",
            f"fp={fp}",
            f"sid={meta['short_id']}",
            "spx=%2F",
        ]

        if network == 'xhttp':
            settings = stream.get('xhttpSettings', {}) or {}
            params.insert(0, "type=xhttp")
            params.append("path=" + urllib.parse.quote(settings.get('path', '/') or '/', safe=''))
            params.append("host=" + urllib.parse.quote(settings.get('host') or sni, safe=''))
            if settings.get('mode'):
                params.append("mode=" + urllib.parse.quote(str(settings['mode']), safe=''))
            extra = settings.get('extra')
            if extra:
                # Share links carry extra as compact, percent-encoded JSON.
                params.append("extra=" + urllib.parse.quote(
                    json.dumps(extra, separators=(',', ':')), safe=''))
        else:
            params.insert(0, "type=" + urllib.parse.quote(str(network), safe=''))
        # The runtime client entry is authoritative for the flow: it carries
        # xtls-rprx-vision on raw TCP presets and, with the VLESS Encryption
        # layer enabled, on XHTTP as well. An empty flow means none.
        if runtime_flow:
            params.append("flow=" + urllib.parse.quote(runtime_flow, safe=''))
        client_encryption = meta.get('vless_client_encryption')
        decryption = settings_node.get('decryption')
        if (client_encryption and isinstance(decryption, str)
                and decryption not in ('', 'none')):
            # The second encryption layer rides every link of this inbound.
            params.append("encryption=" + urllib.parse.quote(client_encryption, safe=''))
        # Format URL
        # vless://{id}@{host}:{port}?type=tcp&security=reality&pbk={public_key}&sni={sni}&fp=chrome&sid={short_id}&spx=%2F&flow=xtls-rprx-vision#{name}

        name = client.get('userData', {}).get('clientName', 'vpn')
        encoded_name = urllib.parse.quote(name)

        url = (
            # meta.json is synced from the live server.json, so it beats the
            # port the panel remembers; an explicit public port beats both.
            f"vless://{client_id}@{server_host}:{public_port or meta.get('port', port)}"
            f"?{'&'.join(params)}#{encoded_name}"
        )
        return url

    def get_runtime_client_ids(self):
        """UUIDs registered in the live server.json vless inbounds.

        The authoritative "can this peer carry traffic" state: the
        clientsTable view can lag a hand-edited config and may keep a row
        enabled long after the peer left the runtime."""
        config = self._get_server_json()
        if not config:
            raise RuntimeError('Xray live config is unavailable')
        return [c.get('id')
                for ib in config.get('inbounds', []) if ib.get('protocol') == 'vless'
                for c in ib.get('settings', {}).get('clients', [])]

    def get_reality_state(self):
        """Current transport and Reality target of the VLESS inbound."""
        config = self._get_server_json()
        if not config:
            return None
        inbound = self._get_vless_inbound(config)
        if not inbound:
            return None
        stream = inbound.get('streamSettings', {}) or {}
        reality = stream.get('realitySettings', {}) or {}
        names = reality.get('serverNames') or []
        return {
            'network': stream.get('network', 'tcp'),
            'dest': reality.get('dest'),
            'sni': names[0] if names else None,
        }

    def get_vless_encryption_state(self):
        """Whether the VLESS Encryption layer is on, and the transport it
        rides (the toggle applies to XHTTP only)."""
        config = self._get_server_json()
        if not config:
            raise RuntimeError('Xray live config is unavailable')
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError('Xray VLESS inbound not found')
        stream = inbound.get('streamSettings', {}) or {}
        decryption = inbound.get('settings', {}).get('decryption')
        enabled = isinstance(decryption, str) and decryption not in ('', 'none')
        return {'enabled': enabled,
                'transport': stream.get('network', 'tcp'),
                'decryption': decryption if isinstance(decryption, str) else ''}

    def _generate_vlessenc_pair(self):
        """Run `xray vlessenc` and return (decryption, encryption) - the
        matched server/client strings it prints."""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} /usr/bin/xray vlessenc")
        if code != 0 or not (out or '').strip():
            raise RuntimeError(f'vlessenc failed: {err or out}')
        try:
            data = json.loads(out)
        except ValueError:
            data = None
        if isinstance(data, dict) and data.get('decryption') and data.get('encryption'):
            return str(data['decryption']), str(data['encryption'])
        decryption = re.search(r'decryption["\s:]+([^\s"]+)', out)
        encryption = re.search(r'encryption["\s:]+([^\s"]+)', out)
        if decryption and encryption:
            return decryption.group(1), encryption.group(1)
        raise RuntimeError('could not parse the vlessenc output')

    def set_vless_encryption(self, enable):
        """Toggle the VLESS Encryption layer (Vision over XHTTP).

        Enabling mints a matched decryption/encryption pair with
        `xray vlessenc`, stores it in the key file, points the inbound's
        decryption at the server string, sets every client's flow to
        Vision and restarts. Disabling reverts to decryption 'none' and
        empty flows. Existing client configs are invalidated: every user
        must re-import the subscription, and only up-to-date Xray-core
        clients carry the layer."""
        config = self._get_server_json()
        if not config:
            raise RuntimeError('Xray live config is unavailable')
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError('Xray VLESS inbound not found')
        stream = inbound.get('streamSettings', {}) or {}
        if stream.get('network') != 'xhttp':
            raise RuntimeError(
                'VLESS Encryption requires the XHTTP transport')
        settings = inbound.setdefault('settings', {})
        clients = settings.setdefault('clients', [])
        if enable:
            decryption, encryption = self._generate_vlessenc_pair()
            settings['decryption'] = decryption
            self._write_vlessenc_pair(decryption, encryption)
            for client in clients:
                client['flow'] = 'xtls-rprx-vision'
        else:
            settings['decryption'] = 'none'
            for client in clients:
                client['flow'] = ''
            self.ssh.run_sudo_command(
                f"rm -f {shlex.quote(self._config_dir() + '/' + VLESS_ENC_KEY_FILE)}")
        self._write_server_json(config, restart=True)
        return self.get_vless_encryption_state()

    def apply_selfsteal(self, domain, dest):
        """Point Reality at the local NGINX site (self-steal SNI).

        The site must already answer with a valid certificate for the
        domain — failed probes are forwarded there, so the mask only
        holds while the site is real. dest uses the docker name when the
        containers share a network, so it survives re-creation.
        """
        config = self._get_server_json()
        if not config:
            raise RuntimeError("Xray server config not found.")
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")
        stream = inbound.get('streamSettings', {}) or {}
        reality = stream.get('realitySettings') or {}
        if not reality:
            raise RuntimeError("Reality is not configured on this instance.")
        reality['dest'] = dest
        reality['serverNames'] = [domain]
        # XHTTP carries the mask in the Host header as well.
        if stream.get('network') == 'xhttp':
            stream.setdefault('xhttpSettings', {})['host'] = domain
        self._write_server_json(config, restart=True)
        return {'dest': dest, 'sni': domain, 'network': stream.get('network', 'tcp')}

    @_serialized_table_write
    def add_client(self, protocol, client_name, server_host, port, public_port=None,
                   warp_ctx=None, fingerprint=None):
        client_id = str(uuid.uuid4())
        
        config = self._get_server_json()
        if not config: raise RuntimeError("Xray server config not found.")

        self._upgrade_config_for_stats(config, restart=False)

        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")

        # Ensure clients structure exists
        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])
        client = {
            "id": client_id,
            "flow": _client_flow(inbound),
            "email": client_id
        }
        if not self._xray_api_add_user(config, client):
            raise RuntimeError(
                "Xray runtime API is not available for hot user updates. "
                "The server config was upgraded, but the container must be restarted once to enable HandlerService. "
                "Restart the Xray container manually and try again."
            )
        clients_node.append(client)
        self._write_server_json(config, restart=False)

        # Update table
        clients_table = self._get_clients_table(strict=True)
        clients_table.append({
            'clientId': client_id,
            'userData': {
                'clientName': client_name,
                'creationDate': datetime.now().isoformat(),
                'enabled': True
            }
        })
        self._save_clients_table(clients_table)

        return {
            'client_id': client_id,
            'config': self.get_client_config(protocol, client_id, server_host, port, public_port,
                                             fingerprint=fingerprint)
        }

    @_serialized_table_write
    def toggle_client(self, protocol, client_id, enable):
        config = self._get_server_json()
        self._upgrade_config_for_stats(config, restart=False)
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")
        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])

        # If toggling on and not present, we can re-add it from clientsTable
        if enable:
            if not any(c['id'] == client_id for c in clients_node):
                client = {
                    "id": client_id,
                    "flow": _client_flow(inbound),
                    "email": client_id
                }
                if not self._xray_api_add_user(config, client):
                    raise RuntimeError("Xray runtime API failed to enable the client without restarting the container.")
                clients_node.append(client)
        else:
            if not self._xray_api_remove_user(config, client_id):
                raise RuntimeError("Xray runtime API failed to disable the client without restarting the container.")
            inbound['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]

        self._write_server_json(config, restart=False)

        clients_table = self._get_clients_table(strict=True)
        for c in clients_table:
            if c['clientId'] == client_id:
                c.setdefault('userData', {})['enabled'] = enable
        self._save_clients_table(clients_table)

    @_serialized_table_write
    def remove_client(self, protocol, client_id):
        config = self._get_server_json()
        self._upgrade_config_for_stats(config, restart=False)
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")
        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])
        if not self._xray_api_remove_user(config, client_id):
            raise RuntimeError("Xray runtime API failed to remove the client without restarting the container.")
        inbound['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]
        self._write_server_json(config, restart=False)

        clients_table = self._get_clients_table(strict=True)
        clients_table = [c for c in clients_table if c['clientId'] != client_id]
        self._save_clients_table(clients_table)
        return True

    @_serialized_table_write
    def rename_client(self, protocol, client_id, new_name):
        """Rename a client. The display name lives in clientsTable
        (userData.clientName) and is embedded into the VLESS URL fragment on
        the fly, so updating the table is enough — UUID, keys and server.json
        stay untouched and existing links keep working.

        The shared writer commits with `docker exec`, so a stopped instance
        is rejected up front with a clear message instead of a generic
        staging failure.
        """
        if not self.check_container_running():
            raise RuntimeError(
                'Xray container is not running - start the instance to rename its clients')
        clients_table = self._get_clients_table(strict=True)
        client = next((c for c in clients_table if c.get('clientId') == client_id), None)
        if client is None:
            raise RuntimeError('Client not found')
        client.setdefault('userData', {})['clientName'] = new_name
        self._save_clients_table(clients_table)
        return {'status': 'success', 'name': new_name}
