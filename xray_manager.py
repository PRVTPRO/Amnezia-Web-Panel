import json
import os
import uuid
import logging
import base64
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)

class XrayManager:
    """Manages Xray (VLESS-Reality) protocol installation and client management."""
    
    PROTOCOL = 'xray'
    CONTAINER_NAME = 'amnezia-xray'
    IMAGE_NAME = 'amneziavpn/amnezia-xray' # or we can build it
    
    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    def _config_dir(self):
        return '/opt/amnezia/xray'

    def _config_path(self):
        return f'{self._config_dir()}/server.json'
        
    def _clients_table_path(self):
        return f'{self._config_dir()}/clientsTable.json'

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0: return False
        out2, _, code2 = self.ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        return 'active' in out2 or 'running' in out2.lower()

    def check_container_running(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

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

    def install_protocol(self, port=443, site_name='yahoo.com'):
        """Full installation of Xray."""
        results = []

        if not self.check_docker_installed():
            results.append("Installing Docker...")
            # Using same install method as AWGManager or assume it's installed
            pass

        results.append("Removing old container if exists...")
        if self.check_protocol_installed():
            self.remove_container()

        results.append("Building Docker image...")
        dockerfile_folder = f"/opt/amnezia/{self.CONTAINER_NAME}"
        dockerfile_content = """FROM alpine:3.15
RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz iptables ip6tables
RUN apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia/xray
RUN curl -L -H "Cache-Control: no-cache" -o /root/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip" && \
    unzip /root/xray.zip -d /usr/bin/ && \
    chmod a+x /usr/bin/xray && \
    rm /root/xray.zip

# Tune network
RUN echo -e " \n\
  fs.file-max = 51200 \n\
  \n\
  net.core.rmem_max = 67108864 \n\
  net.core.wmem_max = 67108864 \n\
  net.core.netdev_max_backlog = 250000 \n\
  net.core.somaxconn = 4096 \n\
  \n\
  net.ipv4.tcp_syncookies = 1 \n\
  net.ipv4.tcp_tw_reuse = 1 \n\
  net.ipv4.tcp_tw_recycle = 0 \n\
  net.ipv4.tcp_fin_timeout = 30 \n\
  net.ipv4.tcp_keepalive_time = 1200 \n\
  net.ipv4.ip_local_port_range = 10000 65000 \n\
  net.ipv4.tcp_max_syn_backlog = 8192 \n\
  net.ipv4.tcp_max_tw_buckets = 5000 \n\
  net.ipv4.tcp_fastopen = 3 \n\
  net.ipv4.tcp_mem = 25600 51200 102400 \n\
  net.ipv4.tcp_rmem = 4096 87380 67108864 \n\
  net.ipv4.tcp_wmem = 4096 65536 67108864 \n\
  net.ipv4.tcp_mtu_probing = 1 \n\
  net.ipv4.tcp_congestion_control = hybla \n\
  " | sed -e 's/^\s\+//g' | tee -a /etc/sysctl.conf && \
  mkdir -p /etc/security && \
  echo -e " \n\
  * soft nofile 51200 \n\
  * hard nofile 51200 \n\
  " | sed -e 's/^\s\+//g' | tee -a /etc/security/limits.conf

RUN echo -e "#!/bin/bash\\nsysctl -p /etc/sysctl.conf 2>/dev/null\\n/usr/bin/xray -config /opt/amnezia/xray/server.json" > /opt/amnezia/start.sh && \
    chmod a+x /opt/amnezia/start.sh
ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
"""
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")
        
        _, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache -t {self.IMAGE_NAME} {dockerfile_folder}", timeout=300
        )
        if code != 0: raise RuntimeError(f"Failed to build container: {err}")

        results.append("Generating keys and config...")
        # We generate a base config using a temp container or directly if host has openssl
        
        # Xray keypair generation using a temporary run overriding the entrypoint
        keypair_cmd = f"docker run --rm --entrypoint=\"\" {self.IMAGE_NAME} /usr/bin/xray x25519"
        out_kp, err_kp, code_kp = self.ssh.run_sudo_command(keypair_cmd)
        if code_kp != 0: raise RuntimeError(f"Failed to generate x25519 keys: {err_kp}")
        
        priv_key = ""
        pub_key = ""
        for line in out_kp.split('\n'):
            if "Private" in line: priv_key = line.split(":", 1)[1].strip()
            if "Public" in line: pub_key = line.split(":", 1)[1].strip()

        short_id_cmd = f"docker run --rm --entrypoint=\"\" {self.IMAGE_NAME} openssl rand -hex 8"
        out_sid, _, _ = self.ssh.run_sudo_command(short_id_cmd)
        short_id = out_sid.strip()

        # Generate initial server.json with Stats and API enabled
        server_json = {
            "log": {"loglevel": "error"},
            "stats": {},
            "api": {
                "services": ["StatsService", "LoggerService"],
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
                    "settings": {
                        "clients": [],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": f"{site_name}:443",
                            "serverNames": [site_name],
                            "privateKey": priv_key,
                            "shortIds": [short_id]
                        }
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": 10085,
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                    "tag": "api"
                }
            ],
            "outbounds": [{"protocol": "freedom"}],
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
        
        # Save keys for our reference
        meta_json = {
            "site_name": site_name,
            "public_key": pub_key,
            "private_key": priv_key,
            "short_id": short_id,
            "port": int(port)
        }

        self.ssh.run_sudo_command("mkdir -p /opt/amnezia/xray")
        self.ssh.upload_file_sudo(json.dumps(server_json, indent=2), "/opt/amnezia/xray/server.json")
        self.ssh.upload_file_sudo(json.dumps(meta_json, indent=2), "/opt/amnezia/xray/meta.json")
        self.ssh.upload_file_sudo("[]", "/opt/amnezia/xray/clientsTable.json")

        results.append("Starting container...")
        run_cmd = f"""docker run -d \\
--restart always \\
--privileged \\
--cap-add=NET_ADMIN \\
-p {port}:{port}/tcp \\
-p {port}:{port}/udp \\
-v /opt/amnezia/xray:/opt/amnezia/xray \\
--name {self.CONTAINER_NAME} \\
{self.IMAGE_NAME}"""

        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0: raise RuntimeError(f"Failed to run container: {err}")

        # Try to connect to network if needed
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.CONTAINER_NAME} || true")

        results.append("Xray configured and running")
        return {'status': 'success', 'protocol': 'xray', 'port': port, 'log': results}

    def remove_container(self):
        self.ssh.run_sudo_command(f"docker stop {self.CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rmi {self.IMAGE_NAME}")
        return True

    # ===================== CLIENT MANAGEMENT =====================

    def _get_server_json(self):
        out, _, code = self.ssh.run_sudo_command(f"cat {self._config_path()}")
        if code != 0: return None
        return json.loads(out)

    def _save_server_json(self, data):
        self.ssh.upload_file_sudo(json.dumps(data, indent=2), self._config_path())
        self.ssh.run_sudo_command(f"docker restart {self.CONTAINER_NAME}")

    def _get_meta_json(self):
        out, _, code = self.ssh.run_sudo_command(f"cat /opt/amnezia/xray/meta.json")
        if code != 0: return {}
        return json.loads(out)

    def _get_clients_table(self):
        out, _, code = self.ssh.run_sudo_command(f"cat {self._clients_table_path()}")
        if code != 0 or not out.strip(): return []
        try: return json.loads(out)
        except: return []

    def _save_clients_table(self, data):
        self.ssh.upload_file_sudo(json.dumps(data, indent=2), self._clients_table_path())

    def _upgrade_config_for_stats(self, config):
        """Injects API and Stats blocks into older Xray configs transparently."""
        dirty = False
        if 'stats' not in config:
            config['stats'] = {}
            dirty = True
        if 'api' not in config:
            config['api'] = {"services": ["StatsService", "LoggerService"], "tag": "api"}
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
                for c in ib.get('settings', {}).get('clients', []):
                    if 'email' not in c:
                        c['email'] = c['id']
                        dirty = True
            
        if dirty:
            self._save_server_json(config)
        return dirty

    def _query_xray_stats(self):
        """Query Xray API for traffic stats using xray api command."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.CONTAINER_NAME} /usr/bin/xray api statsquery -server=127.0.0.1:10085"
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

    def get_clients(self, protocol=None):
        config = self._get_server_json()
        if config:
            self._upgrade_config_for_stats(config)

        clients_table = self._get_clients_table()
        stats = self._query_xray_stats()

        for c in clients_table:
            uid = c.get('clientId', '')
            if uid in stats:
                user_data = c.setdefault('userData', {})
                rx = stats[uid]['rx']
                tx = stats[uid]['tx']
                # Xray doesn't natively expose latest handshake easily in this format,
                # but we can map the traffic accurately
                if rx > 0 or tx > 0:
                    user_data['dataReceived'] = self._format_bytes(rx)
                    user_data['dataSent'] = self._format_bytes(tx)
                    user_data['dataReceivedBytes'] = rx
                    user_data['dataSentBytes'] = tx

        return clients_table

    def get_client_config(self, protocol, client_id, server_host, port):
        clients = self._get_clients_table()
        client = next((c for c in clients if c['clientId'] == client_id), None)
        if not client: return None

        meta = self._get_meta_json()
        if not meta: return None

        # Format URL
        # vless://{id}@{host}:{port}?type=tcp&security=reality&pbk={public_key}&sni={site_name}&fp=chrome&sid={short_id}&spx=%2F&flow=xtls-rprx-vision#{name}
        
        name = client.get('userData', {}).get('clientName', 'vpn')
        encoded_name = urllib.parse.quote(name)
        
        url = (
            f"vless://{client_id}@{server_host}:{meta.get('port', port)}"
            f"?type=tcp&security=reality&pbk={meta['public_key']}"
            f"&sni={meta['site_name']}&fp=chrome&sid={meta['short_id']}"
            f"&spx=%2F&flow=xtls-rprx-vision#{encoded_name}"
        )
        return url

    def add_client(self, protocol, client_name, server_host, port):
        client_id = str(uuid.uuid4())
        
        config = self._get_server_json()
        if not config: raise RuntimeError("Xray server config not found.")

        # Ensure clients structure exists
        clients_node = config['inbounds'][0]['settings'].setdefault('clients', [])
        clients_node.append({
            "id": client_id,
            "flow": "xtls-rprx-vision",
            "email": client_id
        })
        self._save_server_json(config)

        # Update table
        clients_table = self._get_clients_table()
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
            'config': self.get_client_config(protocol, client_id, server_host, port)
        }

    def toggle_client(self, protocol, client_id, enable):
        config = self._get_server_json()
        clients_node = config['inbounds'][0]['settings'].get('clients', [])
        
        # If toggling on and not present, we can re-add it from clientsTable
        if enable:
            if not any(c['id'] == client_id for c in clients_node):
                clients_node.append({
                    "id": client_id,
                    "flow": "xtls-rprx-vision",
                    "email": client_id
                })
        else:
            config['inbounds'][0]['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]

        self._save_server_json(config)

        clients_table = self._get_clients_table()
        for c in clients_table:
            if c['clientId'] == client_id:
                c.setdefault('userData', {})['enabled'] = enable
        self._save_clients_table(clients_table)

    def remove_client(self, protocol, client_id):
        config = self._get_server_json()
        clients_node = config['inbounds'][0]['settings'].get('clients', [])
        config['inbounds'][0]['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]
        self._save_server_json(config)

        clients_table = self._get_clients_table()
        clients_table = [c for c in clients_table if c['clientId'] != client_id]
        self._save_clients_table(clients_table)
        return True
