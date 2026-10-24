#!/usr/bin/env bash
# Установка rkn-extra-block (Debian/Ubuntu, root).
# Скачивает скрипты из репозитория панели и ставит их + systemd-юниты.
set -euo pipefail

RAW="https://raw.githubusercontent.com/PRVTPRO/Amnezia-Web-Panel/main/scripts/rknblock"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

apt-get update -qq
apt-get install -y -qq ipset iptables curl util-linux >/dev/null
command -v flock >/dev/null || { echo "flock not found (util-linux)" >&2; exit 1; }

mkdir -p "$TMP/repo"
for f in rkn-extra-block.sh rkn-extra-block.service rkn-extra-block.timer \
         rkn-agent.sh rkn-agent.service rkn-agent.timer; do
    curl -fsSL "$RAW/$f" -o "$TMP/repo/$f"
done

install -m 0755 "$TMP/repo/rkn-extra-block.sh" /usr/local/sbin/rkn-extra-block
install -m 0755 "$TMP/repo/rkn-agent.sh" /usr/local/sbin/rkn-agent-collect
install -m 0644 "$TMP/repo/rkn-extra-block.service" /etc/systemd/system/rkn-extra-block.service
install -m 0644 "$TMP/repo/rkn-extra-block.timer" /etc/systemd/system/rkn-extra-block.timer
install -m 0644 "$TMP/repo/rkn-agent.service" /etc/systemd/system/rkn-agent.service
install -m 0644 "$TMP/repo/rkn-agent.timer" /etc/systemd/system/rkn-agent.timer

mkdir -p /etc/rkn-extra-block
[ -f /etc/rkn-extra-block/config ] || cat > /etc/rkn-extra-block/config <<'EOF'
# Источники списков C24Be/AS_Network_List (менять не обязательно)
URL_IN4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v4.ipset"
URL_IN6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v6.ipset"
URL_OUT4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v4.ipset"
URL_OUT6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v6.ipset"
EOF

systemctl daemon-reload
systemctl enable --now rkn-extra-block.timer
systemctl enable rkn-extra-block.service
systemctl enable --now rkn-agent.timer

# Первый запуск: подгрузить списки (включая nets.map для агента) и включить
/usr/local/sbin/rkn-extra-block on

# Статистике нужны LOG-правила: включаем журналирование (пересобирает цепочки)
/usr/local/sbin/rkn-extra-block log on || true

touch /var/log/rkn-scans.json

echo "Готово. Управление: rkn-extra-block {on|off|status|update} | log on|off | scan"
