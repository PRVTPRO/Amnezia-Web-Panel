#!/usr/bin/env bash
# Установка rkn-extra-block (Debian/Ubuntu, root).
# Фазы: preflight, packages, download, files, services, blocking, verify.
# Без аргумента (или 'all') выполняется весь цикл: так работают repair и
# ручной запуск. Панель запускает фазы по одной, чтобы показывать прогресс.
set -euo pipefail

# An interactive prompt (needrestart, tzdata, ...) would hang the panel's SSH run.
export DEBIAN_FRONTEND=noninteractive

RAW="${RKN_RAW_BASE:-https://raw.githubusercontent.com/PRVTPRO/Amnezia-Web-Panel/main/scripts/rknblock}"
STAGE="${RKN_STAGE_DIR:-/tmp/amnezia-rkn-stage}"
APT_LOG=""

cleanup() {
    if [ -n "$APT_LOG" ]; then rm -f "$APT_LOG"; fi
}
trap cleanup EXIT

# A half-configured package left by an earlier failure makes every subsequent
# apt-get call fail with "dpkg returned an error code (1)". Report the real
# cause instead of apport noise, and do not try to repair the host silently.
phase_preflight() {
    echo "rknblock: preflight: checking dpkg state"
    AUDIT=$(dpkg --audit 2>&1 || true)
    if [ -n "$AUDIT" ]; then
        echo "ERROR: dpkg is in an inconsistent state. Run 'sudo dpkg --configure -a' on the server, then retry." >&2
        echo "$AUDIT" >&2
        exit 1
    fi
    echo "rknblock: preflight: dpkg is consistent"
}

phase_packages() {
    echo "rknblock: packages: apt-get update"
    apt-get update -qq
    echo "rknblock: packages: installing ipset iptables curl util-linux"
    APT_LOG=$(mktemp /tmp/rkn-apt.XXXXXXXXXX.log)
    if ! apt-get install -y -qq ipset iptables curl util-linux >"$APT_LOG" 2>&1; then
        echo "ERROR: package installation failed (ipset iptables curl util-linux)." >&2
        tail -n 30 "$APT_LOG" >&2
        exit 1
    fi
    command -v flock >/dev/null || { echo "flock not found (util-linux)" >&2; exit 1; }
    echo "rknblock: packages: ipset iptables curl util-linux installed"
}

phase_download() {
    rm -rf "$STAGE"
    mkdir -p "$STAGE/repo"
    echo "rknblock: download: fetching payload to $STAGE/repo"
    for f in rkn-extra-block.sh rkn-extra-block.service rkn-extra-block.timer \
             rkn-agent.sh rkn-agent.service rkn-agent.timer; do
        curl -fsSL "$RAW/$f" -o "$STAGE/repo/$f"
        echo "rknblock: download: $f"
    done
    echo "rknblock: download: payload ready"
}

phase_files() {
    echo "rknblock: files: installing scripts and units"
    install -m 0755 "$STAGE/repo/rkn-extra-block.sh" /usr/local/sbin/rkn-extra-block
    install -m 0755 "$STAGE/repo/rkn-agent.sh" /usr/local/sbin/rkn-agent-collect
    install -m 0644 "$STAGE/repo/rkn-extra-block.service" /etc/systemd/system/rkn-extra-block.service
    install -m 0644 "$STAGE/repo/rkn-extra-block.timer" /etc/systemd/system/rkn-extra-block.timer
    install -m 0644 "$STAGE/repo/rkn-agent.service" /etc/systemd/system/rkn-agent.service
    install -m 0644 "$STAGE/repo/rkn-agent.timer" /etc/systemd/system/rkn-agent.timer
    mkdir -p /etc/rkn-extra-block
    if [ ! -f /etc/rkn-extra-block/config ]; then
        cat > /etc/rkn-extra-block/config <<'EOF'
# Источники списков C24Be/AS_Network_List (менять не обязательно)
URL_IN4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v4.ipset"
URL_IN6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v6.ipset"
URL_OUT4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v4.ipset"
URL_OUT6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v6.ipset"
EOF
        echo "rknblock: files: default config written"
    else
        echo "rknblock: files: existing config kept"
    fi
    echo "rknblock: files: rkn-extra-block and rkn-agent-collect installed"
}

phase_services() {
    systemctl daemon-reload
    echo "rknblock: services: systemd reloaded"
    systemctl enable --now rkn-extra-block.timer
    echo "rknblock: services: rkn-extra-block.timer enabled"
    systemctl enable rkn-extra-block.service
    # A unit without [Install] makes `systemctl enable` a no-op that reports
    # "static": the timer is fine, but nothing restores the rules after a reboot.
    ENABLED_STATE=$(systemctl is-enabled rkn-extra-block.service 2>/dev/null || true)
    if [ "$ENABLED_STATE" != "enabled" ]; then
        echo "ERROR: rkn-extra-block.service is not enabled after install (state: ${ENABLED_STATE:-unknown})." >&2
        echo "       Boot restore would not run; check /etc/systemd/system/rkn-extra-block.service for [Install]." >&2
        exit 1
    fi
    echo "rknblock: services: boot restore enabled"
    systemctl enable --now rkn-agent.timer
    echo "rknblock: services: rkn-agent.timer enabled"
}

phase_blocking() {
    # `on` verifies sets and iptables jumps; a zero-list install must fail
    # instead of reporting a working contour that blocks nothing.
    echo "rknblock: blocking: loading lists and applying rules"
    if ! /usr/local/sbin/rkn-extra-block on; then
        echo "ERROR: rkn-extra-block could not start (empty C24Be lists or iptables rules not applied)" >&2
        /usr/local/sbin/rkn-extra-block status >&2 || true
        exit 1
    fi
    echo "rknblock: blocking: rules are on"
    # Статистике нужны LOG-правила: включаем журналирование (пересобирает цепочки).
    if ! /usr/local/sbin/rkn-extra-block log on; then
        echo "ERROR: rkn-extra-block logging could not be enabled; blocking rules were not verified" >&2
        /usr/local/sbin/rkn-extra-block status >&2 || true
        exit 1
    fi
    touch /var/log/rkn-scans.json
    echo "rknblock: blocking: logging enabled"
}

phase_verify() {
    echo "rknblock: verify: probing the live contour"
    if /usr/local/sbin/rkn-extra-block status; then
        echo "rknblock: verify: status probe completed"
    else
        echo "ERROR: rkn-extra-block status failed after install" >&2
        exit 1
    fi
    rm -rf "$STAGE"
    echo "Готово. Управление: rkn-extra-block {on|off|status|update} | log on|off | scan"
}

PHASE="${1:-all}"
case "$PHASE" in
    preflight) phase_preflight ;;
    packages) phase_packages ;;
    download) phase_download ;;
    files) phase_files ;;
    services) phase_services ;;
    blocking) phase_blocking ;;
    verify) phase_verify ;;
    all)
        phase_preflight
        phase_packages
        phase_download
        phase_files
        phase_services
        phase_blocking
        phase_verify
        ;;
    *)
        echo "ERROR: unknown phase: $PHASE" >&2
        exit 2
        ;;
esac
