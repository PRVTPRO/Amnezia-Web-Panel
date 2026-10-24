#!/usr/bin/env bash
# rkn-extra-block — дополнительная блокировка по спискам C24Be/AS_Network_List.
# Два независимых от amnezia-blocker контуры:
#   IN  (RKN_EXTRA_IN):  подсети РКН/гос-структур — ВХОДЯЩИЕ соединения (INPUT, DROP NEW)
#   OUT (RKN_EXTRA_OUT): сети VK/Max/OK — ИСХОДЯЩИЕ (OUTPUT + FORWARD, REJECT tcp-reset)
# Списки обновляются ежедневно (systemd timer), заливка в ipset атомарная (temp -> swap).
#
# Команды: on | off | status | update | boot | set флаг=on|off... | log on|off|status | scan [файлы...]
#   on      — включить (подгрузить списки если пустые, повесить прыжки в цепочки)
#   off     — выключить (снять прыжки; наборы ipset сохраняются для мгновенного on)
#   status  — состояние, размеры наборов, флаги, дата обновления баз, наличие правил
#   update  — скачать свежие списки и атомарно перезалить наборы (пишет last_update)
#   boot    — вызывается systemd при старте (update + восстановить прыжки если state=on)
#   set     — раздельные флаги block_in|block_out|log_in|log_out = on|off (по умолчанию on)
#   log on  — журналировать срабатывания (journalctl -k -g RKN_EXTRA), по умолчанию ВЫКЛ
#   scan    — ретроспектива: найти IP из списков в логах (по умолчанию nginx/auth)

set -u

CONF_DIR="/etc/rkn-extra-block"
STATE_FILE="$CONF_DIR/state"
LOG_STATE_FILE="$CONF_DIR/log_state"
LOG_FILE="/var/log/rkn-extra-block.log"
LOCK_FILE="/run/rkn-extra-block.lock"
CONFIG_FILE="$CONF_DIR/config"

IN_CHAIN="RKN_EXTRA_IN"
OUT_CHAIN="RKN_EXTRA_OUT"
IN_SET4="rkn_extra_in4"
IN_SET6="rkn_extra_in6"
OUT_SET4="rkn_extra_out4"
OUT_SET6="rkn_extra_out6"

# Максимальные размеры с запасом (сейчас: in4 ~1151, out4 ~204 сетей)
MAXELEM=65536

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"; }
die() { echo "ERROR: $*" >&2; log "ERROR: $*"; exit 1; }

lock() {
    exec 9>"$LOCK_FILE" || die "не удалось открыть $LOCK_FILE"
    flock -n 9 || die "другой экземпляр rkn-extra-block уже работает"
}

get_state() { [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "off"; }
set_state() { echo "$1" > "$STATE_FILE"; }

# --- флаги направлений (block_in/block_out/log_in/log_out) -------------------
# Файл-флаг: $CONF_DIR/<flag>, содержимое on|off. Отсутствие файла = on.
# log-флаги наследуют старый лог-мастер LOG_STATE_FILE, пока свои файлы не созданы.
block_flag() { [ ! -f "$CONF_DIR/$1" ] || [ "$(cat "$CONF_DIR/$1" 2>/dev/null)" = "on" ]; }
log_flag() {
    if [ -f "$CONF_DIR/$1" ]; then
        [ "$(cat "$CONF_DIR/$1" 2>/dev/null)" = "on" ]; return
    fi
    [ ! -f "$LOG_STATE_FILE" ] && return 0
    [ "$(cat "$LOG_STATE_FILE" 2>/dev/null)" = "on" ]
}
flag_val() {
    if [ -f "$CONF_DIR/$1" ]; then cat "$CONF_DIR/$1" 2>/dev/null; return; fi
    case "$1" in
        log_in|log_out) [ -f "$LOG_STATE_FILE" ] && { cat "$LOG_STATE_FILE" 2>/dev/null; return; } ;;
    esac
    echo "on"
}
flags_line() { echo "flags: block_in=$(flag_val block_in) block_out=$(flag_val block_out) log_in=$(flag_val log_in) log_out=$(flag_val log_out)"; }

load_config() {
    # Значения по умолчанию; переопределяются /etc/rkn-extra-block/config
    URL_IN4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v4.ipset"
    URL_IN6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-v6.ipset"
    URL_OUT4="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v4.ipset"
    URL_OUT6="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables/blacklist-vk-v6.ipset"
    URL_MAP="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist_with_comments.txt"
    [ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
}

have6() { command -v ip6tables &>/dev/null && [ -e /proc/net/if_inet6 ]; }

ensure_deps() {
    for d in ipset iptables curl flock; do
        command -v "$d" &>/dev/null || die "нет зависимости: $d (apt install ipset iptables curl)"
    done
}

# --- ipset helpers -----------------------------------------------------------

create_set() { # $1=name $2=family(inet|inet6)
    # ВАЖНО: family и inet — ДВА отдельных аргумента; "family inet" одним словом
    # ipset 7.x отвергает с "Unknown argument".
    ipset create "$1" hash:net family "$2" maxelem $MAXELEM 2>/dev/null || true
}

# Атомарная перезаливка: скачать, вытащить 'add'-строки, залить в _tmp, swap.
# При любом провале старый набор остаётся нетронутым, причина — в лог.
swap_list() { # $1=url $2=set_name $3=family
    local url="$1" set="$2" family="$3"
    local tmp; tmp=$(mktemp) || die "mktemp"
    if ! curl -fsS --max-time 90 "$url" -o "$tmp"; then
        log "SWAP-FAIL $set: не скачался $url — старый набор сохранён"
        rm -f "$tmp"; return 1
    fi
    local adds; adds=$(grep -c '^add ' "$tmp")
    if [ "$adds" -lt 1 ]; then
        log "SWAP-FAIL $set: в $url 0 записей — старый набор сохранён"
        rm -f "$tmp"; return 1
    fi
    local restore; restore=$(mktemp) || die "mktemp"
    {
        echo "create ${set}_tmp hash:net family $family maxelem $MAXELEM"
        tr -d '\r' < "$tmp" | grep '^add ' | sed "s|^add [^ ]*|add ${set}_tmp|"
    } > "$restore"
    local cerr
    cerr=$(ipset create "$set" hash:net family "$family" maxelem $MAXELEM 2>&1) \
        || log "CREATE-WARN $set: $cerr"
    ipset destroy "${set}_tmp" 2>/dev/null
    if ! ipset restore -exist < "$restore" 2>>"$LOG_FILE"; then
        log "SWAP-FAIL $set: ipset restore вернул ошибку — старый набор сохранён"
        ipset destroy "${set}_tmp" 2>/dev/null
        rm -f "$tmp" "$restore"; return 1
    fi
    cerr=$(ipset swap "${set}_tmp" "$set" 2>&1) || {
        log "SWAP-FAIL $set: $cerr — набор $set не обновлён"
        ipset destroy "${set}_tmp" 2>/dev/null
        rm -f "$tmp" "$restore"; return 1
    }
    ipset destroy "${set}_tmp" 2>/dev/null
    rm -f "$tmp" "$restore"
    log "SWAP-OK $set: $adds сетей"
    return 0
}

# --- firewall ----------------------------------------------------------------
# Строит /etc/rkn-extra-block/nets.map: "firstPadded\tlastPadded\tlabel" на каждую
# IPv4-сеть из blacklist_with_comments.txt. Label — из секций AS-Name (читаемое имя)
# или MNT-токенов NET-Name (напр. VKCOMPANY). Нужен агенту статистики (rkn-agent).
build_map() {
    local url="$1" out="$2"
    local tmp; tmp=$(mktemp) || die "mktemp"
    if ! curl -fsS --max-time 90 "$url" -o "$tmp"; then
        log "MAP-FAIL: не скачался $url — старый nets.map сохранён"
        rm -f "$tmp"; return 1
    fi
    tr -d '\r' < "$tmp" | awk -F'\t' -v OFS='\t' '
    function pad(o) { return sprintf("%03d.%03d.%03d.%03d", o[1], o[2], o[3], o[4]) }
    function emit(net, lbl,   a, p, full, bits, step, i, lo, hi) {
        gsub(/\//, ".", net); split(net, a, ".")
        p = a[5] + 0; full = int(p / 8); bits = p % 8
        step = 1; for (i = 0; i < 8 - bits; i++) step *= 2
        for (i = 1; i <= 4; i++) { lo[i] = 0; hi[i] = 255 }
        for (i = 1; i <= full; i++) { lo[i] = a[i]; hi[i] = a[i] }
        if (bits > 0) {
            lo[full + 1] = int(a[full + 1] / step) * step
            hi[full + 1] = lo[full + 1] + step - 1
        }
        print pad(lo), pad(hi), lbl
    }
    /^# AS-Name \(ORG\): / { label = substr($0, index($0, ": ") + 2); next }
    /^# AS-Name: /         { label = substr($0, index($0, ": ") + 2); next }
    /^# NET-Name: / {
        rest = substr($0, index($0, ": ") + 2)
        sub(/^[^ ]+ /, "", rest)
        gsub(/\([^)]*\)/, "", rest); gsub(/[\[\]]/, "", rest)
        n = split(rest, t, /[ \t]+/); lbl = ""
        for (i = 1; i <= n; i++) if (t[i] ~ /MNT/) { x = t[i]; sub(/-MNT$/, "", x); lbl = lbl (lbl ? " " : "") x }
        label = (lbl ? lbl : "C24Be " substr(rest, 1, 40))
        next
    }
    /^#/ { next }
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/ { emit($1, label) }
    ' > "$out.tmp"
    mv "$out.tmp" "$out"
    rm -f "$tmp"
    log "MAP-OK: $(wc -l < "$out") сетей с метками"
    return 0
}

apply_jumps() {
    iptables -C INPUT -j "$IN_CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$IN_CHAIN"
    iptables -C OUTPUT -j "$OUT_CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$OUT_CHAIN"
    iptables -C FORWARD -j "$OUT_CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$OUT_CHAIN"
    if have6; then
        ip6tables -C INPUT -j "$IN_CHAIN" 2>/dev/null || ip6tables -I INPUT 1 -j "$IN_CHAIN" 2>/dev/null
        ip6tables -C OUTPUT -j "$OUT_CHAIN" 2>/dev/null || ip6tables -I OUTPUT 1 -j "$OUT_CHAIN" 2>/dev/null
        ip6tables -C FORWARD -j "$OUT_CHAIN" 2>/dev/null || ip6tables -I FORWARD 1 -j "$OUT_CHAIN" 2>/dev/null
    fi
}

remove_jumps() {
    while iptables -C INPUT -j "$IN_CHAIN" 2>/dev/null; do iptables -D INPUT -j "$IN_CHAIN"; done
    while iptables -C OUTPUT -j "$OUT_CHAIN" 2>/dev/null; do iptables -D OUTPUT -j "$OUT_CHAIN"; done
    while iptables -C FORWARD -j "$OUT_CHAIN" 2>/dev/null; do iptables -D FORWARD -j "$OUT_CHAIN"; done
    if have6; then
        while ip6tables -C INPUT -j "$IN_CHAIN" 2>/dev/null; do ip6tables -D INPUT -j "$IN_CHAIN"; done
        while ip6tables -C OUTPUT -j "$OUT_CHAIN" 2>/dev/null; do ip6tables -D OUTPUT -j "$OUT_CHAIN"; done
        while ip6tables -C FORWARD -j "$OUT_CHAIN" 2>/dev/null; do ip6tables -D FORWARD -j "$OUT_CHAIN"; done
    fi
}

build_chains() {
    local log_in="no" log_out="no" blk_in="no" blk_out="no"
    log_flag "log_in" && log_in="yes"
    log_flag "log_out" && log_out="yes"
    block_flag "block_in" && blk_in="yes"
    block_flag "block_out" && blk_out="yes"

    # Правила ссылаются на наборы ipset: если набора нет (контур не установлен
    # или набор ещё не создан), цепочка остаётся пустой — без мусора в stderr.
    iptables -N "$IN_CHAIN" 2>/dev/null || true
    iptables -F "$IN_CHAIN"
    if ipset list "$IN_SET4" >/dev/null 2>&1; then
        if [ "$log_in" = "yes" ]; then
            iptables -A "$IN_CHAIN" -m set --match-set "$IN_SET4" src -m conntrack --ctstate NEW \
                -m limit --limit 10/min -j LOG --log-prefix "RKN_EXTRA_IN " --log-level 4
        fi
        # Входящие от РКН-подсетей: тишина (DROP), только новые соединения
        if [ "$blk_in" = "yes" ]; then
            iptables -A "$IN_CHAIN" -m set --match-set "$IN_SET4" src -m conntrack --ctstate NEW -j DROP
        fi
    fi

    iptables -N "$OUT_CHAIN" 2>/dev/null || true
    iptables -F "$OUT_CHAIN"
    if ipset list "$OUT_SET4" >/dev/null 2>&1; then
        if [ "$log_out" = "yes" ]; then
            iptables -A "$OUT_CHAIN" -p tcp -m set --match-set "$OUT_SET4" dst \
                -m limit --limit 10/min -j LOG --log-prefix "RKN_EXTRA_OUT " --log-level 4
        fi
        # Исходящие к VK/Max/OK: штатный обрыв как в amnezia-blocker (REJECT)
        if [ "$blk_out" = "yes" ]; then
            iptables -A "$OUT_CHAIN" -p tcp -m set --match-set "$OUT_SET4" dst -j REJECT --reject-with tcp-reset
            iptables -A "$OUT_CHAIN" -m set --match-set "$OUT_SET4" dst -j REJECT
        fi
    fi

    if have6; then
        ip6tables -N "$IN_CHAIN" 2>/dev/null || true
        ip6tables -F "$IN_CHAIN" 2>/dev/null
        if ipset list "$IN_SET6" >/dev/null 2>&1; then
            if [ "$log_in" = "yes" ]; then
                ip6tables -A "$IN_CHAIN" -m set --match-set "$IN_SET6" src -m conntrack --ctstate NEW \
                    -m limit --limit 10/min -j LOG --log-prefix "RKN_EXTRA_IN6 " --log-level 4 2>/dev/null
            fi
            if [ "$blk_in" = "yes" ]; then
                ip6tables -A "$IN_CHAIN" -m set --match-set "$IN_SET6" src -m conntrack --ctstate NEW -j DROP 2>/dev/null
            fi
        fi

        ip6tables -N "$OUT_CHAIN" 2>/dev/null || true
        ip6tables -F "$OUT_CHAIN" 2>/dev/null
        if ipset list "$OUT_SET6" >/dev/null 2>&1; then
            if [ "$log_out" = "yes" ]; then
                ip6tables -A "$OUT_CHAIN" -p tcp -m set --match-set "$OUT_SET6" dst \
                    -m limit --limit 10/min -j LOG --log-prefix "RKN_EXTRA_OUT6 " --log-level 4 2>/dev/null
            fi
            if [ "$blk_out" = "yes" ]; then
                ip6tables -A "$OUT_CHAIN" -p tcp -m set --match-set "$OUT_SET6" dst -j REJECT --reject-with tcp-reset 2>/dev/null
                ip6tables -A "$OUT_CHAIN" -m set --match-set "$OUT_SET6" dst -j REJECT 2>/dev/null
            fi
        fi
    fi
}

# --- commands ----------------------------------------------------------------

cmd_update() {
    load_config
    swap_list "$URL_IN4" "$IN_SET4" inet
    if have6; then
        swap_list "$URL_IN6" "$IN_SET6" inet6
    else
        log "SKIP $IN_SET6: на хосте нет IPv6"
    fi
    swap_list "$URL_OUT4" "$OUT_SET4" inet
    if have6; then
        swap_list "$URL_OUT6" "$OUT_SET6" inet6
    else
        log "SKIP $OUT_SET6: на хосте нет IPv6"
    fi
    mkdir -p "$CONF_DIR"
    build_map "$URL_MAP" "$CONF_DIR/nets.map"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$CONF_DIR/last_update"
}

cmd_on() {
    create_set "$IN_SET4" inet
    if have6; then create_set "$IN_SET6" inet6; fi
    create_set "$OUT_SET4" inet
    if have6; then create_set "$OUT_SET6" inet6; fi
    # Если наборы пустые (первый запуск / после ребута) — подгрузить
    local n; n=$(ipset list "$IN_SET4" 2>/dev/null | grep -c '^[0-9]')
    [ "$n" -lt 1 ] && cmd_update
    build_chains
    apply_jumps
    set_state on
    log "ON"
    echo "rkn-extra-block: ON"
    cmd_status_short
}

cmd_off() {
    remove_jumps
    set_state off
    log "OFF"
    echo "rkn-extra-block: OFF (наборы ipset сохранены, повторное включение мгновенное)"
}

set_count() { ipset list "$1" 2>/dev/null | grep -c '^[0-9]'; }

cmd_status() {
    local st; st=$(get_state)
    local in4 in6 out4 out6
    in4=$(set_count "$IN_SET4"); in6=$(set_count "$IN_SET6")
    out4=$(set_count "$OUT_SET4"); out6=$(set_count "$OUT_SET6")
    echo "rkn_extra_block: $st"
    echo "  входящие (РКН, DROP NEW):  v4=$in4 сетей  v6=$in6 сетей"
    echo "  исходящие (VK/Max, REJECT): v4=$out4 сетей  v6=$out6 сетей"
    flags_line | sed 's/^/  /'
    echo "  last_update: $(cat "$CONF_DIR/last_update" 2>/dev/null || echo '—')"
    if iptables -C INPUT -j "$IN_CHAIN" 2>/dev/null; then echo "  правила: iptables INPUT/OUTPUT/FORWARD — вешаются"; else echo "  правила: СНЯТЫ (блокировка неактивна)"; fi
    have6 && ip6tables -C INPUT -j "$IN_CHAIN" 2>/dev/null && echo "  правила v6: вешаются"
}

cmd_status_short() {
    echo "  in4=$(set_count "$IN_SET4") in6=$(set_count "$IN_SET6") out4=$(set_count "$OUT_SET4") out6=$(set_count "$OUT_SET6")"
}

cmd_boot() {
    load_config
    ensure_deps
    cmd_update
    if [ "$(get_state)" = "on" ]; then
        build_chains
        apply_jumps
        log "BOOT: восстановлено состояние ON"
    else
        log "BOOT: состояние OFF, только наборы обновлены"
    fi
}

cmd_log() {
    case "${1:-}" in
        on)
            mkdir -p "$CONF_DIR"
            echo on > "$LOG_STATE_FILE"
            echo on > "$CONF_DIR/log_in"
            echo on > "$CONF_DIR/log_out"
            build_chains   # пересобрать цепочки с LOG-правилами (прыжки не трогаем)
            log "LOGGING ON"
            echo "Журналирование ВКЛ — срабатывания: journalctl -k -g RKN_EXTRA (лимит 10/мин)"
            ;;
        off)
            echo off > "$LOG_STATE_FILE"
            mkdir -p "$CONF_DIR"
            echo off > "$CONF_DIR/log_in"
            echo off > "$CONF_DIR/log_out"
            build_chains
            log "LOGGING OFF"
            echo "Журналирование ВЫКЛ"
            ;;
        status|*)
            echo "rkn_extra_block logging: log_in=$(flag_val log_in) log_out=$(flag_val log_out)"
            ;;
    esac
}

# Раздельные флаги направлений: rkn-extra-block set block_in=on log_out=off ...
# Прыжки в INPUT/OUTPUT/FORWARD не трогаем — пересобираются только цепочки.
cmd_set() {
    [ "$#" -ge 1 ] || die "set: укажите пары вида block_in=on (флаги: block_in block_out log_in log_out)"
    local pair name val
    for pair in "$@"; do
        case "$pair" in
            block_in=on|block_in=off|block_out=on|block_out=off|log_in=on|log_in=off|log_out=on|log_out=off)
                name="${pair%%=*}"; val="${pair#*=}"
                mkdir -p "$CONF_DIR"
                echo "$val" > "$CONF_DIR/$name"
                ;;
            *) die "set: неизвестная пара '$pair' (нужно block_in|block_out|log_in|log_out = on|off)" ;;
        esac
    done
    build_chains
    log "SET: $*"
    flags_line
}

# Ретроспектива: найти в лог-файлах IP, входящие в текущие наборы rkn-extra-block.
# Использование: rkn-extra-block scan [файл...]  (умолчание: access.log nginx + auth.log)
cmd_scan() {
    command -v python3 &>/dev/null || die "нужен python3"
    local files=("$@")
    [ "${#files[@]}" -eq 0 ] && files=(/var/log/nginx/access.log /var/log/auth.log)
    IN_SET4="$IN_SET4" OUT_SET4="$OUT_SET4" python3 - "${files[@]}" << 'PYEOF'
import collections, gzip, ipaddress, os, re, subprocess, sys

in_set = os.environ["IN_SET4"]; out_set = os.environ["OUT_SET4"]
out = subprocess.run(["ipset", "save"], capture_output=True, text=True).stdout
nets = []
for line in out.splitlines():
    parts = line.split()
    if len(parts) >= 3 and parts[0] == "add" and parts[1] in (in_set, out_set):
        try:
            nets.append(ipaddress.ip_network(parts[2]))
        except ValueError:
            pass
by_first = collections.defaultdict(list)
for n in nets:
    by_first[n.network_address.packed[0] if n.version == 4 else 0].append(n)

ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
hits = collections.Counter()
samples = {}
total = matched = 0
for path in sys.argv[1:]:
    paths = [path]
    if path.endswith("*"):
        import glob
        paths = sorted(glob.glob(path))
    for p in paths:
        if not os.path.exists(p):
            continue
        opener = gzip.open if p.endswith(".gz") else open
        try:
            with opener(p, "rt", errors="replace") as fh:
                for line in fh:
                    total += 1
                    m = ip_re.search(line)
                    if not m:
                        continue
                    try:
                        ip = ipaddress.ip_address(m.group(1))
                    except ValueError:
                        continue
                    for n in by_first.get(ip.packed[0], ()):
                        if ip in n:
                            matched += 1
                            hits[str(ip)] += 1
                            samples.setdefault(str(ip), line.rstrip())
                            break
        except OSError as e:
            print(f"пропуск {p}: {e}", file=sys.stderr)

print(f"просканировано строк: {total}, совпадений с сетями РКН/VK: {matched}")
if not hits:
    print("обращений из заблокированных сетей в указанных логах не найдено")
else:
    print("топ IP:")
    for ip, cnt in hits.most_common(20):
        print(f"  {ip:15s} {cnt:6d}   {samples[ip][:160]}")
PYEOF
}

cmd_clearscans() {
    : > /var/log/rkn-scans.json
    mkdir -p "$CONF_DIR"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$CONF_DIR/scanlog.since"
    log "CLEAR: журнал сканирований обнулён, горизонт сбора перенесён на сейчас"
    echo "журнал сканирований обнулён (старое из kernel-журнала повторно подхвачено не будет)"
}

# Полное удаление контура: прыжки, цепочки, наборы, юниты, скрипты, конфиги, логи.
# Вызывается панелью при удалении приложения; может запускаться из копии в /tmp
# (сам себя установленный скрипт при этом тоже удалит — inode останется у процесса).
cmd_uninstall() {
    remove_jumps
    # Цепочки (возможно с правилами, ссылающимися на наборы — сначала flush)
    for ch in "$IN_CHAIN" "$OUT_CHAIN"; do
        iptables -F "$ch" 2>/dev/null && iptables -X "$ch" 2>/dev/null
        if have6; then
            ip6tables -F "$ch" 2>/dev/null && ip6tables -X "$ch" 2>/dev/null
        fi
    done
    # Юниты: выключить и убрать
    systemctl disable --now rkn-extra-block.timer rkn-agent.timer \
        rkn-extra-block.service rkn-agent.service 2>/dev/null
    rm -f /etc/systemd/system/rkn-extra-block.timer \
          /etc/systemd/system/rkn-extra-block.service \
          /etc/systemd/system/rkn-agent.timer \
          /etc/systemd/system/rkn-agent.service
    systemctl daemon-reload 2>/dev/null
    # Наборы ipset
    for s in "$IN_SET4" "$IN_SET6" "$OUT_SET4" "$OUT_SET6"; do
        ipset destroy "$s" 2>/dev/null
    done
    # Скрипты, конфиги, логи
    rm -f /usr/local/sbin/rkn-extra-block /usr/local/sbin/rkn-agent-collect
    rm -rf "$CONF_DIR"
    rm -f /run/rkn-extra-block.lock
    log "UNINSTALL-OK: контур rkn-extra-block полностью удалён"
    rm -f "$LOG_FILE" /var/log/rkn-scans.json
    echo "rkn-extra-block удалён: правила, наборы, юниты, скрипты, конфиги и логи сняты"
}

case "${1:-}" in
    on)      lock; ensure_deps; cmd_on ;;
    off)     lock; ensure_deps; cmd_off ;;
    status)  cmd_status ;;
    update)  lock; ensure_deps; cmd_update; cmd_status_short ;;
    boot)    lock; cmd_boot ;;
    log)     lock; ensure_deps; shift; cmd_log "${1:-status}" ;;
    scan)    shift; cmd_scan "$@" ;;
    set)     lock; ensure_deps; shift; cmd_set "$@" ;;
    clearscans) lock; cmd_clearscans ;;
    uninstall) lock; ensure_deps; cmd_uninstall ;;
    *) echo "Использование: rkn-extra-block {on|off|status|update|boot|set флаг=on|off...|log on|off|status|scan [файлы...]|clearscans|uninstall}" >&2; exit 2 ;;
esac
