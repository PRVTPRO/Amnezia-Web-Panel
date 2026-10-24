#!/usr/bin/env bash
# rkn-agent — почасовой сборщик статистики срабатываний rkn-extra-block.
# Читает journalctl -k за последний час, матчит SRC-IP против /etc/rkn-extra-block/nets.map
# (сеть → ведомство), пишет компактные JSON-строки в /var/log/rkn-scans.json
# и подрезает файл до последних 5000 строк. Без зависимостей кроме journalctl/awk.
# Работает только если включено журналирование: rkn-extra-block log on.

set -u

MAP_FILE="/etc/rkn-extra-block/nets.map"
OUT_FILE="/var/log/rkn-scans.json"
SINCE_FILE="/etc/rkn-extra-block/scanlog.since"
MAX_LINES=5000
LOCK_FILE="/run/rkn-agent.lock"

exec 9>"$LOCK_FILE" || exit 1
flock -n 9 || exit 0

[ -f "$MAP_FILE" ] || exit 0   # списки ещё не подгружались

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
since="-65 minutes"
[ -f "$SINCE_FILE" ] && since="$(cat "$SINCE_FILE")"

journalctl -k --no-pager --since "$since" 2>/dev/null | grep "RKN_EXTRA" | \
MAP_FILE="$MAP_FILE" TS="$ts" awk '
function pad(o) { return sprintf("%03d.%03d.%03d.%03d", o[1], o[2], o[3], o[4]) }
BEGIN {
    FS = "\t"
    while ((getline line < ENVIRON["MAP_FILE"]) > 0) {
        n = split(line, f, "\t")
        if (n >= 3) { cnt++; first[cnt] = f[1]; last[cnt] = f[2]; label[cnt] = f[3] }
    }
    close(ENVIRON["MAP_FILE"])
}
function lookup(ip,   q, i) {
    split(ip, o, ".")
    q = pad(o)
    for (i = 1; i <= cnt; i++)
        if (q >= first[i] && q <= last[i]) return label[i]
    return ""
}
/RKN_EXTRA/ {
    dir = "in"
    if ($0 ~ /RKN_EXTRA_OUT/) dir = "out"
    if ($0 ~ /RKN_EXTRA_IN6/ || $0 ~ /RKN_EXTRA_OUT6/) dir = dir "6"
    src = ""; dpt = 0
    if (match($0, /SRC=[0-9a-fA-F:.]+/)) src = substr($0, RSTART + 4, RLENGTH - 4)
    if (match($0, /DPT=[0-9]+/))   dpt = substr($0, RSTART + 4, RLENGTH - 4) + 0
    if (src == "") next
    org = (src ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ ? lookup(src) : "")
    if (org == "") org = (dir ~ /6$/ ? "C24Be v6" : "C24Be")
    gsub(/["\\]/, "", org)
    printf "{\"t\":\"%s\",\"dir\":\"%s\",\"ip\":\"%s\",\"dpt\":%d,\"org\":\"%s\"}\n", ENVIRON["TS"], dir, src, dpt, org
}
' >> "$OUT_FILE"

# Подрезка, чтобы лог не рос бесконечно
lines=$(wc -l < "$OUT_FILE")
if [ "$lines" -gt $MAX_LINES ]; then
    tail -n $MAX_LINES "$OUT_FILE" > "$OUT_FILE.tmp"
    mv "$OUT_FILE.tmp" "$OUT_FILE"
fi

# Горизонт следующего сбора — от этого момента (старое из journalctl не тянем)
echo "$ts" > "$SINCE_FILE"
