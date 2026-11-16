"""Учёт и блокировка торрент-трафика на туннельных интерфейсах.

Правила живут ВНУТРИ контейнера на интерфейсе туннеля (awg0 / wg0): после
расшифровки там видно содержимое пакетов, поэтому сигнатуры ловятся без DPI
на хосте, а счётчик привязывается к конкретному пиру.

Направления в контейнере (проверено на живом инстансе):
  клиент → сервер  : INPUT   `-i awg0`, src = tunnel-IP пира  → прыжок по ``-s``;
  клиент → интернет: FORWARD `-i awg0`, src = tunnel-IP пира  → прыжок по ``-s``;
  интернет → клиент: FORWARD `-o awg0`, dst = tunnel-IP пира  → прыжок по ``-d``.
OUTPUT (пакеты самого контейнера к пиру) торрентов не несёт и не фильтруется.

Поколения цепочек. Пересборка правил при добавлении/удалении ключа раньше
снимала хуки, потом строила цепочки — всё это время трафик шёл без фильтра
(на 500 пирах это десятки секунд). Теперь каждый пересбор идёт в НОВЫЕ
цепочки `TGIN<n>`/`TGOUT<n>` и `TGI<n>_<m>`/`TGO<n>_<m>`, а хуки
переставляются последними, когда оба набора уже готовы: окно — две команды
iptables вместо сотен.

Безопасность сигнатур. Рукопожатие ищется бинарным префиксом
`|13|BitTorrent protocol` (0x13 — длина строки протокола), а не голым текстом:
иначе любая страница, где встречается фраза «BitTorrent protocol» (статья
Википедии и т.п.), попадала под DROP в направлении к клиенту. Правило трекера
(`info_hash=`) ставится только в направлении клиент → интернет: в ответах
серверов эта строка встречается в обычных страницах.
"""

import json
import logging
import re
import shlex
import threading
import time
import uuid

logger = logging.getLogger(__name__)

# Состояние живёт в контейнере рядом с clientsTable (persistent volume).
DEFAULT_STATE_PATH = '/opt/amnezia/awg/torrent_guard.json'

# 'on'    — счётчик + DROP (защита по умолчанию);
# 'count' — только счётчик (наблюдение, ничего не режем);
# 'off'   — правил нет вообще.
MODES = ('on', 'count', 'off')
DEFAULT_MODE = 'on'

# Сколько ждём, прежде чем снова проверять контейнер, признанный неспособным
# (нет xt_string/xt_connbytes). Без этого флага «не умеет» залипало навсегда.
CAPABLE_RETRY_SECONDS = 3600

# iptables -w <сек>: без значения ожидание xtables-lock бесконечное.
IPT_WAIT = '5'

# Легаси-имена первой версии: нужны только для уборки старого мусора.
LEGACY_CHAIN_IN = 'TG_IN'
LEGACY_CHAIN_OUT = 'TG_OUT'

PEER_CHAIN_RE = re.compile(r'^TG([IO])(\d+)_(\d+)$')
GEN_IN_RE = re.compile(r'^TGIN(\d+)$')
GEN_OUT_RE = re.compile(r'^TGOUT(\d+)$')

# Сигнатуры протокола. Порядок фиксирован: он же порядок счётчиков в цепочке.
# dirs: в какие направления ставить правило ('in' — клиент → сервер/интернет,
# 'out' — интернет → клиент).
SIGNATURES = (
    {
        'key': 'handshake',
        'proto': 'tcp',
        'dirs': ('in', 'out'),
        # Бинарный префикс 0x13 не бывает в тексте страниц, поэтому ложных
        # DROP на обычном HTTP нет. connbytes ограничивает DPI первыми 2 КБ
        # соединения: без него `-m string` проверяет каждый пакет.
        'match': ['-m', 'connbytes', '--connbytes', '0:2048',
                  '--connbytes-dir', 'original', '--connbytes-mode', 'bytes',
                  '-m', 'string', '--algo', 'bm',
                  '--hex-string', '|13|BitTorrent protocol'],
    },
    {
        'key': 'dht_query',
        'proto': 'udp',
        'dirs': ('in', 'out'),
        # DHT-потоки короткоживущие; окно не даёт сканировать каждый UDP-пакет
        # (QUIC/игры/VoIP) на слабом VPS.
        'match': ['-m', 'connbytes', '--connbytes', '0:4096',
                  '--connbytes-dir', 'both', '--connbytes-mode', 'bytes',
                  '-m', 'string', '--algo', 'bm', '--string', 'd1:ad2:id20:'],
    },
    {
        'key': 'dht_short',
        'proto': 'udp',
        'dirs': ('in', 'out'),
        'match': ['-m', 'connbytes', '--connbytes', '0:4096',
                  '--connbytes-dir', 'both', '--connbytes-mode', 'bytes',
                  '-m', 'string', '--algo', 'bm', '--string', '1:y1:q'],
    },
    {
        'key': 'tracker',
        'proto': 'tcp',
        'dirs': ('in',),
        'match': ['-m', 'connbytes', '--connbytes', '0:4096',
                  '--connbytes-dir', 'original', '--connbytes-mode', 'bytes',
                  '-m', 'string', '--algo', 'bm', '--string', 'info_hash='],
    },
)
SIG_KEYS = tuple(s['key'] for s in SIGNATURES)


def signatures_for(direction):
    """Сигнатуры, которые ставятся в цепочки этого направления."""
    return [sig for sig in SIGNATURES if direction in sig['dirs']]


def target_for(mode):
    """Цель правила: DROP в режиме защиты, RETURN — в режиме наблюдения."""
    return 'DROP' if mode == 'on' else 'RETURN'


def normalize_mode(mode):
    mode = str(mode or '').strip().lower()
    return mode if mode in MODES else DEFAULT_MODE


def chain_in(gen):
    return 'TGIN%d' % int(gen)


def chain_out(gen):
    return 'TGOUT%d' % int(gen)


def chain_peer_in(gen, n):
    return 'TGI%d_%d' % (int(gen), int(n))


def chain_peer_out(gen, n):
    return 'TGO%d_%d' % (int(gen), int(n))


def _args(parts):
    """Список аргументов iptables в одну безопасную строку для sh."""
    return ' '.join(shlex.quote(str(p)) for p in parts)


def _peer_discovery(show_cmd):
    """Функция sh `peer_list`, печатающая tunnel-IP всех пиров (только IPv4).

    Peer в `awg show`/`wg show` описан строкой `allowed ips: 10.8.1.17/32`.
    Берём первый адрес, отбрасываем IPv6 и `0.0.0.0` (exit-транзитные пиры).
    `sh -c` нужен, чтобы `||` не съел пайп: `awg show` есть не в каждом
    контейнере, в остальных работает `wg show`.

    Ретраи обязательны: сразу после установки правил `awg show` изредка
    отдаёт пустой вывод (занят netlink-сокет), и без ретрая скрипт решает,
    что пиров нет. Пустой вывод самой команды и «пиров правда нет» различаем
    по сырому ответу: если `awg show` что-то напечатал, значит пиров нет.
    """
    show = shlex.quote(show_cmd)
    return (
        'peer_list() { i=0; while [ $i -lt 3 ]; do '
        'raw=$(sh -c %s 2>/dev/null); '
        'if [ -n "$raw" ]; then '
        'echo "$raw" | awk \'/allowed ips:/ { split($3, a, "/"); '
        'if (a[1] ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/ && a[1] != "0.0.0.0") '
        'print a[1] }\' | sort -u; '
        'return 0; fi; '
        'i=$((i+1)); sleep 1; done; return 1; }' % show
    )


def _hook_cleanup_lines(iface):
    """Снятие наших хуков, КРОМЕ текущего поколения ($I/$O).

    Порядок в apply: новый набор цепочек уже собран → вставляем новые хуки →
    этим снимаем старые (текущие пропускаются) → удаляем старые цепочки.
    Так окно без фильтра — две команды iptables, а не весь пересбор.
    """
    return [
        'while ipt -D INPUT -i "$IFACE" -j %s; do :; done' % LEGACY_CHAIN_IN,
        'while ipt -D FORWARD -i "$IFACE" -j %s; do :; done' % LEGACY_CHAIN_IN,
        'while ipt -D FORWARD -o "$IFACE" -j %s; do :; done' % LEGACY_CHAIN_OUT,
        'while ipt -D OUTPUT -o "$IFACE" -j %s; do :; done' % LEGACY_CHAIN_OUT,
        "for c in $(iptables -w %s -S INPUT 2>/dev/null | sed -n "
        "'s/^-A INPUT -i .* -j \\(TGIN[0-9][0-9]*\\)$/\\1/p'); do" % IPT_WAIT,
        '    [ "$c" = "$I" ] && continue',
        '    while ipt -D INPUT -i "$IFACE" -j "$c"; do :; done',
        'done',
        "for c in $(iptables -w %s -S FORWARD 2>/dev/null | sed -n "
        "'s/^-A FORWARD -i .* -j \\(TGIN[0-9][0-9]*\\)$/\\1/p'); do" % IPT_WAIT,
        '    [ "$c" = "$I" ] && continue',
        '    while ipt -D FORWARD -i "$IFACE" -j "$c"; do :; done',
        'done',
        "for c in $(iptables -w %s -S FORWARD 2>/dev/null | sed -n "
        "'s/^-A FORWARD -o .* -j \\(TGOUT[0-9][0-9]*\\)$/\\1/p'); do" % IPT_WAIT,
        '    [ "$c" = "$O" ] && continue',
        '    while ipt -D FORWARD -o "$IFACE" -j "$c"; do :; done',
        'done',
    ]


def _chain_cleanup_lines():
    """Удаление наших цепочек в два прохода, кроме текущего поколения.

    Порядок важен: пока жив `TGIN<n>`, он ссылается на пир-цепочки и ядро
    запрещает их удаление (ошибка глушится). Сначала удаляем родителей
    (`TGIN*/TGOUT*/TG_IN/TG_OUT`), затем пир-цепочки. Раньше единый проход
    оставлял висящие `TGI<n>_*` после каждой пересборки — проверено живьём.
    """
    w = IPT_WAIT
    return [
        "chains() { iptables -w %s -S 2>/dev/null | awk '/^-N TG/{print $2}'; }" % w,
        'for c in $(chains); do',
        '    case "$c" in "$I"|"$O") continue;; esac',
        '    case "$c" in TGIN*|TGOUT*|TG_IN|TG_OUT) ;; *) continue;; esac',
        '    ipt -F "$c"',
        '    ipt -X "$c"',
        'done',
        'for c in $(chains); do',
        '    case "$c" in "$I"|"$O") continue;; esac',
        '    case "$c" in TGI"$GEN"_*|TGO"$GEN"_*) continue;; esac',
        '    case "$c" in TGI*|TGO*|TG_I*|TG_O*) ;; *) continue;; esac',
        '    ipt -F "$c"',
        '    ipt -X "$c"',
        'done',
    ]


def build_remove_script(iface):
    """Полное снятие защиты (режим off): хуки, затем цепочки."""
    lines = [
        '#!/bin/sh',
        '# Amnezia Web Panel: torrent guard removal (generated)',
        'IFACE=%s' % shlex.quote(iface),
        'ipt() { iptables -w %s "$@" 2>/dev/null; }' % IPT_WAIT,
        'I=',
        'O=',
        'GEN=',
    ]
    lines.extend(_hook_cleanup_lines(iface))
    lines.extend(_chain_cleanup_lines())
    lines.extend(['echo "@MODE off"', 'echo "@GEN 0"', ''])
    return '\n'.join(lines)


def build_apply_script(iface, mode, show_cmd, gen):
    """Установка: новые цепочки поколения, хуки переставляются последними."""
    mode = normalize_mode(mode)
    if mode == 'off':
        return build_remove_script(iface)
    target = target_for(mode)
    gen = int(gen)
    in_chain = chain_in(gen)
    out_chain = chain_out(gen)
    sig_lines = []
    for sig in signatures_for('in'):
        sig_lines.append('  add -A "$ic" -p %s %s -j "$TARGET"'
                         % (sig['proto'], _args(sig['match'])))
    for sig in signatures_for('out'):
        sig_lines.append('  add -A "$oc" -p %s %s -j "$TARGET"'
                         % (sig['proto'], _args(sig['match'])))
    lines = [
        '#!/bin/sh',
        '# Amnezia Web Panel: torrent guard (generated)',
        'IFACE=%s' % shlex.quote(iface),
        'MODE=%s' % shlex.quote(mode),
        'TARGET=%s' % target,
        'GEN=%d' % gen,
        'I=%s' % in_chain,
        'O=%s' % out_chain,
        'ipt() { iptables -w %s "$@" 2>/dev/null; }' % IPT_WAIT,
        # Ошибки добавления считаем: иначе контейнер без xt_string/xt_connbytes
        # неотличим от рабочего — правила молча не встают, а панель показывает
        # «защита включена».
        'FAIL=0',
        'add() { iptables -w %s "$@" 2>/dev/null || FAIL=$((FAIL+1)); }' % IPT_WAIT,
        'add -N "$I"',
        'add -N "$O"',
        'echo "@MODE $MODE"',
        'echo "@GEN $GEN"',
        _peer_discovery(show_cmd),
        'n=0',
        'for p in $(peer_list); do',
        '  n=$((n+1))',
        '  ic=TGI${GEN}_$n',
        '  oc=TGO${GEN}_$n',
        '  add -N "$ic"',
        '  add -N "$oc"',
        '  add -A "$I" -s "$p" -j "$ic"',
        '  add -A "$O" -d "$p" -j "$oc"',
    ]
    lines.extend(sig_lines)
    lines.extend([
        '  echo "@P $n $p"',
        'done',
        # Переключение: новый набор уже готов, вставляем новые хуки первыми
        # (два iptables-вызова), затем снимаем старые и убираем их цепочки.
        'add -I INPUT 1 -i "$IFACE" -j "$I"',
        'add -I FORWARD 1 -i "$IFACE" -j "$I"',
        'add -I FORWARD 1 -o "$IFACE" -j "$O"',
    ])
    lines.extend(_hook_cleanup_lines(iface))
    lines.extend(_chain_cleanup_lines())
    lines.extend(['echo "@FAIL $FAIL"', 'echo "@END ok"', ''])
    return '\n'.join(lines)


def build_read_script(iface, show_cmd):
    """Скрипт чтения: хуки, поколение, счётчики, целостность, список пиров."""
    w = IPT_WAIT
    in_sel = '"s/^-A INPUT -i $IFACE -j \\(TGIN[0-9][0-9]*\\)$/\\1/p"'
    in2_sel = '"s/^-A FORWARD -i $IFACE -j \\(TGIN[0-9][0-9]*\\)$/\\1/p"'
    out_sel = '"s/^-A FORWARD -o $IFACE -j \\(TGOUT[0-9][0-9]*\\)$/\\1/p"'
    chain_sel = ("'s/^-N \\(TGI[0-9][0-9]*_[0-9][0-9]*\\)$/\\1/p; "
                 "s/^-N \\(TGO[0-9][0-9]*_[0-9][0-9]*\\)$/\\1/p'")
    lines = [
        '#!/bin/sh',
        'IFACE=%s' % shlex.quote(iface),
        'GEN=',
        'h=0',
        ('IN=$(iptables -w ' + w + ' -S INPUT 2>/dev/null | sed -n '
         + in_sel + ' | head -1)'),
        ('IN2=$(iptables -w ' + w + ' -S FORWARD 2>/dev/null | sed -n '
         + in2_sel + ' | head -1)'),
        ('OUT=$(iptables -w ' + w + ' -S FORWARD 2>/dev/null | sed -n '
         + out_sel + ' | head -1)'),
        'if [ -n "$OUT" ]; then GEN=${OUT#TGOUT}; '
        'elif [ -n "$IN" ]; then GEN=${IN#TGIN}; fi',
        'if [ -n "$GEN" ]; then',
        '  [ "$IN" = "TGIN$GEN" ] && h=$((h+1))',
        '  [ "$IN2" = "TGIN$GEN" ] && h=$((h+1))',
        '  [ "$OUT" = "TGOUT$GEN" ] && h=$((h+1))',
        'fi',
        'echo "@HOOK $h 3"',
        'echo "@GEN ${GEN:-0}"',
        'bad=0',
        'if [ -n "$GEN" ]; then',
        ('  for c in $(iptables -w ' + w + ' -S 2>/dev/null | sed -n '
         + chain_sel + '); do'),
        '    case "$c" in TGI"$GEN"_*|TGO"$GEN"_*) ;; *) continue;; esac',
        '    printf "@C %s " "$c"',
        ('    iptables -w ' + w + ' -xvnL "$c" 2>/dev/null | awk '
         + "'NR>2 {printf \"%s \", $1}'"),
        '    echo',
        ('    k=$(iptables -w ' + w + ' -S "$c" 2>/dev/null '
         '| grep -c \'^-A \' || true)'),
        '    case "$c" in TGI*) want=%d;; *) want=%d;; esac'
        % (len(signatures_for('in')), len(signatures_for('out'))),
        '    [ "$k" -eq "$want" ] || bad=$((bad+1))',
        '  done',
        'fi',
        # Два активных поколения (обрыв apply между вставкой хуков и уборкой)
        # не ломают защиту (DROP срабатывает в новом), но это мусор и двойной
        # matching — считаем набор нездоровым и пересобираем.
        ('  c1=$( { iptables -w ' + w + ' -S INPUT 2>/dev/null; '
         'iptables -w ' + w + ' -S FORWARD 2>/dev/null; } '
         "| sed -n 's/.*-j \\(TGIN[0-9][0-9]*\\)$/\\1/p' | sort -u | wc -l)"),
        ('  c2=$(iptables -w ' + w + ' -S FORWARD 2>/dev/null | sed -n '
         "'s/.*-j \\(TGOUT[0-9][0-9]*\\)$/\\1/p' | sort -u | wc -l)"),
        '  { [ "$c1" -le 1 ] && [ "$c2" -le 1 ]; } || bad=$((bad+1))',
        'echo "@BAD $bad"',
        _peer_discovery(show_cmd),
        'echo "@PEERS $(peer_list | tr \'\\n\' \' \')"',
        '',
    ]
    return '\n'.join(lines)


def build_probe_script():
    """Проверка, что контейнер умеет string/connbytes: пробная цепочка.

    Требуем, чтобы прошли ВСЕ сигнатуры: без `xt_connbytes` рукопожатие
    BitTorrent всё равно не поймать, и «частично умеет» здесь бесполезно.
    """
    lines = ['#!/bin/sh', 'iptables -w %s -N AWP_TG_PROBE 2>/dev/null' % IPT_WAIT,
             'ok=1']
    for sig in SIGNATURES:
        lines.append('iptables -w %s -A AWP_TG_PROBE -p %s %s -j RETURN '
                     '2>/dev/null || ok=0'
                     % (IPT_WAIT, sig['proto'], _args(sig['match'])))
    lines.extend([
        'iptables -w %s -F AWP_TG_PROBE 2>/dev/null' % IPT_WAIT,
        'iptables -w %s -X AWP_TG_PROBE 2>/dev/null' % IPT_WAIT,
        'echo "@PROBE $ok"',
        '',
    ])
    return '\n'.join(lines)


def parse_report(out):
    """Разбор вывода скриптов: хуки, поколение, счётчики, пиры, ошибки."""
    report = {'hook': False, 'mode': '', 'gen': 0, 'counters': {}, 'peers': [],
              'ended': False, 'probe': None, 'fail': None, 'bad': 0}
    for raw in (out or '').splitlines():
        line = raw.strip()
        if not line.startswith('@'):
            continue
        parts = line.split()
        tag = parts[0]
        if tag == '@HOOK':
            try:
                report['hook'] = int(parts[1]) == int(parts[2]) > 0
            except (IndexError, ValueError):
                report['hook'] = False
        elif tag == '@GEN':
            try:
                report['gen'] = int(parts[1])
            except (IndexError, ValueError):
                report['gen'] = 0
        elif tag == '@MODE':
            report['mode'] = parts[1] if len(parts) > 1 else ''
        elif tag == '@PROBE':
            report['probe'] = len(parts) > 1 and parts[1] == '1'
        elif tag == '@FAIL':
            try:
                report['fail'] = int(parts[1])
            except (IndexError, ValueError):
                report['fail'] = 1
        elif tag == '@BAD':
            try:
                report['bad'] = int(parts[1])
            except (IndexError, ValueError):
                report['bad'] = 1
        elif tag == '@PEERS':
            report['peers'] = [p for p in parts[1:] if p]
        elif tag == '@C' and len(parts) >= 2:
            values = []
            for token in parts[2:]:
                try:
                    values.append(int(token))
                except ValueError:
                    values.append(0)
            report['counters'][parts[1]] = values
        elif tag == '@P' and len(parts) >= 3:
            report['peers'].append(parts[2])
        elif tag == '@END':
            report['ended'] = True
    return report


def chain_peer(chain, peers):
    """TGI7_3 -> IP пира по списку из того же отчёта (нумерация с единицы)."""
    m = PEER_CHAIN_RE.match(chain or '')
    if not m:
        return ''
    idx = int(m.group(3))
    return peers[idx - 1] if 0 < idx <= len(peers) else ''


def diff_counters(previous, current):
    """Прирост счётчиков по (цепочка, сигнатура).

    Правило стоит с DROP, поэтому ноль прироста — норма даже для активного
    торрент-клиента: он просто перестаёт передавать. Событие = прирост.
    """
    events = []
    for chain, values in (current or {}).items():
        if not PEER_CHAIN_RE.match(chain or ''):
            continue
        old = (previous or {}).get(chain) or []
        is_in = PEER_CHAIN_RE.match(chain).group(1) == 'I'
        keys = [sig['key'] for sig in signatures_for('in' if is_in else 'out')]
        for i, key in enumerate(keys):
            if i >= len(values):
                break
            if i >= len(old):
                continue
            delta = values[i] - old[i]
            if delta > 0:
                events.append({'chain': chain, 'sig': key, 'count': delta})
    return events


_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def _container_lock(key):
    # RLock: apply() держит блокировку на весь цикл (state → gen → установка),
    # а _run_in_container берёт её повторно в том же потоке.
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


class TorrentGuard:
    """Один инстанс: чтение счётчиков и переустановка правил через SSH."""

    def __init__(self, ssh, container, iface,
                 show_cmd='awg show 2>/dev/null || wg show 2>/dev/null',
                 state_path=DEFAULT_STATE_PATH, host_key=''):
        self.ssh = ssh
        self.container = container
        self.iface = iface
        self.show_cmd = show_cmd
        self.state_path = state_path
        # Хост в ключе блокировки: контейнеры с одинаковым именем на разных
        # нодах — это разные контейнеры, сериализовать их незачем.
        self._lock_key = (host_key or '', container)

    def _run_in_container(self, script, timeout=120):
        """Запуск скрипта внутри контейнера через ОДИН sudo-вызов.

        Под non-root SSH панель ходит через `sudo -S`: пароль подаётся в stdin,
        а sudo применяется к одной команде. Поэтому `docker cp ... && docker
        exec ...` в одной строке не работает (sudo получает только `docker cp`),
        а `docker exec -i` ещё и перехватывает stdin с паролем. Здесь весь набор
        (cp → exec → уборка) выполняется host-скриптом под sudo целиком.

        Временный файл кладём в приватный каталог (mktemp -d + 700): файл
        пишется SSH-пользователем, а читает его root, и общий /tmp с
        предсказуемым именем для этого не годится.
        """
        out, err, code = self.ssh.run_command('mktemp -d /tmp/amnz-tg.XXXXXXXX')
        staging = (out or '').strip()
        if code != 0 or not staging.startswith('/tmp/amnz-tg.'):
            raise RuntimeError(err or 'cannot create private staging dir')
        host_path = staging + '/guard.sh'
        # Внутри контейнера каталога staging нет — копируем в плоский /tmp.
        tag = uuid.uuid4().hex[:8]
        cpath = '/tmp/_amnz_tg_%s.sh' % tag
        container = shlex.quote(self.container)
        staging_q = shlex.quote(staging)
        wrapper = '\n'.join([
            '#!/bin/bash',
            '# host-side wrapper: docker cp + docker exec (run under sudo)',
            'set -u',
            'docker cp %s %s:%s' % (shlex.quote(host_path), container, cpath),
            'rc=$?',
            'if [ "$rc" -eq 0 ]; then',
            '    docker exec %s sh %s' % (container, cpath),
            '    rc=$?',
            '    docker exec %s rm -f %s >/dev/null 2>&1 || true' % (container, cpath),
            'fi',
            'rm -rf %s' % staging_q,
            'exit "$rc"',
            '',
        ])
        try:
            self.ssh.upload_file(script, host_path)
            with _container_lock(self._lock_key):
                return self.ssh.run_sudo_script(wrapper, timeout=timeout)
        finally:
            self.ssh.run_command('rm -rf ' + staging_q)

    def read(self, timeout=90):
        out, err, code = self._run_in_container(
            build_read_script(self.iface, self.show_cmd), timeout=timeout)
        report = parse_report(out)
        if code != 0 and not report['hook'] and not report['counters']:
            report['error'] = (err or '').strip() or 'torrent guard read failed'
        else:
            report['error'] = ''
        return report

    def apply(self, mode, timeout=240):
        """Переустановка правил. Состояние пишется сюда же: UI-путь и коллектор
        должны оставлять одинаковый след (иначе `capable=False` залипал)."""
        mode = normalize_mode(mode)
        with _container_lock(self._lock_key):
            # Поколение считаем под блокировкой: иначе коллектор и UI могли
            # выбрать одно и то же число → `add -N` падает и правила дублируются.
            state = self.load_state()
            gen = int(state.get('gen') or 0) + 1
            out, err, code = self._run_in_container(
                build_apply_script(self.iface, mode, self.show_cmd, gen),
                timeout=timeout)
        report = parse_report(out)
        report['mode'] = report['mode'] or mode
        report['gen'] = int(report.get('gen') or gen)
        now = int(time.time())
        if report.get('fail'):
            # iptables отклонил правила: чаще всего нет xt_string/xt_connbytes.
            report['error'] = ('iptables rejected %s rule(s); '
                               'xt_string/xt_connbytes may be unavailable'
                               % report['fail'])
        elif code != 0 and not report['ended']:
            report['error'] = (err or '').strip() or 'torrent guard apply failed'
        else:
            report['error'] = ''

        if mode == 'off':
            self._persist({'mode': 'off', 'gen': report['gen'], 'peers': [],
                           'counters': {}, 'capable': None, 'capable_ts': 0,
                           'ts': now})
        elif report['error']:
            # Транспортный сбой (docker cp/ssh) не должен помечать контейнер
            # «не умеет»: иначе он час не будет перепроверяться.
            capable = False if report.get('fail') else state.get('capable')
            self._persist({'mode': mode, 'gen': report['gen'],
                           'peers': list(report.get('peers') or []),
                           'counters': {}, 'capable': capable,
                           'capable_ts': now, 'ts': now})
        else:
            self._persist({'mode': mode, 'gen': report['gen'],
                           'peers': list(report.get('peers') or []),
                           'counters': {}, 'capable': True,
                           'capable_ts': now, 'ts': now})
        return report

    def probe(self):
        out, err, code = self._run_in_container(build_probe_script())
        report = parse_report(out)
        if report['probe'] is None:
            # Отличаем «не смогли проверить» от «контейнер не умеет».
            report['error'] = (err or '').strip() or 'probe returned no verdict'
        else:
            report['error'] = ''
        return report

    def load_state(self):
        # Без `docker exec -i`: под non-root SSH stdin занят паролем sudo -S.
        out, err, code = self.ssh.run_sudo_command(
            'docker exec %s cat %s 2>/dev/null'
            % (shlex.quote(self.container), shlex.quote(self.state_path)))
        if code != 0 or not (out or '').strip():
            return {}
        try:
            data = json.loads(out)
        except (json.JSONDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_state(self, state):
        staging = '/tmp/_amnz_tg_state_%s.json' % uuid.uuid4().hex[:8]
        self.ssh.upload_file(json.dumps(state, ensure_ascii=False), staging)
        try:
            out, err, code = self.ssh.run_sudo_command(
                'docker cp %s %s:%s'
                % (staging, shlex.quote(self.container),
                   shlex.quote(self.state_path)))
            if code == 0 and self.state_path:
                # Файл содержит tunnel-IP и счётчики: не должен читаться
                # любым локальным пользователем ноды.
                self.ssh.run_sudo_command(
                    'docker exec %s chmod 600 %s'
                    % (shlex.quote(self.container), shlex.quote(self.state_path)))
        finally:
            self.ssh.run_command('rm -f ' + staging)
        if code != 0:
            # Молчаливый отказ записи (нет каталога в контейнере, нет места,
            # контейнер остановлен) делал «состояние сохранено» ложью.
            raise RuntimeError((err or '').strip() or 'state save failed')

    def _persist(self, state):
        try:
            self.save_state(state)
        except Exception as e:                      # noqa: BLE001 - состояние не критично
            logger.warning('torrent guard: state save failed: %s', e)

    def collect(self, mode=None):
        """Один цикл опроса: сверить состояние, при нужде переустановить,
        вернуть новые события по пирам.

        Переустановка нужна, когда: пропали хуки (рестарт/пересоздание
        контейнера), сменилось поколение (потерян state), изменился набор
        пиров, набор правил недособран (`@BAD`) или админ сменил режим.
        В цикле переустановки события не считаются: счётчики только что
        обнулились, базы для дельты нет.
        """
        mode = normalize_mode(mode)
        state = self.load_state()
        now = int(time.time())
        capable = state.get('capable')
        capable_ts = int(state.get('capable_ts') or 0)
        if (capable is False and mode != 'off'
                and now - capable_ts < CAPABLE_RETRY_SECONDS):
            # Неспособность кэшируется на час: иначе каждый цикл дёргает
            # iptables впустую. Через час — перепроверка (модули могли
            # доставить), плюс сброс кэша при успешном apply из UI.
            return {'mode': mode, 'applied': False, 'events': [], 'peers': 0,
                    'error': ('torrent guard unsupported: '
                              'xt_string/xt_connbytes missing'),
                    'cached': True}
        report = self.read()
        if report.get('error'):
            return {'mode': mode, 'applied': False, 'events': [], 'peers': 0,
                    'error': report['error']}
        peers_now = list(report.get('peers') or [])
        peers_old = list(state.get('peers') or [])
        gen_now = int(report.get('gen') or 0)
        gen_old = int(state.get('gen') or 0)
        mode_changed = state.get('mode') != mode
        if mode_changed:
            need_apply = True
        elif mode == 'off':
            need_apply = bool(report.get('hook'))
        elif not report.get('hook'):
            need_apply = True
        elif gen_now != gen_old:
            # State потерян или правила поставлены другим поколением: счётчики
            # нельзя сопоставить с пирами.
            need_apply = True
        elif report.get('bad'):
            need_apply = True
        elif not peers_now and peers_old:
            # Hook стоит, но `awg show` не отдал ни одного пира: транзиентный
            # сбой чтения, а не «всех удалили».
            return {'mode': mode, 'applied': False, 'events': [],
                    'peers': len(peers_old), 'skipped': True, 'error': ''}
        else:
            need_apply = peers_now != peers_old
        if need_apply:
            if mode != 'off' and capable is not True:
                probe = self.probe()
                if probe.get('probe') is False:
                    self._persist({'mode': mode, 'gen': gen_old, 'peers': [],
                                   'counters': {}, 'capable': False,
                                   'capable_ts': now, 'ts': now})
                    return {'mode': mode, 'applied': False, 'events': [],
                            'peers': 0,
                            'error': ('torrent guard unsupported: '
                                      'xt_string/xt_connbytes missing')}
            applied = self.apply(mode)
            if applied.get('error'):
                return {'mode': mode, 'applied': False, 'events': [],
                        'peers': 0, 'error': applied['error']}
            return {'mode': mode, 'applied': True, 'events': [],
                    'peers': len(applied.get('peers') or []), 'error': ''}
        events = diff_counters(state.get('counters'), report.get('counters') or {})
        fresh = []
        for event in events:
            ip = chain_peer(event['chain'], peers_now)
            if ip:
                fresh.append({'ip': ip, 'sig': event['sig'],
                              'count': event['count'], 'ts': now})
        counters = report.get('counters') or {}
        # Не переписываем состояние в контейнер, если ничего не поменялось.
        changed = (state.get('mode') != mode
                   or list(state.get('peers') or []) != peers_now
                   or int(state.get('gen') or 0) != gen_now
                   or (state.get('counters') or {}) != counters)
        state.update({'counters': counters, 'mode': mode, 'gen': gen_now,
                      'peers': peers_now, 'ts': now,
                      'capable': True if capable is not False else capable,
                      'capable_ts': capable_ts})
        if changed:
            self._persist(state)
        return {'mode': mode, 'applied': False, 'events': fresh,
                'peers': len(peers_now), 'error': ''}
