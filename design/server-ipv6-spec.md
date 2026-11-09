# ТЗ: IPv4/IPv6 на сервере и в инстансах (v3)

Статус: v3 после двух независимых ревью и финальной проверки. Макет: `design/server-ipv6.html`.

Что изменилось в v3: закрыт B1 (exit-link блокируется при любом числе пиров, reinstall наследует IPv4-only, ремонтное выключение для уже сломанной связки); убран нереализуемый fallback-сеть `awp-ipv6` (B2); сведена единая таблица `blocked_reason → HTTP → code`; зафиксирован выбор лока; разделены синхронный и 202-путь; описан откат конфига и перенос `start.sh` при пересоздании; `docker create` собирается из `docker inspect` целиком; `get_ip_status` не использует хелперы, глотающие ошибки; `peers: null` при `state_unreadable`.

## 0. Контекст

Панель уже умеет dual-stack, но только автоматически: `_detect_server_ipv6()` (`managers/awg_manager.py:727`) смотрит IPv6 на хосте и default route внутри контейнера. Если Docker IPv6 выключен, инстанс остаётся IPv4-only навсегда. `AllowedIPs = 0.0.0.0/0, ::/0` в клиентском конфиге — требование AmneziaVPN, а не признак работающего IPv6 (`awg_manager.py:3375-3378`).

Факты, проверенные по коду и важные для решений:

- `_configure_container` пишет `# DNS6 = AWG_DEFAULTS['dns6']` жёстко и **игнорирует** переданный `dns6` (`:1564`), хотя `api_install_protocol` его передаёт.
- `_get_dns6` возвращает дефолт даже когда IPv6-шлюза нет (`:3839`) — UI не отличает «не задан» от «дефолт».
- `_get_clients_table` для остановленного контейнера возвращает `[]` (`:2288-2291`) — «0 пиров» может быть ложным.
- Обратного восстановления из `_backup_container_state` нет, а сам бэкап не блокирует операцию при ошибке (`:2245-2266`).
- `exit0.conf` содержит `AllowedIPs = 0.0.0.0/0` (`:1989`), kill-switch ставит `ip -6 route replace unreachable default table $EXIT_TABLE` (`:1894`).
- `awg-quick strip` вырезает `Address`, поэтому `syncconf` IPv6 не применяет — нужен down/up (рестарт).
- `prepare_host` включает Docker IPv6 и откладывает рестарт с маркером `AWP_DOCKER_IPV6=pending`.
- Per-server lock в проекте нет; есть глобальный `serialize_peer_lifecycle` (`peer_lifecycle_lock.py`).
- `_check_admin` пропускает и `admin`, и `support` (`app.py:3358-3366`).

Задача: видеть, какие версии IP есть и используются; включать IPv6 для новых инстансов флажком; в инстансе без пиров включать/выключать IPv6; перезапускать Docker минимально необходимыми действиями; светлая тема обязательна; существующие пиры не мигрируются.

## 1. Решения, принятые до реализации

| Вопрос | Решение |
|---|---|
| Семантика светофора | Как задал владелец: 🟢 есть и используется, 🟠 есть, но не используется, 🔴 нет. Плюс текст и глиф, чтобы цвет не был единственным сигналом |
| «Включён, но пиров с IPv6 нет» | 🟠 + текст «готов, клиентов пока нет» (не отдельный цвет) |
| Существующие серверы | Три-стейт `None` = «авто, как раньше» — регрессии поведения нет |
| IPv6 + exit-link | `link()` отклоняется, если в `Address` есть IPv6-шлюз, **независимо от числа пиров** (`exit_link_ipv6`); новый инстанс, автоматически привязанный к exit-node, создаётся IPv4-only; переустановка наследует прежний IPv4-only режим |
| Выключение IPv6 | Обычно — только при `peers == 0`. Исключение: `exit_linked && peers > 0` — разрешено с предупреждением (это уже нерабочий IPv6, чинимый дефект), чтобы не было взаимоблокировки |
| Гейт «0 пиров» | Только при успешно прочитанных конфиге и clientsTable и работающем контейнере. Иначе 409 `state_unreadable`, `peers: null` |
| Пересоздание контейнера | `stop → rename → create → copy → verify → start → cleanup`, без `rm` до успеха |
| Применение Docker IPv6 | `systemctl restart docker`; bridge проверяется после; fallback — отдельная IPv6-сеть. Ребут сервера не штатный путь |
| `pending` | Не хранится, вычисляется из живого состояния |
| Блокировки | `serialize_peer_lifecycle` для инстансов; отдельный op-lock для Docker |
| Кто admin | Мутации — строгий admin (не support) |

## 1а. UX

### 1а.1. Шапка сервера

В `page-header__actions` (`templates/server.html:693`) добавить кнопку **«Настроить IP»** и чипы статуса. Существующий `#serverIpv6` (`server.html:690`, рендер `:2627-2634`) **удалить**: он показывает IPv6 из `stats` с другим фильтром, и два разных IPv6 в одном заголовке — гарантированная путаница. Все данные — из одного `/ip-status`.

Чипы: `IPv4` + глиф + адрес; `IPv6` + глиф + адрес; `Docker IPv6` — показывать только когда он не 🟢 (иначе шум; в шапке добавление третьего чипа на мобилке лишнее).

Состояния IPv4/IPv6:

| Состояние | Цвет | Глиф | Текст |
|---|---|---|---|
| `in_use` | 🟢 | ✓ | «Инстансы: N · Пиры: M» |
| `host_only` | 🟠 | ! | «не используется» |
| `enabled_no_peers` | 🟠 | ! | «готов, клиентов пока нет» |
| `absent` | 🔴 | ✕ | «нет на хосте» |
| `no_route` | 🔴 | ✕ | «адрес есть, маршрута нет» |
| `unknown` | серый | ? | «нет связи с сервером» |

- Цвет не единственный сигнал: глиф + текст + `aria-label` + `role="status"`.
- Полный адрес — в `title` и в модалке; в чипе `max-width` + ellipsis; на узких экранах только `v4/v6` + глиф.
- Адреса оборачивать в `dir="ltr"` + `unicode-bidi: isolate` (для fa/RTL).
- Docker: 🟢 `EnableIPv6=true` и bridge v6; 🟠 выключен или требуется рестарт; 🔴 Docker недоступен.
- Загрузка — отдельным лёгким запросом при открытии страницы, **независимо от тумблера статистики**.

### 1а.2. Модалка «IP-адреса сервера»

Карточки: IPv4, IPv6, Docker IPv6 — адрес/состояние, светофор, расшифровка, причина.

Switch **«Разрешить IPv6 для новых инстансов»** — три положения:

- `Авто` (как раньше) — текущее автоповедение;
- `Включено` — новые AWG-инстансы dual-stack, если host + Docker + контейнер готовы;
- `Выключено` — новые инстансы IPv4-only.

Хинт: «Существующие инстансы не меняются. IPv6 у существующего включается только в его настройках и только пока в нём нет пиров».

Блок «Docker IPv6»:

- всё в порядке: «включён, bridge IPv6 есть»;
- нужен рестарт: warning-callout с текстом про blast radius и **одна** кнопка «Перезапустить Docker сейчас»;
- «Настройка сохранена» писать только после фактического сохранения preference.

Таблица инстансов: `Инстанс | v4-подсеть | v6-подсеть | Пиры (всего / с v6) | Состояние | Действие`.

- «Действие» — badge + ссылка «Настроить» (открывает модалку инстанса), не второй независимый переключатель.
- Показывать `container_running`, `needs_recreate` и причину блокировки текстом, не только эмодзи.

Кнопки: одна primary с динамической подписью («Сохранить» / «Сохранить и перезапустить Docker»), «Отмена», guard на закрытие с несохранёнными изменениями. После «Позже» — постоянный баннер под шапкой с кнопкой «Перезапустить Docker сейчас».

### 1а.3. Настройки инстанса (AWG)

В модалке «Настройки AmneziaWG» (`server.html:1593`), в блоке DNS:

- switch **«Выдавать IPv6-адреса клиентам»** — только для `awg/awg2/awg3`, **включая мульти-инстансы** `awg3__2` (валидация: `is_valid_protocol(proto)` и `protocol_base(proto) in {'awg','awg2','awg3'}`); для `awg_legacy`/WireGuard — скрыт;
- DNS6 input disabled, когда IPv6 выключен; при включении подставляется текущее значение или дефолт.

Матрица доступности — разная для включения и выключения:

| Действие | peers==0 (успешно прочитано) | exit_linked | host ok | docker ok | server pref |
|---|---|---|---|---|---|
| включить | обязательно | запрещено | обязательно | обязательно | обязательно |
| выключить | обязательно | разрешено (с предупреждением) | — | — | — |
| выключить (ремонт) | **не требуется**, только при exit_linked && peers>0 | обязательно | — | — | — |

Третья строка — не штатный переключатель, а ремонт уже сломанной комбинации: инстанс с пирами, который был привязан к exit-node до этой фичи. Предупреждение: «У существующих клиентов IPv6 перестанет работать. IPv4 не затрагивается». Обычный путь (0 пиров) остаётся как задал владелец.

Причины блокировки (текстом): `peers` — «в инстансе N пиров»; `exit_link` — «привязан к выходной ноде»; `server_off`; `docker_off`; `needs_recreate`; `state_unreadable`; `not_awg`; `env_off`; `env_on`.

**Одна кнопка «Сохранить» на всё.** Двух независимых писателей быть не должно: `update_awg_settings` (`awg_manager.py:3863`) меняет MTU/DNS/`# DNS6` и не трогает `Address`, а переключатель IPv6 — отдельная операция; при двух вызовах порядок не определён. Решение: расширить `POST /api/servers/{id}/awg/settings/save` полем `ipv6_enabled` и выполнять один композитный сценарий с серверной валидацией. Если композитность окажется тяжёлой — отдельная кнопка «Применить IPv6» с блокировкой общего Save, пока переключатель изменён.

Если пиры появились между проверкой и коммитом — 409, конфиг не изменён.

### 1а.4. Установка нового инстанса

В `installModal` (`server.html:1392`) — блок «IPv6» с тремя состояниями (включён / применится после рестарта Docker / выключен на сервере). Данные — из того же `/ip-status`, открытого один раз; лишний SSH на открытие модалки не делать.

Правила:

- preference `Включено` + Docker готов → новый инстанс dual-stack;
- preference `Включено` + Docker pending → **409 `docker_pending` до начала установки** на серверной стороне (`POST /install`), а не только спрятанной кнопкой; кнопка установки заменяется на «Сначала включить Docker IPv6». «Полу-IPv6» создавать нельзя: контейнер без sysctls навсегда IPv4-only;
- preference `Выключено` → IPv4-only;
- preference `Авто` → как сейчас, по `_detect_server_ipv6`;
- **если инстанс будет автоматически привязан к default exit — принудительно IPv4-only**, с явной строкой в логе «IPv6 отключён: инстанс привязывается к exit-ноде» (см. §2.7).

DNS6 в форме установки показывать только при доступном IPv6; подсеть — «свободная `fd42:8:N::/64`», без конкретного N. Per-instance opt-out на этапе установки не делаем: отключается потом, пока нет пиров.

### 1а.5. Тема, мобилка, доступность, i18n

- В `static/css/style.css` **добавить компонент switch**: сейчас `.switch` используется в `server.html:1452`, но стилей нет. Нужны `:focus-visible`, `aria-checked`, disabled, RTL-safe.
- Добавить токены `--warning-border`, `--info-border` в тёмную и светлую темы; перевести `.badge-warn`/`.badge-info` (`style.css:762-772`) с хардкода на токены.
- Контраст: `#d97706` на белом ≈3:1, `#16a34a` ≈3.1:1 — для текста мало. Для светлой темы брать более тёмные оттенки текста + рамку/иконку.
- Мобилка: таблица → карточки (добавить в макет), модалка на всю ширину, футер — как в продукте (`style.css:2930-2944`, строка кнопок), а не «в столбик».
- RTL: `margin-inline-start` вместо `margin-left`, `text-align: start`, `dir="ltr"` на адресах.
- i18n: не вводить новых строк с плюрализацией — формулировки без склонения («Пиры: 36 · IPv6: 0»); ключи во всех 5 локалях; коды ошибок API маппить в локализованные тексты (образец — `EXIT_LINK_ERROR_KEYS`, `server.html:4095-4113`).
- Терминология: в продукте есть и «инстанс», и «экземпляр» — зафиксировать глоссарий, использовать «инстанс».

## 2. Backend

### 2.1. Модель данных

```python
server['ipv6_new_instances'] = None   # None=авто, True=включено, False=выключено
```

Больше ничего не персистим. `ipv6_enabled`, `blocked_reason`, `restart_pending`, `peers_v6` — вычисляемые поля `/ip-status`. Причина: конфиг меняется в обход новых endpoint'ов (`server_config/save`, `backups/restore`, reinstall, ручной `docker cp`), и кэш в data.json начнёт врать.

Совместимость: старые `data.json` без поля → `None` (авто). `load_data` не должен проставлять `False`.

Кэш — только in-memory, ключ `server['uid']` (не индекс: индексы сдвигаются при удалении сервера), TTL 20 с; ошибки не кэшировать дольше 2–5 с; инвалидировать после install/uninstall/toggle/restart/`connections add|remove`/`server_config/save`/`backups/restore`/exit-link, вместе с `_invalidate_config_cache` (`:2553`) и `docker_ps_invalidate`.

### 2.2. Разрешение IPv6

1. env `AWG_IPV6`: `off` → жёстко IPv4-only; `on` → жёстко dual-stack; `auto`/не задан → дальше. UI показывает `env_off`/`env_on` и не даёт переключать в противоположную сторону.
2. `server['ipv6_new_instances']`: `None` → автодетект (текущее поведение); `True` → требовать host+docker+container; `False` → IPv4-only.
3. `prepare_host` **не должен** включать Docker IPv6, если админ явно поставил `False` (сейчас делает это независимо, `:989-1022`) — передавать разрешение в `prepare_host`.

### 2.3. Детект: `get_ip_status()`

Один детектор для шапки, статистики и `/ip-status`. Отдельный метод `AWGManager.get_ip_status(protocols)`.

Хост — не `ip addr`, а адрес интерфейса default route:

- `ip route get 1.1.1.1` → `src`; `ip -6 route get 2606:4700::1111` → `src`;
- `ip -4/-6 route show default`;
- `sysctl -n net.ipv6.conf.all.disable_ipv6`, `net.ipv6.conf.all.forwarding`, `/proc/cmdline` (`ipv6.disable`), `/etc/sysctl.d/*disable_ipv6*`;
- фильтровать `docker*`, `br-*`, `amn0`, `veth*`, `tun*`, `awg*` и ULA `fc00::/7` (как `app.py:4238-4243`).

Docker:

- `/etc/docker/daemon.json` присутствует/валиден;
- `docker network inspect bridge -f '{{.EnableIPv6}}'`;
- `docker version --format '{{.Server.Version}}'` (здоровье демона, не `systemctl is-active`);
- `docker info` / `systemctl cat docker` — конфликт флагов `--ipv6/--ip6tables`.

Контейнер инстанса:

- `docker inspect` → `State.Running`, `HostConfig.Sysctls`;
- `docker exec c cat /proc/sys/net/ipv6/conf/all/disable_ipv6` (значение, не наличие ключа);
- `ip -6 route show default` внутри;
- egress-тест `docker exec c curl -6 -sS -m 4 -o /dev/null https://ipv6.google.com` — только при включении, не в периодическом опросе (curl в образе есть, `:1656`).

Инстанс:

- `Address` читается **один раз** батч-скриптом; `get_ip_status` не использует `_get_subnet_ip`, `_get_subnet_ipv6_ip` и `_get_dns6` — они глотают исключения и при SSH-сбое вернут `10.8.1.1`/`''`, то есть «IPv6 нет» вместо `unknown`;
- `Address` из серверного конфига → `subnet_v6`;
- `peers_total` = union пиров конфига и **включённых** строк clientsTable (как `clients_count`, `:4080-4084`); disabled-строки не считаются живыми пирами; отдельный счётчик осиротевших строк — вне v1 (§7);
- `peers_v6` — по `clientIpv6`/`AllowedIPs`;
- `exit_linked` — из exit-link record;
- `needs_recreate` — контейнер без v6-sysctls или создан без v6.

Ответ:

```json
{
  "state": "ok|degraded|unknown",
  "error": null,
  "host": {"ipv4": "...", "ipv6": "...", "ipv4_state": "in_use", "ipv6_state": "host_only",
           "ipv6_default_route": true, "ipv6_disabled_by_sysctl": false},
  "docker": {"installed": true, "ipv6_enabled": false, "bridge_ipv6": false,
             "daemon_json_present": false, "restart_required": true,
             "flags_conflict": false, "ip6tables_ok": true},
  "preference": {"new_instances": null, "env_override": "auto"},
  "instances": [{
    "proto": "awg3__2", "container": "amnezia-awg3-2",
    "subnet_v4": "10.8.2.0/24", "subnet_v6": null,
    "peers": 36, "peers_v6": 0,
    "ipv6_enabled": false, "container_running": true,
    "container_ipv6_capable": false, "needs_recreate": true,
    "can_enable": false, "can_disable": true,
    "blocked_reason": "peers", "exit_linked": false
  }]
}
```

`blocked_reason`: `peers | exit_link | server_off | docker_off | needs_recreate | state_unreadable | not_awg | env_off | env_on | none`.

При `state_unreadable` контракт обязан отдавать `"peers": null` (UI показывает «—», не «0»), иначе снова появится ложное «0 пиров».

`state`: `unknown` — любая ошибка SSH/батча; `degraded` — есть 🔴/🟠 или `restart_required`; `ok` — иначе. `error` — enum безопасных кодов (`ssh_failed` в v1), не свободный текст. Недоступный Docker отдаётся как `docker.installed = false`, без отдельного кода.

Глоссарий (не смешивать): `docker.restart_required` — `daemon.json` просит IPv6, а bridge его не имеет; `instance.needs_recreate` — контейнер без v6-sysctls; `AWP_DOCKER_IPV6=pending` — маркер установки, не значение поля API.

`restart_required` вычисляется: `daemon.json` просит IPv6, а bridge его не имеет. Не хранится.

SSH-ошибка → `state: "unknown"`, серый статус, не красный.

### 2.4. API

- `GET /api/servers/{id}/ip-status` — read-only, admin и support, без секретов, кэш, бюджет ≤2 с (один батч-скрипт).
- `POST /api/servers/{id}/ipv6` — **только preference**, строгий admin:

  ```json
  {"enabled": true}
  ```

  Ответ 200 `{"changed": true, "preference": {...}}`; повторный идентичный запрос — 200, `changed: false`, без побочных эффектов. Валидация `enabled` ∈ {true, false, null}; невалидное тело — 400 (в остальных endpoint'ах Pydantic даёт 422, `app.py:5072-5076`).
- `POST /api/servers/{id}/docker/ipv6/apply` — операция, строгий admin, тело `{"confirm": "restart-docker"}`; ответ `202 {"op_id": "..."}`. Не смешивает сохранение preference и рестарт.
- `GET /api/servers/{id}/operations/{op_id}` — статус фоновой операции (install/restart), персистентный, переживает рестарт панели; незавершённая помечается `interrupted`.
- `POST /api/servers/{id}/protocol/{proto}/ipv6` — строгий admin, тело `{"enabled": true}`. `proto` валидируется как `is_valid_protocol(proto)` и `protocol_base(proto) in {'awg','awg2','awg3'}` — мульти-инстансы `awg3__2` обязаны работать.

Единая таблица состояний и кодов (одни и те же имена в `blocked_reason`, HTTP-кодах и i18n):

| Причина | `blocked_reason` | HTTP | code |
|---|---|---|---|
| есть пиры | `peers` | 409 | `peers` |
| exit-link | `exit_link` | 409 | `exit_link` |
| IPv6 выключен на сервере | `server_off` | 409 | `server_off` |
| Docker IPv6 не готов | `docker_off` | 409 | `docker_off` |
| нужен рестарт Docker | — | 409 | `docker_pending` |
| контейнер без v6-sysctls | `needs_recreate` | 409 | `needs_recreate` |
| конфиг не прочитан | `state_unreadable` | 409 | `state_unreadable` |
| не AWG | `not_awg` | 400 | `not_awg` |
| принудительно выключено env | `env_off` | 409 | `env_off` |
| принудительно включено env | `env_on` | 409 | `env_on` |
| занято другой операцией | — | 409 | `operation_busy` |
| lifecycle ещё держится | — | 409 | `peer_lifecycle_still_running` (повторять нельзя, операция продолжается) |
| lifecycle в неопределённости | — | 503 | `peer_lifecycle_uncertain` |
| конфликт флагов docker | — | 409 | `docker_flags_conflict` |
| bridge без IPv6 после рестарта | — | 409 | `docker_bridge_ipv6_missing` |
| битый `daemon.json` | — | 409 | `daemon_json_invalid` |
| NAT66 не поддерживается | — | 409 | `ip6tables_unsupported` |
| пул IPv6 исчерпан | — | 409 | `ipv6_pool_exhausted` |

Невалидное тело — 400 `bad_request`.

Синхронность: `POST /protocol/{proto}/ipv6` синхронный, если пересоздание не требуется (200); при `needs_recreate` — 202 + `op_id`, и тогда «пиры появились во время операции» = статус `failed` с `reason: peers_appeared`, а не HTTP 409. Предварительные 409 отдаются до старта.

`GET /operations/{op_id}` в v1 — только для `docker/ipv6/apply` и пересоздания. Установка не переводится на `op_id`: она стримит прогресс и живёт в `_INSTALL_OPS` (`app.py:4957`).

Ответы не содержат `PrivateKey`/`PresharedKey`/паролей — отдельный тест.

### 2.5. Строгий admin

`_check_admin` пропускает `support` (`app.py:3358-3366`). Для `POST /ipv6`, `POST /docker/ipv6/apply`, `POST /protocol/{proto}/ipv6` ввести `_require_admin_strict` (роль `admin`), same-origin (образец `_ssh_trust_admin`, `app.py:3480-3489`); Bearer-токены наследуют ту же проверку. Support: `GET /ip-status` — 200, мутации — 403. В UI у support кнопки disabled/скрыты, чипы видны.

### 2.6. Блокировки

- Инстансные мутации — `@serialize_peer_lifecycle`; `peer_lifecycle_busy` → 409, `uncertain` → 503.
- Docker-рестарт — отдельный host-level op-lock; проверять занятость установки любого протокола (`_INSTALL_OPS`), awg-plugin ops, backup/restore, exit-link; иначе 409 `operation_busy`.
- data.json — короткий read-modify-write через `save_data_async`/`DATA_LOCK`; SSH-операции держать **вне** лока; после длинной SSH-операции перечитывать `data` и патчить только целевой ключ (существующий `save_data` без лока в `api_awg_settings_save`, `app.py:6068`, не копировать).
- exit-link **зафиксировано**: `@serialize_peer_lifecycle` ставится на `api_exit_link`, `unlink`, `relink`, `failover` и на новый endpoint; внутренние `exit_link_service._locks[(uid, proto)]` остаются как защита от параллельных вызовов сервиса. Вариант «либо/либо» из v2 отменён — он оставлял гонку.
- Docker-op-lock держит state-файл операции на хосте (§2.9.7): `_INSTALL_OPS` живёт в памяти и очищается при рестарте панели, поэтому guard’ом быть не может.

### 2.7. Exit-link (обязательные правила)

Причина: новый инстанс автоматически линкуется к default exit (`app.py:5244-5255`), `exit0.conf` разрешает только `0.0.0.0/0` (`:1989`), kill-switch ставит `unreachable default` для IPv6 (`:1894`). Клиенты получают IPv6+DNS6, а трафик уходит в чёрную дыру.

1. При установке: если `should_link_default_exit(...)` → `ipv6=False` принудительно + строка в логе.
2. `exit_link_service.link()`: отклонять при наличии IPv6-шлюза в `Address` **независимо от числа пиров** — `ExitLinkError('exit_link_ipv6')`, текст «сначала выключите IPv6 в настройках инстанса». Сейчас проверка привязана к `peers == 0` и линковка проходит с предупреждением `ipv6_refused` (`:280`, `:388`), которое нигде не используется.
3. Переустановка/relink: `relink_entry` (`app.py:5263`) не применяется к инстансу, у которого после переустановки появился IPv6-шлюз; переустановка наследует прежний IPv4-only режим.
4. Выключение IPv6 у exit-linked инстанса — по матрице §1а.3: при 0 пиров штатно, при `peers > 0` — только как ремонт с предупреждением.
5. UI: старые `exit_link_ipv6_confirm`/`exit_link_ipv6_warning` (`server.html:4194`, `:4277`) переиспользовать: confirm убрать, warning превратить в текст ошибки.
6. IPv6 через exit-ноду — вне v1; в UI явно: «IPv6 не поддерживается на exit-связке».

### 2.8. Переключение IPv6 у существующего инстанса (0 пиров)

Предусловия (все обязательны, иначе fail до изменений):

- контейнер `running`;
- **успешно** прочитаны конфиг и clientsTable; чтение `Address`, `[Peer]`, `clientsTable` (JSON) не упало; иначе 409 `state_unreadable`;
- union пиров = 0;
- для включения: нет `exit_link`, host+docker v6 ок, preference не `False`, env не `off`;
- образ контейнера присутствует, порт известен.

Порядок:

1. **Бэкап обязателен и проверяем**: `data.json`, `/etc/docker/daemon.json`, `/opt/amnezia/awg` (`_backup_container_state`), плюс `docker inspect` (image, port, cap-add, sysctls, network, restart policy). Проверить: код возврата 0, `clientsTable` парсится, `wireguard_server_private_key.key` непустой, sha256. Ошибка бэкапа → abort.
2. **Одно вычисленное `ipv6_effective`** передаётся и в `_docker_run_cmd`, и в `_configure_container`. Два независимых вызова `_detect_server_ipv6` (как сейчас, `:1430` и `:1450`) запрещены: рассинхрон «Address dual-stack, sysctls нет» приводит к тому, что `awg-quick` удаляет `awg0` целиком.
3. **Preflight внутри контейнера** до записи `Address`: `ip link add dummy0 type dummy && ip -6 addr add fd42:8:N::1/64 dev dummy0 && ip link del dummy0` — проверяет реальный `disable_ipv6` netns, а не намерение в `HostConfig`.
4. **Включение**:
   - `Address` += `, fd42:8:N::1/64`, где N берётся из IPv4-подсети инстанса (`10.8.N.1/24` → `fd42:8:N`); проверить, что N не занят v6-подсетью другого контейнера. **Индекс везде десятичный**: `parse_subnet_indexes` сейчас читает `fd42:8:N` как hex (`:97-99`), а `_configure_container` пишет decimal (`:1537`) — при N ≥ 10 проверка занятости врёт, парсер надо привести к decimal;
   - `# DNS6 = <текущее значение или дефолт>`, **без перегенерации ключей** (`_configure_container` нельзя — генерирует новую пару, `:1571-1631`);
   - обязательно `_write_start_script(protocol_type)` — в контейнерах старой установки может не быть IPv6 NAT66/forwarding (`:1795-1806`); `syncconf` для `Address` не работает (`awg-quick strip` вырезает `Address`);
   - если контейнер не имеет v6-sysctls → **пересоздание без потери состояния**:
     `docker stop c` → `docker rename c c.ipv6bak` → `docker create` с аргументами из `docker inspect` **целиком**: `Image`, `HostConfig.Privileged`, `CapAdd`, `Sysctls`, `Binds`, `Ulimits`, `PortBindings`, `RestartPolicy`, `NetworkMode` (иначе получится непривилегированный контейнер без `/lib/modules` и без `--ulimit`), плюс v6-sysctls → `docker cp c.ipv6bak:/opt/amnezia/awg/. c:/opt/amnezia/awg/` в **остановленный** контейнер → `_write_start_script(protocol_type)` для **нового** контейнера (иначе `start.sh` возьмётся из образа без panel-обвязки; `docker cp` каталога `awg` его не копирует) → проверить ключи/clientsTable/`[Peer]`/`exit/` + совпадение публичного ключа → `docker start c` → `docker network connect amnezia-dns-net c` → `_wait_container_running` → `_verify_interface_up` (`:800-821`) → сверить число пиров → `docker rm c.ipv6bak`;
     ошибка на любом шаге → `docker rm` нового, `docker rename` обратно, `docker start`, затем **вернуть конфиг**: `docker cp <backup>/awg0.conf c:/opt/amnezia/awg/awg0.conf` + сверка sha256;
   - `remove_container` (`rm -fv` + `rmi`, `:2235-2243`) не использовать;
   - после старта: `ip -6 route show default` внутри **до** фиксации успеха; нет маршрута → откат.
5. **Выключение**:
   - убрать IPv6 из `Address`, убрать `# DNS6`;
   - `_write_start_script` + `docker restart`; пересоздание не требуется;
   - проверить, что `_get_subnet_ipv6_ip(protocol_type) == ''` (сигнатура `_get_client_ipv6` — `(protocol_type, client_ip)`, `:710`);
   - разрешено даже при `exit_link`/`docker_off`/`server_off`.
6. Любая ошибка → откат конфига/контейнера; инстанс не остаётся без туннеля.
7. Успех фиксируется только после проверки: контейнер `running`, интерфейс поднят, число пиров совпадает, ключи не изменились.

### 2.9. Docker IPv6

Новый метод `enable_docker_ipv6(restart: bool)`; `prepare_host` должен **вызывать его**, а не дублировать логику (`:991-1012`).

1. Preflight:
   - `ip6tables -t nat -L -n` — если не работает, не включать `ip6tables` и честно сказать «NAT66 не поддерживается»;
   - `systemctl cat docker` / `ps -o args= -C dockerd` — при `--ipv6`/`--ip6tables` в юните вернуть 409 `docker_flags_conflict`;
   - `net.ipv6.conf.all.disable_ipv6` — при 1 сразу говорить «нужен sysctl/ребут», не рестартить Docker впустую.
2. Merge `daemon.json` (не overwrite): `ipv6: true`, `fixed-cidr-v6` (сохранить существующий, иначе `fd00:42::/64`), `experimental: true`, `ip6tables: <результат preflight>` — ключ условный, а не всегда `true`; в ответе `docker.ip6tables_ok` и текст «NAT66 не поддерживается».
   - невалидный JSON — **отказ**, не перезапись дефолтом (сейчас `prepare_host` при ошибке парсинга перезаписывает файл, теряя чужие ключи, `:989-1023`);
   - атомарная запись: tmp + rename, mode 0644; backup `daemon.json.bak`.
3. `restart=False` → вернуть `pending`, ничего не рестартить.
4. `restart=True` → `systemctl restart docker` → ждать `docker version --format '{{.Server.Version}}'` в ретраях → дождаться `docker ps` и AWG-контейнеров (`--restart always`) → `docker network inspect bridge -f '{{.EnableIPv6}}'`.
5. Если bridge остался `false` после рестарта: не включать IPv6 новым инстансам, вернуть 409 `docker_bridge_ipv6_missing` с текстом «перезагрузите хост или настройте Docker вручную». Fallback-сеть `awp-ipv6` из v2 **убрана**: `start.sh` делает NAT66/forwarding только на `eth0/eth1` (`:1787-1805`), второй интерфейс не покрывается, а `_docker_run_cmd` не управляет сетями вообще.
6. Ошибка старта Docker → восстановить `daemon.json.bak`, поднять демон, отчёт. Если и восстановление не подняло Docker — оставить `.bak`, **не повторять рестарт**, вернуть 500 `docker_recovery_failed` с инструкцией; панель не блокировать.
7. Рестарт — фоновая операция с `op_id` и state-файлом на хосте, чтобы пережить обрыв панели (если панель в Docker — она тоже перезапустится). Текст в UI условный: «панель на systemd продолжит работать; если панель в Docker — она тоже перезапустится».
8. Guard: не рестартить при активной установке/обновлении/бэкапе — 409.
9. Blast radius: все контейнеры перезапускаются, VPN на 10–30 с. «10–30» — оценка, не гарантия.
10. Сервер целиком не перезагружаем. Только явный fallback с подтверждением владельца, если Docker не поднимается или нужен kernel/sysctl-путь. В v1 кнопки «Перезагрузить сервер» нет.

## 3. Клиентские конфиги

Генерацию менять почти не нужно:

- `_get_client_ipv6(protocol_type, client_ip)` (`awg_manager.py:710`) вернёт `fd42:8:N::<hex>` только если в серверном `Address` есть IPv6-шлюз;
- `add_client`/`get_client_config` (`:3262`, `:3398`) добавят `, <v6>/128` в `Address` и DNS6 в `DNS` только при непустом `clientIpv6`;
- `AllowedIPs = 0.0.0.0/0, ::/0` остаётся всегда — требование AmneziaVPN, даже для IPv4-only инстанса.

Исправить по ходу:

- `_configure_container` должен писать переданный `dns6`, а не `AWG_DEFAULTS['dns6']` (`:1564`);
- `_get_dns6` возвращает `''`, если IPv6-шлюза нет (`:3839`); UI отличает «не задан» от «дефолт»;
- `get_awg_settings` отдаёт `ipv6_enabled` (из `Address`), чтобы модалка не делала лишний запрос;
- инвариант `/24` зафиксировать явно; проверка занятости IPv6-адреса при выдаче — **вне v1** (см. §7): коллизия возможна только при ручной правке конфига.

Пример результата:

- сервер: `Address = 10.8.1.1/24, fd42:8:1::1/64`, `# DNS6 = 2606:4700:4700::1111`;
- клиент: `Address = 10.8.1.37/32, fd42:8:1::25/128`, `DNS = 94.140.14.14, 94.140.15.15, 2606:4700:4700::1111`.

Существующие пиры не мигрируем: у инстанса с пирами переключатель заблокирован, старые конфиги не перевыпускаются. Это отдельная задача.

## 4. Безопасность и откат

- Мутации — строгий admin + same-origin; support только читает.
- Подтверждение перед рестартом Docker (`confirm: "restart-docker"`) и текст про blast radius.
- Бэкапы: `data.json`, `/etc/docker/daemon.json`, серверный конфиг, `/opt/amnezia/awg`, `docker inspect`. Бэкап обязателен и проверяется; ошибка бэкапа = abort.
- Fail-stop: любая ошибка → откат; контейнер не остаётся без конфига/туннеля.
- Успех фиксируется только после проверок (running, интерфейс, число пиров, ключи).
- Не логировать приватные ключи/PSK/пароли; ошибки — безопасным текстом; тест на отсутствие секретов в ответах.
- Первый живой тест — новый инстанс или инстанс с 0 пиров; `awg3` с 36 пирами не трогать.
- Параллельные операции — 409; per-server lock не изобретать, использовать `serialize_peer_lifecycle` + host-level op-lock.

## 5. Тесты и приёмка

Unit / API:

- `get_ip_status`: все комбинации host/docker/container; `unknown` при SSH-ошибке; ULA и docker-мосты отфильтрованы; `state_unreadable` вместо `peers=0`.
- три-стейт preference: старый `data.json` без поля → `None` → автоповедение; `True`/`False`; `env_off`/`env_on` перекрывают.
- контракт `/ip-status`: enum состояний, отсутствие секретов в ошибках.
- support: GET 200, POST 403; Bearer-токен — та же матрица.
- `POST /ipv6` идемпотентен (`changed:false`), bad body → 400.
- `POST /protocol/{proto}/ipv6`: `awg3__2` работает, `awg_legacy` → 400, 409-коды по каждому `blocked_reason`.
- матрица on/off: выключение разрешено при `exit_link`/`docker_off`/`server_off`; включение — нет.
- гонка «пир добавлен во время переключения»: синхронный путь → 409, конфиг не изменён; путь с пересозданием → операция `failed` с `reason: peers_appeared`, конфиг откачен.
- `state_unreadable` → `peers: null` в `/ip-status`, UI показывает «—», не «0».
- `get_ip_status` не вызывает `_get_subnet_ip`/`_get_subnet_ipv6_ip`/`_get_dns6` (иначе SSH-сбой маскируется под «IPv6 нет»).
- bridge без IPv6 после рестарта → 409 `docker_bridge_ipv6_missing`, IPv6 новым не включается.
- `_get_client_ipv6`, `add_client`, `get_client_config` для IPv6 on/off.
- `_configure_container(ipv6=True/False)` — `Address` и `# DNS6`; кастомный `dns6` больше не теряется.
- `update_awg_settings` не ломает DNS6/IPv6; композитный Save в обоих порядках.
- пересоздание: sysctls, copy/verify, ключи и clientsTable и exit0 не изменились, публичный ключ совпал.
- fail-stop: битый бэкап → abort до `stop`; ошибка старта → `rename` обратно.
- инвалидация кэша после add/remove пира, restore, `server_config/save`.

Browser (Playwright):

- шапка: зелёный/оранжевый/красный + `unknown`; чипы не ломают мобилку.
- модалка: switch, warning, confirm, таблица, disabled, баннер после «Позже».
- инстанс: lock при пирах, active при 0, DNS6 disabled, композитный Save.
- установка: auto/pending/off, 409 в pending.
- светлая тема и контраст; мобильные карточки; RTL (fa) — адреса не переставляются.
- i18n parity всех новых ключей в 5 локалях (образец — `tests/test_server_page.py:148-156`).

Live (NATA):

- включить Docker IPv6, рестарт в окне; `docker network inspect bridge` и `ip -6 route` в новом контейнере.
- новый инстанс: серверный `Address` и клиентский конфиг с IPv6.
- инстанс с 0 пиров: включить/выключить IPv6, проверить конфиг и откат.
- `awg3` с 36 пирами: переключатель заблокирован, IPv4-клиенты не сломаны.
- панель в Docker: проверить, что операция помечается `interrupted`, а состояние восстанавливается.
- при выключенном preference новые инстансы IPv4-only.

Приёмка: нет регрессий IPv4; data.json цел; бэкапы на месте; обе темы; 5 локалей; SSH-сбой не показывает «IPv6 нет»; ни один существующий пир не потерян.

## 6. Внедрение

- Ветка/worktree `feat/server-ipv6`; тесты на worktree с временным `DATA_FILE`; PR в апстрим, если чисто.
- Бэкапы перед деплоем; проверка `/login`, журнала, data.json.
- Rollback: восстановить `daemon.json` + рестарт Docker; откатить конфиг/контейнер из бэкапа; вернуть data.json.

## 7. Вне рамок v1

- Миграция существующих пиров на IPv6 (перевыпуск конфигов, `AllowedIPs`, clientsTable).
- IPv6 через exit-ноду.
- Fallback-сеть `awp-ipv6` и вообще IPv6 мимо default bridge: требует переделки NAT66/forwarding в `start.sh`.
- Общий `GET /operations/{op_id}` для установки: установка стримит прогресс и живёт в `_INSTALL_OPS`.
- Проверка коллизий `clientIpv6` при выдаче адреса.
- `orphan_rows` / «N записей без пиров» в UI: не блокирует, только текст.
- RTL-визуальный Playwright-прогон (fa); `dir="ltr"` на адресах делаем сразу.
- Разбор `systemctl cat docker` на флаги `--ipv6`: в v1 только `ip6tables`-probe и `docker info`.
- IPv6 для не-AWG протоколов (WireGuard/Xray/…).
- Множественные IPv6-адреса, prefix delegation, IPv6-only хосты.
- Ребут сервера как штатный способ — только fallback.

## 8. Открытые вопросы владельцу

1. **«Используется»** — считаем по живым пирам с IPv6 (текущая формулировка) или достаточно включённого `Address`? Сейчас: `in_use` только при ≥1 пире, `enabled_no_peers` — оранжевый «готов, клиентов пока нет».
2. **Существующие серверы**: `None` = авто (сохраняет текущее поведение) — подтверждаете?
3. **Support**: только чтение статуса, мутации запрещены — подтверждаете?
4. **Окно рестарта Docker**: требовать ввод слова `restart-docker` в UI или достаточно галочки подтверждения?

Решено без вопроса (перенесено из открытых): осиротевшие строки clientsTable не блокируют и в v1 не показываются отдельно (§7); переустановка сохраняет текущий режим IPv6; `link()` блокируется при любом числе пиров, если в `Address` есть IPv6-шлюз.

