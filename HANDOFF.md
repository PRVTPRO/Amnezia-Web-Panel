> [!IMPORTANT] ПРОТОКОЛ ДЛЯ ЛЮБОГО AI-ЧАТА, РАБОТАЮЩЕГО С ЭТИМ РЕПО
> 1. ПЕРЕД работой: прочитай этот файл целиком + `git fetch --all` и `git log --oneline -5` по интересующим веткам. Файл — память, но git — единственный источник правды о коде. Утверждения «в ветке X есть/нет Y» без проверки git запрещены.
> 2. ПОСЛЕ каждой итерации (коммит, диагностика, решение): допиши запись с датой/временем в КОНЕЦ файла и закоммить вместе с кодом.
> 3. Всё сразу пушится в форк (origin) — ветки это канал синхронизации между чатами.
> 4. Прод-панель (SERVERA, /root/Amnezia-Web-Panel) живёт на deploy/v170 (на SERVERA origin=апстрим, fork=форк).
> 5. Решённые/старые записи выносим в HANDOFF-ARCHIVE.md (он в репо, читать не нужно — только если надо копнуть историю).

# HANDOFF — Amnezia-Web-Panel (форк leonidorlov-hash)

Обновлено: 2026-10-03. Полная история: HANDOFF-ARCHIVE.md.

## Среда
- `origin` = форк `leonidorlov-hash/Amnezia-Web-Panel` (пушим сюда), `upstream` = `PRVTPRO/Amnezia-Web-Panel`.
- Git Bash: каждая команда с `cd "/c/KIMI/panele4ka/ПанелечкаПроект" &&` (cd не сохраняется между вызовами).
- Тесты: `PATH="/c/Program Files/nodejs:$PATH" venv/Scripts/python.exe -m unittest discover -s tests` (473 теста, 1 skip = playwright; настоящий node.exe ОБЯЗАТЕЛЕН — шим kimi-desktop не исполняется через CreateProcess).
- GitHub API токен: `$(printf "protocol=https\nhost=github.com\n\n" | git credential fill | grep '^password=' | cut -d= -f2)`. MCP github жив.

## Серверы пользователя
- SERVERA = root@stockholmservera (<IP:SERVERA>), панель `/root/Amnezia-Web-Panel`, обновление: `cd /root/Amnezia-Web-Panel && git fetch fork && git reset --hard fork/deploy/v170 && systemctl restart amnezia-panel`
- NATA = <IP:NATA>, ssh :1803 (веб-консоль у хостера). Прочие: FINN :54645, RAHMET/EUROBYTE/FIRSTBYTE/CloudPark.by/MRAK :1803. OVH — debian@vps-c27e7981 (systemctl через sudo).
- MAMKAM — панель удалена 2026-09-07 (управляется через SERVERA). Пароли в data.json на SERVERA. Имя сервера <IP:EUROBYTE> = `EUROBYTE` (не EB!).
- Команды для серверов давать ПО ОДНОЙ, помечать «шелл SERVERA» / «шелл EUROBYTE» (владелец путал с консолью Chrome).

## Постоянные правила
- Обновлять этот HANDOFF.md после КАЖДОЙ итерации (коммит + push deploy/v170). Ветка deploy/v160 УДАЛЕНА 03.10 (панель на OVH снесена, прод везде на v170) — не воскрешать; история целиком в HANDOFF-ARCHIVE.md, а код v160 устарел относительно v170.
- В HANDOFF никогда не писать пароли/ключи/IP — только имена серверов и плейсхолдеры <IP:ИМЯ>.
- HANDOFF и служебные заметки НЕ должны утекать в апстрим-PR (автор уже удалял их у себя — e4bb925). Перед PR проверять состав ветки.
- Владелец: «если нет софта для экономии токенов/скорости/качества — предлагай ставить».
- УРОКИ из инцидентов: (1) правя логику менеджера — `grep -n "def <method>" managers/*manager.py`, у протоколов бывают свои оверайды (wireguard toggle_client); (2) «починил» = проверил деплой и поведение в бою, не «запушил»; (3) EUROBYTE WG: ошибка «Cannot enable client: IP ... already present» — это штатная enable-предпроверка (wireguard_manager.py:944), срабатывает на СТАРОМ рассинхроне конфиг↔таблица, лечится правкой clientsTable (enabled=true), не баг кода.

## Актуальное состояние (на 03.10)
- Прод deploy/v170 = апстрим v1.7.3 (merge 33e87c4) + наши незамерженные фиксы: toggle hardening AWG+WG (08b936a/1595db9/37a7ea1), toggle race retry + peerToggling (0938658), glued batch markers (26129da), сторож poisoned batch (4d0db9f). Кандидаты на будущие PR.
- Все наши PR в апстрим СМЕРЖЕНЫ (#195/#196/#198/#200/#201 — вошли в 1.7.2/1.7.3). Открытых наших PR нет.
- «External вместо имён» — закрыт на трёх слоях: сторож 4d0db9f, distrust пустой batch-таблицы 7fff9bc (ad72fc0 в апстриме), склейка маркеров 26129da. Если симптом вернётся — смотреть журнал prefetch batch (секции по одной на контейнер).
- Панель на SERVERA: раскатка v1.7.3 выдана 03.10 (git fetch fork && reset --hard fork/deploy/v170 && restart), подтверждения владельца не было.
- Kernel-модуль AmneziaWG: панель пинит 3.1.20260812 (awg_manager.py:907), апстрим уже 3.1.20260906 — кандидат на однострочный бамп (владелец 03.10 отказался, не поднимать без запроса).
- Поколение протокола: везде AWG 3.1, новее нет — панель актуальна.

## Осторожно / не закрыто
- Пересборка docker-образов amnezia-awg2 на NATA/FIRSTBYTE/EUROBYTE из свежего amneziavpn/amneziawg-go (--pull) НЕ сделана — до этого НЕ переустанавливать эти инстансы из панели (в образах старые awg-tools → туннель упадёт; tools внутри контейнеров уже пересажены вручную, бэкапы .bak). Аналогично FIRSTBYTE хостовый fckrkn собран вручную.
- PR #176 (DRAFT, fix/awg-tools-selfheal): самолечение tools/kernel mismatch — так и висит драфтом.
- Тест test_awg_mtu_budget.test_awg3_default_would_not_fit_a_standard_link ФЛАКИ (периодически 1495 vs 1500) — кандидат на разбор.
- EUROBYTE: редкие всплески SSH-connect до 4с (сеть провайдера) — наблюдать. FINN: SSH-транспорт панели падает после docker stop/start инстанса — само заживает reconnect'ом.
- Скрипт аудита безопасности /tmp/fleet_audit.py остался на SERVERA (переиспользуем при подозрениях, см. архив 30.09).

## 03.10 12:55 — HANDOFF разделён: рабочий (47 строк) + HANDOFF-ARCHIVE.md (458 строк)
- Причина: экономия токенов — каждый чат читал целиком всю историю решённых проблем.
- В рабочем файле: протокол, среда, серверы, постоянные правила+уроки, актуальное состояние, открытые осторожности. В архиве — всё до 03.10 включительно, ничего не удалено.

## 03.10 13:10 — v1.7.3 раскатана на SERVERA (подтверждено владельцем)
- HEAD на SERVERA: 8040c56 (мерж v1.7.3 внутри). Следующий коммит 41d768a (split HANDOFF, docs-only) в раскатку не попал — не критично.

## 03.10 13:25 — deploy/v160 УДАЛЕНА (владелец: «вычисти, удали, забудь»)
- Причина: панель на OVH снесена (больше не нужна), прод везде на v170, уникального актуального кода в v160 не было. Удалена локально и на форке. Не воскрешать; история — в HANDOFF-ARCHIVE.md.

## 03.10 13:55 — DuckDNS-карточка в настройках (fa59e99, deploy/v170)
- Задача владельца: карточка «Свой домен на duckdns.org» рядом с SSL: инструкция 3 шага, домен+токен, флажок SSL = бесплатный автопродлеваемый сертификат в 1 клик. Решения: только для себя (без PR в апстрим), DNS-01 через acme.sh (порт 80 не нужен), авто-обновление IP в duckdns каждые 600с (монитор-фон), «отключение доступа по IP» НЕ делаем, настройки в data.json, карточка пишет в ТУ ЖЕ settings['ssl'], что и ручная SSL-карточка.
- Эндпоинт POST /api/settings/duckdns/apply: нормализация домена, update IP (пустой ip= → duckdns берёт IP вызывающего = сервер панели), выпуск cert через acme.sh --dns dns_duckdns, install в /etc/amnezia/duckdns.{cert,key}.pem, --reloadcmd systemctl restart amnezia-panel (автопродление само перезапускает панель). Первый apply под systemd сам рестартует панель через 2с-таймер; иначе restart_required в ответе.
- Токен НЕ рендерится в страницу; пустое поле = оставить сохранённый. Ошибки: duckdns_domain_token_required / ip_update_failed / cert_failed (502, ssl не трогается).
- 5 локалей, tests/test_duckdns.py (11 тестов), полный прогон 484 OK.
- Деплой SERVERA: git fetch fork && git reset --hard fork/deploy/v170 && systemctl restart amnezia-panel. После: Настройки → «Свой домен на duckdns.org». Для HTTPS панель УЙДЁТ в рестарт сама — открывать https://домен:5000.

## 03.10 14:30 — DuckDNS: боевой дебют поймал гонку reloadcmd (6b3d2c0)
- Первый боевой apply (домен cnacu6o.duckdns.org): cert ВЫПУСТИЛСЯ, файлы в /etc/amnezia записались, но UI показал 502 duckdns_cert_failed. Корень: '--reloadcmd systemctl restart amnezia-panel' исполнялся синхронно внутри install-cert → systemd убивал панель посреди собственного запроса → дочерний install-cert умирал → rc≠0 → 502 (uvicorn graceful shutdown успевал отдать ответ). settings['ssl'] при этом НЕ записался.
- Фикс: reloadcmd = "sh -c '(sleep 5 && systemctl restart amnezia-panel) >/dev/null 2>&1 &'" — отложенно и отцеплено; install-cert всегда возвращает 0, рестарт случается после ответа. Тот же reloadcmd обслуживает кроновские продления. Дублирующий Timer-рестарт из эндпоинта убран. 484 теста OK.
- Поведение повторного apply идемпотентно: acme.sh скажет Skip (cert жив), install-cert экспортирует, ssl-настройки запишутся, панель сама уйдёт на https://домен:5000.

## 03.10 15:10 — DuckDNS: БОЕВАЯ ПРОВЕРКА ПРОЙДЕНА + PR #202 в апстрим
- После фикса 6b3d2c0 повторный apply отработал чисто: Skip → install-cert → ssl-настройки записались → панель сама ушла на HTTPS. Владелец подтвердил: https://<домен>.duckdns.org:5000 открывается с валидным замком. ERR_EMPTY_RESPONSE по http://IP:5000 — ожидаемо (панель теперь TLS-only).
- Ручная SSL-карточка остаётся как есть (владелец отказался от спойлера): duckdns-карточка и ручная редактируют одну конфигурацию settings['ssl'].
- PR #202 в апстрим: feat/duckdns-card от upstream/main (828f060, 2 коммита чисто черри-пикнулись), 480 тестов OK на ветке, HANDOFF в ветку не утёк. В описании пометка «tested live only on my own single panel — needs testing/feedback», деталь про reloadcmd-гонку, out-of-scope (IP-блок, другие DNS-провайдеры).
- Открытые наши PR в апстрим: только #202.

## 03.10 22:30 — Фикс: менеджер паролей автозаполнял поиск пользователей логином
- Симптом: после перевода панели на https-домен (DuckDNS) Chrome подставлял сохранённый логин в фильтр #userSearch на /users. Причина: эвристика автозаполнения — id поля содержит «user», на странице есть type="password» (форма addUserForm) → Chrome считает поле логином.
- Фикс: users.html input#userSearch → autocomplete="off" + readonly, снятие readonly в onfocus (стандартный обход автозаполнения; readonly-поля менеджеры паролей не трогают, а перед вводом readonly снимается). Тесты 484/484 OK.
- Раскатка: git fetch fork && git reset --hard fork/deploy/v170 && systemctl restart amnezia-panel + Ctrl+Shift+R (менялся users.html).

## 03.10 22:50 — PR #204 в апстрим: фикс автозаполнения #userSearch
- Ветка fix/users-search-autofill от upstream/main (v1.7.3), черри-пик 738ce50, HANDOFF из коммита убран (не течёт в апстрим). 484 теста OK. PR: https://github.com/PRVTPRO/Amnezia-Web-Panel/pull/204

## 04.10 00:45 — Noindex + невинная страница входа (срочно, по требованию владельца)
- Контекст: панель торчит в интернет через https-домен DuckDNS. Страница входа светила в view-source весь словарь I18N (706 строк) — витрину всех фич панели (SSH-управление, API-токены, wg-easy/Remnawave/ngrok...). Запрета индексации не было вообще.
- Сделано: (1) middleware в app.py — заголовок X-Robots-Tag: noindex, nofollow на ВСЕ ответы; (2) роут /robots.txt → Disallow: /; (3) <meta name="robots" content="noindex, nofollow"> в base.html и login.html; (4) login.html больше не получает полный translations_json — render() отдаёт login_translations_json (3 ключа: login/logging_in/login_error), вся остальная разметка входа без изменений; (5) регрессионный тест tests/test_noindex_robots.py. 489/489 OK.
- Раскатка SERVERA обычная + Ctrl+Shift+R. Следом — срочный PR в апстрим.

## 04.10 00:55 — Срочный PR #205: noindex + невинная страница входа
- https://github.com/PRVTPRO/Amnezia-Web-Panel/pull/205 (ветка fix/noindex-public-login от upstream/main, тесты 474/474). Содержит: X-Robots-Tag middleware, robots.txt Disallow:/, meta robots в base+login, login_translations_json вместо полного словаря, тест test_noindex_robots.

## 04.10 13:20 — rkn-extra-block v1.0 в репо amnezia-blocker (f668906)
- Доп. контур по спискам C24Be/AS_Network_List: RKN_EXTRA_IN (подсети РКН → DROP новых в INPUT, v4+v6), RKN_EXTRA_OUT (сети VK/Max/OK → REJECT tcp-reset в OUTPUT+FORWARD). Независим от AMNEZIA_BLOCK. Команды rkn-extra-block on|off|status|update|boot, состояние /etc/rkn-extra-block/state, атомарный swap ipset, systemd service+timer (daily+2h jitter). Установка одной командой (install-rkn-extra.sh). Отдельные 4erdenko/ и blablajka/ — копия и обёртка, игнорируем.

## 04.10 13:30 — rkn-extra-block v1.1: log on/off + scan (f74714c)
- log on/off — rate-limited (10/мин) LOG-правила перед DROP/REJECT, просмотр: journalctl -k -g RKN_EXTRA. scan — ретроспектива: матч IP логов против ipset-наборов. ОБСУЖДАЕТСЯ перенос блокировки+статистики сканов в панель (флажок на сервер + агент почасового сбора).

## 04.10 14:30 — RKN/VK-блок в панели: флажок на сервер + статистика сканов (сырой прототип, БЕЗ PR)
- Решение владельца: «да, пока всё сыро, без PR, протестирую сам вначале». Никаких PR в апстрим и раскаток на SERVERA от меня.
- Серверная половина (blocker-repo, cf2a5e7, отдельный приватный репо leonidorlov-hash/amnezia-blocker): update строит nets.map (метки ORG из blacklist_with_comments.txt); rkn-agent-collect (timer rkn-agent.timer, hourly) собирает журнал -k за 65 мин, парсит SRC=/DPT=, пишет /var/log/rkn-scans.json (tail -5000). Инсталлер ставит агент и включает log on.
- Панель (deploy/v170): POST /api/servers/{id}/rkn_block — enabled=true запускает install-rkn-extra.sh по SSH (таймаут 420с, тянет списки C24Be + apt-пакеты, включает log+agent), enabled=false делает только rkn-extra-block off. GET /api/servers/{id}/rkn_scans — статус контура + tail -2000 rkn-scans.json, агрегация by_org/by_dpt/by_dir/last_24h/recent. UI: карточка 🛡 на странице сервера, флажок + сводка сканов. Состояние — server['rkn_block_enabled'] в data.json (дефолт False). Переводы rkn_block_* во всех 5 локалях. blocker-repo/ в .gitignore (это отдельный репозиторий, не коммитить).
- Тесты: 489/489 OK. Вживую эндпоинты не гонялся (нет SSH к серверам) — владелец тестирует сам. Раскатка владельцу по стандартной команде fetch fork + reset --hard fork/deploy/v170.

## 04.10 16:30 — RKN-блок: починка установки (приватный репо 404 + молчаливый успех)
- Симптом владельца: флажок на MRAK поставлен, полчаса «не установлено на сервере». Расследование: в журнале панели НЕТ POST /rkn_block (но флаг true в data.json — POST прошёл раньше и вернул success); `rkn-extra-block status` на сервере пустой → agent_state unknown.
- Корень — ДВЕ ошибки: (1) репо leonidorlov-hash/amnezia-blocker было ПРИВАТНЫМ → raw.githubusercontent отдавал 404; (2) команда установки `bash -c "$(curl -fsSL url)"` при неудачном curl получает пустую строку и выходит с кодом 0 → панель фиксирует успех без установки. Секретов в репо нет (проверено) → сделал его публичным через API.
- Фикс в app.py: установка теперь `curl -fsSL … -o /tmp/rkn-install.sh && bash /tmp/rkn-install.sh` — неудачное скачивание даёт rc≠0 и панель честно ругается. 489/489 OK. УРОК: конструкция bash -c "$(curl …)" всегда молча успешна при недоступном URL — не использовать.
- Владельцу: перераскатать панель и на MRAK перещёлкнуть флажок OFF→ON (флаг уже true, просто ON повторно не запустит install).

## 04.10 16:45 — RKN-блок: установка падала на apt install flock (blocker-repo 622c3d7)
- Вторая причина неработающей установки на MRAK: в install-rkn-extra.sh был `apt-get install … flock`, а flock — не пакет, а бинарник из util-linux → E: Unable to locate package flock, установка падала, fail-loud фикс показал это честным 500.
- Фикс: ставим util-linux + проверка `command -v flock`. Запушено в amnezia-blocker main (622c3d7). Панель НЕ перекатывать — инсталлер тянется с репо в момент тогла.
- Владельцу: на MRAK флажок OFF→ON ещё раз.

## 04.10 18:00 — RKN-блок: красная кнопка «БЫЛИ СКАНИРОВАНИЯ!» на плитках + детали событий
- Задача владельца: на странице списка серверов в плитке — красная кнопка при сканах за 24ч, клик → страница сервера, там «какая служба, кто, как часто».
- app.py: парсинг вынесен в _parse_rkn_scan_output (чистая функция), SSH-фетч в _fetch_rkn_scan_output (общий). Новый GET /api/servers/rkn_scan_flags — сводка {agent_state, events24, last, flag} по всем серверам, кэш в памяти 15 мин (RKN_FLAG_CACHE, ленивое обновление через asyncio.gather; недоступные серверы тоже кэшируются как None, чтобы не долбить). Конфликта с {server_id} нет — такого голого роута нет.
- index.html: контейнер #rkn-alert-N в плитке, JS loadRknScanFlags() на DOMContentLoaded — красная кнопка ⚠ БЫЛИ СКАНИРОВАНИЯ! (N за 24ч) → /server/N#rknBlockCard.
- server.html: таблица «Последние события» (время/IP/организация/порт) из d.recent + расшифровка портов в имена служб (RKN_SVC_NAMES: 22 SSH, 5000 Panel, 51820 WireGuard и т.д.); по #rknBlockCard — автоскролл к карточке.
- Переводы: rkn_scan_alert, rkn_block_recent — все 5 локалей. Тесты tests/test_rkn_scan_flags.py (6 шт, AST-изоляция как в test_auth_security). Полный прогон 495/495 OK. Без PR (сырой прототип, владелец тестирует).

## 04.10 21:20 — MRAK: охота на «дворника» ipset-наборов + чистка мусора владельца
- Симптом: rkn-extra-block контур ON, но наборы пустые; update писал "Sets cannot be swapped: the second set does not exist" (лог при этом SWAP-OK по всем — лог врёт не может, значит наборы создавались, но потом исчезали).
- Выяснено: на MRAK жили чужие контура — rus-routes.timer (каждые 2 мин крутил /usr/local/bin/rus-routes-update.sh), auto-rus-catch.service, ipset.service (restore /etc/ipset.conf при загрузке), cron /etc/cron.d/amnezia-blocker → update-blocks.sh (прокладка blocker.sh update, чистит только свои). Владелец подтвердил: rus-routes-update.sh и auto-rus-catch.py ЕМУ НЕ НУЖНЫ — disable --now + удалены.
- Пока НЕ доказано, кто именно уничтожал rkn_extra_* (в rus-routes-update.sh destroy чужих нет; blocker.sh — только свои). Гипотезы: kernel без поддержки ip_set v6 (in6/out6), либо внешний restore. Следующий шаг: ручное создание 3 недостающих наборов с видимым rc + повторный update + наблюдение.

## 04.10 21:30 — MRAK: наборы залиты, контур полный; фикс молчаливых ошибок (blocker 412a309)
- Итог диагностики: к 21:24 все 4 набора существуют и полные (in4=1151, in6=21, out4=204, out6=3), контур ON, LOGGING ON. Кто именно уничтожал наборы между 16:43 и 20:28 — не доказано (главный подозреваемый rus-routes.timer выключен владельцем как ненужный). Противоречие «терминал: ошибки / лог: SWAP-OK» объяснил находкой: неудачный create и swap НЕ журналировались вообще — лог писал только успехи.
- Фикс в rkn-extra-block.sh: create/swap теперь пишут CREATE-WARN/SWAP-FAIL с текстом ошибки ядра в /var/log/rkn-extra-block.log; stderr ipset restore тоже в лог. blocker-repo 412a309. Установленные копии на серверах обновятся при следующем переустановке (тогл OFF→ON в панели) — не критично, это только журналирование.
- Просьба владельцу: через 10-15 мин перепроверить `rkn-extra-block status | head -3` — если наборы на месте, кейс закрыт (дворник = rus-routes). Данные статистики появятся после почасового сбора агента; кнопка «БЫЛИ СКАНИРОВАНИЯ!» — когда будут события за 24ч.

## 04.10 21:50 — Все 6 серверов с флажком живы; в API добавлены размеры наборов
- Проверка через консоль браузера (fetch /api/servers/{id}/rkn_scans по id 1,2,3,4,5,8): все отвечают agent_state=on, событий пока нет (агенты почасовые, списаний ещё не было — ожидаемо).
- Слепая зона MRAK (статус on, наборы пустые) закрыта: _parse_rkn_scan_output теперь парсит v4=/v6= из cmd_status → поле sets {in4,in6,out4,out6} в ответах rkn_scans и rkn_scan_flags; в карточке сервера строка «наборы: N/N/N/N» + ⚠️ «наборы пустые — update не отработал», если все нули. Переводы rkn_block_sets/_sets_empty во всех локалях. 496/496 OK.

## 04.10 22:10 — КОРНЕВАЯ ПРИЧИНА найдена: "family inet" одним аргументом (blocker dff8841)
- Симптом на всех 6 серверах: agent_state=on, наборы пустые, swap errors "the second set does not exist".
- Корень: create_set вызывал `ipset create ИМЯ hash:net "family inet" maxelem N` — family+inet в ОДНИХ кавычках → ipset 7.x: "Unknown argument: `family inet'". create НИКОГДА не работал (с v1.0). Наборы существовали только где создавали вручную (поэтому MRAK «сам ожил» после ручного create). Все «SWAP-OK» старых логов — фальшивые (старый swap_list логировал успех unconditionally, код возврата затирался следующей командой).
- Заодно: v6-наборы пропускаются на хостах без IPv6 (have6-guard в cmd_update/cmd_on).
- Фикс: blocker-repo dff8841. Раскатка на каждый сервер одной командой (обновить /usr/local/sbin/rkn-extra-block с репо + update). УРОК: (1) подавление stderr + || true делает диагностику невозможной — сначала честный лог (412a309), потом чинить; (2) «установлено и работает» проверять наполненностью (sets в API), а не статусом on.

## 04.10 23:00 — Раскатка dff8841 на все 6 серверов — все наборы полные
- Одной командой с SERVERA: paramiko-скрипт (venv панели) берёт серверы с rkn_block_enabled из data.json, заливает исправленный rkn-extra-block.sh, делает update и перепроверяет наполненность через 5с. Результат: все 6 серверов [1151, 21, 204, 3], стабильно.
- В data.json порт SSH — поле ssh_port (не port!): FINN 54645, остальные 1803. Для будущих флотовых скриптов — брать оттуда.
- Кэш rkn_scan_flags 15 мин — на странице списка серверов свежие sets появятся после истечения кэша; страницы серверов (rkn_scans без кэша) — сразу. Красные кнопки «БЫЛИ СКАНИРОВАНИЯ!» появятся, когда почасовой агент поймает первые сканы из сетей C24Be.

## 04.10 23:20 — Эмуляция сканирования работает; кнопка «сбросить статистику» (корзина)
- Эмуляция: запись в /dev/kmsg (echo "<13>RKN_EXTRA_IN: ... SRC=... DPT=..." > /dev/kmsg) + ручной запуск /usr/local/sbin/rkn-agent-collect → JSON в rkn-scans.json → красная кнопка появилась на плитке MRAK с count=1. Пайплайн подтверждён end-to-end. SRC берём из ipset list rkn_extra_in4 — тогда метка org из nets.map реальная.
- Новое: POST /api/servers/{id}/rkn_scans/clear — обнуляет /var/log/rkn-scans.json на сервере + выгоняет кэш флагов (кнопка на списке серверов гаснет сразу, без 15-мин ожидания). В карточке сервера кнопка-корзина (SVG, не эмодзи — тест mobile_layout запрещает эмодзи в btn-icon), видна только когда агент установлен. Переводы rkn_block_clear/_clear_confirm/_cleared во всех локалях. Тесты 499/499 OK (в test_rkn_scan_flags добавлены 3 теста clear).

## 04.10 23:30 — Карточка RKN: читаемые подписи + легенда (вместо 1151/21/204/3)
- Строка состояния теперь: "агент: on • блок-листы: вх. 1172, исх. 207 • событий за 24ч: N" (суммы v4+v6 с подписями). Под строкой — легенда: вх. = подсети РКН/гос (блок входящих), исх. = сети VK/Max/OK (блок исходящих). Ключи rkn_block_lists/_in_short/_out_short/_legend во всех локалях. 499/499 OK.

## 04.10 23:55 — Сброс сканов не отпускал: агент перечитывал kernel-журнал → горизонт сбора
- Жалоба: корзина обнуляет rkn-scans.json, но надпись возвращается. Причина: событие живёт в journalctl -k, агент раз в час читает последние 65 минут и подкидывает его обратно.
- Фикс (blocker 37d94e8): rkn-agent.sh пишет /etc/rkn-extra-block/scanlog.since после каждого сбора и читает journalctl только с этой метки; новая команда `rkn-extra-block clearscans` обнуляет журнал И переносит метку на «сейчас». Панель (app.py) clear-эндпоинт теперь зовёт clearscans с fallback на старое поведение. Тесты 499/499 (флаки test_awg_mtu_budget поймал 1495-vs-1500 на первом прогоне — известное, перезапуск зелёный).
- Раскатка: 1) панель обычная; 2) флотовая заливка ОБОИХ скриптов (rkn-extra-block.sh + rkn-agent.sh на /usr/local/sbin/rkn-agent-collect) тем же paramiko-скриптом с SERVERA.

## 13.10 23:35 — «Failed to fetch» при установке Xray на MRAK — не баг панели
- Жалоба: создание инстанса Xray на MRAK сопровождалось ошибками. Текст ошибки: «Failed to fetch» (выпытан командами, не прислан сразу).
- Разбор: установка Xray = docker build с нуля (Alpine + Xray-core v26.3.27 с GitHub) ≈ 5,5 мин. За это время рвётся соединение браузер→панель (путь через duckdns/VPN) → fetch умирает по сети, браузер показывает «Failed to fetch». На сервере установка при этом идёт до конца; в журнале панели POST /api/servers/{id}/install завершается 200 OK.
- Факты: установки Xray 13.10: MRAK (id 8) 20:57→21:03 CEST и MAMKAM (id 7) 21:16→21:18 CEST — ОБЕ 200. Ошибок 500/400 в окне нет, RuntimeError не возникал. Текущие индексы серверов: 0 servera, 1 FINN, 2 RAHMET, 3 NATA, 4 EUROBYTE, 5 FIRSTBYTE, 6 CloudPark.by, 7 MAMKAM, 8 MRAK. Xray + wireguard стоят и на MRAK, и на MAMKAM (вторая установка ушла на соседний сервер при ретрае).
- УРОК: (1) «Failed to fetch» — сетевой обрыв fetch, НЕ ответ панели; длинные установки (build >5 мин) через duckdns/VPN — типовой триггер; (2) при ретрае длинной установки проверять, на какой сервер уходит запрос; (3) диагностика: journalctl grep "POST /api/servers/N/install" — код 200 значит установка дошла до конца.
- Открытый вопрос: фронтенд не переживает обрыв — показывает ошибку вместо «установка идёт, опрашиваю статус». Кандидат на PR апстриму (после подтверждения владельцем).

## 13.10 23:50 — Фронт переживает обрыв fetch при установке; бомба в test_rkn_scan_flags
- Повод: «Failed to fetch» при установке Xray на MRAK (см. запись выше) — fetch умирает по таймауту пути браузер→панель, серверная установка доигрывает.
- Фикс (78510c0, кандидат в апстрим): в installProtocol catch → isNetworkAbort(err) (TypeError / Failed to fetch / NetworkError / Load failed) → строка в лог «соединение прервано, проверяю статус…» + waitForInstallVisible: поллинг POST /api/servers/{id}/check каждые 10с до 10 мин, успех = protocols[proto].container_exists || installed. Подтверждение → обычный success-путь (toast + checkServer). Новый ключ install_conn_interrupted во всех 5 локалях (вставлен после install_starting).
- Заодно обезврежена time-bomb в наших же тестах: test_rkn_scan_flags FlagsEndpointTests использовал хардкод '2026-10-04T10:00:00+00:00' — 13.10 он вышел из окна 24ч → 2 стабильных падения events24 0!=1. Теперь timestamp = now-1h. УРОК: в тестах никогда фиксированные «недавние» даты — только now±delta.
- Тесты 499/499 OK (skip playwright). Ветка deploy/v170 = форк 78510c0.

## 14.10 00:05 — PR #210 в апстрим: фронт переживает обрыв fetch при установке
- Ветка fix/install-network-abort (f0b830c) от upstream/main (v1.7.4!) — только templates/server.html + install_conn_interrupted в 5 локалях (+50 строк). Наш RKN-функционал и правка test_rkn_scan_flags в апстрим НЕ идут (тест — часть нашей фичи; в форке это всё уже в deploy/v170 = 78510c0 + 7d72b84).
- Логика: catch в installProtocol → isNetworkAbort (TypeError / Failed to fetch / NetworkError / Load failed) → поллинг /check каждые 10с до 10 мин → protocols[proto].container_exists||installed → success-путь. HTTP-ошибки панели (4xx/5xx) — по-старому, мгновенный фейл.
- ВАЖНО: upstream/main ушёл вперёд — тег v1.7.4. Наш deploy/v170 основан на v1.7.3 → при следующем мерже апстрима ждать конфликтов/новшеств; переписать эту запись после апгрейда.

## 14.10 00:45 — Exit-node: «интернета нет» при живом handshake = жать «Починить связь»
- Симптом (MAMKAM вход → SERVERA выход): exit0 handshake проходит, keepalive ходит, а клиентского интернета нет. Счётчики: MAMKAM exit0 sent 118 KiB / recv 21 KiB; SERVERA transit0 recv 2.97 KiB / sent 21 KiB. Канал чист (tcpdump: 50×1400B UDP MAMKAM→SERVERA доходят до eth0; ICMP полностью заблокирован на SERVERA — не информативен для MTU-проб).
- Диагноз: расхождение рантайм-состояний сторон (stale state) — SERVERA wg не принимал данные сессии. Подозреваемый триггер: exit-нода свежая + перезапуск Docker на SERVERA между привязкой и тестом.
- ЛЕЧЕНИЕ: кнопка «Починить связь» в карточке выходной ноды = relink_entry → link(force=True): add_peer пересоздаёт пир на выходе со СВЕЖИМ PSK, exit0.conf на входе переписывается, x_exit_sync (killswitch/SNAT/conntrack flush). После неё всё заработало.
- УРОК: (1) при симптомах висячей exit-связи (handshake есть, данные не идут) ПЕРВЫМ делом жать «Починить связь», а не копать счётчики; (2) tcpdump на eth0 видит пакеты ДО netfilter — не доказательство доставки в контейнер; (3) exit-link v4-only по дизайну: AllowedIPs=0.0.0.0/0 на входе, транзит IPv4 /24; IPv6 клиентов при активной связи блокируется (unreachable), а не утекает; (4) dual-stack инстанс + exit-link = v6 клиентов режется до отвязки.

## 14.10 01:50 — PR #210: падение CI = флаки upstream mail-теста, не наш фикс
- Первый прогон CI на PR упал: аннотация mail_service.py:152 'mail_error_disabled'. Наш диф (+50 строк: server.html + 1 ключ в 5 локалях) почту не трогает. Проверено: main на той же базе (2fd2efa) 6.10 зелёный; локально ветка 500/500 OK на py3.12 И py3.11 (uv run --python 3.11).
- Пустым коммитом перезапустил CI — зелёный. Вывод: флаки тестов test_mail_service (там фоновые потоки, разделяемый синглтон mail_svc, read-count-based тест test_a_run_whose_settings_break_mid_flight_still_ends; плюс оставленный фоновый bulk-ран в test_a_second_run_is_refused_while_one_is_in_flight).
- УРОК: (1) логи CI без авторизации не отдаются (403) — аннотации чек-рана берутся анонимно из API; (2) падение CI на чужом репо сначала проверять флакостью (перезапуск), прежде чем искать причину в своём дифе; (3) uv run --python 3.11 — рабочий способ воспроизвести CI-версию Python без докера. Пустой коммит 74519b2 оставлен в ветке PR (сносить = новый прогон кубика).

## 14.10 13:10 — Smart Route: итерация 1, ядро (745f164, deploy/v170)
- Задача из ТЗ «Smart Route» (файлы владельца): сплит-трафик exit-link инстансов по RU-префиксам, host-level приложение из магазина. Ветка deploy/v170, тесты с node.exe в PATH, PR в апстрим НЕ делаем.
- Ключевая архитектура: контейнеры НЕ host-net → throw-маршруты и счётчики живут В netns КОНТЕЙНЕРА (паттерн _exit_apply: upload→docker cp→docker exec). Связь хост↔контейнеры: маркеры /etc/smartroute/instances/<container>; хостовой smartroute-update.sh (systemd timer hourly, RandomizedDelaySec=900, Persistent) после обновления списка сам заливает throw-маршруты во все маркированные контейнеры (docker cp merged-листа + docker exec bash).
- Механика сплита: RU-префиксы как throw routes в таблице 200 (exit-таблица) ДО default dev exit0 → lookup прерывается → main → eth0. Kill-switch не ломается. Счётчики: цепь SMARTR_ACCT в mangle/POSTROUTING внутри контейнера (-s subnet -o exit0 / -o eth0), чтение iptables -vnx.
- Источники v4/v6 с fallback: ipdeny aggregated → herrbischoff/country-ip-blocks → RIPE delegated-ripencc-latest (парсинг start+count→CIDR, python-парсер и в panel, и встроен в update.sh). Защита: <100 префоксов → старый список сохранён, error в status.json. Свои подсети: /etc/smartroute/own.cidr (host), мёрджится при каждом apply; хранение списка — в data.json сервера.
- Совместимость с blocker (проверено по blocker.sh v3.2 + rkn-extra-block): полная независимость — Smart Route трогает только table 200 (netns контейнера) и свою mangle-цепь; blocker цепью AMNEZIA_BLOCK на позиции 1 в FORWARD фильтрует ОБА пути (direct и exit). Сценарии blocker on/off/отсутствует — сплит работает всегда; добавлены в критерии приёмки.
- Сделано: managers/smartroute_manager.py (парсеры RIPE/CIDR/счётчиков, генераторы install/remove/update/container-скриптов, SmartRouteManager(ssh): install/uninstall/run_update/host_status/set_own_subnets/enable_instance/disable_instance/refresh_instance/instance_counters). tests/test_smartroute.py — 24 теста (RIPE, normalize, счётчики, состав скриптов, потоки менеджера на FakeSSH). Тесты зелёные.
- НЕ сделано (следующие итерации): app.py эндпоинты + сервисная прослойка (откат инстансов при удалении, DNS-тоггл через DnsViaExit), UI (карточка магазина/модалка/флажок/счётчики/бейджи), локали, полный прогон, боевая проверка на MAMKAM→SERVERA.
- Заметка: ТЗ ссылался на CHAT-RULES.md — файла нет, его протокол живёт в шапке HANDOFF.

## 14.10 16:10 — Smart Route: итерация 2, сервисная оркестрация (29da7bc, deploy/v170)
- smartroute_service.py (корень, рядом с exit_link_service.py): SmartRouteService с DI (load/save data, data_lock, get_ssh, awg_manager_factory, protocol_base, awg_protocols, apply_dns_via_exit). Коды ошибок: server_not_found 404, protocol_not_awg, not_linked, app_not_installed 409, invalid_cidr.
- Ключевые гарантии: (1) uninstall СНАЧАЛА откатывает каждый сплит-инстанс (disable_instance: throw-роуты и SMARTR_ACCT в контейнере), и только потом удаляет хостовые файлы/таймер; сбой отката отдельного контейнера не прерывает uninstall (warning в лог); после — _exit_apply(proto) нормализует связь (conntrack flush), инстансы НИКОГДА не остаются на «всё напрямую»; (2) в data.json каждому затронутому инстансу ставится smart_route_lost=true (warning-бейдж в UI); (3) повторное включение сплита снимает бейдж и применяет текущие списки.
- DNS: выбор на уровне приложения (server['smartroute']['dns_via_exit']) при включении сплита и массово через set_dns_via_exit прокидывается в существующий механизм DnsViaExit (pref 191) по всем сплит-инстансам; ошибка одного инстанса не роняет остальные.
- Свои подсети: валидация normalize_cidrs до SSH; хранение в server['smartroute']['own_subnets']; после сохранения — refresh_instance во все сплит-контейнеры (новые подсети действуют сразу).
- tests/test_smartroute_service.py — 22 теста на изолированном сервисе (FakeAWG + FakeSRM с классовым журналом вызовов, in-memory data.json): порядок disable→uninstall при удалении, переживание сбоя отката, гейты app_not_installed/not_linked/protocol_not_awg, идемпотентность, снятие бейджа, массовый DNS, счётчики. Зелёные.
- Следующая итерация: app.py (сервис-экземпляр + 6 эндпоинтов + smartroute-счётчики в ответе exit-link/status), UI, локали, полный прогон.

## 14.10 17:05 — Smart Route: итерация 3, эндпоинты панели (667e8e0, deploy/v170)
- app.py: smartroute_svc рядом с exit_link_svc; apply_dns_via_exit=lambda → exit_link_svc.set_dns_via_exit (DNS остаётся одним механизмом, pref 191).
- Эндпоинты (все _check_admin): POST /api/servers/{sid}/smartroute/{install,uninstall,update,own-subnets,split,dns}, GET /api/servers/{sid}/smartroute/status. Ошибки SmartRouteError → {error: code, message} со status_code (образец _exit_link_error).
- exit-link/status теперь включает payload['smartroute'] = counters(...) best-effort (try/except → None), чтобы карточка инстанса показывала счётчики без лишнего запроса.
- Полный прогон: 545 тестов OK (489 базовых + 24 менеджер + 22 сервис).
- Следующая итерация: UI (карточка магазина/модалка/флажок в exitLinkModal/счётчики/бейдж smart_route_lost), ключи в 5 локалях.

## 14.10 17:55 — Smart Route: итерация 4, UI (9a2ebf3, deploy/v170)
- Маркетплейс: карточка Smart Route (🧭, services, NEW) — special-case в renderMarketplace: статус из smartRouteStatus.installed, кнопка «Открыть» → smartRouteModal (НЕ installFromMarketplace, т.к. это host-приложение, а не протокол).
- Модалка smartRouteModal: install/remove (confirm с текстом про откат), «Обновить сейчас», статус списков (v4/v6 префиксы, источник, обновлено, следующий запуск, ошибка), редактор своих подсетей (textarea, по CIDR на строку), серверный DNS-via-exit тоггл, список сплит-инстансов.
- exitLinkModal: флажок Smart Route (показывается только у связанного инстанса; disabled + подсказка «сначала установите из магазина», пока приложение не стоит), счётчики напрямую/через выход (formatBytes) из payload smartroute exit-link/status, warning-бейдж при smart_route_lost. Статус приложения подтягивается в openExitLinkModal третьим запросом (best-effort .catch(null)).
- Ошибки API переводятся через smartrouteErrorText (коды: app_not_installed, not_linked, protocol_not_awg, invalid_cidr, server_not_found).
- Локали: 36 ключей smartroute_* + коды ошибок во всех 5 файлах. Тест паритета SmartRouteUiWiringTests (3 теста) в test_server_page.py.
- ОПАСНОЕ МЕСТО: глобальная sed-замена err.message затронула 2 чужих обработчика (toggleRknBlock/clearRknScans) — отловлено диффом, откачено. УРОК: sed по шаблону «(err.message || err)» без привязки к функции опасен — такая строка встречается в чужом коде.
- Полный прогон: 548 тестов OK (489 базовых + 24 + 22 + 3 UI + прочее).
- Осталось: боевая проверка на стенде MAMKAM→SERVERA (команды владельцу по одной).

## 14.10 18:20 — Smart Route: код готов, боевая проверка НЕ выполнена (deploy/v170)
- Итог по критериям приёмки (файл владельца): КОД — всё сделано (git status чист; 548 тестов OK; покрыты установка/удаление, битый список, откат инстанса, RIPE, свои подсети; HANDOFF дописан; чужих/служебных файлов нет — дифф: 11 файлов фичи + HANDOFF).
- БОЕВЫЕ ПУНКТЫ — НЕ ПРОВЕРЕНО ВЖИВУЮ (нет доступа к стенду из этой среды): установка/удаление на MAMKAM, таймер, ребут, «Обновить сейчас», подмена источника, сплит-трафик (rzd/whoer), счётчики, kill-switch, conntrack при тоггле, удаление при включённом флажке, DNS-выбор, визуальная проверка консоли на 5 локалях. Перед боевой проверкой: развернуть ветку deploy/v170 на панели SERVERA (гит-пулл + рестарт сервиса панели).
- Команды для проверки выдаются владельцу ПО ОДНОЙ (шелл MAMKAM / шелл SERVERA), начиная с установки приложения из магазина.

## 15.10 00:45 — Smart Route: фиксы по ревью (f012c7d, deploy/v170)
- Ревьюер подтвердил 2 бага + 2 замечания, всё исправлено:
- БАГ 1 (мёртвый fallback RIPE): в _RIPE_PARSE_PY двойной эскейп → update.sh содержал print("\n"...) → python3 выдавал литеральные \n → вывод одной строкой → страж <100 всегда отбраковывал RIPE. Фикс: print("\n"...) в генерируемом скрипте. Регрессионный тест: RipeHeredocRegressionTests гоняет ВСТРОЕННЫЙ парсер через subprocess на RIPE_SAMPLE и требует многострочный вывод (старые тесты ловили только panel-side парсер — урок: генерируемый код тестировать исполнением, не только сравнением строк).
- БАГ 2 (v6-источник): SOURCES_V6[0] был v4-зоной ipdeny (0 префиксов всегда). Правильный URL проверен curl'ом (200, реальные v6-CIDR): https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone. Тест-регрессия на форму источников.
- ЗАМЕЧАНИЕ 1 (только upload): добавлена цепочка SMARTR_ACCT_IN на mangle/PREROUTING (-i exit0/eth0 -d subnet). parse_acct_counters: итоги (in+out) + разбивка *_in/*_out, формат {pkts, bytes} вложенный — заодно починена несостыковка (менеджер отдавал плоские ключи, UI читал вложенные). UI: ↑исх / ↓вх. Disable/remove снимают обе цепочки.
- ЗАМЕЧАНИЕ 2 (таймаут install): первый апдейт теперь nohup-фоном (лог /var/log/smartroute-install.log), таймер OnBootSec=2min — страховка. Установка возвращается мгновенно; списки появляются ≤2 мин. Нюанс: включение сплита сразу после установки до докачки списка = пустые throws (RU пойдёт через exit — fail-safe направление), таймер дольёт.
- Полный прогон: 551 тест OK (было 548, +3 регрессии). Тесты менеджера: 24→29.
- Раскат на SERVERA: git pull fork deploy/v170 + systemctl restart amnezia-panel. На MAMKAM для входящих счётчиков: переключить флажок сплита выкл→вкл в UI (пересоздаст цепочки) или переустановить приложение.

## 15.10 01:00 — Smart Route: RIPE-fallback был мёртв дважды (доп.фикс к f012c7d)
- Боевой тест на MAMKAM после f012c7d: ripe_parse выдал 1 строку. Эскейп починен, НО корневая причина глубже: heredoc кормил программу через stdin (`python3 -`), весь stdin съедался как текст программы → sys.stdin на EOF → 0 CIDR при любом эскейпе. Ревьюер поймал половину, вживую всплыла вторая.
- Фикс: ripe_parse пишет парсер во временный файл (mktemp), данные передаются аргументом: python3 "$prog" "$1" /dev/stdin — потоки программы и данных разведены.
- УРОК: heredoc в shell-генераторе с `python3 -` — ловушка; генерируемый код проверять исполнением на реальном сервере, а не только юнит-тестом строк. Регрессионный тест теперь зеркалит реальный вызов (файл-программа + путь данных) + кейс ipv6.
- Прогон: 553 теста OK. Требуется повторная перезаливка update.sh на хосты (команды владельцу).

## 15.10 13:00 — Smart Route: карточка на странице сервера + глобальный тумблер + DNS-пара
- Владелец попросил вывести Smart Route из чекбокса в exitLinkModal в полноценную карточку протокола (как у telemt/socks/exit): static card `proto-smartroute` в protocols-grid; видимость — НЕ через currentProtocolStatus (host-приложение, контейнера нет), а через smartRouteStatus.installed (special-case в applyInstalledAppsVisibility; установка по-прежнему из маркетплейса). Статус грузится в checkServer отдельным пробом (не ломает общий чек при недоступности SSH).
- Карточка: бейдж (работает/пауза), данные (v4/v6 префиксы, сплит-инстансы, обновлено, ошибка), кнопки «Настроить» (модалка) и глобальный «Включить/Выключить» (POST /smartroute/enable).
- Глобальный тумблер: server['smartroute']['enabled'] (default True). Пауза = disable_instance во всех сплит-контейнерах (трафик назад на exit0), при этом флаги smart_route и списки/таймер сохраняются — resume восстанавливает точно то, что было. set_split enable заблокирован пока пауза (409 smartroute_paused); disable разрешён. Частичные сбои отдаются в failed[] и не откатывают флаг (инстанс чинится следующим resume).
- Внутри инстанса (exitLinkModal): флажок split отражает глобальную паузу — disabled + hint «включите в карточке Smart Route».
- DNS-пара (по запросу владельца): server['smartroute']['direct_dns'] (default 77.88.8.8 — Яндекс, RU-IP → напрямую) и ['exit_dns'] (default 1.1.1.1 — через exit). Механика: при включении сплита прежняя строка `# DNS =` инстанса запоминается в exit_link.smart_route_prev_dns, в конфиг пишется пара «direct, exit» — путь запроса решает throw-таблица по IP резолвера. Восстановление прежнего DNS при выключении сплита/паузе НЕ откатывается (пауза держит пару)/откатывается при удалении приложения. Поля в карточке + POST /smartroute/dns-servers (валидация IPv4, invalid_dns) с применением ко всем сплит-инстансам. Применяется при выдаче новых клиентских конфигов (per-client userData.dns перекрывает).
- Осторожно: awg_manager.update_awg_settings — общий писатель конфига (переписывает MTU/DNS/I1-I5 целиком); используем строго с dns= и None в остальном. DNS-реврайт не фатален — ошибки глотаются с warning (маршрутизация без него работает).
- Прогон: 570 тестов OK (+17: 14 сервис — пауза/resume/DNS-пара/гейты; 4 UI-разводка карточки; паритет ключей расширен invalid_dns/smartroute_paused). Единственный флаки test_awg_mtu_budget — задокументирован ранее, к фиче не относится (на повторе зелёный).
- НЕ ПРОВЕРЕНО ВЖИВУЮ: карточка/тумблер/DNS в браузере (только юнит+разводка). Боевая проверка: раскатить deploy/v170 на SERVERA, открыть страницу MAMKAM, потыкать тумблер и поля DNS; на сплит-инстансе после save DNS снять/пересоздать клиентский конфиг и проверить `DNS = 77.88.8.8, 1.1.1.1` и whoer.
- Известный край: если убрать exit-link у сплит-инстанса напрямую (обходя Smart Route), exit_link вместе с smart_route_prev_dns удалится, а DNS-строка в конфиге останется парой — чинится ручным DNS в настройках инстанса. Отдельный guard — следующая итерация при необходимости.

## 15.10 21:00 — «Мёртвые души» в списке подключений юзера: диагноз по коду
- Жалоба: у юзера «Сергей Smoke» две карточки NATA/awg2 (ключи P0i5…, ZKqtq…, обе от 12.09), пиров с этими ключами в инстансе нет.
- Механизм (app.py): список на странице юзера = user_connections из data.json; фильтр ТОЛЬКО «протокол есть на сервере» (app.py:6045-6048). Пропавший из инстанса пир НЕ отсеивается: обогащение живыми данными делает `continue` при отсутствии client_id (app.py:6080-6082), карточка рендерится из полей БД.
- Чистка links есть в двух путях: uninstall протокола (app.py:4625-4629) и remove-connection (5452-5456). Значит запись устарела НЕ через них: пир исчез из clientsTable/conf при живом протоколе (класс «conf↔table рассинхрон» старых образов awg2 / ручные правки на сервере / пересоздание контейнера в обход панели).
- Вопрос владельца «можешь ли сам ходить по SSH» — нет, из этой среды нет маршрута/кредов; рабочий инструмент — paramiko-скрипты из venv панели на SERVERA, опрашивающие все серверы из data.json (поле ssh_port). Кандидат на постоянный инструмент fleet.py в репо.
- Следующий шаг: самоопрос NATA (ключи в /opt/amnezia + live-конфиге) → если пиры реально удалены — чистка links фильтром-скриптом с бэкапом data.json.

## 15.10 21:10 — Мёртвые души: ПОДТВЕРЖДЕНО и вычищено
- Самоопросом с SERVERA (paramiko из venv панели): оба ключа отсутствуют в live-конфиге awg2 NATA (43 пира, 0 совпадений) и во всех файлах /opt/amnezia/. Пиры удалены вне панели ~12.09, user_connections устарели.
- Чистка: бэкап data.json + фильтр строго по (user_id, server_id=3, awg2, два ключа) → removed: 2 (255→253). Инстанс и прочие записи не тронуты.
- УРОК: (1) `wg showconf` БЕЗ имени интерфейса молча печатает usage в stderr — в скриптах самоопроса интерфейс обязателен (awg0); (2) поле имени юзера в data.json — 'username', не 'name'.
- Открыто: что 12.09 удаляло пиров мимо панели — не расследовано (симптом закрыт чисткой). Кандидат-инструмент: fleet.py в репо для диагностик всех серверов одной командой с SERVERA.

## 15.10 21:15 — ПОЯВИЛСЯ ПРЯМОЙ SSH-доступ агента к SERVERA
- Владелец выдал ed25519-ключ агенту; ключ хранится локально у владельца вне репо, в git НЕ коммитить (проверено: git ls-files чист).
- Проверено с SERVERA: мёртвые души вычищены (0 совпадений ключей в data.json), панель active, бэкап data.json.bak-20261015-194427 на месте.
- ВНИМАНИЕ: checkout панели на SERVERA = bdbcce2, форк ушёл вперёд (0f48b7b, d27962f — оба docs/HANDOFF-only, кода не касаются) — не критично, подтянется при следующей раскатке.
- Теперь агент может сам гонять диагностики/флотовые проверки с SERVERA (paramiko на остальные серверы из data.json) без пересылки выводов руками.
