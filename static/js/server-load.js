/* ============================================================
   Server load — live load cards for the servers list page.
   Reads the server cards already on the page, asks
   POST /api/servers/<idx>/stats for each one and refreshes the
   cards while the modal stays open. No external dependencies.
   ============================================================ */
(function () {
    'use strict';

    var MODAL_ID = 'serverLoadModal';
    var GRID_ID = 'serverLoadGrid';
    var AUTO_REFRESH_MS = 15000;
    var CONCURRENCY = 4;
    var SPARK_LIMIT = 24;
    var SPARK_W = 300;
    var SPARK_H = 40;
    var SPARK_PAD = 3;

    /* Last-resort English strings: used only when a translation key
       has not been added to translations/*.json yet, so the modal
       never shows a bare "server_load_*" identifier. */
    var FALLBACK = {
        button: 'Show load',
        title: 'Server load',
        refresh: 'Refresh',
        updated: 'updated',
        auto: 'Refreshes every 15 seconds while the window is open',
        uptime: 'Uptime',
        offline: 'offline',
        loading: 'Loading…',
        critical: 'critical',
        disk_low: 'Disk almost full',
        ram_high: 'RAM almost full',
        cpu_high: 'CPU overloaded',
        error: 'Could not load stats',
        empty: 'No servers to show',
        retry: 'Retry'
    };

    var state = {
        servers: [],
        samples: {},
        refreshing: false,
        inflight: null,
        queued: false,
        timer: null,
        lastUpdate: 0
    };

    var LANG = String(document.documentElement.lang || 'en').toLowerCase();
    var DECIMAL = /^(ru|fr|fa)/.test(LANG) ? ',' : '.';

    /* ---------- i18n + formatting helpers ---------- */

    function t(key) {
        var dict = window.SERVER_LOAD_I18N || {};
        var value = dict[key];
        if (typeof value === 'string' && value && value !== 'server_load_' + key) {
            return value;
        }
        return FALLBACK[key] || value || key;
    }

    /* The static labels come from _('server_load_*'). Until those keys are
       added to translations/*.json the server returns the key itself, so use
       the fallback dictionary instead of showing a bare identifier. Once the
       keys exist the translated text no longer matches and is left alone. */
    function hydrateLabels() {
        var nodes = document.querySelectorAll('[data-i18n]');
        Array.prototype.forEach.call(nodes, function (node) {
            var key = String(node.getAttribute('data-i18n') || '').replace(/^server_load_/, '');
            if (key && node.textContent.trim() === 'server_load_' + key) {
                node.textContent = t(key);
            }
        });
    }

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function toNumber(value) {
        var n = Number(value);
        return isFinite(n) ? n : 0;
    }

    function clampPct(value) {
        return Math.max(0, Math.min(100, toNumber(value)));
    }

    function decimalPoint(text) {
        return DECIMAL === ',' ? text.replace('.', ',') : text;
    }

    function formatBytes(bytes) {
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var n = Math.max(0, toNumber(bytes));
        var i = 0;
        while (n >= 1024 && i < units.length - 1) {
            n /= 1024;
            i += 1;
        }
        return decimalPoint(n.toFixed(1)) + ' ' + units[i];
    }

    function formatPctValue(value) {
        var n = clampPct(value);
        var text = (Math.round(n * 10) % 10 === 0) ? String(Math.round(n)) : n.toFixed(1);
        return decimalPoint(text);
    }

    function formatPct(value) {
        return formatPctValue(value) + '%';
    }

    function formatRate(bytes) {
        return formatBytes(bytes) + '/s';
    }

    function pad2(value) {
        return (value < 10 ? '0' : '') + value;
    }

    function formatClock(date) {
        return pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds());
    }

    /* ---------- DOM plumbing ---------- */

    function modalEl() {
        return document.getElementById(MODAL_ID);
    }

    function modalActive() {
        var modal = modalEl();
        return !!(modal && modal.classList.contains('active'));
    }

    function cardEl(server) {
        return document.getElementById('server-load-card-' + server.idx);
    }

    function field(card, name) {
        return card ? card.querySelector('[data-f="' + name + '"]') : null;
    }

    function setText(card, name, value) {
        var el = field(card, name);
        if (el) el.textContent = value;
    }

    function collectServers() {
        var cards = document.querySelectorAll('#serverGrid .server-card');
        return Array.prototype.map.call(cards, function (card) {
            return {
                idx: card.dataset.idx,
                name: card.dataset.name || '',
                host: card.dataset.host || '',
                port: card.dataset.port || '',
                uid: card.dataset.uid || ''
            };
        });
    }

    function sampleFor(idx) {
        if (!state.samples[idx]) {
            state.samples[idx] = {cpu: [], last: null, net: null, failed: false, busy: false};
        }
        return state.samples[idx];
    }

    /* ---------- Card markup (server strings escaped) ---------- */

    function rowMarkup(kind, label) {
        return '<div class="server-load-row" data-f="' + kind + 'Row">'
            + '<div class="server-load-row__top">'
            + '<span class="server-load-row__label">' + label + '</span>'
            + '<span class="server-load-row__pct" data-f="' + kind + 'Pct">--</span>'
            + '</div>'
            + '<div class="server-load-bar"><span class="server-load-bar__fill" data-f="' + kind + 'Bar"></span></div>'
            + '<div class="server-load-row__meta" data-f="' + kind + 'Meta">--</div>'
            + '</div>';
    }

    function cardMarkup(server) {
        var host = esc(server.host);
        if (server.port) host += ':' + esc(server.port);
        return '<div class="server-load-card__head">'
            + '<span class="server-load-card__dot" aria-hidden="true"></span>'
            + '<span class="server-load-card__name" title="' + host + '">' + esc(server.name || server.host) + '</span>'
            + '<span class="server-load-badge" data-f="badge" hidden></span>'
            + '</div>'
            + '<div class="server-load-card__host">' + host + '</div>'
            + '<div class="server-load-cpu" data-f="cpuBlock">'
            + '<div class="server-load-cpu__fig">'
            + '<span class="server-load-cpu__value" data-f="cpu">--</span>'
            + '<span class="server-load-cpu__unit">%</span>'
            + '</div>'
            + '<svg class="server-load-cpu__spark" viewBox="0 0 300 40" preserveAspectRatio="none" aria-hidden="true">'
            + '<polygon class="server-load-spark__area" data-f="sparkArea" points=""></polygon>'
            + '<polyline class="server-load-spark__line" data-f="sparkLine" points=""></polyline>'
            + '</svg>'
            + '</div>'
            + rowMarkup('ram', 'RAM')
            + rowMarkup('disk', 'Disk')
            + '<div class="server-load-io">'
            + '<span class="server-load-io__item"><span class="server-load-io__arrow">&#8595;</span><span data-f="rx">--</span></span>'
            + '<span class="server-load-io__item"><span class="server-load-io__arrow">&#8593;</span><span data-f="tx">--</span></span>'
            + '</div>'
            + '<div class="server-load-alerts" data-f="alerts" hidden></div>'
            + '<div class="server-load-error" data-f="errorBox" hidden>'
            + '<span data-f="errorText">' + esc(t('offline')) + '</span>'
            + '<button type="button" class="btn btn-secondary btn-sm" data-role="retry">' + esc(t('retry')) + '</button>'
            + '</div>'
            + '<div class="server-load-card__foot">'
            + '<span class="server-load-card__clock" data-f="clock">--:--:--</span>'
            + '<span class="server-load-card__uptime" data-f="uptime"></span>'
            + '</div>';
    }

    function skeletonMarkup() {
        return '<div class="server-load-skel is-title"></div>'
            + '<div class="server-load-skel is-sub"></div>'
            + '<div class="server-load-skel is-cpu"></div>'
            + '<div class="server-load-skel is-row"></div>'
            + '<div class="server-load-skel is-row"></div>'
            + '<div class="server-load-skel is-foot"></div>';
    }

    function buildGrid() {
        var grid = document.getElementById(GRID_ID);
        if (!grid) return;
        grid.textContent = '';
        if (!state.servers.length) {
            var empty = document.createElement('div');
            empty.className = 'server-load-empty';
            empty.textContent = t('empty');
            grid.appendChild(empty);
            return;
        }
        state.servers.forEach(function (server) {
            var card = document.createElement('article');
            card.className = 'server-load-card is-loading';
            card.id = 'server-load-card-' + server.idx;
            card.dataset.idx = server.idx;
            card.innerHTML = skeletonMarkup();
            grid.appendChild(card);
        });
    }

    function mountCard(server) {
        var card = cardEl(server);
        if (!card || card.dataset.mounted === '1') return card;
        card.innerHTML = cardMarkup(server);
        card.dataset.mounted = '1';
        card.classList.remove('is-loading');
        var retry = card.querySelector('[data-role="retry"]');
        if (retry) {
            retry.addEventListener('click', function () {
                fetchServer(server);
            });
        }
        return card;
    }

    /* ---------- Rendering ---------- */

    function renderSpark(card, values) {
        var line = field(card, 'sparkLine');
        var area = field(card, 'sparkArea');
        if (!line || !area) return;
        if (!values || !values.length) {
            line.setAttribute('points', '');
            area.setAttribute('points', '');
            return;
        }
        var peak = values.reduce(function (max, value) {
            return Math.max(max, value);
        }, 0);
        var top = Math.max(20, Math.min(100, Math.ceil(peak / 10) * 10));
        var usable = SPARK_H - SPARK_PAD * 2;
        var points;
        if (values.length === 1) {
            var flat = SPARK_H - SPARK_PAD - (Math.min(values[0], top) / top) * usable;
            points = [[0, flat], [SPARK_W, flat]];
        } else {
            points = values.map(function (value, index) {
                var x = (index / (values.length - 1)) * SPARK_W;
                var y = SPARK_H - SPARK_PAD - (Math.min(value, top) / top) * usable;
                return [x, y];
            });
        }
        var coords = points.map(function (point) {
            return point[0].toFixed(1) + ',' + point[1].toFixed(1);
        }).join(' ');
        line.setAttribute('points', coords);
        area.setAttribute('points', coords + ' ' + SPARK_W + ',' + SPARK_H + ' 0,' + SPARK_H);
    }

    function setRow(card, kind, pct, used, total) {
        setText(card, kind + 'Pct', formatPct(pct));
        setText(card, kind + 'Meta', formatBytes(used) + ' / ' + formatBytes(total));
        var bar = field(card, kind + 'Bar');
        if (bar) bar.style.width = clampPct(pct) + '%';
        var row = field(card, kind + 'Row');
        if (row) {
            row.classList.toggle('is-warning', pct >= 75 && pct < 90);
            row.classList.toggle('is-critical', pct >= 90);
        }
    }

    function renderAlerts(card, alerts) {
        var box = field(card, 'alerts');
        if (!box) return;
        box.textContent = '';
        if (!alerts.length) {
            box.hidden = true;
            return;
        }
        alerts.forEach(function (alert) {
            var chip = document.createElement('span');
            chip.className = 'server-load-alert' + (alert.danger ? ' is-danger' : '');
            chip.textContent = alert.text;
            box.appendChild(chip);
        });
        box.hidden = false;
    }

    function applySample(server, sample, card, data) {
        card = mountCard(server) || card;
        if (!card) return;

        var cpuPct = clampPct(data.cpu);
        var ramPct = clampPct(data.ram_percent);
        var diskPct = clampPct(data.disk_percent);
        var now = Date.now();

        sample.cpu.push(cpuPct);
        if (sample.cpu.length > SPARK_LIMIT) sample.cpu.shift();

        var rx = Math.max(0, toNumber(data.net_rx));
        var tx = Math.max(0, toNumber(data.net_tx));
        var rate = null;
        if (sample.net && now > sample.net.at && rx >= sample.net.rx && tx >= sample.net.tx) {
            var seconds = (now - sample.net.at) / 1000;
            rate = {rx: (rx - sample.net.rx) / seconds, tx: (tx - sample.net.tx) / seconds};
        }
        sample.net = {rx: rx, tx: tx, at: now};

        var critical = cpuPct >= 90 || ramPct >= 90 || diskPct >= 90;
        card.classList.remove('is-loading', 'is-offline', 'is-stale');
        card.classList.toggle('is-critical', critical);

        setText(card, 'cpu', formatPctValue(cpuPct));
        renderSpark(card, sample.cpu);

        var cpuBlock = field(card, 'cpuBlock');
        if (cpuBlock) {
            cpuBlock.classList.toggle('is-warning', cpuPct >= 75 && cpuPct < 90);
            cpuBlock.classList.toggle('is-critical', cpuPct >= 90);
        }

        setRow(card, 'ram', ramPct, data.ram_used, data.ram_total);
        setRow(card, 'disk', diskPct, data.disk_used, data.disk_total);

        setText(card, 'rx', rate ? formatRate(rate.rx) : formatBytes(rx));
        setText(card, 'tx', rate ? formatRate(rate.tx) : formatBytes(tx));

        var alerts = [];
        if (cpuPct >= 90) alerts.push({text: t('cpu_high'), danger: true});
        if (ramPct >= 90) alerts.push({text: t('ram_high'), danger: true});
        if (diskPct >= 90) alerts.push({text: t('disk_low'), danger: true});
        renderAlerts(card, alerts);

        var badge = field(card, 'badge');
        if (badge) {
            badge.textContent = t('critical');
            badge.hidden = !critical;
        }

        var errorBox = field(card, 'errorBox');
        if (errorBox) errorBox.hidden = true;

        setText(card, 'clock', formatClock(new Date(now)));
        setText(card, 'uptime', data.uptime ? String(data.uptime) : '');
    }

    function applyError(server, sample, card) {
        card = mountCard(server) || card;
        if (!card) return;
        card.classList.remove('is-loading', 'is-critical');
        card.classList.add('is-offline');
        card.classList.toggle('is-stale', !!sample.last);
        var box = field(card, 'errorBox');
        if (box) {
            box.hidden = false;
            box.title = t('error');
        }
        setText(card, 'errorText', t('offline'));
        var badge = field(card, 'badge');
        if (badge) badge.hidden = true;
    }

    /* ---------- Data fetching ---------- */

    function fetchServer(server) {
        var sample = sampleFor(server.idx);
        if (sample.busy) return Promise.resolve();
        sample.busy = true;
        var card = cardEl(server);
        return Promise.resolve()
            .then(function () {
                return apiCall('/api/servers/' + encodeURIComponent(server.idx) + '/stats', 'POST');
            })
            .then(function (data) {
                if (!data || typeof data !== 'object') throw new Error('unexpected stats payload');
                sample.last = data;
                sample.failed = false;
                state.lastUpdate = Date.now();
                applySample(server, sample, card, data);
            })
            .catch(function () {
                sample.failed = true;
                applyError(server, sample, card);
            })
            .then(function () {
                sample.busy = false;
                updateSubtitle();
            });
    }

    function refreshAll() {
        if (state.refreshing) {
            state.queued = true;
            return state.inflight || Promise.resolve();
        }
        if (!state.servers.length) {
            updateSubtitle();
            return Promise.resolve();
        }
        state.refreshing = true;
        var queue = state.servers.slice();
        var workers = [];
        var count = Math.min(CONCURRENCY, queue.length);

        function worker() {
            if (!queue.length) return Promise.resolve();
            return fetchServer(queue.shift()).then(worker);
        }

        for (var i = 0; i < count; i += 1) workers.push(worker());

        function finish() {
            state.refreshing = false;
            state.inflight = null;
            updateSubtitle();
            if (state.queued) {
                state.queued = false;
                refreshAll();
            }
        }

        state.inflight = Promise.all(workers).then(finish, finish);
        return state.inflight;
    }

    function updateSubtitle() {
        var el = document.getElementById('serverLoadSubtitle');
        if (!el) return;
        var issues = 0;
        state.servers.forEach(function (server) {
            var sample = state.samples[server.idx];
            if (!sample) return;
            if (sample.failed) {
                issues += 1;
                return;
            }
            var data = sample.last;
            if (data && (toNumber(data.cpu) >= 90 || toNumber(data.ram_percent) >= 90
                || toNumber(data.disk_percent) >= 90)) {
                issues += 1;
            }
        });
        var tail = state.lastUpdate
            ? t('updated') + ' ' + formatClock(new Date(state.lastUpdate))
            : t('loading');
        el.textContent = state.servers.length + ' · ' + issues + ' ⚠ · ' + tail;
    }

    /* ---------- Auto refresh (only while the modal is open) ---------- */

    function startTimer() {
        if (state.timer !== null) return;
        state.timer = window.setInterval(function () {
            if (!modalActive() || document.hidden) return;
            refreshAll();
        }, AUTO_REFRESH_MS);
    }

    function stopTimer() {
        if (state.timer === null) return;
        window.clearInterval(state.timer);
        state.timer = null;
    }

    function syncTimer() {
        if (modalActive() && !document.hidden) startTimer();
        else stopTimer();
    }

    function onVisibilityChange() {
        if (document.hidden) {
            stopTimer();
            return;
        }
        if (modalActive()) {
            refreshAll();
            startTimer();
        }
    }

    /* ---------- Public API ---------- */

    function openServerLoad() {
        state.servers = collectServers();
        state.samples = {};
        state.lastUpdate = 0;
        buildGrid();
        updateSubtitle();
        if (typeof window.openModal === 'function') window.openModal(MODAL_ID);
        else if (modalEl()) modalEl().classList.add('active');
        syncTimer();
        refreshAll();
    }

    function closeServerLoad() {
        if (typeof window.closeModal === 'function') window.closeModal(MODAL_ID);
        else if (modalEl()) modalEl().classList.remove('active');
        stopTimer();
    }

    function init() {
        hydrateLabels();
        var modal = modalEl();
        if (modal && window.MutationObserver) {
            new MutationObserver(syncTimer).observe(modal, {
                attributes: true,
                attributeFilter: ['class']
            });
        }
        document.addEventListener('visibilitychange', onVisibilityChange);
        window.openServerLoad = openServerLoad;
        window.closeServerLoad = closeServerLoad;
        window.refreshServerLoad = refreshAll;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
