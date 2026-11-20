/* Харнесс плагина «Защита от торрентов».
 *
 * Исполняет НАСТОЯЩИЙ static/js/torrent-plugin.js в vm-контексте с
 * минимальными DOM-заглушками: проверяет панель, бейдж, запросы установки и
 * режимов, метки в строках подключений и отсутствие inline-стилей/эмодзи.
 *
 * Запуск: node tests/js/torrent_plugin.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const SOURCE_PATH = process.env.TP_SCRIPT ||
    path.join(ROOT, 'static', 'js', 'torrent-plugin.js');
const SOURCE = fs.readFileSync(SOURCE_PATH, 'utf8');

const failures = [];
let checksRun = 0;
function check(name, condition, detail) {
    checksRun += 1;
    if (condition) return;
    failures.push(name + (detail ? ' — ' + detail : ''));
}
function eq(name, actual, expected) {
    check(name, JSON.stringify(actual) === JSON.stringify(expected),
        'получено ' + JSON.stringify(actual) + ', ожидалось ' + JSON.stringify(expected));
}

const ICONS = {
    trash: '<path d="M3 6h18"/>',
    refresh: '<path d="M3 12a9 9 0 0 1 9-9"/>',
    save: '<path d="M15.2 3a2 2 0 0 1 1.4.6"/>',
    eraser: '<path d="m7 21-4.3-4.3"/>',
};

function node(id) {
    const classes = new Set();
    const attrs = {};
    const listeners = {};
    const item = {
        id,
        tagName: 'DIV',
        innerHTML: '',
        textContent: '',
        className: '',
        title: '',
        value: '',
        checked: false,
        disabled: false,
        classList: {
            contains: c => classes.has(c),
            add: c => classes.add(c),
            remove: c => classes.delete(c),
            toggle: (c, on) => {
                if (on) classes.add(c); else classes.delete(c);
                return !!on;
            },
        },
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        fire(type, extra) {
            (listeners[type] || []).forEach(fn => fn(Object.assign(
                { target: item, preventDefault() {}, closest: () => null }, extra)));
        },
        getAttribute(name) { return attrs[name] === undefined ? null : attrs[name]; },
        setAttribute(name, value) { attrs[name] = String(value); },
        insertAdjacentHTML(_where, html) { item.inserted = (item.inserted || '') + html; },
        querySelector(selector) {
            if (selector === '.client-meta') return item.meta || null;
            return null;
        },
        closest() { return null; },
    };
    return item;
}

function createEnv(options) {
    const opts = options || {};
    const nodes = new Map();
    const calls = [];
    const toasts = [];
    const docListeners = {};

    function byId(id) {
        if (!nodes.has(id)) nodes.set(id, node(id));
        return nodes.get(id);
    }

    const document = {
        getElementById: byId,
        addEventListener(type, fn) { (docListeners[type] = docListeners[type] || []).push(fn); },
        fire(type, target) {
            (docListeners[type] || []).forEach(fn => fn({
                target: Object.assign(Object.create(target), {
                    closest: selector => (selector === '[data-tp-clear]' ? target : null),
                }),
            }));
        },
        querySelectorAll(selector) {
            if (selector === '[data-tp-proto]') {
                const html = byId('torrentPluginContent').innerHTML;
                const out = [];
                const pattern = /data-tp-proto="([^"]+)"/g;
                let match;
                while ((match = pattern.exec(html)) !== null) {
                    const id = 'mode-' + match[1];
                    let select = nodes.get(id);
                    if (!select) {
                        select = node(id);
                        select.setAttribute('data-tp-proto', match[1]);
                        select.value = 'on';
                        nodes.set(id, select);
                    }
                    out.push(select);
                }
                return out;
            }
            if (selector === '.tp-mark') return [];
            return [];
        },
        createElement: () => node('created'),
    };

    const sandbox = {
        console,
        document,
        window: {},
        SERVER_ID: 3,
        CSS: { escape: value => String(value) },
        confirm: () => (opts.confirm === undefined ? true : opts.confirm),
        setInterval: () => 1,
        clearInterval: () => {},
        Date,
        Number,
        String,
        Object,
        Array,
        JSON,
        _: key => {
            if (key === 'torrent_activity_text') return '{when} {sig} {count}';
            if (key === 'tp_marks_cleared') return '{count}';
            if (key === 'tp_health_peers') return 'peers: {count}';
            return key;
        },
        apiCall(url, method, body) {
            calls.push({ url, method: method || 'GET', body });
            return Promise.resolve(opts.response ? opts.response(url, method, body) : {});
        },
        showToast(message, kind) { toasts.push({ message, kind }); },
        openModal(id) { byId(id).classList.add('active'); },
        closeModal(id) { byId(id).classList.remove('active'); },
        escapeHtml: value => String(value),
    };
    sandbox.window = sandbox;
    sandbox.window.TORRENT_PLUGIN_STATE = opts.state || {
        id: 'torrent_guard', installed: true, enabled: true, supported: true,
        state: 'on', protocols: ['awg3'], modes: { awg3: 'on' },
        settings: { default_mode: 'on', include_wireguard: true,
                    marks_ttl_days: 30, clear_marks_on_disable: false,
                    poll_seconds: 60 },
        health: { state: 'ok', protocols: { awg3: { ok: true, ts: 1760000000, peers: 3 } } },
        events: 2, last_at: 1760000000,
    };
    sandbox.window.TORRENT_PLUGIN_ICONS = ICONS;
    byId('torrentPluginModal');
    byId('torrentPluginContent');
    byId('torrentPluginBtn');

    vm.createContext(sandbox);
    vm.runInContext(SOURCE, sandbox, { filename: 'torrent-plugin.js' });
    return { sandbox, document, nodes, calls, toasts, byId };
}

function renderHtml(env) {
    return env.byId('torrentPluginContent').innerHTML;
}

async function flush() {
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
}

async function run() {
    // 1. Панель: бейдж состояния, мастер-выключатель, настройки, метки.
    const env = createEnv();
    env.sandbox.TorrentPlugin.open();
    await flush();
    const html = renderHtml(env);
    check('панель отрисована', html.includes('tp-stack'));
    check('бейдж состояния', html.includes('tp_state_on'));
    check('мастер-выключатель', html.includes('id="tpEnabled"'));
    check('инстанс awg3', html.includes('data-tp-proto="awg3"'));
    check('подсказка об ограничениях', html.includes('tp_limits_hint'));
    check('здоровье: число пиров', html.includes('peers: 3'));
    check('настройки плагина', html.includes('id="tpPollSeconds"'));
    check('метки и их очистка', html.includes('id="tpMarksClear"'));
    check('кнопка удаления', html.includes('id="tpUninstall"'));
    check('нет inline-стилей', !/\sstyle="/.test(html),
        (html.match(/\sstyle="[^"]*"/g) || []).slice(0, 2).join(' | '));
    check('нет эмодзи', !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(html));
    check('get состояния при открытии',
        env.calls.some(c => c.method === 'GET' && c.url.endsWith('/plugins/torrent_guard')));

    // 1b. Контроль выключен: режимы недоступны и есть объяснение.
    const envOff = createEnv({ state: {
        id: 'torrent_guard', installed: true, enabled: false, supported: true,
        state: 'off', protocols: ['awg3'], modes: { awg3: 'off' },
        settings: { default_mode: 'on', include_wireguard: true,
                    marks_ttl_days: 30, clear_marks_on_disable: false,
                    poll_seconds: 60 },
        health: { state: 'unknown', protocols: {} }, events: 0, last_at: null,
    } });
    envOff.sandbox.TorrentPlugin.open();
    await flush();
    const offHtml = renderHtml(envOff);
    check('выключено: селект режима disabled', /data-tp-proto="awg3"[^>]*disabled/.test(offHtml));
    check('выключено: подсказка о отсутствии правил', offHtml.includes('tp_control_off_hint'));

    // 1c. Кнопки в шапке больше нет — плагин живёт плиткой в сетке.
    check('нет ссылок на torrentPluginBtn', !SOURCE.includes('torrentPluginBtn'));

    // 2. Мастер-выключатель: POST {enabled}.
    const enabled = env.byId('tpEnabled');
    enabled.checked = false;
    enabled.fire('change');
    await flush();
    const enabledCall = env.calls.find(c => c.url.endsWith('/enabled'));
    check('выключатель отправляет POST', !!enabledCall);
    eq('тело выключателя', enabledCall && enabledCall.body, { enabled: false });

    // 3. Режим инстанса: POST {protocol, mode}.
    const protoSelect = env.document.querySelectorAll('[data-tp-proto]')[0];
    protoSelect.value = 'count';
    protoSelect.fire('change');
    await flush();
    const modeCall = env.calls.find(c => c.url.endsWith('/mode'));
    check('режим отправляет POST', !!modeCall);
    eq('тело режима', modeCall && modeCall.body, { protocol: 'awg3', mode: 'count' });

    // 4. Сохранение настроек: все поля уходят одним пакетом.
    env.byId('tpDefaultMode').value = 'count';
    env.byId('tpIncludeWireguard').checked = false;
    env.byId('tpMarksTtl').value = '14';
    env.byId('tpClearOnDisable').checked = true;
    env.byId('tpPollSeconds').value = '30';
    env.byId('tpSettingsSave').fire('click');
    await flush();
    const settingsCall = env.calls.find(c => c.url.endsWith('/settings'));
    check('настройки отправляют POST', !!settingsCall);
    eq('тело настроек', settingsCall && settingsCall.body, {
        settings: { default_mode: 'count', include_wireguard: false,
                    marks_ttl_days: 14, clear_marks_on_disable: true,
                    poll_seconds: 30 },
    });

    // 5. Проверка правил и переустановка.
    env.byId('tpRefresh').fire('click');
    await flush();
    check('refresh отправляет POST', env.calls.some(c => c.url.endsWith('/refresh')));
    env.byId('tpReapply').fire('click');
    await flush();
    const reapply = env.calls.find(c => c.url.endsWith('/install'));
    check('переустановка отправляет install', !!reapply);
    eq('переустановка с reapply', reapply && reapply.body, { reapply: true });

    // 6. Очистка меток.
    env.byId('tpMarksClear').fire('click');
    await flush();
    check('очистка меток отправляет POST',
        env.calls.some(c => c.url.endsWith('/marks/clear')));

    // 7. Удаление плагина.
    env.byId('tpUninstall').fire('click');
    await flush();
    check('удаление отправляет uninstall',
        env.calls.some(c => c.url.endsWith('/uninstall')));

    // 7b. Кнопки плитки: Старт/Стоп и Удалить.
    const envBtn = createEnv();
    envBtn.sandbox.TorrentPlugin.open();
    await flush();
    await envBtn.sandbox.TorrentPlugin.setEnabled(true);
    await flush();
    const startCall = envBtn.calls.find(c => c.url.endsWith('/enabled'));
    check('Старт отправляет POST', !!startCall);
    eq('тело Старт', startCall && startCall.body, { enabled: true });

    await envBtn.sandbox.TorrentPlugin.setEnabled(false);
    await flush();
    const stopCall = envBtn.calls.filter(c => c.url.endsWith('/enabled')).pop();
    eq('Стоп отправляет enabled=false', stopCall && stopCall.body, { enabled: false });

    await envBtn.sandbox.TorrentPlugin.uninstall();
    await flush();
    check('Удалить отправляет uninstall',
        envBtn.calls.some(c => c.url.endsWith('/uninstall')));

    // 7c. SERVER_ID читается лениво: на верхнем уровне его нет.
    check('нет верхнеуровневого SERVER_ID', !/const BASE = .*SERVER_ID/.test(SOURCE));
    check('ленивый apiBase', SOURCE.includes('function apiBase()'));

    // 8. Метки в строках подключений: ядро передаёт готовый список.
    const env2 = createEnv();
    env2.sandbox.TorrentPlugin.open();
    await flush();
    const meta = node('meta');
    const row = node('row');
    row.setAttribute('data-client-id', 'peer-1');
    row.meta = meta;
    const listEl = {
        querySelector(selector) {
            if (selector.indexOf('row') !== -1) return row;
            return row;
        },
        querySelectorAll(selector) {
            if (selector === '.tp-mark') return [];
            if (selector === '.client-item') return [row];
            return [];
        },
    };
    env2.sandbox.TorrentPlugin.onRowsRendered(listEl, {
        clients: [{ clientId: 'peer-1', torrentIp: '10.8.1.17',
                    torrentEvents: [{ ts: 1760000100, sig: 'handshake', count: 5 }] }],
    }, 'awg3');
    check('метка вставлена после client-meta', !!meta.inserted);
    check('метка содержит сигнатуру', (meta.inserted || '').includes('torrent_sig_handshake'));
    check('метка содержит кнопку очистки', (meta.inserted || '').includes('data-tp-clear="peer-1"'));

    // 8b. Неизвестная сигнатура не показывает сырой ключ перевода.
    const envSig = createEnv();
    envSig.sandbox.TorrentPlugin.open();
    await flush();
    const sigMeta = node('meta-sig');
    const sigRow = node('row-sig');
    sigRow.setAttribute('data-client-id', 'peer-sig');
    sigRow.meta = sigMeta;
    const sigList = {
        querySelector: () => sigRow,
        querySelectorAll: selector => (selector === '.client-item' ? [sigRow] : []),
    };
    envSig.sandbox.TorrentPlugin.onRowsRendered(sigList, {
        clients: [{ clientId: 'peer-sig', torrentIp: '10.0.0.9',
                    torrentEvents: [{ ts: 1, sig: 'weird', count: 1 }] }],
    }, 'awg3');
    check('неизвестная сигнатура даёт torrent_sig_unknown',
        (sigMeta.inserted || '').includes('torrent_sig_unknown'));

    // 8c. Ошибки частичного apply показываются тостом, а не «сохранено».
    const envErr = createEnv({
        response: (url) => (url.endsWith('/settings') ? { errors: ['awg3: boom'] } : {}),
    });
    envErr.sandbox.TorrentPlugin.open();
    await flush();
    envErr.byId('tpSettingsSave').fire('click');
    await flush();
    check('ошибки настроек показаны', envErr.toasts.some(
        item => item.kind === 'error' && String(item.message).includes('awg3: boom')));

    // 9. Очистка метки из строки: POST marks/clear с ключом и адресом.
    const clearButton = node('clear');
    clearButton.setAttribute('data-tp-clear', 'peer-1');
    clearButton.setAttribute('data-tp-ip', '10.8.1.17');
    clearButton.closest = selector => (selector === '.client-item' ? row : null);
    row.setAttribute('data-protocol', 'awg3');
    env2.document.fire('click', clearButton);
    await flush();
    const clearCall = env2.calls.find(c => c.url.endsWith('/marks/clear'));
    check('очистка метки отправляет POST', !!clearCall);
    eq('тело очистки метки', clearCall && clearCall.body,
        { protocol: 'awg3', client_id: 'peer-1', ip: '10.8.1.17' });

    // 10. Безопасность разметки: данные из журнала экранируются.
    const env3 = createEnv();
    env3.sandbox.TorrentPlugin.open();
    await flush();
    const evilMeta = node('meta-evil');
    const evilRow = node('row-evil');
    evilRow.setAttribute('data-client-id', '<img src=x>');
    evilRow.meta = evilMeta;
    const evilList = {
        querySelector(selector) {
            if (selector.indexOf('row-evil') !== -1) return evilRow;
            return evilRow;
        },
        querySelectorAll(selector) {
            if (selector === '.client-item') return [evilRow];
            return [];
        },
    };
    env3.sandbox.TorrentPlugin.onRowsRendered(evilList, {
        clients: [{ clientId: '<img src=x>', torrentIp: '1.2.3.4',
                    torrentEvents: [{ ts: 1, sig: '<script>', count: 1 }] }],
    }, 'awg3');
    check('ключ экранирован', !String(evilMeta.inserted || '').includes('<img'));
}

run().then(() => {
    if (failures.length) {
        console.error('FAIL: ' + failures.length + ' из ' + checksRun);
        failures.forEach(item => console.error(' - ' + item));
        process.exit(1);
    }
    console.log('OK: torrent plugin harness, ' + checksRun + ' проверок пройдено');
}).catch(error => {
    console.error('FAIL: исключение харнесса');
    console.error(error);
    process.exit(1);
});
