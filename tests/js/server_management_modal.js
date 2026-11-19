/* Харнесс для shared-скрипта модалки управления сервером.
 *
 * Исполняет НАСТОЯЩИЙ static/js/server-management.js в vm-контексте с
 * минимальными DOM-заглушками и проверяет то, что нельзя увидеть статическим
 * grep: разметку без inline-стилей, иконки вместо эмодзи, «оживление» тумблера
 * и адреса всех действий. Тумблер торрентов уехал в плагин.
 *
 * Запуск: node tests/js/server_management_modal.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const SOURCE_PATH = process.env.SM_SCRIPT || path.join(ROOT, 'static', 'js', 'server-management.js');
const SOURCE = fs.readFileSync(SOURCE_PATH, 'utf8');

const failures = [];
let checksRun = 0;
function check(name, condition, detail) {
    checksRun += 1;
    if (condition) return;
    failures.push(name + (detail ? ' — ' + detail : ''));
}

function eq(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    check(name, ok, 'получено ' + JSON.stringify(actual) + ', ожидалось ' + JSON.stringify(expected));
}

const ICONS = {
    refresh: '<path d="M3 12a9 9 0 0 1 9-9"/>',
    power: '<path d="M12 2v10"/>',
    eraser: '<path d="m7 21-4.3-4.3"/>',
    trash: '<path d="M3 6h18"/>',
    save: '<path d="M15.2 3a2 2 0 0 1 1.4.6"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5"/>',
};

function makeDocument() {
    const nodes = new Map();
    const listeners = { change: [], click: [] };

    function createNode(id) {
        let html = '';
        const classes = new Set();
        const node = {
            id,
            tagName: 'DIV',
            textContent: '',
            title: '',
            value: '',
            checked: false,
            disabled: false,
            dataset: {},
            tagAttributes: {},
            classList: {
                add: c => classes.add(c),
                remove: c => classes.delete(c),
                contains: c => classes.has(c),
                toggle: (c, on) => {
                    if (on === undefined) {
                        if (classes.has(c)) classes.delete(c); else classes.add(c);
                        return classes.has(c);
                    }
                    if (on) classes.add(c); else classes.delete(c);
                    return !!on;
                },
            },
            matches(selector) {
                if (selector.startsWith('#')) return selector.slice(1) === this.id;
                const attr = /^\[data-([a-z-]+)\]$/.exec(selector);
                if (attr) {
                    const key = attr[1].replace(/-([a-z])/g, (match, letter) => letter.toUpperCase());
                    return Object.prototype.hasOwnProperty.call(this.dataset, key);
                }
                return false;
            },
            closest(selector) {
                return this.matches(selector) ? this : null;
            },
            getAttribute(name) {
                return this.tagAttributes[name] === undefined ? null : this.tagAttributes[name];
            },
            setAttribute(name, value) {
                this.tagAttributes[name] = String(value);
            },
        };
        node.style = {};
        Object.defineProperty(node, 'innerHTML', {
            get() { return html; },
            set(value) {
                html = String(value);
                registerFromMarkup(html);
            },
        });
        return node;
    }

    function nodeFor(id) {
        if (!nodes.has(id)) nodes.set(id, createNode(id));
        return nodes.get(id);
    }

    // После установки innerHTML настоящий браузер создаёт элементы с их id.
    // Заглушка делает то же самое: иначе getElementById() не нашёл бы тумблер.
    function registerFromMarkup(html) {
        const idPattern = /\bid="([^"]+)"/g;
        let match;
        while ((match = idPattern.exec(html)) !== null) nodeFor(match[1]);

        const inputPattern = /<input\b[^>]*>/g;
        while ((match = inputPattern.exec(html)) !== null) {
            const tag = match[0];
            const id = (tag.match(/\bid="([^"]+)"/) || [])[1];
            if (!id) continue;
            const node = nodeFor(id);
            node.tagName = 'INPUT';
            node.type = (tag.match(/\btype="([^"]+)"/) || [])[1] || 'text';
            node.disabled = /\bdisabled\b/.test(tag);
            node.checked = /\bchecked\b/.test(tag);
            node.value = (tag.match(/\bvalue="([^"]*)"/) || [])[1] || '';
        }

        const selectPattern = /<select\b[^>]*>([\s\S]*?)<\/select>/g;
        while ((match = selectPattern.exec(html)) !== null) {
            const id = (match[0].match(/\bid="([^"]+)"/) || [])[1];
            if (!id) continue;
            const options = [...match[1].matchAll(/<option value="([^"]*)"([^>]*)>/g)];
            const chosen = options.find(option => /\bselected\b/.test(option[2])) || options[0];
            const node = nodeFor(id);
            node.tagName = 'SELECT';
            node.options = options.map(option => option[1]);
            if (chosen) node.value = chosen[1];
        }
    }

    return {
        nodes,
        listeners,
        getElementById: id => nodes.get(id) || null,
        ensure(id) { return nodeFor(id); },
        addEventListener(type, handler) {
            if (!listeners[type]) listeners[type] = [];
            listeners[type].push(handler);
        },
        body: { contains: () => true },
        querySelectorAll: () => [],
    };
}

function createHarness(options) {
    const settings = options || {};
    const document = makeDocument();
    // Контейнер содержимого живёт в шаблоне модалки, а не в innerHTML.
    document.ensure('serverManagementContent');
    const calls = [];
    const toasts = [];
    const opened = [];
    let confirmAnswer = true;
    let forcedError = null;

    const state = {
    };
    const pending = [];

    async function apiCall(url, method, body) {
        calls.push({ url, method: method || 'GET', body: body === undefined ? null : body });
        if (settings.defer) {
            return new Promise(resolve => pending.push({
                url, method: method || 'GET', body: body === undefined ? null : body, resolve,
            }));
        }
        if (forcedError) throw forcedError;
        if (url.includes('/ssh_cooldown')) return { ok: true, ssh_cooldown_base: body.seconds };
        if (url.includes('/peer_poll_interval')) return { ok: true, peer_poll_interval: body.seconds };
        return { status: 'success' };
    }

    const sandbox = {
        document,
        setTimeout: fn => { fn(); return 0; },
        clearTimeout: () => {},
        confirm: () => confirmAnswer,
        openModal: id => opened.push(id),
        closeModal: id => opened.push('close:' + id),
        showToast: (message, kind) => toasts.push({ message, kind }),
        _: key => key,
        console,
    };
    sandbox.window = sandbox;
    sandbox.window.apiCall = apiCall;
    sandbox.window.SM_ICONS = ICONS;
    sandbox.window.location = { href: '' };

    vm.createContext(sandbox);
    vm.runInContext(SOURCE, sandbox, { filename: 'server-management.js' });

    return {
        document,
        calls,
        toasts,
        opened,
        state,
        pending,
        open(extra) {
            sandbox.window.ServerManagement.open(Object.assign({
                serverId: 3,
                serverUid: 'node-a',
                sshCooldown: 30,
                peerPollInterval: 15,
            }, extra || {}));
        },
        fire(type, target) {
            (document.listeners[type] || []).forEach(handler => {
                handler({ target });
            });
        },
        setConfirm(answer) { confirmAnswer = answer; },
        failWith(error) { forcedError = error; },
        flush: () => new Promise(resolve => setImmediate(resolve)),
    };
}

module.exports = { createHarness, check, eq, failures, ICONS };

/* ===== Проверки ===== */

function actionTarget(action) {
    return {
        dataset: { serverManagementAction: action },
        closest(selector) {
            return selector === '[data-server-management-action]' ? this : null;
        },
    };
}

async function run() {
    // 1. Разметка: без inline-стилей и эмодзи, иконки — монохромные SVG.
    const page = createHarness();
    page.open();
    await page.flush();
    const html = page.document.getElementById('serverManagementContent').innerHTML;

    check('в разметке нет inline-style', !/\sstyle="/.test(html), (html.match(/\sstyle="[^"]*"/g) || []).slice(0, 3).join(' | '));
    check('в разметке нет эмодзи', !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(html));
    check('стек действий .sm-stack', html.includes('class="sm-stack"'));
    check('секции .sm-section', (html.match(/class="sm-section"/g) || []).length === 2);
    check('кнопки действий .sm-action', (html.match(/sm-action/g) || []).length === 4);
    check('шесть действий', (html.match(/data-server-management-action="/g) || []).length === 6);
    check('иконки SVG в разметке', (html.match(/<svg class="ui-icon"/g) || []).length === 6);

    // 8. Действия меню: адреса и параметры запросов.
    const actions = createHarness();
    actions.open();
    await actions.flush();
    const urls = [];
    for (const action of ['check', 'reboot', 'clear', 'remove']) {
        actions.fire('click', actionTarget(action));
        await actions.flush();
        await actions.flush();
    }
    actions.calls.forEach(call => urls.push(call.method + ' ' + call.url));
    check('check: /api/servers/3/check', urls.includes('POST /api/servers/3/check'));
    check('reboot: /api/servers/3/reboot', urls.includes('POST /api/servers/3/reboot'));
    check('clear: uid в query', urls.includes('POST /api/servers/3/clear?server_uid=node-a'));
    check('remove: panel_only и uid', urls.includes('POST /api/servers/3/delete?server_uid=node-a&panel_only=true'));

    // 9. Настройки: cooldown и интервал опроса пишутся с валидацией.
    actions.fire('click', actionTarget('save-cooldown'));
    await actions.flush();
    actions.fire('click', actionTarget('save-poll'));
    await actions.flush();
    const cooldown = actions.calls.find(call => call.url === '/api/servers/3/ssh_cooldown');
    const poll = actions.calls.find(call => call.url === '/api/servers/3/peer_poll_interval');
    check('save-cooldown: эндпоинт вызван', !!cooldown);
    eq('save-cooldown: тело', cooldown && cooldown.body, { seconds: 30 });
    check('save-poll: эндпоинт вызван', !!poll);
    eq('save-poll: тело', poll && poll.body, { seconds: 15 });

    // 10. Валидация ввода не отправляет заведомо неверные значения.
    const invalid = createHarness();
    invalid.open();
    await invalid.flush();
    invalid.document.getElementById('sshCooldownInput').value = '999';
    invalid.document.getElementById('peerPollSelect').value = '7';
    const before = invalid.calls.length;
    invalid.fire('click', actionTarget('save-cooldown'));
    invalid.fire('click', actionTarget('save-poll'));
    await invalid.flush();
    eq('невалидные значения не отправляются', invalid.calls.length, before);
    eq('два тоста об ошибке', invalid.toasts.filter(toast => toast.kind === 'error').length, 2);

    // 12. Значение вне списка шагов не подменяется «выключено».
    const legacyPoll = createHarness();
    legacyPoll.open({ peerPollInterval: 7 });
    await legacyPoll.flush();
    const legacyHtml = legacyPoll.document.getElementById('serverManagementContent').innerHTML;
    check('нестандартный интервал показан как есть', legacyHtml.includes('<option value="7" selected>'));
    eq('селект не свалился на 0', legacyPoll.document.getElementById('peerPollSelect').value, '7');

    // 13. Отмена в confirm оставляет модалку открытой и не шлёт запрос.
    const cancelled = createHarness();
    cancelled.open();
    await cancelled.flush();
    cancelled.setConfirm(false);
    const beforeCancel = cancelled.calls.length;
    for (const action of ['reboot', 'clear', 'remove']) {
        cancelled.fire('click', actionTarget(action));
        await cancelled.flush();
    }
    eq('отмена: ни одного запроса', cancelled.calls.length, beforeCancel);
    eq('отмена: модалка не закрыта', cancelled.opened.filter(entry => entry.startsWith('close:')).length, 0);

    // 14. Без uid параметр не отправляется: пустой server_uid бэкенд считает
    //     подменой сервера и отвечает 409.
    const noUid = createHarness();
    noUid.open({ serverUid: '' });
    await noUid.flush();
    noUid.fire('click', actionTarget('clear'));
    await noUid.flush();
    noUid.fire('click', actionTarget('remove'));
    await noUid.flush();
    const noUidUrls = noUid.calls.map(call => call.url);
    check('clear без uid: без query', noUidUrls.includes('/api/servers/3/clear'));
    check('delete без uid: только panel_only',
        noUidUrls.includes('/api/servers/3/delete?panel_only=true'));
    check('пустой server_uid не отправляется', !noUidUrls.some(url => url.includes('server_uid=')));
}

run().then(() => {
    if (failures.length === 0) {
        console.log('OK: server management modal harness, ' + checksRun + ' checks passed');
        process.exit(0);
    }
    console.error('FAILED ' + failures.length + ' of ' + checksRun + ':');
    failures.forEach(failure => console.error(' - ' + failure));
    process.exit(1);
}).catch(error => {
    console.error('HARNESS ERROR: ' + (error && error.stack ? error.stack : error));
    process.exit(2);
});
