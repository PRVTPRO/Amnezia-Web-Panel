/* Executes the real inline JavaScript of templates/server.html and checks what
 * updateProtocolCard() paints for a running instance.
 *
 * Why this exists: node --check (tests/test_template_js.py) only proves the
 * script parses. The v1.8.12 merge swallowed a closing brace and left the
 * running-protocol `else` branch empty, which is valid JavaScript: the card
 * kept the initial Install markup, the Connections row stayed hidden and every
 * static assertion still passed. This harness runs the real function against
 * minimal DOM stubs, so an emptied branch fails the build.
 *
 * Usage: node tests/js/protocol_card_actions.js <rendered-inline.js>
 */
const fs = require('fs');
const vm = require('vm');

const sourcePath = process.argv[2];
if (!sourcePath) {
    console.error('usage: node protocol_card_actions.js <rendered-inline.js>');
    process.exit(2);
}

const elements = new Map();

function makeClassList(initial) {
    const names = new Set(initial || []);
    return {
        add(...list) { list.forEach((name) => names.add(name)); },
        remove(...list) { list.forEach((name) => names.delete(name)); },
        toggle(name) { names.has(name) ? names.delete(name) : names.add(name); },
        contains(name) { return names.has(name); },
    };
}

function makeElement(id) {
    const el = {
        id: id,
        innerHTML: '',
        textContent: '',
        value: '',
        checked: false,
        disabled: false,
        hidden: false,
        className: '',
        title: '',
        dataset: {},
        style: {},
        children: [],
        classList: makeClassList(),
        appendChild(child) { this.children.push(child); return child; },
        insertAdjacentElement() {},
        insertAdjacentHTML() {},
        setAttribute(name, value) { this[name] = value; },
        removeAttribute() {},
        getAttribute() { return null; },
        addEventListener() {},
        removeEventListener() {},
        remove() {},
        focus() {},
        click() {},
        closest() { return null; },
        querySelector() { return makeElement('child'); },
        querySelectorAll() { return []; },
    };
    return el;
}

function elementById(id) {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
}

const documentStub = {
    hidden: false,
    cookie: '',
    body: makeElement('body'),
    head: makeElement('head'),
    documentElement: makeElement('html'),
    getElementById: elementById,
    querySelector: () => makeElement('selector'),
    querySelectorAll: () => [],
    createElement: (tag) => makeElement(tag),
    createTextNode: (text) => ({ textContent: text, appendChild() {} }),
    addEventListener() {},
    removeEventListener() {},
};

const sandbox = {
    document: documentStub,
    console: { log() {}, warn() {}, error() {}, info() {}, debug() {} },
    setTimeout: () => 1,
    clearTimeout() {},
    setInterval: () => 1,
    clearInterval() {},
    fetch: () => new Promise(() => {}),
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    navigator: { userAgent: 'node', clipboard: { writeText: () => Promise.resolve() } },
    location: { href: 'http://127.0.0.1:8000/server/1', host: '127.0.0.1:8000', protocol: 'http:', pathname: '/server/1' },
    matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {} }),
    alert() {},
    confirm: () => true,
    prompt: () => null,
    open() {},
    _: (key) => key,
    // Helpers that live in base.html, outside the extracted server script.
    apiCall: () => new Promise(() => {}),
    showToast() {},
    openModal() {},
    closeModal() {},
    setEditorValue() {},
    refreshConfigEditor() {},
    structuredClone: (value) => value,
    addEventListener() {},
    removeEventListener() {},
    URL, URLSearchParams, JSON, Date, Math, Promise, Set, Map, Number, String, Boolean, Array, Object, RegExp, Error,
};
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.globalThis = sandbox;

const context = vm.createContext(sandbox);
let evalError = null;
try {
    vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), context, { filename: 'server_inline.js' });
} catch (err) {
    // The page's init block (checkServer and friends) runs at the end of the
    // script. Function declarations are hoisted, so a failure there must not
    // hide a real defect in updateProtocolCard; it is reported separately.
    evalError = err;
}

const failures = [];

function card(proto, info) {
    const protoKey = String(proto).replace(/_/g, '-');
    const actions = elementById(`${protoKey}-actions`);
    const ctrl = elementById(`${protoKey}-ctrl`);
    actions.innerHTML = '';
    ctrl.innerHTML = '';
    const section = elementById('connectionsSection');
    // The template ships the section as style="display:none" without the hidden
    // class. `.hidden` is display:none !important, so visibility needs both:
    // a non-none display and no hidden class left on the element.
    section.style = { display: 'none' };
    section.classList = makeClassList();
    if (typeof context.updateProtocolCard !== 'function') {
        failures.push(`${proto}: updateProtocolCard is not defined`);
        return { html: '', ctrl: '', visible: false };
    }
    context.updateProtocolCard(proto, info);
    return {
        html: String(actions.innerHTML || ''),
        ctrl: String(ctrl.innerHTML || ''),
        visible: section.style.display !== 'none' && !section.classList.contains('hidden'),
    };
}

function expect(proto, result, needles, forbidden, ctrlNeedles, ctrlForbidden) {
    needles.forEach((needle) => {
        if (!result.html.includes(needle)) failures.push(`${proto}: action row is missing ${needle}`);
    });
    (forbidden || []).forEach((needle) => {
        if (result.html.includes(needle)) failures.push(`${proto}: action row still contains ${needle}`);
    });
    (ctrlNeedles || []).forEach((needle) => {
        if (!result.ctrl.includes(needle)) failures.push(`${proto}: control row is missing ${needle}`);
    });
    (ctrlForbidden || []).forEach((needle) => {
        if (result.ctrl.includes(needle)) failures.push(`${proto}: control row still contains ${needle}`);
    });
}

const running = { container_running: true, port: 51820, clients_count: 4 };
['awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard', 'telemt', 'xray'].forEach((proto) => {
    const result = card(proto, running);
    expect(
        proto, result,
        ['selectProtocolForConns(', 'showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
        ['showServerConfig(', 'toggleContainer('], []
    );
    if (!result.visible) failures.push(`${proto}: the Connections section stayed hidden`);
});

// A running instance can report no port and no peer count (container just
// started, status probe partially failed); the action row must appear anyway.
expect(
    'awg3', card('awg3', { container_running: true }),
    ['selectProtocolForConns(', 'uninstallProtocol('], ['openInstallModal('],
    ['toggleContainer('], []
);

const stopped = { container_running: false, container_exists: true };
['awg3', 'wireguard'].forEach((proto) => {
    expect(
        proto, card(proto, stopped),
        ['openInstallModal(', 'showProtocolBackups(', 'uninstallProtocol('], [],
        ['toggleContainer('], []
    );
});

['awg3', 'wireguard'].forEach((proto) => {
    const result = card(proto, {});
    expect(proto, result, ['openInstallModal('], ['uninstallProtocol(', 'toggleContainer('], [], []);
});

// Service cards paint their own action rows; they share the same branch chain,
// so a swallowed brace can empty any of them.
expect(
    'exit', card('exit', running),
    ['showExitPeers(', 'showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
    ['toggleContainer('], []
);
expect(
    'socks5', card('socks5', running),
    ['openSocks5Settings(', 'uninstallProtocol('], ['openInstallModal('],
    ['toggleContainer('], []
);
expect(
    'nginx', card('nginx', running),
    ['showNginxSite(', 'showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
    ['showServerConfig(', 'toggleContainer('], []
);
expect(
    'adguard', card('adguard', running),
    ['adguard_open_ui', 'showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
    ['toggleContainer('], []
);
expect(
    'haproxy', card('haproxy', running),
    ['showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
    ['showServerConfig(', 'toggleContainer('], []
);
expect(
    'dns', card('dns', running),
    ['showProtocolBackups(', 'uninstallProtocol('], ['openInstallModal('],
    ['toggleContainer('], []
);

if (evalError) console.error('note: page init did not complete: ' + evalError.message);

if (failures.length) {
    failures.forEach((line) => console.error('FAIL ' + line));
    process.exit(1);
}
console.log('ok: protocol card action rows render for every protocol family');
