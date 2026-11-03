/* Peer action queue: delete / disable / enable. One request at a time. */
(function () {
    'use strict';

    const TICK_MS = 300;
    const MAX_TICK = 90;
    const TIMEOUT_MS = 130000;
    const RETRY_MS = 10000;
    const DONE_MS = 2000;
    const STATES = ['queued', 'running', 'done', 'failed'];

    const tasks = [];
    const states = new Map();
    let running = false;
    let runningTask = null;
    let seq = 0;

    const keyOf = t => `${t.serverId}:${t.protocol}:${t.clientId}`;
    const actionName = a => a === 'delete'
        ? _('delete')
        : _(a === 'enable' ? 'enable_connection_progress' : 'disable_connection_progress');
    const sleep = ms => new Promise(r => setTimeout(r, ms));

    function cssEsc(value) {
        const text = String(value);
        return window.CSS && CSS.escape ? CSS.escape(text) : text.replace(/["\\]/g, '\\$&');
    }

    function rows(t) {
        return document.querySelectorAll(
            `.client-item[data-server-id="${cssEsc(t.serverId)}"]` +
            `[data-protocol="${cssEsc(t.protocol)}"]` +
            `[data-client-id="${cssEsc(t.clientId)}"]`);
    }

    function paint(t) {
        const rec = states.get(keyOf(t));
        const state = rec ? rec.state : '';
        rows(t).forEach(row => {
            STATES.forEach(s => row.classList.toggle('peer-queue-' + s, state === s));
            let badge = row.querySelector('.peer-queue-badge');
            if (!state) {
                if (badge) badge.remove();
                return;
            }
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'peer-queue-badge';
                (row.querySelector('.client-meta') || row).appendChild(badge);
            }
            badge.textContent = _('peer_queue_state_' + state);
        });
    }

    function setState(t, state) {
        const key = keyOf(t);
        const old = states.get(key);
        if (old && old.timer) clearTimeout(old.timer);
        if (!state) {
            states.delete(key);
            paint(t);
            return;
        }
        const rec = { state, task: t, timer: null };
        states.set(key, rec);
        if (state === 'done') {
            rec.timer = setTimeout(() => {
                if (states.get(key) === rec) {
                    states.delete(key);
                    paint(t);
                }
            }, DONE_MS);
        }
        paint(t);
    }

    function reapplyRowStates() {
        states.forEach(rec => paint(rec.task));
    }

    function makeToast(t) {
        const el = document.createElement('div');
        el.className = 'toast peer-queue-toast';
        el.setAttribute('role', 'status');
        el.setAttribute('aria-live', 'polite');
        el.innerHTML =
            '<div class="peer-queue-head"><span class="peer-queue-peer"></span>' +
            '<span class="peer-queue-percent">0%</span></div>' +
            '<div class="peer-queue-action"></div>' +
            '<div class="peer-queue-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">' +
            '<div class="peer-queue-fill"></div></div>' +
            '<div class="peer-queue-error" hidden></div>' +
            '<button class="peer-queue-close" type="button" hidden></button>';
        el.querySelector('.peer-queue-peer').textContent = t.peerName || t.clientId;
        el.querySelector('.peer-queue-action').textContent = actionName(t.action);
        const close = el.querySelector('.peer-queue-close');
        close.textContent = '\u00d7';
        close.setAttribute('aria-label', _('peer_queue_close'));
        t.toast = el;
        (document.getElementById('toastContainer') || document.body).appendChild(el);
    }

    function renderToast(t) {
        if (!t.toast) return;
        const pct = Math.max(0, Math.min(100, Math.round(t.percent)));
        t.toast.querySelector('.peer-queue-percent').textContent = pct + '%';
        t.toast.querySelector('.peer-queue-fill').style.width = pct + '%';
        t.toast.querySelector('.peer-queue-track').setAttribute('aria-valuenow', String(pct));
    }

    function startProgress(t) {
        clearInterval(t.timer);
        t.percent = 10;
        renderToast(t);
        t.timer = setInterval(() => {
            if (t.percent < MAX_TICK) {
                t.percent += 1;
                renderToast(t);
            }
        }, TICK_MS);
    }

    function withTimeout(promise) {
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(_('peer_queue_error_network'))), TIMEOUT_MS);
        });
        return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    }

    async function request(t, path, body, isDelete) {
        let busyRetries = 0;
        for (;;) {
            try {
                return await withTimeout(apiCall(`/api/servers/${t.serverId}${path}`, 'POST', body));
            } catch (err) {
                const payload = err && err.payload;
                if (payload && payload.code === 'peer_lifecycle_busy' && busyRetries < 2) {
                    busyRetries += 1;
                    await sleep(RETRY_MS);
                    continue;
                }
                if (isDelete && payload && payload.code === 'final_counter_read_failed' && payload.can_force
                    && confirm(_('delete_unverified_confirm'))) {
                    body = Object.assign({}, body, { allow_unverified: true });
                    continue;
                }
                throw err;
            }
        }
    }

    function run(t) {
        const body = { protocol: t.protocol, client_id: t.clientId };
        if (t.action === 'delete') {
            return request(t, '/connections/remove', body, true);
        }
        body.enable = t.action === 'enable';
        return request(t, '/connections/toggle', body, false);
    }

    async function drain() {
        if (running) return;
        running = true;
        while (tasks.length) {
            const t = tasks.shift();
            runningTask = t;
            t.status = 'running';
            setState(t, 'running');
            startProgress(t);
            try {
                await run(t);
                clearInterval(t.timer);
                t.percent = 100;
                renderToast(t);
                t.toast.classList.add('peer-queue-success');
                await sleep(500);
                t.toast.classList.add('peer-queue-fade');
                await sleep(300);
                t.toast.remove();
                t.status = 'done';
                setState(t, 'done');
            } catch (err) {
                clearInterval(t.timer);
                t.status = 'failed';
                setState(t, 'failed');
                if (t.toast) {
                    t.toast.classList.add('peer-queue-failed');
                    const errEl = t.toast.querySelector('.peer-queue-error');
                    errEl.textContent = (err && err.message) || _('peer_queue_state_failed');
                    errEl.hidden = false;
                    const close = t.toast.querySelector('.peer-queue-close');
                    close.hidden = false;
                    close.onclick = () => {
                        t.toast.remove();
                        if (states.get(keyOf(t)) && states.get(keyOf(t)).state === 'failed') {
                            setState(t, null);
                        }
                    };
                }
            }
            runningTask = null;
        }
        running = false;
        if (typeof window.peerQueueOnIdle === 'function') {
            try { window.peerQueueOnIdle(); } catch (e) { /* keep the queue usable */ }
        }
    }

    function enqueue(task) {
        const t = Object.assign({
            serverId: 0, protocol: 'awg', clientId: '', peerName: '', action: 'enable',
        }, task);
        t.serverId = Number(t.serverId) || 0;
        t.clientId = String(t.clientId || '');
        t.peerName = t.peerName || t.clientId;
        t.action = String(t.action || '');
        if (['enable', 'disable', 'delete'].indexOf(t.action) < 0) return false;

        const key = keyOf(t);
        const busy = tasks.some(x => keyOf(x) === key && x.action === t.action) ||
            (runningTask && keyOf(runningTask) === key && runningTask.action === t.action);
        if (busy) return false;
        if (t.action !== 'delete' && (tasks.some(x => keyOf(x) === key && x.action === 'delete') ||
            (runningTask && keyOf(runningTask) === key && runningTask.action === 'delete'))) {
            return false;
        }

        if (t.action === 'delete') {
            for (let i = tasks.length - 1; i >= 0; i--) {
                if (keyOf(tasks[i]) === key && tasks[i].action !== 'delete') {
                    const cancelled = tasks.splice(i, 1)[0];
                    if (cancelled.toast) cancelled.toast.remove();
                    setState(cancelled, null);
                }
            }
        }

        t.id = ++seq;
        t.percent = 0;
        t.status = 'queued';
        t.attempts = 0;
        tasks.push(t);
        setState(t, 'queued');
        makeToast(t);
        renderToast(t);
        drain();
        return true;
    }

    window.PeerQueue = {
        enqueue,
        reapplyRowStates,
        size: () => tasks.length,
        isIdle: () => !running && tasks.length === 0,
    };
})();
