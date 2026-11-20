/* Плагин «Защита от торрентов»: панель, бейдж и метки в списке подключений.
 *
 * Загружается только когда плагин установлен на сервере (см.
 * templates/_torrent_plugin_modal.html). Пока не установлен, этого файла на
 * странице нет, и ядро о плагине ничего не знает: единственный контракт —
 * необязательный window.TorrentPlugin.onRowsRendered(listEl, data, proto).
 *
 * Вёрстка без inline-стилей и без эмодзи: классы .tp-* в style.css, иконки —
 * из window.TORRENT_PLUGIN_ICONS (реестр templates/_ui_icons.html).
 */
(function () {
    'use strict';

    // SERVER_ID объявляется ниже по странице (в inline-скрипте), поэтому
    // читаем его лениво: на верхнем уровне он ещё в TDZ и ронял весь модуль.
    function apiBase() {
        return '/api/servers/' + SERVER_ID + '/plugins/torrent_guard';
    }
    const ICONS = window.TORRENT_PLUGIN_ICONS || {};
    const POLL_STEPS = [0, 5, 15, 30, 60, 300];
    const MODES = ['on', 'count', 'off'];
    let state = window.TORRENT_PLUGIN_STATE || {};
    let pollTimer = null;
    let busy = false;

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function call(path, method, body) {
        return apiCall(apiBase() + (path || ''), method || 'GET', body);
    }

    function toast(message, kind) {
        if (typeof showToast === 'function') showToast(message, kind);
    }

    function stateLabel(value) {
        return _('tp_state_' + (value || 'not_installed'));
    }

    function stateClass(value) {
        return ({
            on: 'badge-success',
            count: 'badge-info',
            off: 'badge-secondary',
            degraded: 'badge-danger',
            unknown: 'badge-secondary',
            unsupported: 'badge-secondary',
            not_installed: 'badge-warn',
        })[value] || 'badge-secondary';
    }

    function when(ts) {
        const value = Number(ts) || 0;
        if (!value) return '\u2014';
        const d = new Date(value * 1000);
        const two = n => String(n).padStart(2, '0');
        return two(d.getDate()) + '.' + two(d.getMonth() + 1) + ' ' +
            two(d.getHours()) + ':' + two(d.getMinutes());
    }

    function modeLabel(mode) {
        return _('tp_mode_' + mode);
    }

    // Ошибки движка приходят текстом iptables/docker. Админу нужно действие,
    // а не ответ демона: переводим типовые случаи в понятную фразу.
    function humanError(raw) {
        const text = String(raw || '');
        if (/is not running/i.test(text) || /No such container/i.test(text)) {
            return _('tp_err_container_stopped');
        }
        if (/xt_string|xt_connbytes|does not exist|No chain\/target/i.test(text)) {
            return _('tp_err_no_iptables_modules');
        }
        if (/timed out|timeout|Connection refused|No route to host/i.test(text)) {
            return _('tp_err_unreachable');
        }
        return text;
    }

    function healthText(proto) {
        const health = (state.health && state.health.protocols) || {};
        const item = health[proto];
        if (!item) return { text: _('tp_health_unknown'), cls: 'tp-health--unknown' };
        if (item.error) {
            return { text: humanError(item.error), cls: 'tp-health--error' };
        }
        // peers приходит из apply/collect: «правила на месте» без числа пиров
        // не говорит, накрыт ли хоть один ключ.
        const peers = (item.peers === undefined || item.peers === null)
            ? '' : ' \u00b7 ' + _('tp_health_peers')
                .replace('{count}', String(Number(item.peers) || 0));
        return { text: _('tp_health_ok') + peers + ' \u00b7 ' + when(item.ts),
                 cls: 'tp-health--ok' };
    }

    function renderInstances() {
        const protos = state.protocols || [];
        if (!protos.length) {
            return '<div class="empty-state tp-empty">' +
                '<div class="empty-title">' + esc(_('tp_no_instances')) + '</div>' +
                '<div class="empty-desc">' + esc(_('tp_no_instances_hint')) + '</div>' +
                '</div>';
        }
        return protos.map(proto => {
            const mode = (state.modes || {})[proto] || 'off';
            const health = healthText(proto);
            return `
                <div class="tp-instance" data-tp-instance="${esc(proto)}">
                    <div class="tp-instance__head">
                        <span class="tp-instance__name">${esc(proto)}</span>
                        <select class="form-select tp-select" data-tp-proto="${esc(proto)}"
                            aria-label="${esc(_('tp_mode_label'))}"${state.enabled ? '' : ' disabled'}>
                            ${MODES.map(item => `<option value="${item}"${item === mode ? ' selected' : ''}>${modeLabel(item)}</option>`).join('')}
                        </select>
                    </div>
                    <div class="tp-health ${health.cls}">${esc(health.text)}</div>
                </div>`;
        }).join('');
    }

    function renderSettings() {
        const settings = state.settings || {};
        return `
            <div class="tp-settings">
                <div class="sm-section">
                    <label class="sm-field-label" for="tpDefaultMode">${esc(_('tp_default_mode'))}</label>
                    <select class="form-select tp-select" id="tpDefaultMode">
                        ${MODES.map(item => `<option value="${item}"${item === settings.default_mode ? ' selected' : ''}>${modeLabel(item)}</option>`).join('')}
                    </select>
                    <div class="text-muted sm-hint">${esc(_('tp_default_mode_hint'))}</div>
                </div>
                <label class="tp-check" for="tpIncludeWireguard">
                    <input type="checkbox" id="tpIncludeWireguard"${settings.include_wireguard ? ' checked' : ''}>
                    <span>${esc(_('tp_include_wireguard'))}</span>
                </label>
                <div class="sm-section">
                    <label class="sm-field-label" for="tpMarksTtl">${esc(_('tp_marks_ttl'))}</label>
                    <div class="sm-row">
                        <input class="form-input sm-number" type="number" id="tpMarksTtl"
                            min="7" max="90" step="1" value="${esc(settings.marks_ttl_days)}">
                        <span class="text-muted">${esc(_('tp_days'))}</span>
                    </div>
                </div>
                <label class="tp-check" for="tpClearOnDisable">
                    <input type="checkbox" id="tpClearOnDisable"${settings.clear_marks_on_disable ? ' checked' : ''}>
                    <span>${esc(_('tp_clear_marks_on_disable'))}</span>
                </label>
                <div class="sm-section">
                    <label class="sm-field-label" for="tpPollSeconds">${esc(_('tp_poll_seconds'))}</label>
                    <select class="form-select tp-select" id="tpPollSeconds">
                        ${POLL_STEPS.map(item => `<option value="${item}"${item === settings.poll_seconds ? ' selected' : ''}>${item === 0 ? _('tp_poll_manual') : item + ' ' + _('peer_poll_sec')}</option>`).join('')}
                    </select>
                </div>
                <button class="btn btn-secondary btn-sm tp-save" id="tpSettingsSave">
                    <span class="btn-text-with-icon">${ICONS.save || ''} ${esc(_('tp_save'))}</span>
                </button>
            </div>`;
    }

    function renderMarks() {
        return `
            <div class="tp-marks">
                <div class="tp-marks__row">
                    <span>${esc(_('tp_marks_total'))}: <b>${Number(state.events) || 0}</b></span>
                    <span>${esc(_('tp_marks_last'))}: <b>${esc(when(state.last_at))}</b></span>
                </div>
                <button class="btn btn-secondary btn-sm tp-marks__clear" id="tpMarksClear">
                    <span class="btn-text-with-icon">${ICONS.eraser || ''} ${esc(_('tp_marks_clear'))}</span>
                </button>
            </div>`;
    }

    function render() {
        const el = document.getElementById('torrentPluginContent');
        if (!el) return;
        const value = state.state || 'not_installed';
        el.innerHTML = `
            <div class="tp-stack">
                <div class="tp-status">
                    <span class="badge ${stateClass(value)}"><span class="badge-dot"></span> ${esc(stateLabel(value))}</span>
                    <span class="text-muted tp-status__health">${esc(_('tp_health_' + ((state.health && state.health.state) || 'unknown')))}</span>
                </div>
                <div class="text-muted sm-hint">${esc(_('tp_limits_hint'))}</div>
                <label class="tp-check tp-check--master" for="tpEnabled">
                    <input type="checkbox" id="tpEnabled"${state.enabled ? ' checked' : ''}${state.supported ? '' : ' disabled'}>
                    <span>${esc(_('tp_master_title'))}</span>
                </label>
                <div class="text-muted sm-hint">${esc(_('tp_master_hint'))}</div>
                <div class="tp-actions">
                    <button class="btn btn-secondary btn-sm" id="tpRefresh">
                        <span class="btn-text-with-icon">${ICONS.refresh || ''} ${esc(_('tp_refresh'))}</span>
                    </button>
                    <button class="btn btn-secondary btn-sm" id="tpReapply">
                        <span class="btn-text-with-icon">${ICONS.save || ''} ${esc(_('tp_reapply'))}</span>
                    </button>
                </div>
                <div class="sm-section">
                    <div class="sm-field-label">${esc(_('tp_instances_title'))}</div>
                    <div class="tp-instances">${renderInstances()}</div>
                    ${state.enabled ? '' : `<div class="text-muted sm-hint">${esc(_('tp_control_off_hint'))}</div>`}
                </div>
                <div class="sm-section">
                    <div class="sm-field-label">${esc(_('tp_settings_title'))}</div>
                    ${renderSettings()}
                </div>
                <div class="sm-section">
                    <div class="sm-field-label">${esc(_('tp_marks_title'))}</div>
                    ${renderMarks()}
                </div>
                <button class="btn btn-danger btn-sm tp-uninstall" id="tpUninstall">
                    <span class="btn-text-with-icon">${ICONS.trash || ''} ${esc(_('tp_uninstall'))}</span>
                </button>
            </div>`;
        bind();
        updateHeaderBadge();
    }

    // Плитка в сетке инстансов перерисовывается ядром: отдельной кнопки в
    // шапке сервера у плагина нет.
    function updateHeaderBadge() {
        if (typeof window.renderTorrentPluginCard === 'function') {
            window.renderTorrentPluginCard();
        }
    }

    function setBusy(flag) {
        busy = flag;
        const el = document.getElementById('torrentPluginContent');
        if (!el) return;
        el.classList.toggle('tp-busy', flag);
    }

    function applyState(payload) {
        if (payload && typeof payload === 'object') {
            state = Object.assign({}, state, payload);
            window.TORRENT_PLUGIN_STATE = state;
            // Плитка в сетке инстансов читает TORRENT_PLUGIN из шаблона;
            // без синхронизации бейдж и кнопки Старт/Стоп отставали.
            if (typeof TORRENT_PLUGIN !== 'undefined') {
                Object.assign(TORRENT_PLUGIN, state);
            }
        }
        render();
        restartPolling();
    }

    async function refreshState() {
        if (busy) return;
        try {
            applyState(await call('', 'GET'));
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        }
    }

    // poll_seconds — интервал автообновления ОТКРЫТОЙ панели; фоновый сбор
    // на сервере идёт своим циклом (CONN_MONITOR_INTERVAL = 600 с).
    function restartPolling() {
        clearInterval(pollTimer);
        pollTimer = null;
        const seconds = Number((state.settings || {}).poll_seconds) || 0;
        if (!seconds || !document.getElementById('torrentPluginModal').classList.contains('active')) return;
        pollTimer = setInterval(refreshState, seconds * 1000);
    }

    async function setEnabled(enabled) {
        const startBtn = document.getElementById('torrentPluginStart');
        const stopBtn = document.getElementById('torrentPluginStop');
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = true;
        setBusy(true);
        try {
            const res = await call('/enabled', 'POST', {enabled: !!enabled});
            applyState(res);
            toast(enabled ? _('tp_enabled_toast') : _('tp_disabled_toast'), 'success');
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            if (startBtn) startBtn.disabled = false;
            if (stopBtn) stopBtn.disabled = false;
            setBusy(false);
        }
    }

    async function toggleEnabled(box) {
        const wanted = !!box.checked;
        box.disabled = true;
        setBusy(true);
        try {
            applyState(await call('/enabled', 'POST', {enabled: wanted}));
            toast(wanted ? _('tp_enabled_toast') : _('tp_disabled_toast'), 'success');
        } catch (err) {
            box.checked = !wanted;
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            box.disabled = false;
            setBusy(false);
        }
    }

    async function changeMode(select) {
        const proto = select.getAttribute('data-tp-proto');
        if (!proto) return;
        select.disabled = true;
        setBusy(true);
        try {
            const res = await call('/mode', 'POST', {protocol: proto, mode: select.value});
            applyState(res);
            if (res && res.errors && res.errors.length) {
                toast(_('error') + ': ' + humanError(res.errors.join('; ')), 'error');
            } else {
                toast(_('tp_saved'), 'success');
            }
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
            refreshState();
        } finally {
            if (select) select.disabled = false;
            setBusy(false);
        }
    }

    async function saveSettings() {
        const btn = document.getElementById('tpSettingsSave');
        if (btn) btn.disabled = true;
        setBusy(true);
        try {
            const payload = {
                settings: {
                    default_mode: document.getElementById('tpDefaultMode').value,
                    include_wireguard: document.getElementById('tpIncludeWireguard').checked,
                    marks_ttl_days: Number(document.getElementById('tpMarksTtl').value),
                    clear_marks_on_disable: document.getElementById('tpClearOnDisable').checked,
                    poll_seconds: Number(document.getElementById('tpPollSeconds').value),
                },
            };
            const res = await call('/settings', 'POST', payload);
            applyState(res);
            if (res && res.errors && res.errors.length) {
                toast(_('error') + ': ' + humanError(res.errors.join('; ')), 'error');
            } else {
                toast(_('tp_saved'), 'success');
            }
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            if (btn) btn.disabled = false;
            setBusy(false);
        }
    }

    async function refreshRules() {
        setBusy(true);
        try {
            const res = await call('/refresh', 'POST', {});
            applyState(res);
            if (res && res.errors && res.errors.length) {
                toast(_('error') + ': ' + humanError(res.errors.join('; ')), 'error');
            } else {
                toast(_('tp_refreshed'), 'success');
            }
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            setBusy(false);
        }
    }

    async function reapplyRules() {
        setBusy(true);
        try {
            const res = await call('/install', 'POST', {reapply: true});
            applyState(res);
            if (res && res.errors && res.errors.length) {
                toast(_('error') + ': ' + humanError(res.errors.join('; ')), 'error');
            } else {
                toast(_('tp_reapplied'), 'success');
            }
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            setBusy(false);
        }
    }

    async function clearMarks() {
        if (!confirm(_('tp_marks_clear_confirm'))) return;
        setBusy(true);
        try {
            const res = await call('/marks/clear', 'POST', {});
            applyState(await call('', 'GET'));
            toast(_('tp_marks_cleared').replace('{count}', res.removed || 0), 'success');
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
        } finally {
            setBusy(false);
        }
    }

    async function uninstall() {
        if (!confirm(_('tp_uninstall_confirm'))) return;
        setBusy(true);
        try {
            await call('/uninstall', 'POST', {});
            toast(_('tp_uninstall_done'), 'success');
            setTimeout(() => window.location.reload(), 600);
        } catch (err) {
            toast(_('error') + ': ' + humanError(err.message), 'error');
            setBusy(false);
        }
    }

    function bind() {
        const enabled = document.getElementById('tpEnabled');
        if (enabled) enabled.addEventListener('change', () => toggleEnabled(enabled));
        const settingsSave = document.getElementById('tpSettingsSave');
        if (settingsSave) settingsSave.addEventListener('click', saveSettings);
        const refresh = document.getElementById('tpRefresh');
        if (refresh) refresh.addEventListener('click', refreshRules);
        const reapply = document.getElementById('tpReapply');
        if (reapply) reapply.addEventListener('click', reapplyRules);
        const clear = document.getElementById('tpMarksClear');
        if (clear) clear.addEventListener('click', clearMarks);
        const remove = document.getElementById('tpUninstall');
        if (remove) remove.addEventListener('click', uninstall);
        document.querySelectorAll('[data-tp-proto]').forEach(select => {
            select.addEventListener('change', () => changeMode(select));
        });
    }

    function open() {
        state = window.TORRENT_PLUGIN_STATE || state;
        render();
        openModal('torrentPluginModal');
        restartPolling();
        refreshState();
    }

    function close() {
        clearInterval(pollTimer);
        pollTimer = null;
        closeModal('torrentPluginModal');
    }

    // Метки в списке подключений: ядро зовёт хук после отрисовки строк.
    function onRowsRendered(listEl, data, proto) {
        if (!listEl || !data || !Array.isArray(data.clients)) return;
        listEl.querySelectorAll('.tp-mark').forEach(el => el.remove());
        data.clients.forEach(client => {
            const events = Array.isArray(client.torrentEvents) ? client.torrentEvents : [];
            if (!events.length) return;
            const id = client.clientId || '';
            let row = null;
            if (window.CSS && CSS.escape) {
                row = listEl.querySelector('.client-item[data-client-id="' + CSS.escape(id) + '"]');
            }
            if (!row) {
                row = Array.prototype.find.call(
                    listEl.querySelectorAll('.client-item'),
                    el => el.getAttribute('data-client-id') === id);
            }
            if (!row) return;
            const meta = row.querySelector('.client-meta');
            if (!meta) return;
            const last = events[events.length - 1] || {};
            const sig = String(last.sig || 'handshake');
            const sigKey = ['handshake', 'dht_query', 'dht_short', 'tracker']
                .includes(sig) ? 'torrent_sig_' + sig : 'torrent_sig_unknown';
            const text = _('torrent_activity_text')
                .replace('{when}', when(last.ts))
                .replace('{sig}', _(sigKey))
                .replace('{count}', last.count);
            const html = '<div class="conn-warning torrent-warning tp-mark">' +
                '<span>' + esc(text) + '</span>' +
                '<button class="btn btn-secondary btn-sm btn-icon conn-warning-clear tp-mark__clear" ' +
                'data-tp-clear="' + esc(id) + '" data-tp-ip="' + esc(client.torrentIp || '') + '" ' +
                'title="' + esc(_('clear_warnings')) + '">' + (ICONS.trash || '') + '</button>' +
                '</div>';
            meta.insertAdjacentHTML('afterend', html);
        });
    }

    document.addEventListener('click', event => {
        const button = event.target.closest('[data-tp-clear]');
        if (!button) return;
        const clientId = button.getAttribute('data-tp-clear');
        const ip = button.getAttribute('data-tp-ip');
        if (!confirm(_('torrent_clear_confirm'))) return;
        button.disabled = true;
        call('/marks/clear', 'POST', {protocol: protoOfRow(button), client_id: clientId, ip: ip})
            .then(() => {
                toast(_('warnings_cleared'), 'success');
                if (typeof loadConnections === 'function') loadConnections();
                refreshState();
            })
            .catch(err => {
                button.disabled = false;
                toast(_('error') + ': ' + humanError(err.message), 'error');
            });
    });

    function protoOfRow(button) {
        const row = button.closest('.client-item');
        return (row && row.getAttribute('data-protocol')) ||
            (document.getElementById('connProtoSelect') || {}).value || '';
    }

    window.TorrentPlugin = { open, close, onRowsRendered, refresh: refreshState,
        setEnabled, uninstall };
}());
