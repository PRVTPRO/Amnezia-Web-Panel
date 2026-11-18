(function () {
    'use strict';

    const POLL_STEPS = [0, 5, 10, 15, 20, 45, 120, 300, 600];
    let context = null;

    function api() {
        return context && context.apiCall ? context.apiCall : window.apiCall;
    }

    function notify(message, kind) {
        const toast = context && context.showToast ? context.showToast : window.showToast;
        toast(message, kind);
    }

    function selectedUid() {
        return encodeURIComponent(context.serverUid || '');
    }

    // Идентичность сервера добавляется в query только когда uid известен:
    // пустой `?server_uid=` бэкенд трактует как «сервер подменили» (409).
    function withServerUid(url) {
        const uid = selectedUid();
        return uid ? `${url}?server_uid=${uid}` : url;
    }

    function extraParam(url, name, value) {
        return `${url}${url.indexOf('?') === -1 ? '?' : '&'}${name}=${value}`;
    }

    // Иконки берём из реестра templates/_ui_icons.html (window.SM_ICONS
    // выставляет модалка). Эмодзи в интерфейсе не используем: они цветные,
    // игнорируют currentColor и по-разному выглядят в темах и ОС.
    function icon(name, size) {
        const set = (typeof window !== 'undefined' && window.SM_ICONS) || {};
        return '<svg class="ui-icon" width="' + size + '" height="' + size + '"'
            + ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
            + ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"'
            + ' focusable="false">' + (set[name] || '') + '</svg>';
    }

    function render() {
        const el = document.getElementById('serverManagementContent');
        if (!el || !context) return;
        const rawCooldown = Number(context.sshCooldown);
        const rawPoll = Number(context.peerPollInterval);
        const cooldown = Number.isFinite(rawCooldown) ? rawCooldown : 30;
        const poll = Number.isFinite(rawPoll) ? rawPoll : 0;
        let pollOptions = POLL_STEPS.map(seconds => `<option value="${seconds}"${seconds === poll ? ' selected' : ''}>${seconds === 0 ? _('peer_poll_off') : seconds + ' ' + _('peer_poll_sec')}</option>`).join('');
        if (!POLL_STEPS.includes(poll)) {
            // Устаревшее значение в data.json вне списка: показываем его как
            // есть. Иначе браузер выберет первую опцию (0 = выключено), и
            // «Сохранить» без касания селекта молча запишет выключение.
            pollOptions += `<option value="${poll}" selected>${poll} ${_('peer_poll_sec')}</option>`;
        }
        el.innerHTML = `
            <div class="sm-stack">
                <button class="btn btn-secondary sm-action" data-server-management-action="check">
                    <span class="btn-text-with-icon">${icon('refresh', 16)} ${_('check_server_services')}</span>
                </button>
                <button class="btn btn-secondary sm-action" data-server-management-action="reboot">
                    <span class="btn-text-with-icon">${icon('power', 16)} ${_('reboot_server')}</span>
                </button>
                <button class="btn btn-danger sm-action" data-server-management-action="clear">
                    <span class="btn-text-with-icon">${icon('eraser', 16)} ${_('clear_server')}</span>
                </button>
                <button class="btn btn-danger sm-action" data-server-management-action="remove">
                    <span class="btn-text-with-icon">${icon('trash', 16)} ${_('remove_server')}</span>
                </button>
                <div class="sm-section">
                    <label for="sshCooldownInput" class="sm-field-label">${_('ssh_cooldown_title')}</label>
                    <div class="sm-row">
                        <input class="form-input sm-number" id="sshCooldownInput" type="number" min="5" max="300" step="1" value="${cooldown}">
                        <button class="btn btn-secondary btn-sm btn-icon" data-server-management-action="save-cooldown" id="sshCooldownSaveBtn" title="${_('save')}" aria-label="${_('save')}">${icon('save', 16)}</button>
                    </div>
                    <div class="text-muted sm-hint">${_('ssh_cooldown_hint')}</div>
                </div>
                <div class="sm-section">
                    <label for="peerPollSelect" class="sm-field-label">${_('peer_poll_title')}</label>
                    <div class="sm-row">
                        <select class="form-select sm-select" id="peerPollSelect">
                            ${pollOptions}
                        </select>
                        <button class="btn btn-secondary btn-sm btn-icon" data-server-management-action="save-poll" id="peerPollSaveBtn" title="${_('save')}" aria-label="${_('save')}">${icon('save', 16)}</button>
                    </div>
                    <div class="text-muted sm-hint">${_('peer_poll_hint')}</div>
                </div>
            </div>`;
    }

    async function checkServer() {
        closeModal('serverManagementModal');
        if (typeof context.onCheck === 'function') {
            await context.onCheck();
            return;
        }
        try {
            await api()(`/api/servers/${context.serverId}/check`, 'POST');
            notify(_('success'), 'success');
            setTimeout(() => window.location.reload(), 500);
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function rebootServer() {
        // confirm() спрашиваем ДО закрытия: отмена не должна оставлять
        // пользователя с уже закрытой модалкой.
        if (!confirm(_('reboot_server_confirm'))) return;
        closeModal('serverManagementModal');
        try {
            notify(_('rebooting_server'), 'info');
            await api()(`/api/servers/${context.serverId}/reboot`, 'POST');
            notify(_('server_rebooting'), 'success');
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function clearServer() {
        if (!confirm(_('clear_server_confirm'))) return;
        closeModal('serverManagementModal');
        try {
            notify(_('clearing_server'), 'info');
            await api()(withServerUid(`/api/servers/${context.serverId}/clear`), 'POST');
            notify(_('server_cleared'), 'success');
            setTimeout(() => window.location.reload(), 500);
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function removeServer() {
        if (!confirm(_('remove_server_confirm'))) return;
        closeModal('serverManagementModal');
        let url = withServerUid(`/api/servers/${context.serverId}/delete`);
        url = extraParam(url, 'panel_only', 'true');
        try {
            const result = await api()(url, 'POST');
            if (result && result.archived) {
                // Уходим на главную не мгновенно: иначе тост об архивации
                // уничтожается навигацией и пользователь его не увидит.
                notify(_('delete_server_archived').replace('{count}', result.archived), 'success');
                setTimeout(() => { window.location.href = '/'; }, 1200);
                return;
            }
            window.location.href = '/';
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function saveCooldown() {
        const input = document.getElementById('sshCooldownInput');
        const button = document.getElementById('sshCooldownSaveBtn');
        const seconds = Number(input && input.value);
        if (!Number.isFinite(seconds) || seconds < 5 || seconds > 300) {
            notify(_('ssh_cooldown_title') + ': 5–300', 'error');
            return;
        }
        if (button) button.disabled = true;
        try {
            const result = await api()(`/api/servers/${context.serverId}/ssh_cooldown`, 'POST', {seconds});
            context.sshCooldown = result.ssh_cooldown_base;
            if (typeof context.onCooldownChange === 'function') context.onCooldownChange(result.ssh_cooldown_base);
            notify(icon('check', 14), 'success');
        } catch (error) {
            notify(_('error') + ': ' + error.message, 'error');
        } finally {
            if (button) button.disabled = false;
        }
    }

    async function savePoll() {
        const select = document.getElementById('peerPollSelect');
        const button = document.getElementById('peerPollSaveBtn');
        const seconds = Number(select && select.value);
        if (!POLL_STEPS.includes(seconds)) {
            notify(_('peer_poll_title') + ': ' + POLL_STEPS.join('/'), 'error');
            return;
        }
        if (button) button.disabled = true;
        try {
            const result = await api()(`/api/servers/${context.serverId}/peer_poll_interval`, 'POST', {seconds});
            context.peerPollInterval = result.peer_poll_interval;
            if (typeof context.onPollChange === 'function') context.onPollChange(result.peer_poll_interval);
            notify(icon('check', 14), 'success');
        } catch (error) {
            notify(_('error') + ': ' + error.message, 'error');
        } finally {
            if (button) button.disabled = false;
        }
    }

    document.addEventListener('click', event => {
        const button = event.target.closest('[data-server-management-action]');
        if (!button || !context) return;
        const actions = {
            check: checkServer,
            reboot: rebootServer,
            clear: clearServer,
            remove: removeServer,
            'save-cooldown': saveCooldown,
            'save-poll': savePoll,
        };
        const action = actions[button.dataset.serverManagementAction];
        if (action) action();
    });

    window.ServerManagement = {
        open(options) {
            context = Object.assign({}, options);
            render();
            openModal('serverManagementModal');
        },
    };
}());
