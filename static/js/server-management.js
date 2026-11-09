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

    function render() {
        const el = document.getElementById('serverManagementContent');
        if (!el || !context) return;
        const cooldown = Number(context.sshCooldown || 30);
        const poll = Number(context.peerPollInterval || 0);
        el.innerHTML = `
            <div class="flex" style="flex-direction: column; gap: var(--space-sm);">
                <button class="btn btn-secondary" data-server-management-action="check" style="justify-content: flex-start; padding: 12px 20px;">
                    <span style="font-size: 1.2rem; margin-right: 8px;">🔄</span> ${_('check_server_services')}
                </button>
                <button class="btn btn-secondary" data-server-management-action="reboot" style="justify-content: flex-start; padding: 12px 20px;">
                    <span style="font-size: 1.2rem; margin-right: 8px;">🔁</span> ${_('reboot_server')}
                </button>
                <button class="btn btn-danger" data-server-management-action="clear" style="justify-content: flex-start; padding: 12px 20px;">
                    <span style="font-size: 1.2rem; margin-right: 8px;">🧹</span> ${_('clear_server')}
                </button>
                <button class="btn btn-danger" data-server-management-action="remove" style="justify-content: flex-start; padding: 12px 20px;">
                    <span class="btn-text-with-icon">${ICON_TRASH}</span> ${_('remove_server')}
                </button>
                <div style="margin-top: var(--space-md); padding-top: var(--space-md); border-top: 1px solid var(--border);">
                    <label for="sshCooldownInput" style="display:block; font-size:0.85rem; margin-bottom:6px;">${_('ssh_cooldown_title')}</label>
                    <div class="flex" style="gap:8px;">
                        <input class="form-input" id="sshCooldownInput" type="number" min="5" max="300" step="1" value="${cooldown}" style="max-width:120px;">
                        <button class="btn btn-secondary btn-sm" data-server-management-action="save-cooldown" id="sshCooldownSaveBtn">💾</button>
                    </div>
                    <div class="text-muted" style="font-size:0.78rem; margin-top:6px;">${_('ssh_cooldown_hint')}</div>
                </div>
                <div style="margin-top: var(--space-md); padding-top: var(--space-md); border-top: 1px solid var(--border);">
                    <label for="peerPollSelect" style="display:block; font-size:0.85rem; margin-bottom:6px;">${_('peer_poll_title')}</label>
                    <div class="flex" style="gap:8px;">
                        <select class="form-select" id="peerPollSelect" style="max-width:160px;">
                            ${POLL_STEPS.map(seconds => `<option value="${seconds}"${seconds === poll ? ' selected' : ''}>${seconds === 0 ? _('peer_poll_off') : seconds + ' ' + _('peer_poll_sec')}</option>`).join('')}
                        </select>
                        <button class="btn btn-secondary btn-sm" data-server-management-action="save-poll" id="peerPollSaveBtn">💾</button>
                    </div>
                    <div class="text-muted" style="font-size:0.78rem; margin-top:6px;">${_('peer_poll_hint')}</div>
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
        closeModal('serverManagementModal');
        if (!confirm(_('reboot_server_confirm'))) return;
        try {
            notify(_('rebooting_server'), 'info');
            await api()(`/api/servers/${context.serverId}/reboot`, 'POST');
            notify(_('server_rebooting'), 'success');
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function clearServer() {
        closeModal('serverManagementModal');
        if (!confirm(_('clear_server_confirm'))) return;
        try {
            notify(_('clearing_server'), 'info');
            await api()(`/api/servers/${context.serverId}/clear?server_uid=${selectedUid()}`, 'POST');
            notify(_('server_cleared'), 'success');
            setTimeout(() => window.location.reload(), 500);
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function removeServer() {
        closeModal('serverManagementModal');
        if (!confirm(_('remove_server_confirm'))) return;
        const base = `/api/servers/${context.serverId}/delete?server_uid=${selectedUid()}&panel_only=true`;
        try {
            const result = await api()(base, 'POST');
            if (result && result.archived) {
                notify(_('delete_server_archived').replace('{count}', result.archived), 'success');
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
            notify('✓', 'success');
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
            notify('✓', 'success');
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
