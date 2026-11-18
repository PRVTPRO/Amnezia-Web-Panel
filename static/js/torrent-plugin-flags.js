/* Плитки торрент-активности на дашборде.
 *
 * Подключается только когда плагин «Защита от торрентов» установлен хотя бы
 * на одном сервере (templates/index.html). Без плагина на главной нет ни
 * контейнеров плиток, ни этого файла, ни опроса /api/plugins/.../flags.
 */
(function () {
    'use strict';

    const cfg = window.TORRENT_ALERTS || {};
    if (!cfg.endpoint || typeof apiCall !== 'function') return;
    const label = (cfg.i18n && cfg.i18n.badge) || 'Torrents';
    const errorLabel = (cfg.i18n && cfg.i18n.error) || 'Error';

    function hide(el) {
        el.classList.remove('is-visible');
        el.innerHTML = '';
    }

    function render(flags) {
        document.querySelectorAll('.tp-alert').forEach(hide);
        Object.keys(flags || {}).forEach(id => {
            const el = document.getElementById('torrent-alert-' + id);
            if (!el) return;
            const entries = Object.entries(flags[id] || {});
            if (!entries.length) return;
            let total = 0;
            entries.forEach(([, item]) => { total += Number(item && item.events) || 0; });
            const first = entries[0];
            const proto = first[0];
            const data = first[1] || {};
            let url = '/server/' + id + '?protocol=' + encodeURIComponent(proto);
            if (data.client_id) url += '&highlight=' + encodeURIComponent(data.client_id);
            const button = document.createElement('button');
            button.className = 'btn btn-danger btn-sm tp-alert__btn';
            button.textContent = label + ' (' + total + ')';
            button.addEventListener('click', () => { window.location.href = url; });
            el.innerHTML = '';
            el.appendChild(button);
            el.classList.add('is-visible');
        });
    }

    function load() {
        apiCall(cfg.endpoint, 'GET')
            .then(res => render((res && res.flags) || {}))
            .catch(err => console.warn(errorLabel + ': ' + err.message));
    }

    load();
    setInterval(load, 60000);
}());
