(() => {
    const panel = document.querySelector('#xray-exits');
    if (!panel) return;
    const list = panel.querySelector('#xray-exit-list');
    const form = panel.querySelector('#xray-exit-import');
    const status = panel.querySelector('#xray-exit-status');
    const ru = panel.dataset.ru === '1';
    const translate = (russian, english) => ru ? russian : english;
    let busy = false;

    function action(label, operation, profile) {
        const button = document.createElement('button');
        button.className = 'btn btn-secondary btn-sm';
        button.type = 'button';
        button.textContent = label;
        button.addEventListener('click', () => {
            if (operation === 'activate' && !window.confirm(translate(
                'Переключить выход Xray для всех подключений? Текущие сеансы могут переподключиться.',
                'Switch the Xray exit for all connections? Active sessions may reconnect.',
            ))) return;
            if (operation === 'remove' && !window.confirm(translate('Удалить этот выход?', 'Remove this exit?'))) return;
            send(operation, { id: profile.id });
        });
        return button;
    }

    function render({ profiles }) {
        list.replaceChildren();
        for (const profile of profiles) {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;align-items:center;flex-wrap:wrap;gap:.45rem;padding:.45rem 0';
            const label = document.createElement('span');
            const name = profile.id === 'original'
                ? translate('Исходный зарубежный VPS', 'Original exit VPS')
                : profile.name;
            label.textContent = [name, profile.id !== 'original' ? profile.endpoint : '',
                profile.active ? translate('активен', 'active') : '',
                profile.check ? `${profile.check.ip} · handshake ${new Date(profile.check.handshake * 1000).toLocaleString()}` : '',
            ].filter(Boolean).join(' · ');
            row.append(label, action(translate('Проверить', 'Test'), 'test', profile));
            if (!profile.active) {
                row.append(action(translate('Сделать активным', 'Activate'), 'activate', profile));
                if (profile.id !== 'original') row.append(action(translate('Удалить', 'Remove'), 'remove', profile));
            }
            list.append(row);
        }
    }

    async function send(operation, fields = {}) {
        if (busy) return;
        busy = true;
        panel.querySelectorAll('button').forEach(button => button.disabled = true);
        status.textContent = translate('Выполняется…', 'Working…');
        try {
            const response = await fetch(panel.dataset.url, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({operation, ...fields}),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || data.detail || response.statusText);
            render(data);
            if (operation === 'import') form.reset();
            status.textContent = operation === 'list' ? '' : translate('Готово.', 'Done.');
        } catch (error) {
            status.textContent = error.message;
        } finally {
            busy = false;
            panel.querySelectorAll('button').forEach(button => button.disabled = false);
        }
    }

    panel.addEventListener('toggle', () => { if (panel.open) send('list'); });
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const file = form.elements.conf.files[0];
        if (!file || file.size > 12000) {
            status.textContent = translate('Выбери .conf до 12 КБ.', 'Choose a .conf up to 12 KB.');
            return;
        }
        send('import', {name: form.elements.name.value, config: await file.text()});
    });
})();
