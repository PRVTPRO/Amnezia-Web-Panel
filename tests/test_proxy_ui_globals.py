"""Регрессии JS раздела «Прокси»: неопределённые функции ломают карточку.

Инцидент 2026-11-20: в проде нажатие «Учётные записи» давало
`uiIcon is not defined` — код писали на локальной ветке v1.8.11, где
глобальный uiIcon() есть, а прод-сборка v1.8.14 его не определяет.
Тест рендерит реальную страницу сервера и проверяет, что каждая функция
раздела «Прокси» объявлена в этой же странице.
"""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'templates' / 'server.html'

# Вызовы вида proxyFoo(...) в коде раздела «Прокси».
PROXY_CALL_RE = re.compile(r'\b(proxy[A-Z][A-Za-z0-9_]*)\s*\(')
DEFINITION_RES = (
    re.compile(r'\bfunction\s+(proxy[A-Z][A-Za-z0-9_]*)\s*\('),
    re.compile(r'\b(?:const|let|var)\s+(proxy[A-Z][A-Za-z0-9_]*)\s*='),
    re.compile(r'\b(proxy[A-Z][A-Za-z0-9_]*)\s*=\s*function'),
)


def _strip_js_comments(source):
    """Убирает // и /* */ комментарии, чтобы не ловить имена в тексте."""
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.S)
    lines = []
    for line in source.splitlines():
        # `//` внутри строкового литерала не трогаем: адресов в этом коде нет.
        idx = line.find('//')
        lines.append(line if idx < 0 else line[:idx])
    return '\n'.join(lines)


class ProxyJsGlobalsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        data_file = Path(cls.tmp.name) / 'data.json'
        seed = {
            'servers': [{'name': 'TEST', 'host': '192.0.2.1', 'protocols': {}}],
            'users': [{'id': 'admin-id', 'username': 'admin',
                       'password_hash': app.hash_password('admin'),
                       'role': 'admin', 'enabled': True}],
            'user_connections': [], 'settings': {}, 'api_tokens': [],
        }
        data_file.write_text(json.dumps(seed), encoding='utf-8')
        with patch.object(app, 'DATA_FILE', str(data_file)):
            with TestClient(app.app) as client:
                login = client.post('/api/auth/login',
                                    json={'username': 'admin', 'password': 'admin',
                                          'captcha': None})
                assert login.status_code == 200, login.text
                page = client.get('/server/0')
                assert page.status_code == 200, page.text
                cls.html = page.text

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_proxy_block_does_not_use_undefined_ui_icon(self):
        """uiIcon() есть только в локальной ветке; прод его не определяет.

        Проверяем именно блок раздела «Прокси»: остальная страница может
        законно пользоваться своим uiIcon().
        """
        lines = self.html.splitlines()
        start = next((i for i, line in enumerate(lines)
                      if 'Иконки раздела «Прокси»' in line), -1)
        self.assertGreaterEqual(start, 0, 'не найден блок иконок прокси')
        end = next((i for i, line in enumerate(lines[start:], start)
                    if 'Deep link from the users page' in line), len(lines))
        block = _strip_js_comments('\n'.join(lines[start:end]))
        self.assertNotIn('uiIcon(', block,
                         'раздел «Прокси» не должен звать глобальный uiIcon()')
        self.assertIn('function proxyIcon(', block)

    def test_every_proxy_function_is_defined_on_the_page(self):
        code = _strip_js_comments(self.html)
        called = set(PROXY_CALL_RE.findall(code))
        defined = set()
        for pattern in DEFINITION_RES:
            defined.update(pattern.findall(code))
        undefined = sorted(called - defined)
        self.assertEqual(undefined, [],
                         f'вызовы без объявления на странице: {undefined}')

    def test_template_uses_proxy_icon_helper(self):
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('function proxyIcon(', source)
        self.assertIn("proxyIcon('key', 15)", source)

    def test_listener_type_is_a_segment_control(self):
        """Тип листенера — радиокнопки SOCKS5/HTTP/Оба вместо чекбокса."""
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('name="proxyListenerType"', source)
        for radio in ('proxyListenerSocks', 'proxyListenerHttp', 'proxyListenerBoth'):
            self.assertIn(f'id="{radio}"', source)
        self.assertIn('class="seg-group"', source)
        self.assertNotIn('id="proxyHttpEnabled"', source)
        # Выключенный листенер порт не держит: поле и «Проверить» недоступны,
        # значение при этом сохраняется для обратного переключения.
        start = source.index('function syncProxyListenerPorts(')
        body = source[start:start + 900]
        self.assertIn('socksInput.disabled = socksOff', body)
        self.assertIn('httpInput.disabled = httpOff', body)

    def test_one_universal_entity_list(self):
        """Один контейнер и один список на клиентов и учётки прокси."""
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('id="entityListSection"', source)
        self.assertIn('id="entityListInner"', source)
        self.assertIn('function showEntityList(', source)
        for legacy in ('id="connectionsSection"', 'id="proxyAccountsSection"',
                       'id="connectionsListInner"', 'id="proxyAccountsList"'):
            self.assertNotIn(legacy, source, f'{legacy} остался — списки разъедутся')
        # Сортировка общая: строка учётки выставляет те же data-sort-*, что пир.
        for attr in ('data-sort-name', 'data-sort-created', 'data-sort-total',
                     'data-sort-ip', 'data-sort-quota', 'data-sort-maxspeed',
                     'data-sort-rx', 'data-sort-tx', 'data-sort-handshake'):
            self.assertIn(attr, source)
        self.assertIn('function applyEntitySearch(', source)

    def test_progress_toast_component_is_used_by_saving(self):
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('function startProgressToast(', source)
        for klass in ('peer-queue-head', 'peer-queue-percent',
                      'peer-queue-track', 'peer-queue-fill', 'peer-queue-error'):
            self.assertIn(klass, source)
        # Сохранение настроек закрывает модалки только по успеху.
        body = source[source.index('async function submitProxySettings('):]
        body = body[:body.index('\n    }', body.index('finally'))]
        self.assertIn('closeModal(', body)
        self.assertIn('if (ok)', body)
        # Учётка: спиннер в кнопке модалки и прогресс на удаление/toggle.
        for fn in ('submitProxyAccount', 'deleteProxyAccount', 'toggleProxyAccount'):
            start = source.index(f'async function {fn}(')
            chunk = source[start:start + 1600]
            self.assertIn('startProgressToast(', chunk, f'{fn}: нет прогресс-тоста')

    def test_only_one_list_is_visible_at_a_time(self):
        """Прокси ведёт себя как обычный инстанс: список либо клиенты
        инстанса, либо учётки прокси, но не оба сразу."""
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('function setActiveList(', source)
        # Оба способа показа обязаны идти через один переключатель.
        for opener in ('showConnectionsSection', 'showProxyAccounts',
                       'selectProtocolForConns'):
            start = source.index(f'function {opener}(')
            body = source[start:start + 700]
            self.assertIn('setActiveList(', body,
                          f'{opener} обходит setActiveList — списки разъедутся')
        # Автопоказ прокси при /check не должен всплывать сам.
        sync_start = source.index('function syncProxySection(')
        sync_body = source[sync_start:sync_start + 700]
        self.assertNotIn("classList.remove('hidden')", sync_body)
        self.assertIn("setActiveList('none')", sync_body)


class ProxyNamingAndCardTests(unittest.TestCase):
    """Название 3proxy и данные карточки из /check (инцидент 21.11)."""

    def test_protocol_is_named_3proxy_everywhere(self):
        from protocol_names import protocol_display_name
        import telegram_bot
        self.assertEqual(protocol_display_name('socks5'), '3proxy')
        self.assertEqual(
            telegram_bot._protocol_display_name('socks5', {'protocols': {}}), '3proxy')
        source = TEMPLATE.read_text(encoding='utf-8')
        self.assertNotIn('SOCKS5 Proxy', source)
        self.assertIn('<div class="protocol-name">3proxy</div>', source)
        self.assertIn("title: '3proxy'", source)

    def test_card_takes_accounts_and_dns_from_check_before_status(self):
        """Первый кадр: /proxy/status ещё не ответил, а /check уже отдал
        счётчик учёток и DNS — карточка не должна показывать 0 и «—»."""
        source = TEMPLATE.read_text(encoding='utf-8')
        start = source.index('function proxyCardInfo(')
        body = source[start:start + 1200]
        self.assertIn('info.accounts_count', body)
        self.assertIn('info.dns_servers', body)

    def test_sync_proxy_section_loads_status(self):
        """Без загрузки /proxy/status счётчик учёток и DNS оставались пустыми
        до клика по «Учётные записи»."""
        source = TEMPLATE.read_text(encoding='utf-8')
        start = source.index('function syncProxySection(')
        body = source[start:start + 900]
        self.assertIn('loadProxyStatus(', body)

    def test_force_reload_waits_for_inflight_request(self):
        """force после мутации не должен возвращать снимок, снятый до неё."""
        source = TEMPLATE.read_text(encoding='utf-8')
        start = source.index('function loadProxyStatus(')
        body = source[start:start + 700]
        self.assertIn('if (!force) return proxyStatusLoading;', body)
        self.assertIn('loadProxyStatus(true)', body)

    def test_refresh_draws_without_check_payload(self):
        source = TEMPLATE.read_text(encoding='utf-8')
        start = source.index('function refreshProxyCardInfo(')
        body = source[start:start + 500]
        self.assertIn("(currentProtocolStatus || {}).socks5 || {}", body)


    def test_proxy_ui_icons_are_declared(self):
        """ui_icon()/proxyIcon() молча рисуют пустой svg для неизвестного имени."""
        source = TEMPLATE.read_text(encoding='utf-8')
        icons = (TEMPLATE.parent / '_ui_icons.html').read_text(encoding='utf-8')
        # Иконки, которые использует раздел «Прокси».
        for name in ('network', 'plus', 'gauge', 'help'):
            self.assertIn(f"'{name}':", icons, f'ui_icon({name}) не объявлена')
        proxy_block = source[source.index('const PROXY_ICONS = {'):
                             source.index('function proxyIcon(')]
        for name in sorted(set(re.findall(r"proxyIcon\('([^']+)'", source))):
            self.assertIn(f'{name}:', proxy_block, f'proxyIcon({name}) не объявлена')

    def test_avatar_dot_reflects_real_activity(self):
        """Зелёная точка — активность в логе, а не просто enabled."""
        source = TEMPLATE.read_text(encoding='utf-8')
        start = source.index('function proxyAccountRow(')
        body = source[start:start + 1800]
        self.assertIn('account.online === true', body)
        self.assertNotIn("else avatarClass += ' avatar-online'", body)
        self.assertIn('last_seen', body)

if __name__ == '__main__':
    unittest.main()
