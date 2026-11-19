"""Полнота словаря переводов: каждый ключ, который спрашивает UI, есть в каждой локали.

Почему это нужно: `_t()` в app.py и `window._` в base.html возвращают сам ключ,
если его нет в словаре (`lang_batch.get(text_id, text_id)`). Молчаливая потеря
ключей выглядит как текст `diag_title` на кнопке, а не как ошибка.

Запуск на рабочей копии: python translation_keys.py
Запуск на живой панели:  python3 translation_keys.py /root/Amnezia-Web-Panel
Код возврата 1, если есть пропуски.
"""
import json
import pathlib
import re
import sys

KEY_RE = re.compile(r"""_\(\s*['"]([A-Za-z0-9_]+)['"]""")
# Ключи, которые UI не рендерит, а панель отдаёт текстом: ошибки, письма.
PY_KEY_RE = re.compile(r"""_t\(\s*['"]([A-Za-z0-9_]+)['"]""")
SKIP_MARKS = ('.bak.', '.old-', '/vendor/')
# Ключи, которых в словаре нет намеренно: код собирает их из префикса
# (`mail_status_` + статус), а у `saved` есть fallback в самом шаблоне.
SKIP_KEYS = {'saved'}


def collect_used(root):
    """Ключи из `_()` в шаблонах/JS и из `_t()` в Python: {ключ: {файлы}}."""
    root = pathlib.Path(root)
    used = {}
    sources = (
        (root / 'templates', '**/*.html', KEY_RE),
        (root / 'static' / 'js', '*.js', KEY_RE),
        (root, '*.py', PY_KEY_RE),
        (root / 'managers', '*.py', PY_KEY_RE),
    )
    for folder, pattern, regex in sources:
        for path in folder.glob(pattern):
            marker = str(path).replace('\\', '/')
            if any(mark in marker for mark in SKIP_MARKS):
                continue
            text = path.read_text(encoding='utf-8', errors='ignore')
            for key in regex.findall(text):
                used.setdefault(key, set()).add(path.name)
    return {key: files for key, files in used.items()
            if not key.endswith('_') and key not in SKIP_KEYS}


def missing(root):
    """{локаль: [ключи, которых нет]} для всех переводов в root/translations."""
    root = pathlib.Path(root)
    used = collect_used(root)
    gaps = {}
    for locale_file in sorted((root / 'translations').glob('*.json')):
        data = json.loads(locale_file.read_text(encoding='utf-8'))
        absent = sorted(key for key in used if key not in data)
        if absent:
            gaps[locale_file.stem] = absent
    return gaps


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    gaps = missing(root)
    used = collect_used(root)
    print('%s: ключей в UI %d, локалей %d' % (
        root, len(used), len(list(pathlib.Path(root).glob('translations/*.json')))))
    for locale, keys in gaps.items():
        print('%-4s отсутствуют %d: %s' % (locale, len(keys), ', '.join(keys[:10])))
    print('ИТОГ:', 'есть пропуски' if gaps else 'все ключи на месте')
    return 1 if gaps else 0


if __name__ == '__main__':
    sys.exit(main())
