"""Design-system regression guards (accessibility, icons, i18n, type scale)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / 'templates'
STYLE = (ROOT / 'static' / 'css' / 'style.css').read_text(encoding='utf-8')


class TestDesignSystem(unittest.TestCase):
    def test_global_focus_visible_outline(self):
        self.assertRegex(STYLE, r':focus-visible\s*\{[^}]*outline:\s*2px solid var\(--accent\)')

    def test_global_reduced_motion(self):
        blocks = STYLE.split('@media (prefers-reduced-motion: reduce)')
        self.assertGreaterEqual(len(blocks), 2, 'expected a global reduced-motion block')
        self.assertIn('animation-duration: 0.01ms !important', STYLE)
        self.assertIn('transition-duration: 0.01ms !important', STYLE)

    def test_muted_text_passes_aa_contrast(self):
        dark = STYLE.split(':root', 1)[1].split('[data-theme="light"]', 1)[0]
        self.assertIn('--text-muted: #83839c', dark)
        self.assertIn('--text-secondary: #8b8ba0', dark)
        light = STYLE.split('[data-theme="light"]', 1)[1]
        self.assertIn('--text-muted: #6b6b83', light)
        self.assertIn('--text-secondary: #5a5a78', light)

    def test_tabbar_and_section_icons_use_svg_not_emoji(self):
        for name in ('base.html', 'index.html', 'users.html', 'my_connections.html', 'settings.html'):
            src = (TEMPLATES / name).read_text(encoding='utf-8')
            self.assertNotRegex(
                src,
                r'class="tab-icon"[^>]*>\s*[^<]{1,4}\s*<',
                f'{name}: tab-icon must wrap an SVG, not an emoji',
            )
            self.assertNotRegex(
                src,
                r'class="icon">\s*[^<]{1,4}\s*<',
                f'{name}: section icon must wrap an SVG, not an emoji',
            )

    def test_icon_constants_defined(self):
        base = (TEMPLATES / 'base.html').read_text(encoding='utf-8')
        for key in (
            'ICON_SERVERS', 'ICON_USERS', 'ICON_SETTINGS', 'ICON_LINK',
            'ICON_FILE', 'ICON_PLUS', 'ICON_POWER', 'ICON_SHARE', 'ICON_LOCK',
            'ICON_GLOBE', 'ICON_KEY', 'ICON_INFO', 'ICON_REFRESH', 'ICON_COPY',
            'ICON_DOWNLOAD', 'ICON_UPLOAD', 'ICON_DOCS', 'ICON_CHECK', 'ICON_X',
        ):
            self.assertIn(f'window.{key}', base, f'missing {key}')

    def test_no_hardcoded_russian_or_telemt_labels(self):
        for name in ('users.html', 'server.html'):
            src = (TEMPLATES / name).read_text(encoding='utf-8')
            self.assertNotIn('Без срока', src)
            self.assertNotIn('Secret (Hex 32 chars)', src)
            self.assertNotIn('Max TCP Conns', src)
            self.assertNotIn('Quota (Bytes)', src)
            self.assertNotIn('Max Unique IPs', src)

    def test_translation_keys_added(self):
        import json
        for lang in ('en', 'ru'):
            d = json.loads((ROOT / 'translations' / f'{lang}.json').read_text(encoding='utf-8'))
            for key in (
                'no_expiry', 'telemt_secret_label', 'telemt_ad_tag_label',
                'telemt_max_conns_label', 'telemt_quota_label',
                'telemt_max_ips_label', 'telemt_expiry_label', 'optional',
            ):
                self.assertIn(key, d, f'{lang}.json missing {key}')

    def test_type_scale_tokens_defined(self):
        self.assertIn('--text-xs:', STYLE)
        self.assertIn('--text-sm:', STYLE)
        self.assertIn('--text-base:', STYLE)
        self.assertIn('--text-lg:', STYLE)
        self.assertIn('--text-xl:', STYLE)
        self.assertIn('--text-2xl:', STYLE)

    def test_tabular_numerics_on_metrics(self):
        self.assertRegex(STYLE, r'\.client-meta[^}]*font-variant-numeric:\s*tabular-nums')
        self.assertRegex(STYLE, r'\.ping-ms[^}]*font-variant-numeric:\s*tabular-nums')

    def test_settings_has_section_nav(self):
        settings = (TEMPLATES / 'settings.html').read_text(encoding='utf-8')
        self.assertIn('settings-nav', settings)
        self.assertIn('id="settings-appearance"', settings)
        self.assertIn('id="settings-tunnels"', settings)
        self.assertIn('id="settings-ssl"', settings)
        self.assertRegex(STYLE, r'\.settings-nav\s*\{[^}]*position:\s*sticky')


if __name__ == '__main__':
    unittest.main()
