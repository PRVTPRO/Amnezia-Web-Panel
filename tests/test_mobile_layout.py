"""Regression guards for mobile layout fixes and CSS layer markers."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / 'templates'
STYLE = (ROOT / 'static' / 'css' / 'style.css').read_text(encoding='utf-8')


class TestMobileLayout(unittest.TestCase):
    def test_no_minmax_400_in_templates(self):
        for path in TEMPLATES.glob('*.html'):
            src = path.read_text(encoding='utf-8')
            self.assertNotIn(
                'minmax(400px',
                src,
                f'{path.name} still has minmax(400px) grid',
            )

    def test_server_html_no_nowrap_important(self):
        src = (TEMPLATES / 'server.html').read_text(encoding='utf-8')
        self.assertNotIn('flex-wrap: nowrap !important', src)

    def test_no_inline_1fr_1fr_grids(self):
        for name in ('users.html', 'my_connections.html', 'settings.html'):
            src = (TEMPLATES / name).read_text(encoding='utf-8')
            self.assertNotIn(
                'grid-template-columns: 1fr 1fr',
                src,
                f'{name} still has inline 1fr 1fr grid',
            )

    def test_style_css_mobile_layer_markers(self):
        self.assertIn('/* ===== Mobile & PWA layer ===== */', STYLE)
        for marker in (
            '.mobile-tabbar',
            '.cards-grid-2',
            '.grid-2',
            '.grid-expiry',
            '.btn-group-3',
            '.toolbar-search',
            'env(safe-area-inset-bottom)',
            'touch-action: manipulation',
        ):
            self.assertIn(marker, STYLE, f'missing CSS marker {marker}')

    def test_dead_stats_grid_removed(self):
        self.assertNotIn('.stats-grid', STYLE)

    def test_base_has_tabbar_and_qr_helper(self):
        base = (TEMPLATES / 'base.html').read_text(encoding='utf-8')
        self.assertIn('mobile-tabbar', base)
        self.assertIn('window.qrSize', base)
        self.assertIn('.tab-item', base)

    def test_logout_uses_visible_icon_not_btn_before(self):
        """Logout must not rely on .btn::before (hover overlay has opacity:0)."""
        base = (TEMPLATES / 'base.html').read_text(encoding='utf-8')
        self.assertIn('nav-logout', base)
        self.assertIn('nav-logout-icon', base)
        self.assertNotIn(".nav-user .btn::before", STYLE)
        self.assertIn('.nav-logout-icon', STYLE)

    def test_app_container_does_not_trap_modal_stacking(self):
        """Page modals live inside .app-container; z-index there hides them under the tabbar."""
        # Match only a real property declaration, not comments mentioning z-index.
        self.assertNotRegex(
            STYLE,
            r'\.app-container\s*\{[^}]*?\bz-index\s*:',
            '.app-container must not set z-index (traps modal stacking vs tabbar)',
        )

    def test_mobile_modal_covers_tabbar_and_full_width(self):
        self.assertIn('max-width: 100% !important', STYLE)
        self.assertIn('.tab-icon', STYLE)
        # Tab icons need an explicit box; blur lives on ::before so glyphs are not clipped
        self.assertRegex(
            STYLE,
            r'\.tab-icon\s*\{[^}]*height:\s*1\.75em',
        )
        self.assertRegex(
            STYLE,
            r'\.mobile-tabbar\s*\{[^}]*overflow:\s*visible',
        )
        self.assertIn('.mobile-tabbar::before', STYLE)

    def test_manage_link_has_no_inline_flex(self):
        src = (TEMPLATES / 'index.html').read_text(encoding='utf-8')
        self.assertNotIn('style="flex:1"', src)
        self.assertIn('btn-icon-svg', src)

    def test_no_trash_pencil_emoji_in_icon_buttons(self):
        for path in TEMPLATES.glob('*.html'):
            src = path.read_text(encoding='utf-8')
            self.assertIsNone(
                re.search(r'btn-icon[^>]*>\s*[🗑🗑️✏️📝]', src),
                f'{path.name} still uses trash/pencil emoji in a btn-icon',
            )

    def test_shared_svg_icon_constants(self):
        base = (TEMPLATES / 'base.html').read_text(encoding='utf-8')
        self.assertIn('window.ICON_TRASH', base)
        self.assertIn('window.ICON_PENCIL', base)
        self.assertIn('btn-icon-svg', base)

    def test_mobile_forms_tightened(self):
        self.assertIn('awp-mobile-tight-v2', STYLE)
        self.assertRegex(
            STYLE,
            r'\.form-label\s*\{[^}]*font-size:\s*0\.8rem',
        )
        self.assertRegex(
            STYLE,
            r'\.form-input,\s*\n\s*\.form-select,\s*\n\s*\.form-textarea\s*\{[^}]*min-height:\s*42px',
        )
        # Cancel + Connect stay on one row
        footer_blocks = list(re.finditer(
            r'\.modal-footer\s*\{([^}]+)\}',
            STYLE,
        ))
        self.assertTrue(footer_blocks)
        last = footer_blocks[-1].group(1)
        self.assertIn('flex-direction: row', last)

    def test_mobile_header_safe_area_without_double_padding(self):
        """Sticky header owns safe-area; container must not also pad the top."""
        self.assertIn('padding-top: 0', STYLE)
        self.assertIn('calc(env(safe-area-inset-top, 0px) + 10px)', STYLE)
        # Negative full-bleed margins make the page wider than the phone viewport
        self.assertNotIn('margin-left: calc(-1 * var(--space-md))', STYLE)

    def test_mobile_modal_is_centered_not_bottom_docked(self):
        """Edit/add forms must not sit flush at the bottom edge on phones."""
        backdrop_blocks = list(re.finditer(
            r'\.modal-backdrop\s*\{([^}]+)\}',
            STYLE,
        ))
        self.assertTrue(backdrop_blocks)
        last = backdrop_blocks[-1].group(1)
        self.assertIn('align-items: center', last)
        self.assertNotIn('align-items: flex-end', last)
        self.assertNotIn('.modal::before', STYLE)

    def test_custom_scrollbar_only_on_fine_pointer(self):
        """Custom ::-webkit-scrollbar must not apply on touch (Pixel side slider)."""
        self.assertIn('@media (hover: hover) and (pointer: fine)', STYLE)
        self.assertRegex(
            STYLE,
            r'@media \(hover: hover\) and \(pointer: fine\)\s*\{[^}]*::-webkit-scrollbar\s*\{',
        )
        mobile_layer = STYLE.split('/* ===== Mobile & PWA layer ===== */', 1)[-1]
        self.assertNotRegex(
            mobile_layer,
            r'::-webkit-scrollbar\s*\{[^}]*width:\s*6px',
        )

    def test_touch_hides_scrollbar_gutters(self):
        self.assertIn('@media (hover: none), (pointer: coarse)', STYLE)
        self.assertIn('overflow-y: auto', STYLE)

    def test_inputs_cannot_blow_out_phone_width(self):
        """Long bot tokens / URLs must shrink inside the card on Pixel-width screens."""
        self.assertRegex(
            STYLE,
            r'\.form-input,\s*\n\s*\.form-select,\s*\n\s*\.form-textarea\s*\{[^}]*min-width:\s*0',
        )

    def test_grid_children_cannot_blow_out_phone_width(self):
        """Stacked settings columns must shrink around long token inputs on phones."""
        settings = (TEMPLATES / 'settings.html').read_text(encoding='utf-8')
        self.assertIn('settings-grid', settings)
        self.assertNotRegex(STYLE, r'\.grid-2\s*>\s*\*\s*\{')
        self.assertRegex(
            STYLE,
            r'\.settings-grid\s*>\s*\*\s*\{[^}]*min-width:\s*0',
        )

    def test_mobile_full_width_buttons_are_opt_in(self):
        """Users toolbar/actions must not inherit full-width button styling."""
        mobile_layer = STYLE.split('/* ===== Mobile & PWA layer ===== */', 1)[-1]
        self.assertNotIn('.btn.btn-primary', mobile_layer)
        self.assertNotIn('.row-between .btn', mobile_layer)
        self.assertIn('.btn-full-mobile .btn', mobile_layer)

    def test_user_cards_have_tight_height(self):
        """User cards must not reserve empty vertical space for optional data."""
        users = (TEMPLATES / 'users.html').read_text(encoding='utf-8')
        self.assertIn('user-card', users)
        self.assertIn('user-card-body', users)
        self.assertNotRegex(STYLE, r'\.user-card\s*\{[^}]*min-height:\s*220px')
        self.assertNotRegex(STYLE, r'\.user-card-body\s*\{[^}]*min-height')
        self.assertRegex(
            STYLE,
            r'\.user-card\s+\.client-actions\s*\{[^}]*margin-top:\s*var\(--space-sm\)',
        )

    def test_primary_pages_use_scoped_page_headers(self):
        expected = {
            'index.html': 'page--servers',
            'users.html': 'page--users',
            'my_connections.html': 'page--my-connections',
            'settings.html': 'page--settings',
            'server.html': 'page--server-detail',
        }
        base = (TEMPLATES / 'base.html').read_text(encoding='utf-8')
        self.assertIn('block page_class', base)
        for name, page_class in expected.items():
            src = (TEMPLATES / name).read_text(encoding='utf-8')
            self.assertIn(page_class, src, f'{name} missing page-specific class')
            self.assertIn('page-header', src, f'{name} missing shared page header')

    def test_page_header_and_search_classes_exist(self):
        users = (TEMPLATES / 'users.html').read_text(encoding='utf-8')
        self.assertIn('page-header--with-search', users)
        self.assertIn('search-field', users)
        self.assertIn('search-field-icon', users)
        for marker in (
            '.page-header',
            '.page-header__title',
            '.page-header__actions',
            '.page-header__search',
            '.search-field',
            '.search-field-icon',
        ):
            self.assertIn(marker, STYLE, f'missing CSS marker {marker}')

    def test_entity_cards_are_scoped_not_global_client_items(self):
        users = (TEMPLATES / 'users.html').read_text(encoding='utf-8')
        mine = (TEMPLATES / 'my_connections.html').read_text(encoding='utf-8')
        self.assertIn('entity-card user-card', users)
        self.assertIn('entity-card connection-card', mine)
        self.assertIn('entity-card-actions', users)
        self.assertIn('entity-card-actions', mine)
        self.assertIn('.entity-card', STYLE)
        self.assertIn('.entity-card-actions', STYLE)

    def test_connection_cards_keep_compact_horizontal_layout(self):
        """My Connections cards must not inherit tall user-card body spacing.

        The row direction must win the cascade, so it needs higher specificity
        than `.cards-grid-2 > .entity-card { flex-direction: column }`.
        """
        self.assertRegex(
            STYLE,
            r'\.cards-grid-2\s*>\s*\.entity-card\.connection-card\s*\{[^}]*flex-direction:\s*row',
        )
        self.assertRegex(
            STYLE,
            r'\.cards-grid-2\s*>\s*\.entity-card\.connection-card\s*\{[^}]*align-items:\s*center',
        )
        self.assertRegex(
            STYLE,
            r'\.connection-card\s+\.entity-card-actions\s*\{[^}]*width:\s*auto',
        )

    def test_create_buttons_pinned_right_corner(self):
        """Create/add buttons must sit in the header's right corner, like the server page."""
        for name in ('index.html', 'users.html', 'my_connections.html'):
            src = (TEMPLATES / name).read_text(encoding='utf-8')
            self.assertIn('page-header__actions', src, f'{name} missing actions container')
        self.assertRegex(STYLE, r'\.page-header__actions\s*\{[^}]*margin-left:\s*auto')
        mobile_layer = STYLE.split('/* ===== Mobile & PWA layer ===== */', 1)[-1]
        self.assertIn('"title actions"', mobile_layer)
        self.assertIn('"search search"', mobile_layer)
        self.assertNotIn('page-header--stack-mobile', STYLE)


if __name__ == '__main__':
    unittest.main()
