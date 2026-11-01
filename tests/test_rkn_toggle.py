"""Regression guard for the RKN block card's toggle button.

The button used to be hardwired to ``onclick="toggleRknBlockApp(false)"``.
When the block was off the label read "Start", but the click still sent
``enabled: false``, so the contour could never be switched back on. The inline
handler is gone now and ``renderRknBlockCard()`` binds ``!liveOn`` on every
render.

The template is read as text: this stays offline and needs no server.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_TEMPLATE = ROOT / 'templates' / 'server.html'

TOGGLE_BUTTON_ID = 'rknblock-toggle-btn'
HARDWIRED_FALSE_ONCLICK = 'onclick="toggleRknBlockApp(false)"'


def template_source():
    return SERVER_TEMPLATE.read_text(encoding='utf-8')


def js_function_body(source, name):
    """Return the source of one top-level ``function name(...) {...}``.

    The template indents functions by four spaces and never nests a
    declaration, so the next ``\n    function``/``\n    async function``
    marks the end of the requested body.
    """
    start = source.index('function %s(' % name)
    following = re.search(r'\n    (?:async )?function ', source[start:])
    end = start + following.start() if following else len(source)
    return source[start:end]


def opening_tag(source, marker):
    """Return the complete opening tag that contains ``marker``."""
    at = source.index(marker)
    start = source.rindex('<', 0, at)
    end = source.index('>', at) + 1
    return source[start:end]


class RknBlockToggleTemplateTests(unittest.TestCase):
    def setUp(self):
        self.source = template_source()

    def test_toggle_button_has_no_hardwired_false_onclick(self):
        # The exact regression: a literal handler that always disables.
        self.assertNotIn(HARDWIRED_FALSE_ONCLICK, self.source)
        tag = opening_tag(self.source, 'id="%s"' % TOGGLE_BUTTON_ID)
        self.assertNotIn('onclick', tag)
        self.assertNotIn('toggleRknBlockApp', tag)

    def test_render_binds_the_click_handler_to_the_live_state(self):
        body = js_function_body(self.source, 'renderRknBlockCard')
        self.assertIn('const liveOn =', body)
        self.assertIn(
            'toggleBtn.onclick = () => toggleRknBlockApp(!liveOn);',
            body,
        )
        # No leftover unconditional call anywhere in the renderer.
        self.assertNotIn('toggleRknBlockApp(false)', body)

    def test_render_sets_the_label_from_the_live_state(self):
        body = js_function_body(self.source, 'renderRknBlockCard')
        label = re.search(
            r'toggleBtn\.textContent\s*=\s*liveOn\s*\?\s*'
            r"_\(\s*'rknblock_stop'\s*\)\s*:\s*_\('rknblock_start'\)",
            body,
        )
        self.assertIsNotNone(label, 'toggle label must follow liveOn')

    def test_template_still_has_the_toggle_button_id(self):
        self.assertIn('id="%s"' % TOGGLE_BUTTON_ID, self.source)
        # It lives in the installed-actions row, not the install row.
        installed = self.source.index('id="rknblock-installed-actions"')
        toggle = self.source.index('id="%s"' % TOGGLE_BUTTON_ID)
        self.assertLess(installed, toggle)


if __name__ == '__main__':
    unittest.main()
