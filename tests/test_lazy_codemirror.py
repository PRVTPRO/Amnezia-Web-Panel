"""P6: CodeMirror loads on demand, not with every server page.

Nine vendor files (2 CSS + 7 JS, ~79 KB gzip) used to be part of the page
markup although only two modals need an editor. They are now injected on first
use, once, in an order the modes require.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')


def body(start_marker, end_marker):
    start = PAGE.index(start_marker)
    return PAGE[start:PAGE.index(end_marker, start)]


class LazyCodeMirrorTests(unittest.TestCase):
    def test_no_codemirror_tags_in_markup(self):
        # No eager <script src> / <link href> for the vendor bundle.
        self.assertEqual(
            re.findall(r'<(?:script|link)[^>]+[^>]*vendor/codemirror[^>]*>', PAGE), [],
            'CodeMirror must not be referenced by a static tag any more')

    def test_loader_is_single_flight(self):
        fn = body('function ensureCodeMirror()', 'async function withCodeMirror(')
        self.assertIn('if (window.CodeMirror) return Promise.resolve(true);', fn)
        self.assertIn('if (codeMirrorLoader) return codeMirrorLoader;', fn)
        self.assertIn('codeMirrorLoader = (async () => {', fn)
        # A failed attempt must not be cached, or a second click could never
        # recover from a transient network error.
        self.assertIn('codeMirrorLoader = null;', fn)

    def test_both_stylesheets_load_before_the_editor(self):
        fn = body('function ensureCodeMirror()', 'async function withCodeMirror(')
        self.assertIn('codemirror.min.css', fn)
        self.assertIn('theme/material-darker.min.css', fn)
        self.assertLess(fn.index('for (const href of css)'), fn.index('for (const src of js)'))

    def test_modes_load_in_a_workable_order(self):
        fn = body('function ensureCodeMirror()', 'async function withCodeMirror(')
        block = fn[fn.index('const js = ['):fn.index('];', fn.index('const js = ['))]
        paths = re.findall(r"'([^']+)'", block)
        names = [p.rsplit('/', 1)[-1].replace('.min.js', '') for p in paths]
        self.assertEqual(names[0], 'codemirror',
                         'the core must load before any mode')
        # htmlmixed requires xml (+ css + javascript): it must come last.
        self.assertEqual(names[-1], 'htmlmixed')
        self.assertIn('xml', names)
        self.assertIn('css', names)
        self.assertIn('javascript', names)

    def test_both_editor_entry_points_await_the_loader(self):
        for fn_name, next_marker, textarea in (
                ('async function showServerConfig(', 'async function saveServerConfig(',
                 'serverConfigText'),
                ('async function showNginxSite(', 'async function saveNginxSite(',
                 'siteConfigText')):
            fn = body(fn_name, next_marker)
            self.assertIn('await withCodeMirror(', fn,
                          f'{fn_name} must await the loader before using the editor')
            # The editor is filled inside the callback, i.e. after the load.
            self.assertIn(f"setEditorValue('{textarea}'", fn)
            self.assertLess(fn.index('await withCodeMirror('),
                            fn.index(f"setEditorValue('{textarea}'"))

    def test_failure_is_reported_and_not_fatal(self):
        fn = body('async function withCodeMirror(', 'function ensureConfigEditor(')
        self.assertIn("showToast(_('editor_load_failed')", fn)
        # The task still runs: the modal opens with a plain textarea.
        self.assertIn('return task();', fn)

    def test_config_modal_is_left_alone(self):
        # The third modal uses a plain textarea on purpose; it must not be
        # wired to CodeMirror.
        fn = body('function openConfigModal(', 'function closeConfigModal(') \
            if 'function openConfigModal(' in PAGE else ''
        self.assertNotIn('withCodeMirror(', fn)


if __name__ == '__main__':
    unittest.main()
