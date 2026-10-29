"""Sticky settings navigation gains a backdrop only after leaving its slot."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SettingsNavigationTests(unittest.TestCase):
    def test_sticky_backdrop_is_scoped_to_stuck_state(self):
        css = (ROOT / 'static/css/style.css').read_text(encoding='utf-8')
        self.assertIn('.settings-nav.is-stuck {', css)
        block = css.split('.settings-nav.is-stuck {', 1)[1].split('}', 1)[0]
        self.assertIn('background:', block)
        self.assertIn('backdrop-filter:', block)
        template = (ROOT / 'templates/settings.html').read_text(encoding='utf-8')
        self.assertIn('id="settings-nav-anchor"', template)
        self.assertIn('/static/js/settings-nav.js?v={{ static_v }}', template)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_observer_handles_scroll_return_and_missing_elements(self):
        script = ROOT / 'static/js/settings-nav.js'
        result = subprocess.run(['node', '-e', r'''
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const source = fs.readFileSync(process.argv[1], 'utf8');
let callback;
const states = [];
const anchor = {};
const nav = {classList: {toggle: (name, value) => {
    assert.equal(name, 'is-stuck'); states.push(value);
}}};
class Observer {
    constructor(cb) { callback = cb; }
    observe(element) { assert.equal(element, anchor); }
}
vm.runInNewContext(source, {
    document: {querySelector: () => nav, getElementById: () => anchor},
    IntersectionObserver: Observer
});
const entry = (top, visible) => [{boundingClientRect: {top}, isIntersecting: visible}];
callback(entry(100, true));
callback(entry(-2, false));
callback(entry(-500, false));
callback(entry(20, true));
callback(entry(1000, false));
assert.deepEqual(states, [false, true, true, false, false]);
vm.runInNewContext(source, {
    document: {querySelector: () => null, getElementById: () => null},
    IntersectionObserver: Observer
});
''', str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
