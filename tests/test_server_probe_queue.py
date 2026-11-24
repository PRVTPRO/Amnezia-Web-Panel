"""P4: one ordered background-probe queue instead of parallel page-open probes.

Every page-open probe except /check shares a single pooled SSH connection per
server (SSHManager._exec_lock). Starting them "in parallel" only piles threads
on the same lock: the check waits behind the background and the grid appears
late. These assertions pin the shape of the queue and the init order.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / 'templates' / 'server.html').read_text(encoding='utf-8')


def body(start_marker, end_marker):
    start = PAGE.index(start_marker)
    return PAGE[start:PAGE.index(end_marker, start)]


class ProbeQueueStructureTests(unittest.TestCase):
    def test_check_does_not_start_header_probes_itself(self):
        fn = body('async function checkServer(', 'function updateStatusCounts(')
        # A probe may only appear as the task of a queue entry, never as a bare
        # call in the function body (that would start it before /check answers).
        for line in fn.splitlines():
            for call in ('loadRknBlock(', 'loadWarpStatus(', 'loadSmartRouteStatus(',
                         'loadAwgPluginStatus(', 'loadIpStatus('):
                if call in line:
                    self.assertRegex(line, r'ProbeQueue\.(refresh|background)\(',
                                     f'{call} must go through the queue')

    def test_connections_are_queued_first(self):
        fn = body('async function checkServer(', 'function updateStatusCounts(')
        self.assertIn("ProbeQueue.background('connections', 10,", fn)

    def test_init_runs_check_as_the_only_critical_probe(self):
        init = body('// ========== Init ==========', 'let ipStatusPoller = null;')
        self.assertIn("ProbeQueue.critical('check'", init)
        self.assertEqual(init.count('ProbeQueue.critical('), 1)
        # The four probes that used to race the check are queued with the
        # documented priorities.
        for key, priority in (('ssh-trust', 20), ('stats', 30),
                              ('warp', 35), ('rkn', 36), ('cheburcheck', 40),
                              ('smartroute', 45), ('ip', 90), ('plugin', 95)):
            pattern = rf"ProbeQueue\.background\('{re.escape(key)}',\s*{priority},"
            self.assertRegex(init, pattern, f'{key} must be queued at priority {priority}')

    def test_no_legacy_autostart_remains(self):
        self.assertNotIn("DOMContentLoaded', loadSSHTrustStatus", PAGE)
        self.assertNotIn("DOMContentLoaded', loadCheburcheck", PAGE)
        self.assertNotIn("load', () => loadAwgPluginStatus()", PAGE)

    def test_queue_is_single_flight(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn('if (this.inflight.has(key)) return this.inflight.get(key);', queue)
        self.assertIn('if (!force && this.inflight.has(key)) return this.inflight.get(key);', queue)
        self.assertIn('const BG_CONCURRENCY = 1;', PAGE)
        self.assertIn('this.queue.sort((a, b) => a.priority - b.priority);', queue)

    def test_slot_is_freed_on_timeout_but_key_waits_for_the_task(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn('this.active -= 1;', queue)
        self.assertIn("new Error('timeout')", PAGE)
        # The key must NOT be released from the timeout path: a timed-out probe
        # can still hold the SSH lock, and a duplicate would take the slot.
        self.assertNotIn('this.inflight.delete(entry.key);\n                    entry.settle();', queue)
        self.assertIn('if (this.inflight.get(entry.key) === entry.promise) this.inflight.delete(entry.key);', queue)
        self.assertIn('started.then(release, release);', queue)
        # A task that never settles must not kill the key forever: there is a
        # grace release after the timeout.
        self.assertIn('entry.timeoutMs || 25000) + 5000', queue)

    def test_refresh_is_not_swallowed_during_the_boot_check(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn("key !== 'check'", queue)
        self.assertIn('return this.background(key, 0, task, timeoutMs, true);', queue)

    def test_bfcache_requeues_every_probe(self):
        tail = PAGE[PAGE.index("window.addEventListener('pageshow'"):]
        for key in ('smartroute', 'ssh-trust', 'stats', 'warp', 'rkn',
                    'cheburcheck', 'ip'):
            self.assertIn(f"ProbeQueue.background('{key}'", tail)
        self.assertIn("ProbeQueue.background('plugin', 95", PAGE)

    def test_manual_refresh_is_first_in_the_queue(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn('return this.background(key, 0, task, timeoutMs, true);', queue)
        self.assertIn("onCheck: () => ProbeQueue.refresh('check'", PAGE)
        # pageshow restores what pagehide stopped (bfcache).
        self.assertIn("window.addEventListener('pageshow'", PAGE)
        self.assertIn('pageClosing = false;', PAGE)

    def test_busy_is_not_retried_or_painted_as_error(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn("indexOf('busy') === -1", queue)
        self.assertNotIn('setTimeout(() => this.pump()', queue)

    def test_pagehide_stops_the_queue(self):
        self.assertIn('pageClosing = true;', PAGE)
        tail = PAGE[PAGE.index("window.addEventListener('pagehide'"):]
        self.assertIn('clearInterval(ipStatusPoller)', tail)

    def test_cache_refill_never_jumps_the_peer_list(self):
        # On a warm /check the snapshot is served from cache and the fresh
        # check is queued: it must run after the visible probes (connections
        # first), otherwise the peer list waits seconds for a background task.
        self.assertIn("ProbeQueue.background('check-fresh', 96,", PAGE)
        self.assertNotIn("ProbeQueue.background('check-fresh', 1,", PAGE)

    def test_manual_check_refreshes_the_plugin_badge(self):
        fn = body('async function checkServer(', 'function updateStatusCounts(')
        # Priority 95 matches the documented table (P4.11), so a manual check
        # does not run the plugin probe ahead of the visible cards.
        self.assertIn("ProbeQueue.background('plugin', 95,", fn)
        self.assertIn('loadAwgPluginStatus(true)', fn)


def _queue_js():
    """The real queue + its two dependencies, extracted verbatim from the page."""
    start = PAGE.index('    const BG_CONCURRENCY = 1;')
    end = PAGE.index('    // ========== Init ==========', start)
    return PAGE[start:end]


@unittest.skipUnless(shutil.which('node'), 'node is not installed')
class ProbeQueueBehaviourTests(unittest.TestCase):
    """String assertions cannot catch a swallowed manual check — run the JS."""

    def run_queue(self, scenario):
        source = '\n'.join(("'use strict';", _queue_js(), scenario, ''))
        with tempfile.NamedTemporaryFile('w', suffix='.js', encoding='utf-8',
                                         delete=False) as f:
            f.write(source)
            path = Path(f.name)
        try:
            result = subprocess.run(['node', str(path)], capture_output=True,
                                    text=True, check=False, timeout=30)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('QUEUE_OK', result.stdout)

    def test_manual_check_is_queued_behind_the_boot_check(self):
        scenario = r"""
const assert = require('assert');
(async () => {
    let releaseCritical;
    const critical = ProbeQueue.critical('check', () => new Promise(resolve => {
        releaseCritical = resolve;
    }), 10000);
    await Promise.resolve();
    assert.strictEqual(typeof releaseCritical, 'function', 'critical task did not start');
    let manualCalls = 0;
    const manual = ProbeQueue.refresh('check', () => {
        manualCalls += 1;
        return Promise.resolve('manual');
    }, 10000);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
    assert.strictEqual(manualCalls, 0, 'manual check must wait for the critical lane');
    releaseCritical('critical');
    ProbeQueue.settleCritical();
    const results = await Promise.all([critical, manual]);
    assert.strictEqual(results[0], 'critical', 'critical promise was lost');
    assert.strictEqual(manualCalls, 1, 'manual check was swallowed by dedup');
    assert.strictEqual(ProbeQueue.inflight.size, 0, 'inflight map leaked an entry');
    console.log('QUEUE_OK');
    process.exit(0);
})().catch(error => {
    console.error(error && error.stack || error);
    process.exit(1);
});
"""
        self.run_queue(scenario)

    def test_refresh_reuses_an_inflight_probe_for_other_keys(self):
        scenario = r"""
const assert = require('assert');
(async () => {
    ProbeQueue.settleCritical();
    let releaseFirst;
    const first = ProbeQueue.background('other', 50, () => new Promise(resolve => {
        releaseFirst = resolve;
    }), 10000);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
    assert.strictEqual(typeof releaseFirst, 'function', 'background task did not start');
    let secondCalls = 0;
    const second = ProbeQueue.refresh('other', () => {
        secondCalls += 1;
        return Promise.resolve('second');
    }, 10000);
    assert.strictEqual(second, first, 'refresh must reuse the in-flight promise');
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
    assert.strictEqual(secondCalls, 0, 'refresh launched a duplicate probe');
    releaseFirst();
    await first;
    assert.strictEqual(secondCalls, 0);
    console.log('QUEUE_OK');
    process.exit(0);
})().catch(error => {
    console.error(error && error.stack || error);
    process.exit(1);
});
"""
        self.run_queue(scenario)

    def test_forced_plugin_probe_is_not_swallowed(self):
        scenario = r"""
const assert = require('assert');
(async () => {
    ProbeQueue.settleCritical();
    let releaseBoot;
    const bootPlugin = ProbeQueue.background('plugin', 95, () => new Promise(resolve => {
        releaseBoot = resolve;
    }), 10000);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
    assert.strictEqual(typeof releaseBoot, 'function', 'boot plugin probe did not start');
    let forcedCalls = 0;
    const forced = ProbeQueue.background('plugin', 95, () => {
        forcedCalls += 1;
        return Promise.resolve('forced');
    }, 10000, true);
    assert.notStrictEqual(forced, bootPlugin);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
    assert.strictEqual(forcedCalls, 0, 'forced plugin probe must wait its turn');
    releaseBoot();
    await Promise.all([bootPlugin, forced]);
    assert.strictEqual(forcedCalls, 1, 'forced plugin probe was swallowed');
    console.log('QUEUE_OK');
    process.exit(0);
})().catch(error => {
    console.error(error && error.stack || error);
    process.exit(1);
});
"""
        self.run_queue(scenario)


if __name__ == '__main__':
    unittest.main()
