"""P4: one ordered background-probe queue instead of parallel page-open probes.

Every page-open probe except /check shares a single pooled SSH connection per
server (SSHManager._exec_lock). Starting them "in parallel" only piles threads
on the same lock: the check waits behind the background and the grid appears
late. These assertions pin the shape of the queue and the init order.
"""
import re
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
        for call in ('loadRknBlock(', 'loadWarpStatus(', 'loadSmartRouteStatus('):
            self.assertNotIn(call, fn,
                             f'{call} must be queued, not started inside checkServer')
        # The manual-check plugin refresh is allowed, but only through the
        # queue (after the /check answer), never as a bare call.
        for line in fn.splitlines():
            if 'loadAwgPluginStatus(' in line:
                self.assertRegex(line, r'ProbeQueue\.(refresh|background)\(')

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
        self.assertIn('const BG_CONCURRENCY = 1;', PAGE)
        self.assertIn('this.queue.sort((a, b) => a.priority - b.priority);', queue)

    def test_slot_is_freed_on_timeout(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        # active/inflight are released in .finally(), i.e. on timeout too:
        self.assertIn('this.active -= 1;', queue)
        self.assertIn('this.inflight.delete(entry.key);', queue)
        self.assertIn("new Error('timeout')", PAGE)

    def test_busy_is_not_retried_or_painted_as_error(self):
        queue = body('const ProbeQueue = {', '// ========== Init ==========')
        self.assertIn("indexOf('busy') === -1", queue)
        self.assertNotIn('setTimeout(() => this.pump()', queue)

    def test_pagehide_stops_the_queue(self):
        self.assertIn('pageClosing = true;', PAGE)
        tail = PAGE[PAGE.index("window.addEventListener('pagehide'"):]
        self.assertIn('clearInterval(ipStatusPoller)', tail)

    def test_manual_check_refreshes_the_plugin_badge(self):
        fn = body('async function checkServer(', 'function updateStatusCounts(')
        self.assertIn("ProbeQueue.background('plugin', 5,", fn)
        self.assertIn('loadAwgPluginStatus(true)', fn)


if __name__ == '__main__':
    unittest.main()
