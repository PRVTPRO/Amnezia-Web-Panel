"""Progress reporting for the AmneziaWG plugin updater.

The UI has to answer two questions while an update runs: "which step is it
on?" and "is it still moving?"  A DKMS build can take minutes, so the bar must
keep creeping inside the current stage instead of looking frozen.

These tests are deterministic: no SSH, no network, no real update.  The only
sleep is a short poll while the background task started by the endpoint
finishes with an in-memory fake updater.
"""

import asyncio
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as panel
from managers.awg_plugin_updater import (
    KERNEL_MODULE,
    STAGE_STEPS,
    TOTAL_STEPS,
    USERSPACE,
    stage_step,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'templates' / 'server.html'
TRANSLATIONS = ROOT / 'translations'


class ProgressUpdater:
    """Fake updater that only plays log lines through the real callback."""

    def __init__(self, stages):
        self.stages = stages
        # (step, total, percent) observed right after each log() call.
        self.snapshots = []

    def latest_versions(self):
        return {KERNEL_MODULE: '3.1.20260906', USERSPACE: '3.1.20260828'}

    def update(self, component, target, allow_interrupt=False, log=None, should_cancel=None):
        for stage, message in self.stages:
            log(stage, message)
            running = [
                op for op in panel._awg_plugin_ops.values()
                if op.get('state') == 'running' and op.get('component') == component
            ]
            if running:
                op = running[-1]
                self.snapshots.append((op['step'], op['total'], op['percent']))
        return {
            'component': component,
            'previous': '3.1.20260812',
            'installed': target,
            'state': 'updated',
            'rolled_back': False,
        }


class AwgPluginProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._data_file = panel.DATA_FILE
        panel.DATA_FILE = str(Path(self.tmp.name) / 'data.json')
        self.addCleanup(setattr, panel, 'DATA_FILE', self._data_file)

        panel._awg_plugin_ops.clear()
        panel._awg_plugin_active.clear()
        panel._awg_plugin_loaded['done'] = False
        self.addCleanup(panel._awg_plugin_ops.clear)
        self.addCleanup(panel._awg_plugin_active.clear)

        seed = {
            'servers': [{
                'name': 's', 'host': '127.0.0.1', 'ssh_port': 1,
                'username': 'root', 'password': 'x', 'private_key': '',
                'server_info': {}, 'uid': 'u0', 'protocols': {},
            }],
            'users': [], 'user_connections': [],
        }
        Path(panel.DATA_FILE).write_text(json.dumps(seed), encoding='utf-8')

        self.updater = ProgressUpdater([
            ('preflight', 'kernel 6.1.0, blockers: none'),
            ('build', 'dkms build in progress'),
        ])
        patcher = patch.object(panel, '_awg_plugin_updater', lambda server_id: self.updater)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.client = TestClient(panel.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        login = self.client.post(
            '/api/auth/login',
            json={'username': 'admin', 'password': 'admin', 'captcha': None},
        )
        self.assertEqual(login.status_code, 200, login.text)

    # ------------------------------------------------------------------ helpers

    def _start_update(self, component=KERNEL_MODULE):
        response = self.client.post(
            '/api/servers/0/awg-plugin/update',
            json={'component': component},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['operation_id']

    def _wait_until_finished(self, op_id, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            op = panel._awg_plugin_ops.get(op_id)
            if op and op.get('state') != 'running':
                return op
            time.sleep(0.01)
        self.fail('operation %s did not finish' % op_id)

    # --------------------------------------------------------------- stage map

    def test_stage_map_is_ordered_and_complete(self):
        expected = {
            KERNEL_MODULE: {
                'start': 1, 'preflight': 2, 'dependencies': 3, 'backup': 4,
                'download': 5, 'dkms-add': 6, 'build': 7, 'install': 8,
                'verify': 9, 'activate': 10, 'tunnel': 11, 'done': 12,
                'cleanup': 12,
            },
            USERSPACE: {
                'start': 1, 'prepare': 2, 'dependencies': 3, 'backup': 4,
                'build': 5, 'switch': 6, 'network': 7, 'restore': 8,
                'verify': 9, 'finalize': 10, 'tunnel': 11, 'done': 12,
                'cleanup': 12,
            },
        }
        self.assertEqual(TOTAL_STEPS, 12)
        for component, mapping in expected.items():
            with self.subTest(component=component):
                self.assertEqual(STAGE_STEPS[component], mapping)
                for stage, step in mapping.items():
                    self.assertEqual(stage_step(component, stage), (step, 12))

        # Old step numbers moved: the new mapping is asserted explicitly.
        self.assertEqual(stage_step(KERNEL_MODULE, 'preflight'), (2, 12))
        self.assertEqual(stage_step(KERNEL_MODULE, 'build'), (7, 12))
        self.assertEqual(stage_step(USERSPACE, 'build'), (5, 12))

        # The journal emits `dependencies`; it must be a real stage that moves
        # the bar forward, not a transient line the mapping ignores.
        self.assertEqual(stage_step(KERNEL_MODULE, 'dependencies'), (3, 12))
        self.assertIsNotNone(stage_step(KERNEL_MODULE, 'dependencies'))
        self.assertEqual(stage_step(USERSPACE, 'dependencies'), (3, 12))
        self.assertIsNone(stage_step(KERNEL_MODULE, 'not-a-stage'))
        self.assertIsNone(stage_step('not-a-component', 'build'))

        # The two terminal aliases (cleanup/done) both mean "finished" and
        # intentionally share step 12, so strict increase is required for
        # every other adjacent pair in the documented order.
        documented = {
            KERNEL_MODULE: [
                'start', 'preflight', 'dependencies', 'backup', 'download',
                'dkms-add', 'build', 'install', 'verify', 'activate', 'tunnel',
                'done', 'cleanup',
            ],
            USERSPACE: [
                'start', 'prepare', 'dependencies', 'backup', 'build', 'switch',
                'network', 'restore', 'verify', 'finalize', 'tunnel', 'done',
                'cleanup',
            ],
        }
        terminal_aliases = {'done', 'cleanup'}
        for component, order in documented.items():
            with self.subTest(component=component):
                mapping = STAGE_STEPS[component]
                self.assertEqual(set(mapping), set(order))
                steps = [mapping[name] for name in order]
                self.assertTrue(
                    all(1 <= step <= TOTAL_STEPS for step in steps),
                    '%s has a step outside 1..%d: %r' % (component, TOTAL_STEPS, steps),
                )
                for name_before, name_after, previous, current in zip(
                    order, order[1:], steps, steps[1:]
                ):
                    self.assertGreaterEqual(current, previous)
                    if current == previous:
                        self.assertIn(name_before, terminal_aliases)
                        self.assertIn(name_after, terminal_aliases)
                self.assertEqual(sorted(set(steps)), list(range(1, TOTAL_STEPS + 1)))

    # -------------------------------------------------------------------- API

    def test_api_exposes_consistent_progress(self):
        op_id = self._start_update()
        self._wait_until_finished(op_id)

        response = self.client.get('/api/servers/0/awg-plugin/update/%s' % op_id)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        for key in ('step', 'total', 'percent'):
            self.assertIn(key, body)
        self.assertEqual(body['total'], 12)
        self.assertEqual(body['total'], TOTAL_STEPS)
        self.assertEqual(body['percent'], int(round(body['step'] * 100.0 / body['total'])))
        # The worker logged 'done', so the final operation is at 12/12.
        self.assertEqual(body['step'], TOTAL_STEPS)
        self.assertEqual(body['step'], 12)
        self.assertEqual(body['percent'], 100)

        # While the fake was still inside update(), the build stage had
        # already moved the bar to 58% (7/12) - the long-action case the UI
        # cares about, not just the final value.
        self.assertIn((7, 12, 58), self.updater.snapshots)
        self.assertIn((2, 12, 17), self.updater.snapshots)

    def test_progress_never_goes_backwards(self):
        """Drive the real worker with log stages arriving out of order."""
        out_of_order = ProgressUpdater([
            ('preflight', 'stale line after build'),
            ('done', 'finished'),
            ('preflight', 'even later stale line'),
        ])
        op_id = 'op-monotonic'
        panel._awg_plugin_ops[op_id] = {
            'id': op_id, 'server_id': 0, 'component': KERNEL_MODULE,
            'target': '3.1.20260906', 'state': 'running', 'lines': [],
            'result': None, 'error': None, 'cancel_requested': False,
            'step': 7, 'total': TOTAL_STEPS, 'percent': 58,
            'started_at': 't',
        }
        with patch.object(panel, '_awg_plugin_updater', lambda server_id: out_of_order):
            asyncio.run(panel._run_awg_plugin_update(
                op_id, 0, KERNEL_MODULE, '3.1.20260906', False,
            ))

        op = panel._awg_plugin_ops[op_id]
        self.assertEqual(op['state'], 'success')
        self.assertEqual(
            out_of_order.snapshots,
            [(7, 12, 58), (12, 12, 100), (12, 12, 100)],
        )
        self.assertEqual((op['step'], op['total'], op['percent']), (12, 12, 100))

    # ------------------------------------------------------------ persistence

    def test_progress_is_persisted_in_the_journal(self):
        op_id = self._start_update()
        self._wait_until_finished(op_id)

        store = Path(panel._awg_plugin_store_path())
        self.assertTrue(store.exists())
        stored = json.loads(store.read_text(encoding='utf-8'))
        entry = next(item for item in stored if item.get('id') == op_id)
        for key in ('step', 'total', 'percent'):
            self.assertIn(key, entry)
        self.assertEqual(entry['total'], TOTAL_STEPS)
        self.assertEqual(entry['total'], 12)
        self.assertEqual((entry['step'], entry['percent']), (12, 100))

    # --------------------------------------------------------------- template

    def test_template_renders_progress_bar(self):
        html = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('awg-progress-track', html)
        self.assertIn('setAttribute(\'role\', \'progressbar\')', html)
        self.assertIn('awg-progress-fill', html)
        self.assertIn('awgProgressShimmer', html)
        self.assertIn('setAwgProgress(component, data.step, data.total, data.percent', html)
        self.assertIn('labelsStep(', html)
        self.assertIn("replace('{step}'", html)
        self.assertIn("replace('{total}'", html)

    def test_progress_track_is_thin(self):
        """A 4px rail keeps the header compact; 8px looked like a second card."""
        html = TEMPLATE.read_text(encoding='utf-8')
        rules = re.findall(r'\.awg-progress-track\s*\{([^}]*)\}', html)
        self.assertTrue(rules, 'missing .awg-progress-track rule')
        track_rule = next((rule for rule in rules if 'height' in rule), rules[0])
        self.assertIn('height: 4px', track_rule)
        self.assertNotIn('height: 8px', track_rule)

    def test_journal_is_a_collapsed_spoiler(self):
        """The log must not push the modal around: it lives in a <details>."""
        html = TEMPLATE.read_text(encoding='utf-8')
        start = html.index('function renderAwgPluginProgress(component)')
        end = html.index('function setAwgProgress', start)
        body = html[start:end]

        detail = "awgPluginElement('details', 'awg-plugin-details')"
        self.assertIn(detail, body)
        self.assertIn("logBox.id = 'awgPluginLogBox-' + component", body)
        self.assertIn("logBox.appendChild(awgPluginElement('summary', '', labels.log))", body)
        self.assertIn("log.id = 'awgPluginLog-' + component", body)
        self.assertIn('logBox.appendChild(log)', body)

        # The log div is created inside the spoiler and the spoiler is the
        # element appended to the progress host.
        detail_at = body.index(detail)
        log_id_at = body.index("log.id = 'awgPluginLog-' + component")
        attach_at = body.index('logBox.appendChild(log)')
        host_at = body.index('host.appendChild(logBox)')
        self.assertLess(detail_at, log_id_at)
        self.assertLess(log_id_at, attach_at)
        self.assertLess(attach_at, host_at)
        self.assertLess(body.index("logBox.id = 'awgPluginLogBox-' + component"), attach_at)

        # Collapsed by default: nothing opens it while the update renders.
        self.assertNotIn('logBox.open = true', body)

    def test_changelog_is_a_lazy_spoiler(self):
        """The "What changed" block is a spoiler that fetches on first open."""
        html = TEMPLATE.read_text(encoding='utf-8')
        start = html.index('function renderAwgPluginModal()')
        end = html.index('async function loadAwgPluginChangelog', start)
        body = html[start:end]

        self.assertIn("awgPluginElement('details', 'awg-plugin-details')", body)
        self.assertIn("changelog.id = 'awgChangelogBox-' + component", body)
        self.assertIn(
            "changelog.appendChild(awgPluginElement('summary', '', labels.whats_new))",
            body,
        )
        self.assertIn("changelog.addEventListener('toggle'", body)
        self.assertIn('if (changelog.open && !changelog.dataset.loaded)', body)
        self.assertIn("loadAwgPluginChangelog(component, info.available, changelogBody)", body)
        self.assertIn("changelog.appendChild(changelogBody)", body)

        # No leftover "What changed" button / eager loader.
        self.assertNotIn('showAwgPluginChangelog', html)
        for line in body.splitlines():
            if 'labels.whats_new' in line:
                self.assertNotIn('button', line.lower(), line)

    def test_terminal_failure_opens_the_journal(self):
        """A failed or cancelled update must show its reason without a click."""
        html = TEMPLATE.read_text(encoding='utf-8')
        start = html.index('async function pollAwgPluginUpdate(component)')
        end = html.index("document.addEventListener('DOMContentLoaded'", start)
        body = html[start:end]

        branch_at = body.index("if (data.state === 'failed' || data.state === 'cancelled')")
        branch = body[branch_at:]
        self.assertIn(
            "document.getElementById('awgPluginLogBox-' + component)",
            branch,
        )
        self.assertIn('logBox.open = true', branch)
        self.assertNotIn('logBox.open = false', body)
        # Success keeps the spoiler closed; only terminal failures force it open.
        self.assertNotIn('logBox.open = true', body[:branch_at])

    def test_translations_have_step_placeholders(self):
        files = sorted(TRANSLATIONS.glob('*.json'))
        self.assertEqual({path.stem for path in files}, {'en', 'fr', 'ru', 'zh', 'fa'})
        for path in files:
            with self.subTest(locale=path.stem):
                payload = json.loads(path.read_text(encoding='utf-8'))
                self.assertIn('awg_plugin_step', payload)
                value = payload['awg_plugin_step']
                self.assertIn('{step}', value)
                self.assertIn('{total}', value)
                # Spoiler summaries reuse the existing labels.
                self.assertTrue(payload.get('awg_plugin_log'), path.name)
                self.assertTrue(payload.get('awg_plugin_whats_new'), path.name)

    def test_ticker_creeps_and_respects_reduced_motion(self):
        html = TEMPLATE.read_text(encoding='utf-8')
        self.assertIn('setInterval(', html)
        self.assertIn('op.cap = Math.min(99, op.percent + 9)', html)
        self.assertIn('current.display = Math.min(current.cap, (current.display || 0) + 1)', html)
        self.assertIn('@media (prefers-reduced-motion: reduce)', html)
        reduced = html[html.index('@media (prefers-reduced-motion: reduce)'):]
        self.assertIn('.awg-progress-fill::after { animation: none; }', reduced)


if __name__ == '__main__':
    unittest.main()
