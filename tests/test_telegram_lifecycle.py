"""Saved user intent survives settings saves, task failures and panel restarts."""
import asyncio
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

import app as panel
import telegram_bot as bot


ROOT = Path(__file__).resolve().parents[1]


class TelegramLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'data.json')
        self.patches = [patch.object(panel, 'DATA_FILE', self.path),
                        patch.object(panel, 'DATA_LOCK', asyncio.Lock()),
                        patch.object(panel, '_check_admin', return_value=True),
                        patch.object(panel, '_refresh_panel_access')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.seed(False)

    async def asyncTearDown(self):
        await bot.stop_bot()

    async def idle_bot(self, *args):
        await asyncio.Event().wait()

    def seed(self, enabled, token='test-token'):
        panel.save_data({'settings': {'telegram': {'enabled': enabled, 'token': token}}})

    def enabled(self):
        return panel.load_data()['settings']['telegram']['enabled']

    def payload(self, **telegram):
        return panel.SaveSettingsRequest(appearance={}, sync={}, captcha={}, ssl={},
                                         telegram={'token': 'test-token', **telegram})

    async def test_start_then_stale_settings_save_preserves_boot_intent(self):
        with patch.object(bot, '_run_bot', side_effect=self.idle_bot):
            started = await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=True))
            task = bot._bot_task
            self.assertTrue(started['bot_enabled'])
            result = await panel.save_settings(None, self.payload(enabled=False))
            self.assertTrue(result['bot_enabled'])
            self.assertTrue(self.enabled())
            self.assertIs(bot._bot_task, task)
            await bot.stop_bot()

    async def test_stop_then_stale_settings_save_does_not_reenable(self):
        self.seed(True)
        stopped = await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=False))
        self.assertFalse(stopped['bot_enabled'])
        result = await panel.save_settings(None, self.payload(enabled=True))
        self.assertFalse(result['bot_enabled'])
        self.assertFalse(self.enabled())
        self.assertFalse(bot.is_running())

    async def test_explicit_start_is_idempotent_and_launch_runs_on_app_loop(self):
        with patch.object(bot, '_run_bot', side_effect=self.idle_bot):
            await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=True))
            task = bot._bot_task
            await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=True))
            self.assertIs(bot._bot_task, task)
            self.assertIs(task.get_loop(), asyncio.get_running_loop())
            await bot.stop_bot()

    async def test_legacy_toggle_stops_enabled_but_dead_bot(self):
        self.seed(True)
        result = await panel.api_telegram_toggle(None)
        self.assertFalse(result['bot_enabled'])
        self.assertFalse(self.enabled())

    async def test_stop_without_token_and_start_without_token(self):
        self.seed(True, token='')
        await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=False))
        self.assertFalse(self.enabled())
        response = await panel.api_telegram_toggle(None, panel.TelegramToggleRequest(enabled=True))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.enabled())

    async def test_settings_restarts_changed_token_on_application_loop(self):
        self.seed(True)
        seen = []

        async def run(token, *args):
            seen.append(token)
            await asyncio.Event().wait()

        with patch.object(bot, '_run_bot', side_effect=run):
            old = bot.launch_bot('test-token', panel.load_data, None)
            await asyncio.sleep(0)
            await panel.save_settings(None, self.payload(token='replacement-token'))
            await asyncio.sleep(0)
            self.assertTrue(old.done())
            self.assertEqual(seen, ['test-token', 'replacement-token'])
            self.assertTrue(self.enabled())

    async def test_startup_honors_saved_intent_after_runtime_stops(self):
        # Execute the real startup hook, suppressing unrelated fleet/network jobs.
        from contextlib import ExitStack

        def discard(coro):
            coro.close()

        for enabled in (True, False):
            with self.subTest(enabled=enabled), ExitStack() as stack:
                self.seed(enabled)
                for name in ('PanelLease', '_start_conn_monitor', '_start_duckdns_monitor',
                             '_start_subscriptions_monitor', '_cheburcheck_startup_cache', '_op_store'):
                    stack.enter_context(patch.object(panel, name))
                for name in ('_cheburcheck_migrate_settings', 'migrate_recovery_snapshots'):
                    stack.enter_context(patch.object(panel, name, return_value=False))
                stack.enter_context(patch.object(panel.asyncio, 'create_task', side_effect=discard))
                launch = stack.enter_context(patch.object(bot, 'launch_bot'))
                stack.enter_context(patch.object(panel, '_panel_lease', None))
                await panel.startup()
                self.assertEqual(launch.call_count, int(enabled))
                self.assertEqual(self.enabled(), enabled)


class TelegramSupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await bot.stop_bot()

    async def test_network_and_initialization_errors_retry_with_capped_backoff(self):
        run = AsyncMock(side_effect=[httpx.ConnectError('secret-url'), RuntimeError(),
                                    ValueError(), RuntimeError(), RuntimeError(), None])
        sleep = AsyncMock()
        with patch.object(bot, '_run_bot', run), patch.object(bot.asyncio, 'sleep', sleep):
            with self.assertLogs(bot.logger, level='WARNING') as logs:
                await bot._supervise_bot('test-token', None, None)
        self.assertEqual(run.await_count, 6)
        self.assertEqual([c.args[0] for c in sleep.await_args_list], [5, 10, 20, 40, 60])
        self.assertNotIn('secret-url', '\n'.join(logs.output))

    async def test_manual_stop_cancels_pending_retry_and_does_not_restart(self):
        waiting = asyncio.Event()

        async def delay(seconds):
            waiting.set()
            await asyncio.Event().wait()

        run = AsyncMock(side_effect=httpx.ConnectError('offline'))
        with patch.object(bot, '_run_bot', run), patch.object(bot.asyncio, 'sleep', delay):
            task = bot.launch_bot('test-token', None, None)
            self.assertIs(bot.launch_bot('test-token', None, None), task)
            await waiting.wait()
            await bot.stop_bot()
            self.assertTrue(task.done())
            self.assertFalse(bot.is_running())
            self.assertEqual(run.await_count, 1)

    async def test_invalid_token_is_reported_without_endless_retries(self):
        run = AsyncMock(side_effect=bot._InvalidBotToken())
        with patch.object(bot, '_run_bot', run), patch.object(bot.asyncio, 'sleep', AsyncMock()) as sleep:
            with self.assertLogs(bot.logger, level='ERROR'):
                await bot._supervise_bot('test-token', None, None)
            sleep.assert_not_awaited()

    async def test_getme_transient_errors_retry_but_auth_errors_stop(self):
        for code in (401, 404, 429, 500):
            with self.subTest(code=code):
                api = Mock()
                api.call = AsyncMock(return_value={'ok': False, 'error_code': code})
                with patch.object(bot, 'TelegramAPI', return_value=api):
                    error = bot._InvalidBotToken if code in (401, 404) else RuntimeError
                    with self.assertRaises(error):
                        await bot._run_bot('test-token', None, None)


@unittest.skipUnless(shutil.which('node'), 'Node.js is required to execute settings JavaScript')
class TelegramSettingsJavaScriptTests(unittest.TestCase):
    def test_start_stop_and_general_save_use_separate_state(self):
        source = (ROOT / 'templates/settings.html').read_text()
        toggle = source[source.index('    async function toggleBot()'):source.index('    async function downloadFullBackup()')]
        telegram = source[source.index('        const telegram = {'):source.index('        const ssl = {')]
        script = '''
const assert = require('node:assert/strict');
let botEnabled = false;
const element = {value:'token', checked:false, classList:{add(){},remove(){}}};
const document = {getElementById(){return element;}};
const _ = x => x;
const showToast = () => {};
const requests = [];
const fetch = async (url, options) => {
    const body = JSON.parse(options.body); requests.push(body);
    return {ok:true, json:async()=>({bot_enabled:body.enabled,bot_running:body.enabled})};
};
''' + toggle + '''
(async () => {
    await toggleBot(); assert.equal(botEnabled, true);
''' + telegram + '''
    assert.equal(Object.hasOwn(telegram, 'enabled'), false);
    await toggleBot(); assert.equal(botEnabled, false);
    assert.deepEqual(requests, [{enabled:true}, {enabled:false}]);
})().catch(error => {console.error(error); process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
