"""SSE parsing, retries and record-building for the Cheburcheck integration."""
import asyncio
import json
import time
import unittest
from unittest.mock import patch

import cheburcheck


SSE_FIXTURE = (
    "event:started\n"
    'data:{"id":"c1","target":"1.2.3.4","online_probes":40}\n'
    "\n"
    "event:result\n"
    'data:{"asn":"AS12389","provider":"Rostelecom","region":"Костромская область",'
    '"verdicts":["ok"],"dpi_hop":2,"target_hop":3,"cached":false}\n'
    "\n"
    "event:result\n"
    'data:{"asn":"AS8402","provider":"Beeline","region":"Москва",'
    '"verdicts":["tspu_block"],"dpi_hop":1,"target_hop":null,"cached":true}\n'
    "\n"
    "event:done\n"
    'data:{"id":"c1","response_count":2,"online_probes":40,"status":"done"}\n'
    "\n"
)


class FakeStream:
    """Minimal stand-in for httpx's streaming response context manager."""

    def __init__(self, status=200, text=""):
        self.status_code = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def aiter_lines(self):
        for line in self._text.split("\n"):
            yield line


class FakeClient:
    """AsyncClient stand-in yielding a scripted sequence of streams."""

    def __init__(self, streams):
        self._streams = list(streams)
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def stream(self, method, url, timeout=None):
        self.calls += 1
        stream = self._streams.pop(0) if self._streams else FakeStream(200, "")
        return stream


class TestSSEParserWithMock(unittest.IsolatedAsyncioTestCase):
    async def test_parses_fixture_and_counts_verdicts(self):
        with patch.object(cheburcheck.httpx, "AsyncClient", lambda **kw: FakeClient([FakeStream(200, SSE_FIXTURE)])):
            probe = await cheburcheck.fetch_probe("token", timeout=5)
        self.assertIsNotNone(probe)
        self.assertEqual(probe["response_count"], 2)
        self.assertEqual(probe["online_probes"], 40)
        self.assertEqual(probe["verdict_counts"], {"ok": 1, "tspu_block": 1})
        self.assertEqual(len(probe["regions"]), 2)
        self.assertTrue(probe["regions"][1]["cached"])

    async def test_retries_on_429_then_succeeds(self):
        streams = [FakeStream(429, ""), FakeStream(200, SSE_FIXTURE)]
        client = FakeClient(streams)
        with patch.object(cheburcheck, "_read_probe_stream",
                          side_effect=[(None, True), ({"verdicts": [], "regions": [], "response_count": 1}, False)]), \
             patch.object(cheburcheck.asyncio, "sleep", new=self._noop):
            probe = await cheburcheck.fetch_probe("token", max_retries=3)
        self.assertIsNotNone(probe)
        self.assertEqual(probe["response_count"], 1)

    async def test_no_retry_when_error_is_not_retryable(self):
        with patch.object(cheburcheck, "_read_probe_stream",
                          side_effect=[(None, False), (None, False)]) as mocked, \
             patch.object(cheburcheck.asyncio, "sleep", new=self._noop):
            probe = await cheburcheck.fetch_probe("token", max_retries=3)
        self.assertIsNone(probe)
        self.assertEqual(mocked.call_count, 1)

    async def test_gives_up_after_max_retries(self):
        with patch.object(cheburcheck, "_read_probe_stream",
                          side_effect=[(None, True)] * 4), \
             patch.object(cheburcheck.asyncio, "sleep", new=self._noop):
            probe = await cheburcheck.fetch_probe("token", max_retries=3)
        self.assertIsNone(probe)

    @staticmethod
    async def _noop(*a, **kw):
        return None


class TestRequestBackoff(unittest.IsolatedAsyncioTestCase):
    async def test_retries_429_and_returns_response(self):
        class Resp:
            def __init__(self, code):
                self.status_code = code
                self.request = object()

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise AssertionError("should not raise on retryable codes")

            async def get(self, *a, **kw):
                return self

        class Client:
            def __init__(self):
                self.n = 0

            async def get(self, url, timeout=None):
                self.n += 1
                return Resp(429 if self.n < 3 else 200)

        client = Client()
        with patch.object(cheburcheck.asyncio, "sleep", new=self._noop):
            r = await cheburcheck._request_with_backoff(client, "http://x", max_retries=4)
        self.assertEqual(r.status_code, 200)

    async def test_raises_on_4xx(self):
        class Resp:
            status_code = 404
            request = object()

            def raise_for_status(self):
                raise cheburcheck.httpx.HTTPStatusError("404", request=self.request, response=self)

        class Client:
            async def get(self, url, timeout=None):
                return Resp()

        with self.assertRaises(cheburcheck.httpx.HTTPStatusError):
            await cheburcheck._request_with_backoff(Client(), "http://x")

    @staticmethod
    async def _noop(*a, **kw):
        return None


class TestSpacing(unittest.IsolatedAsyncioTestCase):
    async def test_second_call_waits_for_spacing(self):
        old = cheburcheck.CHECK_SPACING
        cheburcheck.CHECK_SPACING = 0.4
        try:
            async with cheburcheck.httpx.AsyncClient() as c:
                t0 = time.monotonic()
                await cheburcheck._respect_spacing(cheburcheck._check_lock, 0.4)
                await cheburcheck._respect_spacing(cheburcheck._check_lock, 0.4)
                elapsed = time.monotonic() - t0
            self.assertGreaterEqual(elapsed, 0.35)
        finally:
            cheburcheck.CHECK_SPACING = old


class TestBuildSummaryFailurePaths(unittest.TestCase):
    def test_error_is_recorded_when_check_failed(self):
        s = cheburcheck.build_summary("1.2.3.4", None, None, error="check failed: boom")
        self.assertEqual(s["status"], "unknown")
        self.assertEqual(s["error"], "check failed: boom")
        self.assertEqual(s["probe"]["blocking_regions"], 0)

    def test_error_on_partial_probe(self):
        static = {"blocked": False, "geo": {"asn": "AS1"}}
        s = cheburcheck.build_summary("1.2.3.4", static, None, error="probe failed: 429")
        self.assertEqual(s["status"], "unknown")
        self.assertEqual(s["error"], "probe failed: 429")
        self.assertEqual(s["static"]["geo"]["asn"], "AS1")

    def test_unknown_gets_default_reason(self):
        s = cheburcheck.build_summary("1.2.3.4", {"blocked": False}, {"regions": [], "response_count": 0})
        self.assertEqual(s["status"], "unknown")
        self.assertIn("no verdicts", s["error"])

    def test_static_hit_without_tspu_is_not_a_ban(self):
        """A CDN/RKN list hit alone must not flip the status to banned."""
        s = cheburcheck.build_summary("1.2.3.4",
                                      {"blocked": True, "blocked_subnets": ["1.2.3.0/24"]},
                                      None, error="probe failed")
        self.assertEqual(s["status"], "unknown")
        self.assertTrue(s["static"]["blocked"])
        self.assertEqual(s["error"], "probe failed")

    def test_static_hit_with_tspu_is_a_ban(self):
        probe = {"regions": [{"region": "r", "verdicts": ["tspu_block"]}],
                 "response_count": 1, "verdicts": ["tspu_block"],
                 "verdict_counts": {"tspu_block": 1}}
        s = cheburcheck.build_summary("1.2.3.4", {"blocked": True}, probe)
        self.assertEqual(s["status"], "banned")

    def test_static_hit_with_clean_probe_is_clean(self):
        probe = {"regions": [{"region": "r", "verdicts": ["ok"]}],
                 "response_count": 1, "verdicts": ["ok"],
                 "verdict_counts": {"ok": 1}}
        s = cheburcheck.build_summary("1.2.3.4", {"blocked": True}, probe)
        self.assertEqual(s["status"], "clean")

    def test_record_has_no_regions_payload(self):
        static = {"blocked": False, "geo": {}}
        probe = {"regions": [{"region": "X", "verdicts": ["ok"]}], "response_count": 1,
                 "verdicts": ["ok"], "online_probes": 5}
        s = cheburcheck.build_summary("1.2.3.4", static, probe)
        self.assertNotIn("regions", s["probe"])
        self.assertEqual(s["probe"]["blocking_regions"], 0)


class TestCdnAndVerdictVoting(unittest.TestCase):
    """Only the TSPU verdict is a ban; SNI/DNS/CDN are restrictions."""

    def test_sni_and_cdn_are_not_bans(self):
        self.assertEqual(cheburcheck.classify(False, ["sni_block"], 5), "clean")
        self.assertEqual(cheburcheck.classify(False, ["cdn_block"], 5), "clean")
        self.assertEqual(cheburcheck.classify(False, ["dns_spoofing"], 5), "clean")
        self.assertEqual(cheburcheck.classify(False, ["tspu_block"], 5), "banned")
        # A static CDN/RKN hit alone is not a ban either.
        self.assertEqual(cheburcheck.classify(True, ["ok"], 5), "clean")

    def test_ok_turns_into_cdn_block_for_static_cdn_without_unblocked_hosts(self):
        verdicts = cheburcheck.normalize_verdicts(
            ["ok"], True, cdn_unblocked=False, host_results=3)
        self.assertEqual(verdicts, ["cdn_block"])
        verdicts = cheburcheck.normalize_verdicts(
            ["ok"], True, cdn_unblocked=True, host_results=3)
        self.assertEqual(verdicts, ["ok"])

    def test_display_counts_and_status_for_a_non_cdn_target(self):
        # 24 raw cdn_block + 10 ok -> 34 "Доступен", one SNI block, 5 whitelist.
        regions = ([{"region": f"r{i}", "verdicts": ["cdn_block"],
                     "cdn_unblocked": False, "host_results": 2} for i in range(24)]
                   + [{"region": f"o{i}", "verdicts": ["ok"],
                       "cdn_unblocked": False, "host_results": 2} for i in range(10)]
                   + [{"region": "s", "verdicts": ["sni_block"],
                       "cdn_unblocked": False, "host_results": 2}]
                   + [{"region": f"w{i}", "verdicts": ["whitelist"],
                       "cdn_unblocked": False, "host_results": 2} for i in range(5)]
                   + [{"region": "u", "verdicts": ["uncertain"],
                       "cdn_unblocked": False, "host_results": 2}])
        probe = {"regions": regions, "response_count": 41,
                 "verdicts": ["cdn_block"] * 24 + ["ok"] * 10 + ["sni_block",
                                                                 "uncertain"]
                 + ["whitelist"] * 5,
                 "verdict_counts": {"cdn_block": 24, "ok": 10, "sni_block": 1,
                                    "whitelist": 5, "uncertain": 1}}
        rec = cheburcheck.build_summary("lamanama.duckdns.org", {}, probe)
        self.assertEqual(rec["status"], "clean")
        self.assertEqual(rec["probe"]["verdict"], "ok")
        self.assertEqual(rec["probe"]["verdict_counts"],
                         {"ok": 34, "sni_block": 1, "whitelist": 5,
                          "uncertain": 1})
        # No TSPU verdict -> nothing banned, but the SNI hit is a restriction.
        self.assertEqual(rec["probe"]["ban_regions"], 0)
        self.assertEqual(rec["probe"]["blocking_regions"], 0)
        self.assertEqual(rec["probe"]["restricted_regions"], 1)
        self.assertEqual(rec["probe"]["clear_regions"], 41)
        self.assertFalse(rec["probe"]["static_cdn"])

    def test_tspu_verdict_bans(self):
        probe = {"regions": [{"region": "r", "verdicts": ["tspu_block"],
                              "cdn_unblocked": False, "host_results": 2}],
                 "response_count": 1, "verdicts": ["tspu_block"],
                 "verdict_counts": {"tspu_block": 1}}
        rec = cheburcheck.build_summary("1.2.3.4", {}, probe)
        self.assertEqual(rec["status"], "banned")
        self.assertEqual(rec["probe"]["ban_regions"], 1)
        self.assertEqual(rec["probe"]["restricted_regions"], 0)

    def test_cdn_target_reports_restriction_not_ban(self):
        probe = {"regions": [{"region": "r", "verdicts": ["cdn_block"],
                              "cdn_unblocked": False, "host_results": 2}],
                 "response_count": 1, "verdicts": ["cdn_block"],
                 "verdict_counts": {"cdn_block": 1}}
        static = {"cdn_providers": {"Cloudflare": [{"subnet": "1.2.3.0/24"}]}}
        rec = cheburcheck.build_summary("cdn.example", static, probe)
        self.assertEqual(rec["status"], "clean")
        self.assertEqual(rec["probe"]["restricted_regions"], 1)
        self.assertTrue(rec["probe"]["static_cdn"])

    def test_majority_vote_and_restriction_counters(self):
        regions = [{"region": "s", "verdicts": ["sni_block"],
                    "cdn_unblocked": False, "host_results": 2}]
        regions += [{"region": f"o{i}", "verdicts": ["ok"],
                     "cdn_unblocked": False, "host_results": 2}
                    for i in range(34)]
        self.assertEqual(cheburcheck.select_verdict(regions, False), "ok")
        self.assertEqual(len(cheburcheck.ban_regions(regions, False)), 0)
        self.assertEqual(len(cheburcheck.restricted_regions(regions, False)), 1)


class TestQuietHours(unittest.TestCase):
    """in_quiet_hours: the window during which no check runs."""

    @staticmethod
    def _at(hour):
        from datetime import datetime
        return datetime(2026, 11, 11, hour, 30)

    def test_disabled_means_never_quiet(self):
        for h in range(24):
            self.assertFalse(cheburcheck.in_quiet_hours(
                {'quiet_enabled': False, 'quiet_start': 0, 'quiet_end': 23}, self._at(h)))

    def test_same_day_window_is_half_open(self):
        cfg = {'quiet_enabled': True, 'quiet_start': 9, 'quiet_end': 17}
        self.assertTrue(cheburcheck.in_quiet_hours(cfg, self._at(9)))
        self.assertTrue(cheburcheck.in_quiet_hours(cfg, self._at(16)))
        self.assertFalse(cheburcheck.in_quiet_hours(cfg, self._at(17)))
        self.assertFalse(cheburcheck.in_quiet_hours(cfg, self._at(8)))

    def test_window_crossing_midnight(self):
        cfg = {'quiet_enabled': True, 'quiet_start': 22, 'quiet_end': 6}
        for h in (22, 23, 0, 3, 5):
            self.assertTrue(cheburcheck.in_quiet_hours(cfg, self._at(h)), h)
        for h in (6, 7, 12, 21):
            self.assertFalse(cheburcheck.in_quiet_hours(cfg, self._at(h)), h)

    def test_equal_start_and_end_is_not_a_window(self):
        cfg = {'quiet_enabled': True, 'quiet_start': 0, 'quiet_end': 0}
        for h in (0, 12, 23):
            self.assertFalse(cheburcheck.in_quiet_hours(cfg, self._at(h)), h)

    def test_malformed_values_are_ignored(self):
        for cfg in ({'quiet_enabled': True, 'quiet_start': 'x', 'quiet_end': 5},
                    {'quiet_enabled': True, 'quiet_start': 25, 'quiet_end': 5},
                    {'quiet_enabled': True, 'quiet_start': 5, 'quiet_end': -1},
                    {'quiet_enabled': True}):
            self.assertFalse(cheburcheck.in_quiet_hours(cfg, self._at(3)), cfg)

    def test_empty_cfg_is_not_quiet(self):
        self.assertFalse(cheburcheck.in_quiet_hours({}, self._at(3)))
        self.assertFalse(cheburcheck.in_quiet_hours(None, self._at(3)))
