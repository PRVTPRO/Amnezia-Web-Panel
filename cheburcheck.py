"""Cheburcheck integration: checking whether a server's public IP is blocked
in Russia (RKN lists + TSPU/SNI/DNS probes via https://cheburcheck.ru).

Public API:
  - fetch_check(target)            -> static check (lists, geo, complaints) or None
  - fetch_probe(id, timeout, ...)  -> aggregated probe dict or None (retries on 429)
  - classify(static_blocked, verdicts, responses) -> 'banned'|'clean'|'unknown'
  - blocking_regions(regions)      -> regions carrying a blocking verdict
  - build_summary(host, static, probe, error=None) -> stored record for one server
"""
import asyncio
import json
import time
import urllib.parse
from datetime import datetime, timezone

import httpx

BASE_URL = "https://cheburcheck.ru"
CHECK_URL = BASE_URL + "/api/v1/check"
PROBE_URL = BASE_URL + "/api/v1/probe/"
STATUS_URL = BASE_URL + "/api/v1/status"
USER_AGENT = "Amnezia-Web-Panel/cheburcheck"

# Service limits: 30 req/min for /check, 5 req/min for /probe (burst 1).
CHECK_SPACING = 2.2
PROBE_SPACING = 12.5

BLOCKING_VERDICTS = {"tspu_block", "sni_block", "dns_spoofing", "cdn_block"}

# Global spacing across all callers (single panel IP).
_check_lock = asyncio.Lock()
_probe_lock = asyncio.Lock()
_last_check = 0.0
_last_probe = 0.0


async def _respect_spacing(lock, spacing):
    """Serialise and space out requests: the service allows one burst per IP."""
    global _last_check, _last_probe
    async with lock:
        last = _last_check if lock is _check_lock else _last_probe
        wait = spacing - (time.monotonic() - last)
        if wait > 0:
            await asyncio.sleep(wait)
        if lock is _check_lock:
            _last_check = time.monotonic()
        else:
            _last_probe = time.monotonic()


async def _request_with_backoff(client, url, *, timeout=40, max_retries=4):
    """GET with retries on 429/5xx/network errors."""
    delay = 2.0
    last_exc = None
    for _ in range(max_retries):
        try:
            r = await client.get(url, timeout=timeout)
            if r.status_code == 429 or r.status_code >= 500:
                last_exc = httpx.HTTPStatusError(
                    f"HTTP {r.status_code}", request=r.request, response=r
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            r.raise_for_status()
            return r
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as e:
            last_exc = e
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
            continue
        except httpx.HTTPStatusError as e:
            # 4xx other than 429: do not retry
            raise
    if last_exc:
        raise last_exc
    return None


async def fetch_status():
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        await _respect_spacing(_check_lock, CHECK_SPACING)
        r = await _request_with_backoff(client, STATUS_URL)
        return r.json() if r is not None else None


async def fetch_check(target):
    """Static check against RKN/CDN lists + geo. Returns parsed dict or None."""
    url = CHECK_URL + "?target=" + _quote(target)
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        await _respect_spacing(_check_lock, CHECK_SPACING)
        r = await _request_with_backoff(client, url)
        if r is None:
            return None
        return r.json()


async def fetch_probe(check_id, timeout=90, max_retries=3):
    """Open the SSE probe stream, collect results, return aggregated dict.

    Retries the whole stream on 429/5xx and network errors: the upstream limit
    is 5 probe requests per minute, and a single 429 must not silently turn a
    healthy server into "unknown".
    """
    delay = 4.0
    for attempt in range(max_retries):
        result, retryable = await _read_probe_stream(check_id, timeout)
        if result is not None:
            return result
        if not retryable:
            return None
        await asyncio.sleep(delay)
        delay = min(delay * 2, 60)
    return None


async def _read_probe_stream(check_id, timeout):
    """One pass over the SSE stream. Returns (result, retryable)."""
    url = PROBE_URL + str(check_id)
    await _respect_spacing(_probe_lock, PROBE_SPACING)
    started = None
    results = []
    done = None
    http_error = None
    try:
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT,
                                              "Accept": "text/event-stream"}) as client:
            async with client.stream("GET", url, timeout=timeout) as resp:
                if resp.status_code >= 400:
                    # 429/5xx are worth another pass; a 4xx is not.
                    return None, (resp.status_code == 429 or resp.status_code >= 500)
                event = None
                async for line in resp.aiter_lines():
                    line = line.rstrip("\r")
                    if line == "":
                        event = None
                        continue
                    if line.startswith("event:"):
                        event = line[6:].strip()
                        continue
                    if line.startswith("data:"):
                        payload = line[5:].strip()
                        if not payload:
                            continue
                        try:
                            data = json.loads(payload)
                        except json.JSONDecodeError:
                            continue
                        if event == "started":
                            started = data
                        elif event == "result":
                            results.append(data)
                        elif event == "done":
                            done = data
    except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as e:
        # A partial pass still carries data; only retry when we got nothing.
        if results:
            pass
        else:
            return None, True
    if not results and started is None and done is None:
        return None, True
    verdicts = []
    for r in results:
        verdicts.extend(r.get("verdicts") or [])
    regions = []
    for r in results:
        regions.append({
            "region": r.get("region"),
            "provider": r.get("provider"),
            "asn": r.get("asn"),
            "verdicts": list(r.get("verdicts") or []),
            "dpi_hop": r.get("dpi_hop"),
            "target_hop": r.get("target_hop"),
            "cached": bool(r.get("cached")),
        })
    return {
        "online_probes": (started or {}).get("online_probes"),
        "response_count": (done or {}).get("response_count", len(results)),
        "started_id": (started or {}).get("id"),
        "regions": regions,
        "verdicts": verdicts,
        "verdict_counts": _count(verdicts),
    }, False


def _count(items):
    out = {}
    for x in items:
        out[x] = out.get(x, 0) + 1
    return out


def _quote(s):
    return urllib.parse.quote(str(s), safe="")


def classify(static_blocked, probe_verdicts, probe_responses):
    """Return 'banned' / 'clean' / 'unknown'."""
    if static_blocked:
        return "banned"
    if any(v in BLOCKING_VERDICTS for v in (probe_verdicts or [])):
        return "banned"
    if not probe_responses:
        return "unknown"
    if all(v == "uncertain" for v in (probe_verdicts or [])):
        return "unknown"
    return "clean"


def blocking_regions(regions):
    out = []
    for r in regions or []:
        vs = r.get("verdicts") or []
        if any(v in BLOCKING_VERDICTS for v in vs):
            out.append(r)
    return out


def in_quiet_hours(cfg, now=None):
    """True when the current hour falls inside the quiet window.

    ``cfg`` is the cheburcheck settings block:
        quiet_enabled: bool
        quiet_start:   hour the window opens (0-23)
        quiet_end:     hour the window closes (0-23)

    The window wraps midnight: 22 -> 6 means 22:00-05:59. ``quiet_end`` is the
    first hour that is NOT quiet, so 0 -> 0 disables the window entirely (an
    empty range would otherwise mean "always quiet").
    """
    quiet_enabled = bool((cfg or {}).get("quiet_enabled"))
    if not quiet_enabled:
        return False
    try:
        start = int(cfg.get("quiet_start"))
        end = int(cfg.get("quiet_end"))
    except (TypeError, ValueError):
        return False
    if not (0 <= start <= 23 and 0 <= end <= 23):
        return False
    if start == end:
        return False           # empty window: nothing is quiet
    hour = (now or datetime.now()).hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def build_summary(host, static, probe, error=None):
    """Build the stored record for one server.

    Never raises on missing input: a failed check must still produce a record,
    otherwise the previous result stays in the cache and a stale "clean" reads
    as a current one. `error` carries the reason when `status` is 'unknown'.
    """
    static = static or {}
    probe = probe or {}
    pv = probe.get("verdicts") or []
    pr = probe.get("response_count") or 0
    regions = probe.get("regions") or []
    blocked = blocking_regions(regions)
    # Count only regions that actually returned verdicts: ``response_count``
    # comes from the "done" event and may exceed what the stream delivered.
    answered = len([r for r in regions if r.get("verdicts")])
    status = classify(bool(static.get("blocked")), pv, pr)
    if status == "unknown" and not error:
        error = "probe returned no verdicts" if pr == 0 else "probe undecided"
    record = {
        "target": host,
        "status": status,                      # banned / clean / unknown
        "checked_at": now_iso(),
        "static": {
            "blocked": bool(static.get("blocked")),
            "blocked_subnets": static.get("blocked_subnets") or [],
            "cdn_providers": list((static.get("cdn_providers") or {}).keys()),
            "geo": static.get("geo") or {},
            "whitelist": static.get("whitelist"),
            "complaints_14d": sum((d.get("count") or 0) for d in (static.get("complaints") or [])),
            "reverse_lookup": static.get("reverse_lookup") or [],
        },
        "probe": {
            "online_probes": probe.get("online_probes"),
            "response_count": pr,
            "verdict_counts": probe.get("verdict_counts") or {},
            "blocking_regions": len(blocked),
            "clear_regions": max(0, answered - len(blocked)),
        },
        "partial": bool(answered and 0 < len(blocked) < answered),
    }
    if error:
        record["error"] = str(error)
    return record
