"""Shared plumbing for every intelligence tool.

Design rules enforced here:
  * A tool NEVER raises into the graph, it returns Evidence with a status.
  * A missing API key is `skipped`, not a failure; the pipeline still runs.
  * Every call is timed and cached, so a fan-out never double-charges an API.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from threatiq.config import Settings, get_settings
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.ratelimit import RateLimiter

log = logging.getLogger(__name__)

# Signature of every tool: (ctx, indicator_value) -> Evidence
ToolFn = Callable[["ToolContext", str], Awaitable[Evidence]]


class ResponseTooLarge(Exception):
    """An upstream response exceeded the size ceiling and was abandoned."""


@dataclass
class _CacheEntry:
    value: Evidence
    expires_at: float


@dataclass
class ToolContext:
    """Per-investigation handle passed to every tool."""
    settings: Settings = field(default_factory=get_settings)
    client: httpx.AsyncClient | None = None
    _cache: dict[str, _CacheEntry] = field(default_factory=dict)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    cache_ttl_s: int = 900
    limiter: RateLimiter | None = None

    def __post_init__(self) -> None:
        if self.limiter is None:
            self.limiter = RateLimiter(self.settings)

    async def __aenter__(self) -> "ToolContext":
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.tool_timeout_s),
                follow_redirects=False,  # redirect chains are evidence, not noise
                headers={"User-Agent": "ThreatIQ/1.0 (security research)"},
                limits=httpx.Limits(max_connections=20),
            )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self.client is not None:
            await self.client.aclose()
            self.client = None

    async def fetch(self, method: str, url: str, *, max_bytes: int | None = None,
                    **kwargs: Any) -> httpx.Response:
        """Perform a request with a hard ceiling on the response body.

        The SSRF guard stops ThreatIQ reaching inward; nothing stopped a
        hostile target flooding it outward. `http_probe` fetches URLs chosen by
        an attacker, so a phishing host could answer with a multi-gigabyte body
        and exhaust the container. httpx has no native size limit, so the body
        is streamed and abandoned the moment it crosses the ceiling.

        Returns a normal Response, so callers keep using `.json()`, `.text` and
        `.status_code` unchanged.
        """
        assert self.client is not None
        ceiling = max_bytes or self.settings.max_response_bytes

        # Trust the advertised length when it is already over the ceiling:
        # no point streaming something that has announced it is too big.
        async with self.client.stream(method, url, **kwargs) as response:
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > ceiling:
                raise ResponseTooLarge(
                    f"{url} declared {int(declared):,} bytes, over the "
                    f"{ceiling:,} byte limit")

            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > ceiling:
                    raise ResponseTooLarge(
                        f"{url} exceeded the {ceiling:,} byte response limit")
                chunks.append(chunk)

            # aiter_bytes() has already decoded the transfer encoding, so the
            # bytes in hand are plain. Carrying the original Content-Encoding
            # over would make the rebuilt Response try to gunzip them a second
            # time and fail with "incorrect header check", which silently broke
            # every gzip-serving source: CISA KEV, NVD and urlscan. The length
            # header is stale for the same reason.
            headers = httpx.Headers(response.headers)
            headers.pop("content-encoding", None)
            headers.pop("content-length", None)

            return httpx.Response(
                status_code=response.status_code,
                headers=headers,
                content=b"".join(chunks),
                request=response.request,
            )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Size-capped GET. Use this rather than ctx.client.get."""
        return await self.fetch("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Size-capped POST. Use this rather than ctx.client.post."""
        return await self.fetch("POST", url, **kwargs)

    def _lock(self, key: str) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def cached(self, key: str, factory: Callable[[], Awaitable[Evidence]]) -> Evidence:
        """Single-flight cache: concurrent agents asking for the same IOC from
        the same source result in exactly one upstream call."""
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit.expires_at > now:
            return hit.value.model_copy(deep=True)
        async with self._lock(key):
            hit = self._cache.get(key)
            if hit and hit.expires_at > time.monotonic():
                return hit.value.model_copy(deep=True)
            value = await factory()
            # Only cache deterministic outcomes; transient errors should retry.
            if value.status in (ToolStatus.OK, ToolStatus.NOT_FOUND, ToolStatus.SKIPPED):
                self._cache[key] = _CacheEntry(value, time.monotonic() + self.cache_ttl_s)
            return value.model_copy(deep=True)


def skipped(source: str, tool: str, indicator: str, reason: str) -> Evidence:
    return Evidence(
        source=source, tool=tool, indicator=indicator,
        status=ToolStatus.SKIPPED, summary=reason, confidence=0.0,
    )


def failed(source: str, tool: str, indicator: str, error: str,
           status: ToolStatus = ToolStatus.ERROR) -> Evidence:
    return Evidence(
        source=source, tool=tool, indicator=indicator, status=status,
        summary=f"{source} lookup failed", error=error[:500], confidence=0.0,
    )


def rate_limited(source: str, tool: str, indicator: str, waited: float,
                 limit: object) -> Evidence:
    """Evidence for a call shed because the source's quota was exhausted.

    Deliberately NOT the same as a clean result. The risk engine treats
    `rate_limited` as missing coverage, so a shed call lowers confidence
    instead of reading as "this source found nothing".
    """
    detail = getattr(limit, "note", "") or "quota exhausted"
    return Evidence(
        source=source, tool=tool, indicator=indicator,
        status=ToolStatus.RATE_LIMITED, confidence=0.0,
        summary=(f"{source} was not queried: local rate limit reached after "
                 f"waiting {waited:.0f}s ({detail}). This is missing coverage, "
                 f"not a clean result."),
        signals={"rate_limited": True, "waited_s": round(waited, 1)},
    )


def timed(source: str, tool: str):
    """Decorator: paces the call against the source's quota, times it, and
    converts any exception into Evidence."""
    def outer(fn: ToolFn) -> ToolFn:
        async def inner(ctx: ToolContext, value: str) -> Evidence:
            start = time.perf_counter()

            # Pace before dialling out. Sources without a configured key take
            # no token, because they return `skipped` without a request.
            limiter = ctx.limiter
            if limiter is not None and limiter.applies_to(source):
                budget = float(ctx.settings.rate_limit_max_wait_s)
                waited = await limiter.acquire(source, budget)
                if waited is None:
                    ev = rate_limited(source, tool, value, budget,
                                      limiter.limit_for(source))
                    ev.latency_ms = int((time.perf_counter() - start) * 1000)
                    return ev

            try:
                ev = await asyncio.wait_for(
                    fn(ctx, value), timeout=ctx.settings.tool_timeout_s + 5
                )
            except asyncio.TimeoutError:
                ev = failed(source, tool, value, "tool timed out",
                            ToolStatus.RATE_LIMITED)
            except ResponseTooLarge as exc:
                # Refused, not errored: we chose to stop reading. A target that
                # answers with an enormous body is itself worth recording.
                log.warning("oversized response from %s: %s", source, exc)
                ev = Evidence(
                    source=source, tool=tool, indicator=value,
                    status=ToolStatus.REFUSED, confidence=0.0,
                    summary=(f"{source} returned an oversized response and was "
                             f"abandoned. Serving a very large body to a "
                             f"scanner is itself suspicious."),
                    error=str(exc)[:300],
                    signals={"oversized_response": True},
                )
            except httpx.HTTPError as exc:
                ev = failed(source, tool, value, f"http error: {exc}")
            except Exception as exc:  # never let a tool kill an investigation
                log.exception("tool %s.%s crashed", source, tool)
                ev = failed(source, tool, value, f"{type(exc).__name__}: {exc}")
            ev.latency_ms = int((time.perf_counter() - start) * 1000)
            return ev
        inner.__name__ = getattr(fn, "__name__", tool)
        return inner
    return outer


class ToolRegistry:
    """Name -> callable, so agents and the MCP bridge share one source of truth."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolFn] = {}
        self._meta: dict[str, dict[str, Any]] = {}

    def register(self, name: str, *, description: str, accepts: list[str],
                 requires_key: str | None = None):
        def deco(fn: ToolFn) -> ToolFn:
            self._tools[name] = fn
            self._meta[name] = {
                "name": name, "description": description,
                "accepts": accepts, "requires_key": requires_key,
            }
            return fn
        return deco

    def get(self, name: str) -> ToolFn | None:
        return self._tools.get(name)

    def for_type(self, indicator_type: str) -> list[str]:
        return [n for n, m in self._meta.items() if indicator_type in m["accepts"]]

    def describe(self) -> list[dict[str, Any]]:
        return list(self._meta.values())

    def configured(self, name: str, settings: Settings) -> bool:
        req = self._meta.get(name, {}).get("requires_key")
        return True if not req else bool(getattr(settings, req, ""))

    async def run_many(self, ctx: ToolContext, names: list[str],
                       value: str) -> list[Evidence]:
        """Fan out across tools concurrently; one slow API can't block the rest."""
        coros, resolved = [], []
        for name in names:
            fn = self._tools.get(name)
            if fn is None:
                # A silent skip here once cost us every DNS and reputation
                # lookup in the pipeline; an unregistered tool is a bug.
                log.error("tool %r is not registered, check threatiq.tools "
                          "imports; skipping", name)
                continue
            resolved.append(name)
            coros.append(ctx.cached(f"{name}|{value.lower()}",
                                    lambda f=fn, v=value: f(ctx, v)))
        if not coros:
            return []
        results = await asyncio.gather(*coros, return_exceptions=True)
        out: list[Evidence] = []
        for name, res in zip(resolved, results):
            if isinstance(res, Evidence):
                out.append(res)
            elif isinstance(res, BaseException):
                out.append(failed(name, name, value, str(res)))
        return out


registry = ToolRegistry()


def verdict_from_ratio(malicious: int, total: int) -> tuple[Verdict, Severity, float]:
    """Shared scoring for multi-engine reputation sources (VT-style).

    Returns (verdict, severity hint, confidence). A single engine hit is noise;
    the thresholds below reflect that.
    """
    if total <= 0:
        return Verdict.UNKNOWN, Severity.INFO, 0.0
    ratio = malicious / total
    if malicious >= 5 or ratio >= 0.10:
        return Verdict.MALICIOUS, Severity.CRITICAL, min(0.95, 0.6 + ratio * 2)
    if malicious >= 2:
        return Verdict.SUSPICIOUS, Severity.HIGH, 0.7
    if malicious == 1:
        return Verdict.SUSPICIOUS, Severity.LOW, 0.4
    return Verdict.BENIGN, Severity.INFO, 0.6
