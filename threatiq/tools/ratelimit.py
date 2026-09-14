"""Per-source rate limiting for outbound intelligence calls.

The threat-intelligence agent fans out concurrently: every indicator, plus
every pivot discovered from it, hits the reputation sources at once. Against
VirusTotal's free tier that is an immediate problem, because the Public API
allows 4 requests per minute. A single phishing email carrying three domains
that resolve to two addresses is already five VirusTotal calls fired
simultaneously, so most of them come back 429 and the investigation silently
loses most of its reputation coverage.

The limiter paces each source independently with a token bucket. Two
properties matter more than throughput:

  * A call that cannot get a token within the wait budget is reported as
    rate-limited rather than queued forever. An investigation has an overall
    deadline, and a tool that blocks for two minutes waiting its turn would
    consume the whole thing. Honest partial coverage beats a hung request.

  * Sources with no API key configured never take a token. They are going to
    return `skipped` without touching the network, so charging them against a
    quota would starve the calls that do go out.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimit:
    """A published quota for one source.

    `requires` names the settings attribute holding that source's API key. When
    it is empty the source is unconfigured, so its calls cost nothing.
    """

    requests: int
    per_seconds: float
    requires: str | None = None
    note: str = ""

    @property
    def refill_per_second(self) -> float:
        return self.requests / self.per_seconds


# Published free-tier quotas. Overridable per deployment: a paid tier has
# different limits, and `RATE_LIMIT_OVERRIDES` in config exists for that.
#
# VirusTotal's numbers are quoted directly from their public-vs-premium docs.
# The others are deliberately conservative: AbuseIPDB and urlscan publish daily
# quotas rather than per-second ones, and NVD documents that a key raises the
# limit without stating the figure on the page this was taken from, so the
# unauthenticated value here is a floor rather than a measured maximum.
FREE_TIER_LIMITS: dict[str, RateLimit] = {
    "virustotal": RateLimit(
        4, 60.0, requires="virustotal_api_key",
        note="Public API: 4 requests/minute, 500/day",
    ),
    "abuseipdb": RateLimit(
        1000, 86_400.0, requires="abuseipdb_api_key",
        note="Free plan: 1,000 IP checks/day",
    ),
    "urlscan": RateLimit(
        1000, 86_400.0, requires=None,
        note="Free plan: 1,000 search requests; search works unauthenticated",
    ),
    "nvd": RateLimit(
        5, 30.0, requires=None,
        note="Conservative floor for the unauthenticated limit; a free key raises it",
    ),
}

# With a key, NVD permits a substantially higher rate. Applied when nvd_api_key
# is set.
NVD_KEYED_LIMIT = RateLimit(50, 30.0, requires=None,
                            note="With an API key")


class TokenBucket:
    """Async token bucket. One per source, shared across an investigation."""

    def __init__(self, limit: RateLimit) -> None:
        self.limit = limit
        self._capacity = float(limit.requests)
        self._refill = limit.refill_per_second
        self._tokens = float(limit.requests)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _replenish(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill)
            self._updated = now

    async def acquire(self, max_wait_s: float) -> float | None:
        """Take one token.

        Returns how long the caller waited, or None if a token could not be
        obtained inside `max_wait_s`. None is not an error: it means this call
        should report itself rate-limited and let the rest of the investigation
        proceed.
        """
        if self._refill <= 0:
            return None
        started = time.monotonic()
        deadline = started + max_wait_s

        while True:
            async with self._lock:
                self._replenish()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return time.monotonic() - started
                shortfall = 1.0 - self._tokens
                wait_for = shortfall / self._refill

            now = time.monotonic()
            if now + wait_for > deadline:
                return None
            # Cap each sleep so a bucket that refills sooner than predicted
            # (another caller returning a token is not possible here, but the
            # clock can jump) is re-checked promptly.
            await asyncio.sleep(min(wait_for, 1.0, max(0.0, deadline - now)))


class RateLimiter:
    """Holds one bucket per source for the lifetime of an investigation."""

    def __init__(self, settings, overrides: dict[str, RateLimit] | None = None) -> None:
        self.settings = settings
        self._limits = dict(FREE_TIER_LIMITS)
        # A configured NVD key buys a higher ceiling.
        if getattr(settings, "nvd_api_key", ""):
            self._limits["nvd"] = NVD_KEYED_LIMIT

        # Deployment overrides, for paid tiers.
        for source, (count, window) in getattr(
                settings, "rate_limit_override_map", {}).items():
            existing = self._limits.get(source)
            self._limits[source] = RateLimit(
                count, window,
                requires=existing.requires if existing else None,
                note=f"configured override: {count} requests/{window:g}s",
            )
        if overrides:
            self._limits.update(overrides)
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def limit_for(self, source: str) -> RateLimit | None:
        return self._limits.get(source)

    def applies_to(self, source: str) -> bool:
        """Whether this source should be paced at all.

        A source whose key is absent will return `skipped` without making a
        request, so it must not consume quota.
        """
        limit = self._limits.get(source)
        if limit is None:
            return False
        if limit.requires and not getattr(self.settings, limit.requires, ""):
            return False
        return True

    async def _bucket(self, source: str) -> TokenBucket:
        if source in self._buckets:
            return self._buckets[source]
        async with self._lock:
            if source not in self._buckets:
                self._buckets[source] = TokenBucket(self._limits[source])
            return self._buckets[source]

    async def acquire(self, source: str, max_wait_s: float) -> float | None:
        """Returns seconds waited, or None if the call should be shed."""
        if not self.applies_to(source):
            return 0.0
        bucket = await self._bucket(source)
        waited = await bucket.acquire(max_wait_s)
        if waited is None:
            log.info("shedding %s call: no quota within %.0fs (%s)",
                     source, max_wait_s, self._limits[source].note)
        elif waited > 1.0:
            log.debug("%s call waited %.1fs for quota", source, waited)
        return waited

    def describe(self) -> list[dict[str, object]]:
        """Current state, for the /health endpoint."""
        out = []
        for source, limit in sorted(self._limits.items()):
            bucket = self._buckets.get(source)
            if bucket is not None:
                bucket._replenish()
            out.append({
                "source": source,
                "requests": limit.requests,
                "per_seconds": limit.per_seconds,
                "active": self.applies_to(source),
                "tokens_available": (round(bucket._tokens, 2)
                                     if bucket else limit.requests),
                "note": limit.note,
            })
        return out
