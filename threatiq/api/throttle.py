"""Inbound abuse controls.

Outbound calls are paced per source. Inbound ones were not, and that asymmetry
is the more dangerous half: one `POST /investigate` carrying a long list of
URLs makes ThreatIQ fetch every one of them. Without a limit, anybody who can
reach the endpoint can

  * use this host as a reconnaissance proxy, so the victim's logs show *your*
    address as the scanner rather than theirs,
  * drain the third-party quotas that the outbound limiter is carefully
    rationing, and
  * pin the process with concurrent investigations until it stops answering.

Two independent controls, because they fail differently. The token bucket
bounds request *rate* per caller. The semaphore bounds *concurrency* across all
callers, which is what actually protects memory and sockets when a handful of
expensive investigations arrive together.

Callers are identified by API key when one is presented, falling back to the
peer address. Neither is strong identity, and nothing here is a substitute for
authentication: this is an abuse control, not an authorisation boundary.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

from threatiq.config import Settings

log = logging.getLogger(__name__)


@dataclass
class _Bucket:
    tokens: float
    updated: float = field(default_factory=time.monotonic)


class InboundLimiter:
    """Per-caller token bucket plus a global concurrency ceiling."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(
            max(1, settings.max_concurrent_investigations))
        self._last_swept = time.monotonic()

    @property
    def _refill_per_second(self) -> float:
        return max(0.0, self.settings.inbound_rate_per_minute) / 60.0

    @staticmethod
    def caller_id(request: Request) -> str:
        """Identify the caller without logging a credential.

        The API key is hashed: this value ends up in log lines and in the 429
        path, and a secret should not.
        """
        key = request.headers.get("x-api-key")
        if key:
            return "key:" + hashlib.blake2b(
                key.encode(), digest_size=8).hexdigest()
        client = request.client
        return f"ip:{client.host}" if client else "ip:unknown"

    async def _sweep(self, now: float) -> None:
        """Drop idle buckets so a spray of distinct addresses cannot grow the
        map without bound. Any bucket that has had time to refill completely
        carries no state worth keeping."""
        if now - self._last_swept < 300:
            return
        self._last_swept = now
        capacity = float(self.settings.inbound_burst)
        refill = self._refill_per_second or 1.0
        idle_after = (capacity / refill) + 60
        stale = [k for k, b in self._buckets.items() if now - b.updated > idle_after]
        for key in stale:
            self._buckets.pop(key, None)

    async def check(self, request: Request) -> None:
        """Consume one token for this caller, or raise 429."""
        if self.settings.inbound_rate_per_minute <= 0:
            return  # explicitly disabled

        caller = self.caller_id(request)
        capacity = float(max(1, self.settings.inbound_burst))
        refill = self._refill_per_second

        async with self._lock:
            now = time.monotonic()
            await self._sweep(now)
            bucket = self._buckets.get(caller)
            if bucket is None:
                bucket = _Bucket(tokens=capacity)
                self._buckets[caller] = bucket

            elapsed = now - bucket.updated
            bucket.tokens = min(capacity, bucket.tokens + elapsed * refill)
            bucket.updated = now

            if bucket.tokens < 1.0:
                retry_after = max(1, int((1.0 - bucket.tokens) / refill) + 1)
                log.warning("throttled %s on %s", caller, request.url.path)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(f"Rate limit exceeded. This endpoint makes outbound "
                            f"requests on your behalf and is limited to "
                            f"{self.settings.inbound_rate_per_minute} per "
                            f"minute. Retry in {retry_after}s."),
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.tokens -= 1.0

    def slot(self) -> asyncio.Semaphore:
        """Concurrency ceiling for the expensive endpoints."""
        return self._semaphore

    def describe(self) -> dict[str, object]:
        return {
            "enabled": self.settings.inbound_rate_per_minute > 0,
            "requests_per_minute": self.settings.inbound_rate_per_minute,
            "burst": self.settings.inbound_burst,
            "max_concurrent_investigations":
                self.settings.max_concurrent_investigations,
            "tracked_callers": len(self._buckets),
        }


_limiter: InboundLimiter | None = None


def get_inbound_limiter(settings: Settings | None = None) -> InboundLimiter:
    global _limiter
    if _limiter is None:
        from threatiq.config import get_settings
        _limiter = InboundLimiter(settings or get_settings())
    return _limiter


def reset_inbound_limiter() -> None:
    """Test hook; also used when settings are reloaded."""
    global _limiter
    _limiter = None


async def throttle(request: Request) -> None:
    """FastAPI dependency. Attach to any endpoint that spends real resources."""
    await get_inbound_limiter().check(request)
