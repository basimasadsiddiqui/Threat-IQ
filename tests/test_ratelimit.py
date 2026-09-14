"""Rate limiter tests.

The limiter exists because the threat-intel agent fans out concurrently and
VirusTotal's free tier allows 4 requests a minute. The properties that matter
are not throughput but honesty: a shed call must be distinguishable from a
clean one, and an unconfigured source must not burn quota it was never going
to use.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from threatiq.config import Settings
from threatiq.schemas import Evidence, ToolStatus, Verdict
from threatiq.tools.ratelimit import (
    FREE_TIER_LIMITS, RateLimit, RateLimiter, TokenBucket,
)


# ------------------------------------------------------------- token bucket

@pytest.mark.asyncio
async def test_bucket_allows_the_initial_burst():
    """A fresh bucket is full, so the first N calls do not wait."""
    bucket = TokenBucket(RateLimit(4, 60.0))
    started = time.monotonic()
    for _ in range(4):
        waited = await bucket.acquire(max_wait_s=1.0)
        assert waited is not None
    assert time.monotonic() - started < 0.2, "the initial burst should not block"


@pytest.mark.asyncio
async def test_bucket_paces_once_the_burst_is_spent():
    # 4 per second: the fifth call waits about a quarter of a second.
    bucket = TokenBucket(RateLimit(4, 1.0))
    for _ in range(4):
        await bucket.acquire(max_wait_s=2.0)

    started = time.monotonic()
    waited = await bucket.acquire(max_wait_s=2.0)
    elapsed = time.monotonic() - started

    assert waited is not None, "should have waited, not shed"
    assert 0.1 < elapsed < 1.0, f"expected roughly 0.25s of pacing, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_bucket_sheds_rather_than_queueing_past_the_budget():
    """An investigation has a deadline. A call that cannot get quota inside
    its budget is dropped so the rest of the investigation still finishes."""
    bucket = TokenBucket(RateLimit(1, 60.0))
    assert await bucket.acquire(max_wait_s=1.0) is not None  # takes the one token

    started = time.monotonic()
    shed = await bucket.acquire(max_wait_s=0.3)
    elapsed = time.monotonic() - started

    assert shed is None, "should have shed the call"
    assert elapsed < 1.0, "shedding must not block for the full refill window"


@pytest.mark.asyncio
async def test_concurrent_callers_are_serialised_not_lost():
    """Every caller either gets a token or is shed. None may double-spend."""
    bucket = TokenBucket(RateLimit(3, 1.0))
    results = await asyncio.gather(*(bucket.acquire(0.05) for _ in range(10)))
    granted = [r for r in results if r is not None]
    assert len(granted) == 3, f"bucket of 3 granted {len(granted)}"


# ----------------------------------------------------------------- limiter

def test_virustotal_free_tier_matches_the_published_quota():
    """4 requests/minute, quoted from VirusTotal's public-vs-premium docs."""
    limit = FREE_TIER_LIMITS["virustotal"]
    assert (limit.requests, limit.per_seconds) == (4, 60.0)
    assert limit.requires == "virustotal_api_key"


def test_unconfigured_source_is_not_paced():
    """A source with no key returns `skipped` without a request, so charging
    it against the quota would starve the calls that do go out."""
    limiter = RateLimiter(Settings(virustotal_api_key=""))
    assert limiter.applies_to("virustotal") is False

    limiter = RateLimiter(Settings(virustotal_api_key="vt_key"))
    assert limiter.applies_to("virustotal") is True


def test_unknown_source_is_not_paced():
    limiter = RateLimiter(Settings())
    assert limiter.applies_to("dns") is False
    assert limiter.applies_to("cisa_kev") is False


@pytest.mark.asyncio
async def test_unpaced_source_acquires_instantly():
    limiter = RateLimiter(Settings(virustotal_api_key=""))
    waited = await limiter.acquire("virustotal", max_wait_s=5.0)
    assert waited == 0.0


def test_nvd_key_raises_the_ceiling():
    without = RateLimiter(Settings(nvd_api_key="")).limit_for("nvd")
    with_key = RateLimiter(Settings(nvd_api_key="nvd_key")).limit_for("nvd")
    assert with_key.refill_per_second > without.refill_per_second


def test_paid_tier_overrides_are_parsed():
    settings = Settings(rate_limit_overrides="virustotal=1000/60,abuseipdb=50000/86400")
    assert settings.rate_limit_override_map == {
        "virustotal": (1000, 60.0), "abuseipdb": (50000, 86400.0)}

    limiter = RateLimiter(settings)
    assert limiter.limit_for("virustotal").requests == 1000
    # The key requirement survives an override.
    assert limiter.limit_for("virustotal").requires == "virustotal_api_key"


@pytest.mark.parametrize("malformed", [
    "virustotal", "virustotal=", "virustotal=abc/60", "virustotal=10",
    "=10/60", "virustotal=0/60", "virustotal=10/0", "",
])
def test_malformed_overrides_are_ignored_not_fatal(malformed):
    """A typo in an optional tuning variable must not stop the service
    starting; falling back to the published free-tier default is safe."""
    settings = Settings(rate_limit_overrides=malformed)
    assert settings.rate_limit_override_map == {}
    limiter = RateLimiter(settings)
    assert limiter.limit_for("virustotal").requests == 4


# --------------------------------------------------------- honest reporting

def test_shed_call_is_not_counted_as_a_clean_result():
    """This is the whole point. A rate-limited lookup is missing coverage; if
    the risk engine treated it as usable, an unqueried source would read as
    'found nothing' and inflate confidence."""
    from threatiq.engine.risk_engine import _usable

    shed = Evidence(source="virustotal", tool="domain", indicator="domain:x.test",
                    status=ToolStatus.RATE_LIMITED, verdict=Verdict.UNKNOWN,
                    confidence=0.0, summary="not queried")
    clean = Evidence(source="virustotal", tool="domain", indicator="domain:y.test",
                     status=ToolStatus.OK, verdict=Verdict.BENIGN, confidence=0.6,
                     summary="no detections")

    usable = _usable([shed, clean])
    assert clean in usable
    assert shed not in usable


def test_shed_calls_lower_confidence():
    from threatiq.engine.risk_engine import RiskInput, assess

    def evidence(status: ToolStatus) -> Evidence:
        return Evidence(source="virustotal", tool="domain",
                        indicator="domain:x.test", status=status,
                        verdict=(Verdict.BENIGN if status is ToolStatus.OK
                                 else Verdict.UNKNOWN),
                        confidence=0.6 if status is ToolStatus.OK else 0.0,
                        summary="s")

    lookalike = Evidence(source="lookalike", tool="analyze",
                         indicator="domain:x.test", status=ToolStatus.OK,
                         verdict=Verdict.MALICIOUS, confidence=0.9,
                         signals={"score": 0.95}, summary="s")

    full = assess(RiskInput(evidence=[evidence(ToolStatus.OK), lookalike],
                            findings=[]))
    shed = assess(RiskInput(evidence=[evidence(ToolStatus.RATE_LIMITED),
                                      lookalike], findings=[]))
    assert shed.confidence < full.confidence


@pytest.mark.asyncio
async def test_fan_out_through_the_decorator_is_paced_not_flooded():
    """The integration point that matters.

    This reproduces the original defect: the threat-intel agent gathers its
    lookups concurrently, so eight VirusTotal calls used to leave at once
    against a 4-per-minute quota. Only the calls that hold a token may reach
    the tool body; the rest must come back as rate-limited evidence rather
    than as 429s or as clean results.
    """
    from threatiq.tools.base import ToolContext, timed

    reached_the_network = []

    @timed("virustotal", "domain")
    async def fake_lookup(ctx, value):
        reached_the_network.append(value)
        return Evidence(source="virustotal", tool="domain",
                        indicator=f"domain:{value}", status=ToolStatus.OK,
                        verdict=Verdict.BENIGN, confidence=0.6, summary="ok")

    settings = Settings(virustotal_api_key="vt_key", rate_limit_max_wait_s=1)
    ctx = ToolContext(settings=settings)

    results = await asyncio.gather(
        *(fake_lookup(ctx, f"host{i}.test") for i in range(8)))

    allowed = [r for r in results if r.status is ToolStatus.OK]
    shed = [r for r in results if r.status is ToolStatus.RATE_LIMITED]

    assert len(allowed) == 4, (
        f"quota is 4/minute but {len(allowed)} calls got through")
    assert len(shed) == 4, "the rest should be shed, not silently dropped"
    assert len(reached_the_network) == 4, "a shed call must not hit the network"

    # A shed call must be unmistakably not-a-result.
    assert all(r.confidence == 0.0 for r in shed)
    assert all("not a clean result" in r.summary for r in shed)


@pytest.mark.asyncio
async def test_unkeyed_source_is_never_shed():
    """Without a key the tool returns `skipped` without a request, so it must
    not be throttled and must not consume quota."""
    from threatiq.tools.base import ToolContext, skipped, timed

    @timed("virustotal", "domain")
    async def unconfigured(ctx, value):
        return skipped("virustotal", "domain", value, "no key")

    ctx = ToolContext(settings=Settings(virustotal_api_key=""))
    results = await asyncio.gather(
        *(unconfigured(ctx, f"h{i}.test") for i in range(20)))
    assert all(r.status is ToolStatus.SKIPPED for r in results)


def test_health_description_reports_state():
    limiter = RateLimiter(Settings(virustotal_api_key="vt"))
    rows = {row["source"]: row for row in limiter.describe()}
    assert rows["virustotal"]["active"] is True
    assert rows["virustotal"]["requests"] == 4
    assert "4 requests/minute" in rows["virustotal"]["note"]
    assert rows["abuseipdb"]["active"] is False  # no key configured
