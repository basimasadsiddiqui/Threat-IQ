"""urlscan.io, passive lookup of how a URL actually behaves in a browser.

Only the *search* endpoint is used by default. Submitting a URL for a live scan
publishes it to a public feed, so that stays behind an explicit opt-in.
"""
from __future__ import annotations

from urllib.parse import urlparse

from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, failed, registry, skipped, timed


@registry.register(
    "urlscan_search",
    description="Look up existing urlscan.io scans for a domain or URL.",
    accepts=["url", "domain"],
)
@timed("urlscan", "search")
async def urlscan_search(ctx: ToolContext, value: str) -> Evidence:
    host = urlparse(value).hostname if "://" in value else value
    host = (host or value).lower()
    indicator = f"domain:{host}"

    assert ctx.client is not None
    headers = {"Accept": "application/json"}
    if ctx.settings.urlscan_api_key:
        headers["API-Key"] = ctx.settings.urlscan_api_key

    resp = await ctx.get(
        "https://urlscan.io/api/v1/search/",
        headers=headers, params={"q": f"page.domain:{host}", "size": 10},
    )
    if resp.status_code == 429:
        return failed("urlscan", "search", indicator,
                      "urlscan.io rate limit exceeded", ToolStatus.RATE_LIMITED)
    if resp.status_code != 200:
        return failed("urlscan", "search", indicator, f"HTTP {resp.status_code}")

    results = resp.json().get("results", [])
    if not results:
        return Evidence(
            source="urlscan", tool="search", indicator=indicator,
            status=ToolStatus.NOT_FOUND, confidence=0.3,
            summary=f"No prior urlscan.io scans for {host}",
            signals={"scan_count": 0},
        )

    malicious_count = 0
    verdict_tags: set[str] = set()
    screenshots: list[str] = []
    result_urls: list[str] = []
    ips: set[str] = set()
    asns: set[str] = set()

    for item in results:
        page = item.get("page", {})
        verdicts = item.get("verdicts", {}).get("overall", {})
        if verdicts.get("malicious"):
            malicious_count += 1
        for tag in verdicts.get("tags", []) or []:
            verdict_tags.add(str(tag))
        for tag in item.get("brand", []) or []:
            name = tag.get("name") if isinstance(tag, dict) else str(tag)
            if name:
                verdict_tags.add(f"brand:{name}")
        if page.get("ip"):
            ips.add(page["ip"])
        if page.get("asn"):
            asns.add(str(page["asn"]))
        if item.get("screenshot"):
            screenshots.append(item["screenshot"])
        if item.get("result"):
            result_urls.append(item["result"])

    total = len(results)
    # A brand tag means urlscan recognised an impersonated login page -
    # that is one of the strongest phishing indicators this API returns.
    brand_impersonation = any(t.startswith("brand:") for t in verdict_tags)

    if malicious_count >= 2 or brand_impersonation:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.CRITICAL, 0.85
    elif malicious_count == 1:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.HIGH, 0.65
    else:
        # Scanned before and never flagged: weak evidence of benignity, but
        # real evidence, unlike the NOT_FOUND path above, which is silence.
        verdict, severity, confidence = Verdict.BENIGN, Severity.INFO, 0.4

    summary = (f"urlscan.io: {total} scan(s) for {host}, "
               f"{malicious_count} flagged malicious")
    if brand_impersonation:
        brands = [t.split(":", 1)[1] for t in verdict_tags if t.startswith("brand:")]
        summary += f"; detected brand impersonation of {', '.join(sorted(set(brands)))}"

    return Evidence(
        source="urlscan", tool="search", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence, summary=summary,
        signals={
            "scan_count": total,
            "malicious_scans": malicious_count,
            "tags": sorted(verdict_tags)[:10],
            "brand_impersonation": brand_impersonation,
            "observed_ips": sorted(ips)[:10],
            "observed_asns": sorted(asns)[:5],
            "screenshot": screenshots[0] if screenshots else "",
            "report_url": result_urls[0] if result_urls else "",
        },
    )


@registry.register(
    "urlscan_submit",
    description="Submit a URL to urlscan.io for a live scan (publishes the URL).",
    accepts=["url"], requires_key="urlscan_api_key",
)
@timed("urlscan", "submit")
async def urlscan_submit(ctx: ToolContext, url: str) -> Evidence:
    indicator = f"url:{url.lower()}"
    if not ctx.settings.urlscan_api_key:
        return skipped("urlscan", "submit", indicator, "URLSCAN_API_KEY not set")

    assert ctx.client is not None
    resp = await ctx.post(
        "https://urlscan.io/api/v1/scan/",
        headers={"API-Key": ctx.settings.urlscan_api_key,
                 "Content-Type": "application/json"},
        # "unlisted" keeps the result out of the public feed.
        json={"url": url, "visibility": "unlisted"},
    )
    if resp.status_code not in (200, 201):
        return failed("urlscan", "submit", indicator, f"HTTP {resp.status_code}")
    body = resp.json()
    return Evidence(
        source="urlscan", tool="submit", indicator=indicator,
        status=ToolStatus.OK, confidence=0.5,
        summary=f"Submitted to urlscan.io; results available at {body.get('result', '')}",
        signals={"scan_uuid": body.get("uuid", ""), "report_url": body.get("result", "")},
    )
