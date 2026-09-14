"""VirusTotal v3, multi-engine reputation for URLs, domains, IPs and hashes."""
from __future__ import annotations

import base64
from typing import Any

from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import (
    ToolContext, failed, registry, skipped, timed, verdict_from_ratio,
)

_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """VT identifies URLs by unpadded base64 of the URL itself."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _vt_get(ctx: ToolContext, path: str) -> tuple[int, dict[str, Any]]:
    assert ctx.client is not None
    resp = await ctx.get(
        f"{_BASE}{path}",
        headers={"x-apikey": ctx.settings.virustotal_api_key},
    )
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {}


def _build(indicator: str, tool: str, stats: dict[str, int],
           attrs: dict[str, Any], extra: dict[str, Any]) -> Evidence:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    verdict, severity, confidence = verdict_from_ratio(malicious + suspicious, total)
    reputation = int(attrs.get("reputation", 0) or 0)
    # Community reputation is a weak but useful tiebreaker.
    if reputation <= -20 and verdict == Verdict.BENIGN:
        verdict, severity = Verdict.SUSPICIOUS, Severity.LOW

    signals = {
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "harmless_engines": harmless,
        "total_engines": total,
        "reputation": reputation,
        "detection_ratio": f"{malicious}/{total}" if total else "0/0",
        **extra,
    }
    summary = (
        f"VirusTotal: {malicious}/{total} engines flagged this as malicious"
        if total else "VirusTotal has no analysis results for this indicator"
    )
    if suspicious:
        summary += f" ({suspicious} more marked suspicious)"

    return Evidence(
        source="virustotal", tool=tool, indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence, summary=summary, signals=signals,
        raw={"last_analysis_stats": stats},
    )


def _guard(ctx: ToolContext, indicator: str, tool: str) -> Evidence | None:
    if not ctx.settings.virustotal_api_key:
        return skipped("virustotal", tool, indicator, "VIRUSTOTAL_API_KEY not set")
    return None


def _http_error(status: int, indicator: str, tool: str) -> Evidence | None:
    if status == 404:
        return Evidence(
            source="virustotal", tool=tool, indicator=indicator,
            status=ToolStatus.NOT_FOUND, confidence=0.3,
            summary="Indicator is not known to VirusTotal",
            signals={"known_to_vt": False},
        )
    if status == 429:
        return failed("virustotal", tool, indicator,
                      "VirusTotal rate limit exceeded", ToolStatus.RATE_LIMITED)
    if status in (401, 403):
        return failed("virustotal", tool, indicator,
                      "VirusTotal rejected the API key")
    if status != 200:
        return failed("virustotal", tool, indicator, f"HTTP {status}")
    return None


@registry.register(
    "virustotal_url", description="VirusTotal reputation for a URL.",
    accepts=["url"], requires_key="virustotal_api_key",
)
@timed("virustotal", "url")
async def virustotal_url(ctx: ToolContext, url: str) -> Evidence:
    indicator = f"url:{url.lower()}"
    if (guard := _guard(ctx, indicator, "url")) is not None:
        return guard
    status, body = await _vt_get(ctx, f"/urls/{_url_id(url)}")
    if (err := _http_error(status, indicator, "url")) is not None:
        return err
    attrs = body.get("data", {}).get("attributes", {})
    return _build(
        indicator, "url", attrs.get("last_analysis_stats", {}), attrs,
        {
            "final_url": attrs.get("last_final_url", ""),
            "title": attrs.get("title", ""),
            "categories": list(attrs.get("categories", {}).values())[:5],
            "times_submitted": attrs.get("times_submitted", 0),
        },
    )


@registry.register(
    "virustotal_domain", description="VirusTotal reputation for a domain.",
    accepts=["domain"], requires_key="virustotal_api_key",
)
@timed("virustotal", "domain")
async def virustotal_domain(ctx: ToolContext, domain: str) -> Evidence:
    indicator = f"domain:{domain.lower()}"
    if (guard := _guard(ctx, indicator, "domain")) is not None:
        return guard
    status, body = await _vt_get(ctx, f"/domains/{domain}")
    if (err := _http_error(status, indicator, "domain")) is not None:
        return err
    attrs = body.get("data", {}).get("attributes", {})
    return _build(
        indicator, "domain", attrs.get("last_analysis_stats", {}), attrs,
        {
            "categories": list(attrs.get("categories", {}).values())[:5],
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date"),
        },
    )


@registry.register(
    "virustotal_ip", description="VirusTotal reputation for an IP address.",
    accepts=["ipv4", "ipv6"], requires_key="virustotal_api_key",
)
@timed("virustotal", "ip")
async def virustotal_ip(ctx: ToolContext, ip: str) -> Evidence:
    indicator = f"ipv4:{ip}"
    if (guard := _guard(ctx, indicator, "ip")) is not None:
        return guard
    status, body = await _vt_get(ctx, f"/ip_addresses/{ip}")
    if (err := _http_error(status, indicator, "ip")) is not None:
        return err
    attrs = body.get("data", {}).get("attributes", {})
    return _build(
        indicator, "ip", attrs.get("last_analysis_stats", {}), attrs,
        {
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner", ""),
            "country": attrs.get("country", ""),
        },
    )


@registry.register(
    "virustotal_file", description="VirusTotal reputation for a file hash.",
    accepts=["file_hash"], requires_key="virustotal_api_key",
)
@timed("virustotal", "file")
async def virustotal_file(ctx: ToolContext, file_hash: str) -> Evidence:
    indicator = f"file_hash:{file_hash.lower()}"
    if (guard := _guard(ctx, indicator, "file")) is not None:
        return guard
    status, body = await _vt_get(ctx, f"/files/{file_hash}")
    if (err := _http_error(status, indicator, "file")) is not None:
        return err
    attrs = body.get("data", {}).get("attributes", {})
    names = attrs.get("names", [])[:5]
    return _build(
        indicator, "file", attrs.get("last_analysis_stats", {}), attrs,
        {
            "type_description": attrs.get("type_description", ""),
            "size": attrs.get("size"),
            "names": names,
            "signature": attrs.get("signature_info", {}).get("product", ""),
            "popular_threat_label": attrs.get("popular_threat_classification", {})
                                         .get("suggested_threat_label", ""),
        },
    )
