"""AbuseIPDB, crowd-sourced abuse reports for IP addresses."""
from __future__ import annotations

from threatiq.engine.indicators import is_private_ip
from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, failed, registry, skipped, timed

# AbuseIPDB category ids -> human labels (subset that matters for triage).
_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


@registry.register(
    "abuseipdb_check",
    description="Abuse report history and confidence score for an IP address.",
    accepts=["ipv4", "ipv6"], requires_key="abuseipdb_api_key",
)
@timed("abuseipdb", "check")
async def abuseipdb_check(ctx: ToolContext, ip: str) -> Evidence:
    indicator = f"ipv4:{ip}"
    if is_private_ip(ip):
        return skipped("abuseipdb", "check", indicator,
                       f"{ip} is a private address; not submitted to a third party")
    if not ctx.settings.abuseipdb_api_key:
        return skipped("abuseipdb", "check", indicator, "ABUSEIPDB_API_KEY not set")

    assert ctx.client is not None
    resp = await ctx.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ctx.settings.abuseipdb_api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )
    if resp.status_code == 429:
        return failed("abuseipdb", "check", indicator,
                      "AbuseIPDB rate limit exceeded", ToolStatus.RATE_LIMITED)
    if resp.status_code in (401, 403):
        return failed("abuseipdb", "check", indicator, "AbuseIPDB rejected the API key")
    if resp.status_code != 200:
        return failed("abuseipdb", "check", indicator, f"HTTP {resp.status_code}")

    data = resp.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    reports = int(data.get("totalReports", 0))
    distinct = int(data.get("numDistinctUsers", 0))

    categories: dict[str, int] = {}
    for report in data.get("reports", [])[:100]:
        for cat_id in report.get("categories", []):
            label = _CATEGORIES.get(cat_id, f"Category {cat_id}")
            categories[label] = categories.get(label, 0) + 1
    top_categories = sorted(categories.items(), key=lambda kv: -kv[1])[:5]

    # AbuseIPDB's own confidence score is well calibrated; map it directly,
    # but require more than one distinct reporter before calling it malicious.
    if score >= 75 and distinct >= 2:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.CRITICAL, 0.9
    elif score >= 50:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.HIGH, 0.75
    elif score >= 25:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.MEDIUM, 0.6
    elif reports > 0:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.LOW, 0.45
    else:
        verdict, severity, confidence = Verdict.BENIGN, Severity.INFO, 0.6

    signals = {
        "abuse_confidence_score": score,
        "total_reports": reports,
        "distinct_reporters": distinct,
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "is_tor": bool(data.get("isTor", False)),
        "is_whitelisted": bool(data.get("isWhitelisted", False)),
        "last_reported_at": data.get("lastReportedAt"),
        "top_categories": [c for c, _ in top_categories],
    }
    if top_categories:
        detail = ", ".join(f"{c} x{n}" for c, n in top_categories)
        summary = (f"AbuseIPDB: {reports} report(s) from {distinct} reporter(s), "
                   f"confidence {score}%, {detail}")
    else:
        summary = f"AbuseIPDB: no abuse reports in the last 90 days (confidence {score}%)"

    return Evidence(
        source="abuseipdb", tool="check", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence, summary=summary, signals=signals,
        raw={"abuseConfidenceScore": score, "totalReports": reports},
    )
