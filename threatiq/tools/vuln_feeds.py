"""Vulnerability intelligence: NVD (severity) and CISA KEV (real-world exploitation).

KEV membership is the single most decisive prioritization signal available -
it means the vulnerability is confirmed exploited in the wild, not theoretical.
"""
from __future__ import annotations

import time
from typing import Any

from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, failed, registry, timed

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_TTL_S = 6 * 3600

# Module-level cache: the KEV catalogue is ~1300 entries and changes daily.
_kev_cache: dict[str, Any] = {"fetched_at": 0.0, "by_cve": {}}


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


@registry.register(
    "nvd_cve", description="Fetch CVSS score, vector and description for a CVE.",
    accepts=["cve"],
)
@timed("nvd", "cve")
async def nvd_cve(ctx: ToolContext, cve_id: str) -> Evidence:
    cve_id = cve_id.upper()
    indicator = f"cve:{cve_id}"
    assert ctx.client is not None

    headers = {"Accept": "application/json"}
    if ctx.settings.nvd_api_key:
        headers["apiKey"] = ctx.settings.nvd_api_key

    resp = await ctx.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers, params={"cveId": cve_id},
    )
    if resp.status_code == 403:
        return failed("nvd", "cve", indicator,
                      "NVD rate limit, set NVD_API_KEY to raise it",
                      ToolStatus.RATE_LIMITED)
    if resp.status_code != 200:
        return failed("nvd", "cve", indicator, f"HTTP {resp.status_code}")

    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return Evidence(
            source="nvd", tool="cve", indicator=indicator,
            status=ToolStatus.NOT_FOUND, confidence=0.4,
            summary=f"{cve_id} is not present in NVD",
        )

    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
    )

    metrics = cve.get("metrics", {})
    score, vector, version = 0.0, "", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            vector = data.get("vectorString", "")
            version = data.get("version", "")
            break

    # Attack-vector and privilege requirements drive exploitability, which the
    # risk engine weighs separately from raw CVSS.
    network_exploitable = "AV:N" in vector
    no_privileges = "PR:N" in vector
    no_user_interaction = "UI:N" in vector

    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)

    products = []
    for config in cve.get("configurations", [])[:3]:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", [])[:5]:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 5:
                    products.append(f"{parts[3]} {parts[4]} {parts[5]}".strip())

    severity = _cvss_to_severity(score)
    verdict = Verdict.MALICIOUS if score >= 7.0 else Verdict.SUSPICIOUS

    return Evidence(
        source="nvd", tool="cve", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=0.95,
        summary=f"{cve_id}: CVSS {score} ({severity.value}), {description[:220]}",
        signals={
            "cvss_score": score,
            "cvss_vector": vector,
            "cvss_version": version,
            "published": cve.get("published", ""),
            "cwe": sorted(set(cwes)),
            "network_exploitable": network_exploitable,
            "no_privileges_required": no_privileges,
            "no_user_interaction": no_user_interaction,
            "affected_products": sorted(set(products))[:10],
            "description": description,
        },
        raw={"cvss": {"score": score, "vector": vector}},
    )


async def _load_kev(ctx: ToolContext) -> dict[str, dict[str, Any]]:
    now = time.monotonic()
    if _kev_cache["by_cve"] and now - _kev_cache["fetched_at"] < _KEV_TTL_S:
        return _kev_cache["by_cve"]
    assert ctx.client is not None
    resp = await ctx.get(_KEV_URL, follow_redirects=True, timeout=30.0,
                         max_bytes=ctx.settings.kev_max_response_bytes)
    resp.raise_for_status()
    entries = resp.json().get("vulnerabilities", [])
    by_cve = {e["cveID"].upper(): e for e in entries if e.get("cveID")}
    _kev_cache["by_cve"] = by_cve
    _kev_cache["fetched_at"] = now
    return by_cve


@registry.register(
    "cisa_kev",
    description="Check whether a CVE is in CISA's Known Exploited Vulnerabilities catalog.",
    accepts=["cve"],
)
@timed("cisa_kev", "lookup")
async def cisa_kev(ctx: ToolContext, cve_id: str) -> Evidence:
    cve_id = cve_id.upper()
    indicator = f"cve:{cve_id}"
    catalog = await _load_kev(ctx)
    entry = catalog.get(cve_id)

    if not entry:
        return Evidence(
            source="cisa_kev", tool="lookup", indicator=indicator,
            status=ToolStatus.OK, verdict=Verdict.UNKNOWN,
            severity_hint=Severity.INFO, confidence=0.8,
            summary=f"{cve_id} is not in the CISA KEV catalog",
            signals={"in_kev": False, "catalog_size": len(catalog)},
        )

    ransomware = str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
    return Evidence(
        source="cisa_kev", tool="lookup", indicator=indicator,
        status=ToolStatus.OK, verdict=Verdict.MALICIOUS,
        severity_hint=Severity.CRITICAL, confidence=0.98,
        summary=(f"{cve_id} IS in the CISA KEV catalog, confirmed exploited in "
                 f"the wild. Remediation due {entry.get('dueDate', 'n/a')}."
                 + (" Known ransomware campaign use." if ransomware else "")),
        signals={
            "in_kev": True,
            "vendor_project": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "date_added": entry.get("dateAdded", ""),
            "due_date": entry.get("dueDate", ""),
            "required_action": entry.get("requiredAction", ""),
            "known_ransomware_use": ransomware,
        },
    )
